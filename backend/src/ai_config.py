"""The stored advisory-provider configuration: read it, write it, and resolve it
against the environment.

WHY THIS MODULE EXISTS
----------------------
Until now, which model this product talks to was decided entirely by environment
variables read once at import (`src/settings.py`). That is the right shape for a
SECRET and the wrong shape for a CHOICE. On Azure Container Apps an environment
variable change is a new revision -- a deploy -- so "point the advisory layer at
our own Foundry deployment" was a pipeline change rather than an admin action,
it never appeared in the product's own audit trail, and nothing recorded who
made it. The header's AI-residency chip could tell a user their network topology
was leaving the box; nothing could tell them who decided that.

`ztpa.ai_config` (db/migrations/0004_ai_config.sql) is one row holding the
choice, with `configured_by` and `updated_at` on it. This module owns every read
and write of that row, and owns the rule for what happens when the row and the
environment disagree.

THE RESOLUTION ORDER, AND WHY IT IS THIS WAY
--------------------------------------------
There are now three sources of truth, so the order has to be written down rather
than emerge from whichever branch ran first:

  1. **The stored row wins for CHOICES** -- provider, azure endpoint, deployment,
     api-version, auth mode, client id. It is what an operator set deliberately,
     through a UI, on this deployment, with their name attached. An environment
     variable is a deployment-time guess made by whoever wrote the container
     spec; the row is a decision made by whoever runs the product. When they
     disagree, the later, attributable, in-product decision is the one to honour
     -- and the alternative ("env always wins") would make the Configuration
     page a form whose Save button silently does nothing on exactly the
     deployment it was built for, since render.yaml/the container spec already
     pins `ADVISORY_PROVIDER`.

  2. **The environment is the bootstrap and the fallback.** With no row --
     a fresh install, before anyone has opened the Configuration page -- the
     environment decides, exactly as it always did. This is what keeps a first
     boot working, and what keeps every existing deployment behaving identically
     after this change until someone deliberately configures it.

  3. **Built-in defaults are the floor** (`auto` routing, identity auth,
     DEFAULT_AZURE_API_VERSION).

  ...and **SECRETS ARE ENVIRONMENT-ONLY, ALWAYS**. `AZURE_AI_API_KEY`,
  `OPENAI_API_KEY`, `ANTHROPIC_API_KEY` are read from the environment and from
  nowhere else. The table has no column that could hold one and must never grow
  one; the stored row says WHICH credential to use (`azure_auth_mode`), never
  WHAT it is. A row is read on every model call, lands in every `pg_dump`, and is
  served by an admin endpoint -- a secret in it is a secret in all three places.

THE ROW IS AUTHORITATIVE AS A BLOCK, NOT FIELD BY FIELD
-------------------------------------------------------
When a row exists, the environment's `AZURE_AI_*` values are ignored entirely --
not merged in field by field. Merging looks friendlier and has a nasty edge: an
operator who CLEARS `azure_client_id` in the UI would have it resurrected from a
stale environment variable on the next call, and the config page would show a
value the product is not using. One source per block, chosen by whether the row
exists, is the version an operator can predict. A NULL `azure_api_version` in a
stored row therefore means "use the application default", which is why the
column is documented as nullable rather than defaulted in SQL.

BREAK-GLASS: `AI_CONFIG_IGNORE_DB=true`
---------------------------------------
Set it and the stored row is ignored; the environment and the defaults decide,
as they did before this table existed. It is the recovery path for a stored
configuration that is wrong on a deployment whose Configuration page cannot be
reached -- one variable and a restart, no SQL, no psql access to a private
Postgres. Read at call time (not at import) so it is togglable in a test.

"COULD NOT READ" IS NOT "NOT CONFIGURED"
-----------------------------------------
This is the failure mode the last three phases of this codebase's audit kept
finding, and it is worse here than almost anywhere else: reading an unreachable
database as "no configuration" would silently route the customer's network
topology to a DIFFERENT PROVIDER than the operator chose -- possibly off their
tenant entirely -- and report it as normal operation. So the two are separated
by construction:

  * `load()` is strict. It RAISES `AiConfigUnavailable` when the store cannot be
    read. It is what the admin read path (`GET /api/admin/ai/config`) must use,
    so that endpoint answers "I cannot read your configuration" instead of
    rendering an empty form over a configuration that exists.

  * `stored()` is the routing path. It never raises -- a dead database must not
    take the deterministic engine down with it -- but it never lies either:
    every result carries a `source`, and the unhappy ones are distinct values.
    When a previous read succeeded it keeps serving THAT config (`source="stale"`)
    rather than reverting to the environment, because the operator's choice is
    still the operator's choice while the database is briefly unreachable. Only
    when nothing has ever been read does it fall through to the environment, as
    `source="unavailable"` and with a WARNING naming the transition.

`source` values: "database" (a row), "defaults" (no row, or no DATABASE_URL at
all -- nothing to read, which is not a failure), "stale" (unreadable now, last
good row still in use), "unavailable" (unreadable and nothing cached),
"ignored" (the break-glass above).

Like `settings.ollama_probe`, the read is cached for a short TTL and the
unhappy states are logged ON CHANGE: `stored()` runs on every model call, and a
line per call would bury the transition it exists to show.
"""

from __future__ import annotations

import logging
import os
import re
import time
from dataclasses import dataclass, replace
from datetime import datetime
from typing import Any
from urllib.parse import urlsplit

import psycopg

from . import db, request_ctx
from .db import get_conn, upsert
from .settings import DB_SCHEMA

# Child of the API logger, so a configuration read failure comes out as one JSON
# line with the request id attached (app/main.py configures "npr.api"). See
# advisory/client.py for the convention.
log = logging.getLogger("npr.api.aiconfig")

TABLE = "ai_config"

# The provider vocabulary, identical to ADVISORY_PROVIDER's (settings.py) so a
# stored value and an environment value are directly comparable. 'auto' is
# storable on purpose: it is how an operator says "go back to letting the
# environment decide" without deleting the row and losing the record that they
# said it.
PROVIDERS: tuple[str, ...] = ("auto", "azure", "openai", "anthropic", "ollama")
AZURE_AUTH_MODES: tuple[str, ...] = ("identity", "key")

# Azure OpenAI data-plane API version used when neither the row nor the
# environment names one. 2024-10-21 is the current GA version and is the one
# verified against the live Foundry account this feature was built for
# (`api-endpoint-inference-resource`, deployments Mistral-Large-3 and
# Kimi-K2.7-Code): the classic
# `{endpoint}/openai/deployments/{deployment}/chat/completions?api-version=...`
# route answers 200 for BOTH, even though neither is an OpenAI-format model.
# That is what lets the already-present `openai` package serve this provider --
# see backend/requirements.txt.
DEFAULT_AZURE_API_VERSION = "2024-10-21"

# `source` values -- see the module docstring. They are the difference between
# "you have not configured this" and "I could not find out".
SOURCE_DATABASE = "database"
SOURCE_DEFAULTS = "defaults"
SOURCE_STALE = "stale"
SOURCE_UNAVAILABLE = "unavailable"
SOURCE_IGNORED = "ignored"

# The states in which a real stored row is in play.
_STORED_SOURCES = (SOURCE_DATABASE, SOURCE_STALE)

# Where a resolved field came from, for the config page and /api/health.
ORIGIN_DATABASE = "database"
ORIGIN_ENVIRONMENT = "environment"
ORIGIN_DEFAULT = "default"

# The failure surface of a read/write against Postgres. Named rather than
# `except Exception` so a defect in THIS module -- a NameError, a bad column
# name in an f-string -- surfaces as a crash instead of being silently
# reclassified as "your database is down" and routed around. `psycopg.Error`
# covers connect failures, pool timeouts (psycopg_pool.PoolTimeout is an
# OperationalError) and a missing table (the migration has not been applied);
# OSError covers a socket/DNS failure that escapes before psycopg wraps it.
_STORE_ERRORS: tuple[type[BaseException], ...] = (psycopg.Error, OSError)

# Anything that ends up inside a URL is validated before it is stored, because
# the stored value is later interpolated into a request path/query by the
# provider. A deployment name with a '?' in it is not a typo, it is a request
# aimed somewhere else.
_DEPLOYMENT_RE = re.compile(r"^[A-Za-z0-9._-]{1,128}$")
_API_VERSION_RE = re.compile(r"^[A-Za-z0-9._-]{1,64}$")
_UUID_RE = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
                      r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")

# Hosts for which plaintext http is tolerated: a developer's local gateway. Any
# other http endpoint is refused -- this product's payloads are firewall rules,
# asset names and reachability paths, and shipping them in the clear is not a
# preference the manual escape hatch gets to express.
_PLAINTEXT_OK_HOSTS = frozenset({"localhost", "127.0.0.1", "::1", "[::1]"})

# Column names that may never exist on this table. Asserted by
# backend/tests/test_ai_config.py against both db/schema.sql and the live
# catalog, so "no secrets in the config table" is a checked property rather than
# a comment somebody can delete.
SECRET_COLUMN_PATTERNS: tuple[str, ...] = (
    "key", "secret", "password", "passwd", "token", "credential", "sas",
)


class AiConfigError(ValueError):
    """A configuration the store refuses to hold. Map to HTTP 400.

    Raised by `save()` BEFORE the database sees the row, so the API layer gets a
    sentence naming the offending field instead of a psycopg IntegrityError
    naming a constraint.
    """


class AiConfigUnavailable(RuntimeError):
    """The configuration store could not be read or written. Map to HTTP 503.

    Deliberately NOT the same as "there is no configuration". See the module
    docstring: conflating them moves inference to a provider nobody chose.
    """


@dataclass(frozen=True)
class AiConfig:
    """The stored row, plus where this instance of it came from.

    `provider` is None only in the no-row states; the column itself is NOT NULL.
    """

    provider: str | None = None
    azure_endpoint: str | None = None
    azure_deployment: str | None = None
    azure_api_version: str | None = None
    azure_auth_mode: str = "identity"
    azure_client_id: str | None = None
    configured_by: str | None = None
    updated_at: datetime | None = None
    source: str = SOURCE_DEFAULTS

    @property
    def is_stored(self) -> bool:
        """True when a real row is behind these values (fresh or stale)."""
        return self.source in _STORED_SOURCES

    @property
    def store_readable(self) -> bool:
        """False when the store could not be read. `is_stored` and this one
        together are what keep 'unconfigured' and 'unknown' apart at a call
        site that only wants a boolean."""
        return self.source not in (SOURCE_STALE, SOURCE_UNAVAILABLE)

    def public(self) -> dict[str, Any]:
        """The row as an API payload. There is nothing to redact -- the table
        holds no secret and cannot -- so this is the whole row plus its source,
        and the absence of a redaction step here is deliberate evidence of that.
        """
        return {
            "provider": self.provider,
            "azure_endpoint": self.azure_endpoint,
            "azure_deployment": self.azure_deployment,
            "azure_api_version": self.azure_api_version,
            "azure_auth_mode": self.azure_auth_mode,
            "azure_client_id": self.azure_client_id,
            "configured_by": self.configured_by,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
            "source": self.source,
            "is_stored": self.is_stored,
        }


DEFAULTS = AiConfig()

# The columns, in one place, so the SELECT, the UPSERT and the tests cannot
# drift apart. `id` is excluded on purpose: it is the singleton key and always
# true (see the migration).
COLUMNS: tuple[str, ...] = (
    "provider", "azure_endpoint", "azure_deployment", "azure_api_version",
    "azure_auth_mode", "azure_client_id", "configured_by", "updated_at",
)


@dataclass(frozen=True)
class Resolved:
    """The answer after the documented resolution order has been applied.

    This -- not `AiConfig` -- is what the routing path and the provider client
    should read: it has no None-means-two-things fields, and it carries where
    each block came from so the UI can say "this deployment is on the
    environment's setting, not yours".
    """

    provider: str
    provider_origin: str
    azure_endpoint: str
    azure_deployment: str
    azure_api_version: str
    azure_auth_mode: str
    azure_client_id: str | None
    azure_origin: str
    config_source: str
    # Set when the endpoint that was configured could not be used as one. Kept
    # as a field rather than raised: `resolve()` is called from
    # `settings.active_provider()`, which runs on every model call, and a
    # malformed AZURE_AI_ENDPOINT in a container spec must degrade the advisory
    # layer, not take down every request in the product.
    azure_endpoint_error: str | None = None

    @property
    def azure_target_configured(self) -> bool:
        return bool(self.azure_endpoint and self.azure_deployment)


# --------------------------------------------------------------------------
# reading: the strict path
# --------------------------------------------------------------------------

def _row_to_config(row: dict[str, Any] | None, *, source: str) -> AiConfig:
    if row is None:
        return DEFAULTS
    return AiConfig(
        provider=row["provider"],
        azure_endpoint=row["azure_endpoint"] or None,
        azure_deployment=row["azure_deployment"] or None,
        azure_api_version=row["azure_api_version"] or None,
        azure_auth_mode=row["azure_auth_mode"] or "identity",
        azure_client_id=row["azure_client_id"] or None,
        configured_by=row["configured_by"] or None,
        updated_at=row["updated_at"],
        source=source,
    )


def read_row(cur: psycopg.Cursor) -> AiConfig:
    """The SELECT, against a cursor the caller owns.

    Split out from `load()` so the real-database tests can exercise the actual
    SQL inside a transaction they roll back, rather than committing into the
    system of record to prove a SELECT works.
    """
    cur.execute(f"SELECT {', '.join(COLUMNS)} FROM {DB_SCHEMA}.{TABLE} WHERE id = true")
    return _row_to_config(cur.fetchone(), source=SOURCE_DATABASE)


def load() -> AiConfig:
    """The stored configuration, or `DEFAULTS` when there is none.

    RAISES `AiConfigUnavailable` when the store exists but could not be read --
    the database is unreachable, the pool is exhausted, or `ztpa.ai_config` is
    missing because `python db/migrate.py` has not been run on this deployment.
    Use it wherever an operator is looking at the answer; use `stored()` on the
    routing path, which must not raise.

    No `DATABASE_URL` at all is NOT a failure: there is no store to read, which
    is a real (if unusual) deployment -- the offline test suite is one -- and it
    resolves through the environment exactly as it did before this table
    existed. The distinction mirrors `metrics.py`'s split between a metrics sink
    that is UNCONFIGURED and one that FAILED, for the same reason: the two have
    different fixes.
    """
    if not db.DATABASE_URL:
        return DEFAULTS
    try:
        with get_conn() as conn, conn.cursor() as cur:
            return read_row(cur)
    except _STORE_ERRORS as exc:
        raise AiConfigUnavailable(
            f"could not read {DB_SCHEMA}.{TABLE}: {type(exc).__name__}: {exc}. "
            f"This is NOT the same as 'no configuration is stored' -- treating it "
            f"as such would route model calls at whatever the environment says "
            f"instead of what the operator chose. If the table is missing, run "
            f"`python db/migrate.py`."
        ) from exc


# --------------------------------------------------------------------------
# reading: the routing path (cached, never raises, always says which state)
# --------------------------------------------------------------------------
# Keyed on the DATABASE_URL the cache was built against, so a process (or a
# test) that repoints the database cannot be served the previous one's answer.
_CACHE: dict[str, Any] = {"checked_at": 0.0, "cfg": None, "url": None, "reported": None,
                          "failed_at": 0.0, "failure": None}
_CACHE_TTL: float = 30.0    # seconds; matches settings._OLLAMA_PROBE_TTL

# A FAILED read is cached too, for a shorter window. Not an optimisation: a
# dead database fails through psycopg_pool's 30-SECOND connect timeout
# (src/db._get_pool), and `stored()` is on the path of every model call, so
# retrying per call would turn "the config database is down" into "every
# capability in the product hangs for half a minute" -- a far worse outcome than
# the degradation itself, and one the deterministic fallback exists to avoid.
# Five seconds is short enough that recovery is effectively immediate to a human
# and long enough that a request storm costs one connect attempt, not hundreds.
_FAILURE_TTL: float = 5.0


def invalidate() -> None:
    """Drop the cached read. Called by `save()` so an operator's change takes
    effect on the next model call rather than up to a TTL later, and by tests."""
    _CACHE.update(checked_at=0.0, cfg=None, url=None, reported=None,
                  failed_at=0.0, failure=None)
    _ENDPOINT_REPORTED["value"] = None


def _report(source: str, detail: str | None) -> None:
    """Log the store's state, but only when it differs from the last one logged.

    `stored()` runs on every model call. Three states are worth a line and each
    has a different fix: the store is unreadable and we are serving the last
    good row (fix the database; nothing has moved yet), unreadable with nothing
    cached (the environment is now deciding -- inference may be at a different
    provider than the operator chose), and readable again.
    """
    if _CACHE["reported"] == (source, detail):
        return
    _CACHE["reported"] = (source, detail)
    if source == SOURCE_STALE:
        log.warning("the AI configuration store is unreadable; still using the last "
                    "configuration successfully read from it",
                    extra={"event": "ai_config_stale", "error": detail})
    elif source == SOURCE_UNAVAILABLE:
        log.error("the AI configuration store is unreadable and nothing has been read from "
                  "it in this process; provider routing has fallen back to the environment, "
                  "which may not be the provider the operator configured",
                  extra={"event": "ai_config_unavailable", "error": detail})
    elif source in (SOURCE_DATABASE, SOURCE_DEFAULTS):
        log.info("AI configuration read", extra={"event": "ai_config_read", "source": source})


def stored() -> AiConfig:
    """The stored configuration for the ROUTING path: cached, never raises.

    The result's `source` is the honest answer about what happened -- see the
    module docstring. A previously-read configuration survives a database blip
    (`source="stale"`) rather than reverting to the environment, because a brief
    outage is not an operator changing their mind.
    """
    if _ignore_db():
        return replace(DEFAULTS, source=SOURCE_IGNORED)

    now = time.monotonic()
    url = db.DATABASE_URL
    same_db = _CACHE["url"] == url
    cached = _CACHE["cfg"] if same_db else None

    if cached is not None and now - _CACHE["checked_at"] < _CACHE_TTL:
        return cached
    if same_db and _CACHE["failure"] and now - _CACHE["failed_at"] < _FAILURE_TTL:
        return _degraded(cached, _CACHE["failure"])       # already reported; do not re-dial

    try:
        cfg = load()
    except AiConfigUnavailable as exc:
        _CACHE.update(url=url, failed_at=now, failure=str(exc))
        return _degraded(cached, str(exc))

    _CACHE.update(checked_at=now, cfg=cfg, url=url, failed_at=0.0, failure=None)
    _report(cfg.source, None)
    return cfg


def _degraded(cached: AiConfig | None, detail: str) -> AiConfig:
    """The answer when the store cannot be read: the last good row if we have
    one, otherwise the environment's turn — and in both cases a `source` that
    says which, so no caller can mistake either for "nothing is configured"."""
    if cached is not None and cached.source in _STORED_SOURCES:
        _report(SOURCE_STALE, detail)
        return replace(cached, source=SOURCE_STALE)
    _report(SOURCE_UNAVAILABLE, detail)
    return replace(DEFAULTS, source=SOURCE_UNAVAILABLE)


def _ignore_db() -> bool:
    """The `AI_CONFIG_IGNORE_DB` break-glass, read at call time.

    Bound late rather than at import so it can be flipped by a test and, more
    importantly, so the meaning of the variable is "what the environment says
    now" rather than "what it said when this module happened to be imported".
    """
    return (os.environ.get("AI_CONFIG_IGNORE_DB") or "").strip().lower() in ("1", "true", "yes")


# --------------------------------------------------------------------------
# resolution: row, then environment, then defaults
# --------------------------------------------------------------------------

def resolve(cfg: AiConfig | None = None) -> Resolved:
    """Apply the documented resolution order. `cfg` defaults to `stored()`.

    Taking the config as an argument keeps this function pure, so the order
    itself is testable without a database, and lets a caller that has already
    read the row (the admin API) resolve without a second read.
    """
    from . import settings                      # late: settings imports this module lazily too

    cfg = stored() if cfg is None else cfg
    row = cfg.is_stored

    provider = cfg.provider if row else (settings.ADVISORY_PROVIDER or "auto")
    provider_origin = ORIGIN_DATABASE if row else (
        ORIGIN_ENVIRONMENT if settings.ADVISORY_PROVIDER else ORIGIN_DEFAULT)

    if row:
        # Whole-block, not field-by-field -- see the module docstring.
        endpoint = cfg.azure_endpoint or ""
        deployment = cfg.azure_deployment or ""
        api_version = cfg.azure_api_version or DEFAULT_AZURE_API_VERSION
        auth_mode = cfg.azure_auth_mode or "identity"
        client_id = cfg.azure_client_id
        azure_origin = ORIGIN_DATABASE
    else:
        endpoint = settings.AZURE_AI_ENDPOINT
        deployment = settings.AZURE_AI_DEPLOYMENT
        api_version = settings.AZURE_AI_API_VERSION or DEFAULT_AZURE_API_VERSION
        auth_mode = settings.AZURE_AI_AUTH_MODE or "identity"
        client_id = settings.AZURE_AI_CLIENT_ID or None
        azure_origin = ORIGIN_ENVIRONMENT if (endpoint or deployment) else ORIGIN_DEFAULT

    safe_endpoint, endpoint_error = _safe_endpoint(endpoint)
    return Resolved(
        provider=(provider or "auto").strip().lower(),
        provider_origin=provider_origin,
        azure_endpoint=safe_endpoint,
        azure_deployment=(deployment or "").strip(),
        azure_api_version=api_version,
        azure_auth_mode=auth_mode,
        azure_client_id=client_id,
        azure_origin=azure_origin,
        config_source=cfg.source,
        azure_endpoint_error=endpoint_error,
    )


# Last endpoint rejection logged, so a permanently malformed AZURE_AI_ENDPOINT
# says so once rather than on every model call. Same idiom as the ollama probe.
_ENDPOINT_REPORTED: dict[str, Any] = {"value": None}


def _safe_endpoint(value: str) -> tuple[str, str | None]:
    """`(endpoint, why_it_was_rejected)` — never raises.

    `save()` validates before storing, so a row written through the product is
    already good. This path exists for the two that are not: an `AZURE_AI_ENDPOINT`
    typed into a container spec, and a row written by hand with psql. Neither may
    turn every model call in the product into a 500.
    """
    raw = (value or "").strip()
    if not raw:
        return "", None
    try:
        return _normalize_endpoint(raw), None
    except AiConfigError as exc:
        if _ENDPOINT_REPORTED["value"] != raw:
            _ENDPOINT_REPORTED["value"] = raw
            log.error("the configured Azure endpoint is not usable as one; the Azure provider "
                      "is unavailable and model-backed capabilities will use their "
                      "deterministic fallback",
                      extra={"event": "ai_config_bad_endpoint", "error": str(exc)})
        return "", str(exc)


def azure_ready(r: Resolved) -> tuple[bool, str | None]:
    """`(usable, why_not)` for a resolved Azure target.

    "Configured" and "will actually work" are different questions and conflating
    them is how a missing secret becomes 401s that read to a user as a weak
    model. Pure, and takes the `Resolved` rather than reading it, so
    `active_provider()` can ask without a second database read on every model
    call.
    """
    from . import settings

    if r.azure_endpoint_error:
        return False, f"the configured Azure endpoint is unusable: {r.azure_endpoint_error}"
    if not r.azure_endpoint:
        return False, "no Azure endpoint is configured"
    if not r.azure_deployment:
        return False, "no Azure model deployment is configured"
    if r.azure_auth_mode == "key" and not settings.AZURE_AI_API_KEY:
        return False, ("azure_auth_mode is 'key' but AZURE_AI_API_KEY is not set in this "
                       "deployment's environment (keys are never stored in the database; "
                       "put it in a Container Apps secret)")
    return True, None


def azure_status() -> dict[str, Any]:
    """The Azure half of the configuration as an API payload, with readiness.

    Surfaced by the Configuration page and `/api/health` so an operator can see
    both what is configured and whether it can make a call.
    """
    r = resolve()
    ready, reason = azure_ready(r)
    return {
        "endpoint": r.azure_endpoint,
        "deployment": r.azure_deployment,
        "api_version": r.azure_api_version,
        "auth_mode": r.azure_auth_mode,
        "client_id": r.azure_client_id,
        "origin": r.azure_origin,
        "config_source": r.config_source,
        "ready": ready,
        "reason": reason,
    }


# --------------------------------------------------------------------------
# writing
# --------------------------------------------------------------------------

def _normalize_endpoint(value: str) -> str:
    """A trimmed endpoint with exactly one trailing slash, validated.

    Rejects (rather than silently strips) a query string, a fragment or embedded
    credentials: an operator who pastes `https://acct.../?api-key=...` out of a
    portal has just tried to put a secret in this table, and quietly deleting it
    would leave them believing the key was saved. Rejects plaintext http to
    anything but a loopback host -- the payloads are firewall rules and asset
    names.
    """
    raw = (value or "").strip()
    if not raw:
        raise AiConfigError("azure_endpoint is empty")
    parts = urlsplit(raw)
    if parts.scheme not in ("http", "https"):
        raise AiConfigError(
            f"azure_endpoint must be an http(s) URL, e.g. "
            f"https://<account>.cognitiveservices.azure.com/ (got {raw!r})")
    if not parts.hostname:
        raise AiConfigError(f"azure_endpoint has no host: {raw!r}")
    if parts.query or parts.fragment:
        raise AiConfigError(
            "azure_endpoint must not carry a query string or fragment. If you pasted a URL "
            "containing an api-key, remove it: keys are never stored in the database -- put "
            "it in this deployment's AZURE_AI_API_KEY environment variable instead.")
    if parts.username or parts.password:
        raise AiConfigError(
            "azure_endpoint must not embed credentials (user:password@host). Use "
            "azure_auth_mode='identity', or put a key in AZURE_AI_API_KEY.")
    if parts.scheme == "http" and parts.hostname.lower() not in _PLAINTEXT_OK_HOSTS:
        raise AiConfigError(
            f"azure_endpoint must use https for a remote host (got http://{parts.hostname}). "
            f"This product sends firewall rules, asset names and reachability paths to the "
            f"model; plaintext is not a configuration choice.")
    path = parts.path.rstrip("/")
    return f"{parts.scheme}://{parts.netloc}{path}/"


def validate(cfg: AiConfig) -> AiConfig:
    """Normalize and check a configuration, or raise `AiConfigError`.

    Every rule here is also a database constraint (see the migration), so the
    store is safe without this function; it exists so the API layer can answer
    400 with a sentence naming the field instead of surfacing a constraint name,
    and so the URL-shaped fields -- which the provider interpolates into a
    request path -- are checked before they are stored rather than after.
    """
    provider = (cfg.provider or "auto").strip().lower()
    if provider not in PROVIDERS:
        raise AiConfigError(f"provider must be one of {PROVIDERS}, got {cfg.provider!r}")

    auth_mode = (cfg.azure_auth_mode or "identity").strip().lower()
    if auth_mode not in AZURE_AUTH_MODES:
        raise AiConfigError(
            f"azure_auth_mode must be one of {AZURE_AUTH_MODES}, got {cfg.azure_auth_mode!r}")

    endpoint = _normalize_endpoint(cfg.azure_endpoint) if (cfg.azure_endpoint or "").strip() else None

    deployment = (cfg.azure_deployment or "").strip() or None
    if deployment and not _DEPLOYMENT_RE.match(deployment):
        raise AiConfigError(
            f"azure_deployment must be a deployment name (letters, digits, '.', '_', '-'), "
            f"got {cfg.azure_deployment!r}. Note this is the DEPLOYMENT name on the account, "
            f"not the model name -- they often differ.")

    api_version = (cfg.azure_api_version or "").strip() or None
    if api_version and not _API_VERSION_RE.match(api_version):
        raise AiConfigError(
            f"azure_api_version must look like '2024-10-21' or '2024-05-01-preview', "
            f"got {cfg.azure_api_version!r}")

    client_id = (cfg.azure_client_id or "").strip() or None
    if client_id and not _UUID_RE.match(client_id):
        raise AiConfigError(
            f"azure_client_id must be the GUID of a user-assigned managed identity, got "
            f"{cfg.azure_client_id!r}. Leave it empty to let DefaultAzureCredential choose.")

    if provider == "azure" and not (endpoint and deployment):
        missing = " and ".join(
            n for n, v in (("an endpoint", endpoint), ("a model deployment", deployment)) if not v)
        raise AiConfigError(
            f"provider 'azure' needs {missing}. A half-configured Azure provider routes every "
            f"model call at nothing and degrades to the deterministic fallback, which reads to "
            f"a user as a weak model rather than an unfinished form.")

    return replace(cfg, provider=provider, azure_endpoint=endpoint, azure_deployment=deployment,
                   azure_api_version=api_version, azure_auth_mode=auth_mode,
                   azure_client_id=client_id)


def write_row(cur: psycopg.Cursor, cfg: AiConfig, actor: str | None) -> None:
    """The UPSERT, against a cursor the caller owns. See `read_row` for why."""
    upsert(cur, TABLE, {
        "id": True,                                   # the singleton key
        "provider": cfg.provider,
        "azure_endpoint": cfg.azure_endpoint,
        "azure_deployment": cfg.azure_deployment,
        "azure_api_version": cfg.azure_api_version,
        "azure_auth_mode": cfg.azure_auth_mode,
        "azure_client_id": cfg.azure_client_id,
        "configured_by": actor,
        # Explicit rather than left to the column's `DEFAULT now()`: the default
        # only fires on INSERT, and every save after the first is the UPDATE half
        # of the upsert -- so relying on it would leave `updated_at` frozen at
        # the moment the row was first created while `configured_by` changed
        # underneath it. Timezone-aware, so the value is unambiguous whatever the
        # container's TZ happens to be. (This is configuration, not the
        # deterministic fact path, which still contains no clock.)
        "updated_at": datetime.now().astimezone(),
    }, ["id"])


def save(cfg: AiConfig, actor: str | None = None) -> AiConfig:
    """Validate and store the configuration; return it as it was written.

    `actor` defaults to the request context's email, the same way `db.audit()`
    reads its identity rather than taking it as an argument -- a call site
    cannot forget an attribution it does not have to pass.

    The change is audited in the SAME transaction as the write, so the row and
    the record of who changed it can never disagree. This happens here rather
    than in the route so that every path that reconfigures the provider is on
    the compliance record, including a future CLI or a second endpoint.

    Raises `AiConfigError` for a configuration the store refuses (map to 400)
    and `AiConfigUnavailable` when the write cannot be made (map to 503).
    """
    cfg = validate(cfg)
    if not db.DATABASE_URL:
        raise AiConfigUnavailable(
            "no DATABASE_URL is configured, so there is nowhere to store the AI "
            "configuration. Set DATABASE_URL, or configure the provider through the "
            "environment (ADVISORY_PROVIDER / AZURE_AI_*).")
    who = actor if actor is not None else request_ctx.current().email
    try:
        with get_conn() as conn, conn.cursor() as cur:
            write_row(cur, cfg, who)
            db.audit(cur, "ai_config_saved", subject=cfg.provider, detail={
                "provider": cfg.provider,
                "azure_endpoint": cfg.azure_endpoint,
                "azure_deployment": cfg.azure_deployment,
                "azure_api_version": cfg.azure_api_version,
                "azure_auth_mode": cfg.azure_auth_mode,
                "azure_client_id": cfg.azure_client_id,
            })
            saved = read_row(cur)
    except psycopg.IntegrityError as exc:
        # A constraint refused the row. `validate()` mirrors every CHECK on the
        # table, so this should be unreachable -- but if the two ever drift, the
        # honest answer is still "your input was rejected" (400), not "the store
        # is unavailable" (503). Classifying a bad request as an outage sends an
        # operator to look at the database instead of at the form they submitted.
        raise AiConfigError(
            f"the database refused this configuration: {exc}. This means "
            f"src/ai_config.validate() and the CHECK constraints in "
            f"db/migrations/0004_ai_config.sql have drifted apart."
        ) from exc
    except _STORE_ERRORS as exc:
        raise AiConfigUnavailable(
            f"could not write {DB_SCHEMA}.{TABLE}: {type(exc).__name__}: {exc}. "
            f"If the table is missing, run `python db/migrate.py`."
        ) from exc
    invalidate()
    return saved
