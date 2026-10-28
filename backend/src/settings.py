"""Centralized configuration. Loads the repo-root .env and exposes typed env
access for the DB and the provider-pluggable AI layer.

Provider routing: Ollama is the local-dev default (no key, offline, keeps the
sensitive topology on the box). If a hosted key is present and the provider is
'auto', we upgrade the highest-stakes judgment to that provider.

ROUTING DECISIONS ARE ANNOUNCED, NOT INFERRED
---------------------------------------------
Two of this module's decisions change what the product *is*, and both used to be
invisible:

  * `ollama_probe` answered "reachable" if ANY model is pulled, not the
    configured tag. A developer who ran `ollama pull qwen3-coder` gets `:latest`
    while `OLLAMA_JUDGE_MODEL` is `qwen3-coder:30b`: the probe says local, the
    residency badge says local, and every model call then fails at request time
    and lands on deterministic fallback. The probe's answer is deliberately
    unchanged (routing is not this workstream's to move), but a configured tag
    that is not present is now named in the log the moment it is observed.
  * under `auto`, a failed probe silently escalates to a HOSTED provider --
    which moves the customer's topology off the box and, for the assistant,
    switches off tool calling entirely. That transition is now logged.

Both log on CHANGE rather than per call: `active_provider()` runs on every model
call, and a line per call would bury the transition it exists to show.

ROUTING IS NO LONGER ENVIRONMENT-ONLY
-------------------------------------
`ADVISORY_PROVIDER` is now the SECOND source consulted, not the first. An
operator can select a provider in the product (Configuration page ->
`ztpa.ai_config`, one row, attributable), and that stored choice wins over an
environment variable baked into a container spec. The full order, and the
reasoning for it, is in `src/ai_config.py`'s docstring -- this module holds the
environment half and defers to that module for the resolution.

Two consequences worth stating here, where the constants are:

  * every `AZURE_AI_*` value below is a FALLBACK, used when no row has been
    stored. `AZURE_AI_API_KEY` is the exception and is never overridden,
    because secrets are environment-only by rule: `ztpa.ai_config` has no
    column that could hold one.
  * `active_provider()` therefore reads the database (cached, 30s, same idiom
    as `ollama_probe`). It still never raises: an unreadable store degrades to
    this module's environment values and says so, loudly, once.
"""

from __future__ import annotations

import logging
import os
from pathlib import Path

from dotenv import load_dotenv

# Child of the API logger; see advisory/client.py for the convention.
log = logging.getLogger("npr.api.settings")

REPO_ROOT = Path(__file__).resolve().parents[2]
BACKEND_ROOT = Path(__file__).resolve().parents[1]
load_dotenv(REPO_ROOT / ".env")

# --- Database (Neon Postgres, system of record) ---------------------------
DATABASE_URL: str = os.environ.get("DATABASE_URL", "")
DB_SCHEMA: str = "ztpa"

# --- AI provider routing ---------------------------------------------------
# auto -> leverage a LOCAL model when Ollama is actually running and serving a
# model (sensitive topology never leaves the box, zero per-call cost); otherwise
# fall back to the customer's OWN Azure AI Foundry deployment if one is
# configured, and only then to a third-party hosted key — OpenAI, then
# Anthropic. Force a single provider with
# ADVISORY_PROVIDER=ollama|azure|vertex|openai|anthropic. On a cloud platform
# (see `platform()`) `auto` prefers that platform's native provider first.
# `vertex` is chosen by `auto` ONLY on GCP: ADC is present on every developer
# machine with gcloud, so routing to it locally would move topology off the box
# by accident.
#
# This is the DEFAULT, consulted when no configuration row has been stored; a
# row selected through the Configuration page wins (see src/ai_config.py).
ADVISORY_PROVIDER: str = os.environ.get("ADVISORY_PROVIDER", "auto").strip().lower()

# The providers that name one destination. `auto` is everything else: it is not
# a provider, it is the instruction to pick one, and every branch that treats it
# as a name has to be able to tell the difference.
EXPLICIT_PROVIDERS: tuple[str, ...] = ("ollama", "azure", "vertex", "anthropic", "openai")

OLLAMA_HOST: str = os.environ.get("OLLAMA_HOST", "http://localhost:11434").rstrip("/")
OLLAMA_JUDGE_MODEL: str = os.environ.get("OLLAMA_JUDGE_MODEL", "qwen3-coder:30b")
OLLAMA_PROSE_MODEL: str = os.environ.get("OLLAMA_PROSE_MODEL", "qwen3-coder:30b")
OLLAMA_EMBED_MODEL: str = os.environ.get("OLLAMA_EMBED_MODEL", "nomic-embed-text")
OLLAMA_TIMEOUT: float = float(os.environ.get("OLLAMA_TIMEOUT", "600"))

ANTHROPIC_API_KEY: str = os.environ.get("ANTHROPIC_API_KEY", "").strip()
ANTHROPIC_MODEL: str = os.environ.get("ADVISORY_MODEL", "claude-sonnet-4-6")

OPENAI_API_KEY: str = os.environ.get("OPENAI_API_KEY", "").strip()
OPENAI_MODEL: str = os.environ.get("OPENAI_MODEL", "gpt-4o")

# --- Azure AI Foundry ------------------------------------------------------
# The customer's OWN model deployment, inside their tenant, their subscription
# and their region. Everything here except the key is a FALLBACK for the stored
# configuration row (src/ai_config.py); the key is environment-only, always,
# because ztpa.ai_config has no column that could hold one and must never grow
# one.
#
# The endpoint is the account's data-plane host as
# `az cognitiveservices account show` reports it, e.g.
# https://<account>.cognitiveservices.azure.com/. The deployment is the
# DEPLOYMENT name on that account, which is not always the model name.
AZURE_AI_ENDPOINT: str = os.environ.get("AZURE_AI_ENDPOINT", "").strip()
AZURE_AI_DEPLOYMENT: str = os.environ.get("AZURE_AI_DEPLOYMENT", "").strip()
AZURE_AI_API_VERSION: str = os.environ.get("AZURE_AI_API_VERSION", "").strip()
# 'identity' (the app's managed identity, no secret anywhere) | 'key'.
AZURE_AI_AUTH_MODE: str = os.environ.get("AZURE_AI_AUTH_MODE", "").strip().lower()
# Optional USER-ASSIGNED managed identity client id. Empty = let
# DefaultAzureCredential choose, which is what works both in the deployed app
# and against a developer's `az login`.
AZURE_AI_CLIENT_ID: str = os.environ.get("AZURE_AI_CLIENT_ID", "").strip()
# The secret, for azure_auth_mode='key' only. A Container Apps secret surfaced
# as an environment variable — never a database column, never a request body
# that gets echoed back.
AZURE_AI_API_KEY: str = os.environ.get("AZURE_AI_API_KEY", "").strip()

# AAD scopes. Constants rather than literals scattered through the call sites,
# and overridable for a sovereign cloud (Azure Government / China), where both
# hosts differ.
#   - the data plane (chat completions on a Cognitive Services / AIServices
#     account) is guarded by the cognitiveservices scope;
#   - ARM (listing resource groups, accounts and deployments for the
#     Configuration page's dropdowns) is guarded by the management scope.
AZURE_AI_SCOPE: str = os.environ.get(
    "AZURE_AI_SCOPE", "https://cognitiveservices.azure.com/.default").strip()
AZURE_ARM_ENDPOINT: str = os.environ.get(
    "AZURE_ARM_ENDPOINT", "https://management.azure.com").rstrip("/")
AZURE_ARM_SCOPE: str = os.environ.get(
    "AZURE_ARM_SCOPE", "https://management.azure.com/.default").strip()
# Which subscription discovery enumerates. Empty = ask ARM for the ones the
# credential can see rather than guessing one.
AZURE_SUBSCRIPTION_ID: str = os.environ.get("AZURE_SUBSCRIPTION_ID", "").strip()

# --- Google Vertex AI ------------------------------------------------------
# The GCP counterpart of the Azure block above: a model in the customer's OWN
# project, reached with Application Default Credentials -- the Cloud Run service
# account in a deployment, `gcloud auth application-default login` on a
# developer machine. No key exists to store. Environment-only for now: the
# stored configuration row selects the provider but holds no Vertex fields.
#
# VERTEX_PROJECT empty = the project ADC reports (GOOGLE_CLOUD_PROJECT, then the
# gcloud config). VERTEX_LOCATION 'global' uses the global endpoint, which has
# the widest model availability; a region pins data processing to it.
VERTEX_PROJECT: str = os.environ.get("VERTEX_PROJECT", "").strip()
VERTEX_LOCATION: str = os.environ.get("VERTEX_LOCATION", "global").strip() or "global"
# Publisher-qualified, as Vertex's OpenAI-compatible endpoint expects.
VERTEX_MODEL: str = os.environ.get("VERTEX_MODEL", "google/gemini-2.5-pro").strip()

# --- Hosting platform ------------------------------------------------------
# Which cloud this process runs on decides the NATIVE AI provider `auto` prefers:
# Vertex AI on GCP, Azure AI Foundry on Azure. 'auto' detects it from the
# variables each runtime injects; set NPR_PLATFORM to override (e.g. on GKE/AKS,
# which inject neither). BYOK keys (OPENAI_API_KEY, ANTHROPIC_API_KEY,
# AZURE_AI_API_KEY, or a service-account file in GOOGLE_APPLICATION_CREDENTIALS)
# still work on any platform: an explicit ADVISORY_PROVIDER selects them, and
# `auto` falls back to them when the native provider is not usable.
NPR_PLATFORM: str = os.environ.get("NPR_PLATFORM", "auto").strip().lower() or "auto"
PLATFORMS: tuple[str, ...] = ("gcp", "azure", "local")


def platform() -> str:
    if NPR_PLATFORM in PLATFORMS:
        return NPR_PLATFORM
    if os.environ.get("K_SERVICE") or os.environ.get("CLOUD_RUN_JOB"):
        return "gcp"
    if os.environ.get("CONTAINER_APP_NAME"):
        return "azure"
    return "local"


def byok_keys() -> list[str]:
    """Names (never values) of the bring-your-own-key secrets present."""
    names = ("OPENAI_API_KEY", "ANTHROPIC_API_KEY", "AZURE_AI_API_KEY",
             "GOOGLE_APPLICATION_CREDENTIALS")
    return [n for n in names if os.environ.get(n, "").strip()]


def _vertex_ok() -> bool:
    from .advisory.client import vertex_ready   # late: client imports this module
    return vertex_ready()[0]


# --- Misc ------------------------------------------------------------------
FRONTEND_ORIGIN: str = os.environ.get("FRONTEND_ORIGIN", "http://localhost:3000")
DEFAULT_SNAPSHOT_LABEL: str = "seed-demo"


def has_anthropic() -> bool:
    return bool(ANTHROPIC_API_KEY)


def has_openai() -> bool:
    return bool(OPENAI_API_KEY)


def azure_target():
    """The resolved Azure target (`ai_config.Resolved`): endpoint, deployment,
    api-version, auth mode, client id, and where each came from.

    A thin accessor so the provider client and the status payload have one place
    to read from and never have to know whether the answer came from the stored
    row or from this module's environment values. The read underneath is cached
    for 30s, so calling it per request is fine.

    Imported late: `ai_config` imports THIS module at its own module scope, so a
    top-level import here would be a cycle. The direction is deliberate --
    settings is the low-level environment layer and ai_config is the policy on
    top of it; the arrow only points down at import time.
    """
    from . import ai_config
    return ai_config.resolve()


def has_azure() -> bool:
    """True when an Azure AI Foundry deployment is configured AND usable.

    'Usable' rather than merely 'set': a configuration that selects key auth on a
    deployment with no `AZURE_AI_API_KEY` in its environment is complete on the
    Configuration page and cannot make one call, and letting `auto` route to it
    would turn a missing secret into 401s that read to a user as a weak model.
    `ai_config.azure_status()` carries the reason as a sentence for the UI.
    """
    from . import ai_config
    return ai_config.azure_ready(azure_target())[0]


# Probe the local Ollama server at most once per TTL so routing decisions don't
# pay a network round-trip on every LLM call. Re-checked so a model that comes up
# (or goes down) mid-session is picked up within the window. The probe caches the
# model list too, so the status banner reuses it instead of re-hitting Ollama.
# `reported` holds the last (ok, missing-tags, error) tuple actually logged, so
# a 30s-TTL probe against a permanently-down server logs the outage once instead
# of twice a minute forever. None means "nothing reported yet".
_OLLAMA_PROBE: dict = {"checked_at": 0.0, "ok": False, "models": [], "reported": None}
_OLLAMA_PROBE_TTL: float = 30.0    # seconds
_OLLAMA_PROBE_TIMEOUT: float = 1.5  # seconds — a down server should fail fast


def _configured_ollama_models() -> list[str]:
    """The model tags this deployment actually asks Ollama for, deduped+sorted."""
    return sorted({OLLAMA_JUDGE_MODEL, OLLAMA_PROSE_MODEL, OLLAMA_EMBED_MODEL})


def _report_probe(ok: bool, models: list[str], error: str | None) -> None:
    """Log the probe's outcome, but only when it differs from the last one logged.

    Three distinct states, because they have three distinct fixes: the server is
    unreachable (start it / fix OLLAMA_HOST), the server is up but serving none
    of the configured tags (`ollama pull <tag>` -- the case that reads as
    "everything is local" while every capability is on fallback), and healthy.
    """
    # Ollama reports an untagged pull as `name:latest` and takes a bare `name`
    # as a request for it, so a plain string comparison called
    # `nomic-embed-text` missing while it was pulled and serving. The warning
    # that produced says every capability is on deterministic fallback, which
    # was false -- and a false degradation notice is worse than none, because it
    # is the notice an operator acts on.
    def _tags(m: str) -> set[str]:
        return {m, f"{m}:latest"} if ":" not in m else {m}
    have = set(models)
    missing = tuple(m for m in _configured_ollama_models() if not (_tags(m) & have))
    state = (ok, missing, error)
    if _OLLAMA_PROBE["reported"] == state:
        return
    _OLLAMA_PROBE["reported"] = state
    if not ok:
        log.warning("local model server unavailable; provider routing will fall back",
                    extra={"event": "ollama_unreachable", "host": OLLAMA_HOST,
                           "error": error, "models": models})
    elif missing:
        # The dangerous one: `ollama_available()` is True, the residency badge
        # says "local", and every call for one of these tags fails at request
        # time and degrades to deterministic output.
        log.warning("local model server is up but the configured model tags are not pulled; "
                    "those capabilities will degrade to deterministic fallback at call time",
                    extra={"event": "ollama_model_missing", "host": OLLAMA_HOST,
                           "missing": list(missing), "available": models})
    else:
        log.info("local model server healthy", extra={"event": "ollama_ready",
                                                      "host": OLLAMA_HOST, "models": models})


def ollama_probe() -> tuple[bool, list[str]]:
    """(reachable_with_models, sorted_model_names), cached for the TTL.

    One shared probe for both routing (`ollama_available`) and the status banner
    (`provider_status`), so a down Ollama costs at most one short timeout per TTL
    instead of a multi-second hang on every call."""
    import time

    now = time.monotonic()
    if now - _OLLAMA_PROBE["checked_at"] < _OLLAMA_PROBE_TTL:
        return _OLLAMA_PROBE["ok"], _OLLAMA_PROBE["models"]

    # Still imported lazily (settings is imported very early), but no longer
    # inside the try: httpx is a hard dependency -- requirements.txt lists it and
    # advisory/client.py imports it at module scope -- so it cannot be missing in
    # a working install, and an ImportError naming it is a far better answer than
    # reporting a broken install as "your model server is down".
    import httpx

    ok, models, error = False, [], None
    try:
        r = httpx.get(f"{OLLAMA_HOST}/api/tags", timeout=_OLLAMA_PROBE_TIMEOUT)
        if r.status_code == 200:
            models = sorted(m["name"] for m in r.json().get("models", []))
            ok = bool(models)
            if not ok:
                error = "the server answered 200 with no models pulled"
        else:
            error = f"HTTP {r.status_code} from {OLLAMA_HOST}/api/tags"
    except (httpx.HTTPError, ValueError, TypeError, KeyError, AttributeError) as e:
        # Narrow on purpose. httpx.HTTPError covers connect/timeout/read
        # failures; ValueError a 200 whose body is not JSON; TypeError/KeyError/
        # AttributeError a 200 whose JSON is not the documented
        # {"models": [{"name": ...}]} shape. `except Exception` would also
        # swallow a defect in this function and report it to the operator as
        # "your model server is down".
        ok, models, error = False, [], f"{type(e).__name__}: {e}"

    _OLLAMA_PROBE.update(checked_at=now, ok=ok, models=models)
    _report_probe(ok, models, error)
    return ok, models


def ollama_available() -> bool:
    """True when a local Ollama server is reachable AND serving ≥1 model.

    'auto' uses this to decide whether a local model exists to leverage; if the
    server is down or has no models pulled, we fall back to a hosted key.
    """
    return ollama_probe()[0]


# Last provider `auto` resolved to, so the escalation is logged on transition
# rather than once per model call. A concurrent double-log is possible and
# harmless; a lock on a routing decision this hot is not worth the contention.
# `unusable` is the same idea for an EXPLICIT selection that cannot work.
_AUTO_ROUTE: dict = {"reported": None, "unusable": None}


def active_provider() -> str:
    """Resolve which chat provider to use for judgment jobs.

    An explicit selection wins — from the stored configuration row first, then
    from ADVISORY_PROVIDER (see `ai_config.resolve` for the order and why it is
    that way). Under 'auto' we leverage a local model when one exists (Ollama
    reachable + a model pulled), else the customer's own Azure AI Foundry
    deployment, else a third-party hosted key — OpenAI first, then Anthropic. If
    nothing is available we still return 'ollama' so callers degrade to the
    deterministic engine fallback.

    WHY AZURE SITS FIRST AMONG THE HOSTED OPTIONS. All three are "hosted" in the
    sense the residency chip means — the topology leaves this box — but they are
    not equivalent, and `auto` exists to pick the least-bad available option:

      * an Azure Foundry deployment is the CUSTOMER'S OWN resource, in their
        subscription, their tenant and their region, reached over their network
        boundary. OpenAI and Anthropic are third parties under someone else's
        contract. When both are available, sending a firewall topology to the
        customer's own resource is strictly the smaller disclosure.
      * it is the only hosted option that works with NO STORED SECRET: managed
        identity is the default auth mode, so preferring it also prefers the
        path with no key to leak.
      * it can only be reached by a DELIBERATE act — an endpoint and a deployment
        chosen on the Configuration page, or set in the container spec — whereas
        `OPENAI_API_KEY` is routinely present in a developer's environment by
        accident. A configured target should outrank an incidental key.

    Under 'auto' the choice is announced when it changes. Escalating from
    'ollama' to a hosted provider is not a detail: it moves the customer's
    topology off the box (`provider_status.data_residency` flips to "hosted")
    and it switches the assistant's tool-calling loop off, since that loop is
    implemented for Ollama only. An operator must be able to see the moment that
    happened without diffing a status payload they never fetched.
    """
    from . import ai_config

    resolved = azure_target()          # one read; both branches below use it
    azure_ok, azure_why = ai_config.azure_ready(resolved)

    if resolved.provider in EXPLICIT_PROVIDERS:
        # An explicit choice is honoured even when it cannot work: substituting a
        # provider nobody chose is precisely the silent failure this module was
        # rewritten to stop. It is said out loud instead, once per transition.
        if resolved.provider == "azure" and not azure_ok:
            if _AUTO_ROUTE["unusable"] != azure_why:
                _AUTO_ROUTE["unusable"] = azure_why
                log.warning("the selected provider cannot make a call; every model-backed "
                            "capability will degrade to its deterministic fallback",
                            extra={"event": "provider_unusable", "provider": "azure",
                                   "reason": azure_why, "origin": resolved.provider_origin,
                                   "config_source": resolved.config_source})
        else:
            _AUTO_ROUTE["unusable"] = None
        return resolved.provider

    plat = platform()
    if plat == "gcp" and _vertex_ok():
        # The platform's own model service, in the customer's own project. This
        # is the one place `auto` may pick vertex: on Cloud Run, ADC is the
        # service account somebody deliberately granted, not a developer's login.
        chosen, why, warn = "vertex", "running on GCP; using the project's Vertex AI", False
    elif plat == "azure" and azure_ok:
        chosen, why, warn = ("azure", "running on Azure; using the subscription's AI Foundry "
                             f"deployment ({resolved.azure_deployment})", False)
    elif ollama_available():
        chosen, why, warn = "ollama", "a local model is reachable", False
    elif azure_ok:
        chosen, why, warn = ("azure",
                             "no local model; an Azure AI Foundry deployment is configured "
                             f"({resolved.azure_deployment})", True)
    elif has_openai():
        chosen, why, warn = "openai", "no local model; OPENAI_API_KEY is set", True
    elif has_anthropic():
        chosen, why, warn = "anthropic", "no local model; ANTHROPIC_API_KEY is set", True
    else:
        # No provider at all. Still 'ollama' so every capability takes its
        # deterministic fallback rather than a hosted path that cannot work.
        chosen, why, warn = ("ollama",
                             "no provider available; capabilities will use deterministic fallback",
                             True)
    if _AUTO_ROUTE["reported"] != (chosen, why):
        _AUTO_ROUTE["reported"] = (chosen, why)
        # WARNING for either kind of departure from the intended posture --
        # topology leaving the box, or no model at all -- INFO for the happy path.
        (log.warning if warn else log.info)(
            "provider routing resolved", extra={
                "event": "provider_route", "provider": chosen, "reason": why,
                "residency": "local" if chosen == "ollama" else "hosted",
                "tool_calling": chosen == "ollama"})
    return chosen
