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
# fall back to a hosted key — OpenAI first, then Anthropic. Force a single
# provider with ADVISORY_PROVIDER=ollama|anthropic|openai.
ADVISORY_PROVIDER: str = os.environ.get("ADVISORY_PROVIDER", "auto").strip().lower()

OLLAMA_HOST: str = os.environ.get("OLLAMA_HOST", "http://localhost:11434").rstrip("/")
OLLAMA_JUDGE_MODEL: str = os.environ.get("OLLAMA_JUDGE_MODEL", "qwen3-coder:30b")
OLLAMA_PROSE_MODEL: str = os.environ.get("OLLAMA_PROSE_MODEL", "qwen3-coder:30b")
OLLAMA_EMBED_MODEL: str = os.environ.get("OLLAMA_EMBED_MODEL", "nomic-embed-text")
OLLAMA_TIMEOUT: float = float(os.environ.get("OLLAMA_TIMEOUT", "600"))

ANTHROPIC_API_KEY: str = os.environ.get("ANTHROPIC_API_KEY", "").strip()
ANTHROPIC_MODEL: str = os.environ.get("ADVISORY_MODEL", "claude-sonnet-4-6")

OPENAI_API_KEY: str = os.environ.get("OPENAI_API_KEY", "").strip()
OPENAI_MODEL: str = os.environ.get("OPENAI_MODEL", "gpt-4o")

# --- Misc ------------------------------------------------------------------
FRONTEND_ORIGIN: str = os.environ.get("FRONTEND_ORIGIN", "http://localhost:3000")
DEFAULT_SNAPSHOT_LABEL: str = "seed-demo"


def has_anthropic() -> bool:
    return bool(ANTHROPIC_API_KEY)


def has_openai() -> bool:
    return bool(OPENAI_API_KEY)


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
    missing = tuple(m for m in _configured_ollama_models() if m not in models)
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
_AUTO_ROUTE: dict = {"reported": None}


def active_provider() -> str:
    """Resolve which chat provider to use for judgment jobs.

    Explicit ADVISORY_PROVIDER wins. Under 'auto' we leverage a local model when
    one exists (Ollama reachable + a model pulled), else fall back to a hosted
    key — OpenAI first, then Anthropic. If nothing is available we still return
    'ollama' so callers degrade to the deterministic engine fallback.

    Under 'auto' the choice is announced when it changes. Escalating from
    'ollama' to a hosted provider is not a detail: it moves the customer's
    topology off the box (`provider_status.data_residency` flips to "hosted")
    and it switches the assistant's tool-calling loop off, since that loop is
    implemented for Ollama only. An operator must be able to see the moment that
    happened without diffing a status payload they never fetched.
    """
    if ADVISORY_PROVIDER in ("ollama", "anthropic", "openai"):
        return ADVISORY_PROVIDER
    if ollama_available():
        chosen, why, warn = "ollama", "a local model is reachable", False
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
