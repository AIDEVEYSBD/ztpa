"""Centralized configuration. Loads the repo-root .env and exposes typed env
access for the DB and the provider-pluggable AI layer.

Provider routing: Ollama is the local-dev default (no key, offline, keeps the
sensitive topology on the box). If a hosted key is present and the provider is
'auto', we upgrade the highest-stakes judgment to that provider.
"""

from __future__ import annotations

import os
from pathlib import Path

from dotenv import load_dotenv

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
# (or goes down) mid-session is picked up within the window.
_OLLAMA_PROBE: dict = {"checked_at": 0.0, "ok": False}
_OLLAMA_PROBE_TTL: float = 30.0  # seconds


def ollama_available() -> bool:
    """True when a local Ollama server is reachable AND serving ≥1 model.

    'auto' uses this to decide whether a local model exists to leverage; if the
    server is down or has no models pulled, we fall back to a hosted key.
    """
    import time

    now = time.monotonic()
    if now - _OLLAMA_PROBE["checked_at"] < _OLLAMA_PROBE_TTL:
        return _OLLAMA_PROBE["ok"]

    ok = False
    try:
        import httpx

        r = httpx.get(f"{OLLAMA_HOST}/api/tags", timeout=2.0)
        ok = r.status_code == 200 and bool(r.json().get("models"))
    except Exception:
        ok = False

    _OLLAMA_PROBE.update(checked_at=now, ok=ok)
    return ok


def active_provider() -> str:
    """Resolve which chat provider to use for judgment jobs.

    Explicit ADVISORY_PROVIDER wins. Under 'auto' we leverage a local model when
    one exists (Ollama reachable + a model pulled), else fall back to a hosted
    key — OpenAI first, then Anthropic. If nothing is available we still return
    'ollama' so callers degrade to the deterministic engine fallback.
    """
    if ADVISORY_PROVIDER in ("ollama", "anthropic", "openai"):
        return ADVISORY_PROVIDER
    if ollama_available():
        return "ollama"
    if has_openai():
        return "openai"
    if has_anthropic():
        return "anthropic"
    return "ollama"
