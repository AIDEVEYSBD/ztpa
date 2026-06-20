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
# auto -> prefer a hosted key for judgment if present, else Ollama; everything
# else stays local. Force a single provider with ADVISORY_PROVIDER=ollama|anthropic|openai.
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


def active_provider() -> str:
    """Resolve which chat provider to use for judgment jobs."""
    if ADVISORY_PROVIDER in ("ollama", "anthropic", "openai"):
        return ADVISORY_PROVIDER
    # auto: prefer the strongest available hosted model, else local.
    if has_anthropic():
        return "anthropic"
    if has_openai():
        return "openai"
    return "ollama"
