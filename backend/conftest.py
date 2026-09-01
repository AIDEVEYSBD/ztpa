"""Offline guard rails for the backend test suite.

pytest loads this automatically for everything under `backend/tests`. The suite
is a *unit* suite: it stubs the model client and asserts on the deterministic
engine, so it has no business opening a socket. Three seams are closed here,
each for a concrete reason found in the production-readiness audit:

1. **DATABASE_URL is blanked** — the checked-in `.env` holds placeholders
   (`postgresql://USER:PASSWORD@HOST/...`). With it set, the psycopg pool in
   `src.db` spends its full 30s connect timeout dialling a host that does not
   resolve, twice, which is ~55s of the ~60s the suite used to take. Blanked,
   `src.db._require_url()` raises immediately and the fail-closed callers move
   on. It also guarantees CI can never reach a real database.

2. **`record_metric` is stubbed** — it is fail-closed by design (it swallows
   every exception), so leaving it live does not make tests *fail*; it makes
   them write junk rows into the live `ztpa.ai_metrics` table that the admin
   dashboard demos. Rows attributed to a phantom `role='viewer'` are already
   there from previous local runs.

3. **`ollama_probe` is stubbed to "no local model"** — a developer with Ollama
   running would otherwise take different routing branches than CI, which is
   exactly the kind of works-on-my-machine gap a test suite exists to remove.
   `settings.ollama_available()` resolves `ollama_probe` through module globals
   at call time, so patching the one name covers both.

Note the stubs are applied where each name is *looked up*, not only where it is
defined: four modules under `src/` do `from ..metrics import record_metric`, so
rebinding `src.metrics.record_metric` alone would miss every real call site.
"""

from __future__ import annotations

import os
import sys

import pytest

# Blank DATABASE_URL at conftest *import* time, which is before any test module
# imports `src.settings`. Two reasons it cannot wait for the fixture: `src.db`
# binds DATABASE_URL as a module-level constant at import, and `src.settings`
# calls load_dotenv() at import — python-dotenv will not overwrite a key that is
# already present in os.environ, so seeding an empty string here is what makes
# the repo-root .env lose.
os.environ["DATABASE_URL"] = ""


def _no_metric(**_kwargs: object) -> None:
    """Stand-in for `src.metrics.record_metric`: accepts the same keyword-only
    call shape and does nothing. Kept keyword-only so a positional call — which
    the real function would reject — still fails loudly in tests."""


def _no_ollama() -> tuple[bool, list[str]]:
    """Stand-in for `src.settings.ollama_probe`: 'unreachable, no models', the
    same answer a machine without Ollama gets, without the network round-trip."""
    return False, []


@pytest.fixture(autouse=True)
def _offline(monkeypatch: pytest.MonkeyPatch) -> None:
    """Applied to every test; monkeypatch unwinds all of it afterwards."""
    import src.db
    import src.metrics
    import src.settings

    # Sweep every already-imported `src.*` module rather than hardcoding the
    # four current importers, so a new `from ..metrics import record_metric`
    # call site cannot silently reintroduce the live write. Patching
    # `src.metrics` itself is what covers modules imported later (lazily, inside
    # a function), since they bind the stub at their own import time.
    for module in list(sys.modules.values()):
        if getattr(module, "__name__", "").startswith("src") and hasattr(module, "record_metric"):
            monkeypatch.setattr(module, "record_metric", _no_metric)

    monkeypatch.setattr(src.settings, "ollama_probe", _no_ollama)

    # Belt and braces on the DB: the environment is already blank from import
    # time, but re-assert it here (so a test that sets it is undone) and blank
    # the two constants that were bound from it before this fixture existed.
    monkeypatch.setenv("DATABASE_URL", "")
    monkeypatch.setattr(src.settings, "DATABASE_URL", "")
    monkeypatch.setattr(src.db, "DATABASE_URL", "")
