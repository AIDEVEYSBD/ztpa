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

4. **Outbound sockets are blocked** — the paragraph above used to be the whole
   argument for the "no business opening a socket" claim, and a claim is not a
   seam. The live Azure discovery probe gated itself opt-OUT, so plain `pytest`
   reached ARM from any machine with an `az login` and then asserted the ABSENCE
   of a GPT deployment in a resource group nobody here controls; when somebody
   deployed `gpt-5.1-codex-mini` the suite went red with no change to this repo.
   A green run has to be a statement about this code, so `connect` to anything
   but loopback now raises `OutboundSocketBlocked`, naming the address and the
   test. LOOPBACK STAYS OPEN: `NPR_TEST_DATABASE_URL` points at a local
   Postgres, which is a dependency the developer controls.

   The one exemption is `@pytest.mark.live`, and a marked test is SKIPPED at
   collection unless `NPR_RUN_LIVE=1` (see `tests/livegate.py`). The two halves
   are deliberately independent: declaring you reach the internet makes you
   opt-in, and NOT declaring it makes you fail loudly rather than quietly
   succeed. Neither half relies on a future test author remembering a rule.

Note the stubs are applied where each name is *looked up*, not only where it is
defined: four modules under `src/` do `from ..metrics import record_metric`, so
rebinding `src.metrics.record_metric` alone would miss every real call site.
"""

from __future__ import annotations

import os
import socket
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


# ---------------------------------------------------------------------------
# 4. the network seam
# ---------------------------------------------------------------------------

class OutboundSocketBlocked(RuntimeError):
    """A test that is not marked `live` tried to connect off this machine.

    Deliberately NOT an `OSError`. Every HTTP client in this dependency tree
    catches `OSError` and re-raises it as its own transport error, and several
    call sites in this codebase turn a transport error into a typed "the service
    is unreachable" result -- which is correct production behaviour and exactly
    the wrong thing here, because it would let a blocked call read as a tested
    failure path. An exception nothing catches is what makes the block visible.
    """


# Loopback in every spelling a resolver or a library might hand `connect`.
# `""` / `0.0.0.0` / `::` appear when a socket is connected after an explicit
# bind, and none of them names a remote host.
_LOOPBACK_HOSTS = frozenset({"", "localhost", "localhost.localdomain",
                             "127.0.0.1", "0.0.0.0", "::1", "::", "::ffff:127.0.0.1"})


def _is_local(address: object) -> bool:
    """True unless `address` names a host off this machine.

    Errs towards ALLOW for anything that is not a recognisable IP address tuple
    -- AF_UNIX paths, netlink, Bluetooth, `socketpair()`. The guard exists to
    stop the suite depending on somebody else's cloud, not to police IPC: a
    false positive here would break asyncio's self-pipe on some platforms and
    the cure would be worse than the disease.
    """
    if not isinstance(address, (tuple, list)) or not address:
        return True
    host = address[0]
    if not isinstance(host, str):
        return True
    h = host.strip("[]").split("%", 1)[0].lower()   # strip brackets and zone id
    if h.startswith("::ffff:"):
        h = h[len("::ffff:"):]
    return h in _LOOPBACK_HOSTS or h.startswith("127.")


@pytest.fixture(autouse=True)
def _no_outbound_sockets(request: pytest.FixtureRequest,
                         monkeypatch: pytest.MonkeyPatch) -> None:
    """Block `connect` to anything but loopback, except for `live` tests.

    Patched on `socket.socket` rather than on each HTTP client: `httpx`,
    `requests`/`urllib3`, `psycopg` and `azure-identity`'s several credential
    sources all bottom out here, and `socket.create_connection` calls
    `sock.connect(sa)` on an instance of this class, so the one patch covers the
    lot. `monkeypatch` unwinds it after every test.
    """
    if request.node.get_closest_marker("live"):
        return

    real_connect = socket.socket.connect
    real_connect_ex = socket.socket.connect_ex

    def _refuse(sock: socket.socket, address: object) -> None:
        # Close first. `socket.create_connection` only closes its socket when it
        # catches an `OSError`, and this deliberately is not one -- so without
        # this the blocked attempt leaks the fd and surfaces as
        # `ResourceWarning: unclosed socket`, which `filterwarnings = error`
        # turns into a failure that says nothing about what was blocked. The
        # clear message below is the entire value of the guard; it must be what
        # the reader actually sees.
        try:
            sock.close()
        except Exception:                                   # noqa: BLE001
            # An un-closable socket must not replace the real diagnosis with a
            # secondary one; the block is still what happened.
            pass
        raise OutboundSocketBlocked(
            f"{request.node.nodeid} tried to connect to {address!r}. This suite "
            "measures THIS repository, so a run's green/red may not depend on a "
            "third party being reachable, on a credential existing on this "
            "machine, or on what somebody else deployed today. If the test "
            "genuinely needs the real service, mark it `@pytest.mark.live` -- "
            "which also makes it opt-in (NPR_RUN_LIVE=1; see tests/livegate.py). "
            "Otherwise stub the transport: tests/test_azure_discovery.py's `arm` "
            "fixture swaps in an httpx.MockTransport and keeps the real parsing, "
            "pagination and error mapping under test."
        )

    def _guarded_connect(self, address, *args, **kwargs):          # noqa: ANN001
        if not _is_local(address):
            _refuse(self, address)
        return real_connect(self, address, *args, **kwargs)

    def _guarded_connect_ex(self, address, *args, **kwargs):       # noqa: ANN001
        if not _is_local(address):
            _refuse(self, address)
        return real_connect_ex(self, address, *args, **kwargs)

    monkeypatch.setattr(socket.socket, "connect", _guarded_connect)
    monkeypatch.setattr(socket.socket, "connect_ex", _guarded_connect_ex)


def pytest_collection_modifyitems(config: pytest.Config,
                                  items: list[pytest.Item]) -> None:
    """Skip every `live` test unless the run explicitly asked for them.

    At COLLECTION, so the gate cannot be forgotten by the test that needs it --
    which is precisely how the Azure probe came to run by default. The reason
    string is the one from `tests/livegate.py`, so `-r s` prints the variable
    that turns them on rather than an unexplained gap in the summary.
    """
    from tests.livegate import skip_reason

    reason = skip_reason()
    if reason is None:
        return
    skip = pytest.mark.skip(reason=reason)
    for item in items:
        if item.get_closest_marker("live"):
            item.add_marker(skip)
