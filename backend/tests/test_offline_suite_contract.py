"""The suite's own contract: a green run is a statement about THIS repository.

WHAT WENT WRONG, AND WHY IT IS A CLASS RATHER THAN A TEST
---------------------------------------------------------
`backend/conftest.py` has always opened with the sentence "this is a unit suite
... it has no business opening a socket". For the database it backed that with a
seam (DATABASE_URL is blanked at import time). For the network it backed it with
nothing, and the gap was used:

  * `test_azure_discovery.py::test_live_azure_discovery_finds_the_foundry_account`
    gated itself OPT-OUT -- it ran unless `NPR_SKIP_AZURE_LIVE` was set -- so the
    documented `pytest` command reached Azure Resource Manager from any machine
    with an `az login`, and asserted the ABSENCE of a GPT deployment in
    `Foundry-RG`. Somebody deployed `gpt-5.1-codex-mini`; the suite went red
    while discovery was returning ARM's answer exactly.
  * `test_api_transactions.py`'s model-call tripwire swept `embed` and not
    `embed_texts`, which is the name the live call site actually imports -- so
    `/api/assets/merge-suggestions` made a real embeddings request to the hosted
    provider on every run, past the very tripwire whose job was to police it.
  * `test_degraded_publication.py`'s `api` fixture left `complete` unstubbed, so
    `/api/report` billed a real chat completion to whatever key the checked-in
    `.env` names, on every run.
  * `test_advisory_azure.py`'s `provider_status` tests probed the REAL AAD
    credential chain on a background thread, because `_azure_probe_once`
    swallows every exception by design and a forgotten `credential` fixture
    therefore looked exactly like a working one.

Only the first was visible, and only because a stranger changed their resource
group. The other three were green the whole time, spending money and depending
on somebody else's uptime. That is the class: a suite cannot police what it
never observes, so the rule stopped being a sentence in a docstring and became
two mechanisms in `backend/conftest.py`. This module tests the mechanisms --
because a guard nobody has ever seen fire is a guard nobody knows works.

THE TWO HALVES
--------------
  1. `pytest_collection_modifyitems` skips every `@pytest.mark.live` test unless
     the run asked for live tests (`tests/livegate.py`). Marking a test live
     makes it opt-in by construction; there is no per-test gate to forget.
  2. `_no_outbound_sockets` blocks `connect` to anything but loopback for every
     test that is NOT marked live. Forgetting the marker buys a loud failure
     naming the address, not a quiet network call.

Each half covers the other's failure mode, which is why both exist.
"""

from __future__ import annotations

import socket
import threading
from pathlib import Path

import pytest

import conftest
from tests import livegate

REPO_ROOT = Path(__file__).resolve().parents[2]


# --------------------------------------------------------------------------
# 1. the socket guard
# --------------------------------------------------------------------------

def test_a_connection_off_this_machine_is_refused() -> None:
    """The guard fires, and says enough to act on.

    198.51.100.1 is TEST-NET-2 (RFC 5737): unroutable by definition, so this
    asserts the REFUSAL rather than a connection failure that would happen
    anyway. The guard raises before any packet leaves.
    """
    with pytest.raises(conftest.OutboundSocketBlocked) as caught:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(1.0)
            s.connect(("198.51.100.1", 443))
    message = str(caught.value)
    assert "198.51.100.1" in message, "the block does not say what it blocked"
    assert "pytest.mark.live" in message, "the block does not say how to ask for the real thing"
    assert test_a_connection_off_this_machine_is_refused.__name__ in message, (
        "the block does not name the test that made the call")


def test_the_guard_is_not_an_oserror() -> None:
    """It must not be catchable as a transport failure.

    Every HTTP client here maps `OSError` onto its own "the service is
    unreachable" type, and this codebase then turns that into a typed degraded
    result -- correct in production, and exactly wrong here, because a blocked
    call would read as a tested failure path and the test would stay green while
    silently measuring nothing.
    """
    assert not issubclass(conftest.OutboundSocketBlocked, OSError)
    assert issubclass(conftest.OutboundSocketBlocked, Exception)


def test_loopback_is_still_allowed() -> None:
    """The database-backed tests dial `localhost:55433`. Blocking loopback would
    make this guard a bigger outage than the problem it fixes, so it is asserted
    against a real listener rather than assumed from the address table."""
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    port = listener.getsockname()[1]
    accepted: list[socket.socket] = []
    thread = threading.Thread(target=lambda: accepted.append(listener.accept()[0]), daemon=True)
    thread.start()
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(5.0)
            s.connect(("127.0.0.1", port))          # must NOT raise
        thread.join(5.0)
        assert accepted, "the loopback connection never arrived"
    finally:
        for sock in accepted:
            sock.close()
        listener.close()


@pytest.mark.parametrize("address, local", [
    (("127.0.0.1", 5432), True),
    (("127.0.0.53", 53), True),                  # the whole 127/8 loopback net
    (("localhost", 55433), True),
    (("::1", 5432, 0, 0), True),
    (("::ffff:127.0.0.1", 443), True),           # v4-mapped loopback
    (("fe80::1%en0", 443, 0, 0), False),         # a real host, zone id and all
    (("10.0.0.5", 443), False),                  # RFC1918 is still off-box
    (("169.254.169.254", 80), False),            # the IMDS endpoint: very much a service
    (("172.66.0.243", 443), False),              # api.openai.com, as measured
    (("management.azure.com", 443), False),
    ("/var/run/postgres/.s.PGSQL.5432", True),   # AF_UNIX: not a network at all
    (None, True),
])
def test_the_address_classifier_is_not_guesswork(address: object, local: bool) -> None:
    """`169.254.169.254` is the one worth reading twice: the instance metadata
    service is link-local, so a naive "private addresses are fine" rule would
    have let a managed-identity token probe through -- which is precisely the
    call that made the offline suite depend on a credential existing."""
    assert conftest._is_local(address) is local


def test_the_guard_covers_create_connection_too() -> None:
    """`socket.create_connection` is what httpcore, urllib3 and psycopg use.

    It is not patched directly; it calls `sock.connect(sa)` on a `socket.socket`
    instance, so patching the class covers it. That is an implementation detail
    of CPython's stdlib and therefore worth an assertion rather than a comment.
    """
    with pytest.raises(conftest.OutboundSocketBlocked):
        socket.create_connection(("198.51.100.1", 443), timeout=1.0)


# --------------------------------------------------------------------------
# 2. the live gate
# --------------------------------------------------------------------------

def test_live_tests_are_off_by_default(monkeypatch: pytest.MonkeyPatch) -> None:
    """THE REGRESSION, stated as a truth table. The old gate returned "run" from
    a clean environment; from a clean environment the answer is now "skip"."""
    for name in (*livegate.OPT_IN_ENVS, *livegate.TARGET_ENVS, livegate.VETO_ENV):
        monkeypatch.delenv(name, raising=False)
    assert livegate.live_enabled() is False
    reason = livegate.skip_reason()
    assert reason and livegate.OPT_IN_ENVS[0] in reason, (
        "the skip does not name the variable that would turn it on")


@pytest.mark.parametrize("value", ["1", "true", "TRUE", "yes", "on"])
def test_the_opt_in_is_honoured(monkeypatch: pytest.MonkeyPatch, value: str) -> None:
    monkeypatch.delenv(livegate.VETO_ENV, raising=False)
    monkeypatch.setenv(livegate.OPT_IN_ENVS[0], value)
    assert livegate.live_enabled() is True
    assert livegate.skip_reason() is None


@pytest.mark.parametrize("value", ["", "  ", "0", "false", "no", "maybe"])
def test_a_non_switch_value_does_not_arm_the_opt_in(monkeypatch: pytest.MonkeyPatch,
                                                    value: str) -> None:
    """Fail CLOSED. `NPR_RUN_LIVE=0` meaning "yes" is the kind of surprise that
    puts a network call back in the default suite."""
    for name in (*livegate.OPT_IN_ENVS, *livegate.TARGET_ENVS, livegate.VETO_ENV):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv(livegate.OPT_IN_ENVS[0], value)
    assert livegate.live_enabled() is False


def test_the_veto_wins_over_the_opt_in(monkeypatch: pytest.MonkeyPatch) -> None:
    """`NPR_SKIP_AZURE_LIVE` predates this gate and some CI jobs set it. A switch
    whose entire purpose is "never touch the network here" must not be
    overridable by a broader one, or honouring it would be a fiction."""
    monkeypatch.setenv(livegate.OPT_IN_ENVS[0], "1")
    monkeypatch.setenv(livegate.TARGET_ENVS[0], "https://example.invalid/")
    monkeypatch.setenv(livegate.VETO_ENV, "1")
    assert livegate.live_enabled() is False
    assert livegate.VETO_ENV in (livegate.skip_reason() or "")


def test_naming_a_live_target_counts_as_asking(monkeypatch: pytest.MonkeyPatch) -> None:
    """Without this, the collection hook would silently defeat a STRONGER gate.

    `test_advisory_azure.py::live_collection_decision` treats "the target
    variable is set but the live test did not run" as a hard FAILURE, because a
    green run containing a skip is what a pipeline reads as proof. If a marked
    test could be skipped while its own target was configured, that guarantee
    would be gone and nothing would have said so.
    """
    for name in (*livegate.OPT_IN_ENVS, livegate.VETO_ENV):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv(livegate.TARGET_ENVS[0],
                       "https://api-endpoint-inference-resource.cognitiveservices.azure.com/")
    assert livegate.live_enabled() is True


def test_the_marker_is_registered() -> None:
    """`--strict-markers` is on, so an unregistered marker is a collection error
    rather than a marker that silently does nothing -- but only while the
    registration is there. It is the load-bearing half of the gate."""
    raw = (REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8")
    assert f'"{livegate.LIVE_MARKER}:' in raw, (
        f"the `{livegate.LIVE_MARKER}` marker is no longer registered in "
        "pyproject.toml; every @pytest.mark.live would become a collection error"
    )
    assert "--strict-markers" in raw


TESTS_DIR = Path(__file__).resolve().parent

# The modules that reach a real external service, and the service each reaches.
# Stated here so that REMOVING a marker is a failure rather than a quietly
# shorter list -- the marker is the only thing keeping these out of the default
# run, and `test_live_azure_discovery_finds_the_foundry_account` is the exact
# test that was in it.
MODULES_WITH_LIVE_TESTS = {
    "test_azure_discovery.py": "Azure Resource Manager (the discovery dropdowns)",
    "test_advisory_azure.py": "a real Foundry deployment (real inference, real AAD)",
}


def test_every_real_world_test_still_carries_the_marker() -> None:
    """Source-level, so it holds under `-k`, `-m` and a single-file run.

    Without the marker a live test is not gated at all: the collection hook
    cannot see it, so it runs by default, and the socket guard then fails it
    with an outbound-connection error instead. Either way the suite stops being
    a measurement -- which is the state this whole module exists to prevent.
    """
    missing = {
        name: what
        for name, what in MODULES_WITH_LIVE_TESTS.items()
        if "@pytest.mark.live" not in (TESTS_DIR / name).read_text(encoding="utf-8")
    }
    assert not missing, (
        "these modules reach a real service but no longer mark any test `live`, "
        "so it is back in the default suite: "
        + "; ".join(f"{name} -> {what}" for name, what in missing.items())
    )


def test_no_marked_test_would_run_in_a_default_suite(request: pytest.FixtureRequest) -> None:
    """The other half, read off the collection pytest actually built.

    Source scanning cannot see a marker applied by a fixture, a parametrisation
    or a module-level `pytestmark`; the collected items can. Whatever is marked
    in THIS run must also be skipped in it, unless the run asked for live tests.
    """
    if livegate.live_enabled():
        pytest.skip("live tests were asked for, so they are not skipped; nothing to assert")
    marked = [item for item in request.session.items if item.get_closest_marker("live")]
    unskipped = [item.nodeid for item in marked
                 if not any(m.name == "skip" for m in item.iter_markers())]
    assert not unskipped, (
        "these tests are marked `live` but would still RUN in a default suite, "
        "so `pytest` would depend on a third party again: " + ", ".join(unskipped)
    )
