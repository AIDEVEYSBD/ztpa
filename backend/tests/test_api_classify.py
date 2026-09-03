"""The custom-change endpoint: POST /api/change/classify must return a DECISION
-- to a caller allowed to ask for one.

Phase 0 exit criterion, and the reason it is a criterion: main.py destructured
`parse_service` -- which returns a 6-field `DecodedService` -- into three names,
so "Simulate a custom change" raised TypeError on every call from the initial
commit until now, and the console's empty catch rendered that as nothing
happening. A green pytest run said nothing about it because no test had ever
issued an HTTP request against this app.

So these tests drive the real ASGI app through TestClient and assert on the
response. Two seams are closed so nothing leaves the process:

  * `get_conn` -> a recording fake cursor. The route persists the change request
    and its decision; we let that code run for real against the fake so a broken
    INSERT still fails the test, but no connection is ever opened.
  * `classify_change.complete` -> a dead model. The repo `.env` carries live
    provider keys, and the point here is the deterministic contract (a decision
    always comes back, fail-closed), not what a model would say today.

The engine is built once and injected into main's cache, so the routes exercise
the same snapshot the deterministic suite does without a rebuild per test.
"""

from __future__ import annotations

import contextlib
import types

import pytest
from fastapi.testclient import TestClient

from app import main
from src import tools_registry
from src.advisory import classify_change
from src.analyzers.run_all import run


class _FakeCursor:
    """Records every statement instead of executing it. Doubles as its own
    context manager because the routes use `with conn.cursor() as cur`."""

    def __init__(self) -> None:
        self.statements: list[tuple[str, object]] = []

    def execute(self, sql, params=None):
        self.statements.append((sql, params))
        return self

    def fetchone(self):
        return None

    def fetchall(self):
        return []

    def __enter__(self):
        return self

    def __exit__(self, *_exc):
        return False


class _FakeConn:
    def __init__(self, cur: _FakeCursor) -> None:
        self._cur = cur

    def cursor(self):
        return self._cur

    def execute(self, sql, params=None):
        return self._cur.execute(sql, params)


@pytest.fixture(scope="module")
def eng():
    """The deterministic engine over the seeded corpus (one build for the module)."""
    return run()


@pytest.fixture
def cur(monkeypatch, eng):
    """Wire the app to a fake DB + dead model and return the recording cursor."""
    fake = _FakeCursor()

    @contextlib.contextmanager
    def _fake_get_conn():
        yield _FakeConn(fake)

    monkeypatch.setattr(main, "get_conn", _fake_get_conn)
    monkeypatch.setattr(main, "_ENGINE", eng)
    # The capability layer reads ztpa.tool_settings through its OWN get_conn
    # (src.tools_registry imports it from src.db), so it needs wiring too: a
    # HEALTHY settings table with no rows, i.e. every capability default-on. It
    # is not optional scenery -- an unreadable settings table now resolves every
    # ai_capability to nobody, admin included (that is the `rank` kill switch,
    # asserted in test_api_authz.py), and `classify` is an ai_capability. Without
    # this the file would be measuring the fail-closed path, not the change gate.
    monkeypatch.setattr(tools_registry, "_CACHE",
                        {"at": 0.0, "map": {}, "loaded": False, "read_at": 0.0})
    monkeypatch.setattr(tools_registry, "get_conn", _fake_get_conn)
    monkeypatch.setattr(tools_registry, "fetch_all", lambda *_a, **_kw: [])
    monkeypatch.setattr(classify_change, "complete", lambda **_kw: types.SimpleNamespace(
        ok=False, text="", provider="stub", model="stub", error="unreachable"))
    return fake


@pytest.fixture
def client(cur):
    # Constructed WITHOUT `with`: entering the context manager would run the
    # startup event, which kicks off a second, real engine build in a thread.
    return TestClient(main.app)


@pytest.fixture
def spy_simulate(monkeypatch):
    """Capture the PolicyRecord the endpoint hands to the engine.

    Asserting on the constructed record is what pins the actual regression: the
    response shape belongs to `simulate_change`, but whether `port_end` and the
    decoded App-ID survived the trip from `parse_service` is this file's bug.
    """
    seen: list = []
    real = main.simulate_change

    # *args/**kwargs rather than a fixed arity: this spy exists to observe the
    # PROPOSED record, and it should not break every time simulate_change gains
    # another engine-derived input (it gained `resolved`, the object catalog,
    # when the gate stopped ruling on source spelling).
    def _spy(records, assets, alias_map, proposed, *args, **kwargs):
        seen.append(proposed)
        return real(records, assets, alias_map, proposed, *args, **kwargs)

    monkeypatch.setattr(main, "simulate_change", _spy)
    return seen


def _post(client, **body):
    return client.post("/api/change/classify", json=body, headers={"x-npr-role": "admin"})


def test_a_viewer_may_not_evaluate_a_change(client):
    """This route is not advisory, whatever the exemption list used to say.

    Every call persists a change_requests row and a change_decisions row -- both
    GOVERNANCE tables -- and spends model tokens doing it. It shipped with no role
    dependency at all, so an auditor's read-only credential could write into the
    compliance trail the whole product rests on. The full route-by-route guard
    matrix is in test_api_authz.py; this asserts it at the point of use, because
    a reader of THIS file should not have to go and find out."""
    r = client.post("/api/change/classify",
                    json={"source": "10.20.5.0/24", "destination": "app-server-07", "service": "tcp/22"},
                    headers={"x-npr-role": "viewer", "x-npr-email": "auditor@example.com"})
    assert r.status_code == 403
    assert "approver role required" in r.json()["detail"]


# --------------------------------------------------------------------------
def test_custom_change_returns_a_decision(client, cur):
    """The flagship card: source + destination + service -> 200 and a ruling."""
    r = _post(client, source="10.20.5.0/24", destination="app-server-07", service="tcp/22",
              justification="ops jump box access")
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["decision"]["decision"] in ("auto_approve", "escalate")
    assert body["decision"]["request_id"] == body["request"]["id"]
    assert "new_exposed_assets" in body["delta"]
    # The ruling was durably recorded, not just returned.
    tables = " ".join(sql for sql, _ in cur.statements)
    assert "ztpa.change_requests" in tables and "ztpa.change_decisions" in tables


def test_custom_change_keeps_a_port_range(client, spy_simulate):
    """"tcp/8000-8100" is a RANGE. Dropping port_end turned it into a single-port
    grant, which is what the range-aware port scoring and `_grant_matches` read."""
    r = _post(client, source="10.20.5.0/24", destination="app-server-07", service="tcp/8000-8100")
    assert r.status_code == 200, r.text
    proposed = spy_simulate[0]
    assert (proposed.protocol, proposed.port, proposed.port_end) == ("tcp", 8000, 8100)
    assert proposed.service == "tcp/8000-8100"


def test_custom_change_keeps_an_l7_app(client, spy_simulate):
    """An App-ID service ("quic") resolves to its fixed transport AND stays tagged
    as the application -- otherwise an encrypted-transport grant reads as unknown."""
    r = _post(client, source="0.0.0.0/0", destination="app-server-07", service="quic")
    assert r.status_code == 200, r.text
    proposed = spy_simulate[0]
    assert proposed.l7_app == "quic"
    assert proposed.l7_source == "declared"
    assert (proposed.protocol, proposed.port) == ("udp", 443)


def test_custom_change_with_a_name_source_is_classified(client):
    """A non-CIDR source is an identity, not a malformed CIDR: still a 200."""
    r = _post(client, source="web-tier", destination="db-prod-01", service="tcp/1433")
    assert r.status_code == 200, r.text
    assert r.json()["decision"]["decision"] in ("auto_approve", "escalate")


def test_internet_to_regulated_asset_escalates(client):
    """The end the gate exists for: the whole internet reaching a PCI database on
    its admin port is force-escalated by the guardrail, never auto-approved."""
    r = _post(client, source="0.0.0.0/0", destination="db-prod-01", service="tcp/1433")
    assert r.status_code == 200, r.text
    decision = r.json()["decision"]
    assert decision["decision"] == "escalate"
    assert decision["forced_escalate"] is True


def test_incomplete_body_is_a_400_not_a_500(client):
    """Neither a known request_id nor a full tuple -> a stated 400."""
    r = _post(client, source="10.20.5.0/24")
    assert r.status_code == 400
    assert "request_id or source+destination+service" in r.json()["detail"]


def test_every_error_carries_the_request_id(client):
    """Errors are traceable: the id on the body matches the response header."""
    r = _post(client, source="10.20.5.0/24")
    assert r.status_code == 400
    assert r.json()["request_id"] == r.headers["x-request-id"]
