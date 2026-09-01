"""The API boundary: who may mutate state, and what the backend believes about
who is asking.

Two independent failures shipped together, and this file pins both.

1. AUTHORIZATION WAS ADVISORY. Role checks were written per-branch instead of as
   dependencies, so nine state-mutating routes had no guard at all. An
   authenticated `viewer` -- the role you hand an auditor -- could drive
   remediate -> submit -> stage -> PUSH and write a rule into the durable overlay
   that is re-applied on every recompute. `stage_change` is the shape of the bug
   in miniature: it checked the role only inside the `escalate` branch, so the
   auto_approve path staged for anybody.

   The first test is parametrised over EVERY mutating route rather than over a
   list somebody maintains by hand, and the second proves each guard still admits
   the role that is supposed to pass -- a guard that 403s everyone is not a fix.

2. THE TRUST BOUNDARY WAS A FORGEABLE HEADER. `request_ctx` trusts `x-npr-role`
   from the proxy and says the backend "must stay private", while render.yaml
   deploys it as a public web service. With NPR_PROXY_SECRET configured, claiming
   a role without the shared secret is a 401; without it configured, behaviour is
   unchanged and /api/health reports `proxy_auth: false` so the gap is visible.

3. THE EXEMPTION LIST LIED, AND THE REFLECTIVE CHECK BELIEVED IT. Three routes
   sat on `exempt` under the comment "Advisory routes that write no governance
   state": /api/change/classify writes change_requests AND change_decisions, and
   the two /remediate routes write remediation_revisions -- all three in
   `GOVERNANCE_TABLES` (src/db.py). A viewer really could reach the classify
   handler and write into the compliance trail. So the exemptions are now
   MEASURED rather than asserted: `test_no_exempt_route_writes_governance_state`
   reads each exempt handler's source and fails if it calls a governance writer,
   which is exactly the claim the false comment was making by hand.

Nothing here opens a connection: `get_conn` and every persistence call main.py
imports are replaced with recorders, so a 403 that is really a masked DB error
cannot pass for a pass.
"""

from __future__ import annotations

import contextlib
import inspect
import types

import pytest
from fastapi.testclient import TestClient

from app import main
from src.advisory import classify_change
from src.models import RankedActions

VIEWER = {"x-npr-role": "viewer", "x-npr-email": "auditor@example.com"}


class _FakeCursor:
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


# A row that satisfies every SELECT the mutating routes make: a decided change
# request for stage_change, a staged change for staging_push.
_ROW = {
    "decision": "auto_approve", "proposed": {"target_tool": "algosec"}, "kind": "add_allow",
    "origin": "change_gate", "snapshot_id": "snap_test", "status": "open",
    "staged_id": "stage_test", "request_id": "cr_test", "target_tool": "algosec",
    "payload": {}, "conflicts": [], "resolution": {}, "push_steps": [],
}
_PUSH_PLAN = {"status": "pushed", "conflicts": [], "resolution": {}, "push_steps": [], "simulated": True}


@pytest.fixture(scope="module")
def eng():
    """One deterministic engine build for the whole module."""
    from src.analyzers.run_all import run
    return run()


@pytest.fixture
def cur(monkeypatch, eng):
    """Replace the entire persistence seam. Returns the recording cursor."""
    fake = _FakeCursor()

    @contextlib.contextmanager
    def _fake_get_conn():
        yield _FakeConn(fake)

    monkeypatch.setattr(main, "get_conn", _fake_get_conn)
    monkeypatch.setattr(main, "_ENGINE", eng)
    monkeypatch.setattr(main, "_ENGINE_STATE",
                        {"inputs_ok": True, "inputs_error": None, "persisted": True,
                         "persist_error": None, "build_error": None})
    monkeypatch.setattr(main, "run", lambda **_kw: eng)
    monkeypatch.setattr(main, "write_scenario", lambda *_a, **_kw: None)

    monkeypatch.setattr(main, "fetch_one", lambda *_a, **_kw: dict(_ROW))
    monkeypatch.setattr(main, "fetch_all", lambda *_a, **_kw: [])
    monkeypatch.setattr(main, "upsert", lambda *_a, **_kw: None)
    monkeypatch.setattr(main, "audit", lambda *_a, **_kw: None)
    monkeypatch.setattr(main, "load_asset_merges", lambda _cur: [])
    monkeypatch.setattr(main, "load_applied_changes", lambda _cur: [])
    monkeypatch.setattr(main, "persist_engine_result", lambda *_a, **_kw: {"assets": 0, "findings": 0})
    monkeypatch.setattr(main, "persist_ranked_actions", lambda *_a, **_kw: None)
    monkeypatch.setattr(main, "persist_campaign_plan", lambda *_a, **_kw: None)
    monkeypatch.setattr(main, "load_campaign_plan", lambda *_a, **_kw: {"steps": []})
    monkeypatch.setattr(main, "persist_asset_merge", lambda *_a, **_kw: None)
    monkeypatch.setattr(main, "delete_asset_merge", lambda *_a, **_kw: None)
    monkeypatch.setattr(main, "persist_staged_change", lambda *_a, **_kw: None)
    monkeypatch.setattr(main, "persist_remediation_revision", lambda *_a, **_kw: {
        "thread_id": "th_test", "seq": 1, "revision_id": "rev_test"})
    monkeypatch.setattr(main, "ensure_change_request_status", lambda *_a, **_kw: None)
    monkeypatch.setattr(main, "reject_change_request", lambda *_a, **_kw: 1)

    # The two expensive model-backed steps, and the one private validator the
    # submit path calls: stubbed so the test measures authorization, not ranking.
    monkeypatch.setattr(main.rank_mod, "rank", lambda _findings: RankedActions())
    monkeypatch.setattr(main.campaign_mod, "plan", lambda *_a, **_kw: {
        "steps": [], "applied_count": 0, "needs_review_count": 0,
        "criticals_trajectory": [0], "cleared_all_criticals": True})
    monkeypatch.setattr(main.staging_mod, "build_push_plan", lambda *_a, **_kw: dict(_PUSH_PLAN))
    monkeypatch.setattr(main, "remediation", types.SimpleNamespace(
        _validate=lambda *_a, **_kw: {"resolves": True},
        draft=lambda *_a, **_kw: {"change": {"op": "remove"}, "by": "stub",
                                  "validation": {"resolves": True}}))
    # The change gate's own model call. The deterministic classifier around it is
    # left real (it is what persists the governance rows this file is about), but
    # the repo `.env` carries live provider keys and an authz test has no business
    # reaching one -- so `complete` answers "unreachable", the fail-closed path.
    monkeypatch.setattr(classify_change, "complete", lambda **_kw: types.SimpleNamespace(
        ok=False, text="", provider="stub", model="stub", error="unreachable"))
    return fake


@pytest.fixture
def client(cur, monkeypatch):
    # No `with`: entering the context manager runs the lifespan, which starts a
    # real engine build in a background thread.
    monkeypatch.delenv("NPR_PROXY_SECRET", raising=False)
    return TestClient(main.app)


# --- the mutating surface --------------------------------------------------
# (method, path, body-factory, the role the guard must ADMIT). Every route in
# app.main that changes state is here; `test_no_mutating_route_is_unguarded`
# fails if a new one is added without being listed and guarded.
MUTATING_ROUTES = [
    ("POST", "/api/recompute", None, "admin"),
    ("POST", "/api/actions/recompute", None, "admin"),
    ("POST", "/api/assets/merge", lambda e: {"a": "app-server-07", "b": "appsrv-07"}, "admin"),
    ("POST", "/api/assets/unmerge", lambda e: {"a": "app-server-07", "b": "appsrv-07"}, "admin"),
    ("POST", "/api/staging/stage_test/push", None, "admin"),
    ("POST", "/api/campaign/plan", lambda e: {}, "analyst"),
    ("POST", "/api/campaign/submit", lambda e: {}, "analyst"),
    ("POST", "/api/staging", lambda e: {"request_id": "cr_test"}, "analyst"),
    ("DELETE", "/api/staging/stage_test", None, "analyst"),
    ("POST", "/api/change/submit", lambda e: {
        "kind": "remediation", "finding_id": e.findings[0].id,
        "change": {"op": "remove", "target_ref": e.findings[0].raw_refs[0]}}, "analyst"),
    ("POST", "/api/change/reject", lambda e: {"request_id": "cr_test"}, "analyst"),
    # Exempted as "advisory" and they are not: each one writes a GOVERNANCE table
    # (change_requests + change_decisions; remediation_revisions) and spends model
    # tokens. Evaluating or drafting a change is analyst work, so `approver` is the
    # guard -- a viewer is what an auditor is given, and an auditor reads.
    ("POST", "/api/change/classify",
     lambda e: {"source": "10.20.5.0/24", "destination": "app-server-07", "service": "tcp/22"}, "analyst"),
    ("POST", "/api/findings/{fid}/remediate", None, "analyst"),
    ("POST", "/api/findings/{fid}/remediate/refine", lambda e: {"comment": "narrow it to the jump box"},
     "analyst"),
    # Already guarded before this change; listed so the admin-only routes are
    # covered by the same parametrisation rather than trusted.
    ("POST", "/api/admin/dataset", lambda e: {"scenario": "demo"}, "admin"),
    ("POST", "/api/admin/reset-demo", None, "admin"),
    ("POST", "/api/admin/tools/explain", lambda e: {"enabled_roles": ["admin"]}, "admin"),
    ("DELETE", "/api/snapshots/snap_other", None, "admin"),
]
_IDS = [f"{m}:{p}" for m, p, _b, _r in MUTATING_ROUTES]


def _call(client, method, path, body, headers):
    return client.request(method, path, json=body, headers=headers)


def _resolve(path: str, eng) -> str:
    """Fill a templated route path with something the handler will actually find.

    Only the guard is under test, and a dependency runs before the body -- but the
    ADMITTED half asserts a 200, so a route keyed on a finding needs a real id
    rather than a placeholder that 404s."""
    return path.replace("{fid}", eng.findings[0].id)


@pytest.mark.parametrize(("method", "path", "make_body", "role"), MUTATING_ROUTES, ids=_IDS)
def test_viewer_is_refused_every_mutating_route(client, eng, method, path, make_body, role):
    """curl with `x-npr-role: viewer` receives 403 from every route that mutates
    state -- the Phase 0 exit criterion, asserted over the route list."""
    r = _call(client, method, _resolve(path, eng), make_body(eng) if make_body else None, VIEWER)
    assert r.status_code == 403, f"{method} {path} answered {r.status_code}: {r.text[:200]}"
    assert "required" in r.json()["detail"] or "admin only" in r.json()["detail"]


@pytest.mark.parametrize(("method", "path", "make_body", "role"), MUTATING_ROUTES, ids=_IDS)
def test_the_guard_admits_the_authorized_role(client, eng, method, path, make_body, role):
    """The other half: each guard lets its own role through to a real response.
    A guard that refuses everyone would pass the test above and break the app."""
    headers = {"x-npr-role": role, "x-npr-email": f"{role}@example.com"}
    r = _call(client, method, _resolve(path, eng), make_body(eng) if make_body else None, headers)
    assert r.status_code == 200, f"{method} {path} answered {r.status_code}: {r.text[:300]}"


# Routes that may POST without a role guard. Each writes NO change-governance
# row: it computes, drafts prose for a human, or refreshes an engine-owned cache.
# The reason is per route because "advisory" as a blanket word is what let three
# governance writers sit on this list; `test_no_exempt_route_writes_governance_state`
# checks the claim instead of taking it.
EXEMPT_ROUTES = {
    # NOT "no writes", which is what this line used to say: the handler calls
    # audit(cur, "user", "agent_ask", ...) -> INSERT INTO ztpa.audit_log. The row
    # is an append to the trail, not change-governance state, so the exemption
    # stands -- but the sentence has to name the write, or it is the same kind of
    # unmeasured claim as the one three governance writers sat behind.
    "/api/agent/ask": "read-only engine tools + prose; its only write appends one ztpa.audit_log row",
    "/api/intake": "parses a request into a proposal for a human; persists nothing",
    "/api/connectors/propose": "drafts a source profile; persists nothing",
    "/api/findings/{fid}/explain": "caches prose onto ztpa.findings, an ENGINE-owned row",
}

# The persist helpers main.py can call that write a change-governance table. Named
# rather than table-matched because the table names live inside src/persist.py --
# an endpoint's own source only ever shows the call.
GOVERNANCE_WRITERS = {
    "persist_change_decision": "change_requests + change_decisions",
    "persist_remediation_revision": "remediation_revisions",
    "accept_remediation_revision": "remediation_revisions",
    "persist_staged_change": "staged_changes",
    "persist_asset_merge": "asset_merges",
    "delete_asset_merge": "asset_merges",
    "reject_change_request": "change_requests",
    "ensure_change_request_status": "change_requests",
    "reset_change_workflow": "every change-governance table",
}


def test_no_mutating_route_is_unguarded(client):
    """Nothing may be added to the mutating surface without a role dependency.

    Reads the live route table instead of a maintained list: a new POST/DELETE
    with neither a role guard nor a place on the exemption list fails here, which
    is the regression that let nine routes ship unguarded in the first place."""
    guards = {main.require_admin, main.require_approver, main.require_operator}
    unguarded = []
    for route in main.app.routes:
        methods = getattr(route, "methods", set()) - {"GET", "HEAD", "OPTIONS"}
        if not methods or route.path in EXEMPT_ROUTES:
            continue
        called = {d.call for d in route.dependant.dependencies}
        if not (called & guards):
            unguarded.append(f"{sorted(methods)} {route.path}")
    assert not unguarded, f"mutating routes with no role guard: {unguarded}"


def _endpoints_by_path() -> dict[str, object]:
    return {r.path: r.endpoint for r in main.app.routes if getattr(r, "endpoint", None)}


def test_no_exempt_route_writes_governance_state():
    """The check that would have caught the false exemption.

    An unguarded route is only acceptable while the sentence justifying it is
    true, so the sentence is verified: the handler's own source may not call any
    governance writer. (Source-level, so it sees the endpoint body and not what a
    helper three frames down does -- which is why every exemption also carries a
    written reason above.)"""
    endpoints = _endpoints_by_path()
    offenders = {}
    for path in EXEMPT_ROUTES:
        src = inspect.getsource(endpoints[path])
        writes = sorted(w for w in GOVERNANCE_WRITERS if w in src)
        if writes:
            offenders[path] = [f"{w} -> {GOVERNANCE_WRITERS[w]}" for w in writes]
    assert not offenders, (
        "An unguarded route writes governance state. Guard it (require_approver "
        f"or require_operator) and take it off EXEMPT_ROUTES:\n{offenders}")


def test_the_governance_writer_check_can_actually_fail():
    """Guard the guard: if the writer names ever stop matching main.py's source,
    the test above would pass by scanning for nothing. The three routes that were
    wrongly exempt are the fixture -- each one must still be detectable."""
    endpoints = _endpoints_by_path()
    for path, writer in (("/api/change/classify", "persist_change_decision"),
                         ("/api/findings/{fid}/remediate", "persist_remediation_revision"),
                         ("/api/findings/{fid}/remediate/refine", "persist_remediation_revision")):
        assert writer in inspect.getsource(endpoints[path]), path
        assert writer in GOVERNANCE_WRITERS
        assert path not in EXEMPT_ROUTES, f"{path} writes governance state and may not be exempt"


# Persistence calls an endpoint body can make. Substrings, matched against the
# handler's own source, so a reason that claims the route writes NOTHING is
# checked against every write it could make -- not only the governance ones.
_ANY_WRITE_CALL = ("audit(", "upsert(", "insert(", "cache_explanation(", "persist_")


def test_an_exemption_that_claims_no_writes_makes_none():
    """The sentence, measured -- one level below the governance check.

    `test_no_exempt_route_writes_governance_state` asks whether an unguarded
    route writes CHANGE-GOVERNANCE state. /api/agent/ask did not, so it passed
    while its justification read "read-only engine tools + prose; no writes" and
    its handler called `audit(cur, "user", "agent_ask", ...)` -- an INSERT into
    ztpa.audit_log on every question anyone asks. Narrowly harmless, and exactly
    the shape of the defect this file exists for: a hand-written claim on the
    exemption list that nothing ever compared against the code.

    So an exemption may claim it writes nothing only while it writes nothing."""
    endpoints = _endpoints_by_path()
    liars = {}
    for path, reason in EXEMPT_ROUTES.items():
        if "no writes" not in reason and "persists nothing" not in reason:
            continue    # the reason already names what it writes; the check above covers it
        src = inspect.getsource(endpoints[path])
        calls = sorted(c for c in _ANY_WRITE_CALL if c in src)
        if calls:
            liars[path] = calls
    assert not liars, (
        "An exemption claims it writes nothing and its handler writes:\n"
        f"{liars}\nName the write in the reason, or stop making it.")

    # Guard the guard: /api/agent/ask is the route the false sentence sat on, so
    # the detector must be able to see its write, and its reason must name it.
    ask = inspect.getsource(endpoints["/api/agent/ask"])
    assert "audit(" in ask, "the write the reason names is gone; re-check the reason"
    assert "audit_log" in EXEMPT_ROUTES["/api/agent/ask"], (
        "/api/agent/ask writes an audit row; its exemption reason must say so")


def test_escalated_change_still_needs_explicit_approval(client):
    """Moving the role check out of the `escalate` branch must not lose the OTHER
    thing that branch required: an escalated change needs a deliberate approval."""
    main_row = dict(_ROW, decision="escalate")
    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(main, "fetch_one", lambda *_a, **_kw: dict(main_row))
        r = client.post("/api/staging", json={"request_id": "cr_test"},
                        headers={"x-npr-role": "analyst"})
        assert r.status_code == 400
        assert "manual approval" in r.json()["detail"]
        ok = client.post("/api/staging", json={"request_id": "cr_test", "manual_approve": True},
                         headers={"x-npr-role": "analyst"})
        assert ok.status_code == 200


def test_an_unknown_role_header_is_treated_as_a_viewer(client):
    """request_ctx clamps anything outside VALID_ROLES to the least privilege, so
    a typo or an injected value cannot become an escalation."""
    r = client.post("/api/recompute", headers={"x-npr-role": "Administrator"})
    assert r.status_code == 403


# --- the proxy trust boundary ----------------------------------------------

def test_headers_are_trusted_when_no_secret_is_configured(client, monkeypatch):
    """Local dev and today's deployments: unchanged behaviour, no 401."""
    monkeypatch.delenv("NPR_PROXY_SECRET", raising=False)
    assert client.post("/api/actions/recompute", headers={"x-npr-role": "admin"}).status_code == 200


def test_claiming_a_role_without_the_secret_is_a_401(client, monkeypatch):
    """Configured: a forged role header from anyone who can reach the public URL
    is refused, rather than believed."""
    monkeypatch.setenv("NPR_PROXY_SECRET", "shared-secret-value")
    r = client.post("/api/actions/recompute", headers={"x-npr-role": "admin"})
    assert r.status_code == 401
    assert "proxy secret" in r.json()["detail"]


def test_a_wrong_secret_is_a_401(client, monkeypatch):
    monkeypatch.setenv("NPR_PROXY_SECRET", "shared-secret-value")
    r = client.post("/api/actions/recompute",
                    headers={"x-npr-role": "admin", "x-npr-proxy-secret": "shared-secret-valuf"})
    assert r.status_code == 401


def test_the_right_secret_admits_the_claimed_role(client, monkeypatch):
    monkeypatch.setenv("NPR_PROXY_SECRET", "shared-secret-value")
    r = client.post("/api/actions/recompute",
                    headers={"x-npr-role": "admin", "x-npr-proxy-secret": "shared-secret-value"})
    assert r.status_code == 200


def test_an_anonymous_request_still_works_with_the_secret_configured(client, monkeypatch):
    """A request that claims nothing needs to prove nothing: probes and public
    reads keep working, they just get the least-privileged actor."""
    monkeypatch.setenv("NPR_PROXY_SECRET", "shared-secret-value")
    assert client.get("/api/live").status_code == 200
    assert client.post("/api/actions/recompute").status_code == 403   # viewer default, not 401


# --- honest health ---------------------------------------------------------

def test_health_is_degraded_and_503_when_the_db_is_down(client, monkeypatch):
    """It hardcoded status:'ok' with db:false, so a dead database and a clean
    estate were pixel-identical on the dashboard."""
    monkeypatch.setattr(main, "ping", lambda: (_ for _ in ()).throw(RuntimeError("no route to host")))
    r = client.get("/api/health")
    assert r.status_code == 503
    body = r.json()
    assert body["status"] == "degraded"
    assert body["db"] is False
    assert "database unreachable" in body["degraded_reasons"]


def test_health_is_degraded_when_the_active_snapshot_is_not_persisted(client, monkeypatch):
    monkeypatch.setattr(main, "ping", lambda: True)
    monkeypatch.setattr(main, "fetch_one", lambda *_a, **_kw: None)
    r = client.get("/api/health")
    assert r.status_code == 503
    assert "active snapshot is not persisted in the database" in r.json()["degraded_reasons"]


def test_health_is_ok_and_reports_the_proxy_gap(client, monkeypatch):
    monkeypatch.setattr(main, "ping", lambda: True)
    monkeypatch.delenv("NPR_PROXY_SECRET", raising=False)
    r = client.get("/api/health")
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "ok"
    assert body["proxy_auth"] is False            # the gap is stated, not silent
    assert body["snapshot_id"] and "ai" in body   # keys the frontend already reads
    monkeypatch.setenv("NPR_PROXY_SECRET", "shared-secret-value")
    assert client.get("/api/health").json()["proxy_auth"] is True


def test_liveness_is_separate_from_readiness(client, monkeypatch):
    """The platform probe must not restart a healthy process whose DB is down."""
    monkeypatch.setattr(main, "ping", lambda: (_ for _ in ()).throw(RuntimeError("down")))
    assert client.get("/api/live").status_code == 200
    assert client.get("/api/health").status_code == 503


# --- a bad dataset is diagnosable, and does not poison the process ---------

def _explodes(message: str):
    """A `run` that raises the way one malformed record in a real export does."""
    def _boom(**_kw):
        raise ValueError(message)
    return _boom


def test_a_bad_dataset_answers_a_diagnosable_4xx_not_an_opaque_500(client, monkeypatch):
    """The engine build is caller-supplied content, so its failure is a 422 that
    NAMES the dataset and the error -- not a 500 that names nothing."""
    monkeypatch.setattr(main, "_ENGINE", None)
    monkeypatch.setattr(main, "run", _explodes("bad prefix len 33 in algosec row 4"))
    r = client.get("/api/findings")
    assert r.status_code == 422, r.text
    detail = r.json()["detail"]
    assert "could not be analyzed" in detail
    assert "bad prefix len 33" in detail and "ValueError" in detail
    assert r.json()["request_id"] == r.headers["x-request-id"]


def test_a_failed_dataset_switch_leaves_the_working_scenario_active(client, monkeypatch, eng):
    """The poisoned singleton, exactly. `_ACTIVE_SCENARIO` was reassigned BEFORE
    the build, so a scenario that fails to analyze became the active one anyway
    and every later request rebuilt it -- one bad switch bricked the process until
    a restart. The build now happens first and only a success rebinds anything."""
    before = main._ACTIVE_SCENARIO
    monkeypatch.setattr(main, "run", _explodes("unparseable object catalog"))
    r = client.post("/api/admin/dataset", json={"scenario": "scale", "n": 10},
                    headers={"x-npr-role": "admin"})
    assert r.status_code == 422, r.text
    assert "scale" in r.json()["detail"]
    assert main._ACTIVE_SCENARIO == before, "the failing scenario became the active one"
    assert main._ENGINE is eng, "the previously good snapshot was thrown away"
    # ...and the app still answers from the snapshot it already had.
    assert client.get("/api/findings").status_code == 200


def test_health_reports_a_rebuild_that_failed_behind_a_served_snapshot(client, monkeypatch):
    """The state that is otherwise invisible: reads keep working off the last good
    engine, so every screen renders confidently while the estate on it is stale."""
    monkeypatch.setattr(main, "ping", lambda: True)
    monkeypatch.setattr(main, "run", _explodes("bad prefix len 33"))
    assert client.post("/api/admin/dataset", json={"scenario": "scale"},
                       headers={"x-npr-role": "admin"}).status_code == 422
    body = client.get("/api/health").json()
    assert body["status"] == "degraded"
    assert any("the last engine rebuild failed" in reason for reason in body["degraded_reasons"])


def test_a_recovered_build_clears_the_marker(client, monkeypatch, eng):
    """A degraded state that cannot clear is its own lie -- the banner would stay
    up forever after one transient bad file."""
    monkeypatch.setattr(main, "ping", lambda: True)
    monkeypatch.setattr(main, "run", _explodes("bad prefix len 33"))
    client.post("/api/admin/dataset", json={"scenario": "scale"}, headers={"x-npr-role": "admin"})
    assert main._ENGINE_STATE["build_error"]
    monkeypatch.setattr(main, "run", lambda **_kw: eng)
    assert client.post("/api/recompute", headers={"x-npr-role": "admin"}).status_code == 200
    assert main._ENGINE_STATE["build_error"] is None
    assert client.get("/api/health").json()["status"] == "ok"


# --- failures that change the answer are no longer swallowed ---------------

def test_recompute_refuses_to_persist_a_snapshot_missing_its_merges(client, monkeypatch):
    """The worst failure mode in the product: a transient DB error made
    `_load_merges` return [], the engine recomputed WITHOUT the operator's
    confirmed merges, and that got persisted as authoritative."""
    def _boom(_cur):
        raise RuntimeError("connection reset")

    monkeypatch.setattr(main, "load_asset_merges", _boom)
    r = client.post("/api/recompute", headers={"x-npr-role": "admin"})
    assert r.status_code == 503
    assert "refusing to persist a degraded snapshot" in r.json()["detail"]
    assert main._ENGINE_STATE["inputs_ok"] is False
    # ...and the reason is on the status payload rather than only in a log.
    monkeypatch.setattr(main, "ping", lambda: True)
    assert any("confirmed merges" in reason
               for reason in client.get("/api/health").json()["degraded_reasons"])


def test_request_id_is_minted_and_echoed(client):
    r = client.get("/api/live")
    assert r.headers["x-request-id"]
    passed_through = client.get("/api/live", headers={"x-request-id": "trace-abc123"})
    assert passed_through.headers["x-request-id"] == "trace-abc123"


def test_an_unhandled_error_returns_the_request_id_not_a_stack(cur, monkeypatch):
    """The global handler: a 500 leaves with the id that is on every log line for
    the request, and nothing else."""
    monkeypatch.setattr(main.rank_mod, "rank", lambda _f: (_ for _ in ()).throw(ValueError("boom")))
    noisy = TestClient(main.app, raise_server_exceptions=False)
    r = noisy.post("/api/actions/recompute", headers={"x-npr-role": "admin"})
    assert r.status_code == 500
    body = r.json()
    assert body["error"] == "internal server error" and body["request_id"]
    assert "boom" not in r.text and "Traceback" not in r.text
