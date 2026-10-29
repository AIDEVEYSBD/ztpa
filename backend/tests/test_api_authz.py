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

Then a five-lens security review found three controls in this file's own subject
area that LOOKED enforced and were not. Each has a section below, and each test
in it fails against the code as it stood:

4. THE SECRET AUTHENTICATED THE CLAIM, NOT THE REQUEST. The middleware demanded
   `x-npr-proxy-secret` only from a request carrying `x-npr-*`, so with the
   boundary correctly configured a header-less request from the open internet was
   still served as the default `viewer` -- which reads every finding, the asset
   inventory and the reachability graph. The test that covered this ASSERTED the
   hole as a feature; see the one that replaced it.

5. THE CAPABILITY GATE WAS DOCUMENTED "FAIL-CLOSED" AND FAILED OPEN. On a cold
   process with the database unreachable, `_settings_map` cached an empty map as
   though it had been read, and an empty map means every capability on for every
   role. Killing the database re-enabled a capability an admin had turned off.

6. THE REFLECTIVE GUARD CHECK COULD NOT CATCH WHAT IT CLAIMED TO. It subtracted
   {GET, HEAD, OPTIONS} from a route's methods BEFORE looking at the handler, so
   a route registered as a GET was invisible to it however much state it wrote --
   and GET /api/actions wrote `ranked_actions` (after a live LLM call) on every
   console load, with this test green throughout. It now measures what a handler
   and its helpers actually write, whatever verb they sit behind.

Nothing here opens a connection: `get_conn` and every persistence call main.py
imports are replaced with recorders, so a 403 that is really a masked DB error
cannot pass for a pass.
"""

from __future__ import annotations

import ast
import contextlib
import inspect
import re
import textwrap
import threading
import time
import types

import pytest
from fastapi.testclient import TestClient

from app import main
from src import request_ctx, tools_registry
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
    monkeypatch.setattr(main, "reject_change_request", lambda *_a, **_kw: 1)

    # The capability layer reads ztpa.tool_settings through its OWN `get_conn`
    # (src.tools_registry imports it from src.db, so patching main's does not
    # cover it). Wired to the same fake with a cold cache, it models a HEALTHY
    # settings table with no rows in it -- every capability default-on for every
    # role -- which is the state this file's subject, ROLE authorization, has to
    # be measured against. The capability layer's own fail-closed behaviour is
    # asserted separately, further down, where the database is dead on purpose.
    monkeypatch.setattr(tools_registry, "_CACHE",
                        {"at": 0.0, "map": {}, "loaded": False, "read_at": 0.0})
    monkeypatch.setattr(tools_registry, "get_conn", _fake_get_conn)
    monkeypatch.setattr(tools_registry, "fetch_all", lambda *_a, **_kw: [])

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


# Routes that may write without a role guard, keyed "METHOD /path" -- the method
# is part of the key because a path can carry both a guarded write and an
# unguarded read (POST and GET /api/campaign/plan), and a per-path exemption
# would silently cover both.
#
# Each entry writes NO change-governance row: it computes, drafts prose for a
# human, or refreshes an engine-owned cache. The reason is per route because
# "advisory" as a blanket word is what let three governance writers sit on this
# list; `test_no_exempt_route_writes_governance_state` checks the claim instead
# of taking it.
EXEMPT_ROUTES = {
    # NOT "no writes", which is what this line used to say: the handler calls
    # audit(cur, "agent_ask", ...) -> INSERT INTO ztpa.audit_log. The row is an
    # append to the trail, not change-governance state, so the exemption stands --
    # but the sentence has to name the write, or it is the same kind of unmeasured
    # claim as the one three governance writers sat behind.
    "POST /api/agent/ask": "read-only engine tools + prose; its only write appends one ztpa.audit_log row",
    "POST /api/intake": "parses a request into a proposal for a human; persists nothing",
    "POST /api/connectors/propose": "drafts a source profile; persists nothing",
    "POST /api/findings/{fid}/explain":
        "caches prose onto ztpa.findings, an ENGINE-owned row (via the _bg_explain thread), "
        "and appends one ztpa.audit_log row",
    # The three reads below reach a write only through the ranked-actions cache:
    # ztpa.ranked_actions is ENGINE-owned (src/db.ENGINE_OWNED_TABLES -- cleared
    # and re-derived on every recompute), it is keyed on the snapshot the caller
    # is already allowed to read, and the model call that fills it is gated by
    # `_require_capability("rank")` rather than by a role. Being on this list is
    # what makes them visible: before the check below could see a GET at all,
    # /api/actions ran an LLM call and a write on every console load and no test
    # in this file could have noticed.
    "GET /api/actions":
        "pure read; on a cache miss it refreshes ztpa.ranked_actions, an ENGINE-owned cache, "
        "on a background thread",
    "GET /api/report": "reads the ztpa.ranked_actions cache and refills it on a miss (ENGINE-owned)",
    "GET /api/report/narrative":
        "reads the ztpa.ranked_actions cache and refills it on a miss (ENGINE-owned)",
}

# The names that write, matched against a handler's own source AND against the
# source of every app.main helper it reaches, because "does this route mutate
# state?" is not answerable from one function body: /api/actions' write moved
# into a helper the moment it was made honest, and a check that only read the
# endpoint body would have called that a fix.
_WRITE_NAME = re.compile(
    r"^_?(?:upsert|upsert_many|insert|audit|cache_explanation|persist_\w+|delete_asset_merge|"
    r"delete_snapshot\w*|reject_change_request|accept_remediation_revision|reset_change_workflow|"
    r"ensure_\w+)$")
_WRITE_SQL = re.compile(r"\b(INSERT\s+INTO|UPDATE\s+ztpa|DELETE\s+FROM)\b", re.I)

# The ONE thing a read is allowed to write, and the only name excluded from the
# scan: `engine()` persists the active snapshot the first time any request needs
# it, because the process holds a computed snapshot the database has never seen.
# That write is a property of the process starting up, not of the caller -- it
# happens once, identically, whoever asks first -- so counting it would mark every
# GET in the file as a mutation and make the check useless. `sid`/`view_sid` are
# one-line wrappers around it and `_warm_engine` is the boot thread that races it.
_SELF_HEAL = frozenset({"engine", "sid", "view_sid", "_warm_engine"})


def _referenced_names(tree: ast.AST) -> set[str]:
    """Every bare name the code MENTIONS -- called or not.

    Not "every name followed by an open paren": work handed to a thread is
    REFERENCED, `_spawn(f"rank-{t}", _bg_rank, t, findings)`, and a call-shaped
    scan walks straight past the one line that moved a write off the request
    path. Read off the AST rather than the text, so a path in a route decorator
    ("/api/agent/suggestions") and a docstring that names another endpoint
    ("...the tables that classify() writes") are not mistaken for code -- both
    produced a false accusation in an earlier draft of this scan.

    ast.Name only, never ast.Attribute: `ranked.actions` would otherwise resolve
    the ATTRIBUTE `actions` to the module-level route handler of the same name
    and drag a whole endpoint into the closure of a two-line helper."""
    return {n.id for n in ast.walk(tree) if isinstance(n, ast.Name)}


def _writes_in(tree: ast.AST) -> set[str]:
    """The write primitives called directly in one function body, plus any raw
    mutating SQL passed to a call (`cur.execute("DELETE FROM ...")`)."""
    found: set[str] = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        fn = node.func
        name = fn.id if isinstance(fn, ast.Name) else fn.attr if isinstance(fn, ast.Attribute) else ""
        if _WRITE_NAME.match(name or ""):
            found.add(name)
        for arg in node.args:
            if isinstance(arg, ast.Constant) and isinstance(arg.value, str) and _WRITE_SQL.search(arg.value):
                found.add("raw SQL")
    return found


def _tree_of(fn):
    try:
        return ast.parse(textwrap.dedent(inspect.getsource(fn)))
    except (OSError, TypeError, SyntaxError):   # a C function, or a lambda from a fixture
        return None


def _writes_reached_by(fn) -> set[str]:
    """Every write primitive `fn` can reach, through the app.main helpers it uses.

    A worklist over the whole reachable closure rather than a depth-limited
    walk: with a depth cut-off the answer depends on the ORDER helpers happen to
    be visited in, and a write four hops down (endpoint -> starter -> thread body
    -> writer) reads as no write at all. The closure is finite -- functions
    defined in app.main -- so it terminates on its own.

    Source-level on purpose: it needs no database, no request and no import of
    what a helper does at runtime, and it fails in the direction that is safe --
    a name it cannot resolve is simply not followed, so the answer is a LOWER
    bound on what a route writes, never an inflated one."""
    found: set[str] = set()
    seen, queue = {fn}, [fn]
    while queue:
        tree = _tree_of(queue.pop())
        if tree is None:
            continue
        found |= _writes_in(tree)
        for name in sorted(_referenced_names(tree)):
            if name in _SELF_HEAL:
                continue
            helper = getattr(main, name, None)
            # Only follow functions DEFINED in app.main: an imported writer
            # (`audit`, `persist_*`) is already detected by name above, and
            # descending into src/persist.py would drown the answer in its
            # internals.
            if not (inspect.isfunction(helper) and helper.__module__ == main.__name__):
                continue
            if helper not in seen:
                seen.add(helper)
                queue.append(helper)
    return found


def _routes() -> list[tuple[str, str, object]]:
    """(method, path, endpoint) for every route in the live app, one row per
    method. HEAD is dropped: Starlette registers it alongside every GET and it
    dispatches to the same handler, so keeping it would double every finding."""
    out = []
    for route in main.app.routes:
        for method in sorted(getattr(route, "methods", set()) or set()):
            if method == "HEAD" or not getattr(route, "endpoint", None):
                continue
            out.append((method, route.path, route.endpoint))
    return out


def _guards_on(route) -> set:
    return {d.call for d in route.dependant.dependencies}

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


def test_no_mutating_route_is_unguarded():
    """Nothing that writes may be reachable without a role dependency.

    THE PROPERTY THIS USED TO CLAIM AND COULD NOT HOLD. The first line of the old
    version was:

        methods = getattr(route, "methods", set()) - {"GET", "HEAD", "OPTIONS"}
        if not methods or route.path in EXEMPT_ROUTES: continue

    -- it decided what mutates state from the HTTP VERB, before looking at the
    handler at all. So a route registered as a GET was structurally invisible to
    it, however much state it changed. That was not hypothetical: GET /api/actions
    ran a live LLM call and wrote ztpa.ranked_actions on every console load, for
    the whole life of the file, and this test passed the entire time. A check that
    cannot fail on the code in front of it is worth less than no check, because it
    is quoted as evidence.

    So the verb is not consulted. Every route in the live table is inspected, and
    "mutates state" is measured from the handler's source and the app.main helpers
    it reaches. A route that writes must carry a role guard or sit on
    EXEMPT_ROUTES with a reason -- and the two tests after this one check the
    reasons and the detector itself, because a scanner that silently matches
    nothing would pass this the same way the verb filter did."""
    guards = {main.require_admin, main.require_approver, main.require_operator}
    by_key = {f"{m} {p}": r for r in main.app.routes
              for m in (getattr(r, "methods", set()) or set()) for p in [r.path]}
    unguarded = {}
    for method, path, endpoint in _routes():
        key = f"{method} {path}"
        if key in EXEMPT_ROUTES:
            continue
        writes = _writes_reached_by(endpoint)
        if writes and not (_guards_on(by_key[key]) & guards):
            unguarded[key] = sorted(writes)
    assert not unguarded, (
        "routes that write with no role guard and no justified exemption:\n"
        f"{unguarded}")


def _endpoints_by_key() -> dict[str, object]:
    return {f"{m} {p}": e for m, p, e in _routes()}


def test_the_check_sees_writes_that_are_not_on_a_post():
    """Guard the guard, against the exact blindness that shipped.

    GET /api/actions is the fixture: it is a read whose cache miss refreshes an
    engine-owned table through a helper and a thread. The detector must see that
    write -- through the helper, on a GET -- or `test_no_mutating_route_is_unguarded`
    is once again asserting a property it cannot observe."""
    endpoints = _endpoints_by_key()
    assert _writes_reached_by(endpoints["GET /api/actions"]), (
        "the write behind GET /api/actions is invisible to the scan; it would be "
        "invisible on any other GET too")
    # ...and the scan is not simply matching everything: a genuine pure read has
    # nothing to find, or the check would flag every route and mean nothing.
    for read in ("GET /api/live", "GET /api/findings", "GET /api/staging", "GET /api/audit"):
        assert not _writes_reached_by(endpoints[read]), f"{read} is a pure read; the scan says otherwise"


def test_every_exemption_names_a_route_that_exists():
    """An exemption for a route that has been renamed or deleted is a hole with a
    comment over it: the key stops matching, nothing is excused, and nobody
    notices -- until a NEW route lands on the stale path and inherits the pass."""
    keys = {f"{m} {p}" for m, p, _e in _routes()}
    assert set(EXEMPT_ROUTES) <= keys, f"exemptions for routes that no longer exist: {set(EXEMPT_ROUTES) - keys}"


def test_no_exempt_route_writes_governance_state():
    """The check that would have caught the false exemption.

    An unguarded route is only acceptable while the sentence justifying it is
    true, so the sentence is verified: neither the handler nor any app.main helper
    it reaches may call a governance writer. Following the helpers matters as much
    here as it does above -- a governance write is no less a governance write for
    being one function call away."""
    offenders = {}
    for key, endpoint in _endpoints_by_key().items():
        if key not in EXEMPT_ROUTES:
            continue
        reached = _writes_reached_by(endpoint)
        writes = sorted(w for w in GOVERNANCE_WRITERS if any(w in r for r in reached))
        if writes:
            offenders[key] = [f"{w} -> {GOVERNANCE_WRITERS[w]}" for w in writes]
    assert not offenders, (
        "An unguarded route writes governance state. Guard it (require_approver "
        f"or require_operator) and take it off EXEMPT_ROUTES:\n{offenders}")


def test_the_governance_writer_check_can_actually_fail():
    """Guard the guard: if the writer names ever stop matching main.py's source,
    the test above would pass by scanning for nothing. The three routes that were
    wrongly exempt are the fixture -- each one must still be detectable."""
    endpoints = _endpoints_by_key()
    for key, writer in (("POST /api/change/classify", "persist_change_decision"),
                        ("POST /api/findings/{fid}/remediate", "persist_remediation_revision"),
                        ("POST /api/findings/{fid}/remediate/refine", "persist_remediation_revision")):
        assert writer in inspect.getsource(endpoints[key]), key
        assert writer in GOVERNANCE_WRITERS
        assert key not in EXEMPT_ROUTES, f"{key} writes governance state and may not be exempt"


def test_an_exemption_that_claims_no_writes_makes_none():
    """The sentence, measured -- one level below the governance check.

    `test_no_exempt_route_writes_governance_state` asks whether an unguarded
    route writes CHANGE-GOVERNANCE state. /api/agent/ask did not, so it passed
    while its justification read "read-only engine tools + prose; no writes" and
    its handler called `audit(cur, "agent_ask", ...)` -- an INSERT into
    ztpa.audit_log on every question anyone asks. Narrowly harmless, and exactly
    the shape of the defect this file exists for: a hand-written claim on the
    exemption list that nothing ever compared against the code.

    So an exemption may claim it writes nothing only while it writes nothing."""
    endpoints = _endpoints_by_key()
    liars = {}
    for key, reason in EXEMPT_ROUTES.items():
        if "no writes" not in reason and "persists nothing" not in reason:
            continue    # the reason already names what it writes; the check above covers it
        calls = sorted(_writes_reached_by(endpoints[key]))
        if calls:
            liars[key] = calls
    assert not liars, (
        "An exemption claims it writes nothing and its handler writes:\n"
        f"{liars}\nName the write in the reason, or stop making it.")

    # Guard the guard: /api/agent/ask is the route the false sentence sat on, so
    # the detector must be able to see its write, and its reason must name it.
    assert "audit" in _writes_reached_by(endpoints["POST /api/agent/ask"]), (
        "the write the reason names is gone; re-check the reason")
    assert "audit_log" in EXEMPT_ROUTES["POST /api/agent/ask"], (
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


def test_during_a_rotation_the_previous_secret_is_also_accepted(client, monkeypatch):
    """The API takes the new secret first while the frontend still sends the
    old one; nothing is refused while they roll. Afterwards the old one is not."""
    monkeypatch.setenv("NPR_PROXY_SECRET", "new-secret-value")
    monkeypatch.setenv("NPR_PROXY_SECRET_PREVIOUS", "old-secret-value")
    for presented in ("new-secret-value", "old-secret-value"):
        r = client.post("/api/actions/recompute", headers={"x-npr-role": "admin", "x-npr-proxy-secret": presented})
        assert r.status_code == 200, presented
    r = client.post("/api/actions/recompute", headers={"x-npr-role": "admin", "x-npr-proxy-secret": "guess"})
    assert r.status_code == 401
    monkeypatch.delenv("NPR_PROXY_SECRET_PREVIOUS")
    r = client.post("/api/actions/recompute", headers={"x-npr-role": "admin", "x-npr-proxy-secret": "old-secret-value"})
    assert r.status_code == 401


def test_an_empty_previous_secret_admits_nothing(client, monkeypatch):
    monkeypatch.setenv("NPR_PROXY_SECRET", "new-secret-value")
    monkeypatch.setenv("NPR_PROXY_SECRET_PREVIOUS", "  ")
    r = client.post("/api/actions/recompute", headers={"x-npr-role": "admin", "x-npr-proxy-secret": ""})
    assert r.status_code == 401


SECRET = {"x-npr-proxy-secret": "shared-secret-value"}


def test_an_anonymous_request_is_refused_when_the_secret_is_configured(client, monkeypatch):
    """THE HOLE THIS FILE USED TO ASSERT AS A FEATURE.

    The test that stood here was named
    `test_an_anonymous_request_still_works_with_the_secret_configured`, and it
    asserted that with NPR_PROXY_SECRET set, a request carrying NO headers at all
    got 403 rather than 401 -- reasoning that "a request that claims nothing needs
    to prove nothing". The middleware agreed: it demanded the secret only from a
    request that claimed an identity.

    But the anonymous default is not "no access", it is `Actor(role="viewer")`,
    and a viewer reads every finding, the whole asset inventory and the
    reachability graph of the customer's network. So the shape of the bypass was
    "send nothing": with the boundary correctly configured and the proxy
    correctly forwarding, anyone who could reach the public Render URL could read
    the entire estate by omitting all headers, and this test called that
    behaviour correct. It is the difference between authenticating the CLAIM and
    authenticating the REQUEST.

    The claim-level refusal is unchanged (the three tests above); what is new is
    that claiming nothing is not a way around it."""
    monkeypatch.setenv("NPR_PROXY_SECRET", "shared-secret-value")
    for method, path in (("GET", "/api/findings"), ("GET", "/api/health"), ("GET", "/api/audit"),
                         ("POST", "/api/actions/recompute"), ("GET", "/api/snapshots")):
        r = client.request(method, path)
        assert r.status_code == 401, f"{method} {path} answered {r.status_code} to a header-less request"
        assert "proxy secret" in r.json()["detail"]
    # ...and the same request WITH the secret is served, so this is a boundary and
    # not simply a wall: the anonymous caller is still the least-privileged actor.
    assert client.get("/api/findings", headers=SECRET).status_code == 200
    assert client.post("/api/actions/recompute", headers=SECRET).status_code == 403   # viewer, not 401


def test_the_liveness_probe_is_reachable_without_the_secret(client, monkeypatch):
    """The one exemption that has to exist: render.yaml points its health check at
    /api/live, Render cannot be handed the shared secret, and a probe that 401s
    restart-loops a process whose only problem is that it is well defended."""
    monkeypatch.setenv("NPR_PROXY_SECRET", "shared-secret-value")
    r = client.get("/api/live")
    assert r.status_code == 200 and r.json() == {"status": "alive"}
    # It is an exemption from PRESENTING the secret, not from the forged-header
    # check: a probe that tries to claim a role is still refused.
    assert client.get("/api/live", headers={"x-npr-role": "admin"}).status_code == 401


def test_a_cors_preflight_is_not_blocked_by_the_boundary(client, monkeypatch):
    """A browser sends no custom headers on a preflight, by specification. If the
    preflight is answered with a 401 (and, because this middleware runs OUTSIDE
    CORSMiddleware, with no CORS headers on it), every cross-origin call fails
    before the request carrying the secret is ever sent."""
    monkeypatch.setenv("NPR_PROXY_SECRET", "shared-secret-value")
    r = client.options("/api/findings", headers={
        "Origin": "http://localhost:3000",
        "Access-Control-Request-Method": "GET",
    })
    assert r.status_code == 200, r.text
    assert r.headers.get("access-control-allow-origin") == "http://localhost:3000"


def test_the_boundary_is_off_when_it_is_unconfigured(client, monkeypatch):
    """Dev parity, stated as a property rather than left implied: with no secret
    configured NOTHING is refused for want of one, which is what makes turning it
    on a deployment decision instead of a code change."""
    monkeypatch.delenv("NPR_PROXY_SECRET", raising=False)
    assert not request_ctx.secret_required_for("/api/findings", "GET")
    assert client.get("/api/findings").status_code == 200
    monkeypatch.setenv("NPR_PROXY_SECRET", "shared-secret-value")
    assert request_ctx.secret_required_for("/api/findings", "GET")
    assert not request_ctx.secret_required_for("/api/live", "GET")
    assert not request_ctx.secret_required_for("/api/findings", "OPTIONS")
    # An exact-path exemption, never a prefix: "/api/live" must not admit a path
    # that merely starts with it.
    assert request_ctx.secret_required_for("/api/livewire", "GET")


# --- the AI kill switch, which was documented fail-closed and failed OPEN ----
# `_require_capability` carried the sentence "403 a disabled AI capability for the
# caller's role (fail-closed)" over a lookup whose except branch was:
#
#     except Exception:
#         m = _CACHE["map"]          # {} on a cold process
#     _CACHE.update(at=now, map=m)   # ...stored as though it had been read
#
# An empty map means "no row", and no row means enabled for every role. So the
# first failed read on a fresh worker turned every capability back on for
# everyone -- and cached that as a successful read. Killing the database was a
# way to re-enable a capability an admin had turned off, which for `rank` means
# re-enabling the spend an operator was trying to stop.
#
# THE FIRST FIX LEFT THE HOLE OPEN FOR THE ONE ROLE THAT COULD USE IT. Unknown
# resolved to a single `FAIL_CLOSED_ROLES = ["admin"]`, on the reasoning that an
# operator must keep the Tools screen during an outage. But /api/actions/recompute
# is admin-only, /api/report is admin-reachable and GET /api/actions spawns a
# background rank, so "admin keeps everything" meant the `rank` kill switch was
# still bypassable by 100% of the callers who could reach the spend. Proved
# against a real Postgres: `rank` durably '{}' for every role plus an unreadable
# ztpa.tool_settings (renamed -- the rest of the database perfectly healthy) gave
# three model calls in one admin session, one of them from a console page load.
# Unknown now resolves per kind: no ai_capability for ANYONE, agent tools for
# admin. The test that pinned the old 200 is the one directly below the cold-start
# test; it asserted the bypass as intended behaviour.
#
# THE THIRD BUG WAS A SUCCESSFUL DISABLE BEING UNDONE. `invalidate_cache()` kept
# map/loaded, so a read failure right after a toggle served the PRE-disable map
# for every role, indefinitely. Two tests below pin the two halves of that fix:
# the toggle is written into the in-process map, and a map nobody can refresh
# decays to the fail-closed answer instead of being served forever.
#
# These tests drive the real endpoint, not the registry function, because the
# claim under test is about what the API does, not about what a helper returns.

def _dead_settings_db(monkeypatch, *, loaded_map=None, stale_for=0.0):
    """Point tools_registry at a database that raises, with the cache in the state
    a freshly started worker is in (nothing ever read) unless `loaded_map` says a
    successful read happened first.

    `loaded_map=None` is the COLD case (`loaded` False, the empty map is not
    knowledge); passing a map is the warm last-known-good case, aged by
    `stale_for` seconds so the decay bound can be exercised without sleeping."""
    monkeypatch.setattr(tools_registry, "_CACHE",
                        {"at": 0.0, "map": dict(loaded_map or {}), "loaded": loaded_map is not None,
                         "read_at": time.monotonic() - stale_for})

    def _boom():
        raise RuntimeError("connection refused")

    monkeypatch.setattr(tools_registry, "get_conn", _boom)


def test_a_capability_stays_disabled_when_the_settings_database_dies(client, monkeypatch):
    """The warm last-known-good path, end to end: a read HAS succeeded and it said
    `rank` is off for every role; the database then goes away; the ranking endpoint
    must not start spending again on the strength of a failed read.

    (`loaded_map` is what that successful read returned, so this is deliberately
    NOT the cold start -- that case is the next test, and it used to pass only
    because this one was mislabelled as covering it.)"""
    _dead_settings_db(monkeypatch, loaded_map={"rank": []})
    called = []
    monkeypatch.setattr(main.rank_mod, "rank", lambda f: called.append(1) or RankedActions())
    r = client.post("/api/actions/recompute", headers={"x-npr-role": "admin"})
    assert r.status_code == 403, r.text
    assert "capability 'rank' is disabled" in r.json()["detail"]
    assert called == [], "the model was asked to rank a capability the admin had disabled"


def test_a_cold_worker_with_no_database_refuses_to_spend_for_every_role(client, monkeypatch):
    """The cold-start bypass itself, which no test covered: nothing has ever been
    read, the read fails, and the honest answer to "is this disabled?" is
    "unknown". Unknown may not resolve to spend -- FOR ANYONE.

    This test asserted `admin -> 200` until the real-Postgres probe showed what
    that 200 costs: with `rank` set to '{}' for every role in the durable table
    and only ztpa.tool_settings unreadable, an admin session made three model
    calls (a console page load, Recompute, and the report's cache-miss refill).
    Admin was the carve-out AND the only role that can reach /api/actions/recompute,
    so the carve-out was the entire bypass. What an operator actually needs during
    the outage -- the Tools screen and the deterministic engine tools -- is
    asserted here too, because a control that locks the operator out is its own
    outage."""
    _dead_settings_db(monkeypatch)
    called = []
    monkeypatch.setattr(main.rank_mod, "rank", lambda f: called.append(1) or RankedActions())

    # Every role, including the one the old test let through.
    admin = client.post("/api/actions/recompute", headers={"x-npr-role": "admin"})
    assert admin.status_code == 403, admin.text
    assert "capability 'rank' is disabled" in admin.json()["detail"]
    assert client.post("/api/actions/recompute", headers={"x-npr-role": "analyst"}).status_code == 403
    for role in ("admin", "analyst"):
        assert client.post("/api/change/classify", headers={"x-npr-role": role},
                           json={"source": "10.20.5.0/24", "destination": "app-server-07",
                                 "service": "tcp/22"}).status_code == 403
    # The two paths a console page load takes: neither may start a ranking.
    actions = client.get("/api/actions", headers={"x-npr-role": "admin"})
    assert actions.status_code == 200, actions.text
    assert actions.json()["pending"] is False, "a cold worker with no settings still queued a ranking"
    assert client.get("/api/report", headers={"x-npr-role": "admin"}).status_code == 403
    assert called == [], "the ranking model was reached on a worker that cannot read its kill switch"

    # ...and the operator keeps what they need to diagnose the outage: the Tools
    # screen (gated by ROLE, never by capability) and the deterministic tools.
    assert client.get("/api/admin/tools", headers={"x-npr-role": "admin"}).status_code == 200
    assert tools_registry.enabled_roles("resolve") == tools_registry.UNKNOWN_TOOL_ROLES == ["admin"]
    assert tools_registry.enabled_roles("rank") == tools_registry.UNKNOWN_SPEND_ROLES == []


def test_a_failed_read_is_never_cached_as_a_successful_one(monkeypatch):
    """The specific line that made this a bypass rather than a blip: the failure
    path used to write `{}` into the cache WITH a fresh timestamp, so for the next
    five seconds the process could not tell it had never read anything."""
    _dead_settings_db(monkeypatch)
    assert tools_registry.enabled_roles("rank") == []
    assert tools_registry._CACHE["loaded"] is False, "a failed read was recorded as knowledge"
    assert tools_registry._CACHE["map"] == {}


def test_an_empty_map_means_opposite_things_read_and_unread(monkeypatch):
    """`{}` is the answer for both "the settings table is empty" and "the query
    raised", and the whole fix rests on those two resolving oppositely. Same empty
    map, both directions, in one place so neither can drift.

    Default-on for a row that genuinely is not there is deliberate: the Tools
    screen is an opt-out toggle, and `classify`, `remediate`, `campaign` and every
    agent tool ship with no row at all."""
    read = {"at": 0.0, "map": {}, "loaded": True, "read_at": time.monotonic()}
    monkeypatch.setattr(tools_registry, "_CACHE", read)
    monkeypatch.setattr(tools_registry, "get_conn", lambda: (_ for _ in ()).throw(RuntimeError("down")))
    assert tools_registry.enabled_roles("rank") == tools_registry.ALL_ROLES   # empty table, read
    _dead_settings_db(monkeypatch)                                            # empty map, never read
    assert tools_registry.enabled_roles("rank") == []


def test_a_last_known_good_answer_survives_a_blip_rather_than_locking_everyone_out(monkeypatch):
    """The other half of fail-closed, which matters just as much: once a read HAS
    succeeded, the answer is known, and a transient failure serves it stale rather
    than dropping every analyst to fail-closed over one dropped connection."""
    _dead_settings_db(monkeypatch, loaded_map={"explain": ["admin", "analyst", "viewer"], "rank": []})
    assert tools_registry.enabled_roles("explain") == ["admin", "analyst", "viewer"]
    assert tools_registry.enabled_roles("rank") == []          # disabled stays disabled
    # An absent row still means default-on, because the map really was read.
    assert tools_registry.enabled_roles("intake") == tools_registry.ALL_ROLES


def test_a_map_nobody_can_refresh_decays_instead_of_being_served_forever(monkeypatch):
    """The bound on "last-known-good". Serving an unrefreshable map indefinitely
    means "keep ztpa.tool_settings unreadable" is a way to keep a killed capability
    alive -- in the worker that never saw the toggle, which apply_setting cannot
    reach. After _MAX_STALE the map is no longer evidence of anything.

    Decay is one-way: it is intersected with the stale map, so ageing out can take
    a role's access away and never hand it back."""
    fresh = {"explain": ["admin", "analyst", "viewer"], "rank": ["admin"], "resolve": []}
    _dead_settings_db(monkeypatch, loaded_map=fresh, stale_for=tools_registry._MAX_STALE + 1)
    assert tools_registry.enabled_roles("explain") == [], "a stale map kept an AI capability alive"
    assert tools_registry.enabled_roles("rank") == []
    assert tools_registry.enabled_roles("intake") == []        # absent row, no longer default-on
    # `resolve` is a free deterministic tool, so the unknown answer is admin -- but
    # the stale map says nobody, and the more restrictive of the two wins.
    assert tools_registry.enabled_roles("resolve") == []
    # ...whereas a stale map that said nothing about it decays to the admin floor.
    _dead_settings_db(monkeypatch, loaded_map={"rank": ["admin"]},
                      stale_for=tools_registry._MAX_STALE + 1)
    assert tools_registry.enabled_roles("resolve") == ["admin"]


def test_a_disable_that_was_written_survives_the_store_breaking_afterwards(client, monkeypatch):
    """The kill switch is pressed successfully, and THEN the settings reads fail.

    `invalidate_cache()` cleared only the timestamp, so the next (failing) read
    fell back on the map from before the toggle: the durably-persisted disable was
    reverted by breaking the store, and not just for admin -- an analyst could
    still fire the model. The row is committed by the time the route returns, so
    the new value is knowledge and is written into the map here."""
    monkeypatch.setattr(tools_registry, "_CACHE",
                        {"at": 0.0, "map": {}, "loaded": False, "read_at": 0.0})
    monkeypatch.setattr(tools_registry, "fetch_all", lambda *_a, **_kw: [
        {"tool_key": "rank", "enabled_roles": list(tools_registry.ALL_ROLES)}])
    assert tools_registry.enabled_roles("rank") == tools_registry.ALL_ROLES   # a real, warm read

    r = client.post("/api/admin/tools/rank", json={"enabled_roles": []},
                    headers={"x-npr-role": "admin"})
    assert r.status_code == 200, r.text

    def _boom():
        raise RuntimeError("connection refused")

    monkeypatch.setattr(tools_registry, "get_conn", _boom)     # the store breaks AFTER the write
    called = []
    monkeypatch.setattr(main.rank_mod, "rank", lambda f: called.append(1) or RankedActions())
    for role in tools_registry.ALL_ROLES:
        assert tools_registry.enabled_for(role, "rank") is False, f"the disable was undone for {role}"
    assert client.post("/api/actions/recompute", headers={"x-npr-role": "admin"}).status_code == 403
    analyst = client.get("/api/actions", headers={"x-npr-role": "analyst"})
    assert analyst.status_code == 200, analyst.text
    assert analyst.json()["pending"] is False
    assert called == [], "a capability disabled through the API spent after the settings read failed"


def test_disabling_ranking_stops_every_path_that_could_spend(client, monkeypatch):
    """The kill switch, measured across the surface rather than at one endpoint.

    `rank` disabled for analysts: the recompute route refuses, the report's
    cache-miss refill refuses, and the read that used to fire a live model call on
    every console load quietly serves the deterministic grouping instead of
    starting a background one. No path reaches `rank_mod.rank`."""
    # A real row in a reachable ztpa.tool_settings: `rank` left on for admins and
    # taken away from everyone else, which is what the Tools screen writes.
    monkeypatch.setattr(tools_registry, "fetch_all",
                        lambda *_a, **_kw: [{"tool_key": "rank", "enabled_roles": ["admin"]}])
    called = []
    monkeypatch.setattr(main.rank_mod, "rank", lambda f: called.append(1) or RankedActions())
    analyst = {"x-npr-role": "analyst"}
    assert client.post("/api/actions/recompute", headers=analyst).status_code == 403
    assert client.get("/api/report", headers=analyst).status_code == 403
    actions = client.get("/api/actions", headers=analyst)
    assert actions.status_code == 200, actions.text
    assert actions.json()["pending"] is False, "a disabled capability still queued a ranking run"
    assert actions.json()["ranked_by"] == "engine_fallback"
    assert called == [], "the ranking model was called with the capability disabled"

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
    # The status payload is behind the boundary too (it names the active snapshot,
    # the AI provider and every degraded reason), so reading it now takes the
    # secret -- which the console's proxy attaches to every call it makes.
    assert client.get("/api/health", headers=SECRET).json()["proxy_auth"] is True


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


# --- the audit trail's reader ----------------------------------------------
# The trail had twenty write sites, one endpoint nobody called, and no screen.
# GET /api/audit is now the read side of it, and it is the one read in the API
# that enumerates WHO did what across every actor in the system -- so it is
# admin-only, bounded, and paginated with a total.

def _audit_rows(n: int) -> list[dict]:
    return [{"id": f"id{i}", "ts": f"2026-09-01T10:{i:02d}:00Z", "actor": "user",
             "actor_email": "admin@example.com", "actor_sub": "sub-1", "actor_role": "admin",
             "action": "recompute_snapshot", "subject": "snap_x", "snapshot_id": "snap_x",
             "detail": {}} for i in range(n)]


def test_the_audit_trail_is_admin_only(client):
    """It names every actor in the system. A viewer reads the posture; an auditor
    who needs the trail is given admin, which is the role that can also see the
    Tools screen and the metrics."""
    for role in ("viewer", "analyst"):
        r = client.get("/api/audit", headers={"x-npr-role": role})
        assert r.status_code == 403, f"{role} read the audit trail"
        assert "admin only" in r.json()["detail"]


def test_the_audit_trail_answers_the_contract_shape(client, monkeypatch):
    """{items, total, limit, offset} -- `total` because "50 rows" out of an
    unknown number is not something a compliance reader can reason about."""
    monkeypatch.setattr(main, "fetch_all", lambda *_a, **_kw: _audit_rows(3))
    monkeypatch.setattr(main, "fetch_one", lambda *_a, **_kw: {"n": 4213})
    r = client.get("/api/audit", headers={"x-npr-role": "admin"}, params={"limit": 3, "offset": 6})
    assert r.status_code == 200, r.text
    body = r.json()
    assert set(body) == {"items", "total", "limit", "offset"}
    assert body["total"] == 4213 and body["limit"] == 3 and body["offset"] == 6
    assert len(body["items"]) == 3
    # The actor columns db.audit() fills in from request_ctx are what make the
    # trail a governance record rather than a list of verbs.
    assert {"actor_email", "actor_sub", "actor_role"} <= set(body["items"][0])


def test_the_audit_query_is_newest_first_and_paged(client, monkeypatch):
    """Ordering and paging are asserted on the statement, not on a fake's answer:
    a stub can return anything, and the property under test is what SQL was
    issued. `ts DESC, id DESC` because rows written in one transaction share a
    `now()`, and paging on a non-total order repeats and skips rows."""
    seen: list[tuple[str, object]] = []

    def _spy(_cur, sql, params=None):
        seen.append((sql, params))
        return _audit_rows(2)

    monkeypatch.setattr(main, "fetch_all", _spy)
    monkeypatch.setattr(main, "fetch_one", lambda *_a, **_kw: {"n": 2})
    client.get("/api/audit", headers={"x-npr-role": "admin"}, params={"limit": 25, "offset": 50})
    sql, params = seen[-1]
    assert "FROM ztpa.audit_log" in sql
    assert "ORDER BY ts DESC, id DESC" in sql
    assert "LIMIT %s OFFSET %s" in sql and params == [25, 50]


def test_the_audit_limit_is_bounded_by_the_route_not_by_hope(client):
    """`Query(..., ge=1, le=200)`: an out-of-range page is a 422 naming the field,
    never a silently clamped page and never an unbounded scan of the table."""
    admin = {"x-npr-role": "admin"}
    assert client.get("/api/audit", headers=admin, params={"limit": 0}).status_code == 422
    assert client.get("/api/audit", headers=admin, params={"limit": 201}).status_code == 422
    assert client.get("/api/audit", headers=admin, params={"offset": -1}).status_code == 422
    assert client.get("/api/audit", headers=admin, params={"limit": 200}).status_code == 200


def test_no_audit_call_site_passes_a_literal_actor(client):
    """The trail's WHO is read inside db.audit() from request_ctx, so it cannot be
    forgotten on one branch out of fifteen -- and a call site that passed its own
    actor string would be overriding the only source of truth there is. Asserted
    over main.py's source, because "every call site" is the claim."""
    src = inspect.getsource(main)
    literal = re.findall(r"audit\(\s*cur\s*,\s*[\"'](?:user|agent|system)[\"']", src)
    assert not literal, f"audit() call sites still passing a literal actor: {literal}"
    assert "audit(cur," in src, "the scan found no audit call sites at all"


def test_background_work_is_attributed_to_the_actor_that_caused_it(client, monkeypatch):
    """A thread starts with an EMPTY ContextVar context, so the two paths that
    move work off the request (`_bg_explain`, `_bg_rank`) used to run as the
    anonymous `viewer` default -- their ai_metrics rows were attributed to a
    phantom, and now that db.audit() reads the actor itself, their audit rows
    would be too. `_spawn` copies the request's context into the thread, so the
    trail says who asked."""
    seen: dict = {}
    done = threading.Event()

    def _record() -> None:
        actor = request_ctx.current()
        seen.update(role=actor.role, email=actor.email, sub=actor.sub, rid=request_ctx.request_id())
        done.set()

    @main.app.get("/_test/spawn")
    def _spawn_probe():                       # pragma: no cover - registered for this test only
        main._spawn("probe", _record)
        return {"ok": True}

    try:
        r = client.get("/_test/spawn", headers={"x-npr-role": "admin", "x-npr-email": "grace@example.com",
                                                "x-npr-sub": "sub-42", "x-request-id": "trace-xyz"})
        assert r.status_code == 200
        assert done.wait(5), "the spawned thread never ran"
        assert seen == {"role": "admin", "email": "grace@example.com", "sub": "sub-42",
                        "rid": "trace-xyz"}, seen
    finally:
        main.app.router.routes = [rt for rt in main.app.router.routes
                                  if getattr(rt, "path", None) != "/_test/spawn"]
