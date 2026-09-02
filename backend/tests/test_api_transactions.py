"""No model call may run while a database connection is checked out.

THE FAILURE THIS PINS. `settings.OLLAMA_TIMEOUT` defaults to 600 seconds. The
psycopg pool is `max_size=10` with a 30-second acquire timeout. `/api/actions`
called `rank_mod.rank(...)` -- one live LLM call -- from INSIDE
`with get_conn()`, and so did the report (`_ranked_cached(cur)`) and, once per
step, the campaign batch. So eleven people opening the Risks or Report tab on a
cold model held every connection in the pool for as long as the model took, and
every unrelated endpoint -- findings, the graph, health's snapshot probe --
raised PoolTimeout, became a 500, and painted the console with red panels. The
demo failure mode is three people opening the app at once.

The Phase 2 exit criterion is stated as a test, and this is that test:

    "No LLM call executes inside an open DB transaction -- asserted by a test
     that patches get_conn to fail if complete() is called while a connection is
     checked out"

HOW IT IS ASSERTED. `get_conn` is replaced with one that counts checkouts per
THREAD (a background worker holding no connection must not be blamed for the
request thread's, and vice versa), and every `complete` in every `src.*` module
is replaced with one that raises if this thread's count is non-zero. Then every
endpoint that can reach a model is driven through TestClient. A violation is a
500 naming the endpoint, not a slow test -- the assertion is structural, so it
holds whether or not a model is reachable, and it runs in milliseconds.

Two things it deliberately does NOT assert:
  * that a route is fast. Deterministic engine work inside a transaction (the
    push planner, the merge rebuild) is bounded, in-process and has no network,
    and the criterion is about the model, not about the clock;
  * that the model is called at all. `complete` here is a tripwire, not a stub
    with opinions: the routes are free to take their deterministic paths.
"""

from __future__ import annotations

import contextlib
import sys
import threading
import types

import pytest
from fastapi.testclient import TestClient

from app import main
from src import tools_registry
from src.advisory import classify_change
from src.models import RankedActions

ADMIN = {"x-npr-role": "admin", "x-npr-email": "admin@example.com"}


class _FakeCursor:
    """Answers every SELECT the routes make with something plausible, and records
    the statements. Nothing here reaches a database."""

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


class _ConnectionWatch:
    """How many connections THIS thread is holding, and whether a model call
    happened while it held one.

    Per-thread rather than global on purpose: the explain and ranking paths do
    their model call on a background thread precisely so the request thread is
    not holding anything, and a global counter would call that a violation (or,
    worse, miss a real one because another thread happened to be idle)."""

    def __init__(self) -> None:
        self._local = threading.local()
        self.violations: list[str] = []

    @property
    def depth(self) -> int:
        return getattr(self._local, "depth", 0)

    @contextlib.contextmanager
    def conn(self):
        self._local.depth = self.depth + 1
        try:
            yield _FakeConn(_FakeCursor())
        finally:
            self._local.depth -= 1

    def note_model_call(self, where: str) -> None:
        if self.depth:
            self.violations.append(f"{where} ran a model call while holding {self.depth} connection(s)")
            raise AssertionError(self.violations[-1])


@pytest.fixture(scope="module")
def eng():
    from src.analyzers.run_all import run
    return run()


@pytest.fixture
def watch(monkeypatch, eng):
    """Wire the app to the tripwire and return it."""
    w = _ConnectionWatch()
    monkeypatch.setattr(main, "get_conn", w.conn)

    # Every module that calls the model imports `complete` into its own
    # namespace, so patching src.advisory.client.complete alone would cover none
    # of them. Sweep every imported src module that has the name -- the same
    # technique backend/conftest.py uses for record_metric, and for the same
    # reason: a new `from .client import complete` call site must not be able to
    # slip past this quietly.
    def _tripwire(**kwargs):
        w.note_model_call(kwargs.get("capability") or kwargs.get("role") or "a model call")
        return types.SimpleNamespace(ok=False, text="", provider="stub", model="stub",
                                     error="unreachable", tool_calls=None,
                                     prompt_tokens=0, completion_tokens=0)

    patched = 0
    for module in list(sys.modules.values()):
        if getattr(module, "__name__", "").startswith("src") and hasattr(module, "complete"):
            monkeypatch.setattr(module, "complete", _tripwire)
            patched += 1
    assert patched >= 5, f"only {patched} model call sites were covered; the sweep is not finding them"

    # Embeddings are the other network call that used to sit inside a block.
    for module in list(sys.modules.values()):
        if getattr(module, "__name__", "").startswith("src") and hasattr(module, "embed"):
            monkeypatch.setattr(module, "embed",
                                lambda *_a, **_kw: w.note_model_call("embed") or [])

    monkeypatch.setattr(main, "_ENGINE", eng)
    monkeypatch.setattr(main, "_ENGINE_STATE",
                        {"inputs_ok": True, "inputs_error": None, "persisted": True,
                         "persist_error": None, "build_error": None})
    monkeypatch.setattr(main, "run", lambda **_kw: eng)
    monkeypatch.setattr(main, "write_scenario", lambda *_a, **_kw: None)
    monkeypatch.setattr(main, "fetch_one", lambda *_a, **_kw: None)
    monkeypatch.setattr(main, "fetch_all", lambda *_a, **_kw: [])
    monkeypatch.setattr(main, "upsert", lambda *_a, **_kw: None)
    monkeypatch.setattr(main, "audit", lambda *_a, **_kw: None)
    monkeypatch.setattr(main, "load_asset_merges", lambda _cur: [])
    monkeypatch.setattr(main, "load_applied_changes", lambda _cur: [])
    monkeypatch.setattr(main, "persist_engine_result", lambda *_a, **_kw: {"assets": 0, "findings": 0})
    monkeypatch.setattr(main, "persist_ranked_actions", lambda *_a, **_kw: None)
    monkeypatch.setattr(main, "persist_campaign_plan", lambda *_a, **_kw: None)
    monkeypatch.setattr(main, "persist_change_decision", lambda *_a, **_kw: None)
    monkeypatch.setattr(main, "persist_asset_merge", lambda *_a, **_kw: None)
    monkeypatch.setattr(main, "delete_asset_merge", lambda *_a, **_kw: None)
    monkeypatch.setattr(main, "cache_explanation", lambda *_a, **_kw: None)
    monkeypatch.setattr(main, "accept_remediation_revision", lambda *_a, **_kw: None)
    monkeypatch.setattr(main, "persist_remediation_revision", lambda *_a, **_kw: {
        "thread_id": "th", "seq": 1, "revision_id": "rev"})
    # A one-step campaign plan, so /api/campaign/submit actually rules on a step
    # rather than returning an empty batch -- the ruling is the expensive part
    # that used to happen inside the transaction.
    monkeypatch.setattr(main, "load_campaign_plan", lambda *_a, **_kw: {
        "steps": [{"n": 1, "status": "applied", "finding_id": eng.findings[0].id,
                   "change": {"op": "remove", "target_ref": eng.findings[0].raw_refs[0]},
                   "target": {"title": "step one"}}]})

    # The capability layer would otherwise open its own (unpatched) connection
    # and fail closed -- to NOBODY, admin included, since an unreadable
    # ztpa.tool_settings resolves every ai_capability to no roles at all. Wiring
    # it to the same fake (a healthy, empty settings table) keeps the test about
    # transactions rather than about which role happens to be allowed today.
    monkeypatch.setattr(tools_registry, "_CACHE",
                        {"at": 0.0, "map": {}, "loaded": False, "read_at": 0.0})
    monkeypatch.setattr(tools_registry, "get_conn", w.conn)
    monkeypatch.setattr(tools_registry, "fetch_all", lambda *_a, **_kw: [])
    monkeypatch.setattr(classify_change, "complete", _tripwire)
    return w


@pytest.fixture
def client(watch):
    # No `with`: entering the context manager runs the lifespan, which starts a
    # real engine build on a thread that would outlive these patches.
    return TestClient(main.app)


def _join_background_threads(prefix: str = "", timeout: float = 10.0) -> None:
    """Wait for the daemon threads the API starts (explain-*, rank-*).

    The whole point of those threads is that the model call happens off the
    request path -- so a test that returned as soon as the response did would be
    asserting nothing about the half that matters."""
    for t in list(threading.enumerate()):
        if t is not threading.current_thread() and t.name.startswith(prefix) and t.is_alive():
            t.join(timeout)


# --- the criterion, endpoint by endpoint -----------------------------------
# Every route that can reach a model or an embedding, with a body that gets it
# past validation. `_resolve` fills in a finding id from the live snapshot.

MODEL_BEARING_ROUTES = [
    ("GET", "/api/actions", None),
    ("POST", "/api/actions/recompute", None),
    ("GET", "/api/report", None),
    ("GET", "/api/report/narrative", None),
    ("GET", "/api/campaign/plan", None),
    ("POST", "/api/campaign/plan", lambda e: {}),
    ("POST", "/api/campaign/submit", lambda e: {}),
    ("POST", "/api/change/classify",
     lambda e: {"source": "10.20.5.0/24", "destination": "app-server-07", "service": "tcp/22"}),
    ("POST", "/api/change/submit", lambda e: {
        "kind": "remediation", "finding_id": e.findings[0].id,
        "change": {"op": "remove", "target_ref": e.findings[0].raw_refs[0]}}),
    ("POST", "/api/findings/{fid}/explain", None),
    ("POST", "/api/findings/{fid}/remediate", None),
    ("POST", "/api/findings/{fid}/remediate/refine", lambda e: {"comment": "narrow it"}),
    ("POST", "/api/agent/ask", lambda e: {"question": "what can reach db-prod-01?"}),
    ("POST", "/api/intake", lambda e: {"text": "please open tcp/443 from the office to app-server-07"}),
    ("POST", "/api/connectors/propose", lambda e: {"sample": {"rules": []}, "tool_hint": "panos"}),
    ("GET", "/api/assets/merge-suggestions", None),
]
_IDS = [f"{m}:{p}" for m, p, _b in MODEL_BEARING_ROUTES]


@pytest.mark.parametrize(("method", "path", "make_body"), MODEL_BEARING_ROUTES, ids=_IDS)
def test_no_model_call_happens_inside_an_open_transaction(client, watch, eng, method, path, make_body):
    """The exit criterion itself, per endpoint. A violation surfaces as a 500 (the
    tripwire raises inside the handler) plus the recorded reason."""
    r = client.request(method, path.replace("{fid}", eng.findings[0].id),
                       json=make_body(eng) if make_body else None, headers=ADMIN)
    _join_background_threads("explain-")
    _join_background_threads("rank-")
    assert not watch.violations, watch.violations
    assert r.status_code == 200, f"{method} {path} answered {r.status_code}: {r.text[:300]}"


def test_the_tripwire_can_actually_fire(watch):
    """Guard the guard. Every assertion above is "nothing happened", which is also
    what a broken detector reports -- so the detector is made to catch a
    deliberate violation of the exact shape that shipped."""
    from src.advisory import rank as rank_mod

    with pytest.raises(AssertionError, match="while holding 1 connection"):
        with main.get_conn() as _conn:
            rank_mod.rank(list(main._ENGINE.findings))
    assert watch.violations, "the tripwire recorded nothing"


def test_the_watch_is_per_thread_not_global(watch):
    """...and it is not so eager that it fires on the background pattern the fix
    is built on: a model call on another thread while THIS one holds a connection
    is exactly what moving work off the request path looks like."""
    ran: list[str] = []

    def _elsewhere() -> None:
        watch.note_model_call("background")     # holds nothing on its own thread
        ran.append("ok")

    with main.get_conn() as _conn:
        t = threading.Thread(target=_elsewhere, name="probe")
        t.start()
        t.join(5)
    assert ran == ["ok"]
    assert not watch.violations


# --- the two shapes the criterion was violated in ---------------------------

def test_the_actions_read_writes_nothing_and_calls_no_model(client, watch, eng):
    """GET /api/actions was a read that ran a 600-second-timeout model call and a
    write, on every console load, inside one transaction. It is now a cache read
    plus the engine's deterministic grouping; the model ranking is started on a
    thread and the caller is told it is `pending`."""
    r = client.get("/api/actions", headers=ADMIN)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["actions"], "an empty action list renders as 'nothing to do'"
    assert body["ranked_by"] == "engine_fallback"
    assert body["pending"] is True, "the richer ranking was never queued"
    _join_background_threads("rank-")
    assert not watch.violations


@pytest.mark.parametrize("path", ["/api/campaign/submit", "/api/change/submit"])
def test_a_submission_rules_outside_the_transaction_it_writes_in(client, watch, eng, monkeypatch, path):
    """campaign_submit ran a full engine re-analysis PER STEP inside one open
    transaction: a 40-step campaign pinned one of ten pooled connections through
    40 re-analyses, and one failure discarded every submission before it. The
    ruling now happens with nothing checked out; the writes are one short
    transaction afterwards.

    A re-analysis is not a model call, so the tripwire above cannot see this one:
    the depth is recorded at the moment the engine is asked to rule."""
    depths: list[int] = []
    real_validate = main.remediation._validate
    monkeypatch.setattr(main.remediation, "_validate",
                        lambda *a, **k: (depths.append(watch.depth), real_validate(*a, **k))[1])
    body = {} if path.startswith("/api/campaign") else {
        "kind": "remediation", "finding_id": eng.findings[0].id,
        "change": {"op": "remove", "target_ref": eng.findings[0].raw_refs[0]}}
    r = client.post(path, json=body, headers=ADMIN)
    assert r.status_code == 200, r.text
    assert depths, "nothing was ruled on, so the test proves nothing"
    assert depths == [0] * len(depths), f"the engine ruled while holding a connection: {depths}"
    assert not watch.violations


def test_ranking_is_single_flighted(monkeypatch):
    """Ten callers arriving on a cold cache must produce ONE ranking run, not ten.
    Driven through the primitive rather than through ten HTTP requests, so the
    assertion is about the guard and not about how a test client schedules
    threads: the leader is held inside `fn` until every follower has arrived."""
    flight = main._SingleFlight()
    started, release = threading.Event(), threading.Event()
    runs, results = [], {}

    def _leader():
        runs.append("leader")
        started.set()
        release.wait(5)
        return "the one answer"

    def _follower_body():
        runs.append("follower")      # must never happen
        return "a second answer"

    leader = threading.Thread(target=lambda: results.update(leader=flight.run("k", _leader)))
    leader.start()
    assert started.wait(5), "the leader never started"

    followers = [threading.Thread(target=lambda i=i: results.update({i: flight.run("k", _follower_body)}))
                 for i in range(3)]
    for t in followers:
        t.start()
    # Every follower is now either waiting on the leader's Event or about to be;
    # releasing the leader is what lets them all resolve to its result.
    release.set()
    leader.join(5)
    for t in followers:
        t.join(5)

    assert runs == ["leader"], f"the computation ran more than once: {runs}"
    assert set(results.values()) == {"the one answer"}
    # ...and the flight is over: the next caller runs its own.
    assert flight.run("k", lambda: "later") == "later"


def test_a_failed_flight_is_raised_to_everyone_waiting():
    """A follower that silently received `None` would render as an empty estate.
    The leader's exception is the shared answer."""
    flight = main._SingleFlight()
    started, release = threading.Event(), threading.Event()
    errors: list[BaseException] = []

    def _boom():
        started.set()
        release.wait(5)
        raise RuntimeError("the model is down")

    def _try(fn):
        try:
            flight.run("k", fn)
        except BaseException as exc:      # noqa: BLE001 - recorded, not swallowed
            errors.append(exc)

    leader = threading.Thread(target=lambda: _try(_boom))
    leader.start()
    assert started.wait(5)
    follower = threading.Thread(target=lambda: _try(lambda: "never runs"))
    follower.start()
    release.set()
    leader.join(5)
    follower.join(5)
    assert len(errors) == 2 and all(isinstance(e, RuntimeError) for e in errors)


# --- the write path degrades instead of 500-ing -----------------------------

def test_classify_still_rules_when_the_decision_store_is_gone(client, monkeypatch, eng):
    """The flagship "simulate a custom change" card 500'd on any deployment
    without a database -- out of an unguarded get_conn on the write, while every
    input the ruling needs was already in memory. It now answers, and says the
    ruling was not recorded rather than implying it was."""
    def _dead(*_a, **_kw):
        raise RuntimeError("DATABASE_URL is not set")

    monkeypatch.setattr(main, "persist_change_decision", _dead)
    r = client.post("/api/change/classify", headers=ADMIN,
                    json={"source": "10.20.5.0/24", "destination": "app-server-07", "service": "tcp/22"})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["decision"]["decision"] in ("auto_approve", "escalate")
    assert body["persisted"] is False
    assert "NOT" in body["degraded_reason"] and "recorded" in body["degraded_reason"]


def test_a_recorded_ruling_says_so(client):
    """The other half: with a working store the payload claims persistence, so
    `persisted` is a real signal rather than a field that is always false."""
    r = client.post("/api/change/classify", headers=ADMIN,
                    json={"source": "10.20.5.0/24", "destination": "app-server-07", "service": "tcp/22"})
    assert r.status_code == 200, r.text
    assert r.json()["persisted"] is True
    assert "degraded_reason" not in r.json()


def test_the_merge_decision_and_its_snapshot_are_one_transaction(client, watch, eng, monkeypatch):
    """A confirmed merge and the re-persisted snapshot that follows from it used
    to be two transactions with an engine rebuild between them -- so a failure in
    the second left the estate on screen derived from a decision the system of
    record did not reflect. They now share a cursor, which also means the rebuild
    can SEE the merge it is applying (a separate connection could not: it is
    uncommitted)."""
    depths: list[int] = []
    real_build = main._build_engine

    def _watching_build(scenario, inputs=None):
        depths.append(watch.depth)
        assert inputs is not None, "the rebuild re-read its inputs instead of taking the cursor's"
        return real_build(scenario, inputs)

    monkeypatch.setattr(main, "_build_engine", _watching_build)
    r = client.post("/api/assets/merge", json={"a": "app-server-07", "b": "appsrv-07"}, headers=ADMIN)
    assert r.status_code == 200, r.text
    assert depths == [1], f"the rebuild ran outside the merge's transaction: {depths}"


def test_the_reset_clears_and_recomputes_in_one_transaction(client, watch, monkeypatch):
    """Same property for reset-demo: clearing the governance working set and
    recomputing the baseline it implies are one act, or a failure between them
    leaves the tables emptied and the snapshot still describing them."""
    depths: list[int] = []
    real_build = main._build_engine

    def _watching_build(scenario, inputs=None):
        depths.append(watch.depth)
        return real_build(scenario, inputs)

    monkeypatch.setattr(main, "_build_engine", _watching_build)
    monkeypatch.setattr(main, "reset_change_workflow", lambda _cur: {"staged_changes": 0})
    r = client.post("/api/admin/reset-demo", headers=ADMIN)
    assert r.status_code == 200, r.text
    assert depths == [1], f"the recompute ran outside the reset's transaction: {depths}"


def test_the_ranking_helpers_are_the_only_place_that_calls_the_model(client, watch):
    """A structural check to go with the behavioural ones: `rank_mod.rank` is
    reachable from exactly one function in app.main, `_rank_once`, which is where
    the capability gate and the single-flight guard live. A second call site
    would bypass both without failing anything above."""
    import ast
    import inspect
    import textwrap

    callers = []
    for name, fn in vars(main).items():
        if not (inspect.isfunction(fn) and fn.__module__ == main.__name__):
            continue
        tree = ast.parse(textwrap.dedent(inspect.getsource(fn)))
        for node in ast.walk(tree):
            if (isinstance(node, ast.Attribute) and node.attr == "rank"
                    and isinstance(node.value, ast.Name) and node.value.id == "rank_mod"):
                callers.append(name)
    assert callers == ["_rank_once"], f"rank_mod.rank is called from {callers}"


def test_the_deterministic_ranking_is_the_same_list_the_model_grouping_orders(eng):
    """`rank_deterministic` is served on the request path, so it has to be a real
    answer: every finding covered, guardrail order enforced, and no model."""
    from src.advisory import rank as rank_mod

    ranked = rank_mod.rank_deterministic(eng.findings)
    assert ranked.ranked_by == "engine_fallback"
    covered = {fid for a in ranked.actions for fid in a.finding_ids}
    assert covered == {f.id for f in eng.findings}, "a finding fell out of the deterministic grouping"
    assert [a.priority for a in ranked.actions] == list(range(1, len(ranked.actions) + 1))
    forced = [i for i, a in enumerate(ranked.actions)
              if any(f.forced_critical for f in eng.findings if f.id in a.finding_ids)]
    assert forced == list(range(len(forced))), "a forced-critical action sits below one that is not"


def test_an_empty_snapshot_ranks_to_an_empty_list(monkeypatch):
    """The degenerate case the request path can hit: no findings must not mean a
    model call, and must not raise."""
    from src.advisory import rank as rank_mod

    assert rank_mod.rank_deterministic([]) == RankedActions(actions=[], ranked_by="engine_fallback")
