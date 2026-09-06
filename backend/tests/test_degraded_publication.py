"""A degraded run must never be published as authoritative.

This file pins the blocker the second production-readiness audit filed as H8,
and the reason it is worth a file of its own is that THE REMEDIATION INTRODUCED
IT. Phase 1 replaced "one malformed rule aborts the whole snapshot" with
per-analyzer isolation, which is the right mechanism -- 9/9 injected mutations
killed, never fired spuriously across every adversarial export the audit built.
What shipped with it was the wrong half of the guarantee:

  * `snapshot_id` was a content hash of the INPUTS, computed BEFORE the analyzers
    ran, so a degraded run minted the IDENTICAL id as the healthy run over the
    same export;
  * `persist_engine_result` opens with `delete_snapshot_children`, so persisting
    that degraded result did not merely add bad rows -- it DELETED the good ones
    first and then wrote fewer;
  * `EngineResult.degraded_analyzers` was populated, logged, and read by nothing:
    `grep -rn degraded_analyzers backend/app frontend db` returned zero hits.

Executed against real Postgres by the audit: a healthy recompute wrote 30
findings; the same export with `shadowing` and `transport_exposure` raising wrote
`200 {"ok": true, "findings": 7}` under the SAME snapshot id, destroying the 30.
`/api/health` then answered 200 `status: "ok"` with `degraded_reasons: []`,
`/api/findings` answered 7 rows `served_from: "database"`, and `/api/report` --
the compliance artefact -- reported `total_findings: 7`. A loud crash had been
converted into a quiet, durable, authoritative under-report, which is strictly
worse than the failure it replaced. Nothing on any screen said so.

WHAT IS ASSERTED HERE, and why each one is a separate claim:

  1. an incomplete analysis cannot MINT the id of a complete one (the collision
     itself, at the engine layer);
  2. `persist_engine_result` REFUSES a degraded result even when handed one with
     a colliding id -- the guard is at the write layer, not only at the four API
     call sites, because a rule enforced at four call sites is a rule missing
     from the fifth (`scripts/precompute.py` is the fifth);
  3. the API refuses to PUBLISH it: `/api/recompute` answers 503, `_ENGINE` still
     holds the previous complete snapshot, and the persisted rows are untouched
     -- proved by counting real rows in real Postgres before and after;
  4. `/api/health` is not `ok` and names the failed analyzer;
  5. `/api/findings`, `/api/report` and `/api/snapshot` carry the completeness of
     the analysis behind their numbers;
  6. a TRUNCATED path scan -- the other way this engine silently under-reports --
     reaches the result, health and the payloads too, and the bridge that carries
     it fails loudly rather than silently if the graph layer's event changes;
  7. `/api/findings` has a bounded default page with a working cursor (quick win
     7: the endpoint was measured at 57.8 MB on a 51-node mesh).

The real-Postgres section runs only with `NPR_TEST_DATABASE_URL` set, on the same
three-way rule as `test_db_governance.py` (unset -> skip, set and unreachable ->
hard failure at collection, never a silent skip). Nothing it does commits.
"""

from __future__ import annotations

import contextlib
import inspect
import logging
import os
import sys
from typing import Any, Iterator

import pytest
from fastapi.testclient import TestClient

from app import main
from src import db, persist
from src.analyzers import run_all
from src.graph import reachability
from tests.dbharness import FAIL, SKIP, TEST_DB_ENV, collection_decision

ADMIN = {"x-npr-role": "admin"}


def _boom(message: str):
    """An analyzer that raises the way one malformed record in a real export does."""
    def _explode(*_args, **_kwargs):
        raise ValueError(message)
    return _explode


def _no_model(**_kwargs: Any) -> Any:
    """`advisory.client.complete`'s answer when no provider is reachable.

    Shaped like the real `LLMResponse` (the fields every caller reads) rather
    than a MagicMock, so a caller that forgets to branch on `ok` fails here the
    way it would in production instead of quietly getting a truthy stub.
    """
    from src.advisory.client import LLMResponse
    return LLMResponse(text="", provider="none", model="none", ok=False,
                       error="no model provider in this test")


# ==========================================================================
# 1. the engine: an incomplete analysis is a DIFFERENT snapshot
# ==========================================================================

@pytest.fixture(scope="module")
def healthy() -> run_all.EngineResult:
    """One complete engine build of the demo corpus, for the whole module."""
    return run_all.run()


def test_a_healthy_run_says_it_is_complete(healthy: run_all.EngineResult) -> None:
    """The positive control. Every assertion below is about the difference from
    this state, so a run that could not reach it would make them vacuous."""
    assert healthy.degraded_analyzers == []
    assert healthy.truncations == []
    assert healthy.degraded is False and healthy.partial is False
    assert healthy.complete is True
    assert healthy.integrity_reasons() == []


def test_a_degraded_run_cannot_mint_the_id_of_the_complete_one(
        monkeypatch: pytest.MonkeyPatch, healthy: run_all.EngineResult) -> None:
    """THE COLLISION, exactly as measured. Same export, same label, same inputs;
    two analyzers raising. The old id was a hash of the inputs alone, so this
    produced the healthy run's id and upserted over its rows."""
    monkeypatch.setattr(run_all.shadowing, "analyze", _boom("malformed rule ALGO-004"))
    monkeypatch.setattr(run_all.transport_exposure, "analyze", _boom("bad service spec"))
    degraded = run_all.run()

    assert [d["analyzer"] for d in degraded.degraded_analyzers] == ["shadowing", "transport_exposure"]
    assert degraded.snapshot_id != healthy.snapshot_id, (
        "a degraded run still hashes to the complete run's snapshot id, so persisting it "
        "would clear the complete run's rows and write fewer in their place")
    assert len(degraded.findings) < len(healthy.findings), "the probe did not degrade anything"


def test_the_degraded_id_is_deterministic(monkeypatch: pytest.MonkeyPatch) -> None:
    """Determinism is a product guarantee and it does not lapse in the degraded
    state: the same failure over the same inputs is the same snapshot, or the
    "distinct id" fix would mint a new snapshot on every retry and fill the
    timeline with rows nobody can compare."""
    monkeypatch.setattr(run_all.shadowing, "analyze", _boom("malformed rule ALGO-004"))
    assert run_all.run().snapshot_id == run_all.run().snapshot_id


def test_the_id_does_not_depend_on_the_exception_message(monkeypatch: pytest.MonkeyPatch) -> None:
    """What is hashed is narrower than what is reported, on purpose: a message can
    carry a repr with a heap address in it, and a snapshot id that moved with the
    heap would be non-deterministic in exactly the state nobody re-runs."""
    monkeypatch.setattr(run_all.shadowing, "analyze", _boom("malformed rule ALGO-004"))
    first = run_all.run()
    monkeypatch.setattr(run_all.shadowing, "analyze", _boom("object at 0x7fb3c0ffee00"))
    second = run_all.run()
    assert first.snapshot_id == second.snapshot_id
    # ...and the message the OPERATOR reads is still the real one.
    assert second.degraded_analyzers[0]["message"] == "object at 0x7fb3c0ffee00"


def test_a_degraded_run_says_which_finding_class_is_missing(
        monkeypatch: pytest.MonkeyPatch) -> None:
    """"Missing" and "nothing found there" are the two readings of a smaller
    number, and only one of them is true. The result has to be able to say which."""
    monkeypatch.setattr(run_all.cidr_overlap, "analyze", _boom("malformed rule"))
    degraded = run_all.run()
    assert degraded.degraded is True and degraded.complete is False
    reasons = degraded.integrity_reasons()
    assert len(reasons) == 1 and "cidr_overlap" in reasons[0]
    assert "not 'nothing found there'" in reasons[0]


# ==========================================================================
# 2. the write layer refuses it, even handed a colliding id
# ==========================================================================

class _RecordingCursor:
    """Records every statement, answers nothing. Enough to prove a write path
    took no action at all -- which is the claim, since the first thing
    `persist_engine_result` does is DELETE."""

    def __init__(self) -> None:
        self.statements: list[str] = []

    def execute(self, sql: Any, params: Any = None) -> None:
        self.statements.append(str(sql))

    def executemany(self, sql: Any, params: Any = None) -> None:
        self.statements.append(str(sql))

    def fetchone(self) -> dict | None:
        return None

    def fetchall(self) -> list[dict]:
        return []


def test_persist_refuses_a_degraded_result_before_it_deletes_anything(
        monkeypatch: pytest.MonkeyPatch, healthy: run_all.EngineResult) -> None:
    """The guard is at the WRITE layer, not only at the API's four call sites.

    The id is forced onto the healthy run's id to reproduce the measured
    collision exactly, so this test would fail against the old code for the right
    reason: it would find `DELETE FROM ztpa.findings` in the statement stream."""
    monkeypatch.setattr(run_all.transport_exposure, "analyze", _boom("bad service spec"))
    degraded = run_all.run()
    degraded.snapshot_id = healthy.snapshot_id          # the pre-fix collision

    cur = _RecordingCursor()
    with pytest.raises(persist.DegradedSnapshotError) as raised:
        persist.persist_engine_result(cur, degraded)    # type: ignore[arg-type]

    assert "transport_exposure" in str(raised.value)
    assert cur.statements == [], (
        "the degraded write got as far as touching the snapshot's rows; "
        f"statements executed: {cur.statements[:3]}")


def test_a_complete_result_still_persists(healthy: run_all.EngineResult) -> None:
    """A guard that refuses everything is not a fix. (The positive control for
    the one above; the real-row version is in the Postgres section.)"""
    cur = _RecordingCursor()
    summary = persist.persist_engine_result(cur, healthy)   # type: ignore[arg-type]
    assert summary["complete"] is True and summary["truncations"] == []
    assert any("DELETE FROM ztpa.findings" in s for s in cur.statements)


def test_the_snapshot_row_of_an_incomplete_run_is_not_called_complete(
        monkeypatch: pytest.MonkeyPatch) -> None:
    """The snapshot timeline is the one screen that says which runs are
    trustworthy. A run that analyzed a bounded sample of its own estate must not
    sit in it wearing the same word as a run that analyzed all of it."""
    monkeypatch.setattr(reachability, "_PATH_SCAN_CAP", 0)
    truncated = run_all.run()
    assert truncated.partial is True, "the probe did not truncate anything"

    row = persist.snapshot_row(truncated)
    assert row["status"] != "complete"
    assert "INCOMPLETE ANALYSIS" in row["notes"]
    assert "scan cap" in row["notes"]


# ==========================================================================
# 3-5. the API refuses to publish it, and says so everywhere
# ==========================================================================

@contextlib.contextmanager
def _conn_yielding(cursor: Any) -> Iterator[Any]:
    """`main.get_conn()`'s shape around a cursor the test owns."""
    class _Conn:
        def cursor(self) -> Any:
            return contextlib.nullcontext(cursor)
    yield _Conn()


@pytest.fixture()
def api(monkeypatch: pytest.MonkeyPatch, healthy: run_all.EngineResult) -> TestClient:
    """The real app serving the healthy snapshot, with the database seam faked.

    TestClient is NOT entered as a context manager: the lifespan starts a warm
    engine build on a background thread that would outlive these patches."""
    cur = _RecordingCursor()
    # /api/report asks the advisory client for a narrative. Unstubbed, that is a
    # real HTTPS call to whatever hosted provider the checked-in .env names --
    # so this module was billing a third party on every run, and the assertions
    # below ("analysis_complete is False", "degraded_analyzers == [...]") were
    # being made about a payload whose narrative half depended on somebody
    # else's uptime. The claim under test is about the ENGINE's completeness,
    # which the deterministic fallback reports identically; a model that cannot
    # be reached is the state CI has always run in, so this makes every machine
    # agree with CI instead of the other way round.
    #
    # `ok=False` rather than a canned success, deliberately: a stub that answers
    # like a working model would let a route that has no fallback pass here and
    # fail in production. (Found by backend/conftest.py's outbound-socket guard.)
    for module in list(sys.modules.values()):
        if getattr(module, "__name__", "").startswith("src") and hasattr(module, "complete"):
            monkeypatch.setattr(module, "complete", _no_model)
    monkeypatch.setattr(main, "get_conn", lambda: _conn_yielding(cur))
    monkeypatch.setattr(main, "ping", lambda: True)
    monkeypatch.setattr(main, "write_scenario", lambda *_a, **_kw: None)
    monkeypatch.setattr(main, "fetch_one", lambda *_a, **_kw: {"n": 0, "snapshot_id": healthy.snapshot_id})
    monkeypatch.setattr(main, "fetch_all", lambda *_a, **_kw: [])
    monkeypatch.setattr(main, "load_asset_merges", lambda _cur: [])
    monkeypatch.setattr(main, "load_applied_changes", lambda _cur: [])
    monkeypatch.setattr(main.tools_registry, "is_enabled", lambda _k: True)
    monkeypatch.setattr(main, "_ENGINE", healthy)
    monkeypatch.setattr(main, "_ENGINE_STATE", {
        "inputs_ok": True, "inputs_error": None, "persisted": True, "persist_error": None,
        "build_error": None, "rejected_snapshot": None, "rejected_reason": None})
    return TestClient(main.app, raise_server_exceptions=False)


def test_recompute_refuses_to_publish_a_degraded_rebuild(
        api: TestClient, monkeypatch: pytest.MonkeyPatch, healthy: run_all.EngineResult) -> None:
    """THE EXIT CRITERION, at the API. The 503 already existed for a snapshot
    built without the operator's merges; a snapshot built without an entire
    ANALYZER went through as `{"ok": true}`."""
    monkeypatch.setattr(run_all.transport_exposure, "analyze", _boom("bad service spec"))

    response = api.post("/api/recompute", headers=ADMIN)
    assert response.status_code == 503, response.text
    detail = response.json()["detail"]
    assert "refusing to persist a degraded snapshot" in detail
    assert "transport_exposure" in detail

    # ...and the process is still serving the complete snapshot, not the partial
    # one it just refused to write. Publishing first and checking second left the
    # served estate and the system of record disagreeing, silently.
    assert main._ENGINE is healthy
    assert main._ENGINE_STATE["rejected_snapshot"] not in (None, healthy.snapshot_id)


def test_health_is_not_ok_and_names_the_failed_analyzer(
        api: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    """`/api/health` answered 200 `ok` / `degraded_reasons: []` over a snapshot
    missing 23 of its 30 findings. It is the endpoint an operator trusts to tell
    them to look, so it is the endpoint the silence cost the most."""
    monkeypatch.setattr(run_all.transport_exposure, "analyze", _boom("bad service spec"))
    api.post("/api/recompute", headers=ADMIN)

    health = api.get("/api/health")
    assert health.status_code == 503
    body = health.json()
    assert body["status"] == "degraded"
    assert any("refused publication" in reason for reason in body["degraded_reasons"]), \
        body["degraded_reasons"]
    assert any("transport_exposure" in reason for reason in body["degraded_reasons"])
    assert body["snapshot"]["rejected_snapshot"]


def test_a_degraded_snapshot_that_is_served_is_declared_on_health(
        api: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    """The cold-build case: there is no previous complete snapshot to fall back
    to, so the degraded one IS served -- and every one of its shortcomings is on
    the honesty endpoint. Served, disclosed, never written."""
    monkeypatch.setattr(run_all.transport_exposure, "analyze", _boom("bad service spec"))
    monkeypatch.setattr(main, "_ENGINE", None)

    body = api.get("/api/health").json()
    assert body["status"] == "degraded"
    assert body["snapshot"]["analysis"]["complete"] is False
    assert body["snapshot"]["analysis"]["degraded_analyzers"] == ["transport_exposure"]
    assert main._ENGINE_STATE["persisted"] is False
    assert "transport_exposure" in (main._ENGINE_STATE["persist_error"] or "")


def test_health_recovers_when_the_analyzers_do(api: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    """A degraded state that cannot clear is its own lie: the banner would stay up
    forever after one transient bad export, and an alarm nobody can clear is an
    alarm nobody reads."""
    working = run_all.transport_exposure.analyze
    monkeypatch.setattr(run_all.transport_exposure, "analyze", _boom("bad service spec"))
    assert api.post("/api/recompute", headers=ADMIN).status_code == 503
    # The one analyzer is restored, not the whole fixture: `monkeypatch.undo()`
    # would also tear down the database seam this client is standing on.
    monkeypatch.setattr(run_all.transport_exposure, "analyze", working)

    assert api.post("/api/recompute", headers=ADMIN).status_code == 200, "the bad export was transient"
    assert main._ENGINE_STATE["rejected_snapshot"] is None
    assert api.get("/api/health").json()["status"] == "ok"


def test_the_read_payloads_carry_the_completeness_of_their_own_numbers(
        api: TestClient, monkeypatch: pytest.MonkeyPatch, healthy: run_all.EngineResult) -> None:
    """`degraded_analyzers` was populated, logged, and read by NOTHING. These are
    the three payloads that publish a claim about the estate as a whole."""
    monkeypatch.setattr(main, "_ENGINE", None)
    monkeypatch.setattr(run_all.transport_exposure, "analyze", _boom("bad service spec"))

    for path in ("/api/findings", "/api/snapshot", "/api/report"):
        body = api.get(path).json()
        assert body["analysis_complete"] is False, path
        assert body["degraded_analyzers"] == ["transport_exposure"], path


def test_a_complete_snapshot_says_so_rather_than_saying_nothing(api: TestClient) -> None:
    """The positive control: `analysis_complete: true` is a claim the API makes,
    so a client reading the key can distinguish "complete" from "this version of
    the API does not tell you"."""
    for path in ("/api/findings", "/api/snapshot", "/api/report"):
        body = api.get(path).json()
        assert body["analysis_complete"] is True, path
        assert body["degraded_analyzers"] == [], path


def test_a_historical_snapshot_is_never_claimed_complete(
        api: TestClient, healthy: run_all.EngineResult) -> None:
    """Three-valued on purpose. The in-memory result describes the ACTIVE
    snapshot; `null` for any other one is "this process cannot say", which is
    true. `[]` would be a positive claim about a run it never analyzed."""
    body = api.get("/api/findings", params={"snapshot": "snap_000000000000"}).json()
    assert body["analysis_complete"] is None
    assert body["degraded_analyzers"] is None


# ==========================================================================
# 6. a truncated path scan is an incomplete analysis too
# ==========================================================================

def test_a_truncated_scan_reaches_the_engine_result(monkeypatch: pytest.MonkeyPatch) -> None:
    """The other silent under-report. On the audit's 51-node mesh the reported
    cross-tool finding count was arithmetically `cap x sensitive_targets` and
    carried no information about the estate -- with `degraded_analyzers: []` and
    health `ok`, because `cross_tool_paths` returns a bare list and the truncation
    only ever reached the log stream."""
    monkeypatch.setattr(reachability, "_PATH_SCAN_CAP", 0)
    truncated = run_all.run()

    assert truncated.truncations, "the bounded scan left no marker on the result"
    assert truncated.partial is True and truncated.complete is False
    assert truncated.degraded is False, "a bounded scan is not a failed analyzer"
    assert all({"fn", "src", "dst", "cap"} == set(t) for t in truncated.truncations)
    assert truncated.truncations == sorted(
        truncated.truncations, key=lambda t: (t["fn"], t["src"], t["dst"])), \
        "the markers escape in set order"
    assert "scan cap" in " ".join(truncated.integrity_reasons())


def test_a_truncated_run_is_a_different_snapshot_than_a_complete_one(
        monkeypatch: pytest.MonkeyPatch, healthy: run_all.EngineResult) -> None:
    """Same rule as a degraded run: a bounded answer must not overwrite the
    complete one it is a subset of."""
    monkeypatch.setattr(reachability, "_PATH_SCAN_CAP", 0)
    assert run_all.run().snapshot_id != healthy.snapshot_id


def test_a_truncated_run_is_still_persisted(monkeypatch: pytest.MonkeyPatch) -> None:
    """Deliberately NOT blocked. Its findings are real and it is the only answer
    that exists for those inputs; blocking it would leave a large estate with no
    snapshot at all. Written under its own id, marked, and surfaced."""
    monkeypatch.setattr(reachability, "_PATH_SCAN_CAP", 0)
    truncated = run_all.run()
    cur = _RecordingCursor()
    summary = persist.persist_engine_result(cur, truncated)   # type: ignore[arg-type]
    assert summary["complete"] is False and summary["truncations"]
    assert any("DELETE FROM ztpa.findings" in s for s in cur.statements)


def test_the_truncation_bridge_is_wired_to_the_event_the_graph_layer_emits(
        monkeypatch: pytest.MonkeyPatch) -> None:
    """THE GUARD ON THE BRIDGE ITSELF.

    `run_all` learns about truncation from the structured `path_scan_truncated`
    warning `graph/reachability.py` already emits, because `cross_tool_paths` and
    `find_paths` return bare lists. That coupling is invisible from either side:
    rename the event, drop the `extra`, or lower the log call, and the engine goes
    back to reporting a bounded scan as a complete one -- silently, which is this
    module's own bug class. So the wire is tested directly, at the level the two
    halves actually meet."""
    monkeypatch.setattr(reachability, "_PATH_SCAN_CAP", 0)
    graph = run_all.run.__globals__["build_graph"]   # the engine's own builder

    with run_all._record_truncations() as recorder:
        reachability.reachable(_mesh(graph), "a", "d")
    markers = recorder.markers()

    assert markers, (
        "graph/reachability.py no longer emits a WARNING carrying "
        f"event={run_all._TRUNCATION_EVENT!r} on logger {run_all._TRUNCATION_LOGGER!r}, "
        "so the engine can no longer tell a bounded scan from a complete one. "
        "Restore the event, or (better) have cross_tool_paths/find_paths RETURN "
        "the truncated flag and read it here instead.")
    assert markers[0]["fn"] == "reachable"
    assert (markers[0]["src"], markers[0]["dst"]) == ("a", "d")


def _mesh(build_graph: Any) -> Any:
    """A four-node diamond: two distinct simple paths a -> d, so a cap of 0 cuts
    the enumeration and a cap of 4000 does not. Built directly rather than through
    the normalizers so the property under test is the truncation, not the fixture."""
    import networkx as nx

    g = nx.DiGraph()
    for node in "abcd":
        g.add_node(node, kind="concrete", tags=[], ip_set=[], zone="internal")
    for src, dst in (("a", "b"), ("a", "c"), ("b", "d"), ("c", "d")):
        g.add_edge(src, dst, grants=[{"tool": "algosec", "ref": f"R-{src}{dst}",
                                      "service": "tcp/443", "action": "allow"}])
    return g


def test_the_recorder_ignores_another_threads_truncation() -> None:
    """A background agent tool call answering `reachable()` on another thread must
    not mark the ENGINE's run truncated. Over-reporting fails in the loud
    direction, which is the safe one -- but it would also make the snapshot id
    depend on a concurrent request, and determinism is a product guarantee."""
    graph_log = logging.getLogger(run_all._TRUNCATION_LOGGER)
    with run_all._record_truncations() as recorder:
        record = graph_log.makeRecord(
            run_all._TRUNCATION_LOGGER, logging.WARNING, __file__, 0,
            "cross-tool path scan truncated", (), None,
            extra={"event": run_all._TRUNCATION_EVENT, "fn": "cross_tool_paths",
                   "source": "0.0.0.0/0", "target": "db-prod", "cap": 4000})
        record.thread = -1                      # some other thread entirely
        graph_log.handle(record)
    assert recorder.markers() == []


def test_a_raised_log_level_cannot_switch_the_signal_off(
        monkeypatch: pytest.MonkeyPatch) -> None:
    """An environment variable that turns a safety net into a false all-clear is
    the defect class this file exists for. NPR_LOG_LEVEL=ERROR silences WARNINGs
    on `npr.api`, and the truncation signal rides on one."""
    graph_log = logging.getLogger(run_all._TRUNCATION_LOGGER)
    monkeypatch.setattr(reachability, "_PATH_SCAN_CAP", 0)
    monkeypatch.setattr(logging.getLogger("npr.api"), "level", logging.ERROR)

    with run_all._record_truncations() as recorder:
        reachability.reachable(_mesh(None), "a", "d")
    assert recorder.markers(), "a raised log level hid the truncation from the engine"
    # ...and the level it borrowed is handed back.
    assert graph_log.level == logging.NOTSET


# ==========================================================================
# 7. quick win 7 -- /api/findings is bounded, with a cursor
# ==========================================================================

@pytest.fixture(scope="module")
def blind_client(healthy: run_all.EngineResult) -> Iterator[TestClient]:
    """The app with no database, so `/api/findings` is answered from the engine's
    own projection -- the same rows, the same order, and the same paging code as
    the persisted read. Paging is asserted here rather than against Postgres
    because the property is "the two sources page identically", and this is the
    source a test can hold every row of."""
    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(db, "DATABASE_URL", "")
        mp.setattr(db, "_POOL", None)
        mp.setattr(main, "_ENGINE", healthy)
        mp.setattr(main, "write_scenario", lambda *_a, **_kw: None)
        yield TestClient(main.app, raise_server_exceptions=False)


def test_the_endpoint_has_a_bounded_default_page(blind_client: TestClient) -> None:
    """Measured at 57.8 MB (and 975 MB process RSS) on a 51-node mesh with no
    limit at all. The default is what protects a caller who does not know to ask."""
    # The route's own declared default, not a constant this test also imports:
    # deleting `limit=Query(...)` from the signature is the regression, and it
    # would leave the constant sitting there unused and the test green.
    declared = inspect.signature(main.findings).parameters["limit"].default
    assert declared.default == main._FINDINGS_LIMIT_DEFAULT <= 500

    body = blind_client.get("/api/findings").json()
    assert body["limit"] == main._FINDINGS_LIMIT_DEFAULT
    # The demo is far below the page size, so the default page is the whole
    # estate and nothing about the demo's output changed.
    assert body["has_more"] is False and body["next_cursor"] is None
    assert len(body["findings"]) == body["total"]


def test_a_page_is_never_mistakable_for_the_estate(blind_client: TestClient) -> None:
    """`total` beside the page. A screen that cannot say "2 of 31" invites the
    reader to assume they are seeing everything, which is this product's
    characteristic failure."""
    body = blind_client.get("/api/findings", params={"limit": 2}).json()
    assert len(body["findings"]) == 2
    assert body["total"] > 2 and body["has_more"] is True and body["next_cursor"]


def test_the_cursor_walks_every_finding_exactly_once(blind_client: TestClient) -> None:
    """Keyset, not OFFSET: the engine rewrites this table on every recompute, so
    an offset walks a moving list and page 2 can skip a critical finding page 1
    pushed down. The whole sort key travels in the token."""
    everything = blind_client.get("/api/findings").json()["findings"]

    walked: list[dict] = []
    cursor, pages = None, 0
    while True:
        params: dict = {"limit": 3}
        if cursor:
            params["cursor"] = cursor
        body = blind_client.get("/api/findings", params=params).json()
        walked += body["findings"]
        pages += 1
        cursor = body["next_cursor"]
        if not cursor:
            break
        assert pages < 100, "the cursor never terminated"

    assert [f["finding_id"] for f in walked] == [f["finding_id"] for f in everything]


def test_a_malformed_cursor_is_a_400_not_page_one(blind_client: TestClient) -> None:
    """Falling back to page 1 would make a client that loops until `next_cursor`
    is null loop forever over the first page -- and read it as the whole estate."""
    r = blind_client.get("/api/findings", params={"cursor": "not-a-cursor"})
    assert r.status_code == 400
    assert "next_cursor" in r.json()["detail"]


def test_an_out_of_range_limit_is_refused_rather_than_clamped(blind_client: TestClient) -> None:
    """A silently clamped page is a page whose size the caller is wrong about."""
    assert blind_client.get("/api/findings", params={"limit": 0}).status_code == 422
    assert blind_client.get("/api/findings", params={
        "limit": main._FINDINGS_LIMIT_MAX + 1}).status_code == 422


def test_paging_does_not_disturb_the_worst_first_order(blind_client: TestClient) -> None:
    """The console's first screen reads the head of this list as "the worst thing
    in the estate", so the page boundary must fall inside the same total order."""
    rows = blind_client.get("/api/findings", params={"limit": 5}).json()["findings"]
    keys = [(not r["forced_critical"], -r["severity"], r["type"], r["finding_id"]) for r in rows]
    assert keys == sorted(keys)


# ==========================================================================
# the exit criterion, against real Postgres
# ==========================================================================
# Same three-way rule as test_db_governance.py: unset -> skip, set and
# unreachable -> hard failure at collection. A run that was ASKED for a database
# and silently did not get one has proved nothing about real rows, and this is
# the section whose whole value is that the rows are real.

def _probe(url: str) -> str | None:
    try:
        import psycopg
        with psycopg.connect(url, connect_timeout=2) as conn:
            conn.execute("SELECT 1")
        return None
    except Exception as exc:
        return f"{type(exc).__name__}: {exc}"


_URL = os.environ.get(TEST_DB_ENV, "").strip()
_DECISION, _REASON = collection_decision(_URL, _probe(_URL) if _URL else None)
if _DECISION == FAIL:
    raise RuntimeError(_REASON)

realdb = pytest.mark.skipif(_DECISION == SKIP, reason=_REASON)


@pytest.fixture()
def live_api(monkeypatch: pytest.MonkeyPatch, healthy: run_all.EngineResult) -> Iterator[Any]:
    """The real app on a real Postgres, inside ONE transaction that is always
    rolled back -- so this can run against a database with data in it and leave
    nothing behind, including after a failure.

    `main.get_conn` is redirected at this connection rather than the pool for the
    same reason `test_db_governance.py` does it: the pooled version COMMITS on
    clean exit, and a test that commits into the system of record is a test that
    damages it."""
    import psycopg
    from psycopg.rows import dict_row

    connection = psycopg.connect(_URL, row_factory=dict_row, autocommit=False)
    connection.execute("SET search_path TO ztpa, public")

    @contextlib.contextmanager
    def _get_conn() -> Iterator[Any]:
        yield connection            # never closed, never committed by the app

    monkeypatch.setattr(main, "get_conn", _get_conn)
    monkeypatch.setattr(main, "ping", lambda: True)
    monkeypatch.setattr(main, "write_scenario", lambda *_a, **_kw: None)
    monkeypatch.setattr(main, "_ENGINE", healthy)
    monkeypatch.setattr(main, "_ENGINE_STATE", {
        "inputs_ok": True, "inputs_error": None, "persisted": True, "persist_error": None,
        "build_error": None, "rejected_snapshot": None, "rejected_reason": None})
    client = TestClient(main.app, raise_server_exceptions=False)
    try:
        yield client, connection
    finally:
        connection.rollback()
        connection.close()


def _findings_count(connection: Any, snapshot_id: str) -> int:
    with connection.cursor() as cur:
        cur.execute("SELECT count(*) AS n FROM ztpa.findings WHERE snapshot_id=%s", [snapshot_id])
        return cur.fetchone()["n"]


@realdb
def test_the_previous_good_snapshot_survives_a_degraded_recompute(
        live_api: Any, monkeypatch: pytest.MonkeyPatch, healthy: run_all.EngineResult) -> None:
    """THE EXIT CRITERION, on real rows.

    The audit's measured sequence, replayed: persist the healthy snapshot, force
    two analyzers to raise, recompute. Before the fix that answered
    `200 {"ok": true, "findings": 7}` and the 30 healthy rows were gone. Now the
    recompute is refused, the rows are untouched, health is not ok, and
    /api/findings still serves the complete snapshot from the database."""
    client, connection = live_api

    with connection.cursor() as cur:
        persist.persist_engine_result(cur, healthy)
    before = _findings_count(connection, healthy.snapshot_id)
    assert before == len(healthy.findings) > 0

    monkeypatch.setattr(run_all.shadowing, "analyze", _boom("malformed rule ALGO-004"))
    monkeypatch.setattr(run_all.transport_exposure, "analyze", _boom("bad service spec"))

    refused = client.post("/api/recompute", headers=ADMIN)
    assert refused.status_code == 503, refused.text
    assert "refusing to persist a degraded snapshot" in refused.json()["detail"]

    # 1. the rows of the complete run are exactly where they were
    assert _findings_count(connection, healthy.snapshot_id) == before

    # 2. the degraded run wrote nothing of its own either
    degraded_id = main._ENGINE_STATE["rejected_snapshot"]
    assert degraded_id and degraded_id != healthy.snapshot_id
    assert _findings_count(connection, degraded_id) == 0

    # 3. the previous good snapshot is what is being SERVED, from the database
    served = client.get("/api/findings")
    assert served.status_code == 200
    body = served.json()
    assert body["served_from"] == "database"
    assert body["total"] == before
    assert body["analysis_complete"] is True
    assert "last_build_rejected" in body, "the frozen estate reads as the current one"

    # 4. ...and health is not ok about any of it
    health = client.get("/api/health")
    assert health.status_code == 503
    reasons = health.json()["degraded_reasons"]
    assert any("shadowing" in r and "transport_exposure" in r for r in reasons), reasons


@realdb
def test_a_degraded_result_cannot_clear_the_healthy_rows_even_by_id_collision(
        live_api: Any, monkeypatch: pytest.MonkeyPatch, healthy: run_all.EngineResult) -> None:
    """The measured destruction, reproduced at the write layer with the colliding
    id restored by hand -- so the test fails against the old code by DELETING the
    rows it then counts, not merely by writing a second snapshot."""
    _client, connection = live_api

    with connection.cursor() as cur:
        persist.persist_engine_result(cur, healthy)
    before = _findings_count(connection, healthy.snapshot_id)

    monkeypatch.setattr(run_all.transport_exposure, "analyze", _boom("bad service spec"))
    degraded = run_all.run()
    degraded.snapshot_id = healthy.snapshot_id

    with connection.cursor() as cur, pytest.raises(persist.DegradedSnapshotError):
        persist.persist_engine_result(cur, degraded)

    assert _findings_count(connection, healthy.snapshot_id) == before


@realdb
def test_a_truncated_snapshot_is_written_and_marked_in_the_timeline(
        live_api: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    """The other half: a bounded scan IS persisted -- and the timeline says the
    run was not complete, so nobody reads its counts as totals."""
    _client, connection = live_api

    monkeypatch.setattr(reachability, "_PATH_SCAN_CAP", 0)
    truncated = run_all.run()
    assert truncated.partial is True

    with connection.cursor() as cur:
        persist.persist_engine_result(cur, truncated)
        cur.execute("SELECT status, notes FROM ztpa.snapshots WHERE snapshot_id=%s",
                    [truncated.snapshot_id])
        row = cur.fetchone()

    assert row is not None, "a truncated run was refused when it should have been recorded"
    assert row["status"] != "complete"
    assert "INCOMPLETE ANALYSIS" in row["notes"]
