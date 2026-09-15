"""A backend that is degraded must not render as a backend that is dead.

This file exists because a Phase 0/1 exit criterion -- "a degraded-but-running
backend does not render as dead" -- was declared met and then refuted end to end.
The half that was genuinely fixed was `lib/api.readHealth`: /api/health answers
503 with a full payload when it cannot reach Postgres, and the client resolves on
that instead of throwing. But the state this repo actually ships in (no
DATABASE_URL) still painted a dead console, because every OTHER console feed went
straight to `get_conn` and died there:

    /api/health     -> 503  (the honest degraded payload)
    /api/snapshot   -> 500  RuntimeError: DATABASE_URL is not set
    /api/findings   -> 500  ...
    /api/graph      -> 500  ...
    /api/actions    -> 500  ...
    /api/snapshots  -> 500  ...

Five of the console's six feeds failed at once, so `app/console/page.tsx` rendered
five red ErrorState panels and forced every nav count to zero -- out of a process
that was running, answering, and holding a fully computed 30-finding snapshot in
memory. The engine had the answer; the API refused to serve it because the read
path went through a database it did not need.

The test that was supposed to cover this scanned page.tsx for the strings
`role="status"`, `degraded_reasons` and `degraded.map`. It asserted that the
banner's MARKUP exists. It could not see the five 500s underneath the banner, and
it passed the whole time. So the check here is behavioural: it drives the real
FastAPI app with DATABASE_URL blanked and asserts what the six feeds actually
answer.

Two things it deliberately also pins, because "serve something" is the easy half
and the dishonest half is what the audit keeps filing:

  * the degraded answer DISCLOSES itself (`served_from: "engine_memory"` plus the
    reason), so a live recompute is never passed off as a persisted read; and
  * memory answers only for the snapshot it actually holds. A HISTORICAL snapshot
    exists only in the database, so that read stays an error naming the store --
    never an empty list, which would read as "that snapshot found nothing".

The same fallback covers the three other purely engine-derived reads -- assets,
the ingest inspector and the rule click-through -- because "no assets", "nothing
was ingested" and "that rule is not in this snapshot" are the same false positive
claim wearing different words.

No database, no network: DATABASE_URL is blanked, the ranking model's transport
is stubbed unreachable so the deterministic fallback runs, and scenario
regeneration is a no-op.
"""

from __future__ import annotations

import json
import re
import types
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app import main
from src import db, persist

REPO_ROOT = Path(__file__).resolve().parents[2]
CONSOLE_PAGE = REPO_ROOT / "frontend" / "app" / "console" / "page.tsx"

# The six feeds `app/console/page.tsx` loads on every screen, in its own order,
# each with the endpoint behind it. This IS the console's `feeds` array --
# `test_the_six_feeds_are_the_consoles_own_six` fails if the page grows a seventh
# or renames one, so the behavioural assertions below cannot drift away from the
# screen they are making claims about.
CONSOLE_FEEDS: tuple[tuple[str, str], ...] = (
    ("service health", "/api/health"),
    ("the snapshot summary", "/api/snapshot"),
    ("findings", "/api/findings"),
    ("the reachability graph", "/api/graph"),
    ("prioritized actions", "/api/actions"),
    ("the snapshot timeline", "/api/snapshots"),
)


@pytest.fixture(scope="module")
def blind_client():
    """The real app with no database at all -- the state this repo ships in.

    `src.db.DATABASE_URL` is blanked rather than mocked away, so `get_conn`
    raises the production `RuntimeError: DATABASE_URL is not set` from
    `_require_url` at exactly the point production would. (backend/conftest.py
    blanks it for the whole suite, but that fixture is function-scoped and this
    one is not, so it is re-asserted here rather than depended on.) TestClient is
    NOT used as a context manager: entering it runs the lifespan, which starts a
    second engine build on a background thread that would outlive this fixture's
    patches."""
    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(db, "DATABASE_URL", "")
        mp.setattr(db, "_POOL", None)
        mp.setattr(main, "_ENGINE", None)          # force the real lazy build
        mp.setattr(main, "_ACTIVE_SCENARIO", main._DEFAULT_SCENARIO)
        mp.setattr(main, "write_scenario", lambda *_a, **_kw: None)
        # The ranking model's transport, not the ranking itself: `rank()` runs for
        # real and takes its own deterministic fallback. The repo .env carries live
        # provider keys and a degradation test has no business reaching one.
        mp.setattr(main.rank_mod, "complete", lambda **_kw: types.SimpleNamespace(
            ok=False, text="", provider="stub", model="stub", error="unreachable"))
        mp.setattr(main, "_ENGINE_STATE", {
            "inputs_ok": True, "inputs_error": None, "persisted": None,
            "persist_error": None, "build_error": None})
        yield TestClient(main.app, raise_server_exceptions=False)


@pytest.fixture(scope="module")
def live_engine(blind_client):
    """The snapshot the process is holding while the database is unreachable."""
    blind_client.get("/api/findings")     # drive the lazy build through the API
    return main._ENGINE


# --------------------------------------------------------------------------
# the criterion itself
# --------------------------------------------------------------------------

def test_the_six_feeds_are_the_consoles_own_six() -> None:
    """CONSOLE_FEEDS must stay the console's `feeds` array, or every behavioural
    assertion below is about a screen that no longer exists."""
    src = CONSOLE_PAGE.read_text(encoding="utf-8")
    block = re.search(r"const feeds = \[(.*?)\n  \]", src, re.S)
    assert block, "app/console/page.tsx no longer declares a `feeds` array"
    labels = re.findall(r'\["([^"]+)",', block.group(1))
    assert labels == [label for label, _ in CONSOLE_FEEDS], (
        f"the console's feeds changed: {labels}")


def test_not_every_console_feed_fails_without_a_database(blind_client) -> None:
    """The refutation, inverted. Five of six used to be a 500 apiece."""
    statuses = {path: blind_client.get(path).status_code for _, path in CONSOLE_FEEDS}
    failed = {p: s for p, s in statuses.items() if s >= 500 and p != "/api/health"}
    assert not failed, f"a degraded backend still renders as dead: {failed}\nall: {statuses}"
    # /api/health's 503 is its considered answer about itself, and `readHealth`
    # resolves on it (see lib/api.ts). Every other feed is a plain 200.
    assert statuses["/api/health"] == 503
    assert all(statuses[p] == 200 for _, p in CONSOLE_FEEDS if p != "/api/health"), statuses


def test_health_still_says_it_is_degraded(blind_client) -> None:
    """Serving from memory must not quiet the alarm: the banner the console draws
    is built from these reasons, and it is the only thing telling the operator
    that nothing durable is being written."""
    body = blind_client.get("/api/health").json()
    assert body["status"] == "degraded"
    assert body["db"] is False
    assert any("database" in r for r in body["degraded_reasons"]), body["degraded_reasons"]


def test_findings_are_served_from_the_engine_and_say_so(blind_client, live_engine) -> None:
    body = blind_client.get("/api/findings").json()
    assert body["served_from"] == "engine_memory"
    assert "database is unreachable" in body["degraded_reason"]
    # The whole snapshot, not a placeholder: every finding the engine holds.
    assert [f["finding_id"] for f in body["findings"]] != []
    assert {f["finding_id"] for f in body["findings"]} == {f.id for f in live_engine.findings}


def test_the_graph_is_served_from_the_engine_and_say_so(blind_client, live_engine) -> None:
    body = blind_client.get("/api/graph").json()
    assert body["served_from"] == "engine_memory"
    assert body["nodes"] and body["edges"]
    assert {n["node_id"] for n in body["nodes"]} == set(live_engine.graph.nodes)
    # Every node carries the zone the map colours by -- the same post-processing
    # the persisted rows go through, because both go through `_graph_payload`.
    assert all(n.get("zone") for n in body["nodes"])


def test_the_snapshot_summary_counts_the_snapshot_in_memory(blind_client, live_engine) -> None:
    body = blind_client.get("/api/snapshot").json()
    assert body["served_from"] == "engine_memory"
    assert body["counts"] == persist.snapshot_counts(live_engine)
    assert body["counts"]["findings"] == len(live_engine.findings)
    assert body["snapshot"]["snapshot_id"] == live_engine.snapshot_id
    # A database default the projection cannot know, so it is null rather than an
    # invented now() (which would also break determinism).
    assert body["snapshot"]["created_at"] is None


def test_actions_are_ranked_from_memory(blind_client) -> None:
    body = blind_client.get("/api/actions").json()
    assert body["served_from"] == "engine_memory"
    assert body["actions"], "the ranking needs findings, not the ranked_actions cache"
    assert [a["priority"] for a in body["actions"]] == sorted(a["priority"] for a in body["actions"])


def test_the_snapshot_timeline_is_unknown_not_empty(blind_client) -> None:
    """The honest exception: a history of PERSISTED runs cannot exist without the
    store. It answers 200 so one absent feed does not take the console down with
    it, and it says the list is unread -- `[]` alone would render as "no
    snapshots yet", which is the empty-vs-failed lie with a 200 on it."""
    body = blind_client.get("/api/snapshots").json()
    assert body["snapshots"] == []
    assert body["served_from"] == "unavailable"
    assert "unknown, not empty" in body["degraded_reason"]
    assert "database is unreachable" in body["degraded_reason"]


def test_the_other_engine_derived_screens_answer_too(blind_client, live_engine) -> None:
    """Assets and the ingest inspector are the same class of read: everything on
    them is derived from the snapshot the engine is holding, and an empty answer
    there ("no assets", "nothing was ingested") is the most misleading sentence
    either screen could print."""
    a = blind_client.get("/api/assets").json()
    assert a["served_from"] == "engine_memory"
    assert {row["asset_key"] for row in a["assets"]} == {x.asset_key for x in live_engine.assets}

    i = blind_client.get("/api/ingest").json()
    assert i["served_from"] == "engine_memory"
    assert len(i["canonical_rules"]) == len(live_engine.records)
    assert [x["tool"] for x in i["sources"]] == sorted({r.source_tool for r in live_engine.records})
    assert i["resolved_objects"], "the object catalog is derived, not stored"


def test_a_rule_click_through_resolves_from_memory(blind_client, live_engine) -> None:
    """RuleRef prints "Rule X is not in this snapshot" for an empty list -- a
    positive claim about the rulebase's contents, which an empty degraded answer
    would make out of a query that never ran."""
    ref = live_engine.records[0].raw_ref
    body = blind_client.get(f"/api/rule/{ref}").json()
    assert body["served_from"] == "engine_memory"
    assert [r["raw_rule_id"] for r in body["rules"]] == [ref]


# --------------------------------------------------------------------------
# the limits: what the fallback must NOT do
# --------------------------------------------------------------------------

def test_a_historical_snapshot_is_never_faked_from_memory(blind_client, live_engine) -> None:
    """Memory holds ONE snapshot. Answering a request for a different one out of
    it -- or with an empty list -- would be a confident answer to a question this
    process cannot answer."""
    other = "snap_000000000000"
    assert other != live_engine.snapshot_id
    for path in ("/api/findings", "/api/graph", "/api/snapshot", "/api/actions",
                 "/api/assets", "/api/ingest"):
        r = blind_client.get(path, params={"snapshot": other})
        assert r.status_code == 503, f"{path} answered {r.status_code}: {r.text[:200]}"
        detail = r.json()["detail"]
        assert other in detail and live_engine.snapshot_id in detail
        assert "unknown rather than empty" in detail


def test_the_degraded_read_is_deterministic(blind_client) -> None:
    """This product's determinism is the claim it sells. The fallback sorts
    explicitly (the SQL's ORDER BY, plus the tiebreak Postgres leaves to the
    planner), so two identical requests are byte-identical."""
    for path in ("/api/findings", "/api/graph", "/api/snapshot"):
        first = blind_client.get(path).text
        second = blind_client.get(path).text
        assert first == second, path


def test_findings_are_ordered_the_way_the_sql_orders_them(blind_client) -> None:
    """ORDER BY forced_critical DESC, severity DESC, type -- the console's first
    screen reads the head of this list as "the worst thing in the estate"."""
    rows = blind_client.get("/api/findings").json()["findings"]
    keys = [(not r["forced_critical"], -r["severity"], r["type"], r["finding_id"]) for r in rows]
    assert keys == sorted(keys)


def test_the_memory_rows_are_the_columns_the_query_selects(blind_client) -> None:
    """A wider dict from the fallback is a contract drift that only the degraded
    path would ever show, so the projection is narrowed to the SELECT list.

    Plus exactly one DERIVED field. `engine_explanation` is not a column and
    never will be: it is computed from the row's own signals, identically on
    both paths, by `_attach_engine_explanations` after they converge. It is
    asserted here rather than exempted, so a SECOND derived field cannot be
    added without this test being read and updated -- which is the whole point
    of pinning the shape.
    """
    rows = blind_client.get("/api/findings").json()["findings"]
    expected = main._FINDING_COLS + ("title", "engine_explanation")

    assert all(tuple(r) == expected for r in rows)
    # ...and it is always populated. An empty one would put the console back to
    # rendering "no explanation has been written", which is what it is for.
    assert all(r["engine_explanation"] for r in rows)
    # ...and so is the title. Without it the console title-cased the TYPE, so
    # all five over-permissive findings shared one heading.
    assert all(r["title"] for r in rows)
    assert not any(r["title"] == r["type"] for r in rows), (
        "a title equal to the type means the analyzer's own one-liner was lost"
    )


def test_nothing_is_persisted_while_the_database_is_unreachable(blind_client) -> None:
    """Serving from memory is a READ concession. The engine must still refuse to
    write a snapshot it computed without the operator's confirmed merges."""
    blind_client.get("/api/findings")
    assert main._ENGINE_STATE["inputs_ok"] is False
    assert main._ENGINE_STATE["persisted"] is False


# --------------------------------------------------------------------------
# the positive control: a working database is still the system of record
# --------------------------------------------------------------------------

class _Cursor:
    """Answers the shape each read expects, and records that it was asked."""

    def __init__(self) -> None:
        self.statements: list[str] = []

    def execute(self, sql, params=None):
        self.statements.append(sql)
        return self

    def fetchone(self):
        return {"n": 7, "snapshot_id": "snap_persisted"}

    def fetchall(self):
        return []

    def __enter__(self):
        return self

    def __exit__(self, *_exc):
        return False


class _Conn:
    def __init__(self, cur: _Cursor) -> None:
        self._cur = cur

    def cursor(self):
        return self._cur

    def execute(self, sql, params=None):
        return self._cur.execute(sql, params)


def test_a_reachable_database_is_still_read_from_the_database(monkeypatch) -> None:
    """The fallback must be a fallback, not a bypass. With a working connection
    every read is served from Postgres and says `served_from: "database"` -- and
    the fabricated row below proves it, because none of it exists in memory."""
    import contextlib

    cur = _Cursor()

    @contextlib.contextmanager
    def _conn():
        yield _Conn(cur)

    persisted = [{"finding_id": "f_from_the_database", "type": "over_permissive", "severity": 9.0,
                  "severity_band": "critical", "forced_critical": True, "signals": {}, "involved": [],
                  "raw_refs": [], "source_tools": [], "explanation": None}]
    queried: list[str] = []

    def _fetch_all(_cur, sql, params=None):
        queried.append(sql)
        return list(persisted)

    monkeypatch.setattr(main, "write_scenario", lambda *_a, **_kw: None)
    monkeypatch.setattr(main, "get_conn", _conn)
    monkeypatch.setattr(main, "fetch_all", _fetch_all)
    monkeypatch.setattr(main, "fetch_one", lambda *_a, **_kw: {"n": 7, "snapshot_id": "snap_persisted"})
    client = TestClient(main.app, raise_server_exceptions=False)

    body = client.get("/api/findings").json()
    assert body["served_from"] == "database"
    assert "degraded_reason" not in body
    assert body["findings"] == persisted, "the DB row was replaced by the in-memory projection"
    assert queried and "FROM ztpa.findings" in queried[0], "no query was issued at all"

    counts = client.get("/api/snapshot").json()
    assert counts["served_from"] == "database"
    assert counts["counts"]["findings"] == 7      # the cursor's number, not the engine's


def test_a_bad_dataset_is_still_a_422_not_a_memory_answer(monkeypatch) -> None:
    """An HTTPException raised inside the guarded block is an ANSWER, not a
    database failure. A 422 from an unanalyzable dataset must not be swallowed
    and re-answered from a stale engine."""
    monkeypatch.setattr(main, "_ENGINE", None)
    monkeypatch.setattr(main, "write_scenario", lambda *_a, **_kw: None)

    def _boom(**_kw):
        raise ValueError("bad prefix len 33 in algosec row 4")

    monkeypatch.setattr(main, "run", _boom)
    client = TestClient(main.app, raise_server_exceptions=False)
    for path in ("/api/findings", "/api/graph", "/api/snapshot", "/api/actions"):
        r = client.get(path)
        assert r.status_code == 422, f"{path} answered {r.status_code}"
        assert "bad prefix len 33" in r.json()["detail"]


def test_the_json_the_console_reads_is_json(blind_client) -> None:
    """Belt and braces: the provenance keys survive serialization (a set or a
    dataclass leaking into the payload would 500 the whole feed)."""
    for _, path in CONSOLE_FEEDS:
        raw = blind_client.get(path).text
        assert json.loads(raw) is not None, path
