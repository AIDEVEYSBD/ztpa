"""The Phase 2 exit criteria, proved against a REAL Postgres.

Every other test in this suite runs offline against a recording cursor or a
static read of `db/schema.sql`. Those are worth keeping -- they are what CI can
run -- but they can only assert about the SQL the application *emits*. They
cannot tell you whether that SQL is accepted, whether the columns it names
exist, whether a CHECK constraint rejects a value the engine now produces, or
whether a governance row is still there afterwards. The audit's own words for
the persist layer were "literally zero executed coverage".

This file closes that gap. It talks to a throwaway Postgres and asserts, end to
end and on real rows:

  * a recompute, a dataset switch, an asset merge AND A RESET each leave
    `change_requests`, `change_decisions` and `audit_log` intact -- counted
    before and after, not inferred from a statement stream, and for the reset
    compared whole-row so "intact" is not satisfied by a row that survived with
    its contents rewritten;
  * ...and the reset still does what a reset is for: it clears the working set
    (staged changes, remediation threads, the cached plan) and empties the
    console, because retiring a row (`archived_at`) and deleting it are
    different acts and only the first one belongs in a system of record;
  * every column `persist_engine_result` writes exists in the database;
  * `audit()` fills `actor_email` / `actor_sub` / `actor_role` from
    `request_ctx` at every call site, because it is the only writer of the table;
  * `upsert_many` persists a batch that exceeds Postgres's 65,535 bind-parameter
    limit -- with the single-statement form it replaced shown failing on the
    same data, in the same transaction;
  * the connected database's migration ledger matches `db/migrations/` exactly.

HOW TO RUN IT
-------------
    NPR_TEST_DATABASE_URL=postgresql://npr:nprdev@localhost:55433/npr pytest

Without that variable every test here SKIPS, so the default `pytest` run stays
offline, fast and green in CI -- which has no database and must never need one.
The variable is deliberately NOT `DATABASE_URL`: `backend/conftest.py` blanks
that one at import to guarantee the unit suite cannot reach a real server, and
this file must not be the loophole that undoes it.

**Nothing here commits.** Each test runs inside one transaction on its own
connection and the fixture rolls it back, so the tests are re-runnable, can run
against a database with real data in it, and leave nothing behind -- including
after a failure. Rows are keyed with a per-test random suffix as a second line
of defence, so a leaked row could never collide with the next run.
"""

from __future__ import annotations

import hashlib
import os
import pathlib
import re
import uuid
from typing import Any, Iterator

import pytest

from tests.dbharness import FAIL, SKIP, TEST_DB_ENV, collection_decision

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
MIGRATIONS_DIR = REPO_ROOT / "db" / "migrations"
BACKEND_SRC = REPO_ROOT / "backend" / "src"
BACKEND_APP = REPO_ROOT / "backend" / "app"


def _probe(url: str) -> str | None:
    """Connect once, fast, and return why not if it fails.

    `connect_timeout=2` because the point of the probe is to decide whether to
    skip: a developer without the container running should wait two seconds, not
    the driver's default. Called once at import (the result is a module
    constant), so the whole file costs one connection attempt.
    """
    try:
        import psycopg
        with psycopg.connect(url, connect_timeout=2) as conn:
            conn.execute("SELECT 1")
        return None
    except Exception as exc:                       # any failure means "skip", not "fail"
        return f"{type(exc).__name__}: {exc}"


_URL = os.environ.get(TEST_DB_ENV, "").strip()
_DECISION, _REASON = collection_decision(_URL, _probe(_URL) if _URL else None)

# A database that was ASKED FOR and could not be reached is a hard failure, not a
# skip. Raising here fails COLLECTION, so the run is red and says why -- the
# alternative (skipping) exits 0 on a CI job that believed it was proving these
# properties against real rows and proved nothing. `tests/dbharness.py` holds the
# decision, and test_persist_snapshot.py unit-tests it offline.
if _DECISION == FAIL:
    raise RuntimeError(_REASON)

pytestmark = pytest.mark.skipif(_DECISION == SKIP, reason=_REASON)


# --------------------------------------------------------------------------
# fixtures
# --------------------------------------------------------------------------

@pytest.fixture()
def conn() -> Iterator[Any]:
    """One connection, one transaction, always rolled back.

    Not `src.db.get_conn()`: that reads `settings.DATABASE_URL`, which
    conftest.py blanks on purpose, and it COMMITS on clean exit. A test that
    commits into the system of record would be a test that damages it.

    REPEATABLE READ, because the exit-criterion tests count WHOLE TABLES before
    and after an act and assert an exact delta ("+4 audit rows, +1 merge"). Under
    READ COMMITTED each count takes a fresh snapshot, so anything else committing
    to the same database between them -- another developer, a second suite, a
    stray `tasks.py demo` -- would show up as a governance row appearing or
    vanishing and fail the test for the one reason it is not about. The
    transaction still sees every one of its OWN writes; it just stops seeing
    other people's arrive mid-test.
    """
    import psycopg
    from psycopg import IsolationLevel
    from psycopg.rows import dict_row

    connection = psycopg.connect(_URL, row_factory=dict_row, autocommit=False)
    connection.isolation_level = IsolationLevel.REPEATABLE_READ
    try:
        connection.execute("SET search_path TO ztpa, public")
        yield connection
    finally:
        connection.rollback()                      # nothing this file does survives
        connection.close()


@pytest.fixture()
def cur(conn: Any) -> Iterator[Any]:
    with conn.cursor() as c:
        yield c


@pytest.fixture(scope="module")
def eng():
    """One real engine result for the whole module (the demo dataset)."""
    from src.analyzers.run_all import run
    return run()


@pytest.fixture()
def as_admin() -> Iterator[str]:
    """An identified actor in the request context, as `_ActorMiddleware` sets it
    from the proxy headers. Yields the email so assertions can name it."""
    from src import request_ctx
    email = f"grace-{uuid.uuid4().hex[:8]}@example.com"
    request_ctx.set_actor("admin", email, f"autox-{uuid.uuid4().hex[:8]}")
    try:
        yield email
    finally:
        request_ctx.set_actor(None, None, None)


# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------

# The three tables the exit criterion names, plus the two that hang off them.
GOVERNANCE_COUNTED = ("change_requests", "change_decisions", "audit_log",
                      "staged_changes", "asset_merges")


def _counts(cur: Any, tables: tuple[str, ...] = GOVERNANCE_COUNTED) -> dict[str, int]:
    return {t: cur.execute(f"SELECT count(*) AS n FROM ztpa.{t}").fetchone()["n"] for t in tables}


def _seed_governance(cur: Any, snapshot_id: str, tag: str) -> dict[str, str]:
    """A complete governance record citing `snapshot_id`: the request somebody
    made, the gate's decision on it, the staged change it produced, and a
    human-confirmed merge. This is the compliance artifact whose loss was the
    reported blocker -- so it is what every path below is measured against.

    Written through `persist_change_request_row` / `persist_change_decision_row`
    rather than a bare `upsert`, because those two are the production writers and
    the only place `archived_at` is cleared. Seeding with a hand-rolled INSERT
    would make the revival test prove a property of the test's own SQL."""
    from src.db import upsert
    from src.persist import persist_change_decision_row, persist_change_request_row

    request_id = f"req-{tag}"
    persist_change_request_row(cur, {
        "request_id": request_id, "snapshot_id": snapshot_id,
        "proposed": {"source": "10.0.0.0/24", "destination": "db-prod", "service": "tcp/5432"},
        "requested_by": "app-team@example.com", "justification": "quarterly access review",
        "kind": "add_allow", "origin": "change_gate", "status": "open",
    })
    persist_change_decision_row(cur, {
        "decision_id": f"dec-{tag}", "request_id": request_id, "decision": "escalate",
        "criteria": {"crosses_boundary": True}, "triggering_reason": "internet -> pci",
        "delta_summary": {"new_paths": 1}, "confidence": 0.9, "forced_escalate": True,
        "model": "engine",
    })
    upsert(cur, "staged_changes", {
        "staged_id": f"stg-{tag}", "snapshot_id": snapshot_id, "request_id": request_id,
        "origin": "change_gate", "kind": "add_allow", "target_tool": "algosec",
        "payload": {"op": "add"}, "decision": "manual_approved", "status": "staged",
    }, ["staged_id"])
    cur.execute("INSERT INTO ztpa.asset_merges (merge_id, name_a, name_b, confirmed_by) "
                "VALUES (%s, %s, %s, %s) ON CONFLICT (merge_id) DO NOTHING",
                [f"mrg-{tag}", f"a-{tag}", f"b-{tag}", "grace@example.com"])
    return {"request_id": request_id, "decision_id": f"dec-{tag}", "staged_id": f"stg-{tag}"}


def _tag() -> str:
    return uuid.uuid4().hex[:12]


def _audit_rows(cur: Any, action: str, subject: str | None = None) -> list[dict]:
    sql = "SELECT * FROM ztpa.audit_log WHERE action = %s"
    params: list[Any] = [action]
    if subject is not None:
        sql += " AND subject = %s"
        params.append(subject)
    return cur.execute(sql + " ORDER BY ts DESC", params).fetchall()


def test_the_fixture_is_insulated_from_concurrent_writers(cur: Any) -> None:
    """The whole-table `_counts` deltas below are only meaningful if nobody
    else's commit can land between the two counts, so the isolation level is
    asserted rather than assumed.

    Asserted structurally instead of demonstrated with a second connection,
    because demonstrating it would mean COMMITTING a row to prove the first
    transaction cannot see it -- and this file's contract is that nothing it does
    survives, including after a failure."""
    assert cur.execute("SHOW transaction_isolation").fetchone()["transaction_isolation"] == \
        "repeatable read"


# ==========================================================================
# 1. THE EXIT CRITERION: four paths, none of them destroys the record
# ==========================================================================
# "A recompute, a dataset switch, an asset merge and a reset each leave
# change_requests, change_decisions and audit_log intact." Each test below
# reproduces one path's PERSISTENCE-LAYER sequence exactly as app/main.py issues
# it, against real rows, and counts before and after.
#
# The API layer is not driven from here on purpose: `write_scenario` (which
# /api/admin/dataset calls) rewrites backend/data/mock/*.json, which are
# committed files that every other test in this suite reads. A test that
# mutates the repository to prove a database property would be trading one
# system of record for another.


def _recompute(cur: Any, eng) -> None:
    """`POST /api/recompute`, from `with get_conn()` to the closing audit --
    app/main.py:recompute. Same for the two callers below it."""
    from src.db import audit
    from src.persist import persist_engine_result

    persist_engine_result(cur, eng)
    cur.execute("DELETE FROM ztpa.ranked_actions WHERE snapshot_id=%s", [eng.snapshot_id])
    cur.execute("UPDATE ztpa.findings SET explanation=NULL WHERE snapshot_id=%s", [eng.snapshot_id])
    audit(cur, "recompute_snapshot", subject=eng.snapshot_id, snapshot_id=eng.snapshot_id,
          detail={"records": len(eng.records)})


def test_recompute_leaves_the_governance_record_intact(cur: Any, eng, as_admin: str) -> None:
    """The blocker itself: the engine is deterministic, so recomputing UNCHANGED
    data resolves to the SAME snapshot_id -- which is exactly what made the old
    delete-the-parent-row implementation cascade the whole approval trail away.
    Pressed twice, because once is the case that used to look fine."""
    tag = _tag()
    _recompute(cur, eng)                                    # the snapshot row must exist first
    seeded = _seed_governance(cur, eng.snapshot_id, tag)
    before = _counts(cur)

    _recompute(cur, eng)
    _recompute(cur, eng)

    after = _counts(cur)
    for table in ("change_requests", "change_decisions", "staged_changes", "asset_merges"):
        assert after[table] == before[table], f"{table} changed across a recompute"
    # audit_log is append-only: it GREW, by exactly the rows the two recomputes
    # wrote (one precompute + one recompute event each). Nothing was removed.
    assert after["audit_log"] == before["audit_log"] + 4

    # ...and the rows are the same rows, not a coincidentally equal count.
    row = cur.execute("SELECT snapshot_id, status FROM ztpa.change_requests WHERE request_id=%s",
                      [seeded["request_id"]]).fetchone()
    assert row is not None, "the change request did not survive the recompute"
    assert row["snapshot_id"] == eng.snapshot_id, "its baseline pointer was cleared"
    assert cur.execute("SELECT count(*) AS n FROM ztpa.change_decisions WHERE request_id=%s",
                       [seeded["request_id"]]).fetchone()["n"] == 1


def test_a_dataset_switch_leaves_the_governance_record_intact(cur: Any, eng, as_admin: str) -> None:
    """`POST /api/admin/dataset` differs from a recompute in exactly one way that
    matters to the database: it persists a DIFFERENT snapshot_id while the
    previous one is still cited by governance rows. A manual merge changes the
    engine's content fingerprint, so `run(manual_merges=...)` yields a genuinely
    different snapshot the same way a different dataset would -- without
    rewriting the committed data/mock fixtures a real switch would."""
    from src.analyzers.run_all import run

    tag = _tag()
    _recompute(cur, eng)
    _seed_governance(cur, eng.snapshot_id, tag)
    before = _counts(cur)

    other = run(manual_merges=[("app-server-01", "app-server-1")])
    assert other.snapshot_id != eng.snapshot_id, "the two snapshots must actually differ"
    _recompute(cur, other)

    after = _counts(cur)
    for table in ("change_requests", "change_decisions", "staged_changes", "asset_merges"):
        assert after[table] == before[table], f"{table} changed across a dataset switch"
    assert after["audit_log"] > before["audit_log"]
    assert cur.execute("SELECT snapshot_id FROM ztpa.change_requests WHERE request_id=%s",
                       [f"req-{tag}"]).fetchone()["snapshot_id"] == eng.snapshot_id


def test_confirming_an_asset_merge_leaves_the_governance_record_intact(
        cur: Any, eng, as_admin: str) -> None:
    """`POST /api/assets/merge` -> `_apply_merges_and_persist`: record the merge,
    re-resolve identities, re-persist. It re-runs the whole persist path, so it
    had the same exposure as a recompute -- and it is the path an operator uses
    most, which is what made the silent loss so expensive."""
    from src.analyzers.run_all import run
    from src.db import audit
    from src.persist import load_asset_merges, persist_asset_merge

    tag = _tag()
    _recompute(cur, eng)
    _seed_governance(cur, eng.snapshot_id, tag)
    before = _counts(cur)

    merge_id = persist_asset_merge(cur, f"host-{tag}-a", f"host-{tag}-b", by="grace@example.com")
    assert merge_id
    assert (f"host-{tag}-a", f"host-{tag}-b") in load_asset_merges(cur)

    merged = run(manual_merges=load_asset_merges(cur))
    from src.persist import persist_engine_result
    persist_engine_result(cur, merged)
    cur.execute("DELETE FROM ztpa.ranked_actions WHERE snapshot_id=%s", [merged.snapshot_id])
    cur.execute("UPDATE ztpa.findings SET explanation=NULL WHERE snapshot_id=%s", [merged.snapshot_id])
    audit(cur, "confirm_merge", subject=f"host-{tag}-a~host-{tag}-b", snapshot_id=merged.snapshot_id,
          detail={"a": f"host-{tag}-a", "b": f"host-{tag}-b"})

    after = _counts(cur)
    for table in ("change_requests", "change_decisions", "staged_changes"):
        assert after[table] == before[table], f"{table} changed across an asset merge"
    assert after["asset_merges"] == before["asset_merges"] + 1     # the merge itself
    assert after["audit_log"] > before["audit_log"]


# The reset is the fourth leg of the criterion and the one that was FALSE on real
# rows until db/migrations/0003: `/api/admin/reset-demo` ran
# `DELETE FROM change_requests` and took the approval trail to zero. It was
# deliberate -- a demo reset clears the working set -- but "the screen should
# look empty" and "destroy the compliance record" are two different acts that
# shared one implementation, and the criterion names the second one. The reset
# now RETIRES: it stamps `archived_at`, the rows stay, and the reads that feed
# the console filter them out. The four tests below assert both halves, because
# either one alone is satisfiable by a wrong implementation -- rows that survive
# but still show up is a broken reset, and an empty screen with no rows is the
# defect that was reported.
#
# These names are written out rather than imported from `src.persist`, on
# purpose. The earlier version of the blast-radius test derived its expectation
# from `RESET_TABLES` itself, so widening that constant widened the test with it:
# adding "audit_log" to the reset made the test assert that audit_log SHOULD be
# emptied, and it passed. A test whose expectation is read from the thing under
# test cannot fail. This list is the DECISION, restated here, and changing the
# reset's blast radius now has to be argued for twice.
RESET_MUST_ARCHIVE = ("change_decisions", "change_requests")
RESET_MUST_CLEAR = ("staged_changes", "remediation_revisions", "campaign_plans")


def test_the_reset_declares_the_blast_radius_this_file_expects() -> None:
    """The two constants the endpoint drives off, checked against the two lists
    above -- so a widened reset fails HERE, naming the table that was added,
    before any of the behavioural tests get a chance to be quietly rewritten by
    it. `audit_log` is asserted absent from both by name: it is the record that
    the reset happened, and no version of "reset" may touch it."""
    from src.persist import RESET_ARCHIVED_TABLES, RESET_CLEARED_TABLES, RESET_TABLES

    assert RESET_ARCHIVED_TABLES == RESET_MUST_ARCHIVE
    assert RESET_CLEARED_TABLES == RESET_MUST_CLEAR
    assert RESET_TABLES == RESET_MUST_ARCHIVE + RESET_MUST_CLEAR
    assert "audit_log" not in RESET_TABLES
    assert "asset_merges" not in RESET_TABLES        # a reset is not an identity reset
    assert not set(RESET_ARCHIVED_TABLES) & set(RESET_CLEARED_TABLES)


def test_reset_leaves_the_governance_record_intact(cur: Any, eng, as_admin: str) -> None:
    """The fourth leg of the exit criterion, on real rows: after a reset, the
    counts of `change_requests`, `change_decisions` and `audit_log` are the
    counts from before it, and the seeded request is still the seeded request --
    compared WHOLE ROW against what was written, so "intact" means every column
    (baseline pointer, justification, status, the proposed change itself) and not
    just "a row with that id exists". The retirement stamp is the one allowed
    difference, and it is the difference the feature is made of.

    Run TWICE, because a reset that is idempotent about deletion (0 rows left,
    delete them again) is not automatically idempotent about a retirement date:
    the second reset must not restamp rows the first one retired, or "when was
    this decision taken off the board" stops being answerable."""
    from src.db import audit
    from src.persist import reset_change_workflow

    def _rows() -> dict[str, Any]:
        return {
            "request": cur.execute("SELECT * FROM ztpa.change_requests WHERE request_id=%s",
                                   [seeded["request_id"]]).fetchone(),
            "decision": cur.execute("SELECT * FROM ztpa.change_decisions WHERE decision_id=%s",
                                    [seeded["decision_id"]]).fetchone(),
        }

    tag = _tag()
    _recompute(cur, eng)
    seeded = _seed_governance(cur, eng.snapshot_id, tag)
    before = _counts(cur)
    before_rows = _rows()
    assert before["change_requests"] > 0 and before["change_decisions"] > 0
    assert before_rows["request"] and before_rows["decision"], "the seed did not land"

    cleared = reset_change_workflow(cur)
    audit(cur, "reset_demo", detail=cleared)
    after_rows = _rows()

    after = _counts(cur)
    for table in ("change_requests", "change_decisions"):
        assert after[table] == before[table], (
            f"the reset destroyed {table}: {before[table]} -> {after[table]}. It must retire "
            f"rows (archived_at), not delete them -- see db/migrations/0003.")
    assert after["audit_log"] == before["audit_log"] + 1, "the reset erased audit history"
    assert after["asset_merges"] == before["asset_merges"], "a reset is not an identity reset"

    # "Intact" in the strong sense: every column of the seeded request and its
    # decision is byte-identical to what was written, EXCEPT the retirement
    # stamp. Compared whole rather than field by field, so a column added later
    # is covered without anyone remembering to add it here.
    assert after_rows["request"] is not None, "the change request did not survive the reset"
    assert {k: v for k, v in after_rows["request"].items() if k != "archived_at"} == \
        {k: v for k, v in before_rows["request"].items() if k != "archived_at"}, \
        "the reset rewrote the change request instead of only retiring it"
    assert {k: v for k, v in after_rows["decision"].items() if k != "archived_at"} == \
        {k: v for k, v in before_rows["decision"].items() if k != "archived_at"}, \
        "the reset rewrote the decision instead of only retiring it"
    assert after_rows["request"]["snapshot_id"] == eng.snapshot_id, "its baseline pointer was cleared"
    assert after_rows["request"]["archived_at"] is not None, \
        "the request should be stamped retired, not left live"
    assert after_rows["decision"]["archived_at"] is not None

    row = after_rows["request"]

    retired_at = row["archived_at"]
    reset_change_workflow(cur)
    assert cur.execute("SELECT archived_at FROM ztpa.change_requests WHERE request_id=%s",
                       [seeded["request_id"]]).fetchone()["archived_at"] == retired_at, \
        "a second reset moved the retirement date of a row the first one had already retired"


def test_reset_leaves_the_audit_log_intact(cur: Any, eng, as_admin: str) -> None:
    """The third table the criterion names, and the one that answers "what
    happened here": the reset appends to `audit_log` and removes nothing from it,
    the row names the admin who ordered it, and its detail carries the per-table
    counts -- for the retired tables, how many rows were taken off the board."""
    from src.db import audit
    from src.persist import reset_change_workflow

    tag = _tag()
    _recompute(cur, eng)
    _seed_governance(cur, eng.snapshot_id, tag)
    before = _counts(cur)
    live_requests = cur.execute("SELECT count(*) AS n FROM ztpa.change_requests "
                                "WHERE archived_at IS NULL").fetchone()["n"]

    cleared = reset_change_workflow(cur)
    audit(cur, "reset_demo", detail=cleared)

    assert _counts(cur)["audit_log"] == before["audit_log"] + 1, "the reset erased audit history"
    row = _audit_rows(cur, "reset_demo")[0]
    assert row["actor_email"] == as_admin, "the reset must name who ordered it"
    assert row["detail"]["change_requests"] == live_requests, \
        "the audit row must record how much the reset retired"


def test_reset_still_empties_the_screens_it_is_supposed_to_empty(
        cur: Any, eng, as_admin: str) -> None:
    """The other half, and the reason the fix is an archive rather than a refusal
    to reset: the demo must still start from a clean slate.

    Asserted through `app.main.LIVE_DECISIONS_SQL` -- the actual query
    GET /api/change-decisions runs, imported rather than transcribed, so a route
    that loses its `archived_at IS NULL` filter fails here instead of passing
    against a copy of the query that still has it."""
    from app.main import LIVE_DECISIONS_SQL
    from src.persist import reset_change_workflow

    tag = _tag()
    _recompute(cur, eng)
    seeded = _seed_governance(cur, eng.snapshot_id, tag)

    live = [r["request_id"] for r in cur.execute(LIVE_DECISIONS_SQL, [200]).fetchall()]
    assert seeded["request_id"] in live, "the seeded decision should be on the board to begin with"

    reset_change_workflow(cur)

    live = [r["request_id"] for r in cur.execute(LIVE_DECISIONS_SQL, [200]).fetchall()]
    assert live == [], f"the decision log is not empty after a reset: {live}"
    assert _counts(cur, ("staged_changes",))["staged_changes"] == 0, (
        "pushed staged_changes are an engine input (persist.load_applied_changes), so a reset "
        "that left them would not make the resolved finding reappear")
    # ...and the KPI tile the admin dashboard reads is zeroed by the same filter.
    assert cur.execute("SELECT count(*) AS n FROM ztpa.change_decisions "
                       "WHERE archived_at IS NULL").fetchone()["n"] == 0


def test_resubmitting_a_retired_request_brings_it_back(cur: Any, eng, as_admin: str) -> None:
    """Request ids are deterministic content hashes, so re-running the demo
    writes the SAME request_id a reset just retired. The write must clear the
    stamp, or the second run's decisions are invisible on every screen while
    sitting in the table looking correct -- a subtler version of the bug this
    whole change is about."""
    from app.main import LIVE_DECISIONS_SQL
    from src.persist import reset_change_workflow

    tag = _tag()
    _recompute(cur, eng)
    seeded = _seed_governance(cur, eng.snapshot_id, tag)
    reset_change_workflow(cur)
    assert cur.execute(LIVE_DECISIONS_SQL, [200]).fetchall() == []

    _seed_governance(cur, eng.snapshot_id, tag)            # the identical ids, re-submitted

    row = cur.execute("SELECT archived_at FROM ztpa.change_requests WHERE request_id=%s",
                      [seeded["request_id"]]).fetchone()
    assert row["archived_at"] is None, "re-submitting a retired request left it retired"
    live = [r["request_id"] for r in cur.execute(LIVE_DECISIONS_SQL, [200]).fetchall()]
    assert live == [seeded["request_id"]], f"the resubmitted request is not back on the board: {live}"


def test_a_retired_request_cannot_be_rejected(cur: Any, eng, as_admin: str) -> None:
    """Retirement is not a soft delete that leaves the row writable. Rejecting a
    request nobody currently holds -- writing `rejected_by` and a reason into
    history -- is the same class of falsification as deleting it, so the UPDATE
    is scoped to live rows and reports 0, which the endpoint turns into a 404."""
    from src.persist import reject_change_request, reset_change_workflow

    tag = _tag()
    _recompute(cur, eng)
    seeded = _seed_governance(cur, eng.snapshot_id, tag)
    reset_change_workflow(cur)

    assert reject_change_request(cur, seeded["request_id"], as_admin, "too late") == 0
    row = cur.execute("SELECT status, rejected_by FROM ztpa.change_requests WHERE request_id=%s",
                      [seeded["request_id"]]).fetchone()
    assert row["status"] == "open" and row["rejected_by"] is None, "history was rewritten"


def test_reset_touches_nothing_outside_its_documented_set(cur: Any, eng, as_admin: str) -> None:
    """The blast radius, measured over the live catalog: every table in the
    schema is either retired, cleared, or completely unchanged -- and which one
    it is comes from the hand-written lists at the top of this section, not from
    the constant the reset itself reads.

    Counting over `information_schema` rather than a fixed list of tables is what
    covers a table added later without anyone remembering to add it here."""
    from src.persist import reset_change_workflow

    _recompute(cur, eng)
    _seed_governance(cur, eng.snapshot_id, _tag())
    tables = tuple(r["table_name"] for r in cur.execute(
        "SELECT table_name FROM information_schema.tables "
        "WHERE table_schema='ztpa' AND table_type='BASE TABLE' ORDER BY table_name").fetchall())
    before = _counts(cur, tables)
    live_before = {t: cur.execute(f"SELECT count(*) AS n FROM ztpa.{t} WHERE archived_at IS NULL")
                   .fetchone()["n"] for t in RESET_MUST_ARCHIVE}
    assert all(n > 0 for n in live_before.values()), "seed something to retire, or this proves nothing"

    reset_change_workflow(cur)

    after = _counts(cur, tables)
    for table in tables:
        if table in RESET_MUST_CLEAR:
            assert after[table] == 0, f"{table} is in the reset's clear list but was not cleared"
        else:
            # Includes the archived tables: retiring a row does not remove it.
            assert after[table] == before[table], f"reset-demo removed rows from {table}"
    for table in RESET_MUST_ARCHIVE:
        assert cur.execute(f"SELECT count(*) AS n FROM ztpa.{table} "
                           "WHERE archived_at IS NULL").fetchone()["n"] == 0, \
            f"{table} is in the reset's archive list but rows were left live"


# ==========================================================================
# 2. persist_engine_result writes only columns that exist
# ==========================================================================
# The audit's note on this module was "literally zero executed coverage": every
# assertion about it was against a fake cursor, which accepts any column name at
# all. A projection naming a column the table does not have fails only in
# production, on the write that matters.


def test_persist_engine_result_writes_the_whole_snapshot_for_real(cur: Any, eng, as_admin: str) -> None:
    """The end-to-end proof, and the strongest form of "every column exists":
    Postgres rejects the statement otherwise. Row counts are compared with
    `snapshot_counts`, the projection app/main.py serves in degraded mode -- so
    this also pins the degraded read to the persisted truth."""
    from src.persist import persist_engine_result, snapshot_counts

    summary = persist_engine_result(cur, eng)
    assert summary["snapshot_id"] == eng.snapshot_id

    expected = snapshot_counts(eng)
    for table, n in expected.items():
        if table == "ranked_actions":
            continue                              # AI-derived; the engine writes none
        actual = cur.execute(f"SELECT count(*) AS n FROM ztpa.{table} WHERE snapshot_id=%s",
                             [eng.snapshot_id]).fetchone()["n"]
        assert actual == n, f"{table}: persisted {actual}, projection promised {n}"


@pytest.mark.parametrize("table,projection", [
    ("snapshots", "snapshot_row"), ("sources", "source_rows"),
    ("resolved_objects", "resolved_object_rows"), ("assets", "asset_rows"),
    ("asset_correlations", "correlation_rows"), ("canonical_rules", "canonical_rule_rows"),
    ("graph_nodes", "graph_node_rows"), ("graph_edges", "graph_edge_rows"),
    ("findings", "finding_rows"),
])
def test_every_projected_column_exists_in_the_database(cur: Any, eng, table: str,
                                                       projection: str) -> None:
    """Named per table so a failure says WHICH projection drifted, instead of
    'the persist raised'. Reads the live catalog, not db/schema.sql: the question
    is what the deployed database has, which is the whole point of a migration
    runner existing."""
    from src import persist

    rows = getattr(persist, projection)(eng)
    rows = [rows] if isinstance(rows, dict) else rows
    if not rows:
        pytest.skip(f"the demo dataset produces no {table} rows")

    have = {r["column_name"] for r in cur.execute(
        "SELECT column_name FROM information_schema.columns "
        "WHERE table_schema='ztpa' AND table_name=%s", [table]).fetchall()}
    missing = sorted(set(rows[0]) - have)
    assert not missing, f"persist writes {missing} to ztpa.{table}, which has no such column"


def test_the_engine_emits_a_correlation_the_shipped_check_constraint_rejected(
        cur: Any, eng, as_admin: str) -> None:
    """The drift the audit named, from the direction that matters.

    Phase 1's identity layer emits `match_key='manual_review'` for a merge the
    guards withheld -- the demo dataset produces one. The shipped
    `asset_correlations_match_key_check` listed only cloud_id/hostname/mac/
    context_ip, so that row was a CheckViolation that aborted the entire snapshot
    persist. It did not fire in practice only because `persist._ensure_merges`
    happened to widen the constraint at runtime, from the unrelated merge-loading
    path -- i.e. the write worked because of an accident of call ordering. With
    that helper deleted, the migration is the only thing standing between the
    engine and a failed persist, which is exactly what this asserts.
    """
    from src.persist import correlation_rows, persist_engine_result

    assert any(r["match_key"] == "manual_review" for r in correlation_rows(eng)), \
        "the demo dataset no longer exercises the widened constraint"
    persist_engine_result(cur, eng)               # raises CheckViolation without migration 0001
    assert cur.execute(
        "SELECT count(*) AS n FROM ztpa.asset_correlations "
        "WHERE snapshot_id=%s AND match_key='manual_review'", [eng.snapshot_id]
    ).fetchone()["n"] >= 1


# ==========================================================================
# 3. the audit trail names someone, at every call site
# ==========================================================================

_AUDIT_CALL = re.compile(r"\baudit\s*\(")
_IDENTITY_KWARG = re.compile(r"\bactor_(?:email|sub|role)\s*=")


def _python_sources() -> list[pathlib.Path]:
    return sorted([*BACKEND_SRC.rglob("*.py"), *BACKEND_APP.rglob("*.py")])


def test_audit_is_the_only_writer_of_the_audit_log() -> None:
    """The premise every claim in this section rests on.

    `audit()` fills the three identity columns unconditionally, so "all fifteen
    call sites are covered" is true if and only if nothing else can insert into
    the table. Checked over the source rather than per call site, because the
    per-call-site version is the one that goes stale when a sixteenth is added.
    """
    offenders: list[str] = []
    for path in _python_sources():
        if path.name == "db.py":
            continue                              # db.audit() is the sanctioned writer
        for i, line in enumerate(path.read_text().splitlines(), 1):
            code = line.split("#", 1)[0]
            if re.search(r"INSERT\s+INTO\s+(?:ztpa\.)?audit_log", code, re.I) or \
               re.search(r"insert\s*\(\s*cur\s*,\s*[\"']audit_log[\"']", code):
                offenders.append(f"{path.relative_to(REPO_ROOT)}:{i}: {line.strip()}")
    assert offenders == [], f"audit_log written outside db.audit(): {offenders}"


def test_no_call_site_can_supply_its_own_identity() -> None:
    """A call site that could PASS actor_email could pass the wrong one, and the
    whole design is that it has no such argument to get wrong."""
    offenders = [
        f"{p.relative_to(REPO_ROOT)}:{i}"
        for p in _python_sources() if p.name != "db.py"
        for i, line in enumerate(p.read_text().splitlines(), 1)
        if _AUDIT_CALL.search(line) and _IDENTITY_KWARG.search(line)
    ]
    assert offenders == [], f"a call site is supplying its own actor identity: {offenders}"


def test_the_audit_call_sites_are_all_still_there() -> None:
    """Guards the guard: if the scan above stops finding call sites (a rename, a
    wrapper), every assertion in this section would pass vacuously."""
    sites = [f"{p.relative_to(REPO_ROOT)}:{i}"
             for p in _python_sources()
             for i, line in enumerate(p.read_text().splitlines(), 1)
             if _AUDIT_CALL.search(line) and "def audit" not in line and not line.lstrip().startswith("#")]
    assert len(sites) >= 15, f"expected the audit's fifteen call sites, found {len(sites)}: {sites}"


@pytest.mark.parametrize("call_site", [
    "persist_engine_result", "persist_ranked_actions", "persist_remediation_revision",
    "persist_staged_change", "reject_change_request", "persist_change_decision",
])
def test_every_persist_call_site_records_the_actor(cur: Any, eng, as_admin: str,
                                                   call_site: str) -> None:
    """Each of the six audit-writing entry points in persist.py, executed for
    real, with the resulting row read back out of Postgres.

    (The fourteen in app/main.py are covered by construction: `audit()` is the
    only writer -- asserted above -- and it takes no identity argument, so a call
    site cannot produce a row without one.)
    """
    from src import persist
    from src.models import ChangeDecision, ChangeRequest, RankedAction, RankedActions

    tag = _tag()
    persist.persist_engine_result(cur, eng)       # every path below needs the snapshot row
    sid = eng.snapshot_id
    before = {r["id"] for r in cur.execute("SELECT id FROM ztpa.audit_log").fetchall()}

    if call_site == "persist_engine_result":
        persist.persist_engine_result(cur, eng)   # again: it upserts, so twice is one state
    elif call_site == "persist_ranked_actions":
        persist.persist_ranked_actions(cur, sid, RankedActions(
            actions=[RankedAction(action_id=f"act-{tag}", title="t", finding_ids=[],
                                  priority=1, rationale="r")],
            ranked_by="engine_fallback"))
    elif call_site == "persist_remediation_revision":
        persist.persist_remediation_revision(cur, sid, eng.findings[0].id,
                                             {"fix_text": "narrow the source"}, comment="please")
    elif call_site == "persist_staged_change":
        persist.persist_staged_change(cur, {"staged_id": f"stg-{tag}", "snapshot_id": sid,
                                            "request_id": f"req-{tag}", "status": "staged"})
    elif call_site == "reject_change_request":
        _seed_governance(cur, sid, tag)
        assert persist.reject_change_request(cur, f"req-{tag}", as_admin, "not this quarter") == 1
    elif call_site == "persist_change_decision":
        # `proposed` is a PolicyRecord; reuse a real one from the engine rather
        # than hand-building a shape the model might tighten later.
        request = ChangeRequest(
            id=f"req-{tag}", title="allow app -> db", proposed=eng.records[0],
            requested_by=as_admin, justification="access review")
        persist.persist_change_decision(cur, sid, request, ChangeDecision(
            request_id=request.id, decision="escalate", criteria={},
            triggering_reason="boundary", delta_summary={}, confidence=0.5,
            forced_escalate=True, decided_by="engine_fallback"))

    written = cur.execute("SELECT * FROM ztpa.audit_log WHERE id <> ALL(%s)",
                          [list(before) or [uuid.uuid4()]]).fetchall()
    assert written, f"{call_site} wrote no audit row"
    for row in written:
        assert row["actor_email"] == as_admin, (call_site, row["action"], row["actor_email"])
        assert row["actor_role"] == "admin", (call_site, row["action"])
        assert row["actor_sub"], (call_site, row["action"])
        assert row["actor"] in ("agent", "user", "system"), row["actor"]


def test_the_snapshot_correlation_survives_deleting_the_snapshot(cur: Any, eng, as_admin: str) -> None:
    """`audit_log.snapshot_id` was a FK with ON DELETE SET NULL, so removing a
    snapshot silently erased the tie between every audit row and the posture it
    was recorded against. It is a plain column since migration 0002."""
    from src.db import audit, delete_snapshot
    from src.persist import persist_engine_result

    persist_engine_result(cur, eng)
    action = f"probe_{_tag()}"                    # unique, so the read-back cannot match
    audit(cur, action, subject="x", snapshot_id=eng.snapshot_id)

    delete_snapshot(cur, eng.snapshot_id)

    row = cur.execute("SELECT snapshot_id FROM ztpa.audit_log WHERE action=%s", [action]).fetchone()
    assert row is not None, "the audit row itself was deleted"
    assert row["snapshot_id"] == eng.snapshot_id, "the snapshot correlation was nulled out"


def test_deleting_a_snapshot_actually_deletes_the_snapshot(cur: Any, eng, as_admin: str) -> None:
    """`delete_snapshot` removes the row, not only its children.

    Phase 2 split one function into two -- `delete_snapshot_children` (clear the
    engine's cache for this snapshot) and `delete_snapshot` (remove it) -- and
    `DELETE /api/snapshots/{id}` kept calling the children-only half under a
    comment claiming it deleted the parent. It answered
    `200 {"ok": true, "deleted": ...}` and left the row exactly where it was,
    now reading 0 findings and 0 assets: the admin was told a thing had happened
    that had not. The route calls `delete_snapshot` now, and
    `test_persist_snapshot.py` pins which helper it reaches; this is the
    executed proof that the helper does what its name says."""
    from src.db import delete_snapshot, delete_snapshot_children
    from src.persist import persist_engine_result

    persist_engine_result(cur, eng)
    sid = eng.snapshot_id
    exists = "SELECT count(*) AS n FROM ztpa.snapshots WHERE snapshot_id=%s"
    findings = "SELECT count(*) AS n FROM ztpa.findings WHERE snapshot_id=%s"
    assert cur.execute(exists, [sid]).fetchone()["n"] == 1
    assert cur.execute(findings, [sid]).fetchone()["n"] > 0

    # The cache-clearing half, first: children gone, the snapshot still there.
    delete_snapshot_children(cur, sid)
    assert cur.execute(findings, [sid]).fetchone()["n"] == 0
    assert cur.execute(exists, [sid]).fetchone()["n"] == 1, \
        "delete_snapshot_children must leave the row every governance record hangs off"

    delete_snapshot(cur, sid)
    assert cur.execute(exists, [sid]).fetchone()["n"] == 0, \
        "delete_snapshot returned without deleting the snapshot"


def test_staged_changes_records_who_approved_it(cur: Any, eng, as_admin: str) -> None:
    """`created_by` on the table listing the changes about to be pushed into a
    production firewall: declared in the first schema, written by nothing."""
    from src.persist import persist_staged_change

    tag = _tag()
    persist_staged_change(cur, {"staged_id": f"stg-{tag}", "request_id": f"req-{tag}",
                                "status": "staged", "target_tool": "algosec"})
    row = cur.execute("SELECT created_by FROM ztpa.staged_changes WHERE staged_id=%s",
                      [f"stg-{tag}"]).fetchone()
    assert row["created_by"] == as_admin


# ==========================================================================
# 4. upsert_many survives a snapshot wider than the bind-parameter cap
# ==========================================================================

def _wide_findings(sid: str, n: int) -> list[dict[str, Any]]:
    """`n` rows shaped exactly like `persist.finding_rows` output (11 columns).

    `signals` arrives pre-wrapped as Jsonb because half of this file's point is
    to execute the OLD single-statement form by hand, outside `upsert_many` and
    therefore outside `db._wrap`. (`_wrap` passes an existing Jsonb through
    untouched, so the chunked path sees exactly what it always would.)
    """
    from psycopg.types.json import Jsonb
    return [{
        "finding_id": f"{sid}-f{i:06d}", "snapshot_id": sid, "type": "over_permissive",
        "severity": i % 101, "severity_band": "low", "forced_critical": False,
        "signals": Jsonb({"i": i}), "involved": [f"asset-{i}"], "raw_refs": [f"algosec-{i}"],
        "source_tools": ["algosec"], "explanation": None,
    } for i in range(n)]


def test_a_snapshot_too_wide_for_one_statement_now_persists(cur: Any, eng, as_admin: str) -> None:
    """The defect, both halves, on the same rows and in the same transaction.

    `finding_rows` emits 11 columns, so 65535 // 11 = 5,957 rows was the ceiling:
    at 5,958 psycopg refused to send the query at all and the persist aborted,
    rolling back the whole snapshot and leaving it live-only. 6,000 findings is
    an ordinary size for a real export -- the audit's Phase 3 target is a
    5,000-RULE file, and rules produce findings.
    """
    import psycopg
    from src.db import DB_SCHEMA, MAX_BIND_PARAMS, upsert, upsert_many
    from src.persist import snapshot_row

    n = 6000
    upsert(cur, "snapshots", snapshot_row(eng), ["snapshot_id"])
    sid = eng.snapshot_id
    rows = _wide_findings(sid, n)
    assert n * len(rows[0]) > MAX_BIND_PARAMS, "this batch has to exceed the cap to prove anything"

    # (a) the statement the OLD implementation built, on this exact data.
    cols = list(rows[0])
    one = "(" + ", ".join(["%s"] * len(cols)) + ")"
    with pytest.raises(psycopg.Error) as excinfo:
        cur.execute(
            f"INSERT INTO {DB_SCHEMA}.findings ({', '.join(cols)}) "
            f"VALUES {', '.join([one] * n)} ON CONFLICT (finding_id) DO NOTHING",
            [r[c] for r in rows for c in cols])
    assert "65535" in str(excinfo.value), excinfo.value
    cur.execute("ROLLBACK")                       # the failed send poisoned the transaction

    # (b) the chunked implementation, same rows, read back from the table.
    upsert(cur, "snapshots", snapshot_row(eng), ["snapshot_id"])
    assert upsert_many(cur, "findings", rows, ["finding_id"]) == n
    assert cur.execute("SELECT count(*) AS n FROM ztpa.findings WHERE snapshot_id=%s AND "
                       "finding_id LIKE %s", [sid, f"{sid}-f%"]).fetchone()["n"] == n


def test_a_chunked_upsert_is_still_an_upsert(cur: Any, eng, as_admin: str) -> None:
    """Re-persisting across the chunk boundary must UPDATE, not duplicate or
    raise -- the property the whole persist layer is built on."""
    from src.db import upsert, upsert_many
    from src.persist import snapshot_row

    n = 6000
    upsert(cur, "snapshots", snapshot_row(eng), ["snapshot_id"])
    sid = eng.snapshot_id
    upsert_many(cur, "findings", _wide_findings(sid, n), ["finding_id"])

    second = _wide_findings(sid, n)
    for row in second:
        row["severity_band"] = "critical"
    assert upsert_many(cur, "findings", second, ["finding_id"]) == n

    counted = cur.execute("SELECT count(*) AS n FROM ztpa.findings WHERE finding_id LIKE %s",
                          [f"{sid}-f%"]).fetchone()["n"]
    assert counted == n, "a re-persist duplicated rows across chunks"
    assert cur.execute("SELECT count(*) AS n FROM ztpa.findings WHERE finding_id LIKE %s "
                       "AND severity_band='critical'", [f"{sid}-f%"]).fetchone()["n"] == n


# ==========================================================================
# 5. migrations are the only way schema changes apply
# ==========================================================================

def test_the_database_ledger_matches_the_repository(cur: Any) -> None:
    """Every file in db/migrations/ is recorded as applied, with the checksum of
    the file as it stands on disk.

    This is the assertion that makes "migrations are the only way schema changes
    apply" checkable rather than aspirational: it fails if a migration was never
    run, if one was applied and then edited (forward-only means an applied file
    is history), or if someone hand-wrote a ledger row to skip one. It is also
    the failure a developer WANTS when their local database is behind -- run
    `python db/migrate.py` and it goes green.
    """
    files = sorted(MIGRATIONS_DIR.glob("*.sql"))
    assert files, "expected at least 0001_governance_fk.sql"
    applied = {r["version"]: r for r in cur.execute(
        "SELECT version, filename, checksum FROM ztpa.schema_migrations").fetchall()}

    for path in files:
        version = path.name.split("_", 1)[0]
        assert version in applied, (
            f"{path.name} has never been applied to this database -- run `python db/migrate.py`")
        assert applied[version]["filename"] == path.name
        assert applied[version]["checksum"] == hashlib.sha256(path.read_bytes()).hexdigest(), (
            f"{path.name} was edited after it was applied; migrations are forward-only -- "
            f"add a new numbered file instead")


def test_the_runtime_ddl_definitions_are_present_in_the_database(cur: Any) -> None:
    """The four deleted `ensure_*` helpers, checked as schema facts rather than
    as SQL text: with the helpers gone, nothing recreates any of this at runtime,
    so a database missing one of them fails the next write instead."""
    tables = {r["table_name"] for r in cur.execute(
        "SELECT table_name FROM information_schema.tables WHERE table_schema='ztpa'").fetchall()}
    assert "asset_merges" in tables                       # was persist._ensure_merges
    assert "campaign_plans" in tables                     # was persist.ensure_campaign_plans

    checks = {r["conname"]: r["def"] for r in cur.execute(
        "SELECT conname, pg_get_constraintdef(oid) AS def FROM pg_constraint "
        "WHERE conrelid IN ('ztpa.findings'::regclass, 'ztpa.asset_correlations'::regclass)"
    ).fetchall()}
    assert "transport_exposure" in checks["findings_type_check"]            # ensure_finding_types
    assert "manual_review" in checks["asset_correlations_match_key_check"]  # _ensure_merges

    columns = {r["column_name"] for r in cur.execute(
        "SELECT column_name FROM information_schema.columns "
        "WHERE table_schema='ztpa' AND table_name='change_requests'").fetchall()}
    assert {"status", "rejected_by", "reject_reason"} <= columns   # ensure_change_request_status


def test_the_audit_identity_columns_and_index_exist(cur: Any) -> None:
    """Migration 0002's own end state, read off the live database."""
    columns = {r["column_name"] for r in cur.execute(
        "SELECT column_name FROM information_schema.columns "
        "WHERE table_schema='ztpa' AND table_name='audit_log'").fetchall()}
    assert {"actor_email", "actor_sub", "actor_role"} <= columns

    fks = [r["conname"] for r in cur.execute(
        "SELECT conname FROM pg_constraint WHERE conrelid='ztpa.audit_log'::regclass "
        "AND contype='f'").fetchall()]
    assert fks == [], f"audit_log still has a foreign key: {fks}"

    indexes = {r["indexname"] for r in cur.execute(
        "SELECT indexname FROM pg_indexes WHERE schemaname='ztpa' AND tablename='audit_log'"
    ).fetchall()}
    assert "idx_audit_ts" in indexes, "GET /api/audit orders by ts DESC on every page"
