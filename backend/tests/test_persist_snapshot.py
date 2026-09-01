"""The recompute path must not destroy the governance record.

The defect these tests pin: `delete_snapshot_children` cleared a snapshot's
children by deleting the PARENT `snapshots` row, and `change_requests.snapshot_id`
was `ON DELETE CASCADE` against it. The engine is deterministic, so recomputing
UNCHANGED data resolves to the same snapshot_id -- one press of Recompute deleted
the live row and cascaded away every change_request and change_decision recorded
against it, leaving staged_changes dangling on a request_id that no longer
resolved. No error, no warning, no way back.

There is no database in this environment (and CI must never reach one), so the
tests work at the two layers that are reachable without one:

  * a **recording cursor** -- a stand-in that captures every `execute(sql, params)`
    -- driven by the real `persist_engine_result` over the real engine output, so
    the assertions are about the SQL the production path actually emits; and
  * a **static read of db/schema.sql**, so the foreign key cannot be quietly
    restored to CASCADE by a future schema edit even if the Python stays correct.

The Phase 0 exit criterion is "pressing Recompute twice leaves the
change-decisions row count unchanged". Without a DB the equivalent proof is
that two consecutive persists emit an identical statement stream that contains
no destructive statement against any governance table -- which is what
`test_recompute_twice_emits_no_destructive_governance_sql` asserts.
"""

from __future__ import annotations

import pathlib
import re
from typing import Any, Iterable

import pytest

from src import persist
from src.analyzers.run_all import run
from src.db import ENGINE_OWNED_TABLES, GOVERNANCE_TABLES, delete_snapshot, delete_snapshot_children

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
SCHEMA_SQL = REPO_ROOT / "db" / "schema.sql"
MIGRATION_0001 = REPO_ROOT / "db" / "migrations" / "0001_governance_fk.sql"

# The four tables the audit names as the compliance artifact. GOVERNANCE_TABLES
# is broader (it also covers ai_metrics, asset_merges, remediation_revisions);
# these are the ones whose loss was the reported blocker, asserted by name so a
# rename or a shrink of the set in db.py cannot quietly weaken the test.
AUDIT_TRAIL = ("change_requests", "change_decisions", "staged_changes", "audit_log")


# --------------------------------------------------------------------------
# recording cursor
# --------------------------------------------------------------------------

class RecordingCursor:
    """A psycopg-shaped cursor that executes nothing and remembers everything.

    Only the surface `persist.py` uses is implemented: `execute` (returning self,
    so psycopg's `cur.execute(...).fetchone()` chaining works), the two fetches,
    and `rowcount`. Anything else raising an AttributeError is the point -- a new
    call in the persist path that needs a real database should be visible here,
    not silently mocked away.
    """

    def __init__(self, rows: list[dict[str, Any]] | None = None) -> None:
        self.calls: list[tuple[str, list[Any]]] = []
        self._rows = rows or []
        self.rowcount = 0

    def execute(self, sql: str, params: Iterable[Any] | None = None) -> "RecordingCursor":
        self.calls.append((sql, list(params) if params is not None else []))
        return self

    def fetchone(self) -> dict[str, Any] | None:
        return self._rows[0] if self._rows else None

    def fetchall(self) -> list[dict[str, Any]]:
        return list(self._rows)

    @property
    def sql(self) -> str:
        """Every statement issued, newline-joined -- the thing under test."""
        return "\n".join(s for s, _ in self.calls)


def _mentions(sql: str, table: str) -> bool:
    """Does `sql` name this table at all? Word-bounded, so `assets` does not
    match `asset_merges` and vice versa."""
    return re.search(rf"\b{re.escape(table)}\b", sql) is not None


_DESTRUCTIVE = r"(?:DELETE\s+FROM|TRUNCATE(?:\s+TABLE)?|UPDATE|DROP\s+TABLE|ALTER\s+TABLE)"


def _destructive_statements(cur: RecordingCursor, table: str) -> list[str]:
    """Statements that would remove or rewrite existing rows of `table`.

    An INSERT is deliberately NOT destructive: `persist_engine_result` appends to
    `audit_log` on every run, which is exactly what an append-only audit trail is
    for. What must never happen is a DELETE/UPDATE/TRUNCATE against it.
    """
    pattern = re.compile(rf"{_DESTRUCTIVE}\s+(?:ztpa\.)?{re.escape(table)}\b", re.I)
    return [s for s, _ in cur.calls if pattern.search(s)]


# --------------------------------------------------------------------------
# delete_snapshot_children -- the function that used to drop the parent row
# --------------------------------------------------------------------------

SID = "snap-test-0001"


@pytest.fixture()
def cleared() -> RecordingCursor:
    cur = RecordingCursor()
    delete_snapshot_children(cur, SID)
    return cur


def test_never_deletes_the_parent_snapshots_row(cleared: RecordingCursor) -> None:
    """The whole defect in one assertion: clearing the cache must not touch the
    row every governance record hangs off."""
    assert _destructive_statements(cleared, "snapshots") == []


def test_clears_every_engine_owned_table(cleared: RecordingCursor) -> None:
    """One explicit, snapshot-scoped DELETE per engine-owned table -- no reliance
    on cascade semantics the function does not control."""
    for table in ENGINE_OWNED_TABLES:
        stmts = _destructive_statements(cleared, table)
        assert len(stmts) == 1, f"{table} should be cleared exactly once, got {stmts}"
        assert stmts[0].startswith("DELETE FROM ztpa."), stmts[0]
    assert len(cleared.calls) == len(ENGINE_OWNED_TABLES)


def test_every_delete_is_scoped_to_the_one_snapshot(cleared: RecordingCursor) -> None:
    """A missing WHERE would wipe every snapshot in the database, which is the
    other way to lose the evidence."""
    for sql, params in cleared.calls:
        assert "WHERE snapshot_id = %s" in sql, sql
        assert params == [SID], (sql, params)


def test_never_names_a_governance_table(cleared: RecordingCursor) -> None:
    """Stronger than 'does not delete from': the governance tables must not
    appear in the emitted SQL at all."""
    for table in AUDIT_TRAIL:
        assert not _mentions(cleared.sql, table), f"{table} named in the clear path"
    for table in GOVERNANCE_TABLES:
        assert not _mentions(cleared.sql, table), f"{table} named in the clear path"


def test_children_are_cleared_before_the_assets_they_reference(cleared: RecordingCursor) -> None:
    """`asset_correlations.asset_id` and `graph_nodes.asset_id` both reference
    `assets`, so `assets` has to go last for the DELETEs to stand alone."""
    order = [t for t in ENGINE_OWNED_TABLES]
    assert order[-1] == "assets"
    assert order.index("asset_correlations") < order.index("assets")
    assert order.index("graph_nodes") < order.index("assets")


def test_engine_and_governance_classifications_are_disjoint() -> None:
    assert not set(ENGINE_OWNED_TABLES) & GOVERNANCE_TABLES


def test_delete_snapshot_drops_children_then_the_row_itself() -> None:
    """The admin 'delete this snapshot' path still needs the parent gone -- that
    intent now has its own function instead of being a side effect of clearing
    the cache."""
    cur = RecordingCursor()
    delete_snapshot(cur, SID)
    last_sql, last_params = cur.calls[-1]
    assert last_sql == "DELETE FROM ztpa.snapshots WHERE snapshot_id = %s"
    assert last_params == [SID]
    assert len(cur.calls) == len(ENGINE_OWNED_TABLES) + 1


# --------------------------------------------------------------------------
# the real persist path, run twice -- the Phase 0 exit criterion
# --------------------------------------------------------------------------

@pytest.fixture(scope="module")
def eng():
    """One real engine result, reused: the same object persisted twice is the
    'Recompute with zero data change' case, which is where the old code did its
    damage (a deterministic snapshot_id means the DELETE hit the live row)."""
    return run()


def _persist_once(eng, monkeypatch: pytest.MonkeyPatch) -> RecordingCursor:
    """Persist an engine result against a fresh recording cursor.

    `_FINDING_TYPES_READY` is a module-level latch, so the second call would
    otherwise skip its two ALTERs and the two runs would not be comparable.
    Resetting it makes 'the second recompute emits exactly what the first did' a
    meaningful assertion.
    """
    monkeypatch.setattr(persist, "_FINDING_TYPES_READY", False)
    cur = RecordingCursor()
    persist.persist_engine_result(cur, eng)
    return cur


def test_recompute_twice_emits_no_destructive_governance_sql(eng, monkeypatch) -> None:
    """The exit criterion, at the layer reachable without a database: two
    consecutive persists of the same snapshot issue an identical statement
    stream, and nothing in it removes or rewrites a governance row."""
    first = _persist_once(eng, monkeypatch)
    second = _persist_once(eng, monkeypatch)

    assert [s for s, _ in first.calls] == [s for s, _ in second.calls]

    for cur in (first, second):
        for table in AUDIT_TRAIL:
            assert _destructive_statements(cur, table) == [], table
        for table in GOVERNANCE_TABLES:
            assert _destructive_statements(cur, table) == [], table


def test_persist_keeps_the_snapshots_row_and_upserts_it(eng, monkeypatch) -> None:
    """The snapshot row is updated in place, never deleted and recreated."""
    cur = _persist_once(eng, monkeypatch)
    assert _destructive_statements(cur, "snapshots") == []
    upserts = [s for s, _ in cur.calls if s.startswith("INSERT INTO ztpa.snapshots ")]
    assert len(upserts) == 1
    assert "ON CONFLICT (snapshot_id) DO UPDATE" in upserts[0]


def test_persist_only_appends_to_the_audit_log(eng, monkeypatch) -> None:
    """`audit_log` is append-only by design; persist writes the precompute event
    and must do nothing else to it."""
    cur = _persist_once(eng, monkeypatch)
    touching = [s for s, _ in cur.calls if _mentions(s, "audit_log")]
    assert touching, "persist_engine_result should record a precompute audit row"
    assert all(s.startswith("INSERT INTO ztpa.audit_log ") for s in touching), touching


def test_persist_clears_every_engine_owned_table(eng, monkeypatch) -> None:
    """Stale rows from a previous shape (a rule that vanished, a finding that
    stopped firing) still have to go -- that was the legitimate half of the old
    delete-the-parent trick."""
    cur = _persist_once(eng, monkeypatch)
    for table in ENGINE_OWNED_TABLES:
        assert _destructive_statements(cur, table), f"{table} not cleared before re-persist"


# --------------------------------------------------------------------------
# db/schema.sql -- so the FK cannot be restored to CASCADE by a schema edit
# --------------------------------------------------------------------------

_COMMENT = re.compile(r"--[^\n]*")
_CREATE_TABLE = re.compile(
    r"CREATE TABLE IF NOT EXISTS\s+(\w+)\s*\((.*?)\n\);", re.S | re.I)
_FK_TO_SNAPSHOTS = re.compile(
    r"REFERENCES\s+snapshots\s*\(\s*snapshot_id\s*\)"
    r"(?:\s+ON\s+DELETE\s+(CASCADE|SET\s+NULL|SET\s+DEFAULT|RESTRICT|NO\s+ACTION))?",
    re.I)


def _schema_text() -> str:
    """schema.sql with line comments stripped, so a CASCADE mentioned in prose
    (there are several, explaining why it is gone) cannot fail the test."""
    return _COMMENT.sub("", SCHEMA_SQL.read_text())


def _table_bodies() -> dict[str, str]:
    return {m.group(1).lower(): m.group(2) for m in _CREATE_TABLE.finditer(_schema_text())}


def _snapshot_fk_actions(body: str) -> list[str]:
    """The ON DELETE action of every FK to snapshots in a table body.
    Postgres' default when the clause is omitted is NO ACTION."""
    return [(m.group(1) or "NO ACTION").upper().replace("  ", " ") for m in _FK_TO_SNAPSHOTS.finditer(body)]


def test_schema_parses() -> None:
    """Guard the guard: if the regex stops finding tables, every assertion below
    would pass vacuously."""
    bodies = _table_bodies()
    assert len(bodies) >= 15
    assert "snapshots" in bodies and "change_requests" in bodies


def test_no_governance_table_cascades_from_snapshots() -> None:
    """The static half of the fix. A governance row's snapshot_id is a 'baseline
    evaluated against' pointer; ownership semantics there is what destroyed the
    approval trail."""
    for table, body in _table_bodies().items():
        if table not in GOVERNANCE_TABLES:
            continue
        assert "CASCADE" not in [a.replace(" ", "") for a in _snapshot_fk_actions(body)], (
            f"{table} declares ON DELETE CASCADE against snapshots")


def test_change_requests_points_at_its_baseline_without_owning_it() -> None:
    body = _table_bodies()["change_requests"]
    assert _snapshot_fk_actions(body) == ["SET NULL"]
    # SET NULL is only reachable if the column may actually hold NULL.
    line = next(ln for ln in body.splitlines() if ln.strip().startswith("snapshot_id"))
    assert "NOT NULL" not in line, line


def test_engine_owned_tables_all_exist_with_a_snapshot_id() -> None:
    bodies = _table_bodies()
    for table in ENGINE_OWNED_TABLES:
        assert table in bodies, f"{table} is cleared by db.py but absent from schema.sql"
        assert re.search(r"^\s*snapshot_id\b", bodies[table], re.M), table


def test_every_snapshot_scoped_table_is_classified() -> None:
    """A new table with a snapshot_id column has to be a deliberate decision:
    cleared on recompute, or durable. Landing in neither set is how campaign_plans
    ended up silently surviving with a plan computed against the old posture."""
    known = set(ENGINE_OWNED_TABLES) | set(GOVERNANCE_TABLES)
    for table, body in _table_bodies().items():
        if table == "snapshots" or not re.search(r"^\s*snapshot_id\b", body, re.M):
            continue
        assert table in known, (
            f"{table} has a snapshot_id column but is in neither ENGINE_OWNED_TABLES "
            f"nor GOVERNANCE_TABLES in backend/src/db.py")


# --------------------------------------------------------------------------
# schema.sql <-> db/migrations must agree (the drift the audit named)
# --------------------------------------------------------------------------

def test_asset_merges_is_in_the_schema_not_only_in_runtime_ddl() -> None:
    """persist._ensure_merges created this table at runtime and schema.sql did not
    have it at all, so a fresh install and a running install disagreed."""
    assert "asset_merges" in _table_bodies()


def test_match_key_check_admits_manual_review() -> None:
    """identity.py emits match_key='manual_review' for a human-confirmed merge;
    the shipped CHECK rejected it."""
    body = _table_bodies()["asset_correlations"]
    assert "manual_review" in body


def test_migration_0001_matches_the_schema() -> None:
    """The fresh-install DDL and the file that converges an existing database must
    describe the same end state."""
    sql = _COMMENT.sub("", MIGRATION_0001.read_text())
    assert _FK_TO_SNAPSHOTS.search(sql), "migration should restate the change_requests FK"
    assert [a.replace(" ", "") for a in _snapshot_fk_actions(sql)] == ["SETNULL"]
    assert "ALTER COLUMN snapshot_id DROP NOT NULL" in sql
    assert "manual_review" in sql
    assert "asset_merges" in sql


def test_migration_filenames_are_ordered_and_forward_only() -> None:
    """The runner refuses a file it cannot order; check the repo has none."""
    files = sorted((REPO_ROOT / "db" / "migrations").glob("*.sql"))
    assert files, "expected at least 0001_governance_fk.sql"
    versions = [f.name.split("_", 1)[0] for f in files]
    assert all(v.isdigit() for v in versions), versions
    assert len(set(versions)) == len(versions), versions
