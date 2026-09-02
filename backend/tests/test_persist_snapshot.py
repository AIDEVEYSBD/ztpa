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

Phase 2 added a real database to the picture:
`backend/tests/test_db_governance.py` runs the same properties end-to-end
against Postgres and is the stronger evidence. These tests stay because they are
the ones CI can run -- there is no database in CI, and there must never be a
reason to add one to keep the recompute path honest.

Three groups of assertion joined them here, all reachable offline:

  * **no DDL leaves this module.** Four `ensure_*` helpers used to execute
    ALTER/CREATE at request time behind module-level READY latches, so the live
    schema depended on which endpoints had been hit since the last restart.
    They are gone; `test_the_persist_path_emits_no_ddl` and
    `test_persist_module_contains_no_runtime_ddl` stop them coming back.
  * **the audit trail names someone.** `audit()` reads `request_ctx` itself, so
    the assertions are that the INSERT carries the actor columns and that their
    values follow the context rather than the call site.
  * **`upsert_many` is chunked.** The statement count and the per-statement bind
    count are asserted at the 65,535-parameter boundary, where a single-statement
    batch used to raise before reaching the server.
"""

from __future__ import annotations

import pathlib
import re
from typing import Any, Iterable

import pytest

from src import persist, request_ctx
from src.analyzers.run_all import run
from src.db import (
    ENGINE_OWNED_TABLES, GOVERNANCE_TABLES, MAX_BIND_PARAMS, audit,
    delete_snapshot, delete_snapshot_children, upsert_many,
)

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
SCHEMA_SQL = REPO_ROOT / "db" / "schema.sql"
MIGRATIONS_DIR = REPO_ROOT / "db" / "migrations"
MIGRATION_0001 = MIGRATIONS_DIR / "0001_governance_fk.sql"
MIGRATION_0002 = MIGRATIONS_DIR / "0002_audit_identity.sql"
PERSIST_PY = REPO_ROOT / "backend" / "src" / "persist.py"

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


def _persist_once(eng) -> RecordingCursor:
    """Persist an engine result against a fresh recording cursor.

    This used to have to reset `persist._FINDING_TYPES_READY` first: a
    module-level latch meant the SECOND call skipped the two ALTER TABLEs the
    first one emitted, so "the second recompute emits exactly what the first did"
    was only true after poking at a global. The latch and its DDL are gone, and
    the statement stream is now identical run to run by construction -- which is
    a stronger version of the same property, obtained by deleting code.
    """
    cur = RecordingCursor()
    persist.persist_engine_result(cur, eng)
    return cur


def test_recompute_twice_emits_no_destructive_governance_sql(eng) -> None:
    """The exit criterion, at the layer reachable without a database: two
    consecutive persists of the same snapshot issue an identical statement
    stream, and nothing in it removes or rewrites a governance row."""
    first = _persist_once(eng)
    second = _persist_once(eng)

    assert [s for s, _ in first.calls] == [s for s, _ in second.calls]

    for cur in (first, second):
        for table in AUDIT_TRAIL:
            assert _destructive_statements(cur, table) == [], table
        for table in GOVERNANCE_TABLES:
            assert _destructive_statements(cur, table) == [], table


def test_persist_keeps_the_snapshots_row_and_upserts_it(eng) -> None:
    """The snapshot row is updated in place, never deleted and recreated."""
    cur = _persist_once(eng)
    assert _destructive_statements(cur, "snapshots") == []
    upserts = [s for s, _ in cur.calls if s.startswith("INSERT INTO ztpa.snapshots ")]
    assert len(upserts) == 1
    assert "ON CONFLICT (snapshot_id) DO UPDATE" in upserts[0]


def test_persist_only_appends_to_the_audit_log(eng) -> None:
    """`audit_log` is append-only by design; persist writes the precompute event
    and must do nothing else to it."""
    cur = _persist_once(eng)
    touching = [s for s, _ in cur.calls if _mentions(s, "audit_log")]
    assert touching, "persist_engine_result should record a precompute audit row"
    assert all(s.startswith("INSERT INTO ztpa.audit_log ") for s in touching), touching


def test_persist_clears_every_engine_owned_table(eng) -> None:
    """Stale rows from a previous shape (a rule that vanished, a finding that
    stopped firing) still have to go -- that was the legitimate half of the old
    delete-the-parent trick."""
    cur = _persist_once(eng)
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


# --------------------------------------------------------------------------
# no DDL runs from application code any more
# --------------------------------------------------------------------------
# Four `ensure_*` helpers used to execute ALTER TABLE / CREATE TABLE from the
# request path, each guarded by a module-level READY latch. Two consequences the
# audit named: the live schema became a function of which endpoints had been hit
# since the last process restart (`CREATE TABLE asset_merges` existed ONLY
# inside `_ensure_merges` and in no .sql file at all), and the application's
# database role had to keep DDL privileges forever. Both directions are pinned
# below -- what the code EMITS, and what the source CONTAINS -- because a
# behavioural check alone would miss a helper reintroduced on a path this
# fixture happens not to exercise.

_DDL = re.compile(r"\b(?:ALTER\s+TABLE|CREATE\s+TABLE|DROP\s+TABLE|CREATE\s+INDEX|"
                  r"ADD\s+CONSTRAINT|DROP\s+CONSTRAINT)\b", re.I)


def test_the_persist_path_emits_no_ddl(eng) -> None:
    """The statement stream of a full persist is DML only."""
    cur = _persist_once(eng)
    offenders = [s for s, _ in cur.calls if _DDL.search(s)]
    assert offenders == [], f"persist_engine_result executed DDL: {offenders}"


def test_no_persist_entry_point_emits_ddl(eng) -> None:
    """Every other cursor-taking entry point, not just the snapshot path.

    `_ensure_merges` was reached from `load_asset_merges` -- a READ -- which is
    how the widened `asset_correlations.match_key` CHECK came to be applied by
    the merge screen and depended on by the persist path.
    """
    cur = RecordingCursor([{"m": -1, "plan": {}, "name_a": "a", "name_b": "b"}])
    persist.load_asset_merges(cur)
    persist.persist_asset_merge(cur, "a", "b")
    persist.delete_asset_merge(cur, "a", "b")
    persist.load_applied_changes(cur)
    persist.load_campaign_plan(cur, SID)
    persist.persist_campaign_plan(cur, SID, {"steps": []})
    persist.reject_change_request(cur, "req-1", "her@example.com", "no")
    persist.reset_change_workflow(cur)
    offenders = [s for s, _ in cur.calls if _DDL.search(s)]
    assert offenders == [], f"a persist entry point executed DDL: {offenders}"


def test_persist_module_contains_no_runtime_ddl() -> None:
    """Source-level guard: no DDL string literal survives in persist.py.

    Deliberately a text scan rather than a behavioural one -- a helper added
    behind a new latch would be invisible to the tests above until something
    called it, and 'invisible until called' is precisely how the schema drifted.
    """
    body = PERSIST_PY.read_text()
    code = "\n".join(ln for ln in body.splitlines() if not ln.lstrip().startswith("#"))
    # Prose in the module docstring explains the helpers by name; strip it so the
    # explanation of why they are gone cannot fail the test that keeps them gone.
    code = code.split('"""', 2)[-1]
    offenders = [ln.strip() for ln in code.splitlines() if _DDL.search(ln)]
    assert offenders == [], f"runtime DDL is back in persist.py: {offenders}"


def test_no_ready_latches_remain() -> None:
    """The four module-level flags that made 'did the DDL run?' unanswerable."""
    for flag in ("_FINDING_TYPES_READY", "_MERGES_READY", "_CHANGE_STATUS_READY", "_CAMPAIGN_READY"):
        assert not hasattr(persist, flag), f"{flag} is back in persist.py"


def test_no_ensure_helper_survives_by_name() -> None:
    """All four are gone as SYMBOLS, not merely emptied out. A surviving no-op
    would be a name for the old behaviour to come back under, and an import that
    keeps working is the thing that lets it come back unnoticed."""
    for helper in ("ensure_finding_types", "_ensure_merges",
                   "ensure_change_request_status", "ensure_campaign_plans"):
        assert not hasattr(persist, helper), f"persist.{helper} is back"


# --------------------------------------------------------------------------
# the audit trail has a WHO
# --------------------------------------------------------------------------
# `audit()` took a literal actor string and all fifteen call sites passed the
# same one, so `audit_log` recorded actor='user' for everything and could not
# answer "who". The identity is now read from request_ctx INSIDE audit(), which
# is the only design where a call site cannot forget it.

_AUDIT_IDENTITY_COLUMNS = ("actor_email", "actor_sub", "actor_role")


def _audit_row(cur: RecordingCursor) -> dict[str, Any]:
    """The one audit INSERT in a statement stream, as {column: bound value}."""
    inserts = [(s, p) for s, p in cur.calls if s.startswith("INSERT INTO ztpa.audit_log ")]
    assert len(inserts) == 1, f"expected exactly one audit insert, got {len(inserts)}"
    sql, params = inserts[0]
    cols = sql.split("(", 1)[1].split(")", 1)[0].replace(" ", "").split(",")
    assert len(cols) == len(params), (cols, params)
    return dict(zip(cols, params))


@pytest.fixture()
def as_analyst() -> Iterable[None]:
    """An identified actor in the request context, as _ActorMiddleware would set."""
    request_ctx.set_actor("analyst", "dana@example.com", "autox-sub-42")
    try:
        yield
    finally:
        request_ctx.set_actor(None, None, None)


def test_audit_writes_the_actor_columns_from_the_request_context(as_analyst) -> None:
    cur = RecordingCursor()
    audit(cur, "delete_snapshot", subject=SID)
    row = _audit_row(cur)
    assert row["actor_email"] == "dana@example.com"
    assert row["actor_sub"] == "autox-sub-42"
    assert row["actor_role"] == "analyst"
    assert row["actor"] == "user"          # someone is identified -> a human acted


def test_audit_never_invents_an_actor_when_nobody_is_identified() -> None:
    """request_ctx defaults to Actor(role='viewer') for a CLI script or the
    warm-engine thread. Writing 'viewer' into the trail would be inventing a
    subject, which is the failure this column exists to end."""
    request_ctx.set_actor(None, None, None)
    cur = RecordingCursor()
    audit(cur, "precompute_snapshot", subject=SID)
    row = _audit_row(cur)
    assert row["actor_email"] is None and row["actor_sub"] is None
    assert row["actor_role"] is None
    assert row["actor"] == "system"        # nobody asked -> a background write


def test_audit_records_agent_work_against_the_human_who_asked_for_it(as_analyst) -> None:
    """actor_kind='agent' is a fact about the WORK (a model produced it), not
    about the actor -- so both are recorded, not one instead of the other."""
    cur = RecordingCursor()
    audit(cur, "rank_findings", actor_kind="agent", snapshot_id=SID)
    row = _audit_row(cur)
    assert row["actor"] == "agent"
    assert row["actor_email"] == "dana@example.com"


def test_audit_still_accepts_the_legacy_positional_actor(as_analyst) -> None:
    """app/main.py's fourteen call sites still pass a literal actor kind. They
    must keep working AND must still get the identity columns -- an audit trail
    that stops recording during a migration is worse than one recording the old
    shape for a commit."""
    cur = RecordingCursor()
    audit(cur, "user", "recompute_snapshot", subject=SID)
    row = _audit_row(cur)
    assert row["action"] == "recompute_snapshot"
    assert row["actor"] == "user"
    assert row["actor_email"] == "dana@example.com"


def test_audit_rejects_a_first_positional_that_is_not_an_actor_kind() -> None:
    """The legacy leg must not turn a typo into a silently mis-recorded action."""
    cur = RecordingCursor()
    with pytest.raises(TypeError):
        audit(cur, "recompute_snapshot", "delete_snapshot")


def test_every_persist_audit_call_carries_the_identity_columns(eng) -> None:
    """The property the exit criterion actually names, asserted over the audit
    write persist.py makes rather than over one hand-built call."""
    cur = _persist_once(eng)
    row = _audit_row(cur)
    for column in _AUDIT_IDENTITY_COLUMNS:
        assert column in row, f"{column} missing from the audit INSERT"


def test_staged_changes_records_who_approved_it(as_analyst) -> None:
    """`created_by` was declared in the first schema and written by nothing, on
    the table listing the changes about to be pushed into a production firewall."""
    cur = RecordingCursor()
    persist.persist_staged_change(cur, {"staged_id": "stg-1", "request_id": "req-1",
                                        "status": "staged"})
    insert = next(s for s, _ in cur.calls if s.startswith("INSERT INTO ztpa.staged_changes "))
    cols = insert.split("(", 1)[1].split(")", 1)[0].replace(" ", "").split(",")
    params = next(p for s, p in cur.calls if s.startswith("INSERT INTO ztpa.staged_changes "))
    assert dict(zip(cols, params))["created_by"] == "dana@example.com"


# --------------------------------------------------------------------------
# upsert_many stays under Postgres's bind-parameter cap
# --------------------------------------------------------------------------
# One multi-VALUES statement over the whole table meant a snapshot wider than
# 65,535 binds never reached the server: 2,621 canonical rules (25 columns) or
# 5,957 findings (11 columns) and the persist raised, rolled back, and left the
# snapshot live-only. That is inside the range this product is sold on.

def _batch(n_rows: int, n_cols: int) -> list[dict[str, Any]]:
    return [{f"c{c}": f"r{r}-{c}" for c in range(n_cols)} for r in range(n_rows)]


@pytest.mark.parametrize("n_cols", [1, 11, 25])
def test_upsert_many_never_exceeds_the_bind_parameter_cap(n_cols: int) -> None:
    """The property, at three real column counts (findings has 11, canonical
    rules 25). `_JSON_COLUMNS` has no entry for this table name, so the values
    pass through unwrapped and the bind count is exactly rows x columns."""
    rows_per_stmt = MAX_BIND_PARAMS // n_cols
    cur = RecordingCursor()
    written = upsert_many(cur, "not_a_real_table", _batch(rows_per_stmt * 2 + 1, n_cols), ["c0"])
    assert written == rows_per_stmt * 2 + 1
    assert len(cur.calls) == 3, "should be three statements, not one oversized one"
    for sql, params in cur.calls:
        assert len(params) <= MAX_BIND_PARAMS, f"{len(params)} binds in one statement"
        assert sql.startswith("INSERT INTO ztpa.not_a_real_table ")
        assert "ON CONFLICT (c0) DO UPDATE" in sql


def test_upsert_many_one_statement_below_the_boundary() -> None:
    """The batching win is kept: a snapshot that fits is still one round-trip."""
    cur = RecordingCursor()
    upsert_many(cur, "not_a_real_table", _batch(MAX_BIND_PARAMS // 11, 11), ["c0"])
    assert len(cur.calls) == 1


def test_upsert_many_dedupes_before_chunking() -> None:
    """De-duping first is what keeps ON CONFLICT safe ACROSS chunks: a primary
    key lands in exactly one chunk, so no two statements can touch one row.
    (Postgres rejects a statement that hits the same conflict row twice; two
    statements would instead silently apply first-then-second.)"""
    rows = _batch(4, 11)
    rows[3]["c0"] = rows[0]["c0"]                     # a duplicate pk, last wins
    cur = RecordingCursor()
    assert upsert_many(cur, "not_a_real_table", rows, ["c0"]) == 3
    assert len(cur.calls) == 1
    assert cur.calls[0][1][0:11] == [rows[3][f"c{c}"] for c in range(11)]


def test_upsert_many_of_nothing_issues_nothing() -> None:
    cur = RecordingCursor()
    assert upsert_many(cur, "not_a_real_table", [], ["c0"]) == 0
    assert cur.calls == []


# --------------------------------------------------------------------------
# db/schema.sql <-> db/migrations, for the Phase 2 columns
# --------------------------------------------------------------------------

def test_audit_log_declares_the_actor_identity_columns() -> None:
    body = _table_bodies()["audit_log"]
    for column in _AUDIT_IDENTITY_COLUMNS:
        assert re.search(rf"^\s*{column}\b", body, re.M), f"{column} missing from schema.sql"


def test_audit_log_snapshot_id_is_a_plain_column() -> None:
    """A FK with ON DELETE SET NULL meant deleting a snapshot ERASED the one
    field tying each audit row to the posture it was recorded against."""
    body = _table_bodies()["audit_log"]
    assert _snapshot_fk_actions(body) == [], "audit_log.snapshot_id still references snapshots"
    line = next(ln for ln in body.splitlines() if ln.strip().startswith("snapshot_id"))
    assert "REFERENCES" not in line.upper(), line


def test_migration_0002_carries_every_phase_2_schema_change() -> None:
    """schema.sql only ever ADDs (every statement is IF NOT EXISTS), so an
    EXISTING database converges only through the numbered files. Each item here
    is one thing that was previously applied by runtime DDL or not at all."""
    sql = _COMMENT.sub("", MIGRATION_0002.read_text())
    for column in _AUDIT_IDENTITY_COLUMNS:
        assert column in sql, f"{column} is in schema.sql but no migration adds it"
    assert "DROP CONSTRAINT IF EXISTS audit_log_snapshot_id_fkey" in sql
    assert "findings_type_check" in sql                    # was ensure_finding_types
    assert "rejected_by" in sql and "reject_reason" in sql  # was ensure_change_request_status
    assert "idx_audit_ts" in sql                           # GET /api/audit, newest first
    assert "staged_changes ADD COLUMN IF NOT EXISTS created_by" in sql


def test_every_runtime_ddl_definition_now_lives_in_a_migration() -> None:
    """The four deleted helpers, checked against the migrations as a whole: a
    fresh install reads schema.sql, an existing one reads these, and both must
    end up with the same schema."""
    raw = "\n".join(_COMMENT.sub("", f.read_text()) for f in sorted(MIGRATIONS_DIR.glob("*.sql")))
    sql = re.sub(r"\s+", " ", raw)   # column definitions are space-aligned in the files
    assert "asset_merges" in sql                  # was persist._ensure_merges
    assert "manual_review" in sql                 # was persist._ensure_merges
    assert "campaign_plans" in sql                # was persist.ensure_campaign_plans
    assert "transport_exposure" in sql            # was persist.ensure_finding_types
    assert "status text NOT NULL DEFAULT 'open'" in sql   # was ensure_change_request_status


# --------------------------------------------------------------------------
# the admin delete route calls the half of the split that deletes the snapshot
# --------------------------------------------------------------------------
# `delete_snapshot_children` and `delete_snapshot` were one function until Phase
# 2 split them, and `DELETE /api/snapshots/{id}` kept calling the children-only
# half -- under a comment that said "deletes the snapshot row; children cascade",
# which had been true of the old implementation and was not true of the new one.
# The route answered `200 {"ok": true, "deleted": ...}` with the row still in
# `ztpa.snapshots`, its findings and assets gone: the timeline kept listing a
# snapshot that now read 0 findings, and an admin was told a thing had happened
# that had not. The real-database proof that the helper deletes the row is
# `test_db_governance.py::test_deleting_a_snapshot_actually_deletes_the_snapshot`;
# this is the offline proof that the ROUTE reaches it, which is the half that was
# wrong.


class _CursorCtx:
    """`conn.cursor()` is used as a context manager by every route; psycopg's is,
    and RecordingCursor deliberately implements only what persist.py touches."""

    def __init__(self, cur: RecordingCursor) -> None:
        self._cur = cur

    def __enter__(self) -> RecordingCursor:
        return self._cur

    def __exit__(self, *_exc: object) -> bool:
        return False


class _RecordingConn:
    """The two-line surface `with get_conn() as conn, conn.cursor() as cur` needs."""

    def __init__(self, cur: RecordingCursor) -> None:
        self._cur = cur

    def __enter__(self) -> "_RecordingConn":
        return self

    def __exit__(self, *_exc: object) -> bool:
        return False

    def cursor(self) -> _CursorCtx:
        return _CursorCtx(self._cur)


def test_the_admin_delete_route_deletes_the_snapshot_row(monkeypatch: pytest.MonkeyPatch) -> None:
    from app import main

    cur = RecordingCursor()
    # `sid()` would build (and try to persist) the engine; the route only needs
    # it to refuse deleting the ACTIVE snapshot, so a literal is the whole
    # dependency and keeps the statement stream to the route's own work.
    monkeypatch.setattr(main, "sid", lambda: "snap-active")
    monkeypatch.setattr(main, "get_conn", lambda: _RecordingConn(cur))

    body = main.delete_snapshot("snap-old")

    assert body == {"ok": True, "deleted": "snap-old"}
    assert _destructive_statements(cur, "snapshots") == [
        "DELETE FROM ztpa.snapshots WHERE snapshot_id = %s"], (
        "the route did not delete the snapshot row it reports as deleted: "
        f"{[s for s, _ in cur.calls]}")
    for table in ENGINE_OWNED_TABLES:                 # ...and its children went too
        assert len(_destructive_statements(cur, table)) == 1, table
    for table in AUDIT_TRAIL:                         # ...and nothing governance was rewritten
        if table == "audit_log":
            continue                                  # the route APPENDS one row: that is the point
        assert _destructive_statements(cur, table) == [], table
    assert any("INSERT INTO ztpa.audit_log" in s for s, _ in cur.calls), "the deletion was not audited"


def test_the_route_that_clears_a_cache_is_not_the_route_that_deletes(
        monkeypatch: pytest.MonkeyPatch) -> None:
    """The mirror image, so the fix cannot be "make delete_snapshot_children
    delete the parent again" -- which would restore the original blocker.
    Clearing the cache and removing the snapshot stay two different acts."""
    cur = RecordingCursor()
    delete_snapshot_children(cur, SID)
    assert _destructive_statements(cur, "snapshots") == []


# --------------------------------------------------------------------------
# every write to the change trail goes through the two persist helpers
# --------------------------------------------------------------------------
# `archived_at` is cleared on the way in by `persist_change_request_row` /
# `persist_change_decision_row`, because a demo reset RETIRES rows rather than
# deleting them (db/migrations/0003) and request ids are deterministic content
# hashes -- so re-running the demo upserts the row a reset just retired. An
# upsert that does not name the column leaves the stamp in place and writes a
# live decision that every screen filters out: present in the table, invisible
# on the board, and reported as persisted. A rule that has to be remembered at
# each call site is a rule that gets forgotten at one, so the test is that there
# are no other call sites.

_APP_SOURCES = sorted((REPO_ROOT / "backend" / "src").rglob("*.py")) + \
    sorted((REPO_ROOT / "backend" / "app").rglob("*.py"))

_DIRECT_TRAIL_WRITE = re.compile(
    r"""upsert(?:_many)?\(\s*[^,]+,\s*["'](?:change_requests|change_decisions)["']""")


def test_only_the_two_persist_helpers_write_the_change_trail() -> None:
    offenders = {
        path.relative_to(REPO_ROOT).as_posix(): _DIRECT_TRAIL_WRITE.findall(path.read_text())
        for path in _APP_SOURCES
        if path != PERSIST_PY and _DIRECT_TRAIL_WRITE.search(path.read_text())
    }
    assert offenders == {}, (
        "these upsert change_requests/change_decisions directly and so cannot clear "
        f"archived_at -- call persist_change_request_row / persist_change_decision_row: {offenders}")

    # ...and inside persist.py there are exactly two, one per helper.
    assert len(_DIRECT_TRAIL_WRITE.findall(PERSIST_PY.read_text())) == 2


def test_the_change_trail_writers_clear_the_retirement_stamp() -> None:
    """Behavioural half: the emitted INSERT names `archived_at` and binds NULL,
    so the ON CONFLICT UPDATE revives a retired row instead of leaving it hidden."""
    for helper, table, row in (
            (persist.persist_change_request_row, "change_requests",
             {"request_id": "req-1", "proposed": {}}),
            (persist.persist_change_decision_row, "change_decisions",
             {"decision_id": "dec-1", "request_id": "req-1", "decision": "escalate"})):
        cur = RecordingCursor()
        helper(cur, row)
        sql, params = cur.calls[-1]
        assert f"INSERT INTO ztpa.{table}" in sql, sql
        assert "archived_at" in sql, f"{table} write does not name archived_at: {sql}"
        assert "archived_at=EXCLUDED.archived_at" in sql, (
            f"{table} write does not clear archived_at on conflict: {sql}")
        assert None in params, params

    # A caller cannot smuggle a stamp in: the helper's own value wins.
    cur = RecordingCursor()
    persist.persist_change_request_row(cur, {"request_id": "req-1", "archived_at": "2020-01-01"})
    assert cur.calls[-1][1] == ["req-1", None], cur.calls[-1][1]


def test_the_reset_retires_the_record_and_deletes_only_the_working_set() -> None:
    """The reset's statement stream, offline: an UPDATE that stamps the two
    governance tables and a DELETE for each working-set table -- and no DELETE
    against `change_requests` / `change_decisions` anywhere in it.

    The table lists are written out rather than read from `persist`, so widening
    the reset's blast radius fails here instead of silently widening the test
    with it -- the exact defect that let an earlier version of this suite pass
    with `audit_log` added to the reset."""
    cur = RecordingCursor()
    counts = persist.reset_change_workflow(cur)

    assert [s for s, _ in cur.calls] == [
        "UPDATE ztpa.change_decisions SET archived_at = now() WHERE archived_at IS NULL",
        "UPDATE ztpa.change_requests SET archived_at = now() WHERE archived_at IS NULL",
        "DELETE FROM ztpa.staged_changes",
        "DELETE FROM ztpa.remediation_revisions",
        "DELETE FROM ztpa.campaign_plans",
    ]
    assert set(counts) == {"change_decisions", "change_requests", "staged_changes",
                           "remediation_revisions", "campaign_plans"}
    for table in ("change_requests", "change_decisions", "audit_log", "asset_merges", "snapshots"):
        assert not re.search(rf"DELETE\s+FROM\s+ztpa\.{table}\b", cur.sql), \
            f"a reset must not delete from {table}"


# --------------------------------------------------------------------------
# the real-database suite skips when there is no database and FAILS when there
# was supposed to be one
# --------------------------------------------------------------------------
# `test_db_governance.py` is the only file that executes against real rows, and
# it skips without `NPR_TEST_DATABASE_URL`, which is what keeps CI green with no
# database. The failure mode that hides behind that skip is a CI job (or a
# developer) that SETS the variable wrongly: a typo in the password, a container
# that did not come up. Skipping there exits 0, and 0 is the number a pipeline
# reads -- so a run that was asked for a database, did not get one, and proved
# nothing would report success. The decision lives in `tests/dbharness.py` so it
# can be tested here, offline, where there is no database either.

def test_no_database_url_skips() -> None:
    from tests.dbharness import SKIP, collection_decision

    decision, reason = collection_decision("", None)
    assert decision == SKIP
    assert "NPR_TEST_DATABASE_URL is not set" in reason
    assert collection_decision("   ", None)[0] == SKIP        # whitespace is unset
    # The probe result is ignored with no URL: nothing was probed.
    assert collection_decision("", "OperationalError: boom")[0] == SKIP


def test_a_reachable_database_runs() -> None:
    from tests.dbharness import RUN, collection_decision

    assert collection_decision("postgresql://npr@localhost/npr", None)[0] == RUN


def test_a_database_that_was_asked_for_and_is_unreachable_fails() -> None:
    from tests.dbharness import FAIL, collection_decision

    decision, reason = collection_decision("postgresql://npr@localhost/npr",
                                           "OperationalError: connection refused")
    assert decision == FAIL
    assert "connection refused" in reason, "the reason must say what actually went wrong"
    assert "must not exit 0" in reason


def test_the_governance_suite_really_fails_on_an_unreachable_database(
        monkeypatch: pytest.MonkeyPatch) -> None:
    """End to end, in-process: importing the module with the variable pointed at
    a dead address raises rather than arranging 32 skips. Port 1 refuses
    immediately, so this costs a syscall, not the probe's 2-second timeout.

    `monkeypatch.delitem` restores the already-collected module afterwards, and a
    failed import removes its own half-built entry from sys.modules."""
    import importlib
    import sys

    monkeypatch.setenv("NPR_TEST_DATABASE_URL", "postgresql://nobody:nope@127.0.0.1:1/none")
    monkeypatch.delitem(sys.modules, "tests.test_db_governance", raising=False)

    with pytest.raises(RuntimeError, match="unreachable"):
        importlib.import_module("tests.test_db_governance")
