"""Postgres (Neon) access layer — the system of record.

Everything is scoped to a snapshot_id and written via UPSERT keyed on the
engine's deterministic ids, so re-running a snapshot produces identical rows.
Table names are schema-qualified (ztpa.*) so we never depend on search_path
surviving the connection pooler.
"""

from __future__ import annotations

import contextlib
import os
import threading
from typing import Any, Iterator, Sequence

import psycopg
from psycopg.types.json import Jsonb
from psycopg.rows import dict_row

try:  # pooling is the fast path; degrade gracefully if the lib is missing
    from psycopg_pool import ConnectionPool
except Exception:  # pragma: no cover - only when psycopg_pool isn't installed
    ConnectionPool = None  # type: ignore[assignment]

from .settings import DATABASE_URL, DB_SCHEMA


def _require_url() -> str:
    if not DATABASE_URL:
        raise RuntimeError(
            "DATABASE_URL is not set. Copy .env.example to .env and fill it in."
        )
    return DATABASE_URL


# --- connection pool -------------------------------------------------------
# The DB is Neon (serverless Postgres). Establishing a fresh connection costs
# ~2s+ (TLS + Neon connection routing, more after an idle suspend), so opening
# one per request made every endpoint feel slow. A warm pool amortises that:
# connections are reused, so only the first one (or one after a Neon suspend)
# pays the setup cost. `SET search_path` runs once per connection via `configure`
# (Neon's pooled endpoint rejects it as a startup option, but a plain statement
# after connect is fine; we also schema-qualify every table name as the primary
# defense).
_POOL: "ConnectionPool | None" = None
_POOL_LOCK = threading.Lock()


def _configure_conn(conn: "psycopg.Connection") -> None:
    # SET is session-level (survives commits), so commit here to leave the
    # connection idle — the pool rejects a connection left mid-transaction.
    conn.execute(f"SET search_path TO {DB_SCHEMA}, public")
    conn.commit()


def _get_pool() -> "ConnectionPool":
    global _POOL
    if _POOL is None:
        with _POOL_LOCK:
            if _POOL is None:
                pool = ConnectionPool(
                    _require_url(),
                    min_size=int(os.getenv("DB_POOL_MIN", "1")),
                    max_size=int(os.getenv("DB_POOL_MAX", "10")),
                    kwargs={"row_factory": dict_row},
                    configure=_configure_conn,
                    check=ConnectionPool.check_connection,  # never hand out a dead Neon conn
                    max_idle=float(os.getenv("DB_POOL_MAX_IDLE", "120")),
                    max_lifetime=float(os.getenv("DB_POOL_MAX_LIFETIME", "1800")),
                    timeout=30.0,
                    name="ztpa",
                    open=False,
                )
                pool.open()
                _POOL = pool
    return _POOL


def close_pool() -> None:
    """Close the pool (used on app shutdown; harmless if never opened)."""
    global _POOL
    if _POOL is not None:
        try:
            _POOL.close()
        finally:
            _POOL = None


@contextlib.contextmanager
def get_conn() -> Iterator[psycopg.Connection]:
    """A transactional connection from the warm pool. Commits on clean exit,
    rolls back on error, returns the connection to the pool either way.

    All work inside the block runs in one transaction, so `SET search_path`
    (applied once when the connection is created) holds for the block.
    """
    if ConnectionPool is None:  # fallback: unpooled, original behavior
        conn = psycopg.connect(_require_url(), row_factory=dict_row)
        try:
            conn.execute(f"SET search_path TO {DB_SCHEMA}, public")
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()
        return
    # pool.connection() commits on clean exit, rolls back on exception, and
    # returns the connection to the pool in all cases.
    with _get_pool().connection() as conn:
        yield conn


def ping() -> bool:
    with get_conn() as conn:
        return conn.execute("SELECT 1 AS ok").fetchone()["ok"] == 1


# JSON-typed columns per table — wrapped in Jsonb so psycopg sends real jsonb.
_JSON_COLUMNS: dict[str, set[str]] = {
    "sources": {"config"},
    "resolved_objects": {"resolved"},
    "assets": {"identifiers"},
    "asset_correlations": {"evidence"},
    "canonical_rules": {"src_value", "dst_value", "ports", "nat_original", "nat_translated"},
    "graph_nodes": set(),
    "graph_edges": {"ports"},
    "findings": {"signals"},
    "change_requests": {"proposed"},
    "change_decisions": {"criteria", "delta_summary"},
    "audit_log": {"detail"},
    "ai_metrics": set(),
    "tool_settings": set(),
    "remediation_revisions": {"change", "validation"},
    "staged_changes": {"payload", "conflicts", "resolution", "push_steps"},
    "campaign_plans": {"plan"},
}


def _wrap(table: str, row: dict[str, Any]) -> dict[str, Any]:
    json_cols = _JSON_COLUMNS.get(table, set())
    out: dict[str, Any] = {}
    for k, v in row.items():
        if k in json_cols and v is not None and not isinstance(v, Jsonb):
            out[k] = Jsonb(v)
        else:
            out[k] = v
    return out


def upsert(cur: psycopg.Cursor, table: str, row: dict[str, Any], pk: Sequence[str]) -> None:
    """INSERT ... ON CONFLICT (pk) DO UPDATE. `table` is the bare name (e.g. 'findings')."""
    row = _wrap(table, row)
    cols = list(row.keys())
    placeholders = ", ".join(["%s"] * len(cols))
    non_pk = [c for c in cols if c not in pk]
    set_clause = ", ".join(f"{c}=EXCLUDED.{c}" for c in non_pk) or f"{pk[0]}={pk[0]}"
    sql = (
        f"INSERT INTO {DB_SCHEMA}.{table} ({', '.join(cols)}) "
        f"VALUES ({placeholders}) "
        f"ON CONFLICT ({', '.join(pk)}) DO UPDATE SET {set_clause}"
    )
    cur.execute(sql, [row[c] for c in cols])


def upsert_many(cur: psycopg.Cursor, table: str, rows: list[dict[str, Any]], pk: Sequence[str]) -> int:
    """Batched INSERT ... ON CONFLICT in a single statement (one round-trip).

    Collapsing per-row upserts into one multi-VALUES statement is the difference
    between ~1 and ~N network round-trips — decisive against a remote DB (Neon),
    where round-trip latency, not query cost, dominates a snapshot re-persist.

    Rows must share the same columns (true for every persist caller, which builds
    each table's rows from a fixed literal). Duplicate primary keys within the
    batch are collapsed to the last occurrence, since Postgres rejects a statement
    that would touch the same conflict row twice.
    """
    if not rows:
        return 0
    wrapped = [_wrap(table, r) for r in rows]
    cols = list(wrapped[0].keys())
    # de-dupe by pk, keeping the last (matches per-row upsert semantics)
    by_pk: dict[tuple, dict[str, Any]] = {}
    for r in wrapped:
        by_pk[tuple(r[c] for c in pk)] = r
    deduped = list(by_pk.values())

    non_pk = [c for c in cols if c not in pk]
    set_clause = ", ".join(f"{c}=EXCLUDED.{c}" for c in non_pk) or f"{pk[0]}={pk[0]}"
    one = "(" + ", ".join(["%s"] * len(cols)) + ")"
    values_sql = ", ".join([one] * len(deduped))
    sql = (
        f"INSERT INTO {DB_SCHEMA}.{table} ({', '.join(cols)}) "
        f"VALUES {values_sql} "
        f"ON CONFLICT ({', '.join(pk)}) DO UPDATE SET {set_clause}"
    )
    params = [r[c] for r in deduped for c in cols]
    cur.execute(sql, params)
    return len(deduped)


def insert(cur: psycopg.Cursor, table: str, row: dict[str, Any]) -> None:
    """Plain INSERT (e.g. append-only audit_log)."""
    row = _wrap(table, row)
    cols = list(row.keys())
    placeholders = ", ".join(["%s"] * len(cols))
    sql = f"INSERT INTO {DB_SCHEMA}.{table} ({', '.join(cols)}) VALUES ({placeholders})"
    cur.execute(sql, [row[c] for c in cols])


def fetch_all(cur: psycopg.Cursor, sql: str, params: Sequence[Any] | None = None) -> list[dict]:
    cur.execute(sql, params or [])
    return cur.fetchall()


def fetch_one(cur: psycopg.Cursor, sql: str, params: Sequence[Any] | None = None) -> dict | None:
    cur.execute(sql, params or [])
    return cur.fetchone()


# --- snapshot lifecycle ----------------------------------------------------
# Which tables a snapshot OWNS versus which merely POINT AT it. Drawing that line
# wrong is what made a recompute destroy the governance record: the previous
# implementation cleared "children" by deleting the PARENT `snapshots` row and
# letting `ON DELETE CASCADE` do the rest — which also took every
# `change_request` (and, through it, every `change_decision`) with it, on a
# recompute of *unchanged* data, because the engine is deterministic and
# re-derives the same snapshot_id.
#
# Engine-owned: fully re-derived from the sources on every run, so a row left
# over from a previous shape is a bug and must be cleared before a re-persist.
# `ranked_actions` and `campaign_plans` are AI-derived caches keyed on
# snapshot_id whose only input (findings) is being regenerated underneath them,
# so they belong here too — `campaign_plans` has no FK at all and was silently
# surviving every recompute with a plan computed against the old posture.
#
# Ordered children-before-parents so each DELETE stands on its own instead of
# leaning on cascade semantics this function does not control:
# `asset_correlations.asset_id` and `graph_nodes.asset_id` both reference
# `assets`, so `assets` is cleared last.
ENGINE_OWNED_TABLES: tuple[str, ...] = (
    "asset_correlations",
    "graph_edges",
    "graph_nodes",
    "canonical_rules",
    "findings",
    "ranked_actions",
    "resolved_objects",
    "campaign_plans",
    "assets",
)

# Governance / durable record. A recompute must NEVER clear these: they are the
# compliance artifact, and their snapshot_id (where they carry one) is a
# "baseline evaluated against" pointer, not ownership. Listed explicitly rather
# than left implied by absence, so the intent is assertable — see
# backend/tests/test_persist_snapshot.py, which fails if a table with a
# snapshot_id column is added to db/schema.sql and classified in neither set.
GOVERNANCE_TABLES: frozenset[str] = frozenset({
    "change_requests",        # the requested change + who asked and why
    "change_decisions",       # how the gate ruled (child of change_requests)
    "staged_changes",         # approved work item, may already be pushed
    "audit_log",              # append-only; persist appends to it, never clears
    "remediation_revisions",  # human comment thread on a finding
    "asset_merges",           # human-confirmed identity merges, cross-snapshot
    "ai_metrics",             # token spend / cost record
})


def delete_snapshot_children(cur: psycopg.Cursor, snapshot_id: str) -> None:
    """Clear every engine-derived row for `snapshot_id`, one explicit DELETE per
    table, leaving the `snapshots` row — and every governance row pointing at it
    — intact.

    Re-persisting is UPSERT-based, so this only exists to drop rows the new run
    no longer produces (a rule that disappeared, a finding that stopped firing).
    That is a statement about engine output, not about governance, which is why
    the parent row is not the lever: deleting it cascades far past the cache.

    Name and signature are unchanged from the cascade-based version so existing
    call sites keep working. Callers that genuinely want the snapshot GONE (the
    admin delete-snapshot endpoint) want `delete_snapshot` below.
    """
    for table in ENGINE_OWNED_TABLES:
        cur.execute(f"DELETE FROM {DB_SCHEMA}.{table} WHERE snapshot_id = %s", [snapshot_id])


def delete_snapshot(cur: psycopg.Cursor, snapshot_id: str) -> None:
    """Drop a snapshot entirely: its engine-derived rows, then the row itself.

    Safe for governance now that `change_requests.snapshot_id` is
    `ON DELETE SET NULL` (db/migrations/0001_governance_fk.sql): the request and
    its decision survive, having lost only the pointer to a baseline that no
    longer exists — which is the truth. `audit_log.snapshot_id` already behaved
    this way.
    """
    delete_snapshot_children(cur, snapshot_id)
    cur.execute(f"DELETE FROM {DB_SCHEMA}.snapshots WHERE snapshot_id = %s", [snapshot_id])


def audit(cur: psycopg.Cursor, actor: str, action: str, *, subject: str | None = None,
          snapshot_id: str | None = None, detail: dict | None = None) -> None:
    insert(cur, "audit_log", {
        "actor": actor,
        "action": action,
        "subject": subject,
        "snapshot_id": snapshot_id,
        "detail": detail or {},
    })
