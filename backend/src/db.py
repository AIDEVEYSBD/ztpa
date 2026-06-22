"""Postgres (Neon) access layer — the system of record.

Everything is scoped to a snapshot_id and written via UPSERT keyed on the
engine's deterministic ids, so re-running a snapshot produces identical rows.
Table names are schema-qualified (ztpa.*) so we never depend on search_path
surviving the connection pooler.
"""

from __future__ import annotations

import contextlib
from typing import Any, Iterator, Sequence

import psycopg
from psycopg.types.json import Jsonb
from psycopg.rows import dict_row

from .settings import DATABASE_URL, DB_SCHEMA


def _require_url() -> str:
    if not DATABASE_URL:
        raise RuntimeError(
            "DATABASE_URL is not set. Copy .env.example to .env and fill it in."
        )
    return DATABASE_URL


@contextlib.contextmanager
def get_conn() -> Iterator[psycopg.Connection]:
    """A transactional connection. Commits on clean exit, rolls back on error.

    All work inside the block runs in one transaction (one pooled backend), so
    `SET search_path` persists for the block as a belt-and-suspenders default.
    """
    # NB: Neon's pooled endpoint rejects `search_path` as a startup option, so we
    # set it as the first statement of the transaction instead (and additionally
    # schema-qualify every table name in upsert/insert as the primary defense).
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
    for r in rows:
        upsert(cur, table, r, pk)
    return len(rows)


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


def delete_snapshot_children(cur: psycopg.Cursor, snapshot_id: str) -> None:
    """ON DELETE CASCADE from snapshots clears all child rows; deleting the
    snapshot row and re-inserting guarantees no stale rows from a prior shape."""
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
