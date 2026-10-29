"""Postgres (Neon) access layer — the system of record.

Everything is scoped to a snapshot_id and written via UPSERT keyed on the
engine's deterministic ids, so re-running a snapshot produces identical rows.
Table names are schema-qualified (ztpa.*) so we never depend on search_path
surviving the connection pooler.

Two Phase 2 changes live here.

**`audit()` reads the actor itself.** It used to take a literal actor string and
every call site passed the same one, so `audit_log` recorded `actor='user'` for
all fifteen and could not answer "who". The identity now comes from
`request_ctx.current()` inside `audit()`, into `actor_email` / `actor_sub` /
`actor_role` — a call site cannot forget an argument it does not have.

**`upsert_many` is chunked.** It built one multi-VALUES statement over the whole
table, so a snapshot wider than Postgres's 65,535 bind parameters (2,621
canonical rules, 5,957 findings) failed to persist — inside the range this
product is sold on. See `MAX_BIND_PARAMS`.
"""

from __future__ import annotations

import contextlib
import logging
import os
import threading
from typing import Any, Iterator, Sequence

import psycopg
from psycopg.types.json import Jsonb
from psycopg.rows import dict_row

from . import request_ctx
from .settings import DATABASE_URL, DB_SCHEMA

# A child of the API's logger, exactly like src/analyzers/run_all.py: app/main.py
# configures "npr.api" with the JSON formatter, so a line emitted here comes out
# as one structured record with the request id and actor already attached. Run
# outside the API (tasks.py, db/migrate.py, a script) it falls through to the
# root handler and still prints.
log = logging.getLogger("npr.api.db")

try:  # pooling is the fast path; degrade gracefully if the lib is missing
    from psycopg_pool import ConnectionPool
except Exception as _pool_import_error:  # pragma: no cover - only when psycopg_pool isn't installed
    ConnectionPool = None  # type: ignore[assignment]
    # NOT silent any more. Without the pool every request pays a fresh Neon
    # connect (~2s+ of TLS + connection routing), which reads to a user as "the
    # product is slow" and to an operator as nothing at all -- there was no line
    # anywhere saying the fast path had been disabled. Logged at import because
    # this is a once-per-process configuration fact, not a per-request event;
    # app/main.py has not attached its handler yet at this point, so the line
    # goes out through logging's lastResort handler (stderr) instead of as JSON,
    # which is still infinitely better than the silence it replaces.
    log.warning("psycopg_pool is unavailable; falling back to one unpooled connection per request",
                extra={"event": "db_pool_unavailable", "error": str(_pool_import_error)})


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


# Postgres's wire protocol carries the parameter count as an int16, so a single
# extended-query statement may bind at most 65535 parameters. `upsert_many` used
# to build ONE multi-VALUES statement over the whole table, so the cap was a hard
# ceiling on snapshot size: canonical_rules has 25 columns (65535 // 25 = 2,621
# rows) and findings has 11 (5,957 rows). One row past that and psycopg raised
# before a single byte reached the server -- the persist aborted, the transaction
# rolled back, and the snapshot silently stayed live-only. That is inside the
# range the product is *sold* on ("a real 5,000-rule AlgoSec export"), so it was
# not a theoretical limit.
MAX_BIND_PARAMS = 65535


def _chunk_rows(rows: list[dict[str, Any]], n_cols: int) -> Iterator[list[dict[str, Any]]]:
    """Slice `rows` so no emitted statement can exceed MAX_BIND_PARAMS binds.

    `max(1, ...)` twice on purpose: a zero-column row would divide by zero, and a
    table with more than 65,535 columns cannot exist in Postgres, but a chunk
    size of 0 would loop forever rather than fail. One row per statement is the
    correct degenerate answer.
    """
    size = max(1, MAX_BIND_PARAMS // max(1, n_cols))
    for start in range(0, len(rows), size):
        yield rows[start:start + size]


def upsert_many(cur: psycopg.Cursor, table: str, rows: list[dict[str, Any]], pk: Sequence[str]) -> int:
    """Batched INSERT ... ON CONFLICT, chunked to stay under the bind-parameter cap.

    Collapsing per-row upserts into multi-VALUES statements is the difference
    between ~1 and ~N network round-trips — decisive against a remote DB (Neon),
    where round-trip latency, not query cost, dominates a snapshot re-persist.
    Chunking keeps that win (a 5,000-rule snapshot is 2 statements, not 5,000)
    while removing the ceiling: the batch is now bounded by the protocol rather
    than bounded by luck.

    Rows must share the same columns (true for every persist caller, which builds
    each table's rows from a fixed literal). Duplicate primary keys within the
    batch are collapsed to the last occurrence, since Postgres rejects a statement
    that would touch the same conflict row twice — and de-duping BEFORE chunking
    is what keeps that guarantee across chunk boundaries: a pk appears in exactly
    one chunk, so no two statements can conflict on the same row either.

    Returns the number of distinct rows written (not the number of statements).
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
    head = f"INSERT INTO {DB_SCHEMA}.{table} ({', '.join(cols)}) VALUES "
    tail = f" ON CONFLICT ({', '.join(pk)}) DO UPDATE SET {set_clause}"
    for chunk in _chunk_rows(deduped, len(cols)):
        cur.execute(head + ", ".join([one] * len(chunk)) + tail,
                    [r[c] for r in chunk for c in cols])
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
    # The infrastructure layer (0007). Engine-owned like the graph tables: each
    # is a derived view of ONE ingest, rebuilt in full on every recompute, so a
    # stale row is a wrong answer rather than a lost record. The gap/evidence
    # register is deliberately NOT here -- it must survive a recompute, and it
    # carries a nullable snapshot_id for that reason.
    #
    # Ordered BEFORE `assets`, which stays last: it is the table the others
    # reference, so deleting it first would orphan or block every child. The
    # test asserting `order[-1] == "assets"` exists because that ordering is
    # easy to break by appending to the end of this tuple, which is the natural
    # thing to do.
    "devices",
    "device_interfaces",
    "topology_links",
    "vlans",
    "subnets",
    "circuits",
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


# --- the audit trail -------------------------------------------------------
# `actor` is a KIND, not an identity: it separates "a human asked for this" from
# "the model did it" from "a background job did it", and it is the column the
# CHECK constraint pins. It was also the ONLY thing recorded about who acted --
# and every one of the fifteen call sites passed the same literal, so the table
# said `actor='user'` for every row and answered "who deleted the snapshot?" with
# "a user". That is an event log; an audit trail has to name someone.
_ACTOR_KINDS: tuple[str, ...] = ("agent", "user", "system")


def _actor_identity() -> dict[str, str | None]:
    """The acting identity, read from the request context rather than passed in.

    Reading it HERE is the whole design: a call site cannot forget an argument it
    does not have, and cannot pass the wrong one. `request_ctx` is populated by
    `_ActorMiddleware` from the proxy-injected `x-npr-*` headers, which are only
    believed behind the shared-secret boundary (see src/request_ctx.py).

    When nothing identified the caller (a CLI script, the warm-engine thread, a
    dev instance with no proxy in front of it) the three columns stay NULL. The
    role in that case is `request_ctx`'s least-privilege DEFAULT, not a claim
    anyone made, and writing 'viewer' into an audit row would be inventing a
    subject -- exactly the failure mode this column exists to end.
    """
    actor = request_ctx.current()
    if not (actor.email or actor.sub):
        return {"actor_email": None, "actor_sub": None, "actor_role": None}
    return {"actor_email": actor.email, "actor_sub": actor.sub,
            # A job acting for someone claims no role (request_ctx.acting_as).
            "actor_role": None if request_ctx.on_behalf() else actor.role}


def audit(cur: psycopg.Cursor, action: str, *_legacy: str, subject: str | None = None,
          snapshot_id: str | None = None, detail: dict | None = None,
          actor_kind: str | None = None) -> None:
    """Append one row to the append-only audit trail.

        audit(cur, "recompute_snapshot", subject=snap, snapshot_id=snap, detail=summary)

    `actor_email` / `actor_sub` / `actor_role` are filled from `request_ctx`
    inside this function; callers neither pass nor can suppress them.

    `actor_kind` defaults to `'user'` when someone is identified and `'system'`
    otherwise, and is passed explicitly ONLY to say "a model did this, on a
    human's behalf" (`actor_kind='agent'`) -- which is a fact about the work, not
    about the actor, and so is not derivable from the request context.

    The legacy positional form `audit(cur, 'user', 'recompute_snapshot', ...)` is
    still accepted, with the literal supplying the kind. No call site in the repo
    uses it any more; it is kept because this signature change and the fifteen
    call sites landed as separate edits to separate modules, and an audit trail
    that stops recording -- or worse, raises on every mutating request -- because
    one of them was reverted or half-merged is a far more expensive failure than
    an extra branch. It is not a second way to write a row: the identity columns
    are filled identically on both legs, and a first positional that is neither a
    known actor kind nor followed by an action is a TypeError rather than a
    quietly mis-recorded event.
    """
    if _legacy:
        if len(_legacy) > 1:
            raise TypeError(f"audit() takes at most 2 positional arguments, got {2 + len(_legacy)}")
        legacy_kind, action = action, _legacy[0]
        if legacy_kind not in _ACTOR_KINDS:
            raise TypeError(
                f"audit(): first positional argument {legacy_kind!r} is neither an action "
                f"(one positional) nor an actor kind (legacy two-positional form, one of "
                f"{_ACTOR_KINDS})")
        actor_kind = actor_kind or legacy_kind

    identity = _actor_identity()
    if actor_kind is None:
        actor_kind = ("agent" if request_ctx.on_behalf() else
                      "user" if identity["actor_email"] or identity["actor_sub"] else "system")
    if actor_kind not in _ACTOR_KINDS:
        # The CHECK constraint would reject this anyway, several frames later and
        # with a message about a constraint name; failing here names the caller.
        raise ValueError(f"audit(): actor_kind must be one of {_ACTOR_KINDS}, got {actor_kind!r}")

    insert(cur, "audit_log", {
        "actor": actor_kind,
        "action": action,
        "subject": subject,
        # A plain text column since db/migrations/0002: it was a FK with
        # ON DELETE SET NULL, so deleting a snapshot erased the one thing that
        # tied an audit row to the posture it was recorded against. The id is a
        # deterministic content hash -- it stays meaningful (and re-derivable)
        # long after the row it named is gone.
        "snapshot_id": snapshot_id,
        "detail": detail or {},
        **identity,
    })
