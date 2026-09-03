"""Map an EngineResult into the ztpa tables (the deterministic system of record).

Every row uses a deterministic id derived from snapshot + content, so re-running
a snapshot UPSERTs to identical rows. We clear the snapshot's engine-owned
tables first (`delete_snapshot_children`) and re-insert, so a changed analysis
never leaves stale rows behind. That clear is deliberately scoped to tables the
engine derives: the `snapshots` row itself and every governance row that cites
it (change_requests, change_decisions, staged_changes, audit_log) survive a
recompute, because the audit trail must outlive the analysis it was recorded
against. AI-derived columns (findings.explanation, ranked_actions,
change_decisions) are written later by the advisory/change layers.

**NO DDL RUNS FROM THIS MODULE, AND NO `ensure_*` HELPER SURVIVES.** It used to
carry four -- `ensure_finding_types`, `_ensure_merges`,
`ensure_change_request_status`, `ensure_campaign_plans` -- each executing
ALTER/CREATE at request time behind a module-level READY latch. That made the
application's schema a function of which endpoints had happened to be hit since
the last process start: `CREATE TABLE asset_merges` lived only in
`_ensure_merges` and existed in no .sql file at all, so a fresh install and a
running install genuinely disagreed; the widened
`asset_correlations.match_key` CHECK that admits `'manual_review'` was applied by
a helper on the *merge* path, which meant persisting a snapshot whose identity
layer emitted a withheld-merge correlation succeeded or raised a CheckViolation
depending on call order. It also required the application's database role to hold
DDL privileges forever, and each latch made "did the DDL run?" un-answerable
after the fact. Every one of those definitions now lives in `db/schema.sql` and
in a numbered file under `db/migrations/`, applied and recorded exactly once by
`db/migrate.py`. If a column is missing at runtime the write fails loudly, which
is the correct answer: the deploy skipped its migration step.
"""

from __future__ import annotations

import json
import logging

import psycopg

from . import request_ctx
from .analyzers.run_all import EngineResult
from .db import audit, delete_snapshot_children, upsert, upsert_many
from .graph.build import node_db_kind
from .ids import det_id
from .models import ChangeDecision, ChangeRequest, RankedActions

# Child of the API's logger (app/main.py configures "npr.api"), so a degraded
# write comes out as one JSON line carrying the request id and the actor.
log = logging.getLogger("npr.api.persist")

_DEVICE = {"algosec": "afa-edge-fw-01", "guardicore": "guardicore-mgmt", "wiz": "wiz-cloud-connector"}


def _asset_id(sid: str, key: str) -> str:
    return det_id("asset", sid, key)


def _rule_uid(sid: str, tool: str, ref: str) -> str:
    return det_id("rule", sid, tool, ref)


def _value(val: str, kind: str) -> dict:
    return {"cidrs": [val]} if kind == "cidr" else {"identity": val}


def _ports(protocol: str, port: int | None, port_end: int | None = None) -> list[dict]:
    if protocol == "any" or port is None:
        return []
    return [{"proto": protocol, "port_start": port, "port_end": port_end if port_end is not None else port}]


# --- pure projection: an EngineResult as the rows the tables hold ----------
# `persist_engine_result` WRITES these dicts; `app.main` READS them straight
# out of the in-memory result when Postgres is unreachable, so a degraded read
# answers with the SAME shape the persisted read would have returned. One
# mapping with two consumers, deliberately: a second hand-written copy of the
# column list in the API would drift the moment a column moved, and the drift
# would only ever be visible in the degraded path -- the one nobody exercises.
#
# Every function here is pure (no cursor, no I/O) and deterministic: it emits
# rows in the engine's own order, which is already sorted upstream.

def _canon(r: EngineResult, name: str) -> str:
    """The surviving identity for `name` after the identity layer merged aliases."""
    return r.alias_map.get(name, name)


def snapshot_row(r: EngineResult) -> dict:
    """The `ztpa.snapshots` row. No `created_at`: the database defaults it, so a
    projection cannot know it (and inventing `now()` would break determinism).

    `status` used to be the constant "complete" -- for every run, including one
    whose path enumeration stopped at the scan cap. The snapshot timeline is the
    one screen that says which runs are trustworthy, so a run that analyzed a
    bounded sample of its own estate must not sit in it wearing the same word as
    a run that analyzed all of it. A `partial` run is recorded as `failed` and
    the reason goes in `notes`, because the timeline's CHECK admits only
    running/complete/failed; `db/schema.sql` wants a `partial` value and a
    `degraded_reasons` column, which is a migration outside this module's reach
    (see the remediation report). "failed" over-states in the SAFE direction --
    it makes an operator look -- while "complete" under-states in the direction
    every defect in this product's audit went.

    A `degraded` run never reaches here at all: `persist_engine_result` refuses
    it outright."""
    notes = f"{len(r.records)} canonical rules, {len(r.assets)} assets, {len(r.findings)} findings"
    if not r.complete:
        notes += " -- INCOMPLETE ANALYSIS: " + "; ".join(r.integrity_reasons())
    return {
        "snapshot_id": r.snapshot_id, "label": r.label,
        "status": "complete" if r.complete else "failed",
        "notes": notes,
    }


def source_rows(r: EngineResult) -> list[dict]:
    return [{
        "source_id": det_id("src", tool), "tool": tool,   # global connector, not per-snapshot
        "device": _DEVICE.get(tool, tool), "config": {"mode": "simulated_export"},
    } for tool in sorted({rec.source_tool for rec in r.records})]


def resolved_object_rows(r: EngineResult) -> list[dict]:
    sid = r.snapshot_id
    return [{
        "id": det_id("ro", sid, ro.source_tool, ro.source_device or "", ro.object_name, ro.object_kind),
        "snapshot_id": sid, "source_tool": ro.source_tool, "source_device": ro.source_device,
        "object_name": ro.object_name, "object_kind": ro.object_kind,
        "resolved": ro.resolved, "is_dynamic": ro.is_dynamic,
    } for ro in r.resolved]


def asset_rows(r: EngineResult) -> list[dict]:
    sid = r.snapshot_id
    return [{
        "asset_id": _asset_id(sid, a.asset_key), "snapshot_id": sid, "asset_key": a.asset_key,
        "kind": a.kind, "context": a.context, "identifiers": a.identifiers,
        "ip_set": list(a.ip_set), "tags": list(a.tags), "source_tools": list(a.source_tools),
    } for a in r.assets]


def correlation_rows(r: EngineResult) -> list[dict]:
    sid = r.snapshot_id
    return [{
        "id": det_id("corr", sid, c.asset_key, c.match_key, c.evidence),
        "snapshot_id": sid, "asset_id": _asset_id(sid, c.asset_key),
        "match_key": c.match_key, "confidence": c.confidence, "evidence": c.evidence,
    } for c in r.correlations]


def canonical_rule_rows(r: EngineResult) -> list[dict]:
    sid = r.snapshot_id
    return [{
        "rule_uid": _rule_uid(sid, rec.source_tool, rec.raw_ref), "snapshot_id": sid,
        "source_tool": rec.source_tool, "source_device": _DEVICE.get(rec.source_tool),
        "raw_rule_id": rec.raw_ref, "policy_id": None, "rule_order": rec.order, "action": rec.action,
        "src_kind": rec.source_kind, "src_value": _value(rec.source, rec.source_kind), "src_context": None,
        "dst_kind": rec.destination_kind, "dst_value": _value(rec.destination, rec.destination_kind), "dst_context": None,
        "protocol": rec.protocol, "ports": _ports(rec.protocol, rec.port, rec.port_end), "l7_app": rec.l7_app,
        "nat_original": None, "nat_translated": None, "tags": list(rec.dest_tags), "enabled": True,
        "schedule": None, "direction": None,
        "src_asset_refs": [_asset_id(sid, _canon(r, rec.source))],
        "dst_asset_refs": [_asset_id(sid, _canon(r, rec.destination))],
    } for rec in r.records]


def graph_node_rows(r: EngineResult) -> list[dict]:
    sid = r.snapshot_id
    return [{
        "node_id": node_id, "snapshot_id": sid,
        "kind": node_db_kind(node_id, data.get("kind", "concrete")),
        "label": data.get("display", node_id), "context": None,
        "asset_id": _asset_id(sid, node_id), "tags": list(data.get("tags", [])),
        "ip_set": list(data.get("ip_set", [])),
    } for node_id, data in r.graph.nodes(data=True)]


def graph_edge_rows(r: EngineResult) -> list[dict]:
    """One row per ALLOW record -- a deny is a rule, never an edge of reachability."""
    sid = r.snapshot_id
    return [{
        "edge_id": det_id("edge", sid, rec.source_tool, rec.raw_ref), "snapshot_id": sid,
        "src_node": _canon(r, rec.source), "dst_node": _canon(r, rec.destination), "action": rec.action,
        "ports": _ports(rec.protocol, rec.port, rec.port_end),
        "l7_app": rec.l7_app, "rule_uid": _rule_uid(sid, rec.source_tool, rec.raw_ref),
        "source_tool": rec.source_tool, "enforcement_point": _DEVICE.get(rec.source_tool),
    } for rec in r.records if rec.action == "allow"]


def finding_rows(r: EngineResult) -> list[dict]:
    """`explanation` is None by construction: prose is AI-derived and cached onto
    the row later, so an in-memory projection never has one."""
    sid = r.snapshot_id
    return [{
        "finding_id": f.id, "snapshot_id": sid, "type": f.type, "severity": f.severity,
        "severity_band": f.severity_band, "forced_critical": f.forced_critical,
        "signals": {**f.signals, "title": f.title}, "involved": list(f.involved),
        "raw_refs": list(f.raw_refs), "source_tools": list(f.source_tools), "explanation": None,
    } for f in r.findings]


def snapshot_counts(r: EngineResult) -> dict[str, int]:
    """`SELECT count(*)` per engine-owned table, without the database.

    Counted over the DISTINCT conflict key of each upsert rather than over the
    source list, because that is precisely what the table would hold: two
    records that collide on `rule_uid` are one row, not two, and a projection
    that said otherwise would make the degraded counts differ from the
    persisted ones for the same snapshot. (`len({...})` on the key tuples --
    a cardinality, so no iteration order escapes into the answer.)
    """
    return {
        "assets": len({row["asset_id"] for row in asset_rows(r)}),
        "canonical_rules": len({row["rule_uid"] for row in canonical_rule_rows(r)}),
        "graph_nodes": len({(row["snapshot_id"], row["node_id"]) for row in graph_node_rows(r)}),
        "graph_edges": len({(row["snapshot_id"], row["edge_id"]) for row in graph_edge_rows(r)}),
        "findings": len({row["finding_id"] for row in finding_rows(r)}),
        "resolved_objects": len({row["id"] for row in resolved_object_rows(r)}),
        "asset_correlations": len({row["id"] for row in correlation_rows(r)}),
        # AI-derived, written by the ranking layer and never by the engine, so an
        # engine projection genuinely holds none. Not "0 ranked actions exist" --
        # the caller reading this from memory is told the source in the payload.
        "ranked_actions": 0,
    }


class DegradedSnapshotError(RuntimeError):
    """A snapshot that lost an entire finding class was offered to the system of
    record. Raised, never logged-and-continued: this is the exact write the
    audit measured destroying 30 findings' worth of healthy rows with 7."""


def persist_engine_result(cur: psycopg.Cursor, r: EngineResult) -> dict:
    """Write an EngineResult to the system of record -- if it is fit to be one.

    THE GUARD IS HERE, at the lowest layer, and not only in the API. `app.main`
    already refuses to publish a degraded rebuild, but this function is also
    called by `scripts/precompute.py`, by the merge/reset routes and by anything
    written next; a rule enforced at four call sites is a rule that is missing
    from the fifth. `delete_snapshot_children` on the first line is what makes
    the stakes total rather than partial -- it CLEARS the snapshot's rows before
    re-inserting, so persisting a degraded result does not merely add a bad row,
    it deletes the good ones first.

    Truncated (`partial`) results ARE written: they are the best answer that
    exists for those inputs and refusing them would leave a large estate with no
    snapshot at all. They are written under their own id (the engine folds the
    truncation into the fingerprint), marked in `snapshot_row`, and reported by
    /api/health -- surfaced, not suppressed."""
    if r.degraded:
        raise DegradedSnapshotError(
            "refusing to persist a degraded snapshot: "
            + "; ".join(r.integrity_reasons())
            + ". The findings for the failed analyzer(s) do not exist in this result, and "
              "writing it would clear the rows of the last complete run for this snapshot id.")
    sid = r.snapshot_id
    # No `ensure_finding_types(cur)` here any more: the widened findings.type
    # CHECK is in db/schema.sql and db/migrations/0002. See the module docstring.
    delete_snapshot_children(cur, sid)   # engine-owned tables only; governance rows survive

    upsert(cur, "snapshots", snapshot_row(r), ["snapshot_id"])
    upsert_many(cur, "sources", source_rows(r), ["source_id"])
    upsert_many(cur, "resolved_objects", resolved_object_rows(r), ["id"])
    upsert_many(cur, "assets", asset_rows(r), ["asset_id"])
    upsert_many(cur, "asset_correlations", correlation_rows(r), ["id"])
    upsert_many(cur, "canonical_rules", canonical_rule_rows(r), ["rule_uid"])
    upsert_many(cur, "graph_nodes", graph_node_rows(r), ["snapshot_id", "node_id"])
    upsert_many(cur, "graph_edges", graph_edge_rows(r), ["snapshot_id", "edge_id"])
    upsert_many(cur, "findings", finding_rows(r), ["finding_id"])

    # actor_kind='system': the engine derived this, and it also runs from the
    # warm-engine thread at boot where there is no request and no actor at all.
    # The actor columns still fill in from request_ctx when a human pressed
    # Recompute, so the row says both "the system wrote it" and "she asked".
    # `complete` and `truncations` are in the audit detail because the trail is
    # where a compliance function reconstructs what was known when: "30 findings"
    # and "30 findings out of a scan that hit its cap" are different claims and
    # the row has to be able to tell them apart years later.
    audit(cur, "precompute_snapshot", actor_kind="system", subject=sid, snapshot_id=sid, detail={
        "records": len(r.records), "assets": len(r.assets), "findings": len(r.findings),
        "forced_critical": sum(1 for f in r.findings if f.forced_critical),
        "complete": r.complete, "truncations": r.truncations,
    })

    return {
        "snapshot_id": sid, "records": len(r.records), "assets": len(r.assets),
        "correlations": len(r.correlations), "resolved": len(r.resolved),
        "nodes": r.graph.number_of_nodes(), "edges": r.graph.number_of_edges(),
        "findings": len(r.findings),
        # Every caller of this returns the summary to a human or an audit row.
        # A count with no completeness flag beside it is the thing that read as
        # authoritative when it was not.
        "complete": r.complete, "truncations": r.truncations,
    }


# --- AI-derived persistence (written by the advisory/change layers) --------

def persist_ranked_actions(cur: psycopg.Cursor, sid: str, ranked: RankedActions) -> int:
    cur.execute("DELETE FROM ztpa.ranked_actions WHERE snapshot_id = %s", [sid])
    for a in ranked.actions:
        upsert(cur, "ranked_actions", {
            "action_id": a.action_id, "snapshot_id": sid, "title": a.title,
            "finding_ids": list(a.finding_ids), "priority": a.priority, "rationale": a.rationale,
        }, ["snapshot_id", "action_id"])
    audit(cur, "rank_findings", actor_kind="agent", snapshot_id=sid,
          detail={"actions": len(ranked.actions), "ranked_by": ranked.ranked_by})
    return len(ranked.actions)


def cache_explanation(cur: psycopg.Cursor, finding_id: str, text: str, by: str | None = None) -> None:
    """Persist the explanation plus the provider:model that produced it, so the
    cache can report real provenance (e.g. 'openai:gpt-4o') instead of a bare 'cache'."""
    cur.execute(
        "UPDATE ztpa.findings SET explanation = %s, explanation_by = %s WHERE finding_id = %s",
        [text, by, finding_id],
    )


# --- human-confirmed asset merges (durable across snapshots) ----------------
# `ztpa.asset_merges` and the widened `asset_correlations.match_key` CHECK are
# schema, declared in db/schema.sql and converged by db/migrations/0001. The
# `_ensure_merges` helper that used to CREATE the table here on first read is
# gone; see the module docstring for why that was load-bearing and wrong.

def load_asset_merges(cur: psycopg.Cursor) -> list[tuple[str, str]]:
    """All human-confirmed merges, applied by the identity layer on every run."""
    cur.execute("SELECT name_a, name_b FROM ztpa.asset_merges")
    return [(r["name_a"], r["name_b"]) for r in cur.fetchall()]


def persist_asset_merge(cur: psycopg.Cursor, a: str, b: str, by: str = "human") -> str:
    a, b = sorted([a, b])
    mid = det_id("merge", a, b)
    cur.execute("""INSERT INTO ztpa.asset_merges (merge_id, name_a, name_b, confirmed_by)
        VALUES (%s, %s, %s, %s) ON CONFLICT (merge_id) DO NOTHING""", [mid, a, b, by])
    return mid


def delete_asset_merge(cur: psycopg.Cursor, a: str, b: str) -> None:
    a, b = sorted([a, b])
    cur.execute("DELETE FROM ztpa.asset_merges WHERE merge_id = %s", [det_id("merge", a, b)])


# --- remediation iteration thread (Risk To-Do) -----------------------------

def remediation_thread_id(sid: str, finding_id: str) -> str:
    return det_id("rthread", sid or "", finding_id)


def load_remediation_thread(cur: psycopg.Cursor, sid: str, finding_id: str) -> list[dict]:
    tid = remediation_thread_id(sid, finding_id)
    return [dict(r) for r in cur.execute(
        "SELECT revision_id, thread_id, finding_id, seq, comment, fix_text, change, validation, by, "
        "status, created_at FROM ztpa.remediation_revisions WHERE thread_id=%s ORDER BY seq",
        [tid]).fetchall()]


def persist_remediation_revision(cur: psycopg.Cursor, sid: str, finding_id: str,
                                 draft: dict, comment: str | None = None) -> dict:
    """Append the next revision to a finding's thread and return the stored row."""
    tid = remediation_thread_id(sid, finding_id)
    row = cur.execute("SELECT COALESCE(MAX(seq), -1) AS m FROM ztpa.remediation_revisions WHERE thread_id=%s",
                      [tid]).fetchone()
    seq = int(row["m"]) + 1
    rid = det_id("rev", tid, str(seq))
    upsert(cur, "remediation_revisions", {
        "revision_id": rid, "thread_id": tid, "finding_id": finding_id, "snapshot_id": sid, "seq": seq,
        "comment": comment, "fix_text": draft.get("fix_text"), "change": draft.get("change") or {},
        "validation": draft.get("validation") or {}, "by": draft.get("by"), "status": "draft",
    }, ["revision_id"])
    audit(cur, "remediate_revision", actor_kind="agent", subject=finding_id, snapshot_id=sid,
          detail={"seq": seq, "resolves": (draft.get("validation") or {}).get("resolves")})
    return {"revision_id": rid, "thread_id": tid, "finding_id": finding_id, "seq": seq, "comment": comment,
            "fix_text": draft.get("fix_text"), "change": draft.get("change"),
            "validation": draft.get("validation"), "by": draft.get("by"), "status": "draft"}


def accept_remediation_revision(cur: psycopg.Cursor, revision_id: str) -> None:
    cur.execute("UPDATE ztpa.remediation_revisions SET status='accepted' WHERE revision_id=%s", [revision_id])


# --- staging area -----------------------------------------------------------

def persist_staged_change(cur: psycopg.Cursor, row: dict) -> str:
    """Write a staged change, stamping `created_by` from the request context.

    `staged_changes.created_by` has existed since the first schema and was NEVER
    written -- the staging queue is the list of changes about to be pushed into
    a production firewall and it could not say who put them there. Filled here
    rather than at the call site for the same reason `audit()` reads the actor
    itself: the one call site in app/main.py is behind `require_approver`, so
    there is always an identified approver, and a column that depends on a caller
    remembering to pass it is a column that ends up NULL.

    An explicit `created_by` in `row` still wins, so a future non-request writer
    (a job, a backfill) can name itself.
    """
    actor = request_ctx.current()
    row = {**row, "created_by": row.get("created_by") or actor.email or actor.sub}
    upsert(cur, "staged_changes", row, ["staged_id"])
    audit(cur, "stage_change", subject=row.get("request_id"), snapshot_id=row.get("snapshot_id"),
          detail={"target_tool": row.get("target_tool"), "kind": row.get("kind"),
                  "decision": row.get("decision")})
    return row["staged_id"]


# `change_requests.status` / `rejected_by` / `reject_reason` are schema, declared
# in db/schema.sql and converged on an existing database by db/migrations/0002.
# `ensure_change_request_status`, which ALTERed them into existence from the
# request path behind a _CHANGE_STATUS_READY latch, is deleted -- the last of the
# four. app/main.py no longer imports or calls it.

def reject_change_request(cur: psycopg.Cursor, request_id: str, by: str, reason: str | None = None) -> int:
    """Mark a request rejected. Returns the number of rows updated (0 = unknown id).

    `archived_at IS NULL` scopes it to the LIVE trail: a request retired by a
    demo reset is history, and rewriting history to say a reviewer declined
    something they never saw is the same class of lie as deleting it. The 0 rows
    become the endpoint's 404, which is the honest answer -- that request is no
    longer open.
    """
    cur.execute("UPDATE ztpa.change_requests SET status='rejected', rejected_by=%s, reject_reason=%s "
                "WHERE request_id=%s AND archived_at IS NULL", [by, reason, request_id])
    n = cur.rowcount
    if n:
        audit(cur, "reject_change", subject=request_id, detail={"by": by, "reason": reason})
    return n


def load_applied_changes(cur: psycopg.Cursor) -> list[dict]:
    """Operator-accepted changes -- staged changes that were successfully pushed.
    The engine re-applies these to the records on every run (a durable overlay,
    like asset merges), so a recompute reflects the applied state. Ordered for
    deterministic application; only 'pushed' rows count (conflicts are excluded).

    RAISES on a database error instead of returning `[]`. The empty list is a
    real answer here -- "nothing has been pushed yet" -- so returning it on
    failure made the two indistinguishable, and the distinction changes the
    ANSWER: the engine would recompute without the operator's applied changes and
    `persist_engine_result` would then write that as the authoritative snapshot,
    with the dashboard reporting the resurrected findings as current. The caller
    that cares (`app.main._load_applied`) already catches, logs
    `event=load_applied_failed` with the request id, and returns
    `(changes, loaded_ok=False)` so `_require_trustworthy_inputs` can refuse to
    persist -- machinery this `except` was silently defeating.
    """
    cur.execute("SELECT kind, payload FROM ztpa.staged_changes WHERE status='pushed' "
                "ORDER BY created_at, staged_id")
    return [dict(r) for r in cur.fetchall()]


# --- remediation campaign (persisted, one plan per snapshot) ----------------

# `ztpa.campaign_plans` is declared in db/schema.sql and created on an existing
# database by db/migrations/0001. `ensure_campaign_plans` (CREATE TABLE at
# request time, behind a _CAMPAIGN_READY latch) is gone with the rest of them.

def persist_campaign_plan(cur: psycopg.Cursor, sid: str, plan: dict) -> None:
    """Cache the campaign plan for a snapshot so navigating away and back re-reads
    it instead of paying another (LLM) planning pass. Re-planning overwrites it."""
    upsert(cur, "campaign_plans", {"snapshot_id": sid, "plan": plan}, ["snapshot_id"])


def load_campaign_plan(cur: psycopg.Cursor, sid: str) -> dict | None:
    """The cached plan for a snapshot, or None if it was never planned (or the
    snapshot changed -- a recompute yields a new id, so the plan is naturally stale)."""
    row = cur.execute("SELECT plan FROM ztpa.campaign_plans WHERE snapshot_id=%s", [sid]).fetchone()
    if not row:
        return None
    return row["plan"] if isinstance(row["plan"], dict) else None


# What `/api/admin/reset-demo` does, as TWO lists rather than one, because the
# two halves of "reset" are two different acts and only one of them may remove
# a row. Named here so the audit detail, the endpoint and the tests that pin the
# blast radius all read the same declaration.
#
# ARCHIVED: the compliance record. A reset stamps `archived_at` and the rows
# stay. Ordered children-before-parents out of habit; it does not matter for an
# UPDATE, and it will the day one of these goes back to being deleted.
RESET_ARCHIVED_TABLES: tuple[str, ...] = ("change_decisions", "change_requests")

# CLEARED: the working set and the cache. The push queue, the human comment
# thread on a finding and the cached campaign plan describe work in flight, not
# a decision that was taken -- and `staged_changes` rows with status='pushed'
# are an ENGINE INPUT (load_applied_changes), so a reset that left them would
# not be a reset: the resolved finding would not reappear on the next recompute,
# which is the entire observable point of the button.
RESET_CLEARED_TABLES: tuple[str, ...] = (
    "staged_changes", "remediation_revisions", "campaign_plans",
)

# Everything a reset touches, in the order it touches it. `audit_log` is in
# NEITHER list and must never be in either: it is the record that the reset
# happened.
RESET_TABLES: tuple[str, ...] = RESET_ARCHIVED_TABLES + RESET_CLEARED_TABLES


def reset_change_workflow(cur: psycopg.Cursor) -> dict:
    """Retire the change-governance working set so a demo can be re-run from a
    clean slate. Leaves snapshots/findings alone -- those regenerate on recompute.

    NOTHING IN THE COMPLIANCE RECORD IS DELETED. `change_requests` and
    `change_decisions` are STAMPED `archived_at = now()`; the rows stay in the
    table, countable and queryable, and every read that feeds a screen filters
    `archived_at IS NULL` so the console still resets to an empty slate. Only the
    working set and the cache -- staged_changes, remediation_revisions,
    campaign_plans -- are actually deleted.

    That distinction is the Phase 2 exit criterion, which reads (audit line 230):
    "a recompute, a dataset switch, an asset merge and a RESET each leave
    change_requests, change_decisions and audit_log intact". The first three were
    made true by db/migrations/0001 and by `delete_snapshot_children` no longer
    deleting the parent snapshot row. This one was not: the reset used to run
    `DELETE FROM change_requests` unconditionally, so on a real database the
    approval trail still went to zero -- on purpose, and documented, but "the
    screen should look empty" is not a reason a system of record gets to destroy
    evidence. `archived_at` gives the screen what it wanted without it.

    Re-submitting an archived request revives it: ids are deterministic content
    hashes, so re-running the demo writes the SAME request_id, and
    `persist_change_request_row` clears `archived_at` on the way through.

    Audited with its own row (in `audit_log`, which it does not touch either)
    carrying the per-table counts -- for the archived tables that count is how
    many rows were retired, for the cleared ones how many were removed.

    RAISES on a failed statement instead of recording a 0. The old `except: pass`
    was worse than merely quiet: these statements run inside one transaction, so
    the first failure aborts it and every later one raises
    InFailedSqlTransaction -- which the same handler swallowed. The endpoint then
    returned `{"staged_changes": 0, ...}`, i.e. "nothing needed clearing", to an
    admin whose reset had in fact done nothing at all.
    """
    counts: dict[str, int] = {}
    # `WHERE archived_at IS NULL` is not an optimisation: without it a second
    # reset would move the stamp on rows retired by the first, rewriting when
    # they were retired. A retirement date is a fact about one event.
    statements = [(t, f"UPDATE ztpa.{t} SET archived_at = now() WHERE archived_at IS NULL")
                  for t in RESET_ARCHIVED_TABLES]
    statements += [(t, f"DELETE FROM ztpa.{t}") for t in RESET_CLEARED_TABLES]
    for table, sql in statements:
        try:
            cur.execute(sql)
        except Exception as exc:
            log.error("reset of the change-governance working set failed", exc_info=True,
                      extra={"event": "reset_change_workflow_failed", "table": table,
                             "cleared_so_far": dict(counts), "error": str(exc)})
            raise
        # The count is telemetry for the audit row, not the operation. psycopg
        # sets `rowcount` after every execute, so the default is unreachable
        # against a real database; it exists so a cursor stand-in that has not
        # implemented the attribute (backend/tests/test_api_authz.py::_FakeCursor,
        # which another module owns) cannot turn a SUCCESSFUL reset into a 500.
        # The statement itself is deliberately not tolerant -- see the try above.
        counts[table] = getattr(cur, "rowcount", 0)
    return counts


# --- the two writers of the change trail -----------------------------------
# Every write to `change_requests` / `change_decisions` goes through one of these
# two functions, and they exist for one reason: `archived_at` must be cleared on
# the way in. Request and decision ids are deterministic content hashes, so
# re-submitting the same change after a reset UPSERTs the archived row -- and an
# upsert that did not name the column would leave the stamp in place, writing a
# live decision that no screen could see. A rule that has to be remembered at
# every call site is a rule that gets forgotten at one, so there is nowhere else
# to write these tables from: `test_persist_snapshot.py` fails if another module
# upserts either table directly.

def persist_change_request_row(cur: psycopg.Cursor, row: dict) -> None:
    """Upsert one `change_requests` row, live. See the note above."""
    upsert(cur, "change_requests", {**row, "archived_at": None}, ["request_id"])


def persist_change_decision_row(cur: psycopg.Cursor, row: dict) -> None:
    """Upsert one `change_decisions` row, live. See the note above."""
    upsert(cur, "change_decisions", {**row, "archived_at": None}, ["decision_id"])


def persist_change_decision(cur: psycopg.Cursor, sid: str, request: ChangeRequest,
                            decision: ChangeDecision, kind: str = "add_allow",
                            origin: str = "change_gate") -> str:
    persist_change_request_row(cur, {
        "request_id": request.id, "snapshot_id": sid,
        "proposed": json.loads(request.proposed.model_dump_json()),
        "requested_by": request.requested_by, "justification": request.justification,
        "kind": kind, "origin": origin,
    })
    decision_id = det_id("dec", sid, request.id)
    persist_change_decision_row(cur, {
        "decision_id": decision_id, "request_id": request.id, "decision": decision.decision,
        "criteria": decision.criteria, "triggering_reason": decision.triggering_reason,
        "delta_summary": decision.delta_summary, "confidence": decision.confidence,
        "forced_escalate": decision.forced_escalate, "model": decision.decided_by,
    })
    audit(cur, "classify_change", actor_kind="agent", subject=request.id, snapshot_id=sid,
          detail={"decision": decision.decision, "forced_escalate": decision.forced_escalate,
                  "decided_by": decision.decided_by})
    return decision_id
