"""Map an EngineResult into the ztpa tables (the deterministic system of record).

Every row uses a deterministic id derived from snapshot + content, so re-running
a snapshot UPSERTs to identical rows. We delete the snapshot first (ON DELETE
CASCADE clears children) and re-insert, so a changed analysis never leaves stale
rows behind. AI-derived columns (findings.explanation, ranked_actions,
change_decisions) are written later by the advisory/change layers.
"""

from __future__ import annotations

import json

import psycopg

from .analyzers.run_all import EngineResult
from .db import audit, delete_snapshot_children, upsert, upsert_many
from .graph.build import node_db_kind
from .ids import det_id
from .models import ChangeDecision, ChangeRequest, RankedActions

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


def persist_engine_result(cur: psycopg.Cursor, r: EngineResult) -> dict:
    sid = r.snapshot_id
    delete_snapshot_children(cur, sid)

    upsert(cur, "snapshots", {
        "snapshot_id": sid, "label": r.label, "status": "complete",
        "notes": f"{len(r.records)} canonical rules, {len(r.assets)} assets, {len(r.findings)} findings",
    }, ["snapshot_id"])

    tools = sorted({rec.source_tool for rec in r.records})
    upsert_many(cur, "sources", [{
        "source_id": det_id("src", tool), "tool": tool,   # global connector, not per-snapshot
        "device": _DEVICE.get(tool, tool), "config": {"mode": "simulated_export"},
    } for tool in tools], ["source_id"])

    upsert_many(cur, "resolved_objects", [{
        "id": det_id("ro", sid, ro.source_tool, ro.source_device or "", ro.object_name, ro.object_kind),
        "snapshot_id": sid, "source_tool": ro.source_tool, "source_device": ro.source_device,
        "object_name": ro.object_name, "object_kind": ro.object_kind,
        "resolved": ro.resolved, "is_dynamic": ro.is_dynamic,
    } for ro in r.resolved], ["id"])

    upsert_many(cur, "assets", [{
        "asset_id": _asset_id(sid, a.asset_key), "snapshot_id": sid, "asset_key": a.asset_key,
        "kind": a.kind, "context": a.context, "identifiers": a.identifiers,
        "ip_set": list(a.ip_set), "tags": list(a.tags), "source_tools": list(a.source_tools),
    } for a in r.assets], ["asset_id"])

    upsert_many(cur, "asset_correlations", [{
        "id": det_id("corr", sid, c.asset_key, c.match_key, c.evidence),
        "snapshot_id": sid, "asset_id": _asset_id(sid, c.asset_key),
        "match_key": c.match_key, "confidence": c.confidence, "evidence": c.evidence,
    } for c in r.correlations], ["id"])

    def canon(name: str) -> str:
        return r.alias_map.get(name, name)

    upsert_many(cur, "canonical_rules", [{
        "rule_uid": _rule_uid(sid, rec.source_tool, rec.raw_ref), "snapshot_id": sid,
        "source_tool": rec.source_tool, "source_device": _DEVICE.get(rec.source_tool),
        "raw_rule_id": rec.raw_ref, "policy_id": None, "rule_order": rec.order, "action": rec.action,
        "src_kind": rec.source_kind, "src_value": _value(rec.source, rec.source_kind), "src_context": None,
        "dst_kind": rec.destination_kind, "dst_value": _value(rec.destination, rec.destination_kind), "dst_context": None,
        "protocol": rec.protocol, "ports": _ports(rec.protocol, rec.port, rec.port_end), "l7_app": rec.l7_app,
        "nat_original": None, "nat_translated": None, "tags": list(rec.dest_tags), "enabled": True,
        "schedule": None, "direction": None,
        "src_asset_refs": [_asset_id(sid, canon(rec.source))], "dst_asset_refs": [_asset_id(sid, canon(rec.destination))],
    } for rec in r.records], ["rule_uid"])

    upsert_many(cur, "graph_nodes", [{
        "node_id": node_id, "snapshot_id": sid,
        "kind": node_db_kind(node_id, data.get("kind", "concrete")),
        "label": data.get("display", node_id), "context": None,
        "asset_id": _asset_id(sid, node_id), "tags": list(data.get("tags", [])),
        "ip_set": list(data.get("ip_set", [])),
    } for node_id, data in r.graph.nodes(data=True)], ["snapshot_id", "node_id"])

    upsert_many(cur, "graph_edges", [{
        "edge_id": det_id("edge", sid, rec.source_tool, rec.raw_ref), "snapshot_id": sid,
        "src_node": canon(rec.source), "dst_node": canon(rec.destination), "action": rec.action,
        "ports": _ports(rec.protocol, rec.port, rec.port_end),
        "l7_app": rec.l7_app, "rule_uid": _rule_uid(sid, rec.source_tool, rec.raw_ref),
        "source_tool": rec.source_tool, "enforcement_point": _DEVICE.get(rec.source_tool),
    } for rec in r.records if rec.action == "allow"], ["snapshot_id", "edge_id"])

    upsert_many(cur, "findings", [{
        "finding_id": f.id, "snapshot_id": sid, "type": f.type, "severity": f.severity,
        "severity_band": f.severity_band, "forced_critical": f.forced_critical,
        "signals": {**f.signals, "title": f.title}, "involved": list(f.involved),
        "raw_refs": list(f.raw_refs), "source_tools": list(f.source_tools), "explanation": None,
    } for f in r.findings], ["finding_id"])

    audit(cur, "system", "precompute_snapshot", subject=sid, snapshot_id=sid, detail={
        "records": len(r.records), "assets": len(r.assets), "findings": len(r.findings),
        "forced_critical": sum(1 for f in r.findings if f.forced_critical),
    })

    return {
        "snapshot_id": sid, "records": len(r.records), "assets": len(r.assets),
        "correlations": len(r.correlations), "resolved": len(r.resolved),
        "nodes": r.graph.number_of_nodes(), "edges": r.graph.number_of_edges(),
        "findings": len(r.findings),
    }


# --- AI-derived persistence (written by the advisory/change layers) --------

def persist_ranked_actions(cur: psycopg.Cursor, sid: str, ranked: RankedActions) -> int:
    cur.execute("DELETE FROM ztpa.ranked_actions WHERE snapshot_id = %s", [sid])
    for a in ranked.actions:
        upsert(cur, "ranked_actions", {
            "action_id": a.action_id, "snapshot_id": sid, "title": a.title,
            "finding_ids": list(a.finding_ids), "priority": a.priority, "rationale": a.rationale,
        }, ["snapshot_id", "action_id"])
    audit(cur, "agent", "rank_findings", snapshot_id=sid,
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
_MERGES_READY = False


def _ensure_merges(cur: psycopg.Cursor) -> None:
    global _MERGES_READY
    if _MERGES_READY:
        return
    cur.execute("""CREATE TABLE IF NOT EXISTS ztpa.asset_merges (
        merge_id text PRIMARY KEY, name_a text NOT NULL, name_b text NOT NULL,
        confirmed_by text, created_at timestamptz DEFAULT now())""")
    # Allow the human-confirmed correlation type (idempotent; widens the existing check).
    cur.execute("ALTER TABLE ztpa.asset_correlations DROP CONSTRAINT IF EXISTS asset_correlations_match_key_check")
    cur.execute("""ALTER TABLE ztpa.asset_correlations ADD CONSTRAINT asset_correlations_match_key_check
        CHECK (match_key IN ('cloud_id','hostname','mac','context_ip','manual_review'))""")
    _MERGES_READY = True


def load_asset_merges(cur: psycopg.Cursor) -> list[tuple[str, str]]:
    """All human-confirmed merges, applied by the identity layer on every run."""
    _ensure_merges(cur)
    cur.execute("SELECT name_a, name_b FROM ztpa.asset_merges")
    return [(r["name_a"], r["name_b"]) for r in cur.fetchall()]


def persist_asset_merge(cur: psycopg.Cursor, a: str, b: str, by: str = "human") -> str:
    _ensure_merges(cur)
    a, b = sorted([a, b])
    mid = det_id("merge", a, b)
    cur.execute("""INSERT INTO ztpa.asset_merges (merge_id, name_a, name_b, confirmed_by)
        VALUES (%s, %s, %s, %s) ON CONFLICT (merge_id) DO NOTHING""", [mid, a, b, by])
    return mid


def delete_asset_merge(cur: psycopg.Cursor, a: str, b: str) -> None:
    _ensure_merges(cur)
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
    audit(cur, "agent", "remediate_revision", subject=finding_id, snapshot_id=sid,
          detail={"seq": seq, "resolves": (draft.get("validation") or {}).get("resolves")})
    return {"revision_id": rid, "thread_id": tid, "finding_id": finding_id, "seq": seq, "comment": comment,
            "fix_text": draft.get("fix_text"), "change": draft.get("change"),
            "validation": draft.get("validation"), "by": draft.get("by"), "status": "draft"}


def accept_remediation_revision(cur: psycopg.Cursor, revision_id: str) -> None:
    cur.execute("UPDATE ztpa.remediation_revisions SET status='accepted' WHERE revision_id=%s", [revision_id])


# --- staging area -----------------------------------------------------------

def persist_staged_change(cur: psycopg.Cursor, row: dict) -> str:
    upsert(cur, "staged_changes", row, ["staged_id"])
    audit(cur, "user", "stage_change", subject=row.get("request_id"), snapshot_id=row.get("snapshot_id"),
          detail={"target_tool": row.get("target_tool"), "kind": row.get("kind"), "decision": row.get("decision")})
    return row["staged_id"]


_CHANGE_STATUS_READY = False


def ensure_change_request_status(cur: psycopg.Cursor) -> None:
    """Widen change_requests with a lifecycle status so a request can be rejected
    (not just approved/staged). Runtime + idempotent, like _ensure_merges."""
    global _CHANGE_STATUS_READY
    if _CHANGE_STATUS_READY:
        return
    cur.execute("ALTER TABLE ztpa.change_requests ADD COLUMN IF NOT EXISTS status text NOT NULL DEFAULT 'open'")
    cur.execute("ALTER TABLE ztpa.change_requests ADD COLUMN IF NOT EXISTS rejected_by text")
    cur.execute("ALTER TABLE ztpa.change_requests ADD COLUMN IF NOT EXISTS reject_reason text")
    _CHANGE_STATUS_READY = True


def reject_change_request(cur: psycopg.Cursor, request_id: str, by: str, reason: str | None = None) -> int:
    """Mark a request rejected. Returns the number of rows updated (0 = unknown id)."""
    ensure_change_request_status(cur)
    cur.execute("UPDATE ztpa.change_requests SET status='rejected', rejected_by=%s, reject_reason=%s "
                "WHERE request_id=%s", [by, reason, request_id])
    n = cur.rowcount
    if n:
        audit(cur, "user", "reject_change", subject=request_id, detail={"by": by, "reason": reason})
    return n


def load_applied_changes(cur: psycopg.Cursor) -> list[dict]:
    """Operator-accepted changes -- staged changes that were successfully pushed.
    The engine re-applies these to the records on every run (a durable overlay,
    like asset merges), so a recompute reflects the applied state. Ordered for
    deterministic application; only 'pushed' rows count (conflicts are excluded)."""
    try:
        cur.execute("SELECT kind, payload FROM ztpa.staged_changes WHERE status='pushed' "
                    "ORDER BY created_at, staged_id")
        return [dict(r) for r in cur.fetchall()]
    except Exception:
        return []


def reset_change_workflow(cur: psycopg.Cursor) -> dict:
    """Clear the change-governance working set (requests, decisions, staged
    changes, remediation threads) so a demo can be re-run from a clean slate.
    Leaves snapshots/findings alone -- those regenerate from the seed on recompute."""
    counts: dict[str, int] = {}
    for table in ("staged_changes", "change_decisions", "change_requests", "remediation_revisions"):
        try:
            cur.execute(f"DELETE FROM ztpa.{table}")
            counts[table] = cur.rowcount
        except Exception:
            counts[table] = 0
    return counts


def persist_change_decision(cur: psycopg.Cursor, sid: str, request: ChangeRequest,
                            decision: ChangeDecision, kind: str = "add_allow",
                            origin: str = "change_gate") -> str:
    upsert(cur, "change_requests", {
        "request_id": request.id, "snapshot_id": sid,
        "proposed": json.loads(request.proposed.model_dump_json()),
        "requested_by": request.requested_by, "justification": request.justification,
        "kind": kind, "origin": origin,
    }, ["request_id"])
    decision_id = det_id("dec", sid, request.id)
    upsert(cur, "change_decisions", {
        "decision_id": decision_id, "request_id": request.id, "decision": decision.decision,
        "criteria": decision.criteria, "triggering_reason": decision.triggering_reason,
        "delta_summary": decision.delta_summary, "confidence": decision.confidence,
        "forced_escalate": decision.forced_escalate, "model": decision.decided_by,
    }, ["decision_id"])
    audit(cur, "agent", "classify_change", subject=request.id, snapshot_id=sid,
          detail={"decision": decision.decision, "forced_escalate": decision.forced_escalate,
                  "decided_by": decision.decided_by})
    return decision_id
