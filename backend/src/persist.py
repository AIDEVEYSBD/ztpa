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
from .db import audit, delete_snapshot_children, upsert
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


def _ports(protocol: str, port: int | None) -> list[dict]:
    if protocol == "any" or port is None:
        return []
    return [{"proto": protocol, "port_start": port, "port_end": port}]


def persist_engine_result(cur: psycopg.Cursor, r: EngineResult) -> dict:
    sid = r.snapshot_id
    delete_snapshot_children(cur, sid)

    upsert(cur, "snapshots", {
        "snapshot_id": sid, "label": r.label, "status": "complete",
        "notes": f"{len(r.records)} canonical rules, {len(r.assets)} assets, {len(r.findings)} findings",
    }, ["snapshot_id"])

    tools = sorted({rec.source_tool for rec in r.records})
    for tool in tools:
        upsert(cur, "sources", {
            "source_id": det_id("src", tool), "tool": tool,   # global connector, not per-snapshot
            "device": _DEVICE.get(tool, tool), "config": {"mode": "simulated_export"},
        }, ["source_id"])

    for ro in r.resolved:
        upsert(cur, "resolved_objects", {
            "id": det_id("ro", sid, ro.source_tool, ro.source_device or "", ro.object_name, ro.object_kind),
            "snapshot_id": sid, "source_tool": ro.source_tool, "source_device": ro.source_device,
            "object_name": ro.object_name, "object_kind": ro.object_kind,
            "resolved": ro.resolved, "is_dynamic": ro.is_dynamic,
        }, ["id"])

    for a in r.assets:
        upsert(cur, "assets", {
            "asset_id": _asset_id(sid, a.asset_key), "snapshot_id": sid, "asset_key": a.asset_key,
            "kind": a.kind, "context": a.context, "identifiers": a.identifiers,
            "ip_set": list(a.ip_set), "tags": list(a.tags), "source_tools": list(a.source_tools),
        }, ["asset_id"])

    for c in r.correlations:
        upsert(cur, "asset_correlations", {
            "id": det_id("corr", sid, c.asset_key, c.match_key, c.evidence),
            "snapshot_id": sid, "asset_id": _asset_id(sid, c.asset_key),
            "match_key": c.match_key, "confidence": c.confidence, "evidence": c.evidence,
        }, ["id"])

    def canon(name: str) -> str:
        return r.alias_map.get(name, name)

    for rec in r.records:
        s, d = canon(rec.source), canon(rec.destination)
        upsert(cur, "canonical_rules", {
            "rule_uid": _rule_uid(sid, rec.source_tool, rec.raw_ref), "snapshot_id": sid,
            "source_tool": rec.source_tool, "source_device": _DEVICE.get(rec.source_tool),
            "raw_rule_id": rec.raw_ref, "policy_id": None, "rule_order": rec.order, "action": rec.action,
            "src_kind": rec.source_kind, "src_value": _value(rec.source, rec.source_kind), "src_context": None,
            "dst_kind": rec.destination_kind, "dst_value": _value(rec.destination, rec.destination_kind), "dst_context": None,
            "protocol": rec.protocol, "ports": _ports(rec.protocol, rec.port), "l7_app": None,
            "nat_original": None, "nat_translated": None, "tags": list(rec.dest_tags), "enabled": True,
            "schedule": None, "direction": None,
            "src_asset_refs": [_asset_id(sid, s)], "dst_asset_refs": [_asset_id(sid, d)],
        }, ["rule_uid"])

    for node_id, data in r.graph.nodes(data=True):
        upsert(cur, "graph_nodes", {
            "node_id": node_id, "snapshot_id": sid,
            "kind": node_db_kind(node_id, data.get("kind", "concrete")),
            "label": data.get("display", node_id), "context": None,
            "asset_id": _asset_id(sid, node_id), "tags": list(data.get("tags", [])),
            "ip_set": list(data.get("ip_set", [])),
        }, ["snapshot_id", "node_id"])

    for rec in r.records:
        if rec.action != "allow":
            continue
        s, d = canon(rec.source), canon(rec.destination)
        upsert(cur, "graph_edges", {
            "edge_id": det_id("edge", sid, rec.source_tool, rec.raw_ref), "snapshot_id": sid,
            "src_node": s, "dst_node": d, "action": rec.action, "ports": _ports(rec.protocol, rec.port),
            "l7_app": None, "rule_uid": _rule_uid(sid, rec.source_tool, rec.raw_ref),
            "source_tool": rec.source_tool, "enforcement_point": _DEVICE.get(rec.source_tool),
        }, ["snapshot_id", "edge_id"])

    for f in r.findings:
        upsert(cur, "findings", {
            "finding_id": f.id, "snapshot_id": sid, "type": f.type, "severity": f.severity,
            "severity_band": f.severity_band, "forced_critical": f.forced_critical,
            "signals": {**f.signals, "title": f.title}, "involved": list(f.involved),
            "raw_refs": list(f.raw_refs), "source_tools": list(f.source_tools), "explanation": None,
        }, ["finding_id"])

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


def cache_explanation(cur: psycopg.Cursor, finding_id: str, text: str) -> None:
    cur.execute("UPDATE ztpa.findings SET explanation = %s WHERE finding_id = %s", [text, finding_id])


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


def persist_change_decision(cur: psycopg.Cursor, sid: str, request: ChangeRequest,
                            decision: ChangeDecision) -> str:
    upsert(cur, "change_requests", {
        "request_id": request.id, "snapshot_id": sid,
        "proposed": json.loads(request.proposed.model_dump_json()),
        "requested_by": request.requested_by, "justification": request.justification,
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
