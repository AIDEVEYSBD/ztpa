"""ZeroTrust Policy Advisor API.

Dashboard reads come from Postgres (the precomputed snapshot, the system of
record). Live LLM/agent calls (explain, classify, ask, remediate, report,
suggest, connector-authoring) run on demand. The deterministic engine is held in
memory for live reachability/simulation (identical data to the persisted snapshot).
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))  # backend root

from fastapi import BackgroundTasks, FastAPI, HTTPException  # noqa: E402
from fastapi.middleware.cors import CORSMiddleware  # noqa: E402
from pydantic import BaseModel  # noqa: E402

from src import settings  # noqa: E402
from src.advisory import authoring, classify_change, entity_suggest, explain as explain_mod  # noqa: E402
from src.advisory import intake as intake_mod, orchestrator, rank as rank_mod, remediation, report as report_mod  # noqa: E402
from src.advisory.client import provider_status  # noqa: E402
from src.agent.assistant import ask as agent_ask  # noqa: E402
from src.analyzers.run_all import EngineResult, run  # noqa: E402
from src.change.requests import DEMO_REQUESTS  # noqa: E402
from src.change.simulate import simulate_change  # noqa: E402
from src.scenarios import SCENARIOS, write_scenario  # noqa: E402
from src.db import audit, delete_snapshot_children, fetch_all, fetch_one, get_conn, ping  # noqa: E402
from src.graph.zones import zone_of  # noqa: E402
from src.ids import det_id  # noqa: E402
from src.models import ChangeRequest, RankedAction, RankedActions  # noqa: E402
from src.persist import (  # noqa: E402
    cache_explanation, delete_asset_merge, load_asset_merges, persist_asset_merge,
    persist_change_decision, persist_engine_result, persist_ranked_actions,
)

app = FastAPI(title="ZeroTrust Policy Advisor", version="1.0")
app.add_middleware(
    CORSMiddleware, allow_origins=[settings.FRONTEND_ORIGIN, "http://localhost:3000"],
    allow_methods=["*"], allow_headers=["*"],
)

_ENGINE: EngineResult | None = None
_ACTIVE_SCENARIO = "demo"


def _load_merges() -> list[tuple[str, str]]:
    """Human-confirmed asset merges, applied by the identity layer on every run."""
    try:
        with get_conn() as conn, conn.cursor() as cur:
            return load_asset_merges(cur)
    except Exception:
        return []


def engine() -> EngineResult:
    """Cached deterministic engine; persists the snapshot if the DB lacks it."""
    global _ENGINE
    if _ENGINE is None:
        try:
            write_scenario(_ACTIVE_SCENARIO)   # keep data/mock consistent with the active scenario
        except Exception:
            pass
        _ENGINE = run(label=_ACTIVE_SCENARIO, manual_merges=_load_merges())
        try:
            with get_conn() as conn, conn.cursor() as cur:
                row = fetch_one(cur, "SELECT snapshot_id FROM ztpa.snapshots WHERE snapshot_id=%s",
                                [_ENGINE.snapshot_id])
                if not row:
                    persist_engine_result(cur, _ENGINE)
        except Exception:
            pass  # DB optional for live-only ops
    return _ENGINE


def sid() -> str:
    return engine().snapshot_id


def view_sid(snapshot: str | None) -> str:
    """Snapshot to READ from: an explicit historical one, else the active one."""
    return snapshot or engine().snapshot_id


def _finding(fid: str):
    return next((f for f in engine().findings if f.id == fid), None)


# --------------------------------------------------------------------------
@app.get("/api/health")
def health():
    db_ok = False
    try:
        db_ok = ping()
    except Exception:
        pass
    return {"status": "ok", "db": db_ok, "snapshot_id": sid(), "ai": provider_status()}


@app.post("/api/recompute")
def recompute():
    """Re-run the deterministic engine LIVE and reset the AI caches, so the next
    rank/explain/classify recompute live too. Lets a demo show computation happening
    on stage. Deterministic: same seed -> same snapshot id and rows."""
    global _ENGINE
    try:
        write_scenario(_ACTIVE_SCENARIO)   # regenerate the active scenario so data/mock stays consistent
    except Exception:
        pass
    _ENGINE = run(label=_ACTIVE_SCENARIO, manual_merges=_load_merges())
    snap = _ENGINE.snapshot_id
    with get_conn() as conn, conn.cursor() as cur:
        summary = persist_engine_result(cur, _ENGINE)
        summary["timings"] = _ENGINE.timings
        summary["paths"] = sum(1 for f in _ENGINE.findings if f.type == "cross_tool_path")
        cur.execute("DELETE FROM ztpa.ranked_actions WHERE snapshot_id=%s", [snap])
        cur.execute("UPDATE ztpa.findings SET explanation=NULL WHERE snapshot_id=%s", [snap])
        audit(cur, "user", "recompute_snapshot", subject=snap, snapshot_id=snap, detail=summary)
    return {"ok": True, "summary": summary}


@app.get("/api/scenarios")
def scenarios():
    return {"scenarios": SCENARIOS, "active": _ACTIVE_SCENARIO}


class DatasetBody(BaseModel):
    scenario: str
    n: int = 500


@app.post("/api/admin/dataset")
def switch_dataset(body: DatasetBody):
    """Regenerate the simulated exports for a scenario, then recompute live."""
    global _ENGINE, _ACTIVE_SCENARIO
    try:
        write_scenario(body.scenario, body.n)
    except ValueError as e:
        raise HTTPException(400, str(e))
    _ACTIVE_SCENARIO = body.scenario
    _ENGINE = run(label=body.scenario, manual_merges=_load_merges())
    snap = _ENGINE.snapshot_id
    with get_conn() as conn, conn.cursor() as cur:
        summary = persist_engine_result(cur, _ENGINE)
        summary["timings"] = _ENGINE.timings
        summary["paths"] = sum(1 for f in _ENGINE.findings if f.type == "cross_tool_path")
        cur.execute("DELETE FROM ztpa.ranked_actions WHERE snapshot_id=%s", [snap])
        cur.execute("UPDATE ztpa.findings SET explanation=NULL WHERE snapshot_id=%s", [snap])
        audit(cur, "user", "switch_dataset", subject=body.scenario, snapshot_id=snap, detail=summary)
    return {"ok": True, "scenario": body.scenario, "summary": summary}


@app.get("/api/rule/{ref}")
def rule_detail(ref: str, snapshot: str | None = None):
    """A single canonical rule by its raw ref (for click-through rule links)."""
    t = view_sid(snapshot)
    with get_conn() as conn, conn.cursor() as cur:
        rows = fetch_all(cur, "SELECT source_tool,source_device,raw_rule_id,rule_order,action,src_kind,src_value,dst_kind,dst_value,protocol,ports,tags FROM ztpa.canonical_rules WHERE snapshot_id=%s AND raw_rule_id=%s", [t, ref])
    return {"ref": ref, "rules": rows}


@app.get("/api/ingest")
def ingest(snapshot: str | None = None):
    """What actually got ingested for the snapshot (admin inspector)."""
    t = view_sid(snapshot)
    with get_conn() as conn, conn.cursor() as cur:
        sources = fetch_all(cur, "SELECT DISTINCT source_tool AS tool, source_device AS device FROM ztpa.canonical_rules WHERE snapshot_id=%s ORDER BY source_tool", [t])
        resolved = fetch_all(cur, "SELECT source_tool,object_name,object_kind,resolved,is_dynamic FROM ztpa.resolved_objects WHERE snapshot_id=%s ORDER BY source_tool,object_name", [t])
        rules = fetch_all(cur, "SELECT rule_uid,source_tool,raw_rule_id,rule_order,action,src_kind,src_value,dst_kind,dst_value,protocol,ports,tags FROM ztpa.canonical_rules WHERE snapshot_id=%s ORDER BY source_tool,rule_order", [t])
    return {"active_scenario": _ACTIVE_SCENARIO, "sources": sources, "resolved_objects": resolved, "canonical_rules": rules}


@app.get("/api/snapshots")
def snapshots_list():
    with get_conn() as conn, conn.cursor() as cur:
        rows = fetch_all(cur, """
            SELECT s.snapshot_id, s.label, s.status, s.created_at,
              (SELECT count(*) FROM ztpa.assets a WHERE a.snapshot_id=s.snapshot_id) AS assets,
              (SELECT count(*) FROM ztpa.canonical_rules r WHERE r.snapshot_id=s.snapshot_id) AS rules,
              (SELECT count(*) FROM ztpa.findings f WHERE f.snapshot_id=s.snapshot_id) AS findings,
              (SELECT count(*) FROM ztpa.findings f WHERE f.snapshot_id=s.snapshot_id AND f.type='cross_tool_path') AS paths,
              (SELECT count(*) FROM ztpa.findings f WHERE f.snapshot_id=s.snapshot_id AND f.severity_band='critical') AS critical
            FROM ztpa.snapshots s ORDER BY s.created_at DESC""")
    return {"snapshots": rows, "active": sid()}


@app.delete("/api/snapshots/{snapshot_id}")
def delete_snapshot(snapshot_id: str):
    if snapshot_id == sid():
        raise HTTPException(400, "Cannot delete the active snapshot. Switch dataset or recompute first.")
    with get_conn() as conn, conn.cursor() as cur:
        delete_snapshot_children(cur, snapshot_id)   # deletes the snapshot row; children cascade
        audit(cur, "user", "delete_snapshot", subject=snapshot_id, detail={})
    return {"ok": True, "deleted": snapshot_id}


@app.get("/api/snapshot")
def snapshot_meta(snapshot: str | None = None):
    t = view_sid(snapshot)
    with get_conn() as conn, conn.cursor() as cur:
        snap = fetch_one(cur, "SELECT * FROM ztpa.snapshots WHERE snapshot_id=%s", [t])
        counts = {}
        for tbl in ("assets", "canonical_rules", "graph_nodes", "graph_edges",
                    "findings", "resolved_objects", "asset_correlations", "ranked_actions"):
            counts[tbl] = fetch_one(cur, f"SELECT count(*) n FROM ztpa.{tbl} WHERE snapshot_id=%s", [t])["n"]
    return {"snapshot": snap, "counts": counts, "viewing": t, "active": sid()}


@app.get("/api/graph")
def graph(snapshot: str | None = None):
    t = view_sid(snapshot)
    with get_conn() as conn, conn.cursor() as cur:
        nodes = fetch_all(cur, "SELECT node_id,kind,label,tags,ip_set FROM ztpa.graph_nodes WHERE snapshot_id=%s", [t])
        edges = fetch_all(cur, "SELECT src_node,dst_node,source_tool,ports,rule_uid FROM ztpa.graph_edges WHERE snapshot_id=%s", [t])
        ct = fetch_all(cur, "SELECT signals FROM ztpa.findings WHERE snapshot_id=%s AND type='cross_tool_path' ORDER BY finding_id", [t])
    for n in nodes:
        n["zone"] = zone_of(n["node_id"], n.get("tags") or [])
    grouped: dict[tuple, dict] = {}
    for ed in edges:
        key = (ed["src_node"], ed["dst_node"])
        g = grouped.setdefault(key, {"src": ed["src_node"], "dst": ed["dst_node"], "tools": set(), "services": set()})
        g["tools"].add(ed["source_tool"])
        for p in (ed.get("ports") or []):
            g["services"].add(f"{p.get('proto')}/{p.get('port_start')}")
        if not ed.get("ports"):
            g["services"].add("any")
    edge_list = [{"src": v["src"], "dst": v["dst"], "tools": sorted(v["tools"]),
                  "services": sorted(v["services"])} for v in grouped.values()]
    cross = [r["signals"] for r in ct]
    highlight = cross[0].get("path") if cross else []
    return {"nodes": nodes, "edges": edge_list, "highlight_path": highlight, "cross_tool_paths": cross}


@app.get("/api/findings")
def findings(snapshot: str | None = None):
    with get_conn() as conn, conn.cursor() as cur:
        rows = fetch_all(cur, """
            SELECT finding_id,type,severity,severity_band,forced_critical,signals,involved,raw_refs,
                   source_tools,explanation FROM ztpa.findings WHERE snapshot_id=%s
            ORDER BY forced_critical DESC, severity DESC, type""", [view_sid(snapshot)])
    return {"findings": rows}


@app.get("/api/findings/{fid}")
def finding_detail(fid: str):
    with get_conn() as conn, conn.cursor() as cur:
        row = fetch_one(cur, "SELECT * FROM ztpa.findings WHERE finding_id=%s AND snapshot_id=%s", [fid, sid()])
    if not row:
        raise HTTPException(404, "finding not found")
    return row


_EXPLAIN_TIMEOUT = 180.0
_explaining: set[str] = set()   # findings whose LLM explanation is being computed in the background


def _bg_explain(fid: str, f) -> None:
    """Compute the LLM explanation off the request path and cache it. Cold local
    models can take minutes; doing this in the background means the HTTP request
    (which a dev proxy would reset) already returned the deterministic version."""
    try:
        result = explain_mod.explain(f, timeout=_EXPLAIN_TIMEOUT)
        if result.get("by") != "engine_fallback" and result.get("explanation", "").strip():
            with get_conn() as conn, conn.cursor() as cur:
                cache_explanation(cur, fid, result["explanation"])
                audit(cur, "agent", "explain_finding", subject=fid, snapshot_id=sid(), detail={"by": result["by"]})
    finally:
        _explaining.discard(fid)


@app.post("/api/findings/{fid}/explain")
def explain_finding(fid: str, background: BackgroundTasks):
    f = _finding(fid)
    if not f:
        raise HTTPException(404, "finding not found")
    with get_conn() as conn, conn.cursor() as cur:
        row = fetch_one(cur, "SELECT explanation FROM ztpa.findings WHERE finding_id=%s", [fid])
    if row and row.get("explanation"):
        return {"explanation": row["explanation"], "by": "cache", "cached": True, "pending": False}
    # Not cached: return the deterministic explanation immediately and compute the
    # richer LLM one in the background (de-duped per finding). The UI re-fetches.
    if fid not in _explaining:
        _explaining.add(fid)
        background.add_task(_bg_explain, fid, f)
    return {"explanation": explain_mod._fallback(f), "by": "engine_fallback", "cached": False, "pending": True}


@app.post("/api/findings/{fid}/remediate")
def remediate_finding(fid: str):
    f = _finding(fid)
    if not f:
        raise HTTPException(404, "finding not found")
    result = remediation.draft(f, engine())
    with get_conn() as conn, conn.cursor() as cur:
        audit(cur, "agent", "remediate_finding", subject=fid, snapshot_id=sid(),
              detail={"by": result["by"], "resolves": result["validation"].get("resolves")})
    return result


@app.get("/api/actions")
def actions(snapshot: str | None = None):
    t = view_sid(snapshot)
    with get_conn() as conn, conn.cursor() as cur:
        rows = fetch_all(cur, "SELECT action_id,title,finding_ids,priority,rationale FROM ztpa.ranked_actions WHERE snapshot_id=%s ORDER BY priority", [t])
        if rows or t != sid():
            return {"actions": rows, "ranked_by": "cache"}   # historical: show cache only
        ranked = rank_mod.rank(engine().findings)
        persist_ranked_actions(cur, t, ranked)
        rows = fetch_all(cur, "SELECT action_id,title,finding_ids,priority,rationale FROM ztpa.ranked_actions WHERE snapshot_id=%s ORDER BY priority", [t])
    return {"actions": rows, "ranked_by": ranked.ranked_by}


@app.post("/api/actions/recompute")
def recompute_actions():
    ranked = rank_mod.rank(engine().findings)
    with get_conn() as conn, conn.cursor() as cur:
        persist_ranked_actions(cur, sid(), ranked)
    return {"actions": [a.model_dump() for a in ranked.actions], "ranked_by": ranked.ranked_by}


@app.get("/api/assets")
def assets(snapshot: str | None = None):
    t = view_sid(snapshot)
    with get_conn() as conn, conn.cursor() as cur:
        a = fetch_all(cur, "SELECT asset_id,asset_key,kind,context,identifiers,ip_set,tags,source_tools FROM ztpa.assets WHERE snapshot_id=%s ORDER BY asset_key", [t])
        c = fetch_all(cur, "SELECT asset_id,match_key,confidence,evidence FROM ztpa.asset_correlations WHERE snapshot_id=%s", [t])
    return {"assets": a, "correlations": c}


@app.get("/api/assets/merge-suggestions")
def merge_suggestions():
    return {"suggestions": entity_suggest.suggest_merges(engine().assets)}


class MergeBody(BaseModel):
    a: str
    b: str


def _apply_merges_and_persist(action: str, a: str, b: str) -> dict:
    """Re-resolve identities with the current confirmed merges, then re-persist the
    snapshot (delete_snapshot_children + reinsert) so DB-backed reads reflect it."""
    global _ENGINE
    _ENGINE = run(label=_ACTIVE_SCENARIO, manual_merges=_load_merges())
    snap = _ENGINE.snapshot_id
    with get_conn() as conn, conn.cursor() as cur:
        persist_engine_result(cur, _ENGINE)
        cur.execute("DELETE FROM ztpa.ranked_actions WHERE snapshot_id=%s", [snap])
        cur.execute("UPDATE ztpa.findings SET explanation=NULL WHERE snapshot_id=%s", [snap])
        audit(cur, "user", action, subject=f"{a}~{b}", snapshot_id=snap, detail={"a": a, "b": b})
    return {"assets": len(_ENGINE.assets), "snapshot_id": snap}


@app.post("/api/assets/merge")
def confirm_merge(body: MergeBody):
    """Human-confirm that two suggested duplicates are the same logical asset. The
    decision is durable; the identity layer unifies them on every run from now on."""
    if not body.a or not body.b or body.a == body.b:
        raise HTTPException(400, "provide two distinct asset keys")
    with get_conn() as conn, conn.cursor() as cur:
        persist_asset_merge(cur, body.a, body.b, by="human")
    summary = _apply_merges_and_persist("confirm_merge", body.a, body.b)
    return {"ok": True, "merged": [body.a, body.b], **summary}


@app.post("/api/assets/unmerge")
def undo_merge(body: MergeBody):
    """Reverse a previously confirmed merge (the assets split back apart)."""
    with get_conn() as conn, conn.cursor() as cur:
        delete_asset_merge(cur, body.a, body.b)
    summary = _apply_merges_and_persist("undo_merge", body.a, body.b)
    return {"ok": True, "unmerged": [body.a, body.b], **summary}


@app.get("/api/assets/merges")
def list_merges():
    """Confirmed merges (the human-decision audit trail for identity)."""
    with get_conn() as conn, conn.cursor() as cur:
        return {"merges": [{"a": a, "b": b} for a, b in load_asset_merges(cur)]}


@app.get("/api/change-requests")
def change_requests():
    return {"requests": [{"id": r.id, "title": r.title, "requested_by": r.requested_by,
                          "justification": r.justification,
                          "proposed": {"source": r.proposed.source, "destination": r.proposed.destination,
                                       "service": r.proposed.service, "action": r.proposed.action}}
                         for r in DEMO_REQUESTS.values()]}


class ClassifyBody(BaseModel):
    request_id: str | None = None
    source: str | None = None
    destination: str | None = None
    service: str | None = None
    justification: str | None = None


@app.post("/api/change/classify")
def classify(body: ClassifyBody):
    e = engine()
    if body.request_id and body.request_id in DEMO_REQUESTS:
        req = DEMO_REQUESTS[body.request_id]
    elif body.source and body.destination and body.service:
        from src.normalizers.common import is_cidr, parse_service
        proto, port, label = parse_service(body.service)
        from src.models import PolicyRecord
        # Deterministic id from the proposed tuple: re-simulating the same change
        # updates its record (idempotent), but distinct changes accumulate as
        # separate audit entries in change_requests/change_decisions.
        cr_id = det_id("cr", body.source, body.destination, label)
        req = ChangeRequest(id=cr_id, title=f"{body.source} -> {body.destination} {label}",
                            proposed=PolicyRecord(id=f"{cr_id}-rule", source_tool="algosec", raw_ref=cr_id,
                                                  source=body.source, source_kind="cidr" if is_cidr(body.source) else "identity",
                                                  destination=body.destination, destination_kind="cidr" if is_cidr(body.destination) else "identity",
                                                  dest_tags=[], service=label, port=port, protocol=proto, action="allow", order=999),
                            requested_by="custom", justification=body.justification)
    else:
        raise HTTPException(400, "provide request_id or source+destination+service")
    delta = simulate_change(e.records, e.assets, e.alias_map, req.proposed)
    decision = classify_change.classify_change(req, delta)
    with get_conn() as conn, conn.cursor() as cur:
        persist_change_decision(cur, sid(), req, decision)
    return {"request": {"id": req.id, "title": req.title, "justification": req.justification},
            "delta": delta, "decision": decision.model_dump()}


@app.get("/api/change-decisions")
def change_decisions_log(limit: int = 25):
    """The change audit trail: every evaluated request joined to how the gate
    ruled on it (decision, guardrail, who decided, when). Reads the
    change_requests + change_decisions tables that classify() writes."""
    with get_conn() as conn, conn.cursor() as cur:
        rows = fetch_all(cur, """
            SELECT d.decision_id, d.request_id, d.decision, d.forced_escalate, d.confidence,
                   d.model AS decided_by, d.triggering_reason, d.decided_at,
                   r.proposed, r.justification, r.requested_by
            FROM ztpa.change_decisions d
            JOIN ztpa.change_requests r ON r.request_id = d.request_id
            ORDER BY d.decided_at DESC NULLS LAST
            LIMIT %s
        """, [limit])
    return {"decisions": rows}


class AskBody(BaseModel):
    question: str


@app.post("/api/agent/ask")
def agent(body: AskBody):
    result = agent_ask(engine(), body.question)
    with get_conn() as conn, conn.cursor() as cur:
        audit(cur, "user", "agent_ask", snapshot_id=sid(),
              detail={"question": body.question[:200], "tools": [t["tool"] for t in result.get("trace", [])]})
    return result


@app.get("/api/agent/suggestions")
def agent_suggestions():
    """Question suggestions derived from THIS snapshot's facts (not hardcoded):
    a real cross-tool path terminal, a regulated asset, a real over-permissive
    exposure, and the guardrail-forced findings."""
    from src.config import SENSITIVE_TAGS
    e = engine()
    qs: list[str] = []
    paths = [f for f in e.findings if f.type == "cross_tool_path"]
    if paths and paths[0].signals.get("terminal"):
        qs.append(f"Can the internet reach {paths[0].signals['terminal']}, and through which path and tools?")
    sens = sorted({a.asset_key for a in e.assets if set(a.tags) & SENSITIVE_TAGS})
    if sens:
        qs.append(f"What can reach {sens[0]}?")
    op = [f for f in e.findings if f.type == "over_permissive"]
    if op:
        sig = op[0].signals
        src, dst, svc = sig.get("source"), sig.get("dest_display") or sig.get("dest"), sig.get("service")
        if src and dst:
            qs.append(f"What would happen if I open {svc or 'tcp/22'} from {src} to {dst}?")
    if any(f.forced_critical for f in e.findings):
        qs.append("Which findings are forced-critical, and why?")
    qs.append("Summarize the riskiest exposure in this snapshot.")
    out: list[str] = []
    for q in qs:
        if q not in out:
            out.append(q)
    return {"suggestions": out[:4]}


def _ranked_cached(cur) -> RankedActions:
    """Reuse the persisted ranked actions (same cache /api/actions uses) so the
    report never re-runs the slow ranking model. Computes + persists only if absent."""
    t = sid()
    rows = fetch_all(cur, "SELECT action_id,title,finding_ids,priority,rationale FROM ztpa.ranked_actions WHERE snapshot_id=%s ORDER BY priority", [t])
    if rows:
        return RankedActions(
            actions=[RankedAction(action_id=r["action_id"], title=r["title"], finding_ids=r["finding_ids"],
                                  priority=r["priority"], rationale=r["rationale"]) for r in rows],
            ranked_by="llm",
        )
    ranked = rank_mod.rank(engine().findings)
    persist_ranked_actions(cur, t, ranked)
    return ranked


@app.get("/api/report")
def report():
    """Instant, deterministic report (visuals + numbers + a deterministic narrative).
    The richer LLM narrative is fetched separately so the page never hangs."""
    e = engine()
    with get_conn() as conn, conn.cursor() as cur:
        ranked = _ranked_cached(cur)
    return orchestrator.posture_facts(e.findings, e.assets, ranked)


@app.get("/api/report/narrative")
def report_narrative():
    """The slow, board-ready LLM narrative (bounded + fail-closed)."""
    e = engine()
    with get_conn() as conn, conn.cursor() as cur:
        ranked = _ranked_cached(cur)
    return orchestrator.posture_narrative(e.findings, e.assets, ranked)


class IntakeBody(BaseModel):
    text: str


@app.post("/api/intake")
def intake(body: IntakeBody):
    return intake_mod.extract(body.text)


class ProposeBody(BaseModel):
    sample: dict
    tool_hint: str = ""


@app.post("/api/connectors/propose")
def propose_connector(body: ProposeBody):
    return authoring.propose_profile(body.sample, body.tool_hint)


@app.get("/api/audit")
def audit_log():
    with get_conn() as conn, conn.cursor() as cur:
        rows = fetch_all(cur, "SELECT ts,actor,action,subject,detail FROM ztpa.audit_log ORDER BY ts DESC LIMIT 50")
    return {"audit": rows}
