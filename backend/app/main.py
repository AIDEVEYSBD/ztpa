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

from fastapi import BackgroundTasks, Depends, FastAPI, HTTPException  # noqa: E402
from fastapi.middleware.cors import CORSMiddleware  # noqa: E402
from psycopg.types.json import Jsonb  # noqa: E402
from pydantic import BaseModel  # noqa: E402

from src import request_ctx, settings, tools_registry  # noqa: E402
from src.advisory import authoring, classify_change, entity_suggest, explain as explain_mod  # noqa: E402
from src.advisory import intake as intake_mod, orchestrator, rank as rank_mod, remediation, report as report_mod  # noqa: E402
from src.advisory.client import provider_status  # noqa: E402
from src.agent.assistant import ask as agent_ask  # noqa: E402
from src.analyzers.run_all import EngineResult, reanalyze, run  # noqa: E402
from src.change import staging as staging_mod  # noqa: E402
from src.change.requests import DEMO_REQUESTS  # noqa: E402
from src.change.simulate import simulate_change  # noqa: E402
from src.scenarios import SCENARIOS, write_scenario  # noqa: E402
from src.db import audit, delete_snapshot_children, fetch_all, fetch_one, get_conn, ping, upsert  # noqa: E402
from src.graph.zones import zone_of  # noqa: E402
from src.ids import det_id  # noqa: E402
from src.models import ChangeRequest, RankedAction, RankedActions  # noqa: E402
from src.persist import (  # noqa: E402
    accept_remediation_revision, cache_explanation, delete_asset_merge, load_asset_merges,
    load_remediation_thread, persist_asset_merge, persist_change_decision, persist_engine_result,
    persist_ranked_actions, persist_remediation_revision, persist_staged_change,
)

app = FastAPI(title="ZeroTrust Policy Advisor", version="1.0")
app.add_middleware(
    CORSMiddleware, allow_origins=[settings.FRONTEND_ORIGIN, "http://localhost:3000"],
    allow_methods=["*"], allow_headers=["*"],
)


class _ActorMiddleware:
    """Pure-ASGI middleware: read the proxy-injected role/email headers and stash
    them in request_ctx so metric recording + per-role tool enforcement can
    attribute work. Set in the async context before the (threadpooled) endpoint
    runs, so anyio copies the value into the worker thread."""

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope.get("type") == "http":
            h = {k.decode("latin-1").lower(): v.decode("latin-1") for k, v in scope.get("headers", [])}
            request_ctx.set_actor(h.get("x-ztpa-role"), h.get("x-ztpa-email"))
        await self.app(scope, receive, send)


app.add_middleware(_ActorMiddleware)


def require_admin() -> None:
    if request_ctx.role() != "admin":
        raise HTTPException(403, "admin only")


def _require_capability(key: str) -> None:
    """403 a disabled AI capability for the caller's role (fail-closed)."""
    if not tools_registry.is_enabled(key):
        raise HTTPException(403, f"capability '{key}' is disabled for role {request_ctx.role()}")

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
def switch_dataset(body: DatasetBody, _: None = Depends(require_admin)):
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
def delete_snapshot(snapshot_id: str, _: None = Depends(require_admin)):
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
                cache_explanation(cur, fid, result["explanation"], result.get("by"))
                audit(cur, "agent", "explain_finding", subject=fid, snapshot_id=sid(), detail={"by": result["by"]})
    finally:
        _explaining.discard(fid)


@app.post("/api/findings/{fid}/explain")
def explain_finding(fid: str, background: BackgroundTasks):
    _require_capability("explain")
    f = _finding(fid)
    if not f:
        raise HTTPException(404, "finding not found")
    with get_conn() as conn, conn.cursor() as cur:
        row = fetch_one(cur, "SELECT explanation, explanation_by FROM ztpa.findings WHERE finding_id=%s", [fid])
    if row and row.get("explanation"):
        # Report the original provider:model (e.g. "openai:gpt-4o (cached)") when we
        # captured it; older rows without provenance fall back to a bare "cache".
        src = row.get("explanation_by")
        by = f"{src} (cached)" if src else "cache"
        return {"explanation": row["explanation"], "by": by, "cached": True, "pending": False}
    # Not cached: return the deterministic explanation immediately and compute the
    # richer LLM one in the background (de-duped per finding). The UI re-fetches.
    if fid not in _explaining:
        _explaining.add(fid)
        background.add_task(_bg_explain, fid, f)
    # tell the UI which provider will produce the richer explanation, so it can
    # label the "refining…" state truthfully (local model vs a hosted one).
    return {"explanation": explain_mod._fallback(f), "by": "engine_fallback",
            "cached": False, "pending": True, "provider": settings.active_provider()}


@app.post("/api/findings/{fid}/remediate")
def remediate_finding(fid: str):
    _require_capability("remediate")
    f = _finding(fid)
    if not f:
        raise HTTPException(404, "finding not found")
    result = remediation.draft(f, engine())
    with get_conn() as conn, conn.cursor() as cur:
        rev = persist_remediation_revision(cur, sid(), fid, result)
        audit(cur, "agent", "remediate_finding", subject=fid, snapshot_id=sid(),
              detail={"by": result["by"], "resolves": result["validation"].get("resolves")})
    return {**result, "thread_id": rev["thread_id"], "seq": rev["seq"], "revision_id": rev["revision_id"]}


class RefineBody(BaseModel):
    comment: str
    prior_change: dict | None = None


@app.post("/api/findings/{fid}/remediate/refine")
def remediate_refine(fid: str, body: RefineBody):
    """Iterate on a remediation: fold the reviewer's comment into a revised draft,
    re-validate it deterministically, and append it to the finding's thread."""
    _require_capability("remediate")
    f = _finding(fid)
    if not f:
        raise HTTPException(404, "finding not found")
    result = remediation.draft(f, engine(), comment=body.comment, prior=body.prior_change)
    with get_conn() as conn, conn.cursor() as cur:
        rev = persist_remediation_revision(cur, sid(), fid, result, comment=body.comment)
    return {**result, "thread_id": rev["thread_id"], "seq": rev["seq"], "revision_id": rev["revision_id"]}


@app.get("/api/findings/{fid}/remediation-thread")
def remediation_thread(fid: str):
    with get_conn() as conn, conn.cursor() as cur:
        return {"revisions": load_remediation_thread(cur, sid(), fid)}


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
    _require_capability("entity_suggest")
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
    _require_capability("classify")
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
                   r.proposed, r.justification, r.requested_by, r.kind, r.origin,
                   s.staged_id, s.status AS staged_status
            FROM ztpa.change_decisions d
            JOIN ztpa.change_requests r ON r.request_id = d.request_id
            LEFT JOIN ztpa.staged_changes s ON s.request_id = d.request_id
            ORDER BY d.decided_at DESC NULLS LAST
            LIMIT %s
        """, [limit])
    return {"decisions": rows}


# --- Risk To-Do -> Change Gate: submit an accepted remediation -------------
class SubmitBody(BaseModel):
    kind: str = "remediation"
    finding_id: str | None = None
    change: dict | None = None
    revision_id: str | None = None
    justification: str | None = None


@app.post("/api/change/submit")
def change_submit(body: SubmitBody):
    """Submit an accepted Risk-To-Do remediation to the Change Gate. The engine
    re-simulates it deterministically and the gate decides: auto_approve if it
    resolves its finding and introduces no new criticals, else escalate."""
    _require_capability("classify")
    if body.kind != "remediation":
        raise HTTPException(400, "unsupported submit kind")
    if not body.finding_id or not body.change:
        raise HTTPException(400, "remediation submit needs finding_id and change")
    f = _finding(body.finding_id)
    if not f:
        raise HTTPException(404, "finding not found")
    validation = remediation._validate(engine(), f, body.change)
    resolves = bool(validation.get("resolves"))
    new_crit = validation.get("introduces_new_criticals") or []
    decision = "auto_approve" if (resolves and not new_crit) else "escalate"
    request_id = det_id("cr", body.finding_id, body.revision_id or body.change)
    decision_id = det_id("dec", sid(), request_id)
    ref = body.change.get("target_ref")
    rule = next((r for r in engine().records if r.raw_ref == ref), None)
    target_tool = rule.source_tool if rule else "algosec"
    proposed = {**body.change, "finding_id": body.finding_id, "target_tool": target_tool,
                "summary": f"{body.change.get('op')} {ref}".strip()}
    crit = {"resolves": resolves, "no_new_criticals": not new_crit}
    trig = ("introduces new critical findings: " + ", ".join(new_crit)) if new_crit else (
        None if resolves else "the fix does not resolve the finding")
    with get_conn() as conn, conn.cursor() as cur:
        upsert(cur, "change_requests", {
            "request_id": request_id, "snapshot_id": sid(), "proposed": proposed,
            "requested_by": request_ctx.current().email or "risk_todo", "justification": body.justification,
            "kind": "remediation", "origin": "risk_todo"}, ["request_id"])
        upsert(cur, "change_decisions", {
            "decision_id": decision_id, "request_id": request_id, "decision": decision, "criteria": crit,
            "triggering_reason": trig if decision == "escalate" else None, "delta_summary": validation,
            "confidence": 1.0 if resolves else 0.5, "forced_escalate": bool(new_crit), "model": "engine"},
            ["decision_id"])
        if body.revision_id:
            accept_remediation_revision(cur, body.revision_id)
        audit(cur, "user", "submit_remediation", subject=body.finding_id, snapshot_id=sid(),
              detail={"decision": decision, "request_id": request_id})
    return {"request_id": request_id, "kind": "remediation",
            "decision": {"request_id": request_id, "decision": decision, "criteria": crit,
                         "triggering_reason": trig, "delta_summary": validation,
                         "confidence": 1.0 if resolves else 0.5, "forced_escalate": bool(new_crit),
                         "decided_by": "engine"},
            "target_tool": target_tool}


# --- Staging area ----------------------------------------------------------
class StageBody(BaseModel):
    request_id: str
    target_tool: str | None = None
    manual_approve: bool = False


@app.post("/api/staging")
def stage_change(body: StageBody):
    with get_conn() as conn, conn.cursor() as cur:
        row = fetch_one(cur, """
            SELECT d.decision, r.proposed, r.kind, r.origin, r.snapshot_id
            FROM ztpa.change_decisions d JOIN ztpa.change_requests r ON r.request_id = d.request_id
            WHERE d.request_id = %s""", [body.request_id])
        if not row:
            raise HTTPException(404, "change request/decision not found")
        if row["decision"] == "escalate":
            if not body.manual_approve:
                raise HTTPException(400, "escalated change requires manual approval to stage")
            if request_ctx.role() not in ("admin", "analyst"):
                raise HTTPException(403, "only admin or analyst can approve an escalated change")
            staged_decision = "manual_approved"
        else:
            staged_decision = "auto_approve"
        proposed = row["proposed"] or {}
        target = body.target_tool or proposed.get("target_tool") or "algosec"
        staged_id = det_id("stage", body.request_id)
        persist_staged_change(cur, {
            "staged_id": staged_id, "snapshot_id": row.get("snapshot_id") or sid(),
            "request_id": body.request_id, "origin": row.get("origin") or "change_gate",
            "kind": row.get("kind") or "add_allow", "target_tool": target, "payload": proposed,
            "decision": staged_decision, "status": "staged"})
    return {"ok": True, "staged_id": staged_id, "status": "staged", "target_tool": target}


@app.get("/api/staging")
def staging_list():
    with get_conn() as conn, conn.cursor() as cur:
        rows = fetch_all(cur, """
            SELECT s.staged_id, s.snapshot_id, s.request_id, s.origin, s.kind, s.target_tool, s.payload,
                   s.decision, s.status, s.conflicts, s.resolution, s.push_steps, s.created_at, s.pushed_at,
                   r.justification, r.requested_by
            FROM ztpa.staged_changes s LEFT JOIN ztpa.change_requests r ON r.request_id = s.request_id
            ORDER BY s.created_at DESC""")
    return {"staged": rows}


@app.post("/api/staging/{staged_id}/push")
def staging_push(staged_id: str):
    """Simulated, stepped push. Conflicts are detected with real engine math and
    resolved deterministically; the UI animates the returned steps."""
    with get_conn() as conn, conn.cursor() as cur:
        row = fetch_one(cur, "SELECT * FROM ztpa.staged_changes WHERE staged_id=%s", [staged_id])
        if not row:
            raise HTTPException(404, "staged change not found")
        others = fetch_all(cur, """
            SELECT staged_id, kind, target_tool, payload FROM ztpa.staged_changes
            WHERE target_tool=%s AND staged_id<>%s AND status IN ('staged','pushed')""",
            [row["target_tool"], staged_id])
        plan = staging_mod.build_push_plan(engine(), row, others)
        cur.execute(
            "UPDATE ztpa.staged_changes SET status=%s, conflicts=%s, resolution=%s, push_steps=%s, "
            "pushed_at=now() WHERE staged_id=%s",
            [plan["status"], Jsonb(plan["conflicts"]), Jsonb(plan["resolution"]),
             Jsonb(plan["push_steps"]), staged_id])
        audit(cur, "user", "push_staged_change", subject=staged_id, snapshot_id=row.get("snapshot_id"),
              detail={"status": plan["status"], "target_tool": row.get("target_tool")})
    return {"staged_id": staged_id, **plan}


@app.delete("/api/staging/{staged_id}")
def staging_delete(staged_id: str):
    with get_conn() as conn, conn.cursor() as cur:
        cur.execute("DELETE FROM ztpa.staged_changes WHERE staged_id=%s", [staged_id])
        audit(cur, "user", "discard_staged_change", subject=staged_id, detail={})
    return {"ok": True, "deleted": staged_id}


# --- Admin: tools registry + per-role toggles ------------------------------
@app.get("/api/admin/tools")
def admin_tools(_: None = Depends(require_admin)):
    with get_conn() as conn, conn.cursor() as cur:
        roles_map = {r["tool_key"]: r["enabled_roles"]
                     for r in fetch_all(cur, "SELECT tool_key, enabled_roles FROM ztpa.tool_settings")}
        agg = {r["tool_name"]: r for r in fetch_all(cur, """
            SELECT tool_name, count(*) AS uses, COALESCE(round(avg(latency_ms)),0) AS avg_latency_ms,
                   COALESCE(sum(total_tokens),0) AS total_tokens, COALESCE(sum(est_cost_usd),0) AS est_cost_usd,
                   sum(CASE WHEN ok THEN 0 ELSE 1 END) AS errors, max(ts) AS last_used
            FROM ztpa.ai_metrics GROUP BY tool_name""")}
    out = []
    for t in tools_registry.TOOLS:
        a = agg.get(t["key"], {})
        out.append({**t, "enabled_roles": roles_map.get(t["key"], list(tools_registry.ALL_ROLES)),
                    "metrics": {"uses": int(a.get("uses") or 0), "avg_latency_ms": int(a.get("avg_latency_ms") or 0),
                                "total_tokens": int(a.get("total_tokens") or 0),
                                "est_cost_usd": float(a.get("est_cost_usd") or 0),
                                "errors": int(a.get("errors") or 0), "last_used": a.get("last_used")}})
    return {"tools": out, "roles": list(tools_registry.ALL_ROLES)}


class ToolRolesBody(BaseModel):
    enabled_roles: list[str]


@app.post("/api/admin/tools/{key}")
def admin_set_tool(key: str, body: ToolRolesBody, _: None = Depends(require_admin)):
    if key not in tools_registry.TOOLS_BY_KEY:
        raise HTTPException(404, "unknown tool")
    roles = [r for r in body.enabled_roles if r in tools_registry.ALL_ROLES]
    with get_conn() as conn, conn.cursor() as cur:
        upsert(cur, "tool_settings", {"tool_key": key, "enabled_roles": roles,
               "updated_by": request_ctx.current().email or "admin"}, ["tool_key"])
        audit(cur, "user", "set_tool_roles", subject=key, detail={"enabled_roles": roles})
    tools_registry.invalidate_cache()
    return {"ok": True, "tool_key": key, "enabled_roles": roles}


# --- Admin: KPI / cost dashboard -------------------------------------------
@app.get("/api/admin/metrics")
def admin_metrics(days: int = 30, _: None = Depends(require_admin)):
    days = max(1, min(days, 365))
    with get_conn() as conn, conn.cursor() as cur:
        win = "ts > now() - make_interval(days => %s)"
        totals = fetch_one(cur, f"""
            SELECT count(*) AS calls, COALESCE(sum(total_tokens),0) AS tokens,
                   COALESCE(sum(est_cost_usd),0) AS cost, COALESCE(round(avg(latency_ms)),0) AS avg_latency,
                   sum(CASE WHEN ok THEN 0 ELSE 1 END) AS errors
            FROM ztpa.ai_metrics WHERE {win}""", [days])
        latency = fetch_one(cur, f"""
            SELECT COALESCE(percentile_disc(0.5) WITHIN GROUP (ORDER BY latency_ms),0) AS p50,
                   COALESCE(percentile_disc(0.95) WITHIN GROUP (ORDER BY latency_ms),0) AS p95
            FROM ztpa.ai_metrics WHERE latency_ms IS NOT NULL AND {win}""", [days])
        by_provider = fetch_all(cur, f"""
            SELECT provider, model, count(*) AS calls, COALESCE(sum(total_tokens),0) AS tokens,
                   COALESCE(sum(est_cost_usd),0) AS cost
            FROM ztpa.ai_metrics WHERE {win} GROUP BY provider, model ORDER BY calls DESC""", [days])
        by_capability = fetch_all(cur, f"""
            SELECT capability, count(*) AS calls, COALESCE(sum(total_tokens),0) AS tokens,
                   COALESCE(sum(est_cost_usd),0) AS cost, COALESCE(round(avg(latency_ms)),0) AS avg_latency
            FROM ztpa.ai_metrics WHERE {win} GROUP BY capability ORDER BY calls DESC""", [days])
        by_role = fetch_all(cur, f"""
            SELECT role, count(*) AS calls, COALESCE(sum(total_tokens),0) AS tokens
            FROM ztpa.ai_metrics WHERE {win} GROUP BY role ORDER BY calls DESC""", [days])
        timeseries = fetch_all(cur, f"""
            SELECT to_char(date_trunc('day', ts), 'YYYY-MM-DD') AS day, count(*) AS calls,
                   COALESCE(sum(total_tokens),0) AS tokens, COALESCE(sum(est_cost_usd),0) AS cost
            FROM ztpa.ai_metrics WHERE {win} GROUP BY 1 ORDER BY 1""", [days])
        top_tools = fetch_all(cur, f"""
            SELECT tool_name, count(*) AS uses, COALESCE(sum(total_tokens),0) AS tokens
            FROM ztpa.ai_metrics WHERE {win} GROUP BY tool_name ORDER BY uses DESC LIMIT 8""", [days])
        decisions = fetch_all(cur, "SELECT decision, count(*) AS n FROM ztpa.change_decisions GROUP BY decision")
        staging = fetch_all(cur, "SELECT status, count(*) AS n FROM ztpa.staged_changes GROUP BY status")
        snaps = fetch_one(cur, "SELECT count(*) AS n FROM ztpa.snapshots")
        finds = fetch_one(cur, """
            SELECT count(*) AS findings,
                   COALESCE(sum(CASE WHEN severity_band='critical' THEN 1 ELSE 0 END),0) AS critical
            FROM ztpa.findings WHERE snapshot_id=%s""", [sid()])
    return {
        "days": days,
        "totals": {**totals, "p50_latency": latency["p50"], "p95_latency": latency["p95"]},
        "by_provider": by_provider, "by_capability": by_capability, "by_role": by_role,
        "timeseries": timeseries, "top_tools": top_tools,
        "decisions": {r["decision"]: r["n"] for r in decisions},
        "staging": {r["status"]: r["n"] for r in staging},
        "snapshots": snaps["n"], "findings": finds["findings"], "critical": finds["critical"],
        "active_snapshot": sid(),
    }


class AskBody(BaseModel):
    question: str


@app.post("/api/agent/ask")
def agent(body: AskBody):
    _require_capability("assistant")
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
    _require_capability("report")
    e = engine()
    with get_conn() as conn, conn.cursor() as cur:
        ranked = _ranked_cached(cur)
    return orchestrator.posture_facts(e.findings, e.assets, ranked)


@app.get("/api/report/narrative")
def report_narrative():
    """The slow, board-ready LLM narrative (bounded + fail-closed)."""
    _require_capability("report")
    e = engine()
    with get_conn() as conn, conn.cursor() as cur:
        ranked = _ranked_cached(cur)
    return orchestrator.posture_narrative(e.findings, e.assets, ranked)


class IntakeBody(BaseModel):
    text: str


@app.post("/api/intake")
def intake(body: IntakeBody):
    _require_capability("intake")
    return intake_mod.extract(body.text)


class ProposeBody(BaseModel):
    sample: dict
    tool_hint: str = ""


@app.post("/api/connectors/propose")
def propose_connector(body: ProposeBody):
    _require_capability("authoring")
    return authoring.propose_profile(body.sample, body.tool_hint)


@app.get("/api/audit")
def audit_log():
    with get_conn() as conn, conn.cursor() as cur:
        rows = fetch_all(cur, "SELECT ts,actor,action,subject,detail FROM ztpa.audit_log ORDER BY ts DESC LIMIT 50")
    return {"audit": rows}
