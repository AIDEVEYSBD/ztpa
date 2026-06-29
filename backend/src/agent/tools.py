"""Deterministic tools the agent may call (named per the Review Agent doc).

resolve / reachable / effective_policy / find_paths / risk_findings /
simulate_change. Each returns FACTS computed by the engine; the agent never
recomputes them. They operate on an EngineResult passed as `ctx`.
"""

from __future__ import annotations

import time

from .. import request_ctx, tools_registry
from ..change.simulate import simulate_change
from ..graph.reachability import find_paths as g_find_paths, reachable as g_reachable, who_can_reach
from ..metrics import record_metric
from ..models import PolicyRecord
from ..normalizers.common import is_cidr, parse_service


def _canon(ctx, name: str) -> str:
    return ctx.alias_map.get(name, name)


def resolve(ctx, name: str) -> dict:
    key = _canon(ctx, name)
    asset = next((a for a in ctx.assets if a.asset_key == key), None)
    if asset:
        return {"found": True, "asset_key": asset.asset_key, "kind": asset.kind, "tags": asset.tags,
                "ip_set": asset.ip_set, "source_tools": asset.source_tools, "context": asset.context}
    if key in ctx.graph:
        d = ctx.graph.nodes[key]
        return {"found": True, "asset_key": key, "kind": d.get("kind"), "tags": d.get("tags", []),
                "zone": d.get("zone")}
    return {"found": False, "query": name}


def reachable(ctx, src: str, dst: str, port: int | None = None) -> dict:
    cs, cd = _canon(ctx, src), _canon(ctx, dst)
    res = g_reachable(ctx.graph, cs, cd, port)
    return {"src": cs, "dst": cd, "port": port, "reachable": res["reachable"],
            "paths": [" -> ".join(p["display_path"]) for p in res["paths"][:5]]}


def find_paths(ctx, src: str, dst: str) -> dict:
    cs, cd = _canon(ctx, src), _canon(ctx, dst)
    paths = g_find_paths(ctx.graph, cs, cd)
    return {"src": cs, "dst": cd, "count": len(paths),
            "paths": [{"path": " -> ".join(p["display_path"]), "tools": p["tools"]} for p in paths[:8]]}


def effective_policy(ctx, asset: str) -> dict:
    return who_can_reach(ctx.graph, _canon(ctx, asset))


def risk_findings(ctx, type: str | None = None, min_severity: int = 0) -> dict:
    out = []
    for f in ctx.findings:
        if type and f.type != type:
            continue
        if f.severity < min_severity:
            continue
        out.append({"id": f.id, "type": f.type, "title": f.title, "severity": f.severity,
                    "band": f.severity_band, "forced_critical": f.forced_critical})
    return {"count": len(out), "findings": out}


def simulate_change_tool(ctx, source: str, destination: str, service: str, action: str = "allow") -> dict:
    svc = parse_service(service)
    cd = _canon(ctx, destination)
    dest_tags = ctx.graph.nodes[cd]["tags"] if cd in ctx.graph else []
    proposed = PolicyRecord(
        id="adhoc", source_tool="algosec", raw_ref="ADHOC",
        source=source, source_kind="cidr" if is_cidr(source) else "identity",
        destination=destination, destination_kind="cidr" if is_cidr(destination) else "identity",
        dest_tags=dest_tags, service=svc.label, port=svc.port, port_end=svc.port_end,
        protocol=svc.protocol, l7_app=svc.l7_app, l7_source=svc.l7_source, action=action, order=9999,
    )
    delta = simulate_change(ctx.records, ctx.assets, ctx.alias_map, proposed)
    return {"new_paths": [" -> ".join(p["display_path"]) for p in delta["new_paths"]],
            "new_exposed_assets": delta["new_exposed_assets"],
            "boundaries_crossed": delta["boundaries_crossed"],
            "new_over_permissive": delta["new_over_permissive"],
            "would_escalate": delta["forced_escalate"]}


DISPATCH = {
    "resolve": resolve, "reachable": reachable, "find_paths": find_paths,
    "effective_policy": effective_policy, "risk_findings": risk_findings,
    "simulate_change": simulate_change_tool,
}


def dispatch(ctx, name: str, args: dict) -> dict:
    fn = DISPATCH.get(name)
    if fn is None:
        return {"error": f"unknown tool {name}"}
    # Per-role enforcement: a disabled tool fails closed with a clear message the
    # assistant narrates, rather than crashing the loop.
    if not tools_registry.is_enabled(name):
        record_metric(kind="agent_tool", capability="assistant", tool_name=name,
                      provider="engine", model="deterministic", ok=False,
                      error="disabled for role", latency_ms=0)
        return {"error": f"tool '{name}' is disabled for role {request_ctx.role()}", "disabled": True}
    t0 = time.perf_counter()
    try:
        out = fn(ctx, **(args or {}))
        ok, err = True, None
    except Exception as e:  # noqa: BLE001
        out, ok, err = {"error": f"{type(e).__name__}: {e}", "tool": name, "args": args}, False, str(e)
    record_metric(kind="agent_tool", capability="assistant", tool_name=name,
                  provider="engine", model="deterministic",
                  latency_ms=round((time.perf_counter() - t0) * 1000), ok=ok, error=err)
    return out


# OpenAI / Ollama function-calling schemas
SCHEMAS = [
    {"type": "function", "function": {
        "name": "resolve", "description": "Resolve a name or CIDR to its canonical asset (tags, ips, tools, zone).",
        "parameters": {"type": "object", "properties": {"name": {"type": "string"}}, "required": ["name"]}}},
    {"type": "function", "function": {
        "name": "reachable", "description": "Can src reach dst (optionally on a port)? Returns yes/no + the path(s).",
        "parameters": {"type": "object", "properties": {
            "src": {"type": "string"}, "dst": {"type": "string"}, "port": {"type": "integer"}},
            "required": ["src", "dst"]}}},
    {"type": "function", "function": {
        "name": "find_paths", "description": "All paths from src to dst, with the tools each hop crosses.",
        "parameters": {"type": "object", "properties": {"src": {"type": "string"}, "dst": {"type": "string"}},
                       "required": ["src", "dst"]}}},
    {"type": "function", "function": {
        "name": "effective_policy", "description": "What can actually reach this asset, and is it internet-exposed.",
        "parameters": {"type": "object", "properties": {"asset": {"type": "string"}}, "required": ["asset"]}}},
    {"type": "function", "function": {
        "name": "risk_findings", "description": "The deterministic risk findings, optionally filtered by type/min_severity.",
        "parameters": {"type": "object", "properties": {
            "type": {"type": "string", "enum": ["over_permissive", "cidr_overlap", "shadowed_rule", "cross_tool_path"]},
            "min_severity": {"type": "integer"}}}}},
    {"type": "function", "function": {
        "name": "simulate_change", "description": "What delta would adding an allow rule create (new paths/exposure)?",
        "parameters": {"type": "object", "properties": {
            "source": {"type": "string"}, "destination": {"type": "string"}, "service": {"type": "string"},
            "action": {"type": "string", "enum": ["allow", "deny"]}},
            "required": ["source", "destination", "service"]}}},
]
