"""Deterministic tools the agent may call (named per the Review Agent doc).

resolve / reachable / effective_policy / find_paths / risk_findings /
simulate_change. Each returns FACTS computed by the engine; the agent never
recomputes them. They operate on an EngineResult passed as `ctx`.
"""

from __future__ import annotations

import time

from .. import request_ctx, tools_registry
from ..change.simulate import simulate_change
from ..graph.reachability import reachable as g_reachable, who_can_reach
from ..metrics import record_metric
from ..models import PolicyRecord
from ..normalizers.common import is_cidr, parse_service


# effective_policy returns one witness path per source; on a real estate that list
# is unbounded, and it goes straight into a prompt. Cap what we render, and report
# the true total next to it so the cap can never read as "that is all there is".
_MAX_WITNESSES = 10


def _canon(ctx, name: str) -> str:
    return ctx.alias_map.get(name, name)


def _display(path: dict | None) -> str | None:
    """One described path -> the arrow string the assistant quotes."""
    return " -> ".join(path["display_path"]) if path else None


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
    """Can src reach dst? The verdict, the paths, and how complete the search was.

    `truncated` is passed straight through from the engine: the path enumeration
    is bounded (`_PATH_SCAN_CAP`), so with it true a `reachable: false` means "no
    path in the candidates examined", not "no path". The assistant is told to say
    that rather than assert an absence it did not establish -- and `path_count`
    sits next to the rendered list for the same reason `effective_policy` reports
    `source_count`: a cap that reads as "that is all there is" is a lie."""
    cs, cd = _canon(ctx, src), _canon(ctx, dst)
    res = g_reachable(ctx.graph, cs, cd, port)
    return {"src": cs, "dst": cd, "port": port, "reachable": res["reachable"],
            "path_count": len(res["paths"]), "truncated": res["truncated"],
            "paths": [" -> ".join(p["display_path"]) for p in res["paths"][:5]]}


def find_paths(ctx, src: str, dst: str) -> dict:
    """Every path src -> dst. Routed through `g_reachable` rather than the
    `find_paths` wrapper purely so the truncation flag survives: the path list is
    identical (find_paths IS the unfiltered path list), but a list that stopped at
    the scan cap must not be handed to a model as if it were exhaustive."""
    cs, cd = _canon(ctx, src), _canon(ctx, dst)
    res = g_reachable(ctx.graph, cs, cd)
    paths = res["paths"]
    return {"src": cs, "dst": cd, "count": len(paths), "truncated": res["truncated"],
            "paths": [{"path": " -> ".join(p["display_path"]), "tools": p["tools"]} for p in paths[:8]]}


def effective_policy(ctx, asset: str) -> dict:
    """What can reach `asset`, each source carrying the witness path that proves it.

    Same `_bfs_witnesses` primitive as `reachable`, so a source appears here iff
    `reachable(source, asset)` is true -- the assistant can call both in one turn
    without contradicting itself. `witness_paths` is capped for prompt size, which
    is why `source_count` reports the full total alongside it.

    `internet_entries` NAMES the internet nodes that reach the asset rather than
    leaving `internet_exposed: true` to be taken on faith. It is not decoration:
    the engine used to answer this question with `"0.0.0.0/0" in sources`, so an
    asset exposed through a named object (``ANY-EXTERNAL``) was reported NOT
    internet-exposed, and the assistant repeated that to an operator. With the
    entries listed, the claim carries the evidence for itself -- and
    `internet_path` is the shortest of them, not the only one.
    """
    key = _canon(ctx, asset)
    res = who_can_reach(ctx.graph, key)
    return {
        "target": key, "target_tags": res["target_tags"],
        "internet_exposed": res["internet_exposed"],
        "internet_entries": res["internet_entries"],
        "internet_path": _display(res["internet_path"]),
        "sources": res["sources"], "source_count": len(res["sources"]),
        "witness_paths": [{"source": w["entry"], "path": _display(w), "tools": w["tools"]}
                          for w in res["witnesses"][:_MAX_WITNESSES]],
    }


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
    delta = simulate_change(ctx.records, ctx.assets, ctx.alias_map, proposed, getattr(ctx, "resolved", ()))
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
        "name": "reachable", "description": "Can src reach dst (optionally on a port)? Returns yes/no + the "
                       "path(s). If truncated is true the path search hit its cap, so a false answer "
                       "means 'no path was found within the search budget', not 'no path exists' -- say so.",
        "parameters": {"type": "object", "properties": {
            "src": {"type": "string"}, "dst": {"type": "string"}, "port": {"type": "integer"}},
            "required": ["src", "dst"]}}},
    {"type": "function", "function": {
        "name": "find_paths", "description": "All paths from src to dst, with the tools each hop crosses. "
                       "If truncated is true the list is the first count paths found, not all of them.",
        "parameters": {"type": "object", "properties": {"src": {"type": "string"}, "dst": {"type": "string"}},
                       "required": ["src", "dst"]}}},
    {"type": "function", "function": {
        "name": "effective_policy",
        "description": "What can actually reach this asset, and is it internet-exposed. Returns every "
                       "source with a witness path proving it, using the same reachability rule as "
                       "`reachable`; witness_paths is capped at 10 (source_count is the true total). "
                       "internet_entries names the internet nodes that reach it -- an estate may spell "
                       "the internet '0.0.0.0/0', 'any' or as a named object, and all of them count.",
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
