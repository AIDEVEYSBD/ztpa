"""Cross-tool reachability + path tracing over the policy graph (networkx).

The differentiator: a chain that traverses a Wiz edge, then a Guardicore edge,
then an AlgoSec edge is just a normal path here. We flag paths that reach a
sensitive asset AND span >= 2 distinct source tools -- the exposure no single
tool can see. Single-tool exposure is intentionally NOT re-derived (each tool
already flags that inside its own domain).
"""

from __future__ import annotations

from itertools import islice

import networkx as nx

from ..normalizers.common import INTERNET_CIDR
from .zones import boundary_label, boundary_multiplier, crosses_boundary

# all_simple_paths is worst-case exponential; cap how many candidates we examine
# per (source,target) so the engine stays bounded at thousands of assets/edges.
_PATH_SCAN_CAP = 4000


def _path_edges(g: nx.DiGraph, path: list[str]):
    return [(path[i], path[i + 1], g[path[i]][path[i + 1]]) for i in range(len(path) - 1)]


def _representative(data: dict) -> dict:
    return sorted(data["grants"], key=lambda gr: (gr["tool"], gr.get("ref") or ""))[0]


def _distinct_tools(g: nx.DiGraph, path: list[str]) -> set[str]:
    tools: set[str] = set()
    for _u, _v, data in _path_edges(g, path):
        tools |= {t for t in data.get("tools", []) if t}
    return tools


def _valid_traversal(g: nx.DiGraph, path: list[str]) -> bool:
    """Reject paths that pivot THROUGH an abstract node (subnet/internet).

    Reaching hosts inside a range does not let you originate as that range, so an
    abstract node may be a path endpoint but never an intermediate hop. (With
    CIDR-membership expansion the concrete hosts in the range would be the real
    pivot nodes; that is the production extension.)
    """
    return all(g.nodes[n].get("kind") == "concrete" for n in path[1:-1])


def describe_path(g: nx.DiGraph, path: list[str]) -> dict:
    edges = _path_edges(g, path)
    hops = []
    for u, v, data in edges:
        rep = _representative(data)
        hops.append({
            "src": u, "dst": v,
            "src_display": g.nodes[u].get("display", u),
            "dst_display": g.nodes[v].get("display", v),
            "tool": rep["tool"], "service": rep["service"], "ref": rep["ref"],
            "tools": data.get("tools", []), "services": data.get("services", []),
        })
    entry, terminal = path[0], path[-1]
    src_zone = g.nodes[entry].get("zone", "internal")
    dst_zone = g.nodes[terminal].get("zone", "internal")
    return {
        "path": list(path),
        "display_path": [g.nodes[n].get("display", n) for n in path],
        "hops": hops,
        "hops_tools": [h["tool"] for h in hops],
        "tools": sorted(_distinct_tools(g, path)),
        "entry": entry,
        "terminal": terminal,
        "terminal_tags": sorted(g.nodes[terminal].get("tags", [])),
        "terminal_service": hops[-1]["service"] if hops else None,
        "boundary": boundary_label(src_zone, dst_zone),
        "boundary_crossed": crosses_boundary(src_zone, dst_zone),
        "boundary_multiplier": boundary_multiplier(src_zone, dst_zone),
        "length": len(edges),
    }


def cross_tool_paths(g: nx.DiGraph, sensitive_tags: set[str],
                     source: str = INTERNET_CIDR, cutoff: int = 8) -> list[dict]:
    """All paths from `source` to any sensitive-tagged asset that span >= 2 tools."""
    if source not in g:
        return []
    targets = sorted(
        n for n, d in g.nodes(data=True)
        if n != source and set(d.get("tags", [])) & sensitive_tags
    )
    out: list[dict] = []
    seen: set[tuple] = set()
    for target in targets:
        if not nx.has_path(g, source, target):
            continue
        for path in islice(nx.all_simple_paths(g, source, target, cutoff=cutoff), _PATH_SCAN_CAP):
            if not _valid_traversal(g, path):
                continue                                  # no pivoting through abstract nodes
            if len(_distinct_tools(g, path)) < 2:
                continue                                  # not cross-tool
            key = tuple(path)
            if key in seen:
                continue
            seen.add(key)
            out.append(describe_path(g, path))
    out.sort(key=lambda d: (d["length"], d["path"]))
    return out


# --- primitives the agent's deterministic tools wrap -----------------------

def reachable(g: nx.DiGraph, src: str, dst: str, port: int | None = None,
              cutoff: int = 8) -> dict:
    """yes/no + the path(s). Honors the directed allow graph (effective policy)."""
    if src not in g or dst not in g or not nx.has_path(g, src, dst):
        return {"reachable": False, "paths": []}
    paths = []
    for path in islice(nx.all_simple_paths(g, src, dst, cutoff=cutoff), _PATH_SCAN_CAP):
        if not _valid_traversal(g, path):
            continue
        desc = describe_path(g, path)
        if port is not None:
            last = desc["hops"][-1] if desc["hops"] else {}
            if f"/{port}" not in (last.get("service") or "") and "any" not in (last.get("service") or ""):
                continue
        paths.append(desc)
    paths.sort(key=lambda d: (d["length"], d["path"]))
    return {"reachable": bool(paths), "paths": paths}


def find_paths(g: nx.DiGraph, src: str, dst: str, cutoff: int = 8) -> list[dict]:
    if src not in g or dst not in g or not nx.has_path(g, src, dst):
        return []
    paths = [describe_path(g, p) for p in islice(nx.all_simple_paths(g, src, dst, cutoff=cutoff), _PATH_SCAN_CAP)
             if _valid_traversal(g, p)]
    paths.sort(key=lambda d: (d["length"], d["path"]))
    return paths


def who_can_reach(g: nx.DiGraph, target: str, cutoff: int = 8) -> dict:
    """effective_policy(asset): which nodes can actually reach `target`, and how."""
    if target not in g:
        return {"target": target, "sources": [], "internet_exposed": False}
    sources = []
    internet_exposed = False
    for n in g.nodes:
        if n == target:
            continue
        if nx.has_path(g, n, target):
            sources.append(n)
            if n == INTERNET_CIDR:
                internet_exposed = True
    return {
        "target": target,
        "target_tags": sorted(g.nodes[target].get("tags", [])),
        "sources": sorted(sources),
        "internet_exposed": internet_exposed,
    }
