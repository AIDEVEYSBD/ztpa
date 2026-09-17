"""The packet walk: one flow, hop by hop, before and after a proposed change.

WHAT THIS IS, AND WHAT IT IS NOT
--------------------------------
This is a SIMULATION OVER THE OBSERVED ESTATE. It walks the effective-policy
graph the engine built from the consoles' own exports, and at each hop it names
the rule that permits the step and the console that reported that rule. Run it
again with a rule removed and it stops at the hop the removal closed.

It is NOT emulation. Nothing boots, no image runs, no packet is forwarded. It
cannot tell you that a FortiGate's parser accepts the config you are about to
paste, and it must never be labelled as if it could -- `METHOD_DETAIL` below is
the sentence the console renders, and it says so.

What it can do that an emulator cannot is the reason it exists. The demo's
headline exposure runs Internet -> lb-public-01 -> app-server-07 ->
internal-app-01 -> db-prod-01, and the four grants on it come from three
different consoles. No single device sees that chain, so no single device can be
booted to test it. The effective-policy graph is the only place it exists.

THE HONESTY RULES, which are the whole point
--------------------------------------------
1. A hop is only drawn where a grant was OBSERVED. This walk never infers a step
   from adjacency: a cable is not a grant.
2. When the flow still gets through after the change by a DIFFERENT route, that
   is reported as loudly as the closed hop. A walk that showed only the hop it
   closed would be an advert, not evidence -- and in the seeded demo it would be
   actively misleading, because cutting the chain's last grant leaves ALGO-002
   (RDP straight off the internet) reaching the same database.
3. `truncated` is carried through from `find_paths`. With it set, "no surviving
   path" means "none in the first N candidates", and the caller must not round
   that up to "closed".
"""

from __future__ import annotations

from typing import Any

import networkx as nx

from ..graph.reachability import _path_edges, _representative, find_paths

#: Rendered verbatim by the console beside the walk. Kept here, next to the code
#: that earns it, rather than in the UI where it would drift from the method.
METHOD = "policy-graph walk"
METHOD_DETAIL = (
    "each hop is an allow rule a console actually reported, replayed over the "
    "effective-policy graph with the change applied. Simulated against the "
    "observed estate, not emulated on device firmware."
)


def _hops(g: nx.DiGraph, path: list[str]) -> list[dict[str, Any]]:
    """One row per grant traversed, in order, each naming its rule and console."""
    out: list[dict[str, Any]] = []
    for i, (u, v, data) in enumerate(_path_edges(g, path), 1):
        rep = _representative(data)
        out.append({
            "n": i,
            "src": u,
            "dst": v,
            "src_display": g.nodes[u].get("display", u),
            "dst_display": g.nodes[v].get("display", v),
            "service": rep["service"],
            "ref": rep["ref"],
            "tool": rep["tool"],
            # Every grant on the edge, not just the representative: an operator
            # about to cut `ref` needs to see that three other rules permit the
            # same step, which is exactly the covering-twin trap.
            "also_granted_by": sorted({str(x.get("ref")) for x in data.get("grants", [])} - {rep["ref"]}),
            "verdict": "pass",
        })
    return out


def _blocked_at(before: list[dict[str, Any]], g_after: nx.DiGraph) -> int | None:
    """The 1-based hop number the change closed, or None if the walk survives.

    Walks the ORIGINAL hop list against the NEW graph and returns the first step
    that no longer has an edge. Deliberately not "recompute the shortest path
    and diff": the reader is being shown the chain they already read, with the
    step that broke marked in place.
    """
    for h in before:
        if not g_after.has_edge(h["src"], h["dst"]):
            return h["n"]
    return None


def walk(g_before: nx.DiGraph, g_after: nx.DiGraph, path: list[str],
         cutoff: int = 8) -> dict[str, Any]:
    """The before/after readout for one path. Pure; no I/O, no model.

    `g_after` is the graph rebuilt from the record set with the change applied.
    Both graphs are passed in rather than rebuilt here so the caller controls the
    (expensive) rebuild and the two are guaranteed to differ only by the change.
    """
    before = _hops(g_before, path)
    if not before:
        return {"method": METHOD, "method_detail": METHOD_DETAIL,
                "flow": None, "before": [], "blocked_at": None,
                "still_reachable": False, "survivors": [], "truncated": False}

    blocked = _blocked_at(before, g_after)

    # Does the FLOW still complete, by any route? This is rule 2, and it is the
    # half a demo is tempted to leave out.
    src, dst = path[0], path[-1]
    survivors: list[dict[str, Any]] = []
    truncated = False
    if src in g_after and dst in g_after:
        found = find_paths(g_after, src, dst, cutoff=cutoff)
        for p in found:
            nodes = p["path"] if isinstance(p, dict) else list(p)
            if nodes == list(path):
                continue                      # the chain we just cut, if intact
            survivors.append({
                "display_path": [g_after.nodes[n].get("display", n) for n in nodes],
                "hops": _hops(g_after, nodes),
            })
            truncated = truncated or bool(isinstance(p, dict) and p.get("truncated"))

    return {
        "method": METHOD,
        "method_detail": METHOD_DETAIL,
        "flow": {
            "src_display": before[0]["src_display"],
            "dst_display": before[-1]["dst_display"],
            "service": before[-1]["service"],
        },
        "before": before,
        # 1-based hop number, or None when the change does not touch this chain.
        "blocked_at": blocked,
        # The load-bearing field. True means: this exact chain may be cut, and
        # the destination is STILL reachable from the same origin by another
        # route the consoles reported.
        "still_reachable": bool(survivors),
        "survivors": survivors,
        "truncated": truncated,
    }
