"""Cross-tool reachability + path tracing over the policy graph (networkx).

The differentiator: a chain that traverses a Wiz edge, then a Guardicore edge,
then an AlgoSec edge is just a normal path here. We flag paths that reach a
sensitive asset AND span >= 2 distinct source tools -- the exposure no single
tool can see. Single-tool exposure is intentionally NOT re-derived (each tool
already flags that inside its own domain).

ONE traversal rule, ONE primitive. Every public function in this module answers
"is there a path?" through `_bfs_witnesses`, which encodes `_valid_traversal`'s
abstract-pivot rule directly in the frontier expansion. `reachable`,
`find_paths` and `who_can_reach` therefore cannot disagree about the same pair
-- they used to, because `who_can_reach` asked `nx.has_path` (no traversal rule
at all) while the other two filtered with `_valid_traversal`, so the assistant
could answer "internet_exposed: true" and "there is no path" about the same
asset in the same turn.

PATH ENUMERATION IS BOUNDED, AND SAYS SO. `all_simple_paths` is worst-case
exponential, so every enumeration stops at `_PATH_SCAN_CAP` candidates. That
bound changes what a negative answer MEANS: "no path was found in the first N
candidates" is not "no path exists". `reachable` therefore reports `truncated`
alongside its verdict, and logs a warning naming the pair, so a caller (the
change gate's force-escalation above all) can tell a proven "no" from an
exhausted scan budget instead of silently trusting the smaller answer.
"""

from __future__ import annotations

import logging

import networkx as nx

from ..normalizers.common import INTERNET_CIDR
from .zones import boundary_label, boundary_multiplier, crosses_boundary

# A child of the API's logger: when app.main is imported this inherits its JSON
# handler (and its propagate=False), so a truncation warning lands in the same
# structured stream, with the same request id, as every other backend event. In
# the engine-only contexts (verify_engine.py, the test suite) it propagates to
# the root logger instead, which is exactly where pytest's caplog can see it.
log = logging.getLogger("npr.api.graph")

# all_simple_paths is worst-case exponential; cap how many candidates we examine
# per (source,target) so the engine stays bounded at thousands of assets/edges.
# NOTE this bounds candidates YIELDED, not the DFS backtracking behind them (the
# audit measured 117s on a 34-node mesh) -- that is a separate, open problem.
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


def _grant_matches(grant: dict, port: int | None, protocol: str | None, app: str | None) -> bool:
    """Structured match of a request against one grant (replaces fragile substring checks)."""
    gproto = grant.get("protocol")
    if gproto == "any":
        return True                                   # wildcard grant matches anything
    if app is not None:
        return (grant.get("l7_app") or "").lower() == app.lower()
    if protocol is not None and protocol != "any" and gproto != protocol:
        return False
    if port is not None:
        start = grant.get("port")
        if start is None:
            return False
        end = grant.get("port_end") if grant.get("port_end") is not None else start
        if not (start <= port <= end):
            return False
    return True


def _edge_matches(data: dict, port: int | None, protocol: str | None, app: str | None) -> bool:
    if port is None and protocol is None and app is None:
        return True
    return any(_grant_matches(gr, port, protocol, app) for gr in data.get("grants", []))


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
            "l7_app": rep.get("l7_app"), "l7_source": rep.get("l7_source"),
            "tools": data.get("tools", []), "services": data.get("services", []),
            "apps": data.get("apps", []),
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
        "terminal_apps": hops[-1]["apps"] if hops else [],
        "boundary": boundary_label(src_zone, dst_zone),
        "boundary_crossed": crosses_boundary(src_zone, dst_zone),
        "boundary_multiplier": boundary_multiplier(src_zone, dst_zone),
        "length": len(edges),
    }


# --- the single traversal primitive ----------------------------------------

def _bfs_witnesses(g: nx.DiGraph, origin: str, cutoff: int, reverse: bool) -> dict[str, list[str]]:
    """Breadth-first search that refuses to EXPAND THROUGH an abstract node.

    This is `_valid_traversal` moved from a post-hoc filter into the frontier
    itself. A node sitting at BFS depth 0 is the path's own endpoint (an abstract
    subnet/internet node is allowed there); a node at depth >= 1 becomes an
    *intermediate* hop the moment we grow the path past it, so it is expanded only
    when concrete. Every path this yields therefore satisfies `_valid_traversal`
    by construction, and every `_valid_traversal`-passing path has a counterpart
    here -- deleting a cycle from a valid walk only removes intermediates, so it
    stays valid, and BFS finds the shortest such simple path.

    `reverse=False` walks successors and returns {dst: path from origin to dst};
    `reverse=True` walks predecessors and returns {src: path from src to origin}.
    Both return paths in real edge direction. Frontier and neighbours are visited
    in sorted order so the chosen witness is deterministic, and `cutoff` bounds
    path LENGTH IN EDGES exactly like networkx's all_simple_paths(cutoff=...).

    O(V+E) -- it replaces an O(V*(V+E)) `nx.has_path`-per-candidate loop.
    """
    step = g.predecessors if reverse else g.successors
    parent: dict[str, str] = {}          # discovered node -> the node it was reached from
    frontier, depth = [origin], 0
    while frontier and depth < cutoff:
        nxt: list[str] = []
        for u in frontier:
            # depth 0 is the origin endpoint; past that, growing the path makes u
            # an intermediate hop, which only a concrete node may be.
            if depth > 0 and g.nodes[u].get("kind") != "concrete":
                continue
            for v in sorted(step(u)):
                if v in parent:
                    continue             # already reached, and BFS got there no later
                parent[v] = u
                nxt.append(v)
        frontier, depth = sorted(nxt), depth + 1

    out: dict[str, list[str]] = {}
    for end in parent:
        chain = [end]
        # Walk back to the origin. `origin` itself is a legitimate key when a cycle
        # returns to it, so the first step is always taken (a zero-edge "path" from
        # a node to itself traverses no grant and is never an answer).
        while len(chain) == 1 or chain[-1] != origin:
            chain.append(parent[chain[-1]])
        out[end] = chain if reverse else chain[::-1]
    return out


def cross_tool_paths(g: nx.DiGraph, sensitive_tags: set[str],
                     source: str = INTERNET_CIDR, cutoff: int = 8) -> list[dict]:
    """All paths from `source` to any sensitive-tagged asset that span >= 2 tools."""
    if source not in g:
        return []
    # One BFS prunes every target with no valid path at all, instead of an
    # nx.has_path call per target that ignores the traversal rule and so let the
    # exponential enumeration run for targets that could never yield a hit.
    valid_targets = _bfs_witnesses(g, source, cutoff, reverse=False)
    targets = sorted(
        n for n, d in g.nodes(data=True)
        if n != source and n in valid_targets and set(d.get("tags", [])) & sensitive_tags
    )
    out: list[dict] = []
    seen: set[tuple] = set()
    for target in targets:
        scanned = 0
        for path in nx.all_simple_paths(g, source, target, cutoff=cutoff):
            if scanned >= _PATH_SCAN_CAP:
                # Cut off mid-target: a cross-tool path may exist beyond here and
                # would simply not be reported -- a MISSING finding, which is the
                # silent direction. There is no witness to fall back on (the BFS
                # witness need not be cross-tool), so the only honest thing to do
                # is say it out loud.
                log.warning("cross-tool path scan truncated; findings for this target may be incomplete",
                            extra={"event": "path_scan_truncated", "fn": "cross_tool_paths",
                                   "source": source, "target": target, "cap": _PATH_SCAN_CAP})
                break
            scanned += 1
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
              protocol: str | None = None, app: str | None = None, cutoff: int = 8) -> dict:
    """yes/no + the path(s) + whether the search was cut short.

    Returns `{"reachable": bool, "paths": [...], "truncated": bool}`. Honors the
    directed allow graph (effective policy).

    An optional port/protocol/app filter is applied to the LAST hop (the grant
    into the destination) using structured grant matching -- so "is db-prod-01
    reachable over QUIC?" is answerable, not just "on port 443".

    THE YES/NO COMES FROM `_bfs_witnesses`, the same primitive `who_can_reach`
    uses, so the two tools agree by construction rather than by coincidence. The
    enumeration below only decides WHICH paths to show, and it is bounded by
    `_PATH_SCAN_CAP`; when it ends with nothing to show we cite the BFS witness
    instead of reporting "no path" for something the primitive just proved
    reachable. That fallback covers two real cases, not one:

      * the cap cut the enumeration off before a valid path turned up, and
      * `src is dst` on a CYCLE, where `all_simple_paths` can only ever yield the
        zero-edge path `[src]` -- which traverses no grant, so it is dropped --
        while a genuine allow chain does return to the node.

    `truncated` is the honest half of the answer: with it True, a False verdict
    means "no path in the first _PATH_SCAN_CAP candidates", NOT "no path". It
    matters because `find_paths` feeds `simulate_change._internet_sensitive_paths`,
    so on a large estate a silently-shrunken path set can flip the change gate's
    force-escalation from escalate to auto-approve.
    """
    if src not in g or dst not in g:
        return {"reachable": False, "paths": [], "truncated": False}
    witnesses = _bfs_witnesses(g, src, cutoff, reverse=False)
    if dst not in witnesses:
        # The BFS is exhaustive under the traversal rule, so this "no" is proven,
        # not merely unfound: nothing was truncated to reach it.
        return {"reachable": False, "paths": [], "truncated": False}
    filtered = port is not None or protocol is not None or app is not None
    paths = []
    truncated = False
    scanned = 0
    for path in nx.all_simple_paths(g, src, dst, cutoff=cutoff):
        if scanned >= _PATH_SCAN_CAP:
            truncated = True
            break
        scanned += 1
        if len(path) < 2 or not _valid_traversal(g, path):
            continue                                      # len 1 == src is dst: no grant traversed
        if filtered and not _edge_matches(g[path[-2]][path[-1]], port, protocol, app):
            continue
        paths.append(describe_path(g, path))
    if truncated:
        # WARNING, not debug: from here on the path list is a sample, and the
        # answer built from it is the smaller of two possible answers.
        log.warning("path enumeration truncated at the scan cap",
                    extra={"event": "path_scan_truncated", "fn": "reachable", "src": src, "dst": dst,
                           "cap": _PATH_SCAN_CAP, "shown": len(paths), "filtered": filtered})
    if not paths:
        # The witness is a real, rule-abiding walk of >= 1 grant. Unfiltered it is
        # always citable; under a filter it only answers the question asked if its
        # own last hop matches, and when it does not we return False WITH
        # `truncated` set, so the caller reads "not found within budget" rather
        # than a proof of absence. (Under a filter with nothing truncated, the
        # only witness this can add is a cyclic src==dst one -- every other
        # witness is a simple path, so a complete enumeration already tested it.)
        witness = witnesses[dst]
        if not filtered or _edge_matches(g[witness[-2]][witness[-1]], port, protocol, app):
            paths = [describe_path(g, witness)]
    paths.sort(key=lambda d: (d["length"], d["path"]))
    return {"reachable": bool(paths), "paths": paths, "truncated": truncated}


def find_paths(g: nx.DiGraph, src: str, dst: str, cutoff: int = 8) -> list[dict]:
    """Every valid path src -> dst. Deliberately just the unfiltered `reachable`
    path list, so `bool(find_paths(...)) == reachable(...)['reachable']` always.

    The list can be TRUNCATED (see `reachable`): a caller that needs to know
    whether it is looking at every path or at the first `_PATH_SCAN_CAP` of them
    must call `reachable` and read `truncated`. Truncation is also logged."""
    return reachable(g, src, dst, cutoff=cutoff)["paths"]


def who_can_reach(g: nx.DiGraph, target: str, cutoff: int = 8) -> dict:
    """effective_policy(asset): which nodes can actually reach `target`, and how.

    A reverse `_bfs_witnesses` walk, so "actually" now means what it says: a
    source is listed iff `reachable(source, target)` is true, and each source
    ships the WITNESS PATH that proves it -- the assistant cites a concrete chain
    of grants instead of asserting exposure it cannot show. `internet_exposed` is
    exactly "the internet node is one of those sources", not a bare path-existence
    check that would count an unusable pivot through a subnet object.
    """
    if target not in g:
        return {"target": target, "target_tags": [], "sources": [],
                "witnesses": [], "internet_exposed": False, "internet_path": None}
    witnesses = _bfs_witnesses(g, target, cutoff, reverse=True)
    described = sorted((describe_path(g, p) for p in witnesses.values()),
                       key=lambda d: (d["length"], d["path"]))
    return {
        "target": target,
        "target_tags": sorted(g.nodes[target].get("tags", [])),
        "sources": sorted(witnesses),
        "witnesses": described,
        "internet_exposed": INTERNET_CIDR in witnesses,
        "internet_path": describe_path(g, witnesses[INTERNET_CIDR]) if INTERNET_CIDR in witnesses else None,
    }
