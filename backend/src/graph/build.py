"""Build the directed policy graph from canonical records + the asset layer.

Nodes are canonical assets (names unified across tools via alias_map, so Wiz's
"appsrv-07" and AlgoSec's "app-server-07" are ONE node). Edges are allowed
connections carrying every grant's service/port + originating tool + rule ref
(provenance). Parallel grants between two nodes are kept as a list, not collapsed.

Effective policy note: for the demo the only deny (a shadowed deny) does not
override any allow, so the union of allow edges equals the effective policy. The
shadowing analyzer surfaces the dead deny; a non-shadowed deny that removed an
allow would be subtracted here in production (deny-precedence by first-match).
"""

from __future__ import annotations

import networkx as nx

from ..models import Asset, PolicyRecord
from ..normalizers.common import INTERNET_CIDR
from .zones import zone_of


def build_graph(records: list[PolicyRecord], assets: list[Asset],
                alias_map: dict[str, str]) -> nx.DiGraph:
    g = nx.DiGraph()
    for a in assets:
        g.add_node(
            a.asset_key,
            kind=a.kind,
            tags=list(a.tags),
            ip_set=list(a.ip_set),
            display=a.display_name or a.asset_key,
            zone=zone_of(a.asset_key, a.tags),
            tools=list(a.source_tools),
        )

    def canon(name: str) -> str:
        return alias_map.get(name, name)

    def ensure(name: str) -> None:
        if name not in g:
            g.add_node(name, kind="abstract", tags=[], ip_set=[], display=name,
                       zone=zone_of(name, []), tools=[])

    for r in records:
        if r.action != "allow":
            continue
        s, d = canon(r.source), canon(r.destination)
        ensure(s)
        ensure(d)
        grant = {"service": r.service, "port": r.port, "protocol": r.protocol,
                 "tool": r.source_tool, "ref": r.raw_ref}
        if g.has_edge(s, d):
            data = g[s][d]
            data["grants"].append(grant)
            data["tools"] = sorted(set(data["tools"]) | {r.source_tool})
            data["services"] = sorted(set(data["services"]) | {r.service})
        else:
            g.add_edge(s, d, grants=[grant], tools=[r.source_tool], services=[r.service])
    return g


def node_db_kind(node_key: str, asset_kind: str) -> str:
    """Map to the graph_nodes.kind CHECK domain."""
    if node_key == INTERNET_CIDR:
        return "internet"
    if asset_kind == "abstract":
        return "subnet"
    return "asset"


def sensitive_assets(g: nx.DiGraph, sensitive_tags: set[str]) -> list[str]:
    """Concrete nodes carrying a sensitive tag (sorted, deterministic)."""
    out = [n for n, data in g.nodes(data=True) if set(data.get("tags", [])) & sensitive_tags]
    return sorted(out)
