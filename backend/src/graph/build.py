"""Build the directed policy graph from canonical records + the asset layer.

Nodes are canonical assets (names unified across tools via alias_map, so Wiz's
"appsrv-07" and AlgoSec's "app-server-07" are ONE node). Edges are allowed
connections carrying every grant's service/port + originating tool + rule ref
(provenance). Parallel grants between two nodes are kept as a list, not collapsed.

Node identity is the contract with the traversal filter
------------------------------------------------------
Two node attributes are read by code far away from here and must therefore be
derived here, once, from the same facts:

  ``kind``  "concrete" | "abstract". `graph.reachability._valid_traversal`
            rejects any path that PIVOTS THROUGH an abstract node — reaching
            hosts inside a range does not let you originate as that range — so
            this attribute decides which paths exist. It is copied straight off
            `Asset.kind`, which the identity layer folds from the normalizers'
            `ObservedEntity.abstract`. The audit's finding (algosec.py:31) was
            that a named ``network`` object came through as concrete while the
            identical block written as a raw CIDR came through as abstract, so
            the flagship path pivoted through a /16 purely because the export
            happened to name it. The fix belongs in the normalizers; what this
            module owns is not re-deciding, re-defaulting or dropping the flag
            on the way onto the node.

  ``zone``  the trust zone, from `zones.zone_of`, which is now given the node's
            resolved address space (`Asset.ip_set`) and kind as well as its key
            — so a named object resolving to ``0.0.0.0/0`` lands in the same
            zone, with the same boundary multiplier, as the literal string.

Effective policy note: for the demo the only deny (a shadowed deny) does not
override any allow, so the union of allow edges equals the effective policy. The
shadowing analyzer surfaces the dead deny; a non-shadowed deny that removed an
allow would be subtracted here in production (deny-precedence by first-match).
"""

from __future__ import annotations

import networkx as nx

from ..models import Asset, PolicyRecord
from ..netaddr import is_public, parse_net
from .zones import zone_of


def build_graph(records: list[PolicyRecord], assets: list[Asset],
                alias_map: dict[str, str]) -> nx.DiGraph:
    g = nx.DiGraph()
    for a in assets:
        g.add_node(
            a.asset_key,
            # Copied, never re-derived: the identity layer already folded every
            # tool's view of this node into one abstract/concrete verdict, and a
            # second opinion here would let the graph and `_valid_traversal`
            # disagree about the same node.
            kind=a.kind,
            tags=list(a.tags),
            ip_set=list(a.ip_set),
            display=a.display_name or a.asset_key,
            # ip_set + kind are what let a NAMED network object classify like
            # the CIDR it dereferences to (and stop a concrete host that happens
            # to hold a public IP from being classified as the internet).
            zone=zone_of(a.asset_key, a.tags, a.ip_set, a.kind),
            tools=list(a.source_tools),
        )

    def canon(name: str) -> str:
        return alias_map.get(name, name)

    def ensure(name: str, resolved: list[str] | None = None) -> None:
        """Create a node for a record endpoint the identity layer never saw.

        Reachable only when a normalizer emitted a record referencing a token it
        emitted no ObservedEntity for — malformed or partial input, or a
        change-gate proposal naming something outside the current snapshot.

        Three deliberate decisions:

        * If the token IS address space, the node is given that address space,
          canonicalized, so it is indistinguishable from the asset-backed node
          for the same block: same ``kind``, same ``ip_set``, same ``zone``.
          Without it, ``ensure("0.0.0.0/1")`` produced a zone-less internal node
          while the asset-backed ``0.0.0.0/1`` was ZONE_INTERNET.
        * If the token is a NAME, `resolved` — the record's own
          ``source_cidrs``/``dest_cidrs`` — is the address space it denotes, and
          it is used for exactly the same reason: ``ANY-EXTERNAL`` resolving to
          ``0.0.0.0/0`` must land in the zone the literal string lands in. The
          record already carries this fact; without it the zone layer was the one
          place in the engine that never got to see it, so the boundary
          multiplier disagreed with the exposure score about the same rule.
        * An unresolvable LABEL stays ``abstract``. We have no evidence it is a
          host, and abstract is the fail-closed answer: `_valid_traversal` will
          refuse to pivot through it rather than invent a path through a node
          nothing in the input describes. Fabricated reachability is the one
          error a security tool cannot ship.
        """
        if name in g:
            return
        net = parse_net(name)
        # Canonical form (``10.0.0.1/24`` -> ``10.0.0.0/24``), matching
        # PolicyRecord._canonicalize_cidrs, so one block is one string. The
        # record's resolved space is already canonical (same validator) and is
        # sorted here only so the node cannot depend on record order.
        ip_set = [str(net)] if net is not None else sorted(resolved or ())
        g.add_node(name, kind="abstract", tags=[], ip_set=ip_set, display=name,
                   zone=zone_of(name, [], ip_set, "abstract"), tools=[])

    for r in records:
        # Deny precedence is NOT implemented: the effective policy modelled here
        # is the union of allow edges. This is a disclosed simplification
        # (docs/ENGINE.md §10.1) and is Phase 3 scope — first-match deny
        # subtraction needs rule order across devices, which the record model
        # does not yet carry. Left deliberately untouched.
        if r.action != "allow":
            continue
        s, d = canon(r.source), canon(r.destination)
        ensure(s, r.source_cidrs)
        ensure(d, r.dest_cidrs)
        grant = {"service": r.service, "port": r.port, "port_end": r.port_end, "protocol": r.protocol,
                 "l7_app": r.l7_app, "l7_source": r.l7_source, "tool": r.source_tool, "ref": r.raw_ref}
        apps = {r.l7_app} if r.l7_app else set()
        if g.has_edge(s, d):
            data = g[s][d]
            data["grants"].append(grant)
            data["tools"] = sorted(set(data["tools"]) | {r.source_tool})
            data["services"] = sorted(set(data["services"]) | {r.service})
            data["apps"] = sorted(set(data.get("apps", [])) | apps)
        else:
            g.add_edge(s, d, grants=[grant], tools=[r.source_tool], services=[r.service],
                       apps=sorted(apps))
    return g


def node_db_kind(node_key: str, asset_kind: str) -> str:
    """Map a graph node onto the `graph_nodes.kind` CHECK domain.

    The same classification `zones.zone_of` makes, expressed in the DB's
    vocabulary, so a persisted row cannot contradict the zone the engine scored
    with. It used to compare the key against the literal ``0.0.0.0/0``, which
    filed ``0.0.0.0/1`` — half the routable internet — as an ordinary subnet.

    `is_public` covers the wildcard vocabulary too (``any``/``all``/``*``), and
    the concrete short-circuit is the same rule as in `zone_of`: a host holding a
    public address is an asset, not the internet.
    """
    if asset_kind != "concrete" and is_public(node_key):
        return "internet"
    if asset_kind == "abstract":
        return "subnet"
    return "asset"


def sensitive_assets(g: nx.DiGraph, sensitive_tags: set[str]) -> list[str]:
    """Nodes carrying a sensitive tag (sorted, deterministic).

    Not filtered to concrete nodes on purpose: a regulated *segment* is in
    regulatory scope exactly like a regulated host, and this list is what the
    report prints as "regulated assets in scope".
    """
    out = [n for n, data in g.nodes(data=True) if set(data.get("tags", [])) & sensitive_tags]
    return sorted(out)
