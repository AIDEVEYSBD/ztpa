"""Rule shadowing: a later rule that can never fire because an earlier rule
(broader-or-equal source, same dest, overlapping service) matches first.

A shadowed DENY is dangerous (traffic you meant to block is actually allowed) ->
scored on the effective exposure. A shadowed ALLOW is dead config -> low fixed.
"""

from __future__ import annotations

import ipaddress

import networkx as nx

from ..graph.zones import zone_of
from ..models import Finding, PolicyRecord
from .severity import band, score_shadowed


def _src_net(rec: PolicyRecord):
    if rec.source_kind != "cidr":
        return None
    try:
        return ipaddress.ip_network(rec.source, strict=False)
    except ValueError:
        return None


def _service_overlaps(a: PolicyRecord, b: PolicyRecord) -> bool:
    return a.protocol == "any" or b.protocol == "any" or a.service == b.service


def _covers(earlier: PolicyRecord, later: PolicyRecord) -> bool:
    en, ln = _src_net(earlier), _src_net(later)
    if en is not None and ln is not None:
        return ln.subnet_of(en)
    if earlier.source_kind == "identity" and later.source_kind == "identity":
        return earlier.source == later.source
    return False


def analyze(records: list[PolicyRecord], g: nx.DiGraph, alias_map: dict[str, str]) -> list[Finding]:
    by_tool: dict[str, list[PolicyRecord]] = {}
    for rec in records:
        if rec.order is None:
            continue
        by_tool.setdefault(rec.source_tool, []).append(rec)

    findings: list[Finding] = []
    for tool, recs in by_tool.items():
        recs = sorted(recs, key=lambda r: (r.order, r.raw_ref))
        for i, later in enumerate(recs):
            for earlier in recs[:i]:
                if alias_map.get(earlier.destination, earlier.destination) != \
                        alias_map.get(later.destination, later.destination):
                    continue
                if not _service_overlaps(earlier, later) or not _covers(earlier, later):
                    continue

                d = alias_map.get(later.destination, later.destination)
                s = alias_map.get(later.source, later.source)
                dst_zone = g.nodes[d]["zone"] if d in g else zone_of(d, later.dest_tags)
                src_zone = g.nodes[s]["zone"] if s in g else zone_of(s, [])
                sc = score_shadowed(
                    shadowed_action=later.action, source=later.source,
                    source_kind=later.source_kind, protocol=later.protocol, port=later.port,
                    dest_tags=later.dest_tags, src_zone=src_zone, dst_zone=dst_zone,
                )
                dest_display = g.nodes[d]["display"] if d in g else d
                if later.action == "deny":
                    title = f"Dead deny on {dest_display}: blocked traffic is actually allowed"
                    reason = (f"deny {later.source} -> {dest_display} ({later.service}) never fires; earlier "
                              f"allow {earlier.raw_ref} ({earlier.source}) already permits it")
                else:
                    title = f"Dead allow on {dest_display}: redundant rule never adds anything"
                    reason = (f"allow {later.source} -> {dest_display} ({later.service}) is redundant; earlier "
                              f"rule {earlier.raw_ref} ({earlier.source}) already covers it")
                findings.append(Finding(
                    id=f"shadowed_rule|{tool}|{later.raw_ref}",
                    type="shadowed_rule", title=title,
                    severity=sc["severity"], severity_band=band(sc["severity"]), forced_critical=False,
                    signals={
                        "shadowed_ref": later.raw_ref, "shadowing_ref": earlier.raw_ref, "reason": reason,
                        "shadowed_action": later.action, "shadowing_action": earlier.action,
                        "dest": d, "service": later.service, "tool": tool,
                        "severity_vector": sc["vector"],
                    },
                    involved=[s, d], raw_refs=sorted([earlier.raw_ref, later.raw_ref]),
                    source_tools=[tool],
                ))
                break   # earliest shadower is enough
    return findings
