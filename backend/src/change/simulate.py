"""Apply a proposed change to a COPY of the graph and compute the DELTA.

The change is never classified in isolation -- the engine first computes what
newly becomes reachable, then the model judges THAT. All of this is deterministic
(no model): new internet->sensitive paths, newly exposed sensitive assets,
trust boundaries newly crossed, and any over-permissive pattern the rule itself
introduces. A guardrail force-escalates the catastrophic patterns up front.
"""

from __future__ import annotations

from ..analyzers.over_permissive import _reasons as _overpermissive_reasons
from ..analyzers.severity import dest_score, exposure_score, port_score, score_over_permissive
from ..config import SENSITIVE_TAGS
from ..graph.build import build_graph
from ..graph.reachability import find_paths
from ..graph.zones import boundary_label, crosses_boundary, zone_of
from ..models import Asset, PolicyRecord


def _internet_sensitive_paths(g) -> dict[tuple, dict]:
    targets = sorted(n for n, d in g.nodes(data=True) if set(d.get("tags", [])) & SENSITIVE_TAGS)
    out: dict[tuple, dict] = {}
    for t in targets:
        for p in find_paths(g, "0.0.0.0/0", t):
            out[tuple(p["path"])] = p
    return out


def _proposed_summary(p: PolicyRecord) -> dict:
    return {
        "source": p.source, "source_kind": p.source_kind, "destination": p.destination,
        "service": p.service, "protocol": p.protocol, "action": p.action,
    }


def simulate_change(records: list[PolicyRecord], assets: list[Asset], alias_map: dict[str, str],
                    proposed: PolicyRecord) -> dict:
    base_graph = build_graph(records, assets, alias_map)
    new_graph = build_graph(records + [proposed], assets, alias_map)

    before = _internet_sensitive_paths(base_graph)
    after = _internet_sensitive_paths(new_graph)
    new_paths = [p for key, p in after.items() if key not in before]
    new_exposed = sorted({p["terminal"] for p in new_paths})

    E = exposure_score(proposed.source, proposed.source_kind)
    P, _ = port_score(proposed.protocol, proposed.port)
    dest_score(proposed.dest_tags)  # validated but boundary uses graph zones below
    s = alias_map.get(proposed.source, proposed.source)
    d = alias_map.get(proposed.destination, proposed.destination)
    src_zone = new_graph.nodes[s]["zone"] if s in new_graph else zone_of(s, [])
    dst_zone = new_graph.nodes[d]["zone"] if d in new_graph else zone_of(d, proposed.dest_tags)
    proposed_crosses = crosses_boundary(src_zone, dst_zone)
    op_reasons = _overpermissive_reasons(proposed, E, P)
    sc = score_over_permissive(
        source=proposed.source, source_kind=proposed.source_kind, protocol=proposed.protocol,
        port=proposed.port, dest_tags=proposed.dest_tags, src_zone=src_zone, dst_zone=dst_zone,
    )

    boundaries = sorted({p["boundary"] for p in new_paths if p["boundary_crossed"]})
    if proposed_crosses:
        boundaries = sorted(set(boundaries) | {boundary_label(src_zone, dst_zone)})

    forced_reasons: list[str] = []
    if new_paths:
        forced_reasons.append(
            f"opens {len(new_paths)} new internet path(s) reaching sensitive asset(s): {', '.join(new_exposed)}")
    forced_reasons += sc["forced_reasons"]
    if proposed.protocol == "any":
        forced_reasons.append("introduces an any/any rule")
    if E >= 1.0 and dst_zone == "internal":
        forced_reasons.append("creates new internet->internal exposure")
    # de-dupe, preserve order
    seen: set[str] = set()
    forced_reasons = [r for r in forced_reasons if not (r in seen or seen.add(r))]

    return {
        "proposed": _proposed_summary(proposed),
        "new_paths": [{"display_path": p["display_path"], "tools": p["tools"],
                       "terminal": p["terminal"], "terminal_tags": p["terminal_tags"],
                       "boundary": p["boundary"]} for p in new_paths],
        "new_exposed_assets": new_exposed,
        "boundaries_crossed": boundaries,
        "new_over_permissive": op_reasons,
        "proposed_boundary": boundary_label(src_zone, dst_zone),
        "proposed_crosses_boundary": proposed_crosses,
        "forced_escalate": bool(forced_reasons),
        "forced_reasons": forced_reasons,
    }
