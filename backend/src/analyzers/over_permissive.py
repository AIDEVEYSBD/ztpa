"""Over-permissive detection: rules that allow more than they should.

Flags any/any, broad source ranges, and admin/data ports or sensitive
destinations exposed too widely. Each flagged rule is scored by the full
severity formula; the guardrail floor force-marks the catastrophic ones.
"""

from __future__ import annotations

import networkx as nx

from ..config import OVERPERMISSIVE_CONFIG, PORT_NAMES, SENSITIVE_TAGS
from ..graph.zones import crosses_boundary, zone_of
from ..models import Finding, PolicyRecord
from .severity import (
    band, dest_score, exposure_score, port_score, prefixlen_of, score_over_permissive,
)


def _reasons(rec: PolicyRecord, E: float, P: float) -> list[str]:
    cfg = OVERPERMISSIVE_CONFIG
    is_internet = E >= 1.0
    sensitive = bool(set(rec.dest_tags) & SENSITIVE_TAGS)
    out: list[str] = []
    if rec.protocol == "any":
        out.append("allows every protocol and port (any/any)")
    if is_internet and (P >= cfg["admin_data_min_P"] or sensitive):
        out.append("exposed directly to the internet")
    if sensitive and E >= cfg["sensitive_dest_min_E"]:
        out.append("regulated destination reachable from more than a single host")
    if P >= cfg["admin_data_min_P"] and E >= cfg["broad_source_E"]:
        out.append("admin/data port open to a broad source range")
    return out


def analyze(records: list[PolicyRecord], g: nx.DiGraph, alias_map: dict[str, str]) -> list[Finding]:
    findings: list[Finding] = []
    for rec in records:
        if rec.action != "allow":
            continue
        E = exposure_score(rec.source, rec.source_kind)
        P, _ = port_score(rec.protocol, rec.port)
        D = dest_score(rec.dest_tags)
        reasons = _reasons(rec, E, P)
        if not reasons:
            continue

        s = alias_map.get(rec.source, rec.source)
        d = alias_map.get(rec.destination, rec.destination)
        src_zone = g.nodes[s]["zone"] if s in g else zone_of(s, [])
        dst_zone = g.nodes[d]["zone"] if d in g else zone_of(d, rec.dest_tags)
        sc = score_over_permissive(
            source=rec.source, source_kind=rec.source_kind, protocol=rec.protocol,
            port=rec.port, dest_tags=rec.dest_tags, src_zone=src_zone, dst_zone=dst_zone,
        )
        dest_display = g.nodes[d]["display"] if d in g else d
        port_name = PORT_NAMES.get(rec.port) if rec.port else None
        access = "any protocol/port" if rec.protocol == "any" else (port_name or rec.service)
        src_label = "the internet" if E >= 1.0 else rec.source
        signals = {
            "exposed_port": rec.port, "port_name": port_name, "service": rec.service,
            "protocol": rec.protocol, "source": rec.source, "source_kind": rec.source_kind,
            "source_scope": rec.source if rec.source_kind == "cidr" else "identity",
            "source_prefixlen": prefixlen_of(rec.source, rec.source_kind),
            "dest": d, "dest_display": dest_display, "dest_tags": sorted(rec.dest_tags),
            "src_zone": src_zone, "dst_zone": dst_zone,
            "boundary_crossed": crosses_boundary(src_zone, dst_zone),
            "port_class": sc["port_class"], "reasons": reasons,
            "forced_reasons": sc["forced_reasons"], "severity_vector": sc["vector"],
            "tool": rec.source_tool, "raw_ref": rec.raw_ref,
        }
        findings.append(Finding(
            id=f"over_permissive|{rec.source_tool}|{rec.raw_ref}",
            type="over_permissive",
            title=f"{access} open from {src_label} to {dest_display}",
            severity=sc["severity"],
            severity_band="critical" if sc["forced_critical"] else band(sc["severity"]),
            forced_critical=sc["forced_critical"],
            signals=signals, involved=[s, d], raw_refs=[rec.raw_ref], source_tools=[rec.source_tool],
        ))
    return findings
