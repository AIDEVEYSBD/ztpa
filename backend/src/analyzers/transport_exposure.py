"""Transport- / application-layer exposure: the risk class legacy single-console
tools miss because they reason about ports, not applications.

Two deterministic checks, both over decoded L7 facts (PolicyRecord.l7_app):

  1. quic_blind_spot      -- an allow on an uninspectable app (QUIC / HTTP-3 /
                            DNS-over-QUIC). These ride UDP and/or encrypt their
                            handshake, so legacy firewalls cannot inspect them; a
                            reachable allow is an inspection blind spot.
  2. tls_fallback_not_blocked -- a destination reachable on BOTH tcp/443 and
                            udp/443. An inspectable TLS path exists, yet QUIC can
                            silently win, so inspection cannot be forced.

No model, no randomness -- pure lookups over the canonical records + graph.
"""

from __future__ import annotations

import networkx as nx

from ..config import INSPECTION_BLIND_APPS, TRANSPORT_CONFIG
from ..graph.zones import crosses_boundary, zone_of
from ..models import Finding, PolicyRecord
from .severity import band, exposure_score, score_transport_exposure


def _zones(rec: PolicyRecord, g: nx.DiGraph, alias_map: dict[str, str]) -> tuple[str, str, str, str]:
    s = alias_map.get(rec.source, rec.source)
    d = alias_map.get(rec.destination, rec.destination)
    src_zone = g.nodes[s]["zone"] if s in g else zone_of(s, [])
    dst_zone = g.nodes[d]["zone"] if d in g else zone_of(d, rec.dest_tags)
    return s, d, src_zone, dst_zone


def _src_label(rec: PolicyRecord) -> str:
    return "the internet" if exposure_score(rec.source, rec.source_kind) >= 1.0 else rec.source


def analyze(records: list[PolicyRecord], g: nx.DiGraph, alias_map: dict[str, str]) -> list[Finding]:
    findings: list[Finding] = []

    # --- 1. uninspectable-app (QUIC) blind spots -- one finding per allow rule ---
    for rec in records:
        if rec.action != "allow" or (rec.l7_app or "") not in INSPECTION_BLIND_APPS:
            continue
        s, d, src_zone, dst_zone = _zones(rec, g, alias_map)
        sc = score_transport_exposure(
            subtype="quic_blind_spot", source=rec.source, source_kind=rec.source_kind,
            protocol=rec.protocol, port=rec.port, l7_app=rec.l7_app, dest_tags=rec.dest_tags,
            src_zone=src_zone, dst_zone=dst_zone,
        )
        dest_display = g.nodes[d]["display"] if d in g else d
        app = (rec.l7_app or "").upper()
        findings.append(Finding(
            id=f"transport_exposure|blind|{rec.source_tool}|{rec.raw_ref}",
            type="transport_exposure",
            title=f"{app} ({rec.service}) reachable from {_src_label(rec)} to {dest_display} — likely uninspected",
            severity=sc["severity"],
            severity_band="critical" if sc["forced_critical"] else band(sc["severity"]),
            forced_critical=sc["forced_critical"],
            signals={
                "subtype": "quic_blind_spot", "l7_app": rec.l7_app, "l7_source": rec.l7_source,
                "protocol": rec.protocol, "exposed_port": rec.port, "service": rec.service,
                "source": rec.source, "source_kind": rec.source_kind, "dest": d,
                "dest_display": dest_display, "dest_tags": sorted(rec.dest_tags),
                "src_zone": src_zone, "dst_zone": dst_zone,
                "boundary_crossed": crosses_boundary(src_zone, dst_zone),
                "uninspectable": True, "port_class": sc["port_class"],
                "forced_reasons": sc["forced_reasons"], "severity_vector": sc["vector"],
                "tool": rec.source_tool, "raw_ref": rec.raw_ref,
                "remediation_hint": "Block UDP/443 (force the TLS fallback) or route QUIC through "
                                    "an inspection-capable enforcement point.",
            },
            involved=[s, d], raw_refs=[rec.raw_ref], source_tools=[rec.source_tool],
        ))

    # --- 2. TLS fallback not blocked -- one finding per destination per pair ---
    allows = [r for r in records if r.action == "allow" and r.port is not None]
    for (a, b) in TRANSPORT_CONFIG["fallback_pairs"]:
        by_dest: dict[str, dict[tuple[str, int], list[PolicyRecord]]] = {}
        for r in allows:
            key = (r.protocol, r.port)
            if key not in (a, b):
                continue
            d = alias_map.get(r.destination, r.destination)
            by_dest.setdefault(d, {}).setdefault(key, []).append(r)
        for d, hits in sorted(by_dest.items()):
            if a not in hits or b not in hits:
                continue
            refs = sorted({r.raw_ref for rs in hits.values() for r in rs})
            tools = sorted({r.source_tool for rs in hits.values() for r in rs})
            rep = hits[b][0]                                  # the udp/QUIC side, for the vector
            _s, _d, src_zone, dst_zone = _zones(rep, g, alias_map)
            sc = score_transport_exposure(
                subtype="tls_fallback_not_blocked", source=rep.source, source_kind=rep.source_kind,
                protocol=rep.protocol, port=rep.port, l7_app=rep.l7_app, dest_tags=rep.dest_tags,
                src_zone=src_zone, dst_zone=dst_zone,
            )
            dest_display = g.nodes[d]["display"] if d in g else d
            findings.append(Finding(
                id=f"transport_exposure|fallback|{d}|{a[0]}{a[1]}-{b[0]}{b[1]}",
                type="transport_exposure",
                title=f"{dest_display} is reachable on both {a[0]}/{a[1]} and {b[0]}/{b[1]} "
                      f"— QUIC cannot be forced to the inspectable path",
                severity=sc["severity"],
                severity_band=band(sc["severity"]),
                forced_critical=False,
                signals={
                    "subtype": "tls_fallback_not_blocked", "dest": d, "dest_display": dest_display,
                    "dest_tags": sorted(rep.dest_tags), "pair": [f"{a[0]}/{a[1]}", f"{b[0]}/{b[1]}"],
                    "tcp_refs": sorted({r.raw_ref for r in hits[a]}),
                    "udp_refs": sorted({r.raw_ref for r in hits[b]}),
                    "port_class": sc["port_class"], "severity_vector": sc["vector"],
                    "remediation_hint": f"Block {b[0]}/{b[1]} so traffic falls back to the "
                                        f"inspectable {a[0]}/{a[1]} path, or inspect QUIC explicitly.",
                },
                involved=[d], raw_refs=refs, source_tools=tools,
            ))

    return findings
