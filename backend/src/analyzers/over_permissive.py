"""Over-permissive detection: rules that allow more than they should.

Flags any/any, broad source ranges, and admin/data ports or sensitive
destinations exposed too widely. Each flagged rule is scored by the full
severity formula; the guardrail floor force-marks the catastrophic ones.

What Phase 1 changed here
-------------------------
This analyzer decides WHETHER a rule is worth reporting (`_reasons`) before
`score_over_permissive` decides how bad it is. Both halves were reading the
*spelling* of a rule rather than what it grants, and the two failures compounded:

  * The exposure test read `source_kind`, so `ANY-EXTERNAL -> db-prod-01` (a
    named object dereferencing to 0.0.0.0/0) scored E=0.1 -- the exposure of a
    single host -- and produced NO reason, hence no finding at all. The same
    grant written `0.0.0.0/0` was severity 100 and forced critical. Everything
    now goes through `PolicyRecord.source_cidrs`, the resolved address space.
  * The port test read the single `port` scalar, so `tcp/1-65535` was scored from
    port 1 as "unknown / ephemeral" (P=0.5) and, again, produced no finding --
    while `tcp/3389`, a strictly narrower grant, was forced critical.

Both fixes move findings in one direction only: a rule that was reported still
is, and rules that were silently clean now surface.
"""

from __future__ import annotations

import networkx as nx

from ..config import OVERPERMISSIVE_CONFIG, PORT_NAMES, SENSITIVE_TAGS
from ..graph.zones import crosses_boundary, zone_of
from ..models import Finding, PolicyRecord
from ..netaddr import is_any
from ..normalizers.common import parse_service
from .severity import (
    band, exposure_score, port_score, prefixlen_of, score_over_permissive,
)


def _service_ports(rec: PolicyRecord) -> list[tuple[int, int]] | None:
    """Every interval a comma-separated service opens, or None for a single one.

    `PolicyRecord` is scalar (widening it is Phase 3), so `tcp/80,443` reaches us
    as port=80/port_end=None with the other interval surviving only in the
    service LABEL. Re-decoding the label is how the score and the guardrail get
    to see 443. `parse_service` never raises and is the same decoder the
    normalizer used, so this cannot disagree with the stored pair.
    """
    if rec.service and "," in rec.service:
        return parse_service(rec.service).ports
    return None


def _is_wildcard_source(rec: PolicyRecord) -> bool:
    """Does the source denote the WHOLE address space (however it is spelled)?

    Display and prose only -- the guardrail's "from the internet" test is
    `severity.is_internet_source`, which is broader (any globally-routable
    space). This one stays narrow deliberately: writing "open from the internet"
    above a rule sourced from one partner's public /24 would be a false
    statement in the most-read line of the finding.
    """
    return is_any(rec.source) or any(is_any(c) for c in rec.source_cidrs)


def _reasons(rec: PolicyRecord, E: float, P: float) -> list[str]:
    cfg = OVERPERMISSIVE_CONFIG
    is_internet = E >= 1.0            # E == 1.0 is exactly a /0 (published band table)
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
        ports = _service_ports(rec)
        E = exposure_score(rec.source, rec.source_kind, rec.source_cidrs)
        P, _ = port_score(rec.protocol, rec.port, rec.port_end, ports)
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
            port_end=rec.port_end, ports=ports, source_cidrs=rec.source_cidrs,
        )
        dest_display = g.nodes[d]["display"] if d in g else d
        # Name the port only when the rule opens exactly one: calling
        # tcp/22-2000 "SSH" describes the rule by its first port, which is the
        # bug this phase exists to remove.
        port_name = PORT_NAMES.get(rec.port) if rec.port is not None and rec.port_end is None \
            and not ports else None
        access = "any protocol/port" if rec.protocol == "any" else (port_name or rec.service)
        src_label = "the internet" if _is_wildcard_source(rec) else rec.source
        signals = {
            "exposed_port": rec.port, "exposed_port_end": rec.port_end,
            "exposed_ports": [list(iv) for iv in ports] if ports else None,
            "port_name": port_name, "service": rec.service,
            "protocol": rec.protocol, "source": rec.source, "source_kind": rec.source_kind,
            "source_scope": rec.source if rec.source_kind == "cidr" else "identity",
            # The resolved address space the score was computed on -- for a named
            # object this is the difference between "identity, prefixlen null" and
            # "0.0.0.0/0". Both are reported so the dereference is auditable.
            "source_cidrs": list(rec.source_cidrs),
            "source_prefixlen": prefixlen_of(rec.source, rec.source_kind, rec.source_cidrs),
            "dest": d, "dest_display": dest_display, "dest_tags": sorted(rec.dest_tags),
            "dest_cidrs": list(rec.dest_cidrs),
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
