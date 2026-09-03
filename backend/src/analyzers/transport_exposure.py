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

What Phase 1 changed here
-------------------------
The fallback-pair match was `(r.protocol, r.port) in (a, b)`: an exact match on
one scalar port. A rule written `tcp/443-8443` -- or `tcp/80,443`, the most
common AlgoSec service encoding -- opens 443 without ever being equal to
`("tcp", 443)`, so the pair went undetected and a destination reachable on both
transports read as clean. The match is now interval containment over the whole
service, which is the same arithmetic `severity.port_score` uses. Scoring gained
the resolved source space and the full interval set for the same reason it did
in `over_permissive`: a QUIC allow from a named object that dereferences to
0.0.0.0/0 must score like one written `0.0.0.0/0`.

What THIS round changed here (PROD-READINESS-AUDIT-2, quick win 3)
------------------------------------------------------------------
The fallback-pair check filtered its input to `r.port is not None` and `_opens`
re-tested the same thing, so an `any` service -- protocol "any", no port, the
widest grant an export can express -- was excluded from the one check whose own
docstring says "a rule whose protocol is `any` opens the port on every
transport". `data/mock/algosec_export.json` ships such a rule (ALGO-001,
`0.0.0.0/0 -> 10.0.0.0/8 any`), so the analyzer was skipping the worst rule in
the product's own demo. Both tests are now one: a rule that names no port opens
every port exactly when it names no protocol either, which is how
`severity.port_score` already scores it (PORT_CLASS_ANY_PORT). A `tcp` rule whose
service failed to decode still opens nothing -- "port unknown" is not evidence
that 443 is reachable, and inventing a grant is the mirror-image error.
"""

from __future__ import annotations

import networkx as nx

from ..config import INSPECTION_BLIND_APPS, TRANSPORT_CONFIG
from ..graph.zones import crosses_boundary, zone_of
from ..models import Finding, PolicyRecord
from ..netaddr import is_any
from ..normalizers.common import parse_service
from .severity import band, score_transport_exposure


def _zones(rec: PolicyRecord, g: nx.DiGraph, alias_map: dict[str, str]) -> tuple[str, str, str, str]:
    s = alias_map.get(rec.source, rec.source)
    d = alias_map.get(rec.destination, rec.destination)
    src_zone = g.nodes[s]["zone"] if s in g else zone_of(s, [])
    dst_zone = g.nodes[d]["zone"] if d in g else zone_of(d, rec.dest_tags)
    return s, d, src_zone, dst_zone


def _service_ports(rec: PolicyRecord) -> list[tuple[int, int]] | None:
    """Every interval a comma-separated service opens, or None for a single one.

    `PolicyRecord` is scalar until Phase 3, so the second interval of
    `tcp/80,443` survives only in the service label. See the identical helper in
    `over_permissive` -- both re-decode with `parse_service`, the decoder the
    normalizer itself used, so neither can disagree with the stored pair.
    """
    if rec.service and "," in rec.service:
        return parse_service(rec.service).ports
    return None


def _src_label(rec: PolicyRecord) -> str:
    """Display only: a source that denotes the whole address space reads as "the
    internet", however the export spelled it (`0.0.0.0/0`, `any`, or a named
    object resolving to one). Deliberately narrower than the guardrail's
    `is_internet_source` -- see `over_permissive._is_wildcard_source`."""
    return "the internet" if is_any(rec.source) or any(is_any(c) for c in rec.source_cidrs) \
        else rec.source


def _opens(rec: PolicyRecord, protocol: str, port: int) -> bool:
    """Does this rule actually grant (protocol, port)?

    Interval containment, not scalar equality: `tcp/443`, `tcp/443-8443` and
    `tcp/80,443` all open tcp/443 and all must trip the fallback pair. A rule
    whose protocol is `any` opens the port on every transport.

    A rule carrying NO port at all is a grant of every port only when it names no
    protocol either -- an `any` service. That is the same reading
    `severity.port_score` gives it (`_class_applies` returns PORT_CLASS_ANY_PORT
    for `protocol == "any"`), and it is what the sentence above has always
    claimed. A protocol-bearing rule with `port is None` is a service the decoder
    could not read: mid-risk, but not evidence that this port is open, so it
    stays False rather than manufacturing a grant nobody wrote.
    """
    if rec.protocol != protocol and rec.protocol != "any":
        return False
    if rec.port is None:
        return rec.protocol == "any"
    intervals = _service_ports(rec) or \
        [(rec.port, rec.port_end if rec.port_end is not None else rec.port)]
    return any(lo <= port <= hi for lo, hi in intervals)


def analyze(records: list[PolicyRecord], g: nx.DiGraph, alias_map: dict[str, str]) -> list[Finding]:
    findings: list[Finding] = []

    # --- 1. uninspectable-app (QUIC) blind spots -- one finding per allow rule ---
    for rec in records:
        if rec.action != "allow" or (rec.l7_app or "") not in INSPECTION_BLIND_APPS:
            continue
        s, d, src_zone, dst_zone = _zones(rec, g, alias_map)
        ports = _service_ports(rec)
        sc = score_transport_exposure(
            subtype="quic_blind_spot", source=rec.source, source_kind=rec.source_kind,
            protocol=rec.protocol, port=rec.port, l7_app=rec.l7_app, dest_tags=rec.dest_tags,
            src_zone=src_zone, dst_zone=dst_zone,
            port_end=rec.port_end, ports=ports, source_cidrs=rec.source_cidrs,
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
                "protocol": rec.protocol, "exposed_port": rec.port,
                "exposed_port_end": rec.port_end, "service": rec.service,
                "source": rec.source, "source_kind": rec.source_kind,
                "source_cidrs": list(rec.source_cidrs), "dest": d,
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
    # No `r.port is not None` filter: `_opens` is the one place that decides
    # what a rule grants, and an `any/any` rule grants this pair.
    allows = [r for r in records if r.action == "allow"]
    for (a, b) in TRANSPORT_CONFIG["fallback_pairs"]:
        by_dest: dict[str, dict[tuple[str, int], list[PolicyRecord]]] = {}
        for r in allows:
            d = alias_map.get(r.destination, r.destination)
            for key in (a, b):
                if _opens(r, key[0], key[1]):
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
                port_end=rep.port_end, ports=_service_ports(rep), source_cidrs=rep.source_cidrs,
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
