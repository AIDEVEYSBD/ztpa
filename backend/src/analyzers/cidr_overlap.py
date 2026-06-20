"""CIDR overlap / redundancy: allow rules (same tool, dest, service) whose
source ranges contain or overlap one another. Hygiene, not exposure -> low band.
All subnet math via ipaddress (never a model).
"""

from __future__ import annotations

import ipaddress
from itertools import combinations

from ..models import Finding, PolicyRecord
from .severity import band, score_overlap


def _net(source: str):
    try:
        return ipaddress.ip_network(source, strict=False)
    except ValueError:
        return None


def _relation(a: ipaddress._BaseNetwork, b: ipaddress._BaseNetwork) -> str | None:
    if a == b or a.subnet_of(b) or b.subnet_of(a):
        return "contains"
    if a.overlaps(b):
        return "overlaps"
    return None


def analyze(records: list[PolicyRecord]) -> list[Finding]:
    groups: dict[tuple, list[PolicyRecord]] = {}
    for rec in records:
        if rec.action != "allow" or rec.source_kind != "cidr":
            continue
        groups.setdefault((rec.source_tool, rec.destination, rec.service), []).append(rec)

    findings: list[Finding] = []
    for (tool, dest, service), recs in groups.items():
        for a, b in combinations(sorted(recs, key=lambda r: r.raw_ref), 2):
            na, nb = _net(a.source), _net(b.source)
            if na is None or nb is None:
                continue
            relation = _relation(na, nb)
            if relation is None:
                continue
            sev = score_overlap(
                dest_tags_a=a.dest_tags, dest_tags_b=b.dest_tags,
                source_a=a.source, source_kind_a=a.source_kind,
                source_b=b.source, source_kind_b=b.source_kind,
            )
            outer, inner = (b, a) if na.subnet_of(nb) else (a, b)
            refs = sorted([a.raw_ref, b.raw_ref])
            findings.append(Finding(
                id=f"cidr_overlap|{tool}|{refs[0]}|{refs[1]}",
                type="cidr_overlap",
                title=f"Redundant rules to {dest} ({service}): {outer.source} already covers {inner.source}",
                severity=sev, severity_band=band(sev), forced_critical=False,
                signals={
                    "cidr_a": a.source, "cidr_b": b.source, "relation": relation, "refs": refs,
                    "dest": dest, "service": service, "tool": tool,
                    "outer": outer.source, "inner": inner.source, "severity_vector": {},
                },
                involved=[dest], raw_refs=refs, source_tools=[tool],
            ))
    return findings
