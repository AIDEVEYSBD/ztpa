"""Asset / identity layer — the duplicate-IP solution.

IP is an attribute, not the key. We merge each tool's view of a node into one
canonical asset using *deterministic* signals only:
  - exact name match across tools  (match_key = hostname)
  - shared host IP across names     (match_key = context_ip)

A wrong merge would corrupt a fact (reachability), so this is deterministic and
auditable. Fuzzy, embedding-based *suggestions* for review live separately
(advisory.entity_suggest) and never auto-merge.

The alias_map (every observed name -> canonical asset_key) is what lets the
graph connect "appsrv-07" (Wiz) to "app-server-07" (AlgoSec/Guardicore).
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field

from .models import Asset, AssetCorrelation
from .normalizers.common import INTERNET_CIDR, ObservedEntity


@dataclass
class IdentityResult:
    assets: list[Asset] = field(default_factory=list)
    correlations: list[AssetCorrelation] = field(default_factory=list)
    alias_map: dict[str, str] = field(default_factory=dict)   # observed name -> canonical key


def _host_cidr(ip: str) -> str:
    return f"{ip}/32"


def resolve_identities(entities: list[ObservedEntity],
                       manual_merges: list[tuple[str, str]] = ()) -> IdentityResult:
    names = sorted({e.name for e in entities})
    parent = {n: n for n in names}

    def find(x: str) -> str:
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    def union(a: str, b: str) -> None:
        ra, rb = find(a), find(b)
        if ra != rb:
            parent[max(ra, rb)] = min(ra, rb)   # smaller name becomes root (deterministic)

    by_name: dict[str, list[ObservedEntity]] = defaultdict(list)
    for e in entities:
        by_name[e.name].append(e)

    # link different names that share a concrete host IP
    ip_to_names: dict[str, set[str]] = defaultdict(set)
    for e in entities:
        if e.ip:
            ip_to_names[e.ip].add(e.name)
    for ip, ns in ip_to_names.items():
        ordered = sorted(ns)
        for other in ordered[1:]:
            union(ordered[0], other)

    # human-confirmed merges (advisory.entity_suggest -> reviewed -> confirmed).
    # Deterministic like the others; only union names we actually observed.
    for a, b in manual_merges:
        if a in parent and b in parent:
            union(a, b)

    components: dict[str, list[str]] = defaultdict(list)
    for n in names:
        components[find(n)].append(n)

    result = IdentityResult()
    for _root, members in components.items():
        members = sorted(members)
        ents = [e for nm in members for e in by_name[nm]]

        def tool_count(nm: str) -> int:
            return len({e.tool for e in by_name[nm]})

        # canonical key = name used by the most tools; tie -> lexicographically smallest
        canonical = sorted(members, key=lambda nm: (-tool_count(nm), nm))[0]
        tools = sorted({e.tool for e in ents})
        tags = sorted({t for e in ents for t in e.tags})
        ips: set[str] = set()
        identifiers: dict = {}
        for e in ents:
            if e.ip:
                ips.add(_host_cidr(e.ip))
            if e.cidr:
                ips.add(e.cidr)
            identifiers.update({k: v for k, v in e.identifiers.items() if v is not None})
        abstract = all(e.abstract for e in ents)

        result.assets.append(Asset(
            asset_key=canonical,
            kind="abstract" if abstract else "concrete",
            context=identifiers.get("env") or identifiers.get("cloud"),
            identifiers=identifiers,
            ip_set=sorted(ips),
            tags=tags,
            source_tools=tools,
            display_name="Internet" if canonical == INTERNET_CIDR else canonical,
        ))
        for nm in members:
            result.alias_map[nm] = canonical

        if abstract:
            continue  # don't emit identity-merge audits for internet/subnet nodes

        # audit: exact-name merges (a single name seen by >1 tool)
        for nm in members:
            ts = sorted({e.tool for e in by_name[nm]})
            if len(ts) > 1:
                result.correlations.append(AssetCorrelation(
                    asset_key=canonical, match_key="hostname", confidence=1.0,
                    evidence={"name": nm, "tools": ts},
                ))
        # audit: shared-IP merges (>1 distinct name unified by an IP)
        if len(members) > 1:
            for ip, ns in ip_to_names.items():
                shared = sorted(set(ns) & set(members))
                if len(shared) > 1:
                    result.correlations.append(AssetCorrelation(
                        asset_key=canonical, match_key="context_ip", confidence=0.95,
                        evidence={"ip": ip, "names": shared},
                    ))

    # audit: human-confirmed merges (so the unified asset shows as cross-tool correlated)
    for a, b in manual_merges:
        if a in result.alias_map and b in result.alias_map and result.alias_map[a] == result.alias_map[b]:
            result.correlations.append(AssetCorrelation(
                asset_key=result.alias_map[a], match_key="manual_review", confidence=1.0,
                evidence={"names": sorted({a, b}), "by": "human-confirmed"},
            ))

    result.assets.sort(key=lambda a: a.asset_key)
    result.correlations.sort(key=lambda c: (c.asset_key, c.match_key, str(c.evidence)))
    return result
