"""NAT in the review: context on access rules, and NAT-rule hygiene checks.

WHAT THIS DOES NOT CLAIM. Whether a gateway matches an access rule before or
after destination translation depends on its configuration, so access grants are
NOT rewritten through NAT here. Instead every access rule whose destination
overlaps a NAT rule's original or translated destination carries that NAT rule
as context, and the checks below are the ones that hold either way:

  nat_shadowed           an earlier enabled NAT rule on the same gateways already
                         matches everything this one would: it is never used
  nat_disabled           disabled, still in the policy (cleanup)
  nat_orphan             a static destination NAT that no live allow rule reaches,
                         by its original or its translated address: dead config
  nat_internet_exposure  a static destination NAT whose address a live allow rule
                         opens to the internet: names the internal host behind it

NAT-rule service coverage compares resolved specs exactly ("any" covers all), so
shadowing hidden behind port ranges can be missed but is never invented.
"""

from __future__ import annotations

import bisect
import ipaddress
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Iterable, Optional

from .rulebase import NatRule, ParsedRulebase

CONTEXT_MAX = 10
_SEV = {"nat_shadowed": 45, "nat_disabled": 25, "nat_orphan": 30, "nat_internet_exposure": 70}
_ALL = {"policy targets", "any", "all"}
_NO_TRANSLATION = {"original", ""}


def _band(score: int) -> str:
    return "critical" if score >= 85 else "high" if score >= 65 else "medium" if score >= 40 else "low"


Interval = tuple[int, int, int]                      # (ip version, first, last)


def _intervals(cidrs: Iterable[str]) -> list[Interval]:
    out = []
    for c in cidrs:
        try:
            n = ipaddress.ip_network(c, strict=False)
        except ValueError:
            continue
        out.append((n.version, int(n.network_address), int(n.broadcast_address)))
    return out


def _overlaps(a: list[Interval], b: list[Interval]) -> bool:
    return any(x[0] == y[0] and x[1] <= y[2] and y[1] <= x[2] for x in a for y in b)


def _covers(outer: list[Interval], inner: list[Interval]) -> bool:
    return bool(inner) and bool(outer) and all(
        any(o[0] == i[0] and o[1] <= i[1] and i[2] <= o[2] for o in outer) for i in inner)


def _targets(n: NatRule) -> set[str]:
    t = {x.lower() for x in n.install_on}
    return {"*"} if (not t or t & _ALL) else t


def _translates_destination(n: NatRule) -> bool:
    return bool(n.translated_destination_cidrs) and not (
        {x.lower() for x in n.translated_destination} <= _NO_TRANSLATION)


@dataclass
class NatFinding:
    check: str
    severity: int
    band: str
    title: str
    nat_uid: str
    nat_number: Optional[int]
    package: str
    evidence: dict = field(default_factory=dict)


def analyse(parsed: ParsedRulebase) -> tuple[list[NatFinding], dict[str, list[dict]]]:
    """(NAT findings, {access rule uid: [NAT context]})."""
    findings: list[NatFinding] = []
    nats = [n for n in parsed.nat]
    if not nats:
        return findings, {}
    number = {r.uid: r.number for r in parsed.rules}

    def add(check: str, n: NatRule, title: str, **ev) -> None:
        findings.append(NatFinding(check, _SEV[check], _band(_SEV[check]), title, n.uid, n.number,
                                   n.package, ev))

    # Live allow grants, per access rule, as intervals.
    # (from the internet?, destination intervals) per grant. Whether a grant's
    # source covers the internet is a property of the grant: computed once here,
    # not once per NAT rule it touches (that was 7.9M checks at 20k rules).
    internet = _intervals(["0.0.0.0/0"])
    grants: dict[str, list[tuple[bool, list[Interval]]]] = {}
    for rec in parsed.result.records:
        if rec.action != "allow":
            continue
        grants.setdefault(rec.raw_ref, []).append(
            (_covers(_intervals(rec.source_cidrs), internet), _intervals(rec.dest_cidrs)))

    prepared = []
    for n in nats:
        prepared.append((n, _intervals(n.original_source_cidrs), _intervals(n.original_destination_cidrs),
                         _intervals(n.translated_destination_cidrs)))

    # Which grants reach which NAT rule, via a sorted interval index over the
    # NAT rules' original + translated destinations (one bisect per grant
    # destination) instead of every NAT rule scanning every grant: 500 NAT rules
    # x 77,647 grants went from 19.9 s to well under a second.
    index: dict[int, list[tuple[int, int, int]]] = defaultdict(list)     # version -> (start, end, nat i)
    for i, (n, _osrc, odst, tdst) in enumerate(prepared):
        if n.enabled and _translates_destination(n):
            for v, a, b in odst + tdst:
                index[v].append((a, b, i))
    starts: dict[int, list[int]] = {}
    widest: dict[int, int] = {}
    for v, iv in index.items():
        iv.sort()
        starts[v] = [a for a, _b, _i in iv]
        widest[v] = max(b - a for a, b, _i in iv)
    hits: dict[int, dict[str, bool]] = defaultdict(dict)        # nat i -> {rule uid: from internet}
    for uid, gs in grants.items():
        for from_internet, dst in gs:
            seen: set[int] = set()
            for v, a, b in dst:
                if v not in index:
                    continue
                lo = bisect.bisect_left(starts[v], a - widest[v])
                hi = bisect.bisect_right(starts[v], b)
                for na, nb, i in index[v][lo:hi]:
                    if na <= b and a <= nb and i not in seen:
                        seen.add(i)
                        hits[i][uid] = hits[i].get(uid, False) or from_internet

    context: dict[str, list[dict]] = {}
    for i, (n, osrc, odst, tdst) in enumerate(prepared):
        if not n.enabled:
            add("nat_disabled", n, f"NAT rule {n.number} is disabled but still in the policy")
            continue
        # Shadowed by an earlier enabled NAT rule on (at least) the same gateways.
        for e, esrc, edst, _ in prepared[:i]:
            if not e.enabled or e.package != n.package:
                continue
            if not ("*" in _targets(e) or _targets(n) <= _targets(e)):
                continue
            svc_ok = "any" in e.original_service_specs or set(n.original_service_specs) <= set(e.original_service_specs)
            if svc_ok and _covers(esrc, osrc) and _covers(edst, odst):
                add("nat_shadowed", n, f"NAT rule {n.number} is never used: NAT rule {e.number} above it "
                                       "already matches the same traffic", covered_by_nat_rule=e.number)
                break
        if not _translates_destination(n):
            continue
        # Which live allow rules reach this NAT rule's original or translated address.
        reached_by, exposed_by = [], []
        for uid, from_internet in hits.get(i, {}).items():
            reached_by.append(number.get(uid))
            if from_internet:
                exposed_by.append(number.get(uid))
            ctx = context.setdefault(uid, [])
            if len(ctx) >= CONTEXT_MAX:
                # Bounded: a rule to a broad network can reach hundreds of NAT
                # rules, and the review document is stored and served per page.
                ctx[-1]["more_nat_rules"] = ctx[-1].get("more_nat_rules", 0) + 1
                continue
            ctx.append({
                "nat_rule": n.number, "package": n.package, "method": n.method,
                "original_destination": n.original_destination,
                "translated_destination": n.translated_destination,
                "translated_destination_cidrs": n.translated_destination_cidrs})
        if n.method == "static" and not reached_by:
            add("nat_orphan", n, f"static NAT rule {n.number} translates "
                                 f"{', '.join(n.original_destination)} → {', '.join(n.translated_destination)}, "
                                 "but no live allow rule reaches either address",
                translated_destination=n.translated_destination)
        if exposed_by:
            add("nat_internet_exposure", n,
                f"the internet reaches {', '.join(n.translated_destination)} through static NAT rule "
                f"{n.number} and access rule(s) {', '.join(str(x) for x in sorted(filter(None, exposed_by)))}",
                access_rules=sorted(filter(None, exposed_by)),
                translated_destination=n.translated_destination,
                translated_destination_cidrs=n.translated_destination_cidrs)
    return findings, context
