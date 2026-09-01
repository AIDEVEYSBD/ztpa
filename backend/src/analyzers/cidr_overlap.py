"""CIDR overlap / redundancy: allow rules (same tool, same destination address
space, same service) whose SOURCE address spaces contain or overlap one another.
Hygiene, not exposure -> low band. All subnet math via ipaddress (never a model).

Two Phase 1 corrections live here, both of which changed what this analyzer can
see at all:

  * **It crashed on IPv6.** `_relation` compared two networks without checking
    `.version`, and `ipaddress._BaseNetwork._is_subnet_of` *raises* TypeError
    across families rather than returning False. One IPv6 rule alongside IPv4 was
    therefore not a degraded finding but a 500 on every route until the process
    restarted -- `app.main._ENGINE` is a cached singleton, so the exception was
    re-raised on every subsequent request. Every comparison now goes through
    `netaddr.same_family`.

  * **It ignored every named-object rule.** The old guard was
    `if rec.source_kind != "cidr": continue`, so a rule whose source is the
    object `DC-SUBNETS` -- i.e. most rules in a real export -- was invisible, and
    the analyzer found almost nothing outside the demo fixture, where 15 of 16
    sources are raw CIDRs. It now reads `PolicyRecord.source_cidrs` / `dest_cidrs`
    (the RESOLVED address space the label denotes) and falls back to parsing the
    label only when no resolved space was recorded.

Grouping is on the resolved DESTINATION space rather than the destination label
for the same reason: two rules pointing at one network written two ways (the
object `app-segment` and the literal `10.30.0.0/16`) are rules to the same place,
and redundancy between them is exactly what this analyzer exists to report.
"""

from __future__ import annotations

from itertools import combinations

from ..models import Finding, PolicyRecord
from ..netaddr import ANY_V4, Network, is_any, parse_net, same_family
from .severity import band, score_overlap


# --- resolved address space -------------------------------------------------
# `shadowing` imports these two: it and this module are the only analyzers that
# do subnet math, and one implementation means the IPv6 family guard cannot be
# fixed here and forgotten there.

def source_nets(rec: PolicyRecord) -> list[Network]:
    """Every network the rule's SOURCE denotes. Empty = no address space known.

    `source_cidrs` is authoritative -- it is the object catalog's answer, already
    canonicalized and sorted by the model validator. The fallback only runs when
    it is empty, which means one of two things: a record built outside the
    normalizers (the change pipeline constructs PolicyRecords from an operator's
    request, with no catalog to dereference against), or a token that names no
    address space at all. The first is recoverable -- a `cidr`-kind source IS its
    own address space, and a wildcard word denotes all of it -- and the second
    correctly stays empty.
    """
    return _nets(rec.source_cidrs, rec.source, rec.source_kind)


def dest_nets(rec: PolicyRecord) -> list[Network]:
    """Every network the rule's DESTINATION denotes. Empty = none known."""
    return _nets(rec.dest_cidrs, rec.destination, rec.destination_kind)


def _nets(resolved: list[str], label: str, kind: str) -> list[Network]:
    nets = [n for n in (parse_net(c) for c in resolved) if n is not None]
    if nets:
        return nets
    if is_any(label):                     # `any` / `all` / `*` / 0.0.0.0/0
        return [parse_net(ANY_V4)]
    net = parse_net(label) if kind == "cidr" else None
    return [net] if net is not None else []


def covers(outer: list[Network], inner: list[Network]) -> bool:
    """True when EVERY network in `inner` sits inside one of `outer`.

    An address group resolves to several networks, so containment is set
    containment, not a single `subnet_of`. Empty `inner` is not coverage: an
    unresolvable source proves nothing about what it can reach.
    """
    if not inner or not outer:
        return False
    return all(any(same_family(o, i) and i.subnet_of(o) for o in outer) for i in inner)


def _overlaps(a: list[Network], b: list[Network]) -> bool:
    return any(same_family(x, y) and x.overlaps(y) for x in a for y in b)


def _relation(a: list[Network], b: list[Network]) -> str | None:
    """"contains" when one side's space covers the other's, "overlaps" when they
    merely intersect, None when they are disjoint (or incomparable, e.g. an IPv4
    rule beside an IPv6 one -- the family guard the crash fix turns on)."""
    if covers(a, b) or covers(b, a):
        return "contains"
    if _overlaps(a, b):
        return "overlaps"
    return None


def _dest_key(rec: PolicyRecord) -> tuple[str, ...]:
    """Group key for a destination: its resolved space, else its label.

    Two rules to `app-segment` and to `10.30.0.0/16` are rules to the same
    network. Falling back to the label keeps rules to an unresolvable name
    grouped exactly as they were before.
    """
    nets = dest_nets(rec)
    if nets:
        return ("cidrs",) + tuple(str(n) for n in nets)
    return ("name", rec.destination)


def analyze(records: list[PolicyRecord]) -> list[Finding]:
    groups: dict[tuple, list[PolicyRecord]] = {}
    for rec in records:
        if rec.action != "allow":
            continue
        groups.setdefault((rec.source_tool, _dest_key(rec), rec.service), []).append(rec)

    findings: list[Finding] = []
    for (tool, _dkey, service), recs in sorted(groups.items()):
        recs = sorted(recs, key=lambda r: r.raw_ref)
        # Resolve each source ONCE per group rather than per pair: the loop below
        # is O(n^2) (bucketing is Phase 3) and re-parsing inside it was measured
        # as the dominant cost.
        nets = [source_nets(r) for r in recs]
        # The destination LABEL to display. The group is keyed on address space,
        # so several names can share it; `min` picks one deterministically.
        dest = min(r.destination for r in recs)
        for (ia, a), (ib, b) in combinations(list(enumerate(recs)), 2):
            na, nb = nets[ia], nets[ib]
            relation = _relation(na, nb)
            if relation is None:
                continue
            # `score_overlap` decides "broad source" from the RESOLVED space
            # (its is_broad is an E threshold now), so the object catalog's
            # answer goes in alongside the label rather than instead of it.
            sev = score_overlap(
                dest_tags_a=a.dest_tags, dest_tags_b=b.dest_tags,
                source_a=a.source, source_kind_a=a.source_kind,
                source_b=b.source, source_kind_b=b.source_kind,
                source_cidrs_a=a.source_cidrs, source_cidrs_b=b.source_cidrs,
            )
            outer, inner = (b, a) if covers(nb, na) else (a, b)
            refs = sorted([a.raw_ref, b.raw_ref])
            findings.append(Finding(
                id=f"cidr_overlap|{tool}|{refs[0]}|{refs[1]}",
                type="cidr_overlap",
                title=f"Redundant rules to {dest} ({service}): {outer.source} already covers {inner.source}",
                severity=sev, severity_band=band(sev), forced_critical=False,
                signals={
                    "cidr_a": a.source, "cidr_b": b.source, "relation": relation, "refs": refs,
                    "dest": dest, "service": service, "tool": tool,
                    "outer": outer.source, "inner": inner.source,
                    # The resolved spaces the verdict was actually computed on, so
                    # a reader can redo the subnet math for a named object.
                    "source_cidrs_a": [str(n) for n in na],
                    "source_cidrs_b": [str(n) for n in nb],
                    "severity_vector": {},
                },
                involved=[dest], raw_refs=refs, source_tools=[tool],
            ))
    return findings
