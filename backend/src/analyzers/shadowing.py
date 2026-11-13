"""Rule shadowing: a later rule that can never fire because an earlier rule in
the same ordered rulebase (broader-or-equal source, covering destination,
covering service) matches first.

A shadowed DENY is dangerous (traffic you meant to block is actually allowed) ->
scored on the effective exposure. A shadowed ALLOW is dead config -> low fixed.

What Phase 1 changed
--------------------
The coverage predicate used to be so narrow that it only detected the shape the
seed fixture was written to contain (two rules with the *same destination name*
and the *same service string*). The two shapes that actually cause shadowing in
production firewalls were both invisible:

  * a broad rule whose DESTINATION is a network object containing the later
    rule's host -- destinations were compared by NAME, so `10.0.0.0/8` and
    `db-prod-01` (10.50.0.10) looked unrelated; and
  * a service RANGE covering a later single port -- services were compared with
    `a.service == b.service`, raw string equality on the display label, so
    `tcp/1-65535` did not cover `tcp/443`.

Both are now containment tests over the resolved facts (`source_cidrs`,
`dest_cidrs`, the port interval), which is what makes the canonical
"broad allow at the top of the rulebase kills everything below it" finding
detectable at all.

Coverage is also now DIRECTIONAL. The old service test asked whether the two
services *overlapped*, which is not the same question: an earlier `tcp/443` rule
does not shadow a later any/any rule, it only shadows part of it. Shadowing means
the earlier rule matches EVERYTHING the later one would, so every leg of the test
asks "does earlier cover later", never "do they intersect".

Deliberately still out of scope (Phase 3 of the September 2026 readiness audit; see docs/REMEDIATION-LOG.md): the
full 5-tuple test, deny-before-deny (the prose below assumes the shadower is an
allow), and rulebase/device scoping finer than the source tool.

CANDIDATE INDEX (was the O(n^2) scan)
-------------------------------------
An earlier rule can only shadow a later one if its destination covers the later
rule's: the same canonical asset, or an address space containing every later
destination network -- in particular the FIRST one. The networks that contain a
given network are exactly its supernets (at most 33 for IPv4, 129 for IPv6), so
earlier rules are indexed by each destination network they name and by their
canonical destination, and a later rule looks up only those keys. The full
coverage predicates then run on the candidates in rule order, so the earliest
shadower is still the one reported and the findings are identical to the scan's.
Measured on a synthetic Check Point rulebase (19,394 grants from 5,000 rules):
33.9 s for the scan, 2.9 s for the whole review with this index.
"""

from __future__ import annotations

import networkx as nx

from ..graph.zones import zone_of
from ..models import Finding, PolicyRecord
from ..netaddr import Network
from ..normalizers.common import parse_service
from .cidr_overlap import covers, dest_nets, source_nets
from .severity import band, score_shadowed


def _intervals(rec: PolicyRecord) -> list[tuple[int, int]] | None:
    """The port intervals a rule matches. ``None`` = it names no port at all.

    None is NOT "no ports" -- it is "this rule does not constrain the port", which
    is what an icmp/gre rule or a bare App-ID rule means. Callers must therefore
    distinguish it from a real interval list rather than treating it as empty.

    A comma-separated service ("tcp/80,443") only survives in the service LABEL:
    `PolicyRecord` is scalar and keeps the FIRST interval in port/port_end
    (widening it is Phase 3), so the label is re-decoded when it names more than
    one interval. `parse_service` never raises and is the same decoder the
    normalizers used, so this cannot disagree with the stored pair.
    """
    if rec.port is None:
        return None
    return _multi_intervals(rec) or \
        [(rec.port, rec.port_end if rec.port_end is not None else rec.port)]


def _multi_intervals(rec: PolicyRecord) -> list[tuple[int, int]] | None:
    """`DecodedService.ports` recovered from the service label, or None.

    Only a service that names MORE than one interval has anything here; the
    scalar port/port_end pair is the whole story for every other rule. See
    `_intervals` for why the label is the only place a comma list survives.
    """
    if rec.service and "," in rec.service:
        return parse_service(rec.service).ports
    return None


def _service_covers(earlier: PolicyRecord, later: PolicyRecord) -> bool:
    """Does `earlier`'s service match every packet `later`'s service would?"""
    if earlier.protocol == "any":
        return True                       # every protocol and every port
    if later.protocol == "any" or earlier.protocol != later.protocol:
        return False
    e_ivs, l_ivs = _intervals(earlier), _intervals(later)
    if e_ivs is None:
        return True                       # earlier constrains no port -> all of them
    if l_ivs is None:
        # `later` names no port but `earlier` does, so containment is unprovable
        # from the intervals. Fall back to the old exact-label test rather than
        # guessing: calling a live rule dead is the expensive direction to be
        # wrong in.
        return earlier.service == later.service
    return all(any(elo <= llo and lhi <= ehi for elo, ehi in e_ivs) for llo, lhi in l_ivs)


def _source_covers(earlier_nets: list[Network], later_nets: list[Network],
                   earlier: PolicyRecord, later: PolicyRecord) -> bool:
    """Does `earlier`'s source address space contain `later`'s?

    Falls back to identity equality when neither side resolves to an address
    space (two rules sourced from the same user/tag/application group), which is
    the pre-Phase-1 behaviour and still the only sound answer there.
    """
    if earlier_nets and later_nets:
        return covers(earlier_nets, later_nets)
    if earlier.source_kind == "identity" and later.source_kind == "identity":
        return earlier.source == later.source
    return False


def _dest_covers(earlier_nets: list[Network], later_nets: list[Network],
                 earlier: PolicyRecord, later: PolicyRecord,
                 alias_map: dict[str, str]) -> bool:
    """Does `earlier`'s destination cover `later`'s?

    Same canonical asset (the identity layer's alias map) or -- the case the old
    name comparison could not see -- an address space that contains it.
    """
    if alias_map.get(earlier.destination, earlier.destination) == \
            alias_map.get(later.destination, later.destination):
        return True
    return covers(earlier_nets, later_nets)


def _single_port(ivs: list[tuple[int, int]] | None) -> int | None:
    if ivs and len(ivs) == 1 and ivs[0][0] == ivs[0][1]:
        return ivs[0][0]
    return None


def _index_keys(earlier: PolicyRecord) -> list:
    """Service buckets an earlier rule is filed under (see `_lookup_keys`)."""
    if earlier.protocol == "any":
        return ["*"]
    port = _single_port(_intervals(earlier))
    if port is None:
        return [(earlier.protocol, "multi")]          # a range, several ports, or no port
    return [(earlier.protocol, port), (earlier.protocol, "single")]


def _lookup_keys(later: PolicyRecord) -> list:
    """Every bucket that can hold a rule whose service covers `later`'s, read
    off `_service_covers`: an any-protocol rule covers everything; otherwise only
    the same protocol, and a single-port rule only covers that same single port
    (or, when `later` names no port, possibly anything -- the label fallback)."""
    if later.protocol == "any":
        return ["*"]
    keys = ["*", (later.protocol, "multi")]
    ivs = _intervals(later)
    if ivs is None:
        keys.append((later.protocol, "single"))
    else:
        port = _single_port(ivs)
        if port is not None:
            keys.append((later.protocol, port))
    return keys


def _union_cover(partial: list[int], snets: list, later_nets: list) -> list[int] | None:
    """Earlier rules that each cover a grant's destination and service but only
    part of its sources can still take ALL of its traffic together (two /25
    allows above a /24 allow). Returns the contributing rules, in order, when
    the union of their sources contains the grant's; else None. Union along the
    source dimension only: sound (every packet of the grant matches one of
    them), not complete."""
    import ipaddress
    contributing = [k for k in partial if any(a.overlaps(b) for a in snets[k] for b in later_nets
                                              if a.version == b.version)]
    if len(contributing) < 2:
        return None
    union = []
    for version in (4, 6):
        nets = [n for k in contributing for n in snets[k] if n.version == version]
        union += list(ipaddress.collapse_addresses(nets))
    return contributing if covers(union, later_nets) else None


def analyze(records: list[PolicyRecord], g: nx.DiGraph, alias_map: dict[str, str], *,
            per_rule: bool = False) -> list[Finding]:
    """One finding per shadowed grant, or with `per_rule` one per rule (raw_ref):
    the first covered grant's finding, carrying `signals["covered_grants"]`:
    [grant id, covering rule] for every covered grant of the rule. A rulebase
    review needs only that, and a finding per grant cost ~1 KiB each at
    hundreds of thousands of grants."""
    by_tool: dict[str, list[PolicyRecord]] = {}
    for rec in records:
        if rec.order is None:
            continue
        by_tool.setdefault(rec.source_tool, []).append(rec)

    findings: list[Finding] = []
    by_ref: dict[tuple[str, str], Finding] = {}
    for tool in sorted(by_tool):
        recs = sorted(by_tool[tool], key=lambda r: (r.order, r.raw_ref))
        # Resolve each rule's address space ONCE. The scan below is O(n^2) until
        # Phase 3 buckets it, and re-parsing inside the inner loop was measured as
        # the dominant cost (11.5 s at 2,000 rules).
        snets = [source_nets(r) for r in recs]
        dnets = [dest_nets(r) for r in recs]
        by_net: dict = {}
        by_dest: dict = {}
        for i, later in enumerate(recs):
            canon = alias_map.get(later.destination, later.destination)
            look = _lookup_keys(later)
            cand: set[int] = set()
            for k in look:
                cand.update(by_dest.get((canon, k), ()))
            if dnets[i]:
                first = dnets[i][0]
                for plen in range(first.prefixlen + 1):
                    sup = first.supernet(new_prefix=plen)
                    for k in look:
                        cand.update(by_net.get((sup, k), ()))
            hit: list[int] | None = None
            partial: list[int] = []          # cover dest + service, part of the sources
            for j in sorted(cand):
                earlier = recs[j]
                if not _dest_covers(dnets[j], dnets[i], earlier, later, alias_map):
                    continue
                if not _service_covers(earlier, later):
                    continue
                if _source_covers(snets[j], snets[i], earlier, later):
                    hit = [j]
                    break
                if per_rule and snets[j] and snets[i]:
                    partial.append(j)
            if hit is None and len(partial) > 1:
                hit = _union_cover(partial, snets, snets[i])
            seen = by_ref.get((tool, later.raw_ref)) if (per_rule and hit) else None
            if seen is not None:
                seen.signals["covered_grants"].extend((later.id, recs[k].raw_ref) for k in hit)
            elif hit:                            # the earliest coverer describes the finding
                earlier = recs[hit[0]]
                j = hit[0]

                d = alias_map.get(later.destination, later.destination)
                s = alias_map.get(later.source, later.source)
                dst_zone = g.nodes[d]["zone"] if d in g else zone_of(d, later.dest_tags)
                src_zone = g.nodes[s]["zone"] if s in g else zone_of(s, [])
                # A shadowed DENY is scored on the exposure it fails to block,
                # so it gets the same resolved facts an over-permissive allow
                # gets: the whole port interval and the resolved source space.
                sc = score_shadowed(
                    shadowed_action=later.action, source=later.source,
                    source_kind=later.source_kind, protocol=later.protocol, port=later.port,
                    dest_tags=later.dest_tags, src_zone=src_zone, dst_zone=dst_zone,
                    port_end=later.port_end, ports=_multi_intervals(later),
                    source_cidrs=later.source_cidrs,
                )
                dest_display = g.nodes[d]["display"] if d in g else d
                # THE VOCABULARY IS THE INDUSTRY'S, NOT OURS.
                #
                # These used to read "Dead deny" and "Dead allow". A reviewer
                # told us plainly that "dead allow" is nowhere -- and they are
                # right: it is not a term anyone uses, so it cannot be looked up,
                # cannot be matched against what AlgoSec or Tufin or Panorama
                # calls the same condition, and makes the product sound like it
                # invented its own theory of firewall policy.
                #
                # Al-Shaer & Hamed's anomaly classification is the vocabulary
                # every serious policy tool uses, and both cases here land
                # cleanly inside it:
                #
                #   SHADOWED   an earlier rule matches all of this rule's packets
                #              with a DIFFERENT action, so this rule never fires.
                #              A deny sitting under a broader allow is the
                #              textbook case, and the dangerous one -- the
                #              operator believes traffic is blocked.
                #   REDUNDANT  an earlier rule already covers this one with the
                #              SAME action, so removing it changes nothing.
                #              Clutter, not exposure.
                #
                # The distinction is the action difference, which is exactly what
                # this branch tests, so the two terms map onto it one-to-one.
                if later.action == "deny":
                    title = (f"Shadowed rule {later.raw_ref}: deny to {dest_display} never fires "
                             f"(an earlier allow already permits it)")
                    reason = (f"deny {later.source} -> {dest_display} ({later.service}) never fires; earlier "
                              f"allow {earlier.raw_ref} ({earlier.source}) already permits it")
                else:
                    title = (f"Redundant rule {later.raw_ref}: allow to {dest_display} is already "
                             f"covered by {earlier.raw_ref}")
                    reason = (f"allow {later.source} -> {dest_display} ({later.service}) is redundant; earlier "
                              f"rule {earlier.raw_ref} ({earlier.source}) already covers it")
                findings.append(Finding(
                    id=f"shadowed_rule|{tool}|{later.raw_ref}",
                    type="shadowed_rule", title=title,
                    severity=sc["severity"], severity_band=band(sc["severity"]), forced_critical=False,
                    signals={
                        "shadowed_ref": later.raw_ref, "shadowing_ref": earlier.raw_ref, "reason": reason,
                        # Which grant of the rule is covered: a rule with several
                        # grants never matches only when every one of them is.
                        "shadowed_record": later.id,
                        # Al-Shaer & Hamed's class, carried as data so the UI
                        # groups and filters on the industry term instead of
                        # pattern-matching our prose.
                        "anomaly_class": "shadowed" if later.action == "deny" else "redundant",
                        "shadowed_action": later.action, "shadowing_action": earlier.action,
                        "dest": d, "service": later.service, "tool": tool,
                        # The resolved facts the coverage verdict was computed on,
                        # so an operator can check the containment by hand.
                        "shadowing_source_cidrs": [str(n) for n in snets[j]],
                        "shadowed_source_cidrs": [str(n) for n in snets[i]],
                        "shadowing_dest_cidrs": [str(n) for n in dnets[j]],
                        "shadowed_dest_cidrs": [str(n) for n in dnets[i]],
                        "shadowed_port": later.port, "shadowed_port_end": later.port_end,
                        "severity_vector": sc["vector"],
                    },
                    involved=[s, d], raw_refs=sorted([earlier.raw_ref, later.raw_ref]),
                    source_tools=[tool],
                ))
                if per_rule:
                    f = findings[-1]
                    f.signals["covered_grants"] = [(later.id, recs[k].raw_ref) for k in hit]
                    if len(hit) > 1:
                        f.signals["union_of"] = [recs[k].raw_ref for k in hit]
                    by_ref[(tool, later.raw_ref)] = f
            # Index AFTER the lookup: a rule never shadows itself.
            for k in _index_keys(later):
                by_dest.setdefault((canon, k), []).append(i)
                for n in dnets[i]:
                    by_net.setdefault((n, k), []).append(i)
    return findings
