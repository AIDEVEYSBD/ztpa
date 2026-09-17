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

Deliberately still out of scope (Phase 3, see docs/PROD-READINESS-AUDIT.md): the
full 5-tuple test, deny-before-deny (the prose below assumes the shadower is an
allow), rulebase/device scoping finer than the source tool, and replacing the
O(n^2) scan with bucketing.
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


def analyze(records: list[PolicyRecord], g: nx.DiGraph, alias_map: dict[str, str]) -> list[Finding]:
    by_tool: dict[str, list[PolicyRecord]] = {}
    for rec in records:
        if rec.order is None:
            continue
        by_tool.setdefault(rec.source_tool, []).append(rec)

    findings: list[Finding] = []
    for tool in sorted(by_tool):
        recs = sorted(by_tool[tool], key=lambda r: (r.order, r.raw_ref))
        # Resolve each rule's address space ONCE. The scan below is O(n^2) until
        # Phase 3 buckets it, and re-parsing inside the inner loop was measured as
        # the dominant cost (11.5 s at 2,000 rules).
        snets = [source_nets(r) for r in recs]
        dnets = [dest_nets(r) for r in recs]
        for i, later in enumerate(recs):
            for j in range(i):
                earlier = recs[j]
                if not _dest_covers(dnets[j], dnets[i], earlier, later, alias_map):
                    continue
                if not _service_covers(earlier, later) or \
                        not _source_covers(snets[j], snets[i], earlier, later):
                    continue

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
                break   # earliest shadower is enough
    return findings
