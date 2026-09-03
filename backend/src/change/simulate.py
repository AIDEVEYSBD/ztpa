"""Apply a proposed change to a COPY of the graph and compute the DELTA.

The change is never classified in isolation -- the engine first computes what
newly becomes reachable, then the model judges THAT. All of this is deterministic
(no model): new internet->sensitive paths, newly exposed sensitive assets,
trust boundaries newly crossed, and any over-permissive pattern the rule itself
introduces. A guardrail force-escalates the catastrophic patterns up front.

The caller supplies the proposed rule but does NOT get to say what the
destination is: `resolve_dest_tags` re-derives the destination's sensitivity
tags from the engine's own asset set before anything is scored. Without that,
omitting `dest_tags` silently disarms every tag-driven guardrail and buys an
auto-approve (see PROD-READINESS-AUDIT, Phase 0 workstream 1).

The same rule now applies to the ADDRESS SPACE. `resolve_cidrs` fills
`source_cidrs` / `dest_cidrs` from the engine's asset set, and everything that
scores exposure reads the resolved space rather than the label, so the same
proposal expressed as a named object ("CORP-SUPERNET") and as the network it
dereferences to ("10.0.0.0/8") gets the SAME severity, the same over-permissive
reasons and the same gate ruling. Scoring the label made the named spelling
score as a single host (E_IDENTITY, 0.1) instead of a /8 (0.9) -- a free
auto-approve for anyone whose export happens to use object names.

And it applies to THE INTERNET ITSELF. The force-escalation arm below is the
diff of `_internet_sensitive_paths` before and after the rule, and that used to
start from the literal node ``0.0.0.0/0``. An estate whose internet ingress is
spelled ``any`` or ``ANY-EXTERNAL`` therefore had no internet paths on either
side of the diff, so a proposed INTERNAL rule that completes a chain from the
internet to a PCI database came back `forced_escalate=False` -- the gate
disarmed by the spelling of a rule the operator did not write. The entry set now
comes from `reachability.internet_entries`, the same zone-derived answer
`path_trace` shows the buyer.

And a DENY is not a grant. `graph.build.build_graph` adds edges for allows only,
so a proposed deny subtracts nothing and adds nothing; running it through the
over-permissive predicates anyway read "deny any from 0.0.0.0/0" as an any/any
internet grant and force-escalated a rule that TIGHTENS policy. Permissive
scoring is skipped for a deny, and the delta says so out loud rather than
presenting a structurally-empty result as a clean bill of health.
"""

from __future__ import annotations

import ipaddress
from typing import Iterable, Optional, Union

from ..analyzers.over_permissive import _reasons as _overpermissive_reasons
from ..analyzers.severity import exposure_score, is_internet_source, port_score, score_over_permissive
from ..config import SENSITIVE_TAGS
from ..graph.build import build_graph
from ..graph.reachability import find_paths, internet_entries
from ..graph.zones import boundary_label, crosses_boundary, zone_of
from ..models import Asset, PolicyRecord
from ..normalizers.common import ResolvedObject, cidrs_for_token, parse_service

_Network = Union[ipaddress.IPv4Network, ipaddress.IPv6Network]


def _internet_sensitive_paths(g) -> dict[tuple, dict]:
    """Every internet -> sensitive-asset path in `g`, keyed by its node tuple.

    The gate's whole force-escalation arm is the DIFF of this map before and
    after the proposed rule, so what counts as "the internet" here decides
    whether an operator may auto-approve. It used to be the literal string
    ``find_paths(g, "0.0.0.0/0", t)``, which meant an estate whose pre-existing
    internet ingress is spelled ``any`` or ``ANY-EXTERNAL`` -- a NAMED object,
    how most real exports write it -- produced an empty map on BOTH sides. An
    internal rule that newly exposes a PCI database then flipped
    `forced_escalate` True -> False purely on the spelling of somebody else's
    rule, and `advisory.classify_change` short-circuits to escalate on
    `forced_escalate` BEFORE any model call, so with it False the decision went
    to the LLM under a delta that read "no new internet paths".

    `internet_entries` is the graph's own zone answer and the same one
    `path_trace` uses, so the finding a buyer is shown and the ruling an operator
    is given can no longer disagree about where the internet is. Entries and
    targets are both iterated in sorted order, so the insertion order of this
    dict -- which becomes the order of `new_paths` on the wire -- is stable.
    """
    entries = internet_entries(g)
    targets = sorted(n for n, d in g.nodes(data=True) if set(d.get("tags", [])) & SENSITIVE_TAGS)
    out: dict[tuple, dict] = {}
    for entry in entries:
        for t in targets:
            if t == entry:
                continue          # a zero-edge "path" traverses no grant
            for p in find_paths(g, entry, t):
                out[tuple(p["path"])] = p
    return out


def _as_network(token: str) -> Optional[_Network]:
    """A CIDR or a bare host address -> a network; None when the token is a name.

    `ip_network` widens a bare address to its host prefix ("10.50.0.10" ->
    10.50.0.10/32), which is exactly the comparison we want: one host is a /32
    network for containment purposes.
    """
    try:
        return ipaddress.ip_network(token, strict=False)
    except ValueError:
        return None


def _overlaps(a: _Network, b: _Network) -> bool:
    """True when two networks intersect. Mixed address families never do -- and
    `subnet_of` raises TypeError across families, so the guard is load-bearing."""
    if a.version != b.version:
        return False
    return a.subnet_of(b) or b.subnet_of(a)


def resolve_dest_tags(destination: str, assets: list[Asset], alias_map: dict[str, str],
                      declared: Iterable[str] = ()) -> list[str]:
    """Derive a destination's sensitivity tags from the ENGINE's asset set.

    `dest_tags` on an incoming PolicyRecord is caller-supplied, and everything
    that decides "is this a regulated destination" reads it: `_reasons`
    predicates 2 and 3 in over_permissive, the third guardrail in
    `score_over_permissive`, and `dest_score`. A caller that passes `[]` --
    which the custom-change endpoint and intake both used to hardcode -- turns
    all of those off and hands itself a clean delta.

    So the caller's tags are treated as a claim, never as the answer: this
    UNIONS them with what the engine knows. The caller may only ever ADD
    sensitivity (which can only escalate -- fail-closed); it can never subtract
    what the asset layer already asserts. That asymmetry is the security
    property, and `test_change_simulate.py` pins it.

    Destination forms understood, all resolving against the same asset set:
      - a canonical asset key, or any tool alias of one (via `alias_map`)
      - an asset's display name
      - a bare host address ("10.50.0.10") -> every asset whose ip_set covers it
      - a CIDR ("10.50.0.8/30")            -> every asset the network contains,
        unioned, so a wider destination inherits everything it can actually
        reach (10.50.0.0/24 reaching a PCI database IS a PCI destination)

    The one exemption is a 0-prefix network (0.0.0.0/0, ::/0): that is the
    internet pseudo-node -- an egress endpoint, not "every asset in the estate"
    -- so unioning the whole estate into it would mislabel every egress rule as
    crown-jewel. It is not an escape hatch: any other prefix still aggregates,
    0.0.0.0/1 included, and an internet SOURCE is caught independently by the
    exposure guardrails below.
    """
    key = alias_map.get(destination, destination)
    names = {destination, key}
    dest_net = _as_network(key)
    if dest_net is None:
        dest_net = _as_network(destination)
    # prefixlen 0 == the internet pseudo-node; see the docstring.
    aggregate = dest_net is not None and dest_net.prefixlen > 0

    tags: set[str] = set(declared)
    for a in assets:
        if a.asset_key in names or (a.display_name and a.display_name in names):
            tags |= set(a.tags)
            continue
        if not aggregate:
            continue
        for cidr in a.ip_set:
            net = _as_network(cidr)
            if net is not None and _overlaps(net, dest_net):
                tags |= set(a.tags)
                break
    return sorted(tags)


def resolve_cidrs(token: str, assets: list[Asset], alias_map: dict[str, str],
                  declared: Iterable[str] = (),
                  resolved: Iterable[ResolvedObject] = ()) -> list[str]:
    """Derive the ADDRESS SPACE a source/destination token denotes, from the
    ENGINE's asset set AND the export's own object catalog. The address-space
    twin of `resolve_dest_tags`.

    `PolicyRecord.source_cidrs` is what every exposure decision now reads, and a
    proposal that arrives through the change gate has nobody to fill it: the
    normalizers resolve their own export's object catalog, but a hand-typed or
    model-extracted request has no catalog behind it. Left empty, the record
    falls back to E_IDENTITY -- the score of a single host -- so `ANY-EXTERNAL`
    would be gated as one machine while `0.0.0.0/0`, the very same request, is
    gated as the internet. That difference is worth an auto-approve, so the gate
    resolves the space itself before scoring anything.

    Token forms understood, in the order they are tried:
      - an address or CIDR ("10.0.0.0/8", "10.50.0.10") -> itself, canonical
      - the wildcard vocabulary ("any"/"all"/"*")       -> 0.0.0.0/0
      - a canonical asset key, a tool alias of one, or an asset display name
        -> that asset's `ip_set`
      - a NAMED OBJECT in the export's catalog ("ANY-EXTERNAL", "INTERNET", an
        address group) -> that object's resolved `cidrs`

    The catalog arm is not an optimisation, it is the difference between the
    gate working and not. `normalizers/algosec.py` emits an entity only for a
    token some EXISTING rule references, so a perimeter object that is defined
    in the catalog but not currently used resolves to nothing in the asset set.
    Before this arm existed, "allow tcp/22 from ANY-EXTERNAL to db-prod-01
    (pci)" was gated with E = 0.1 -- one host -- and came back
    forced_escalate=False with no reasons, while the byte-identical request
    written `0.0.0.0/0` was forced_escalate=True. `advisory.classify_change`
    short-circuits on forced_escalate before any model call, so that gap was an
    auto-approve of internet-to-PCI SSH decided purely by spelling.

    Everything found is UNIONED, never intersected, and the caller's own
    `declared` list is one more contribution rather than the answer. Union is the
    fail-closed direction here: an address space can only grow, so the resolved
    exposure can only ever be scored HIGHER. A caller cannot narrow what the
    engine knows by declaring a tighter list -- the same asymmetry
    `resolve_dest_tags` enforces for sensitivity tags.

    Unlike `resolve_dest_tags` this does NOT aggregate by containment: the tags
    of everything inside 10.50.0.0/24 are inherited by a rule aiming at that /24
    (sensitivity flows up), but the address space a token DENOTES is what it
    names, not the union of the assets that happen to live in it.

    The returned list is not canonicalized here -- it is handed to
    `PolicyRecord`, whose `_canonicalize_cidrs` validator is the single place
    that normal form is defined.
    """
    key = alias_map.get(token, token)
    names = (token, key)
    out: list[str] = list(declared)
    out += cidrs_for_token(key) or cidrs_for_token(token)
    for a in assets:
        if a.asset_key in names or (a.display_name and a.display_name in names):
            out += list(a.ip_set)
    # The export's own catalog, which knows objects the asset set does not.
    # Matched case-insensitively because object names are operator-typed and
    # vendors do not agree on case ("ANY-EXTERNAL" vs "Any-External").
    lowered = {n.lower() for n in names}
    for obj in resolved:
        if obj.object_kind != "address" or obj.object_name.lower() not in lowered:
            continue
        cidrs = (obj.resolved or {}).get("cidrs") or []
        out += [str(c) for c in cidrs]
    return out


def _granted_intervals(p: PolicyRecord) -> list[tuple[int, int]]:
    """Every (lo, hi) port interval the proposed rule opens.

    `PolicyRecord` carries one scalar (port, port_end) pair, so a comma list
    ("tcp/80,443") survives only in the service LABEL -- which is exactly why
    `DecodedService.ports` exists. Decode the label and use it when its first
    interval agrees with the authoritative scalars; where they disagree the
    numbers win, so a record is scored on its fields and never on its prose.
    (`change.staging._service_of` applies the same reconciliation to the dict
    shape a staged payload has.)
    """
    scalar: list[tuple[int, int]] = []
    if p.port is not None:
        scalar = [(p.port, p.port_end if p.port_end is not None else p.port)]
    parsed = parse_service(p.service).intervals() if p.service else []
    if parsed and (not scalar or parsed[0] == scalar[0]):
        return parsed
    return scalar


def _proposed_summary(p: PolicyRecord) -> dict:
    return {
        "source": p.source, "source_kind": p.source_kind, "destination": p.destination,
        "service": p.service, "protocol": p.protocol, "action": p.action,
        # The ENGINE-resolved tags and address space, not whatever the caller
        # sent -- this is the evidence that the sensitivity guardrails and the
        # exposure score were evaluated on real facts. Two spellings of one
        # proposal ("CORP-SUPERNET" and "10.0.0.0/8") differ here only in
        # `source`/`source_kind`; the resolved lists are identical, which is the
        # whole claim.
        "dest_tags": sorted(p.dest_tags), "port": p.port, "port_end": p.port_end,
        "l7_app": p.l7_app,
        "source_cidrs": list(p.source_cidrs), "dest_cidrs": list(p.dest_cidrs),
    }


def simulate_change(records: list[PolicyRecord], assets: list[Asset], alias_map: dict[str, str],
                    proposed: PolicyRecord,
                    resolved: Iterable[ResolvedObject] = ()) -> dict:
    # Re-derive from the engine BEFORE anything is built or scored -- the
    # destination's sensitivity TAGS and the ADDRESS SPACE behind both endpoints
    # -- and judge that record from here on. Rebuilding through
    # `model_validate` rather than `model_copy` is deliberate: `model_copy` does
    # not re-run validators, and `_canonicalize_cidrs` is the single definition
    # of the normal form these lists must be in for the analyzers' subnet math
    # and for the equality checks downstream. It stays side-effect free -- a new
    # instance, so the caller's record, `records` and `assets` all come back
    # exactly as they were passed in.
    proposed = PolicyRecord.model_validate({
        **proposed.model_dump(),
        "dest_tags": resolve_dest_tags(proposed.destination, assets, alias_map, proposed.dest_tags),
        "source_cidrs": resolve_cidrs(proposed.source, assets, alias_map, proposed.source_cidrs, resolved),
        "dest_cidrs": resolve_cidrs(proposed.destination, assets, alias_map, proposed.dest_cidrs, resolved),
    })
    # A deny is not a grant. `build_graph` adds edges for allows only, so a
    # proposed deny subtracts nothing and adds nothing -- the path diff below is
    # empty by construction. Running it through the over-permissive predicates
    # anyway read "deny any from 0.0.0.0/0" as an any/any internet grant and
    # force-escalated a rule that TIGHTENS policy, which is the one direction a
    # change gate must never make expensive.
    is_deny = proposed.action == "deny"

    base_graph = build_graph(records, assets, alias_map)
    new_graph = build_graph(records + [proposed], assets, alias_map)

    before = _internet_sensitive_paths(base_graph)
    after = _internet_sensitive_paths(new_graph)
    new_paths = [p for key, p in after.items() if key not in before]
    new_exposed = sorted({p["terminal"] for p in new_paths})

    # Scored on the RESOLVED address space and on the WHOLE service interval set,
    # so the gate reaches the same numbers the engine reaches for an identical
    # rule that arrived through a normalizer -- a named object is not cheaper
    # than its CIDR, and `tcp/1-65535` is not cheaper than `tcp/3389`.
    intervals = _granted_intervals(proposed)
    E = exposure_score(proposed.source, proposed.source_kind, proposed.source_cidrs)
    P, _ = port_score(proposed.protocol, proposed.port, proposed.port_end, intervals)
    s = alias_map.get(proposed.source, proposed.source)
    d = alias_map.get(proposed.destination, proposed.destination)
    src_zone = new_graph.nodes[s]["zone"] if s in new_graph else zone_of(s, [])
    dst_zone = new_graph.nodes[d]["zone"] if d in new_graph else zone_of(d, proposed.dest_tags)
    proposed_crosses = crosses_boundary(src_zone, dst_zone)

    # Everything from here to `forced_reasons` describes what the rule PERMITS,
    # so none of it applies to a deny.
    op_reasons = [] if is_deny else _overpermissive_reasons(proposed, E, P)
    guardrail_reasons: list[str] = []
    if not is_deny:
        guardrail_reasons = score_over_permissive(
            source=proposed.source, source_kind=proposed.source_kind, protocol=proposed.protocol,
            port=proposed.port, dest_tags=proposed.dest_tags, src_zone=src_zone, dst_zone=dst_zone,
            port_end=proposed.port_end, ports=intervals, source_cidrs=proposed.source_cidrs,
        )["forced_reasons"]

    boundaries = sorted({p["boundary"] for p in new_paths if p["boundary_crossed"]})
    if proposed_crosses and not is_deny:
        # `boundaries_crossed` is "boundaries traffic newly crosses". A deny
        # carries no traffic, so its endpoints spanning a boundary is a fact
        # about the rule (kept in `proposed_crosses_boundary`) and not a delta.
        boundaries = sorted(set(boundaries) | {boundary_label(src_zone, dst_zone)})

    forced_reasons: list[str] = []
    if new_paths:
        forced_reasons.append(
            f"opens {len(new_paths)} new internet path(s) reaching sensitive asset(s): {', '.join(new_exposed)}")
    if not is_deny:
        forced_reasons += guardrail_reasons
        if proposed.protocol == "any":
            forced_reasons.append("introduces an any/any rule")
        # "From the internet" is a property of the address space, not of a score:
        # `E >= 1.0` was true only for a literal /0, so the same request written
        # as 0.0.0.0/1 -- half the routable internet -- tripped nothing here.
        # `is_internet_source` is the classifier severity.py and graph.zones both
        # use, so the gate and the engine cannot disagree about what is public.
        if dst_zone == "internal" and is_internet_source(
                proposed.source, proposed.source_kind, proposed.source_cidrs):
            forced_reasons.append("creates new internet->internal exposure")
    # de-dupe, preserve order
    seen: set[str] = set()
    forced_reasons = [r for r in forced_reasons if not (r in seen or seen.add(r))]

    # An empty delta for a deny means "the engine models allows only", NOT "this
    # change is harmless". Saying so on the wire is the same truth-in-labelling
    # rule the staging plan follows: never let a structural silence read as a
    # clean bill of health.
    notes: list[str] = []
    if is_deny:
        notes.append(
            "Proposed action is 'deny'. The engine's graph is built from allow grants only, "
            "so a deny subtracts nothing from it: this delta shows what the rule does not "
            "OPEN, not what it blocks. It is deliberately not scored as a permissive grant.")

    return {
        "proposed": _proposed_summary(proposed),
        "new_paths": [{"display_path": p["display_path"], "tools": p["tools"],
                       "terminal": p["terminal"], "terminal_tags": p["terminal_tags"],
                       "boundary": p["boundary"]} for p in new_paths],
        "new_exposed_assets": new_exposed,
        "boundaries_crossed": boundaries,
        "new_over_permissive": op_reasons,
        "proposed_boundary": boundary_label(src_zone, dst_zone),
        "proposed_crosses_boundary": proposed_crosses,
        "forced_escalate": bool(forced_reasons),
        "forced_reasons": forced_reasons,
        "notes": notes,
    }
