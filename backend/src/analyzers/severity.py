"""Deterministic severity: the four sub-scores (all by lookup), the
multiplicative combination, the bands, and the guardrail floor (BUILD_SPEC s6).

risk = likelihood x impact, with impact capped by destination value so a
dev-sandbox finding can never out-rank a crown-jewel one. The floor is separate:
categorically-unacceptable patterns are force-flagged critical regardless of the
smooth score, so no model error downstream can bury a true emergency.

Every number this module returns comes from a published table in `config.py`.
That is the property the whole severity story rests on: a client can take the
`severity_vector` off any finding and recompute it by hand from ENGINE.md. None
of the changes below introduce a computed constant -- they change WHICH row of a
published table a rule lands on, never how the rows are made.

What Phase 1 changed here, and why (PROD-READINESS-AUDIT)
--------------------------------------------------------
The formula was right; what it was fed was wrong. Three inputs were read from
the *spelling* of a rule rather than from what the rule actually grants:

1. **A port RANGE was scored as its start port.** `port_score` read one scalar,
   so `0.0.0.0/0 -> host tcp/1-65535` scored P=0.5 "unknown/ephemeral" from port
   1 and produced ZERO findings, while the identical grant written `tcp/3389`
   was forced critical at 90. `port_score` now takes the whole interval set and
   returns the MAX class over it, so widening a range can only ever raise P.

2. **Exposure was scored from the label, not the address space.** A named
   object -- `ANY-EXTERNAL`, an address group -- arrived as
   `source_kind == "identity"` and short-circuited to E_IDENTITY (0.1, the score
   of a single host) even when it dereferenced to `0.0.0.0/0`. `exposure_score`
   now scores the BROADEST network in `PolicyRecord.source_cidrs` and falls back
   to E_IDENTITY only when that list is genuinely empty. This is the "four
   encodings" property: `0.0.0.0/0`, `any`, a named object and an address group
   all describe one address space and must score identically.

3. **"The internet" was a number, not a place.** `_is_internet(E)` tested
   `E >= 1.0`, which is true only for a `/0`. Written as two `/1`s -- an entirely
   ordinary way to express the same rule -- the guardrail floor did not fire at
   all. The test is now `netaddr.is_public` over the resolved address space, the
   same classifier `graph.zones` uses, so the two layers cannot drift.

What THIS round changed here (PROD-READINESS-AUDIT-2, L1)
---------------------------------------------------------
A fourth instance of the same class: one rule, two halves, and only one half
applied it. `netaddr` publishes IPv4-mapped v6 unwrapping as a classification
DECISION -- "``::ffff:10.0.0.0/104`` is therefore 10/8", with the stated reason
that not unwrapping "would silently hide an internet-facing v6 rule written in
mapped form". It applied it inside `is_public` only. The band tables are indexed
by (family, prefix length) and every mapped block is /96 or longer, so
`_exposure_of` banded `::ffff:0.0.0.0/96` -- the whole internet -- in the bottom
v6 row at E = 0.1, the exposure of a single host, while `is_public` called the
same token public. `prefixlen_of` printed 96 beside it. Both now read the
network through `_net_of`, which parses AND unwraps, so one address space has one
prefix length and one E however it is spelled.

The guardrail CLAUSES are unchanged: still exactly the three published in
ENGINE.md 5.4 for over-permissive rules. They fire on strictly more inputs now
(a range that contains an admin port, a public source that is not a `/0`), which
is the direction a floor is allowed to move. No clause was added, so the
published list stays true.

Determinism: no sets in an output path, no dict-order dependence (the one table
that is iterated, `PORT_CLASS_P`, is declared in a load-bearing order), no clock,
no randomness. Same records in, byte-identical scores out.
"""

from __future__ import annotations

from ..config import (
    ADMIN_LATERAL_PORTS, DATA_STORE_PORTS, D_UNTAGGED, EXPOSURE_BANDS_BY_VERSION,
    E_IDENTITY, E_UNRESOLVED, GENERAL_APP_PORTS, INFRA_CONTROL_PORTS, PORT_CLASS_ADMIN,
    PORT_CLASS_ANY_PORT, PORT_CLASS_DATA_STORE, PORT_CLASS_GENERAL_APP,
    PORT_CLASS_INFRA_CONTROL, PORT_CLASS_P, PORT_CLASS_UNKNOWN, PORT_SPAN_ANY,
    P_UNKNOWN, SENSITIVE_TAGS, SEVERITY_CONFIG, TAG_SENSITIVITY, TRANSPORT_CONFIG,
    ZONE_INTERNET,
)
from ..graph.zones import boundary_multiplier
from ..netaddr import Network, _unwrap_mapped, is_any, is_public, parse_net
from ..normalizers.common import parse_service

# The L4 port space. Mirrored from `normalizers.common` deliberately rather than
# imported from its private name: this module must be able to canonicalize an
# interval list handed to it by ANY caller, including one that never went
# through the decoder.
_PORT_MIN, _PORT_MAX = 0, 65535

# Port class label -> the ports that put a service in that class. The two
# label-only classes are absent on purpose: "any-port" is a property of the
# protocol or of the span, and "unknown / ephemeral" is the complement of every
# set here, so neither can be expressed as a membership test.
_PORT_CLASS_SETS: dict[str, frozenset[int]] = {
    PORT_CLASS_ADMIN: frozenset(ADMIN_LATERAL_PORTS),
    PORT_CLASS_DATA_STORE: frozenset(DATA_STORE_PORTS),
    PORT_CLASS_INFRA_CONTROL: frozenset(INFRA_CONTROL_PORTS),
    PORT_CLASS_GENERAL_APP: frozenset(GENERAL_APP_PORTS),
}
# Every port that lands in *some* named class. A range that covers a port
# outside this set grants unclassified access, which is P_UNKNOWN (0.5) -- and
# 0.5 outranks "general app" (0.4), so tcp/80-8080 cannot be reported as a web
# grant just because it happens to contain 443.
_CLASSIFIED_PORTS: frozenset[int] = frozenset().union(*_PORT_CLASS_SETS.values())


# --- the four sub-scores (categorical lookups; never computed) -------------

def exposure_score(source: str, source_kind: str,
                   source_cidrs: list[str] | None = None,
                   source_unresolved: bool = False) -> float:
    """E: exposure breadth of the address space the source actually denotes.

    `source_cidrs` is `PolicyRecord.source_cidrs`: the RESOLVED address space
    behind the source token, canonical and sorted, filled by the normalizer from
    the export's own object catalog. When it is non-empty it WINS over the label
    -- that is the entire point of carrying it -- and E is the score of the
    BROADEST network in it, because a grant is as exposed as the widest address
    it admits. An address group of {0.0.0.0/0, 10.0.0.0/8} is internet exposure.

    An EMPTY list means the token genuinely names no address space (a user, a
    tag, an application group, an object the export omitted), and only then does
    the label itself get read -- which for a raw-CIDR record IS the address
    space, so `exposure_score("10.0.0.0/8", "cidr")` still answers 0.9.

    `source_kind` is no longer consulted. It used to short-circuit
    (`if source_kind == "identity": return E_IDENTITY`), and that single line is
    what scored `ANY-EXTERNAL -> 0.0.0.0/0` like a single host. The kind stays in
    the signature because it is a fact about the record every call site already
    has, and because dropping a positional parameter would break them all.

    Falls back to E_IDENTITY when nothing in hand parses as address space --
    a label we cannot resolve is not evidence of exposure.

    `source_unresolved` separates the two ways that fallback is reached, because
    they mean opposite things. A token that names no address space at all (a
    user, a tag, an application group) genuinely IS a narrow source: E_IDENTITY
    is the right answer. A token the export DECLARED as an address but which the
    engine could not read -- a malformed CIDR, a broken catalog reference, an
    undecoded syntax -- is an UNKNOWN of unknown breadth, and scoring that as one
    host lets bad input LOWER the reported risk. Those get E_UNRESOLVED, a
    conservative floor that keeps the rule visible. `object_is_abstract` already
    fails closed on the identical warning; this is the scoring half of that
    decision, and the two halves now agree.
    """
    scored = [e for e in (_exposure_of(t) for t in _source_tokens(source, source_cidrs))
              if e is not None]
    if not scored:
        # Nothing resolved. Which kind of nothing decides the answer.
        return E_UNRESOLVED if source_unresolved else E_IDENTITY
    return max(scored)          # broadest network wins; order-independent


def port_score(protocol: str | None, port: int | None, port_end: int | None = None,
               ports: list[tuple[int, int]] | None = None) -> tuple[float, str]:
    """P: the kind of access granted (admin/data/infra/app/any/unknown).

    Scores the WHOLE service, not its first port. Three encodings reach here and
    all three are one interval set:

      port                       a single port          -> [(p, p)]
      port + port_end            a range                -> [(lo, hi)]
      ports                      a comma list           -> every interval

    `ports` is `DecodedService.ports` (`tcp/80,443` -> [(80,80),(443,443)]) and
    takes precedence when supplied, because it is the complete story; the scalar
    pair only ever holds the FIRST interval. An empty/absent list falls back to
    the scalars, so no caller has to decide which field is authoritative.

    The answer is the MAX class over every port the service opens, found by
    walking `PORT_CLASS_P` in its declared most-severe-first order and returning
    the first class that applies. Two consequences worth stating:

      - Widening a service can never LOWER P. tcp/80 is 0.4; tcp/80-81 is 0.5,
        because port 81 is unclassified and unclassified outranks web.
      - A span wider than `PORT_SPAN_ANY` (1024, the size of the IANA System
        port range) is P_ANY_PORT whatever it contains -- and it is reported as
        "any-port", not as the admin class it also matches, because that tie is
        pinned by the order of the config table.

    An unknown port (`port is None`) stays P_UNKNOWN, exactly as before: the
    engine has to score something, and "we could not read the service" is a
    mid-risk fact, not a safe one.
    """
    intervals = _service_intervals(port, port_end, ports)
    span = sum(hi - lo + 1 for lo, hi in intervals)
    for label, p in PORT_CLASS_P.items():
        if _class_applies(label, protocol, intervals, span):
            return p, label
    return P_UNKNOWN, PORT_CLASS_UNKNOWN      # no readable port at all


def port_score_from_service(service: str | None) -> tuple[float, str]:
    """P for a service STRING (`tcp/3389`, `quic`, `tcp/80,443`, `tcp/1-65535`).

    Signature unchanged; range- and list-aware inside, because `parse_service`
    now returns every interval the token names. This is the path
    `score_cross_tool_path` uses for a terminal edge's service.
    """
    if not service:
        return port_score("tcp", None)
    svc = parse_service(service)
    return port_score(svc.protocol, svc.port, svc.port_end, svc.intervals())


def dest_score(tags: list[str]) -> float:
    """D: max sensitivity over the destination's tags; untagged -> 0.4."""
    if not tags:
        return D_UNTAGGED
    return max((TAG_SENSITIVITY.get(t, D_UNTAGGED) for t in tags), default=D_UNTAGGED)


def is_internet_source(source: str, source_kind: str,
                       source_cidrs: list[str] | None = None) -> bool:
    """True when the source is an UNBOUNDED set of globally-routable addresses.

    The guardrail floor's definition of "from the internet", and the replacement
    for the old `_is_internet(E) -> E >= 1.0`. That test was a proxy: E == 1.0
    happens only for a `/0`, so `0.0.0.0/1` (half the routable internet),
    `1.0.0.0/8`, a partner's public `/24` and `::/0` all read as internal and the
    floor never fired. Classification belongs to the address space, so it is
    delegated to `netaddr.is_public` -- the same classifier `graph.zones` calls.

    Resolved CIDRs win over the label, exactly as in `exposure_score`, and ANY
    public member makes the grant internet-facing: a group containing both
    10.0.0.0/8 and 1.0.0.0/8 admits the internet.

    A SINGLE public host is deliberately not the internet
    ----------------------------------------------------
    `is_public` alone answers "does this contain a routable address", and a DMZ
    load balancer's own address (`52.20.10.10/32`) does. But the clause this
    function gates reads "exposed to the internet", and a grant to one named
    external peer is a reviewable exception, not a categorical emergency: the
    set of hosts that can use it is bounded and known. Forcing it critical would
    relabel every DMZ hop in the estate -- `graph.zones` refuses the mirror-image
    of this for the same reason, and its docstring spells it out: a host that
    *faces* the internet is not the internet.

    So the test is public AND more than one address. Every case the audit filed
    (`0.0.0.0/0`, `0.0.0.0/1`, `1.0.0.0/8`, a partner's public `/24`, `::/0`,
    `2000::/3`) is a multi-address block and still fires; only the single-host
    case is excluded, and its narrowness is already priced in by E = 0.1.

    Note this is deliberately NOT the same question `zone_of` asks. Zone answers
    "where does this node live" (a bare public /32 node key is outside the
    estate, so it is ZONE_INTERNET and B rises accordingly); the floor answers
    "is this grant open to the world". Both are true at once, and neither should
    be rewritten to match the other.
    """
    return any(_denotes_the_internet(t) for t in _source_tokens(source, source_cidrs))


# --- combination + bands ---------------------------------------------------

def severity_from_vector(E: float, P: float, D: float, B: float) -> int:
    c = SEVERITY_CONFIG
    impact = D * (c["impact_base"] + c["impact_p_weight"] * P)        # capped by D
    exposure_factor = c["exposure_floor"] + c["exposure_span"] * E    # floored
    raw = impact * exposure_factor * B
    return round(100 * min(raw, 1.0))


def band(severity: int) -> str:
    c = SEVERITY_CONFIG
    if severity >= c["band_critical"]:
        return "critical"
    if severity >= c["band_high"]:
        return "high"
    if severity >= c["band_medium"]:
        return "medium"
    return "low"


# --- per-type scoring (BUILD_SPEC s6.5) ------------------------------------

def score_over_permissive(*, source, source_kind, protocol, port, dest_tags,
                          src_zone, dst_zone, port_end=None, ports=None,
                          source_cidrs=None, source_unresolved=False) -> dict:
    """The full vector plus the three published guardrail clauses (ENGINE.md 5.4).

    `port_end` / `ports` / `source_cidrs` / `source_unresolved` are trailing and
    optional so every existing call site keeps working; supplying them is what
    makes the score describe the rule instead of its first port and its label.
    """
    E = exposure_score(source, source_kind, source_cidrs, source_unresolved)
    P, p_class = port_score(protocol, port, port_end, ports)
    D = dest_score(dest_tags)
    B = boundary_multiplier(src_zone, dst_zone)
    severity = severity_from_vector(E, P, D, B)

    internet = is_internet_source(source, source_kind, source_cidrs)
    intervals = _service_intervals(port, port_end, ports)
    forced, reasons = False, []
    sensitive = bool(set(dest_tags) & SENSITIVE_TAGS)
    # Clause 1 -- any/any from the internet.
    if internet and protocol == "any":
        forced = True
        reasons.append("internet any/any")
    # Clause 2 -- an admin/lateral-movement port from the internet. Tested by
    # INTERSECTION with the interval set, not by `port in ...`: `tcp/1-65535`
    # exposes 3389 just as surely as `tcp/3389` does, and a guardrail an
    # ordinary port range walks straight through is not a floor.
    if internet and _intersects(intervals, ADMIN_LATERAL_PORTS):
        forced = True
        reasons.append("admin/lateral-movement port exposed to the internet")
    # Clause 3 -- a regulated/crown-jewel destination reachable from the
    # internet. Port-independent by design.
    if sensitive and internet:
        forced = True
        reasons.append("regulated/crown-jewel asset reachable from the internet")
    return {
        "severity": severity,
        "vector": {"E": E, "P": P, "D": D, "B": B},
        "forced_critical": forced,
        "forced_reasons": reasons,
        "port_class": p_class,
        "E": E, "P": P, "D": D, "B": B,
    }


def score_transport_exposure(*, subtype, source, source_kind, protocol, port, l7_app,
                             dest_tags, src_zone, dst_zone, port_end=None, ports=None,
                             source_cidrs=None) -> dict:
    """Severity for transport-/application-layer exposure findings.

    quic_blind_spot: the smooth vector + a bump for the uninspectable app, forced
    critical when it crosses a boundary or reaches a sensitive asset from the
    internet. tls_fallback_not_blocked: a fixed control-gap base (you can't force
    the inspectable path), bumped for a sensitive destination.
    """
    E = exposure_score(source, source_kind, source_cidrs)
    P, p_class = port_score(protocol, port, port_end, ports)
    D = dest_score(dest_tags)
    B = boundary_multiplier(src_zone, dst_zone)
    base = severity_from_vector(E, P, D, B)
    tc = TRANSPORT_CONFIG
    sensitive = bool(set(dest_tags) & SENSITIVE_TAGS)

    forced, reasons = False, []
    if subtype == "tls_fallback_not_blocked":
        severity = tc["fallback_base"] + (tc["fallback_sensitive_bump"] if sensitive else 0)
    else:  # quic_blind_spot
        severity = base + tc["blind_spot_bump"]
        if is_internet_source(source, source_kind, source_cidrs) and (B > 1.0 or sensitive):
            forced = True
            reasons.append(f"uninspectable app ({l7_app}) reachable from the internet to "
                           f"{'a regulated/crown-jewel asset' if sensitive else 'an internal asset'}")
    return {
        "severity": min(severity, 100),
        "vector": {"E": E, "P": P, "D": D, "B": B},
        "forced_critical": forced,
        "forced_reasons": reasons,
        "port_class": p_class,
    }


def score_cross_tool_path(path: dict) -> dict:
    """Severity for one cross-tool reachability chain.

    The guardrail here used to require `path["boundary"] == "internet->internal"`
    -- a comparison against the DESTINATION's zone label. A PCI database that is
    also tagged `internet-facing` sits in the DMZ, so the boundary read
    `internet->dmz`, B collapsed to 1.0, and the crown-jewel asset most exposed
    to the internet was the one asset the floor could not protect. The floor now
    asks only what it means to ask: does this chain start in public address space
    and end on a regulated asset. The zone label still drives B (that is what B
    is for); it no longer gates the floor.

    `entry_cidrs` is read when the path carries it, so a chain entered through a
    named object classifies like the address space that object resolves to.
    """
    entry = path.get("entry", "")
    entry_cidrs = path.get("entry_cidrs") or []
    entry_kind = "cidr" if (parse_net(entry) is not None or is_any(entry)) else "identity"
    E = exposure_score(entry, entry_kind, entry_cidrs)
    P, p_class = port_score_from_service(path.get("terminal_service"))
    D = dest_score(path.get("terminal_tags", []))
    B = float(path.get("boundary_multiplier", 1.0))
    severity = severity_from_vector(E, P, D, B)

    reaches_sensitive = bool(set(path.get("terminal_tags", [])) & SENSITIVE_TAGS)
    # Either arm is enough: the entry IS public address space, or the graph
    # already labelled the crossing as starting at the internet zone. Keeping
    # the label arm means the floor is a strict superset of what it used to be.
    from_internet = (is_internet_source(entry, entry_kind, entry_cidrs)
                     or str(path.get("boundary", "")).startswith(f"{ZONE_INTERNET}->"))
    forced = bool(from_internet and reaches_sensitive)
    reasons = []
    if forced:
        reasons.append("cross-tool path enters from the internet and reaches a sensitive asset")
    return {
        "severity": severity,
        "vector": {"E": E, "P": P, "D": D, "B": B},
        "forced_critical": forced,
        "forced_reasons": reasons,
        "reaches_sensitive": reaches_sensitive,
        "port_class": p_class,
    }


def score_overlap(*, dest_tags_a, dest_tags_b, source_a, source_kind_a,
                  source_b, source_kind_b, source_cidrs_a=None,
                  source_cidrs_b=None) -> int:
    """cidr_overlap: hygiene, not exposure. Fixed base, one conditional bump.

    "Broad source" is expressed as an E threshold rather than a raw prefix
    length, so it reads the resolved address space (a named object that
    dereferences to `0.0.0.0/0` is broad) and so it means the same thing in both
    address families -- comparing a v6 prefix length against a v4-calibrated
    `overlap_broad_prefixlen` would call a v6 /32, which holds 2**96 addresses,
    "narrow". The threshold constant itself is unchanged and still published.
    """
    c = SEVERITY_CONFIG
    severity = c["overlap_base"]
    sensitive = bool((set(dest_tags_a) | set(dest_tags_b)) & SENSITIVE_TAGS)
    broad_floor = _band_for(4, c["overlap_broad_prefixlen"])

    def is_broad(source: str, kind: str, cidrs: list[str] | None) -> bool:
        return exposure_score(source, kind, cidrs) >= broad_floor

    if (sensitive
            or is_broad(source_a, source_kind_a, source_cidrs_a)
            or is_broad(source_b, source_kind_b, source_cidrs_b)):
        severity += c["overlap_sensitive_bump"]
    return severity


def score_shadowed(*, shadowed_action, source, source_kind, protocol, port,
                   dest_tags, src_zone, dst_zone, port_end=None, ports=None,
                   source_cidrs=None) -> dict:
    if shadowed_action == "allow":
        # dead allow config -- low fixed; carries no effective exposure
        return {"severity": SEVERITY_CONFIG["shadowed_allow_base"], "vector": {}, "forced_critical": False}
    # shadowed deny: traffic you intended to block is actually permitted by the
    # earlier broad allow -> score the full formula on that effective exposure.
    E = exposure_score(source, source_kind, source_cidrs)
    P, _ = port_score(protocol, port, port_end, ports)
    D = dest_score(dest_tags)
    B = boundary_multiplier(src_zone, dst_zone)
    return {
        "severity": severity_from_vector(E, P, D, B),
        "vector": {"E": E, "P": P, "D": D, "B": B},
        "forced_critical": False,
    }


def prefixlen_of(source: str, source_kind: str,
                 source_cidrs: list[str] | None = None) -> int | None:
    """The broadest prefix length the source denotes; None when it denotes none.

    A display/explanation signal, not an input to the score. It reads
    `source_cidrs` for the same reason `exposure_score` does: printing
    "source_prefixlen: null" next to a finding whose source object resolves to
    0.0.0.0/0 is the same lie in a smaller font. Mixed-family groups return the
    numerically smallest prefix length, which is only meaningful within one
    family -- callers that need the exposure ranking should read E.

    Reads the same canonical network `_exposure_of` bands, so the printed prefix
    length and the E beside it always describe one address space: a mapped
    `::ffff:0.0.0.0/96` prints 0, not 96, because as address space it IS a /0.
    """
    lens = [n.prefixlen for n in (_net_of(t) for t in _source_tokens(source, source_cidrs))
            if n is not None]
    lens += [0 for t in _source_tokens(source, source_cidrs) if _net_of(t) is None and is_any(t)]
    return min(lens) if lens else None


# --- internals -------------------------------------------------------------

def _source_tokens(source: str, source_cidrs: list[str] | None) -> list[str]:
    """The address-space tokens a source denotes, resolved list first.

    One rule, applied identically by every function that asks "what address
    space is this?": the resolved list wins when non-empty, otherwise the label
    itself is the only evidence there is. Returning a list (never a set) keeps
    every consumer's iteration order fixed by the caller's sorted input.
    """
    if source_cidrs:
        return list(source_cidrs)
    return [source] if isinstance(source, str) else []


def _net_of(token: str) -> Network | None:
    """The network a token denotes: parsed, and IPv4-mapped v6 UNWRAPPED.

    Every read of a prefix length in this module goes through here, and that is
    the whole point of it existing. `netaddr` treats unwrapping as part of what
    an address space IS (its module docstring publishes the decision and the
    reason), but applies it inside `is_public` only. A mapped block is always /96
    or longer, so banding the raw network puts EVERY mapped address space in the
    bottom v6 row: `::ffff:0.0.0.0/96` -- the entire internet, spelled in mapped
    form -- scored E = 0.1, the exposure of one host, while `is_public` called it
    public. Two halves of one published rule, disagreeing.

    `_unwrap_mapped` is imported under its private name rather than reimplemented
    here on purpose: a second copy of a classification decision is exactly the
    defect this round exists to remove. The cleaner home for it is
    `netaddr.parse_net` itself, so that `cidr_overlap`, `PolicyRecord` and
    `graph.zones` inherit it too -- that is a change to `netaddr`, not to this
    module.
    """
    net = parse_net(token)
    return None if net is None else _unwrap_mapped(net)


def _denotes_the_internet(token: str) -> bool:
    """One token: public address space holding more than one address.

    A wildcard WORD parses as nothing but denotes everything, so it short-cuts
    to True. Anything that is not public, and any single-address network, is
    False -- see `is_internet_source` for why the host case is excluded.
    """
    if not is_public(token):
        return False
    net = _net_of(token)
    if net is None:
        return True                       # "any" / "all" / "*": the whole space
    # Address COUNT is invariant under unwrapping (a mapped /120 and its 1.2.3.0/24
    # twin hold the same 256 addresses), so this arm cannot disagree with itself;
    # it goes through `_net_of` so the module has exactly one way to read a token.
    return net.num_addresses > 1


def _band_for(version: int, prefixlen: int) -> float:
    """Published (max_prefixlen, E) band lookup for one address family."""
    for max_prefixlen, e in EXPOSURE_BANDS_BY_VERSION[version]:
        if prefixlen <= max_prefixlen:
            return e
    return E_IDENTITY


def _exposure_of(token: str) -> float | None:
    """E for ONE token; None when it names no address space at all.

    Bands the CANONICAL network (`_net_of`), so `::ffff:52.20.10.0/120` scores
    0.3 exactly as `52.20.10.0/24` does rather than falling into the v6 /65-/128
    row at 0.1.
    """
    net = _net_of(token)
    if net is None:
        # A wildcard WORD ("any"/"all"/"*") parses as nothing but denotes
        # everything. Both band tables agree that a 0-prefix is 1.0, so the
        # family we look it up under cannot change the answer.
        return _band_for(4, 0) if is_any(token) else None
    return _band_for(net.version, net.prefixlen)


def _service_intervals(port: int | None, port_end: int | None,
                       ports: list[tuple[int, int]] | None) -> list[tuple[int, int]]:
    """The canonical interval set a service covers. `ports` wins when non-empty."""
    if ports:
        return _canonical_intervals(ports)
    if port is None:
        return []
    return _canonical_intervals([(port, port_end if port_end is not None else port)])


def _canonical_intervals(intervals) -> list[tuple[int, int]]:
    """Sort, clamp, drop the meaningless, and coalesce. Total, never raises.

    `DecodedService.ports` already arrives canonical, but this function must also
    accept whatever an arbitrary caller (a change-simulation payload, a test)
    hands it, because the guardrail floor reads the same intervals the score
    does and the two must never see different sets. Coalescing touching
    intervals -- [(80,80),(81,81)] -> [(80,81)] -- is what makes the span count
    independent of how the vendor punctuated the list.
    """
    cleaned: list[tuple[int, int]] = []
    for interval in intervals or ():
        try:
            lo, hi = interval
        except (TypeError, ValueError):
            continue                                  # not a pair: not an interval
        if not isinstance(lo, int) or not isinstance(hi, int):
            continue
        if lo > hi or hi < _PORT_MIN or lo > _PORT_MAX:
            continue                                  # inverted or entirely off-range
        cleaned.append((max(lo, _PORT_MIN), min(hi, _PORT_MAX)))
    merged: list[tuple[int, int]] = []
    for lo, hi in sorted(cleaned):
        if merged and lo <= merged[-1][1] + 1:
            merged[-1] = (merged[-1][0], max(merged[-1][1], hi))
        else:
            merged.append((lo, hi))
    return merged


def _intersects(intervals: list[tuple[int, int]], ports) -> bool:
    """True when any port in `ports` falls inside any interval.

    Iterates the small class set against the (also small) interval list rather
    than walking 65,535 ports: `tcp/1-65535` is one comparison per class member.
    The result is a boolean, so iterating a set here cannot leak order.
    """
    return any(lo <= p <= hi for p in ports for lo, hi in intervals)


def _covers_unclassified(intervals: list[tuple[int, int]]) -> bool:
    """True when the service opens at least one port in no named class.

    Counted, not enumerated: the intervals are disjoint by construction, so the
    number of NAMED ports they contain is exact, and any shortfall against the
    total span is an unclassified port.
    """
    span = sum(hi - lo + 1 for lo, hi in intervals)
    if span == 0:
        return False
    named = sum(1 for p in _CLASSIFIED_PORTS
                if any(lo <= p <= hi for lo, hi in intervals))
    return named < span


def _class_applies(label: str, protocol: str | None,
                   intervals: list[tuple[int, int]], span: int) -> bool:
    """Does this service fall in the named port class? One row of the table."""
    if label == PORT_CLASS_ANY_PORT:
        # Every protocol/port (a wildcard rule), or so many ports that naming
        # them individually is a distinction without a difference.
        return protocol == "any" or span > PORT_SPAN_ANY
    if label == PORT_CLASS_UNKNOWN:
        return _covers_unclassified(intervals)
    return _intersects(intervals, _PORT_CLASS_SETS[label])
