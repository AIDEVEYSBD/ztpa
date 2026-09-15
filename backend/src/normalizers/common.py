"""Shared normalization helpers + the intermediate shapes the normalizers emit.

Each normalizer turns one tool's native export into:
  - records:  canonical PolicyRecord rows (the policy table)
  - entities: ObservedEntity rows (one tool's *view* of a node; the identity
              layer later merges these across tools into assets)
  - resolved: ResolvedObject audit rows (name -> value dereferencing)
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from typing import Optional, Union

from ..config import APP_BY_PORT, APP_TRANSPORT, L7_APPS
from ..models import (
    Circuit, NetDevice, NetInterface, NetLink, PolicyRecord, Subnet, Vlan,
)
from ..netaddr import ANY_V4, is_any, parse_net

# The internet node key and the /0 network are the SAME string by construction,
# so no layer can drift into comparing one against the other.
INTERNET_CIDR = ANY_V4

# The L4 vocabulary we decode. Must stay a subset of models.Protocol -- a token
# that reaches PolicyRecord.protocol outside this set is a validation error, not
# a silent rewrite.
_PROTOCOLS = {"tcp", "udp", "icmp", "sctp", "gre", "esp", "ah", "any"}

# Vendor keywords that mean "every protocol". Palo Alto and ASA both write a
# true any/any rule as the service `ip` or `all`; both used to decode to plain
# "tcp", which is precisely why the any/any guardrail never fired on a real
# export while firing correctly on the demo fixture.
_PROTOCOL_ALIASES = {"ip": "any", "all": "any", "*": "any", "ip-any": "any"}

_PORT_MIN, _PORT_MAX = 0, 65535


@dataclass
class ObservedEntity:
    """One tool's view of one node, before the identity layer merges the views.

    Why there are TWO address fields
    --------------------------------
    `cidr` is a single Optional[str] and always was, so an address GROUP -- an
    object whose catalog value is ``["0.0.0.0/0", "10.0.0.0/8"]`` -- had nowhere
    to put its address space and came through as ``cidr=None``. That is where
    the fourth spelling of "the internet" lost its address space: with `cidr`
    empty, `identity.resolve_identities` built ``Asset.ip_set == []``,
    `graph.build` handed that empty list to `zones.zone_of`, and a group
    resolving to ``0.0.0.0/0`` was classified ZONE_INTERNAL. The boundary
    multiplier then collapsed 1.5 -> 1.0 and the SAME grant scored 86/critical
    written ``0.0.0.0/0`` and 57/medium written as a two-member group.

    The resolved space already travelled correctly on `PolicyRecord.source_cidrs`
    (which is why the E term was right and only B was wrong), but a record field
    cannot classify a NODE: zones are a property of the graph, and the graph is
    built from assets. So the entity -- the asset's only input -- has to be able
    to carry more than one block.

    `cidrs` is that channel: EVERY block of the address space this node denotes,
    canonical, ``[]`` when it denotes none. `cidr` keeps its exact old meaning
    (the single block, when there is exactly one) because callers and tests read
    it as "none of several is THE cidr"; it is redundant with ``cidrs[0]`` and
    is deliberately left alone rather than widened, so no existing reader has to
    re-learn a type. The identity layer folds BOTH into `Asset.ip_set`.
    """

    name: str                                   # canonical node key (CIDR string or asset name)
    kind: str                                   # "cidr" | "identity"
    tool: str
    ip: Optional[str] = None                    # concrete host ip
    cidr: Optional[str] = None                  # network cidr for named segments / raw subnets
    # The FULL address space this node denotes ([] = none). A single-block node
    # populates both this and `cidr`; a multi-block group populates only this.
    cidrs: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)
    identifiers: dict = field(default_factory=dict)
    abstract: bool = False                      # internet / zone / subnet (not a concrete asset)


@dataclass
class ResolvedObject:
    source_tool: str
    object_name: str
    object_kind: str                            # address|service|zone|application|user|tag_group
    resolved: dict
    source_device: Optional[str] = None
    is_dynamic: bool = False


@dataclass
class NormalizeResult:
    """Everything one export yielded, in the engine's own vocabulary.

    The first three fields are POLICY: grants, the nodes they name, and the
    object-dereferencing audit trail. The six that follow are INFRASTRUCTURE:
    the network those grants run on.

    They travel together because they come from one read of one console -- a
    FortiManager export carries both its policy package and its managed-device
    list -- and they are kept as separate fields, rather than folded into the
    entity list, because they are consumed by two different graphs that must
    never merge. `src.graph` reads `records` and `entities`. `src.topology`
    reads the six below. A cable is not a grant, and `verify_engine` asserts
    `cross_tool_paths` is byte-identical with and without any of them.

    A normalizer populating none of the infrastructure fields is not degraded:
    Guardicore genuinely has no view of a switch. What would be degraded is a
    normalizer inventing one.
    """

    records: list[PolicyRecord] = field(default_factory=list)
    entities: list[ObservedEntity] = field(default_factory=list)
    resolved: list[ResolvedObject] = field(default_factory=list)
    # --- infrastructure (see models.py "THE INFRASTRUCTURE LAYER") ---
    devices: list[NetDevice] = field(default_factory=list)
    interfaces: list[NetInterface] = field(default_factory=list)
    links: list[NetLink] = field(default_factory=list)
    vlans: list[Vlan] = field(default_factory=list)
    subnets: list[Subnet] = field(default_factory=list)
    circuits: list[Circuit] = field(default_factory=list)

    def extend(self, other: "NormalizeResult") -> None:
        self.records.extend(other.records)
        self.entities.extend(other.entities)
        self.resolved.extend(other.resolved)
        self.devices.extend(other.devices)
        self.interfaces.extend(other.interfaces)
        self.links.extend(other.links)
        self.vlans.extend(other.vlans)
        self.subnets.extend(other.subnets)
        self.circuits.extend(other.circuits)


# ---------------------------------------------------------------------------
# Scope — the namespace an address is unique inside.
#
# `identity.resolve_identities` will only fuse two names on a shared IP INSIDE
# one declared namespace, because an RFC 1918 address identifies a host only
# relative to the VRF / VPC / account that assigns it. That rule was written
# against `ObservedEntity.identifiers[<namespace key>]` — and no normalizer
# populated one, so `identity.context_of` returned None for every entity any
# shipped code produced: the scoped arm (and with it MAX_IP_FANOUT and the
# environment guard) was unreachable in production and the ONLY guard that could
# fire was `unscoped_ip`. The merge did not misbehave — it fails safe, so the
# effect was silently withholding every shared-IP merge — but a rule that cannot
# be satisfied is not a rule, and the tests covering it reached that state only
# by `setattr`.
#
# `scope_identifiers` is the missing half: it lifts whatever namespace an export
# row actually declares into the canonical key the merge reads. Nothing is
# invented — a row that declares no namespace still yields {}, which is exactly
# the "no scope, therefore no merge" answer. NONE of the three bundled demo
# exports declares one, so the seeded snapshot is unchanged by this: it stays a
# hostname-merge-only estate whose `10.30.7.7` collision is a review candidate.
# ---------------------------------------------------------------------------

# The canonical namespace keys, in the order `identity.CONTEXT_IDENTIFIER_KEYS`
# resolves them (narrowest first). Kept as its own tuple rather than imported
# from `identity` because the dependency runs the other way: identity imports
# this module.
SCOPE_KEYS: tuple[str, ...] = ("vrf", "vpc", "account", "subscription", "project", "tenant")

# Vendor spellings -> canonical key. Compared after case-folding and stripping
# every non-alphanumeric character, so `vpcId`, `vpc_id` and `VPC-ID` are one
# entry. Deliberately conservative: only fields that NAME A NAMESPACE are here.
# `region`, `env` and `cloud` are absent for the same reason `identity` excludes
# them — every account in the estate shares those labels, so keying a merge on
# one would reintroduce the collision the scope rule exists to prevent.
_SCOPE_ALIASES: dict[str, str] = {
    "vrf": "vrf", "vrfname": "vrf", "routinginstance": "vrf", "virtualrouter": "vrf",
    "vpc": "vpc", "vpcid": "vpc", "vnet": "vpc", "vnetid": "vpc", "networkid": "vpc",
    "account": "account", "accountid": "account", "awsaccountid": "account",
    "accountexternalid": "account",
    "subscription": "subscription", "subscriptionid": "subscription",
    "subscriptionexternalid": "subscription",
    "project": "project", "projectid": "project", "gcpprojectid": "project",
    "tenant": "tenant", "tenantid": "tenant", "tenantname": "tenant",
}


def _scope_key(key) -> Optional[str]:
    """A raw export key -> the canonical namespace key it spells, or None."""
    if not isinstance(key, str):
        return None
    return _SCOPE_ALIASES.get("".join(ch for ch in key.lower() if ch.isalnum()))


def scope_identifiers(meta) -> dict[str, str]:
    """The namespaces one export row declares, under canonical keys.

    Returns ``{}`` for a row that declares none, for a non-dict, and for a key
    whose value is empty or not a scalar — all four mean "this export declared
    no scope", which `identity.context_of` reads as None and the merge reads as
    "do not fuse". Failing to an empty dict rather than a guess is the whole
    contract: a WRONG namespace would union two hosts that share an address,
    which is the false statement about the customer's network this layer exists
    to prevent.

    An integer value is accepted and stringified because a cloud account id is a
    JSON number about as often as it is a string, and `12345` and `"12345"` must
    not be two namespaces. `bool` is excluded — `True` is a flag, not an id.

    Deterministic: source keys are visited in sorted order, so when a row spells
    one namespace twice (``vpc`` and ``vpcId``) the winner is fixed rather than
    an accident of JSON key order, and the result is emitted in `SCOPE_KEYS`
    order rather than insertion order.
    """
    if not isinstance(meta, dict):
        return {}
    found: dict[str, str] = {}
    for raw_key in sorted((k for k in meta if isinstance(k, str))):
        canon = _scope_key(raw_key)
        if canon is None or canon in found:
            continue
        value = meta[raw_key]
        if isinstance(value, str) and value.strip():
            found[canon] = value.strip()
        elif isinstance(value, int) and not isinstance(value, bool):
            found[canon] = str(value)
    return {k: found[k] for k in SCOPE_KEYS if k in found}


def is_cidr(token: str) -> bool:
    """True only for explicit network notation (has a prefix length)."""
    if "/" not in token:
        return False
    try:
        ipaddress.ip_network(token, strict=False)
        return True
    except ValueError:
        return False


def normalize_cidr(token: str) -> str:
    return str(ipaddress.ip_network(token, strict=False))


@dataclass
class DecodedService:
    """The fully-decoded service of a rule: L4 transport + L7 application.

    `l7_app` is the decoded App-ID (e.g. "quic"); `l7_source` records HOW it was
    decoded ("declared" = the export named it; "inferred" = our deterministic
    (proto, port) lookup). Both are facts the engine owns -- never a model guess.

    `ports` carries EVERY interval of a comma list ("tcp/80,443"), which the
    scalar port/port_end pair structurally cannot hold; `warnings` carries the
    non-fatal decode problems that used to be swallowed. Both exist because the
    old decoder answered "I don't know" and "the export said something invalid"
    with the same silence -- and "unknown port" scores 0.5, i.e. mid-risk, so a
    dropped port list read as a clean rule.
    """

    protocol: str                       # tcp | udp | icmp | sctp | gre | esp | ah | any
    port: Optional[int]                 # first interval's start (None = unknown/rejected)
    port_end: Optional[int]             # first interval's end (None = a single port)
    label: str                          # human label, e.g. "tcp/443", "quic"
    l7_app: Optional[str]               # decoded App-ID, or None if unknown
    l7_source: Optional[str]            # "declared" | "inferred" | None
    # ALL intervals, canonical (sorted, overlaps merged), when the service names
    # more than one. None -- not [] -- when the service is a single interval, in
    # which case (port, port_end) IS the whole story. Consumers that want to
    # iterate uniformly should read `intervals()`.
    ports: Optional[list[tuple[int, int]]] = None
    # Non-fatal decode problems, in the order they were found; [] when clean.
    # A warning never blocks a record: an unreadable service is still a grant.
    warnings: list[str] = field(default_factory=list)

    def intervals(self) -> list[tuple[int, int]]:
        """Every (lo, hi) this service covers -- [] when no port is known.

        The one place that reconciles `ports` with the scalar pair, so no caller
        has to remember which is authoritative.
        """
        if self.ports is not None:
            return list(self.ports)
        if self.port is None:
            return []
        return [(self.port, self.port_end if self.port_end is not None else self.port)]


def _decode_proto(proto: Optional[str]) -> tuple[str, list[str]]:
    """Map a raw protocol token onto the decoded vocabulary. Never raises.

    Returns (protocol, warnings). Absent input defaults to tcp silently -- there
    is nothing to report about a field the export did not have. An UNRECOGNIZED
    token still defaults to tcp, because the engine has to score something, but
    the coercion is now RECORDED: "reported as TCP" for an export that said
    `application-default` or `HTTP_AND_HTTPS` is a false statement about the
    customer's network, and a false statement nobody can see is the failure mode
    this whole phase exists to remove.
    """
    if proto is None:
        return "tcp", []
    raw = str(proto).strip()
    if not raw:
        return "tcp", []
    p = _PROTOCOL_ALIASES.get(raw.lower(), raw.lower())
    if p in _PROTOCOLS:
        return p, []
    return "tcp", [f"unrecognized protocol {raw!r} defaulted to tcp"]


def _infer_l7(protocol: str, port: Optional[int]) -> tuple[Optional[str], Optional[str]]:
    """Deterministic (protocol, port) -> App-ID lookup. Marked 'inferred'."""
    if port is None:
        return (None, None)
    app = APP_BY_PORT.get((protocol, port))
    return (app, "inferred") if app else (None, None)


def _decode_port(token: str) -> tuple[Optional[int], Optional[str]]:
    """One port number -> (value, warning). Validates 0 <= port <= 65535."""
    t = token.strip()
    if not t:
        return None, "empty port token"
    try:
        value = int(t, 10)
    except ValueError:
        return None, f"unparseable port {t!r}"
    if not (_PORT_MIN <= value <= _PORT_MAX):
        return None, f"port {value} outside {_PORT_MIN}-{_PORT_MAX}"
    return value, None


def _merge_intervals(intervals: list[tuple[int, int]]) -> list[tuple[int, int]]:
    """Sort and coalesce touching/overlapping intervals. Deterministic."""
    merged: list[tuple[int, int]] = []
    for lo, hi in sorted(intervals):
        if merged and lo <= merged[-1][1] + 1:
            merged[-1] = (merged[-1][0], max(merged[-1][1], hi))
        else:
            merged.append((lo, hi))
    return merged


def _parse_port_spec(spec: str) -> tuple[list[tuple[int, int]], list[str]]:
    """Decode the port half of a service token into canonical intervals.

    Handles every encoding a real export uses: a single port ("443"), a range
    ("8000-8100"), a COMMA LIST of either ("80,443", "80,8000-8100") -- the most
    common AlgoSec/Palo encoding, which used to fail int() as a whole and vanish,
    leaving a rule that grants two ports scored as "port unknown" -- and the
    WILDCARD ("any" / "all" / "*"), which is the widest grant a service column
    can express and which used to decode to no port at all. See the comment on
    the wildcard branch below; it is the sharpest inversion in the decoder.

    Invalid intervals are REJECTED with a warning, never coerced. An inverted
    range or a 70000 has no meaning worth preserving, and passing it on would
    put a nonsense number in front of the port-class lookup and the guardrails.

    The result is sorted with overlaps merged, so "tcp/443,80" and "tcp/80,443"
    decode identically: the snapshot fingerprint must not depend on the order a
    vendor happened to write the list in.
    """
    warnings: list[str] = []
    raw = spec.strip()
    if not raw:
        return [], ["missing port specification"]
    intervals: list[tuple[int, int]] = []
    for token in raw.split(","):
        tok = token.strip()
        if not tok:
            warnings.append("empty port token")
            continue
        # THE WILDCARD VOCABULARY, APPLIED PER COMMA ELEMENT.
        # `any` / `all` / `*` is how Palo Alto, Check Point and AlgoSec spell
        # "every port of this protocol", and `"*"` is how an Azure NSG spells
        # `destinationPortRange` (which Wiz ingests and hands us through the
        # separate `port` field). All of it used to fall through to `int("any")`,
        # be rejected, and leave the record with `port=None` -> P_UNKNOWN (0.5)
        # and an EMPTY interval set -- so `tcp/any`, the widest TCP grant it is
        # possible to write, produced no finding at all while the byte-equivalent
        # `tcp/1-65535` scored 90/critical, and guardrail clause 2 (which
        # intersects the intervals with the admin ports) could not fire either.
        # Narrowing a grant from "every protocol" to "every port of one protocol"
        # must not be able to silence the engine.
        #
        # `netaddr.is_any` is the SAME test the whole-service token
        # (`parse_service`), the src/dst tokens (`cidrs_for_token`) and
        # `_PROTOCOL_ALIASES` already use, so the four places that decide what a
        # wildcard is cannot drift apart. It is safe on port tokens: it matches
        # only the three words and a token that parses as a 0-prefix NETWORK, so
        # "0", "443" and "-5" are unaffected (verified in test_parse_service).
        #
        # Per element, not per spec, because `tcp/443,any` grants every port --
        # the union of a wildcard with anything is the wildcard, and
        # `_merge_intervals` collapses it to exactly that.
        if is_any(tok):
            intervals.append((_PORT_MIN, _PORT_MAX))
            continue
        # A leading "-" is a negative number, not a range separator: `port=-5`
        # must read as "out of range", not as an unparseable range.
        if "-" in tok[1:]:
            head, _, hi_tok = tok[1:].partition("-")
            lo_tok = tok[0] + head
            if not lo_tok.strip() or not hi_tok.strip():
                warnings.append(f"unparseable port range {tok!r}")
                continue
            lo, lo_warn = _decode_port(lo_tok)
            hi, hi_warn = _decode_port(hi_tok)
            warnings.extend(w for w in (lo_warn, hi_warn) if w)
            if lo is None or hi is None:
                continue
            if lo > hi:
                warnings.append(f"inverted port range {lo}-{hi} rejected")
                continue
            intervals.append((lo, hi))
            continue
        value, warn = _decode_port(tok)
        if value is None:
            warnings.append(warn or f"unparseable port {tok!r}")
            continue
        intervals.append((value, value))
    return _merge_intervals(intervals), warnings


def _project(intervals: list[tuple[int, int]]
             ) -> tuple[Optional[int], Optional[int], Optional[list[tuple[int, int]]]]:
    """Canonical intervals -> the (port, port_end, ports) triple.

    port/port_end stay the FIRST interval so every existing consumer keeps
    working unchanged; `ports` is populated only when there is more than one
    interval, so "is this multi-valued" is a `is not None` check.
    """
    if not intervals:
        return None, None, None
    lo, hi = intervals[0]
    return lo, (hi if hi != lo else None), (intervals if len(intervals) > 1 else None)


def _spec_label(intervals: list[tuple[int, int]]) -> str:
    """Render canonical intervals back to the '80,8000-8100' form."""
    return ",".join(f"{lo}-{hi}" if hi != lo else f"{lo}" for lo, hi in intervals)


def _from_app(app: str, port: Optional[int], protocol: Optional[str]) -> DecodedService:
    """Resolve a declared App-ID token to its fixed transport (port/proto may override).

    An explicit port that fails validation falls back to the App-ID's own fixed
    transport port and records a warning -- that fallback is a real fact (an
    App-ID names the application, and the transport it rides is fixed), not an
    invented one, and it beats `int("abc")` raising out of a normalizer.
    """
    app = str(app).strip().lower()
    t_proto, t_port = APP_TRANSPORT.get(app, ("tcp", None))
    if protocol is not None and str(protocol).strip():
        proto, warnings = _decode_proto(protocol)
    else:
        proto, warnings = t_proto, []
    pi = t_port
    if port is not None:
        value, warn = _decode_port(str(port))
        if warn:
            warnings = warnings + [warn]
        else:
            pi = value
    return DecodedService(proto, pi, None, app, app, "declared", None, warnings)


def parse_service(service: Optional[str] = None, port: Optional[int] = None,
                  protocol: Optional[str] = None, app: Optional[str] = None) -> DecodedService:
    """Decode a rule's service into L4 + L7 facts.

    Accepts any of: an AlgoSec-style `service` string ("tcp/443", "tcp/8000-8100",
    "tcp/80,443", "quic", "any", "ip"); a Guardicore/Wiz separate `port`+`protocol`;
    and/or an explicit `app` App-ID field.

    NEVER RAISES, on any input at all -- including a list, an int, or a dict that
    a mis-mapped ingest profile put in the service column. A normalizer that dies
    on one bad row loses the other 4,999, so every failure here is expressed as a
    `warnings` entry on the returned DecodedService instead of an exception.

    The signature and the position of the existing fields are frozen: main.py,
    staging.py, intake.py, profile.py and severity.py all consume this.
    """
    if app is not None and str(app).strip().lower() in L7_APPS:
        return _from_app(app, port, protocol)

    if service is not None and str(service).strip():
        s = str(service).strip()
        low = s.lower()
        # One wildcard vocabulary, shared with source/destination classification:
        # any / Any / ANY / all / * / 0.0.0.0/0 can no longer diverge by spelling.
        if is_any(low):
            return DecodedService("any", None, None, low, None, None)
        if low in L7_APPS:                         # App-ID named as the service
            return _from_app(low, port, protocol)
        if "/" in s:
            proto_tok, _, spec = s.partition("/")
            proto, warnings = _decode_proto(proto_tok)
            intervals, port_warnings = _parse_port_spec(spec)
            pstart, pend, ports = _project(intervals)
            l7, l7src = _infer_l7(proto, pstart)
            return DecodedService(proto, pstart, pend, s, l7, l7src, ports,
                                  warnings + port_warnings)
        # bare token: a protocol (icmp/gre/esp/...), a vendor any-keyword
        # (ip/all), or a service name we do not recognize (warned, then tcp).
        proto, warnings = _decode_proto(low)
        return DecodedService(proto, None, None, s, None, None, None, warnings)

    proto, warnings = _decode_proto(protocol)
    if port is None:
        if protocol is None or not str(protocol).strip():
            # NOTHING was supplied: no service token, no port, no protocol, and
            # no App-ID we recognize. The old answer was a confident bare `tcp`
            # with no warning at all -- the audit's sharpest row, "no `service`
            # field at all -> NO FINDING, and zero warnings" -- and `port=None`
            # scores P_UNKNOWN (0.5), i.e. mid-risk, so an unread service column
            # reads as a moderate rule rather than as a gap. The decode is
            # unchanged (there is nothing else to score); what changes is that
            # the absence is now a FACT on the record, which `service_audit`
            # carries into the ingest audit trail.
            return DecodedService(proto, None, None, proto, None, None, None,
                                  warnings + ["no service, port or protocol specified"])
        return DecodedService(proto, None, None, proto, None, None, None, warnings)
    intervals, port_warnings = _parse_port_spec(str(port))
    pstart, pend, ports = _project(intervals)
    warnings = warnings + port_warnings
    l7, l7src = _infer_l7(proto, pstart)
    # Keep the raw token in the label when nothing decoded, so the console shows
    # what the export actually said rather than a confident "tcp".
    label = f"{proto}/{_spec_label(intervals)}" if intervals else f"{proto}/{str(port).strip()}"
    return DecodedService(proto, pstart, pend, label, l7, l7src, ports, warnings)


# ---------------------------------------------------------------------------
# The address-space NOTATIONS a real export writes, beyond `a.b.c.d/len`.
#
# `parse_net` (netaddr.py) already reads prefix notation, the slash-netmask form
# `10.0.0.0/255.0.0.0` and the slash-hostmask form `10.0.0.0/0.255.255.255`,
# plus a bare host. Two more notations are in every catalog the audit sampled
# and resolved to NOTHING, which is the worst possible answer: `source_cidrs`
# came back `[]`, `exposure_score` fell back to E_IDENTITY (0.1 -- one host) and
# an internet-to-PCI grant produced zero findings.
#
#   Check Point / Palo range object   1.0.0.0-223.255.255.255
#   Cisco ASA address + mask          10.0.0.0 0.255.255.255   (wildcard)
#                                     10.0.0.0 255.0.0.0       (netmask)
#
# Both are decoded here rather than in `netaddr.parse_net` on purpose: they are
# EXPORT notations, not address-space classification, and `parse_net` is the
# frozen primitive that `zones`, `severity` and `models` all share.
# ---------------------------------------------------------------------------

# The separator a range object uses. One partition, not a split: a range has
# exactly two endpoints, and `db-prod-01` must never be read as one.
_RANGE_SEP = "-"

# The characters an IPv4/IPv6 literal is made of. Used only to decide whether a
# token was WRITTEN as address space (and is therefore worth a malformed-address
# warning), never to parse one -- `ipaddress` does the parsing.
_ADDRESS_CHARS: frozenset[str] = frozenset("0123456789abcdefABCDEF.:")

# The two address classes, as one alias, so the range/mask helpers below can say
# what they take and return without repeating the union at every signature.
_IPAddress = Union[ipaddress.IPv4Address, ipaddress.IPv6Address]


def _bare_address(token: str) -> Optional[_IPAddress]:
    """A bare IPv4/IPv6 literal -> the address object; None otherwise.

    Deliberately NOT `parse_net`: an endpoint of a range and the left half of an
    ASA mask pair are addresses, never networks, and accepting `10.0.0.0/8-...`
    here would invent a shape no vendor writes.
    """
    try:
        return ipaddress.ip_address(token.strip())
    except ValueError:
        return None


def _address_shaped(token: str) -> bool:
    """True when a token is spelled out of address characters alone."""
    t = token.strip()
    return bool(t) and all(ch in _ADDRESS_CHARS for ch in t)


def _cidrs_for_range(token: str) -> list[str]:
    """`10.0.0.0-10.0.3.255` -> the minimal covering CIDR list; [] if not a range.

    This is how Check Point writes an address range object and how AlgoSec
    re-exports one, and `0.0.0.0-255.255.255.255` is a spelling of the internet
    that produced no finding at all. `summarize_address_range` yields the
    minimal set in ascending order, so the answer is canonical and the record's
    `source_cidrs` is deterministic. An inverted or mixed-family range resolves
    to nothing and is reported by the caller as a malformed address -- coercing
    it (by swapping the endpoints) would silently invent a grant.
    """
    lo_tok, sep, hi_tok = token.partition(_RANGE_SEP)
    if not sep:
        return []
    lo, hi = _bare_address(lo_tok), _bare_address(hi_tok)
    if lo is None or hi is None or lo.version != hi.version or lo > hi:
        return []
    return [str(net) for net in ipaddress.summarize_address_range(lo, hi)]


def _prefixlen_for_mask(address: _IPAddress, mask_token: str) -> Optional[int]:
    """(address, dotted mask) -> prefix length, for BOTH Cisco conventions.

    ASA/IOS writes a block two ways and the same file uses both: a NETMASK
    (contiguous 1s from the left, `255.0.0.0`) in `network-object`, and a
    WILDCARD mask (contiguous 1s from the right, `0.255.255.255`) in an ACL.
    They are bit-complements, so exactly one reading is valid for any mask
    except the two that are their own complement:

      ``0.0.0.0``          netmask -> /0    wildcard -> /32
      ``255.255.255.255``  netmask -> /32   wildcard -> /0

    For those two the ADDRESS decides, because only one reading of each pair is
    something an operator ever writes: `0.0.0.0 0.0.0.0` and
    `0.0.0.0 255.255.255.255` are both the ASA idiom for "any", while
    `10.0.0.5 <either>` is that one host in whichever convention. Guessing the
    other way round would either inflate one host into the whole internet or
    shrink the internet to one host -- and this rule does neither.

    A DISCONTIGUOUS mask (`0.255.0.255`, a legal ACL wildcard for "every second
    /16") denotes a set no CIDR list can express, so it returns None and the
    caller reports it rather than approximating it.
    """
    mask = _bare_address(mask_token)
    if mask is None or mask.version != 4 or address.version != 4:
        return None
    bits = int(mask)
    ones = bin(bits).count("1")
    is_netmask = bits == (((1 << ones) - 1) << (32 - ones))    # 1s then 0s
    is_wildcard = bits == ((1 << ones) - 1)                    # 0s then 1s
    if is_netmask and is_wildcard:                             # 0.0.0.0 / 255.255.255.255
        return 0 if int(address) == 0 else 32
    if is_netmask:
        return ones
    if is_wildcard:
        return 32 - ones
    return None


def _cidrs_for_masked(token: str) -> list[str]:
    """`10.0.0.0 0.255.255.255` -> `["10.0.0.0/8"]`; [] if not an address+mask."""
    parts = token.split()
    if len(parts) != 2:
        return []
    address = _bare_address(parts[0])
    if address is None:
        return []
    prefixlen = _prefixlen_for_mask(address, parts[1])
    if prefixlen is None:
        return []
    return [str(ipaddress.ip_network((address, prefixlen), strict=False))]


def looks_like_address_space(token: Optional[str]) -> bool:
    """True when a token was WRITTEN as address space, whatever it resolves to.

    The one predicate that separates "this object names no address" (a user
    group, a tag, an application) from "this object claims to be an address and
    is not one" (`10.0.0.0/33`, `10.0.0.0-9.0.0.0`, `10.0.0.0 0.255.0.255`).
    That distinction is the whole basis of the malformed-address warning and, as
    of B2, of `PolicyRecord.source_unresolved`: only the second case may raise
    the exposure floor, because only the second case is evidence that address
    space was meant.

    Deliberately narrow on the two mask/range notations -- a hostname is allowed
    to contain a dash (`db-prod-01`, `ANY-EXTERNAL`) and an object label is
    allowed to contain a space, so the half that is not the separator must be a
    bare IP literal AND the other half must be spelled out of address characters
    alone. `web-10.0.0.1` is therefore a name, not a broken range.
    """
    if not isinstance(token, str):
        return False
    t = token.strip()
    if not t:
        return False
    if "/" in t:                                   # prefix, netmask or hostmask form
        return True
    lo, sep, hi = t.partition(_RANGE_SEP)
    if sep and _bare_address(lo) is not None and _address_shaped(hi):
        return True
    parts = t.split()
    return (len(parts) == 2 and _bare_address(parts[0]) is not None
            and _address_shaped(parts[1]))


def cidrs_for_token(token: Optional[str]) -> list[str]:
    """Resolve a source/destination TOKEN to the address space it denotes.

    This is the token-level half of the "carry the resolved value, not the label"
    fix: it handles every case that needs no catalog lookup --

      an address        `10.20.0.0/16`, `10.20.0.5` (its own /32),
                        `10.20.0.0/255.255.0.0`, `10.20.0.0/0.0.255.255`
      the wildcards     `any`/`all`/`*`/`0.0.0.0/0`, all collapsing onto
                        INTERNET_CIDR so four spellings of one rule score alike
      a range object    `10.20.0.0-10.20.255.255` (Check Point)
      address + mask    `10.20.0.0 255.255.0.0` / `10.20.0.0 0.0.255.255` (ASA)

    Returns [] for anything else -- a named object, a user, a tag, an
    application group. That emptiness is the signal each NORMALIZER must act on
    by resolving the name against its export's object catalog before the record
    is built; see PolicyRecord.source_cidrs on why [] must mean "no address
    space exists", never "nobody looked".
    """
    if token is None:
        return []
    net = parse_net(token)
    if net is not None:
        return [str(net)]
    if is_any(token):
        return [INTERNET_CIDR]
    if not isinstance(token, str):
        return []
    return _cidrs_for_range(token) or _cidrs_for_masked(token)


def record_from_service(*, record_id: str, source_tool: str, raw_ref: str, source: str,
                       destination: str, svc: DecodedService, action: str = "allow",
                       dest_tags: Optional[list[str]] = None, order: Optional[int] = None,
                       source_ip: Optional[str] = None, dest_ip: Optional[str] = None,
                       note: Optional[str] = None,
                       source_cidrs: Optional[list[str]] = None,
                       dest_cidrs: Optional[list[str]] = None,
                       source_unresolved: bool = False) -> PolicyRecord:
    """Build a canonical PolicyRecord from an ALREADY-decoded service.

    Every ad-hoc record site (the custom-change endpoint, intake extraction, the
    agent's simulate tool) hand-rolls this constructor, and the ones that do
    quietly drop half of what `parse_service` just decoded -- `port_end` and
    `l7_app` in particular. Those two are inputs to range-aware port scoring and
    to `_grant_matches`, so losing them turns a "tcp/8000-8100" grant into a
    single-port one and an App-ID grant into an unknown service. Constructing
    records through one helper is what makes that class of loss impossible
    rather than merely unlikely.

    `source_kind` / `destination_kind` are DERIVED from the token here (never
    passed in) so the same string cannot be a CIDR at one call site and an
    identity at the next. `source_cidrs` / `dest_cidrs` follow the same rule by
    default -- derived from the token via `cidrs_for_token` -- but a caller that
    HAS an object catalog (a normalizer resolving a named object or an address
    group) passes the resolved list explicitly and it wins. Passing [] is a
    deliberate statement that the object resolves to no address space at all.

    `source_unresolved` splits that [] in two (see `PolicyRecord.source_unresolved`).
    A caller that does not pass it gets the honest default for a token it never
    inspected -- False, "nothing claimed address space" -- and when the caller
    passed no `source_cidrs` either, the flag is derived here from the token
    itself, so an ad-hoc record site cannot silently lose the distinction the
    way it used to lose `port_end` and `l7_app`.
    """
    derived_source = source_cidrs is None
    resolved_source = cidrs_for_token(source) if derived_source else list(source_cidrs)
    return PolicyRecord(
        id=record_id, source_tool=source_tool, raw_ref=raw_ref,
        source=source, source_kind="cidr" if is_cidr(source) else "identity",
        destination=destination, destination_kind="cidr" if is_cidr(destination) else "identity",
        source_cidrs=resolved_source,
        dest_cidrs=cidrs_for_token(destination) if dest_cidrs is None else list(dest_cidrs),
        source_unresolved=(source_unresolved or
                           (derived_source and not resolved_source
                            and looks_like_address_space(source))),
        dest_tags=list(dest_tags or []),
        service=svc.label, port=svc.port, port_end=svc.port_end, protocol=svc.protocol,
        l7_app=svc.l7_app, l7_source=svc.l7_source,
        action=action, order=order, source_ip=source_ip, dest_ip=dest_ip, note=note,
    )


def merge_entities(entities: dict[str, ObservedEntity], ent: ObservedEntity) -> None:
    """Merge an entity into a per-tool dict keyed by name (union tags, keep ip/cidr).

    `cidrs` is UNIONED rather than first-wins like `cidr`: two rules naming the
    same object hand us the same catalog answer, but a rule that resolved the
    object and one that could not must not be able to erase address space --
    losing a block here is exactly how a group's ``0.0.0.0/0`` went missing from
    the zone layer. Sorted, because the union feeds `Asset.ip_set`, which is
    persisted and fingerprinted.
    """
    cur = entities.get(ent.name)
    if cur is None:
        entities[ent.name] = ent
        return
    cur.tags = sorted(set(cur.tags) | set(ent.tags))
    cur.ip = cur.ip or ent.ip
    cur.cidr = cur.cidr or ent.cidr
    cur.cidrs = sorted(set(cur.cidrs) | set(ent.cidrs))
    cur.identifiers = {**ent.identifiers, **cur.identifiers}
    cur.abstract = cur.abstract and ent.abstract
