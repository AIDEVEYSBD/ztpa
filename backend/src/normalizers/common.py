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
from typing import Optional

from ..config import APP_BY_PORT, APP_TRANSPORT, L7_APPS
from ..models import PolicyRecord

INTERNET_CIDR = "0.0.0.0/0"
_PROTOCOLS = {"tcp", "udp", "icmp", "sctp", "any"}


@dataclass
class ObservedEntity:
    name: str                                   # canonical node key (CIDR string or asset name)
    kind: str                                   # "cidr" | "identity"
    tool: str
    ip: Optional[str] = None                    # concrete host ip
    cidr: Optional[str] = None                  # network cidr for named segments / raw subnets
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
    records: list[PolicyRecord] = field(default_factory=list)
    entities: list[ObservedEntity] = field(default_factory=list)
    resolved: list[ResolvedObject] = field(default_factory=list)

    def extend(self, other: "NormalizeResult") -> None:
        self.records.extend(other.records)
        self.entities.extend(other.entities)
        self.resolved.extend(other.resolved)


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
    """

    protocol: str                       # tcp | udp | icmp | sctp | any
    port: Optional[int]                 # single port, or range start
    port_end: Optional[int]             # range end (None for a single port)
    label: str                          # human label, e.g. "tcp/443", "quic"
    l7_app: Optional[str]               # decoded App-ID, or None if unknown
    l7_source: Optional[str]            # "declared" | "inferred" | None


def _clamp_proto(proto: str) -> str:
    p = proto.strip().lower()
    return p if p in _PROTOCOLS else "tcp"


def _infer_l7(protocol: str, port: Optional[int]) -> tuple[Optional[str], Optional[str]]:
    """Deterministic (protocol, port) -> App-ID lookup. Marked 'inferred'."""
    if port is None:
        return (None, None)
    app = APP_BY_PORT.get((protocol, port))
    return (app, "inferred") if app else (None, None)


def _parse_ports(p: str) -> tuple[Optional[int], Optional[int]]:
    """Parse '443' -> (443, None) or '8000-8100' -> (8000, 8100)."""
    p = p.strip()
    if "-" in p:
        lo, _, hi = p.partition("-")
        try:
            return (int(lo), int(hi))
        except ValueError:
            return (None, None)
    try:
        return (int(p), None)
    except ValueError:
        return (None, None)


def _from_app(app: str, port: Optional[int], protocol: Optional[str]) -> DecodedService:
    """Resolve a declared App-ID token to its fixed transport (port/proto may override)."""
    app = app.strip().lower()
    t_proto, t_port = APP_TRANSPORT.get(app, ("tcp", None))
    proto = _clamp_proto(protocol) if protocol else t_proto
    pi = int(port) if port is not None else t_port
    return DecodedService(proto, pi, None, app, app, "declared")


def parse_service(service: Optional[str] = None, port: Optional[int] = None,
                  protocol: Optional[str] = None, app: Optional[str] = None) -> DecodedService:
    """Decode a rule's service into L4 + L7 facts.

    Accepts any of: an AlgoSec-style `service` string ("tcp/443", "tcp/8000-8100",
    "quic", "any"); a Guardicore/Wiz separate `port`+`protocol`; and/or an explicit
    `app` App-ID field. Returns a DecodedService; never raises on bad input.
    """
    if app and str(app).strip().lower() in L7_APPS:
        return _from_app(str(app), port, protocol)

    if service:
        s = service.strip()
        low = s.lower()
        if low == "any":
            return DecodedService("any", None, None, "any", None, None)
        if low in L7_APPS:                         # App-ID named as the service
            return _from_app(low, port, protocol)
        if "/" in s:
            proto_tok, _, p = s.partition("/")
            proto = _clamp_proto(proto_tok)
            pstart, pend = _parse_ports(p)
            l7, l7src = _infer_l7(proto, pstart)
            return DecodedService(proto, pstart, pend, s, l7, l7src)
        # bare token: a protocol (icmp/sctp/tcp/udp) or an unknown service name
        proto = _clamp_proto(low)
        return DecodedService(proto, None, None, s, None, None)

    proto = _clamp_proto(protocol or "tcp")
    if port is None:
        return DecodedService(proto, None, None, proto, None, None)
    pi = int(port)
    l7, l7src = _infer_l7(proto, pi)
    return DecodedService(proto, pi, None, f"{proto}/{pi}", l7, l7src)


def merge_entities(entities: dict[str, ObservedEntity], ent: ObservedEntity) -> None:
    """Merge an entity into a per-tool dict keyed by name (union tags, keep ip/cidr)."""
    cur = entities.get(ent.name)
    if cur is None:
        entities[ent.name] = ent
        return
    cur.tags = sorted(set(cur.tags) | set(ent.tags))
    cur.ip = cur.ip or ent.ip
    cur.cidr = cur.cidr or ent.cidr
    cur.identifiers = {**ent.identifiers, **cur.identifiers}
    cur.abstract = cur.abstract and ent.abstract
