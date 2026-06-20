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

from ..models import PolicyRecord

INTERNET_CIDR = "0.0.0.0/0"


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


def parse_service(service: Optional[str] = None, port: Optional[int] = None,
                  protocol: Optional[str] = None) -> tuple[str, Optional[int], str]:
    """Return (protocol, port, label). Accepts AlgoSec 'tcp/443'/'any' or
    Guardicore/Wiz separate port+protocol."""
    if service:
        s = service.strip()
        if s.lower() == "any":
            return ("any", None, "any")
        if "/" in s:
            proto, _, p = s.partition("/")
            try:
                pi: Optional[int] = int(p)
            except ValueError:
                pi = None
            return (proto.lower(), pi, s)
        return (s.lower(), None, s)
    proto = (protocol or "tcp").lower()
    if port is None:
        return (proto, None, proto)
    return (proto, int(port), f"{proto}/{port}")


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
