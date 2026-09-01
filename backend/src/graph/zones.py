"""Zone classification + trust-boundary multiplier — the ``B`` term of the
severity vector, and the only place the engine decides which side of a trust
boundary a node sits on.

Why this module changed
-----------------------
``zone_of`` used to answer "is this the internet?" with one string comparison,
``node_key == "0.0.0.0/0"``. Every other spelling of the same address space —
``0.0.0.0/1`` (half the routable internet), ``1.0.0.0/8``, ``::/0``, or a named
object whose catalog value dereferences to ``0.0.0.0/0`` — fell through to
ZONE_INTERNAL. The boundary multiplier then collapsed from 1.5 to 1.0 and the
internet→internal guardrail never fired, so the *same rule* scored 90/critical
written one way and 56/medium written the other. (PROD-READINESS-AUDIT,
`backend/src/graph/zones.py:12`.)

Classification is now a property of the ADDRESS SPACE a node denotes, delegated
to `netaddr.is_public` — the one shared classifier the normalizers, the severity
model and this module all call — so no two layers can drift into disagreeing
about what "the internet" means.

What is deliberately NOT the internet
-------------------------------------
A **concrete asset is never ZONE_INTERNET**, even when it holds a globally
routable address. ``lb-public-01`` (52.20.10.10) is a host that *faces* the
internet; it is not the internet. Zone answers "where does this node live", and
the published rule in `config.ZONE_TAGS` is that an internet-facing asset sits in
the DMZ — which is also why ``(internet, dmz)`` is deliberately absent from
BOUNDARY_MULTIPLIERS (a DMZ box is *meant* to be reachable from outside).
Classifying every public-IP'd host as ZONE_INTERNET would relabel every DMZ hop
in the estate and silently inflate ``dmz->internal`` (1.25) into
``internet->internal`` (1.5) on paths that never touch the internet.

So the public-space test applies only to nodes that DENOTE address space — a raw
CIDR node key, a wildcard token, or an abstract network/group object whose
resolved CIDRs are public — and never to a host that merely has an address.

Auditability
------------
`boundary_multiplier` stays a pure lookup into `config.BOUNDARY_MULTIPLIERS`.
The severity vector is published in the UI, so every number in it has to be
traceable to a named, reviewable constant rather than to a computation. Pairs
absent from the table are intra-zone (`B_INTRA` = 1.0) *by design*, not by
omission — see the comment above the table in `config.py`.

Everything here is a pure function of its arguments: no I/O, no clock, no set
iteration in an output path.
"""

from __future__ import annotations

from ..config import (
    BOUNDARY_MULTIPLIERS, B_INTRA, ZONE_INTERNAL, ZONE_INTERNET, ZONE_PRIORITY, ZONE_TAGS,
)
from ..netaddr import is_public


def zone_of(node_key: str, tags: list[str], cidrs: list[str] | None = None,
            kind: str | None = None) -> str:
    """Which trust zone a graph node belongs to.

    `node_key` is the canonical node name; `tags` are the node's tags. The two
    trailing arguments are optional so every existing 2-argument call site keeps
    working, and are supplied by `graph.build.build_graph`, which is the only
    caller that knows them:

      cidrs: the node's resolved address space (`Asset.ip_set`). This is what
             makes a NAMED object classify like the CIDR it dereferences to — an
             address-group called "ANY-EXTERNAL" whose catalog value is
             ``0.0.0.0/0`` is the internet, exactly as the literal string is.
      kind:  "concrete" | "abstract" | None. "concrete" suppresses the
             address-space test entirely (see the module docstring: a host with
             a public IP is a DMZ asset, not the internet). None means "unknown",
             and an unknown node is classified from its address space — the
             higher-exposure answer, which is the correct direction to fail in
             for a security tool.

    Order is deliberate: the address-space test wins over tags, so a ``/0``
    labelled ``dev`` is still the internet.
    """
    if _denotes_public_space(node_key, cidrs, kind):
        return ZONE_INTERNET
    present = {ZONE_TAGS[t] for t in tags if t in ZONE_TAGS}
    for zone in ZONE_PRIORITY:        # most-exposed wins; ZONE_PRIORITY is an
        if zone in present:           # ordered list, so the set is only ever
            return zone               # membership-tested, never iterated
    return ZONE_INTERNAL


def boundary_multiplier(src_zone: str, dst_zone: str) -> float:
    """Published (src_zone, dst_zone) -> multiplier lookup. Never computed.

    Unlisted pairs are `B_INTRA` (1.0). The table lives in `config.py` so the
    severity vector the UI prints can be traced to a reviewable constant.
    """
    return BOUNDARY_MULTIPLIERS.get((src_zone, dst_zone), B_INTRA)


def crosses_boundary(src_zone: str, dst_zone: str) -> bool:
    """True when the pair is one the table calls a trust-boundary crossing."""
    return boundary_multiplier(src_zone, dst_zone) > B_INTRA


def boundary_label(src_zone: str, dst_zone: str) -> str:
    """The human-readable crossing, e.g. ``internet->internal``."""
    return f"{src_zone}->{dst_zone}"


# --- internals -------------------------------------------------------------

def _denotes_public_space(node_key: str, cidrs: list[str] | None,
                          kind: str | None) -> bool:
    """True when this node IS globally-routable address space.

    Two independent arms, because one address space reaches the graph under two
    spellings and both must land in the same zone:

      1. the node key itself is address space — a raw CIDR (``0.0.0.0/1``,
         ``2000::/3``) or a wildcard word (``any``/``all``/``*``, which
         `netaddr.is_public` resolves through `is_any`);
      2. the node is a named object whose RESOLVED address space is public —
         an AlgoSec ``network``/``group`` object, a profile's address group.

    A concrete asset short-circuits to False: it has an address, it is not an
    address space. `any()` over `cidrs` is order-independent, so no explicit
    sort is needed to keep this deterministic.
    """
    if kind == "concrete":
        return False
    if is_public(node_key):
        return True
    return any(is_public(c) for c in cidrs or ())
