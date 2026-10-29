"""Address-space classification — the single place the engine decides what a
source/destination token *is*.

Why this module exists
----------------------
Before it, three layers each answered "is this the internet?" a different way,
and all three answered it by comparing a *string* or a *score*:

  - ``graph/zones.zone_of``   ``node_key == "0.0.0.0/0"``
  - ``analyzers/severity``    ``E >= 1.0`` (E comes from a prefix-length band table)
  - the normalizers           ``is_cidr(token)`` — "does it contain a slash"

So the same grant written four ways (``0.0.0.0/0``, ``any``, a named object
resolving to ``0.0.0.0/0``, an address group) scored four different ways, and
``0.0.0.0/1`` — which contains the entire routable internet — dropped from
critical to medium and tripped no guardrail at all. Classification has to be a
property of the address space, not of how the export happened to spell it.

Everything here is a pure function of the input: no I/O, no clock, no set
iteration in an output path. Same token in, same answer out, forever.

Classification decisions (auditable, deliberate)
------------------------------------------------
``is_public(net)`` answers exactly one question: **does this address space
contain at least one globally-routable address?** It is a "contains any", not a
"is entirely" — because for a firewall rule the risk is carried by the widest
address the block can reach, not by its average member. That single decision
drives every case below.

  ``0.0.0.0/0``      PUBLIC — the whole address space, by definition. Any
                     0-prefix network (v4 or v6, however spelled, including the
                     netmask form ``0.0.0.0/0.0.0.0``) is the internet.
  ``0.0.0.0/1``      PUBLIC — this is the audit's regression. Half the IPv4
                     space: it contains 1.0.0.0/8, 8.8.8.8, everything routable
                     below 128/1. Note that ``ipaddress`` calls its two *edges*
                     (0.0.0.0 and 127.255.255.255) non-global, which is exactly
                     the trap an edge-sampling implementation falls into.
  ``1.0.0.0/8``      PUBLIC — ordinary routable space.
  ``10/8``, ``172.16/12``, ``192.168/16``
                     NOT public — RFC 1918.
  ``100.64.0.0/10``  NOT public — RFC 6598 CGNAT/shared space. It is carrier
                     space, never globally routed, so a grant sourced from it is
                     not internet exposure. (This is the one block where
                     ``.is_private`` and ``.is_global`` disagree in the stdlib:
                     it is not private, and it is not global. We follow global.)
  ``169.254/16``     NOT public — RFC 3927 link-local. Also 127/8 loopback,
                     0/8 "this network", 198.18/15 benchmarking, the three
                     TEST-NETs and 240/4 reserved.
  ``::/0``           PUBLIC — the v6 default route, same rule as v4.
  ``2000::/3``       PUBLIC — global unicast. It *contains* the special-use
                     blocks 2001::/23 and 2001:db8::/32 but is not covered by
                     them, so the "contains any" rule holds.
  ``fc00::/7``, ``fe80::/10``, ``::1``, ``::``, ``100::/64``, ``2001::/23``,
  ``2001:db8::/32``  NOT public.
  ``::ffff:1.2.3.4`` PUBLIC — IPv4-mapped v6 is UNWRAPPED to its embedded v4
                     network and classified as v4. ``ipaddress`` reports the
                     mapped block as private (it is special-use *as v6*), which
                     would silently hide an internet-facing v6 rule written in
                     mapped form. ``::ffff:10.0.0.0/104`` is therefore 10/8.
  ``224.0.0.0/4``, ``ff00::/8``
                     PUBLIC — multicast is marked globally reachable by IANA and
                     by ``ipaddress.is_global``; we do not second-guess the
                     registry here. Multicast as a policy *source* is a data
                     defect, not a classification question, and belongs to the
                     normalizer's warning path.
  bare ``0.0.0.0`` / ``::``
                     NOT public and NOT "any" — a bare unspecified address is a
                     /32 (resp. /128) sentinel that real exports use as a
                     placeholder for "unknown". Reading it as the whole internet
                     would inflate a missing value into a critical finding; the
                     identity layer separately refuses to merge on it.

How ``is_public`` is computed
-----------------------------
Not by string comparison, and not by ``net.is_private`` / ``net.is_global`` on
the network object either: those are defined on the *pair of edge addresses*, so
their answer for a block that straddles several special-use ranges depends on
the stdlib version (CPython changed exactly this in 3.12). Instead we hold the
IANA special-purpose registry as an explicit, auditable table below and do exact
set arithmetic against it: a network is public unless every address in it falls
inside that table. ``test_netaddr.py`` cross-checks every row of the table
against ``ipaddress``'s own ``.is_global``/``.is_private`` so the two can never
drift apart unnoticed.
"""

from __future__ import annotations

import functools
import ipaddress
from typing import Union

# The two canonical wildcards. `normalizers.common.INTERNET_CIDR` is ANY_V4, so
# "the internet node" and "the /0 network" are literally the same string.
ANY_V4 = "0.0.0.0/0"
ANY_V6 = "::/0"

Network = Union[ipaddress.IPv4Network, ipaddress.IPv6Network]
_Address = (ipaddress.IPv4Address, ipaddress.IPv6Address)
_Net = (ipaddress.IPv4Network, ipaddress.IPv6Network)

# The wildcard VOCABULARY: tokens that mean "every address" without being
# written as an address at all. Compared lowercased and stripped. Any other
# spelling that parses to a 0-prefix network is caught by `is_any` numerically,
# so this set only has to carry the non-numeric words.
ANY_TOKENS = frozenset({"any", "all", "*"})

# IANA special-purpose address registries, as CIDR blocks that are NOT globally
# routable. Pairwise disjoint by construction (asserted in the tests) — the
# coverage arithmetic in `_fully_special` depends on that.
_SPECIAL_USE: dict[int, tuple[Network, ...]] = {
    4: tuple(ipaddress.ip_network(b) for b in (
        "0.0.0.0/8",        # RFC 1122 "this network"
        "10.0.0.0/8",       # RFC 1918 private
        "100.64.0.0/10",    # RFC 6598 shared address space (CGNAT)
        "127.0.0.0/8",      # RFC 1122 loopback
        "169.254.0.0/16",   # RFC 3927 link-local
        "172.16.0.0/12",    # RFC 1918 private
        "192.0.0.0/24",     # RFC 6890 IETF protocol assignments
        "192.0.2.0/24",     # RFC 5737 TEST-NET-1
        "192.168.0.0/16",   # RFC 1918 private
        "198.18.0.0/15",    # RFC 2544 benchmarking
        "198.51.100.0/24",  # RFC 5737 TEST-NET-2
        "203.0.113.0/24",   # RFC 5737 TEST-NET-3
        "240.0.0.0/4",      # RFC 1112 reserved (includes 255.255.255.255)
    )),
    6: tuple(ipaddress.ip_network(b) for b in (
        "::/128",           # RFC 4291 unspecified
        "::1/128",          # RFC 4291 loopback
        "100::/64",         # RFC 6666 discard-only
        "2001::/23",        # RFC 2928 IETF protocol assignments (incl. Teredo)
        "2001:db8::/32",    # RFC 3849 documentation
        "fc00::/7",         # RFC 4193 unique-local
        "fe80::/10",        # RFC 4291 link-local
    )),
}

# ::ffff:0:0/96 — IPv4-mapped v6. Handled by unwrapping, never by the table.
_V4_MAPPED = ipaddress.ip_network("::ffff:0:0/96")


def parse_net(value: str) -> Network | None:
    """Parse a CIDR/host string into a network. ``None`` when unparseable.

    Never raises — a malformed token from a customer export is a fact to be
    classified, not an exception to be handled at every call site.

    Accepts network notation (``10.0.0.0/8``), the netmask form
    (``10.0.0.0/255.0.0.0``) and a bare host, which becomes its own single-host
    network (``10.0.0.5`` -> ``10.0.0.5/32``, ``::1`` -> ``::1/128``). Host bits
    are tolerated (``strict=False``) because exports routinely write
    ``10.0.0.1/24`` meaning the ``10.0.0.0/24`` network; the result is the
    canonical network, so two spellings of one block resolve to one string.

    Already-parsed network/address objects pass through, so callers can hand
    this whatever they have without a type dance.
    """
    if isinstance(value, _Net):
        return value
    if isinstance(value, _Address):
        return ipaddress.ip_network(value)
    if not isinstance(value, str):
        return None                       # None, ints, lists: not address space
    return _parse_token(value)


@functools.lru_cache(maxsize=1 << 17)
def _parse_token(value: str) -> Network | None:
    """Cached: a rulebase names a few thousand networks across hundreds of
    thousands of grants, and each parse allocates a fresh network object. The
    objects are immutable, so every grant naming one network shares one."""
    token = value.strip()
    if not token:
        return None
    try:
        return ipaddress.ip_network(token, strict=False)
    except (ValueError, TypeError):
        return None


def is_any(value: str) -> bool:
    """True for the wildcard vocabulary: any / Any / ANY / all / * / 0.0.0.0/0 / ::/0.

    Two independent tests, because exports use both spellings for one meaning:
    a word from ``ANY_TOKENS`` (case-insensitive, whitespace-tolerant), or any
    token that parses to a 0-prefix network. The second arm is what makes
    ``0.0.0.0/0``, ``::/0`` and ``0.0.0.0/0.0.0.0`` agree with ``any`` without
    anyone maintaining a list of spellings.

    A bare ``0.0.0.0`` is deliberately NOT "any" — see the module docstring.
    """
    if isinstance(value, _Net):
        return value.prefixlen == 0
    if not isinstance(value, str):
        return False
    token = value.strip().lower()
    if not token:
        return False
    if token in ANY_TOKENS:
        return True
    net = parse_net(token)
    return net is not None and net.prefixlen == 0


def is_public(net) -> bool:
    """True when the address space contains at least one globally-routable address.

    This is the engine's definition of "the internet" — used for zone
    classification and for the guardrail floor, both of which must fire on
    ``0.0.0.0/1`` exactly as they fire on ``0.0.0.0/0``.

    Accepts a network object or a string. A string is parsed with `parse_net`,
    and a wildcard WORD (`any`/`all`/`*`) counts as public — it denotes the whole
    address space, so treating it as anything else would hide exposure, which is
    the exact direction of failure this phase exists to fix. Anything else that
    will not parse is False: an unresolvable label is not evidence of internet
    exposure. See the module docstring for the full decision table.
    """
    n = parse_net(net) if not isinstance(net, _Net) else net
    if n is None:
        return is_any(net)                # "any" / "all" / "*" mean everything
    if n.prefixlen == 0:                  # 0.0.0.0/0, ::/0: the whole space
        return True
    n = _unwrap_mapped(n)
    if n.prefixlen == 0:                  # ::ffff:0:0/96 unwraps to 0.0.0.0/0
        return True
    return not _fully_special(n)


def same_family(a, b) -> bool:
    """True when both operands are the same IP version.

    The analyzers that compare two address spaces (`cidr_overlap`, `shadowing`)
    must call this first: ``IPv4Network.subnet_of(IPv6Network)`` raises TypeError,
    so one v6 rule in a v4 record set takes the whole snapshot down. Unparseable
    on either side is False — nothing is comparable to a non-address.
    """
    na = parse_net(a) if not isinstance(a, _Net) else a
    nb = parse_net(b) if not isinstance(b, _Net) else b
    if na is None or nb is None:
        return False
    return na.version == nb.version


# --- internals -------------------------------------------------------------

def _unwrap_mapped(n: Network) -> Network:
    """``::ffff:1.2.3.4/128`` -> ``1.2.3.4/32``; everything else unchanged.

    IPv4-mapped v6 is v4 wearing a v6 hat. ``ipaddress`` classifies the whole
    ``::ffff:0:0/96`` block as special-use, so without this an internet-facing
    rule written in mapped form would classify as private.
    """
    if n.version != 6 or not n.subnet_of(_V4_MAPPED):
        return n
    embedded = ipaddress.IPv4Address(int(n.network_address) & 0xFFFFFFFF)
    return ipaddress.IPv4Network((embedded, n.prefixlen - 96), strict=False)


def _fully_special(n: Network) -> bool:
    """True when EVERY address in `n` is special-use (i.e. none is routable).

    Exact set arithmetic, not sampling. Two CIDR blocks are either disjoint or
    nested, and the table is pairwise disjoint, so `n` is fully covered iff it
    sits inside one block, or the blocks nested inside it account for all of its
    addresses. That second arm is what a `.is_private` edge test gets wrong:
    ``0.0.0.0/1`` has two special-use edges (0/8 and 127/8) but 2 * 2**24
    covered addresses out of 2**31 — overwhelmingly routable.
    """
    covered = 0
    for block in _SPECIAL_USE[n.version]:
        if n.subnet_of(block):
            return True
        if block.subnet_of(n):
            covered += block.num_addresses
    return covered >= n.num_addresses
