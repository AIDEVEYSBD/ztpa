"""Address-space classification, pinned case by case.

`netaddr` exists because three layers each decided "is this the internet?" by
comparing a string (`node_key == "0.0.0.0/0"`) or a score (`E >= 1.0`). Under
that rule `0.0.0.0/1` -- half the routable internet -- dropped from 90/critical
to 56/medium and tripped no guardrail, and `any` scored like a single host.

So the tests here are a decision TABLE, not spot checks: every row is a
classification a client can audit, and the two the audit called out by name
(`0.0.0.0/1`, `1.0.0.0/8`) have their own regression test so a failure names
itself. Three further tests defend the mechanism rather than the answers: the
special-use table must stay pairwise disjoint (the coverage arithmetic in
`_fully_special` is only exact if it is), it must stay in agreement with
`ipaddress`'s own view of what is globally reachable, and nothing in the module
may raise on any input a customer export can contain.

Pure functions, no fixtures, no I/O.
"""

from __future__ import annotations

import ipaddress
import itertools

import pytest

from src.netaddr import (
    ANY_V4, ANY_V6, _SPECIAL_USE, _unwrap_mapped, is_any, is_public, parse_net, same_family,
)

# --- parse_net -------------------------------------------------------------
# (token, canonical network string or None). Host bits are dropped, a bare host
# becomes its own single-host network, and nothing unparseable ever raises.
PARSE_CASES = [
    ("0.0.0.0/0", "0.0.0.0/0"),
    ("10.0.0.0/8", "10.0.0.0/8"),
    ("10.0.0.1/24", "10.0.0.0/24"),          # host bits tolerated -> the network
    ("10.0.0.5", "10.0.0.5/32"),             # bare host -> /32
    ("  10.0.0.0/8  ", "10.0.0.0/8"),        # surrounding whitespace
    ("10.0.0.0/255.0.0.0", "10.0.0.0/8"),    # netmask form
    ("0.0.0.0", "0.0.0.0/32"),               # sentinel host, NOT the internet
    ("::/0", "::/0"),
    ("::1", "::1/128"),
    ("2001:db8::/32", "2001:db8::/32"),
    ("::ffff:1.2.3.4", "::ffff:1.2.3.4/128"),
    ("any", None),                           # a word, not an address
    ("", None),
    ("   ", None),
    ("garbage", None),
    ("999.999.999.999/8", None),             # the audit's typo'd CIDR
    ("10.0.0.0/33", None),                   # impossible prefix length
    ("10.0.0.0-10.0.0.255", None),           # range notation is not CIDR
    ("tcp/443", None),                       # a service, handed in by mistake
    (None, None),
    (12345, None),                           # ints are not address space
    (["10.0.0.0/8"], None),
]


@pytest.mark.parametrize("token,expected", PARSE_CASES)
def test_parse_net(token, expected):
    net = parse_net(token)
    assert (str(net) if net is not None else None) == expected


def test_parse_net_passes_through_parsed_objects():
    """Callers hand this whatever they have; a network survives the round trip."""
    net = ipaddress.ip_network("10.0.0.0/8")
    assert parse_net(net) is net
    assert str(parse_net(ipaddress.ip_address("10.0.0.5"))) == "10.0.0.5/32"


# --- is_any ----------------------------------------------------------------
ANY_CASES = [
    ("any", True), ("Any", True), ("ANY", True), ("  any  ", True),
    ("all", True), ("ALL", True), ("*", True),
    ("0.0.0.0/0", True), ("::/0", True),
    ("0.0.0.0/0.0.0.0", True),               # netmask spelling of /0
    ("::/128", False),                       # the unspecified ADDRESS, not /0
    ("0.0.0.0", False),                      # sentinel host: a placeholder, not the world
    ("0.0.0.0/1", False),                    # public (see below) but not a wildcard
    ("10.0.0.0/8", False),
    ("ANY-EXTERNAL", False),                 # a named object: the catalog resolves it
    ("anything", False),
    ("", False), ("   ", False), (None, False), (7, False),
]


@pytest.mark.parametrize("token,expected", ANY_CASES)
def test_is_any(token, expected):
    assert is_any(token) is expected


def test_every_wildcard_spelling_classifies_identically():
    """The audit's headline defect: one rule, four spellings, four answers.

    Whatever else changes, these must stay indistinguishable to the engine.
    """
    spellings = ["any", "Any", "ANY", "all", "*", ANY_V4, ANY_V6, "0.0.0.0/0.0.0.0"]
    assert all(is_any(s) for s in spellings)
    assert all(is_public(s) for s in spellings)


# --- is_public -------------------------------------------------------------
# The decision table from the module docstring, asserted row by row.
PUBLIC_CASES = [
    # the whole space, in both families
    (ANY_V4, True), (ANY_V6, True), ("0.0.0.0/0.0.0.0", True),
    # THE regression: a 0-prefix is not the only internet
    ("0.0.0.0/1", True),          # contains 1.0.0.0/8, 8.8.8.8, ...
    ("128.0.0.0/1", True),
    ("1.0.0.0/8", True),
    ("8.8.8.8/32", True), ("8.8.8.8", True),
    ("172.32.0.0/12", True),      # adjacent to RFC1918 but outside it
    ("192.169.0.0/16", True),     # one bit off 192.168/16
    ("10.0.0.0/7", True),         # spans 10/8 (private) + 11/8 (routable)
    # RFC 1918 / special use
    ("10.0.0.0/8", False), ("10.1.2.0/24", False),
    ("172.16.0.0/12", False), ("192.168.1.0/24", False),
    ("100.64.0.0/10", False),     # RFC 6598 CGNAT: not private, not global
    ("100.64.1.1/32", False),
    ("169.254.0.0/16", False),    # link-local
    ("127.0.0.1/32", False),      # loopback
    ("0.0.0.0/32", False),        # "this host" sentinel
    ("0.0.0.0/8", False),
    ("198.18.0.0/15", False), ("192.0.2.0/24", False), ("203.0.113.0/24", False),
    ("240.0.0.0/4", False), ("255.255.255.255/32", False),
    # v6
    ("2000::/3", True),           # global unicast, though it CONTAINS 2001::/23
    ("2606:4700::/32", True),
    ("::1/128", False), ("::/128", False),
    ("fc00::/7", False), ("fd00::/8", False), ("fe80::/10", False),
    ("2001:db8::/32", False), ("2001::/23", False), ("100::/64", False),
    # IPv4-mapped v6 is classified as the v4 it embeds
    ("::ffff:1.2.3.4/128", True),
    ("::ffff:10.0.0.0/104", False),
    ("::ffff:0:0/96", True),      # the whole mapped block == 0.0.0.0/0
    # wildcard WORDS are the whole space; unresolvable labels are not exposure
    ("any", True), ("all", True), ("*", True),
    ("ANY-EXTERNAL", False), ("garbage", False), ("", False), (None, False),
]


@pytest.mark.parametrize("token,expected", PUBLIC_CASES)
def test_is_public(token, expected):
    assert is_public(token) is expected


def test_audit_regression_broad_v4_blocks_are_the_internet():
    """`0.0.0.0/1` and `1.0.0.0/8` are internet, exactly like `0.0.0.0/0`.

    Named separately from the table because this is the finding the phase exists
    to close: under the old string comparison both scored as ordinary internal
    space and neither tripped a guardrail.
    """
    assert is_public("0.0.0.0/1") is True
    assert is_public("1.0.0.0/8") is True
    assert is_public(ANY_V4) is True


def test_is_public_accepts_network_objects_as_well_as_strings():
    assert is_public(ipaddress.ip_network("0.0.0.0/1")) is True
    assert is_public(ipaddress.ip_network("10.0.0.0/8")) is False


# --- the mechanism ---------------------------------------------------------

def test_special_use_blocks_are_pairwise_disjoint():
    """`_fully_special` sums block sizes, which is only exact if none overlap."""
    for version, blocks in _SPECIAL_USE.items():
        for a, b in itertools.combinations(blocks, 2):
            assert not a.overlaps(b), f"v{version}: {a} overlaps {b}"


@pytest.mark.parametrize("block", [b for blocks in _SPECIAL_USE.values() for b in blocks])
def test_special_use_table_agrees_with_ipaddress(block):
    """Drift guard: every block we call non-routable, `ipaddress` does too.

    The table is held explicitly (rather than read off `.is_private`) because
    the stdlib's network-level answer is defined on the two EDGE addresses, so
    it changes meaning across CPython versions and gets `0.0.0.0/1` wrong. This
    keeps the two definitions tied together at every row we assert.
    """
    assert block.network_address.is_global is False
    assert is_public(block) is False


def test_ipv4_mapped_divergence_is_deliberate():
    """We disagree with `ipaddress` on mapped v6 -- on purpose, and only here.

    `ipaddress` calls the whole ::ffff:0:0/96 block special-use, so an
    internet-facing rule written in mapped form would classify as private and
    disappear. We unwrap to the embedded v4 and classify that.
    """
    mapped = ipaddress.ip_network("::ffff:1.2.3.4/128")
    assert mapped.is_private is True          # the stdlib's view
    assert str(_unwrap_mapped(mapped)) == "1.2.3.4/32"
    assert is_public(mapped) is True          # ours
    assert str(_unwrap_mapped(ipaddress.ip_network("::ffff:10.0.0.0/104"))) == "10.0.0.0/8"


# --- same_family -----------------------------------------------------------
SAME_FAMILY_CASES = [
    ("10.0.0.0/8", "192.168.0.0/16", True),
    ("::/0", "2001:db8::/32", True),
    ("10.0.0.0/8", "::/0", False),            # the mixed-family crash guard
    ("0.0.0.0/0", "::/0", False),
    ("10.0.0.0/8", "garbage", False),
    ("garbage", "garbage", False),
    (None, "10.0.0.0/8", False),
]


@pytest.mark.parametrize("a,b,expected", SAME_FAMILY_CASES)
def test_same_family(a, b, expected):
    assert same_family(a, b) is expected
    assert same_family(b, a) is expected      # symmetric


def test_same_family_guards_the_subnet_comparison_that_raises():
    """The reason this function exists: the comparison it gates is a TypeError."""
    v4 = ipaddress.ip_network("10.0.0.0/8")
    v6 = ipaddress.ip_network("::/0")
    assert same_family(v4, v6) is False
    with pytest.raises(TypeError):
        v4.subnet_of(v6)                      # what one v6 rule used to do to a run


# --- total functions -------------------------------------------------------
GARBAGE = [
    None, "", "   ", "any", "*", "0.0.0.0/0", "-1", "1.2.3", "1.2.3.4.5", "10.0.0.0/-1",
    "10.0.0.0/999", "::::", "%", "10.0.0.0 10.255.255.255", "tcp/443", 0, -1, 3.5,
    True, [], {}, ("10.0.0.0/8",), object(),
]


@pytest.mark.parametrize("value", GARBAGE)
def test_nothing_raises_on_any_input(value):
    """A malformed token is a fact to classify, never an exception to handle.

    Every one of these reaches the module from a customer export -- a service
    string in the source column, a null, a list-valued field from a mis-mapped
    ingest profile. One traceback here loses the other 4,999 rules.
    """
    net = parse_net(value)
    assert net is None or isinstance(net, (ipaddress.IPv4Network, ipaddress.IPv6Network))
    assert isinstance(is_any(value), bool)
    assert isinstance(is_public(value), bool)
    assert isinstance(same_family(value, "10.0.0.0/8"), bool)
