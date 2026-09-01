"""Service decoding, encoding by encoding, with the silence removed.

`parse_service` is the only thing standing between a vendor's service column and
every port-dependent decision the engine makes -- the port class P, both
port-dependent guardrails, `_grant_matches`, and the staging conflict check. It
used to answer "I could not read that" and "the export said something invalid"
with the same value it uses for "I don't know": a bare `tcp` with no port, which
scores P=0.5, i.e. squarely mid-risk. Three consequences, all measured in the
audit and all pinned below:

  - `tcp/80,443` -- the most common AlgoSec/Palo encoding -- lost BOTH ports.
  - `ip` and `all`, the standard way to write a true any/any rule, decoded to
    plain `tcp`, so the any/any guardrail could not fire on a real export.
  - `tcp/70000` and `tcp/500-100` were accepted verbatim, and `port="abc"`
    raised ValueError straight out of the normalizer.

So the table below asserts the FULL decode -- protocol, port, port_end, ports,
label, l7 and warnings -- for every encoding named in the audit, and the tests
after it pin the two properties the callers depend on: the function never
raises, on anything, and its dataclass keeps the field ORDER that four other
modules construct positionally.
"""

from __future__ import annotations

import pytest

from src.models import PolicyRecord
from src.normalizers.common import (
    DecodedService, cidrs_for_token, parse_service, record_from_service,
)

# (service, protocol, port, port_end, ports, label, l7_app, warning substrings)
# `ports` is None for a single interval -- (port, port_end) is then the whole
# story -- and the full canonical interval list when the service names several.
SERVICE_CASES = [
    # --- ordinary, unchanged by this work -----------------------------------
    ("tcp/443", "tcp", 443, None, None, "tcp/443", "tls", ()),
    ("udp/443", "udp", 443, None, None, "udp/443", "quic", ()),
    ("tcp/8000-8100", "tcp", 8000, 8100, None, "tcp/8000-8100", None, ()),
    ("icmp", "icmp", None, None, None, "icmp", None, ()),
    ("quic", "udp", 443, None, None, "quic", "quic", ()),          # App-ID token
    ("any", "any", None, None, None, "any", None, ()),
    # --- the full-range rule that produced ZERO findings ---------------------
    # It used to score P=0.5 "unknown" off the range START; the range is now
    # carried whole so the scorer can see it is every port there is.
    ("tcp/1-65535", "tcp", 1, 65535, None, "tcp/1-65535", None, ()),
    # --- comma lists: both ports used to vanish ------------------------------
    ("tcp/80,443", "tcp", 80, None, [(80, 80), (443, 443)], "tcp/80,443", "http", ()),
    ("tcp/80,8000-8100", "tcp", 80, None, [(80, 80), (8000, 8100)],
     "tcp/80,8000-8100", "http", ()),
    # order-independent: the interval list is canonical, the label is verbatim
    ("tcp/443,80", "tcp", 80, None, [(80, 80), (443, 443)], "tcp/443,80", "http", ()),
    # overlapping/touching intervals coalesce, so one address space has one form
    # l7 is inferred from the FIRST interval's start port (pre-existing behaviour)
    ("tcp/80-90,85-95", "tcp", 80, 95, None, "tcp/80-90,85-95", "http", ()),
    ("tcp/443,443", "tcp", 443, None, None, "tcp/443,443", "tls", ()),
    # --- any-protocol keywords: the guardrail's whole reason to exist ---------
    ("ip", "any", None, None, None, "ip", None, ()),
    ("all", "any", None, None, None, "all", None, ()),
    ("*", "any", None, None, None, "*", None, ()),
    ("ANY", "any", None, None, None, "any", None, ()),             # lowercased label
    # --- protocols that used to be rewritten to tcp --------------------------
    ("gre", "gre", None, None, None, "gre", None, ()),
    ("esp", "esp", None, None, None, "esp", None, ()),
    ("ah", "ah", None, None, None, "ah", None, ()),
    ("gre/0", "gre", 0, None, None, "gre/0", None, ()),
    # --- validated, not coerced ----------------------------------------------
    ("tcp/0", "tcp", 0, None, None, "tcp/0", None, ()),            # 0 is in range
    ("tcp/65535", "tcp", 65535, None, None, "tcp/65535", None, ()),
    ("tcp/70000", "tcp", None, None, None, "tcp/70000", None, ("outside 0-65535",)),
    ("tcp/-5", "tcp", None, None, None, "tcp/-5", None, ("outside 0-65535",)),
    ("tcp/500-100", "tcp", None, None, None, "tcp/500-100", None, ("inverted",)),
    ("tcp/1-70000", "tcp", None, None, None, "tcp/1-70000", None, ("outside 0-65535",)),
    ("tcp/", "tcp", None, None, None, "tcp/", None, ("missing port specification",)),
    ("tcp/abc", "tcp", None, None, None, "tcp/abc", None, ("unparseable port",)),
    # a partly-valid list keeps what parsed and reports what did not
    ("tcp/80,99999", "tcp", 80, None, None, "tcp/80,99999", "http", ("outside 0-65535",)),
    # --- garbage: still a grant, now an audible one --------------------------
    ("HTTP_AND_HTTPS", "tcp", None, None, None, "HTTP_AND_HTTPS", None,
     ("unrecognized protocol",)),
    ("application-default", "tcp", None, None, None, "application-default", None,
     ("unrecognized protocol",)),
    ("!!!", "tcp", None, None, None, "!!!", None, ("unrecognized protocol",)),
]


@pytest.mark.parametrize(
    "service,protocol,port,port_end,ports,label,l7_app,warns", SERVICE_CASES,
    ids=[c[0] for c in SERVICE_CASES],
)
def test_parse_service_table(service, protocol, port, port_end, ports, label, l7_app, warns):
    svc = parse_service(service)
    assert svc.protocol == protocol
    assert svc.port == port
    assert svc.port_end == port_end
    assert svc.ports == ports
    assert svc.label == label
    assert svc.l7_app == l7_app
    assert len(svc.warnings) == len(warns), svc.warnings
    for fragment in warns:
        assert any(fragment in w for w in svc.warnings), svc.warnings


def test_clean_decodes_carry_no_warnings():
    """A warning must mean something; it cannot be background noise."""
    for case in SERVICE_CASES:
        svc = parse_service(case[0])
        assert (svc.warnings == []) is (case[7] == ()), (case[0], svc.warnings)


# --- the separate port/protocol/app inputs (Guardicore, Wiz, ingest profiles) --
KWARG_CASES = [
    # (kwargs, protocol, port, label, warning substrings)
    (dict(), "tcp", None, "tcp", ()),
    (dict(protocol="tcp"), "tcp", None, "tcp", ()),
    (dict(port=443, protocol="udp"), "udp", 443, "udp/443", ()),
    (dict(port=3389, protocol="TCP"), "tcp", 3389, "tcp/3389", ()),
    (dict(protocol="ip"), "any", None, "any", ()),          # any/any from a field
    (dict(protocol="GRE"), "gre", None, "gre", ()),
    (dict(protocol="ipsec"), "tcp", None, "tcp", ("unrecognized protocol",)),
    (dict(port="443"), "tcp", 443, "tcp/443", ()),          # numeric string
    (dict(port="abc"), "tcp", None, "tcp/abc", ("unparseable port",)),   # used to RAISE
    (dict(port=70000), "tcp", None, "tcp/70000", ("outside 0-65535",)),
    (dict(port=-5), "tcp", None, "tcp/-5", ("outside 0-65535",)),
    (dict(app="quic"), "udp", 443, "quic", ()),
    (dict(app="quic", port=8443), "udp", 8443, "quic", ()),
    # an App-ID with an unusable port falls back to the app's fixed transport
    (dict(app="quic", port="nope"), "udp", 443, "quic", ("unparseable port",)),
    (dict(service="tcp/443", app="not-an-app"), "tcp", 443, "tcp/443", ()),
]


@pytest.mark.parametrize("kwargs,protocol,port,label,warns", KWARG_CASES,
                         ids=[str(c[0]) for c in KWARG_CASES])
def test_parse_service_kwargs(kwargs, protocol, port, label, warns):
    svc = parse_service(**kwargs)
    assert (svc.protocol, svc.port, svc.label) == (protocol, port, label)
    assert len(svc.warnings) == len(warns), svc.warnings
    for fragment in warns:
        assert any(fragment in w for w in svc.warnings), svc.warnings


# --- properties the callers rely on ----------------------------------------
NEVER_RAISES = [
    None, "", "   ", "any", "tcp/", "/443", "tcp//443", "tcp/443/8080", ",", "tcp/,",
    "tcp/,,443", "-", "tcp/-", "tcp/1-", "tcp/-1", "0", "tcp/0-0", "tcp/99999999999999",
    "\t\n", "tcp/443 ", "TCP/443", "µ", "tcp/٤٤٣", 0, 1, -1, 3.5, True, [], ["tcp/443"],
    {}, {"a": 1}, (1, 2), object(),
]


@pytest.mark.parametrize("value", NEVER_RAISES)
def test_parse_service_never_raises(value):
    """A normalizer that dies on one bad row loses the other 4,999.

    Every value here is a shape a real export or a mis-mapped ingest profile has
    put in a service column. The contract is total: always a DecodedService.
    """
    for svc in (parse_service(value), parse_service(service=value),
                parse_service(port=value), parse_service(protocol=value),
                parse_service(app=value)):
        assert isinstance(svc, DecodedService)
        assert svc.protocol in {"tcp", "udp", "icmp", "sctp", "gre", "esp", "ah", "any"}
        assert svc.port is None or 0 <= svc.port <= 65535
        assert svc.port_end is None or 0 <= svc.port_end <= 65535
        assert isinstance(svc.warnings, list)


@pytest.mark.parametrize("service", [c[0] for c in SERVICE_CASES])
def test_decoded_protocol_is_always_a_valid_policy_record_protocol(service):
    """The decoder's vocabulary must stay a subset of models.Protocol.

    Widening one without the other turns every `gre` rule in a customer export
    into a pydantic ValidationError at normalize time.
    """
    svc = parse_service(service)
    rec = PolicyRecord(
        id="r", source_tool="algosec", raw_ref="r", source="10.0.0.0/8", source_kind="cidr",
        destination="db-prod-01", destination_kind="identity", service=svc.label,
        port=svc.port, port_end=svc.port_end, protocol=svc.protocol, action="allow",
    )
    assert rec.protocol == svc.protocol


def test_decoded_service_field_order_is_frozen():
    """`ports` and `warnings` are TRAILING and defaulted, on purpose.

    intake.py, staging.py, main.py and the agent tools construct and read this
    dataclass; adding a field anywhere but the end (or without a default) breaks
    every positional construction in the codebase at import time.
    """
    svc = DecodedService("tcp", 443, None, "tcp/443", "tls", "inferred")
    assert svc.ports is None
    assert svc.warnings == []
    assert [f for f in DecodedService.__dataclass_fields__][:6] == [
        "protocol", "port", "port_end", "label", "l7_app", "l7_source",
    ]


def test_warnings_are_not_shared_between_decodes():
    """A mutable default would leak one rule's warnings onto the next."""
    bad = parse_service("tcp/70000")
    clean = parse_service("tcp/443")
    assert bad.warnings and clean.warnings == []
    bad.warnings.append("x")
    assert parse_service("tcp/70000").warnings == ["port 70000 outside 0-65535"]


INTERVAL_CASES = [
    ("tcp/443", [(443, 443)]),
    ("tcp/1-65535", [(1, 65535)]),
    ("tcp/80,443", [(80, 80), (443, 443)]),
    ("tcp/80,8000-8100", [(80, 80), (8000, 8100)]),
    ("any", []),
    ("tcp/70000", []),
]


@pytest.mark.parametrize("service,expected", INTERVAL_CASES)
def test_intervals_reconciles_the_scalar_pair_with_the_list(service, expected):
    """One accessor, so no consumer has to know which field is authoritative."""
    assert parse_service(service).intervals() == expected


# --- the resolved value, carried instead of discarded ----------------------
TOKEN_CASES = [
    ("10.20.0.0/16", ["10.20.0.0/16"]),
    ("10.20.0.1/16", ["10.20.0.0/16"]),      # canonicalized
    ("10.20.0.5", ["10.20.0.5/32"]),         # a bare host IS an address space
    ("any", ["0.0.0.0/0"]), ("ANY", ["0.0.0.0/0"]), ("all", ["0.0.0.0/0"]),
    ("*", ["0.0.0.0/0"]), ("0.0.0.0/0", ["0.0.0.0/0"]),
    ("::/0", ["::/0"]),
    ("DB-SUBNETS", []),                      # a named object: the catalog resolves it
    ("finance-users", []),
    ("", []), (None, []),
]


@pytest.mark.parametrize("token,expected", TOKEN_CASES)
def test_cidrs_for_token(token, expected):
    assert cidrs_for_token(token) == expected


def test_record_from_service_carries_the_resolved_address_space():
    """The audit's root cause: the resolver's answer was assigned to `_s_cidr`.

    Deriving the resolved list here means an ad-hoc record site cannot drop it,
    and `any` and `0.0.0.0/0` cannot diverge -- they resolve to one string.
    """
    svc = parse_service("tcp/3389")
    any_rec = record_from_service(record_id="a", source_tool="algosec", raw_ref="a",
                                  source="any", destination="db-prod-01", svc=svc)
    cidr_rec = record_from_service(record_id="b", source_tool="algosec", raw_ref="b",
                                   source="0.0.0.0/0", destination="db-prod-01", svc=svc)
    assert any_rec.source_cidrs == cidr_rec.source_cidrs == ["0.0.0.0/0"]
    assert any_rec.dest_cidrs == []          # a named object, unresolvable here


def test_record_from_service_accepts_a_catalog_resolution():
    """A normalizer WITH the object catalog passes the resolved list; it wins."""
    rec = record_from_service(
        record_id="c", source_tool="algosec", raw_ref="c", source="ANY-EXTERNAL",
        destination="DC-SUBNETS", svc=parse_service("tcp/443"),
        source_cidrs=["0.0.0.0/0"], dest_cidrs=["10.2.0.0/16", "10.1.0.0/16"],
    )
    assert rec.source_kind == "identity"     # the label is still what the operator sees
    assert rec.source_cidrs == ["0.0.0.0/0"]
    assert rec.dest_cidrs == ["10.1.0.0/16", "10.2.0.0/16"]      # sorted, canonical


def test_empty_resolved_list_means_unresolvable_not_unset():
    """[] is a claim, and an explicit [] must survive being passed in."""
    rec = record_from_service(
        record_id="d", source_tool="algosec", raw_ref="d", source="10.0.0.0/8",
        destination="app-group", svc=parse_service("tcp/443"), source_cidrs=[],
    )
    assert rec.source_cidrs == []            # explicitly overridden, not derived
