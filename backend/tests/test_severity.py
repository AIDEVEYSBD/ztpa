"""The severity model, pinned constant by constant and clause by clause.

Why this file exists
--------------------
The product's headline claim is an exact E x P x D x B vector plus guardrail
floors, shipped on every finding so a client can recompute it by hand. Before
this file, that number had NO regression protection. The audit measured exactly
what could be changed while `pytest` and `verify_engine.py` both stayed green:

  - move the critical band from 80 to 95
  - empty `ADMIN_LATERAL_PORTS` (deleting the admin-port guardrail outright)
  - re-tune `impact_base`, so every score in every snapshot shifts
  - make every PCI asset score like an untagged one

So the tests here are deliberately written the boring way. Every published
constant is pinned to a LITERAL, not compared against itself: asserting
`dest_score(["pci"]) == TAG_SENSITIVITY["pci"]` passes after someone edits
`TAG_SENSITIVITY["pci"]`, which is precisely the mutation that must fail. And
every guardrail clause has a case where it is the ONLY clause that can fire, so
deleting one clause fails exactly one test and names itself.

The Phase 1 regressions each have their own named test, because a failure whose
name is the bug is worth more than a failure in `test_scoring_table[17]`:

  - `test_full_port_range_from_the_internet_is_forced_critical`
  - `test_the_four_encodings_of_one_address_space_score_identically`
  - `test_half_the_internet_scores_like_the_internet`
  - `test_internet_facing_sensitive_asset_cannot_escape_the_cross_tool_floor`
  - `test_any_protocol_is_reported_as_any_port_not_as_admin`

Pure functions throughout: no fixtures, no I/O, no database, no model.
"""

from __future__ import annotations

import pytest

from src.analyzers.severity import (
    band, dest_score, exposure_score, is_internet_source, port_score,
    port_score_from_service, prefixlen_of, score_cross_tool_path, score_over_permissive,
    score_overlap, score_shadowed, score_transport_exposure, severity_from_vector,
)
from src.config import (
    ADMIN_LATERAL_PORTS, DATA_STORE_PORTS, EXPOSURE_BANDS, EXPOSURE_BANDS_V6,
    E_IDENTITY, GENERAL_APP_PORTS, INFRA_CONTROL_PORTS, PORT_CLASS_ADMIN,
    PORT_CLASS_ANY_PORT, PORT_CLASS_DATA_STORE, PORT_CLASS_GENERAL_APP,
    PORT_CLASS_INFRA_CONTROL, PORT_CLASS_P, PORT_CLASS_UNKNOWN, PORT_SPAN_ANY,
    P_ADMIN, P_ANY_PORT, P_DATA_STORE, P_GENERAL_APP, P_INFRA_CONTROL, P_UNKNOWN,
    SEVERITY_CONFIG, TAG_SENSITIVITY, TRANSPORT_CONFIG, ZONE_INTERNAL, ZONE_INTERNET,
)

BAND_ORDER = ["low", "medium", "high", "critical"]


# ==========================================================================
# 1 - The published constants. Pinned to literals, so a "calibration tweak"
#     is a red test rather than a silent repricing of every finding.
# ==========================================================================

def test_severity_config_is_exactly_this():
    """ENGINE.md 5.2/5.3 prints these numbers. Changing one changes every score
    in every snapshot the product has ever produced, so it changes here first."""
    assert SEVERITY_CONFIG == {
        "impact_base": 0.5,
        "impact_p_weight": 0.5,
        "exposure_floor": 0.4,
        "exposure_span": 0.6,
        "band_critical": 80,
        "band_high": 60,
        "band_medium": 35,
        "overlap_base": 10,
        "overlap_sensitive_bump": 20,
        "overlap_broad_prefixlen": 8,
        "shadowed_allow_base": 10,
    }


def test_tag_sensitivity_table_is_exactly_this():
    """D is a categorical policy fact. A row silently added, removed or retuned
    reprices a whole class of asset -- 'make every PCI asset score like an
    untagged one' was one of the mutations that used to pass green."""
    assert TAG_SENSITIVITY == {
        "crown-jewel": 1.0,
        "pci": 0.9, "customer-data": 0.9, "phi": 0.9,
        "prod": 0.6,
        "dev": 0.2, "sandbox": 0.2, "test": 0.2,
    }


def test_exposure_band_tables_are_exactly_this():
    """Both families. The v6 table is not a copy of the v4 one: a prefix length
    means a different amount of address space in each, and running v6 through
    the v4 rows scores a /32 holding 2**96 addresses as a single host."""
    assert EXPOSURE_BANDS == [(0, 1.0), (8, 0.9), (16, 0.7), (23, 0.5), (27, 0.3), (32, 0.1)]
    assert EXPOSURE_BANDS_V6 == [(0, 1.0), (16, 0.9), (32, 0.7), (48, 0.5), (64, 0.3), (128, 0.1)]
    assert E_IDENTITY == 0.1


def test_port_class_sets_are_exactly_this():
    """Emptying ADMIN_LATERAL_PORTS deletes the admin-port guardrail without
    touching a line of guardrail code. The audit confirmed the old suite stayed
    green through exactly that edit."""
    assert ADMIN_LATERAL_PORTS == {22, 23, 135, 445, 3389, 5985, 5986}
    assert DATA_STORE_PORTS == {5432, 3306, 1433, 27017, 6379}
    assert INFRA_CONTROL_PORTS == {6443, 2379}
    assert GENERAL_APP_PORTS == {80, 443, 8080, 8443, 53, 123}


def test_port_class_p_values_are_exactly_this():
    assert (P_ANY_PORT, P_ADMIN, P_DATA_STORE, P_INFRA_CONTROL, P_UNKNOWN,
            P_GENERAL_APP) == (1.0, 1.0, 0.9, 0.85, 0.5, 0.4)


def test_port_span_any_threshold_is_exactly_this():
    """1024 = the size of the IANA System port range (RFC 6335 s6). It is the
    published boundary above which a contiguous grant is 'any port', so it is a
    number an auditor checks against the RFC, not a knob to tune quietly."""
    assert PORT_SPAN_ANY == 1024


def test_transport_config_knobs_are_exactly_this():
    assert TRANSPORT_CONFIG["blind_spot_bump"] == 15
    assert TRANSPORT_CONFIG["fallback_base"] == 40
    assert TRANSPORT_CONFIG["fallback_sensitive_bump"] == 20


# ==========================================================================
# 2 - The port CLASS table. The float is not the identity.
# ==========================================================================

def test_every_port_class_is_a_distinct_published_row():
    """Regression: the class table used to be keyed by P value. P_ANY_PORT and
    P_ADMIN are both 1.0, so the 'any-port' row was overwritten at import time
    and `PORT_CLASS_LABEL[P_ANY_PORT]` answered 'admin / lateral-movement'.
    Every any/any finding in the product shipped a port_class naming ports the
    rule does not mention, and the 'any-port' label was unreachable."""
    assert len(PORT_CLASS_P) == 6
    assert PORT_CLASS_P[PORT_CLASS_ANY_PORT] == P_ANY_PORT
    assert PORT_CLASS_P[PORT_CLASS_ADMIN] == P_ADMIN
    assert PORT_CLASS_P[PORT_CLASS_ANY_PORT] == PORT_CLASS_P[PORT_CLASS_ADMIN], (
        "the two 1.0 classes must still be allowed to share a P -- what must not "
        "be shared is their identity")


def test_port_class_table_order_is_most_severe_first():
    """`port_score` returns the FIRST applicable row, which is only 'the max
    class over the range' if the table is sorted descending. It is also what
    pins the 1.0 tie: tcp/1-65535 is both any-port and admin, and which label it
    reports must not depend on dict iteration luck."""
    values = list(PORT_CLASS_P.values())
    assert values == sorted(values, reverse=True)
    assert next(iter(PORT_CLASS_P)) == PORT_CLASS_ANY_PORT


def test_any_protocol_is_reported_as_any_port_not_as_admin():
    assert port_score("any", None) == (P_ANY_PORT, PORT_CLASS_ANY_PORT)
    assert port_score("any", 443) == (P_ANY_PORT, PORT_CLASS_ANY_PORT)


# ==========================================================================
# 3 - severity_from_vector: exact values across every band boundary.
# ==========================================================================
# (E, P, D, B, severity, band). Every value is a literal computed once and
# frozen; the boundary rows 34/35, 59/60 and 79/80 exist so an off-by-one in
# `band` or a re-tuned weight in SEVERITY_CONFIG lands on a named row.
VECTOR_CASES = [
    (0.1, 0.4, 0.2, 1.0, 6, "low"),
    (0.1, 1.0, 0.2, 1.0, 9, "low"),
    (1.0, 0.5, 0.2, 1.0, 15, "low"),
    (0.1, 0.4, 1.0, 1.0, 32, "low"),
    (0.7, 0.4, 0.4, 1.5, 34, "low"),          # low/medium boundary - low side
    (0.1, 0.5, 1.0, 1.0, 34, "low"),          # low/medium boundary - low side
    (0.3, 1.0, 0.6, 1.0, 35, "medium"),       # low/medium boundary - medium side
    (0.9, 0.5, 0.4, 1.25, 35, "medium"),      # low/medium boundary - medium side
    (0.1, 0.9, 0.9, 1.5, 59, "medium"),       # medium/high boundary - medium side
    (0.3, 0.5, 0.9, 1.5, 59, "medium"),       # medium/high boundary - medium side
    (0.5, 0.9, 0.9, 1.0, 60, "high"),         # medium/high boundary - high side
    (1.0, 1.0, 0.4, 1.5, 60, "high"),         # medium/high boundary - high side
    (0.5, 1.0, 0.9, 1.25, 79, "high"),        # high/critical boundary - high side
    (1.0, 0.4, 0.9, 1.25, 79, "high"),        # high/critical boundary - high side
    (0.9, 0.9, 0.9, 1.0, 80, "critical"),     # high/critical boundary - critical side
    (0.3, 0.85, 1.0, 1.5, 80, "critical"),    # high/critical boundary - critical side
    (1.0, 1.0, 0.9, 1.5, 100, "critical"),    # ENGINE.md 5.5 worked example
    (1.0, 1.0, 1.0, 1.0, 100, "critical"),
    (1.0, 0.85, 1.0, 1.25, 100, "critical"),
    (0.9, 1.0, 1.0, 1.5, 100, "critical"),
]


@pytest.mark.parametrize("E,P,D,B,expected,expected_band", VECTOR_CASES)
def test_severity_from_vector_exact(E, P, D, B, expected, expected_band):
    severity = severity_from_vector(E, P, D, B)
    assert severity == expected
    assert band(severity) == expected_band


def test_the_engine_md_worked_example_still_reproduces_to_exactly_100():
    """ENGINE.md 5.5, the example the documentation invites a client to check by
    hand: `allow 0.0.0.0/0 -> db-prod-01 tcp/3389`, db tagged pci,
    internet -> internal. E=1.0, P=1.0, D=0.9, B=1.5 -> impact 0.90,
    exposure_factor 1.00, raw 1.35, severity 100. Pinned end to end AND
    sub-score by sub-score, so a published document cannot quietly go stale."""
    assert exposure_score("0.0.0.0/0", "cidr") == 1.0
    assert port_score("tcp", 3389) == (1.0, PORT_CLASS_ADMIN)
    assert dest_score(["pci", "customer-data", "prod"]) == 0.9
    assert severity_from_vector(1.0, 1.0, 0.9, 1.5) == 100

    scored = score_over_permissive(
        source="0.0.0.0/0", source_kind="cidr", protocol="tcp", port=3389,
        dest_tags=["pci", "customer-data", "prod"],
        src_zone=ZONE_INTERNET, dst_zone=ZONE_INTERNAL)
    assert scored["severity"] == 100
    assert band(scored["severity"]) == "critical"
    assert scored["vector"] == {"E": 1.0, "P": 1.0, "D": 0.9, "B": 1.5}
    assert scored["forced_critical"] is True


BAND_CASES = [
    (0, "low"), (34, "low"), (35, "medium"), (59, "medium"),
    (60, "high"), (79, "high"), (80, "critical"), (100, "critical"),
]


@pytest.mark.parametrize("severity,expected", BAND_CASES)
def test_band_boundaries(severity, expected):
    """Lower-inclusive thresholds, both sides of all three boundaries. Moving
    band_critical from 80 to 95 -- a mutation the old suite survived -- fails
    the 80 row here."""
    assert band(severity) == expected


# ==========================================================================
# 4 - D: one case per TAG_SENSITIVITY entry.
# ==========================================================================
TAG_CASES = [
    ("crown-jewel", 1.0), ("pci", 0.9), ("customer-data", 0.9), ("phi", 0.9),
    ("prod", 0.6), ("dev", 0.2), ("sandbox", 0.2), ("test", 0.2),
]


@pytest.mark.parametrize("tag,expected", TAG_CASES)
def test_dest_score_per_tag(tag, expected):
    assert dest_score([tag]) == expected


def test_dest_score_covers_every_published_tag():
    """Guards the table above against a row added to config and forgotten here."""
    assert {tag for tag, _ in TAG_CASES} == set(TAG_SENSITIVITY)


def test_dest_score_defaults_and_max():
    assert dest_score([]) == 0.4                                  # untagged
    assert dest_score(["unheard-of"]) == 0.4                      # unknown tag
    assert dest_score(["dev", "pci"]) == 0.9                      # max, not mean
    assert dest_score(["dev", "crown-jewel", "prod"]) == 1.0
    assert dest_score(["dev", "unheard-of"]) == 0.4               # default can win


# ==========================================================================
# 5 - E: exposure from the resolved address space, not from the label.
# ==========================================================================
EXPOSURE_CASES = [
    ("0.0.0.0/0", 1.0), ("128.0.0.0/1", 0.9), ("1.0.0.0/8", 0.9),
    ("10.0.0.0/9", 0.7), ("10.0.0.0/16", 0.7),
    ("10.0.0.0/17", 0.5), ("10.0.0.0/23", 0.5),
    ("10.0.0.0/24", 0.3), ("10.0.0.0/27", 0.3),
    ("10.0.0.0/28", 0.1), ("10.0.0.5/32", 0.1), ("10.0.0.5", 0.1),
    ("::/0", 1.0), ("2000::/3", 0.9), ("2001:db8::/32", 0.7),
    ("2001:db8::/48", 0.5), ("2001:db8::/64", 0.3), ("2001:db8::1", 0.1),
]


@pytest.mark.parametrize("source,expected", EXPOSURE_CASES)
def test_exposure_score_bands(source, expected):
    assert exposure_score(source, "cidr") == expected


def test_exposure_falls_back_to_identity_only_when_nothing_resolves():
    """E_IDENTITY is the score of a single host. It is the right answer for a
    user, a tag or an application group -- and the wrong answer for every named
    object that does dereference to address space, which is what the old
    `if source_kind == "identity": return E_IDENTITY` short-circuit produced."""
    assert exposure_score("web-tier", "identity") == E_IDENTITY
    assert exposure_score("web-tier", "identity", []) == E_IDENTITY
    assert exposure_score("garbage/not-a-cidr", "cidr") == E_IDENTITY
    assert exposure_score("ANY-EXTERNAL", "identity", ["0.0.0.0/0"]) == 1.0


def test_exposure_scores_the_broadest_member_of_a_group():
    """A group is as exposed as its widest member: a firewall admits traffic
    matching ANY entry, so averaging or taking the first would understate it."""
    assert exposure_score("G", "identity", ["10.0.0.0/8", "0.0.0.0/0"]) == 1.0
    assert exposure_score("G", "identity", ["0.0.0.0/0", "10.0.0.0/8"]) == 1.0
    assert exposure_score("G", "identity", ["10.0.0.0/24", "10.1.0.0/16"]) == 0.7
    # Mixed families: each network is scored under its own table, then maxed.
    assert exposure_score("G", "identity", ["10.0.0.5/32", "2001:db8::/32"]) == 0.7


def test_resolved_cidrs_win_over_the_label():
    """The label is evidence only when there is nothing better. Once the
    normalizer has resolved the object, the resolved value is the answer."""
    assert exposure_score("10.0.0.5/32", "cidr", ["0.0.0.0/0"]) == 1.0
    assert exposure_score("0.0.0.0/0", "cidr", ["10.0.0.5/32"]) == 0.1


def test_wildcard_vocabulary_is_the_whole_address_space():
    for token in ("any", "Any", "ANY", "all", "*", "0.0.0.0/0", "::/0"):
        assert exposure_score(token, "cidr") == 1.0, token
        assert is_internet_source(token, "cidr") is True, token


def test_exposure_never_falls_as_the_source_widens():
    """Monotonicity. A wider grant can never be scored as less exposed -- the
    property that makes E defensible to a client with a spreadsheet."""
    previous = 0.0
    for prefixlen in range(32, -1, -1):
        current = exposure_score(f"10.0.0.0/{prefixlen}", "cidr")
        assert current >= previous, prefixlen
        previous = current


# ==========================================================================
# 6 - P: the max class over the whole service, not the first port.
# ==========================================================================
# (protocol, port, port_end, ports, P, class label)
PORT_CASES = [
    # single ports, one per class
    ("tcp", 3389, None, None, P_ADMIN, PORT_CLASS_ADMIN),
    ("tcp", 22, None, None, P_ADMIN, PORT_CLASS_ADMIN),
    ("tcp", 5432, None, None, P_DATA_STORE, PORT_CLASS_DATA_STORE),
    ("tcp", 6443, None, None, P_INFRA_CONTROL, PORT_CLASS_INFRA_CONTROL),
    ("tcp", 443, None, None, P_GENERAL_APP, PORT_CLASS_GENERAL_APP),
    ("tcp", 9100, None, None, P_UNKNOWN, PORT_CLASS_UNKNOWN),
    ("tcp", None, None, None, P_UNKNOWN, PORT_CLASS_UNKNOWN),
    ("any", None, None, None, P_ANY_PORT, PORT_CLASS_ANY_PORT),
    # ranges: the class of the WORST port inside, not of the start port
    ("tcp", 3389, 3389, None, P_ADMIN, PORT_CLASS_ADMIN),
    ("tcp", 3380, 3400, None, P_ADMIN, PORT_CLASS_ADMIN),
    ("tcp", 5400, 5500, None, P_DATA_STORE, PORT_CLASS_DATA_STORE),
    ("tcp", 6440, 6450, None, P_INFRA_CONTROL, PORT_CLASS_INFRA_CONTROL),
    ("tcp", 8000, 8100, None, P_UNKNOWN, PORT_CLASS_UNKNOWN),
    ("tcp", 1, 65535, None, P_ANY_PORT, PORT_CLASS_ANY_PORT),
    ("tcp", 0, 65535, None, P_ANY_PORT, PORT_CLASS_ANY_PORT),
    # comma lists: the max over ALL intervals, not over the first
    ("tcp", 80, None, [(80, 80), (443, 443)], P_GENERAL_APP, PORT_CLASS_GENERAL_APP),
    ("tcp", 80, None, [(80, 80), (3389, 3389)], P_ADMIN, PORT_CLASS_ADMIN),
    ("tcp", 80, None, [(80, 80), (5432, 5432)], P_DATA_STORE, PORT_CLASS_DATA_STORE),
    ("tcp", 80, None, [(80, 80), (9100, 9100)], P_UNKNOWN, PORT_CLASS_UNKNOWN),
    # span thresholds, both sides of PORT_SPAN_ANY, on ports in no named class
    ("tcp", 10000, 11023, None, P_UNKNOWN, PORT_CLASS_UNKNOWN),      # exactly 1024
    ("tcp", 10000, 11024, None, P_ANY_PORT, PORT_CLASS_ANY_PORT),    # 1025
    ("tcp", 20000, 20500, [(20000, 20500), (30000, 30600)], P_ANY_PORT, PORT_CLASS_ANY_PORT),
]


@pytest.mark.parametrize("protocol,port,port_end,ports,expected_p,expected_class", PORT_CASES)
def test_port_score_cases(protocol, port, port_end, ports, expected_p, expected_class):
    assert port_score(protocol, port, port_end, ports) == (expected_p, expected_class)


def test_a_port_range_is_not_scored_as_its_start_port():
    """The audit's most quotable failure, stated as a test. `tcp/1-65535` reads
    port 1 -- unclassified, P=0.5 -- unless the whole interval is scored."""
    assert port_score("tcp", 1) == (P_UNKNOWN, PORT_CLASS_UNKNOWN)
    assert port_score("tcp", 1, 65535) == (P_ANY_PORT, PORT_CLASS_ANY_PORT)


def test_unclassified_outranks_general_app_inside_a_range():
    """tcp/80-120 opens HTTP and 40 ports nobody named. Reporting it as a
    'general app / web' grant because of the one port it happens to contain
    would understate it; the max class over the interval is 'unknown /
    ephemeral'. (Wider still, tcp/80-8080 crosses PORT_SPAN_ANY and is
    'any-port' -- the same rule applied one step further.)"""
    assert port_score("tcp", 80, 120) == (P_UNKNOWN, PORT_CLASS_UNKNOWN)
    assert port_score("tcp", 80, 81) == (P_UNKNOWN, PORT_CLASS_UNKNOWN)
    assert port_score("tcp", 80, 80) == (P_GENERAL_APP, PORT_CLASS_GENERAL_APP)
    assert port_score("tcp", 80, 8080) == (P_ANY_PORT, PORT_CLASS_ANY_PORT)


@pytest.mark.parametrize("lo", [1, 10000, 40000])
def test_p_never_falls_as_the_service_widens(lo):
    """Monotonicity, the same property E has: opening more ports can raise the
    class and can never lower it. This is what makes 'score the range' safe to
    state to a client as a rule rather than as a table of special cases."""
    previous = 0.0
    for hi in (lo, lo + 1, lo + 100, lo + 1023, lo + 1024, lo + 5000, 65535):
        current, _ = port_score("tcp", lo, hi)
        assert current >= previous, (lo, hi)
        previous = current


def test_port_score_is_independent_of_how_the_vendor_punctuated_the_list():
    """`tcp/443,80` and `tcp/80,443` are one service. Determinism forbids the
    snapshot depending on which order an export happened to write."""
    assert (port_score("tcp", 80, None, [(80, 80), (443, 443)])
            == port_score("tcp", 443, None, [(443, 443), (80, 80)]))
    # touching intervals coalesce, so the span count cannot be inflated by
    # splitting one range into two
    assert (port_score("tcp", 10000, None, [(10000, 10500), (10501, 11024)])
            == port_score("tcp", 10000, 11024, None))


def test_port_score_never_raises_on_input_a_caller_can_produce():
    """The guardrail floor reads the same intervals the score does, so this
    function has to be total: an inverted range, an out-of-range port or a
    malformed pair is dropped, never propagated into the class lookup."""
    assert port_score("tcp", 500, 100) == (P_UNKNOWN, PORT_CLASS_UNKNOWN)     # inverted
    assert port_score("tcp", None, 443) == (P_UNKNOWN, PORT_CLASS_UNKNOWN)    # no start
    assert port_score("tcp", 3389, None, []) == (P_ADMIN, PORT_CLASS_ADMIN)   # empty list
    assert port_score(None, 3389) == (P_ADMIN, PORT_CLASS_ADMIN)              # no protocol
    assert port_score("tcp", 0, 70000) == (P_ANY_PORT, PORT_CLASS_ANY_PORT)   # clamped
    assert port_score("tcp", 80, None, [(80, 80), None]) == (P_GENERAL_APP,
                                                             PORT_CLASS_GENERAL_APP)


SERVICE_CASES = [
    ("tcp/3389", P_ADMIN, PORT_CLASS_ADMIN),
    ("tcp/5432", P_DATA_STORE, PORT_CLASS_DATA_STORE),
    ("tcp/443", P_GENERAL_APP, PORT_CLASS_GENERAL_APP),
    ("quic", P_GENERAL_APP, PORT_CLASS_GENERAL_APP),
    ("tcp/8000-8100", P_UNKNOWN, PORT_CLASS_UNKNOWN),
    ("tcp/1-65535", P_ANY_PORT, PORT_CLASS_ANY_PORT),
    ("tcp/80,443", P_GENERAL_APP, PORT_CLASS_GENERAL_APP),
    ("tcp/80,3389", P_ADMIN, PORT_CLASS_ADMIN),
    ("ip", P_ANY_PORT, PORT_CLASS_ANY_PORT),
    (None, P_UNKNOWN, PORT_CLASS_UNKNOWN),
    ("", P_UNKNOWN, PORT_CLASS_UNKNOWN),
]


@pytest.mark.parametrize("service,expected_p,expected_class", SERVICE_CASES)
def test_port_score_from_service(service, expected_p, expected_class):
    """The string path -- what a cross-tool path's terminal edge is scored by.
    It must agree with the structured path on every encoding, ranges and comma
    lists included."""
    assert port_score_from_service(service) == (expected_p, expected_class)


# ==========================================================================
# 7 - The guardrail floor. One case per clause, asserted independently.
# ==========================================================================
# Each case is built so exactly ONE clause can fire: deleting that clause fails
# exactly one test, and the test names the clause it lost.

def test_guardrail_clause_1_internet_any_any():
    scored = score_over_permissive(
        source="0.0.0.0/0", source_kind="cidr", protocol="any", port=None,
        dest_tags=[], src_zone=ZONE_INTERNET, dst_zone=ZONE_INTERNAL)
    assert scored["forced_critical"] is True
    assert scored["forced_reasons"] == ["internet any/any"]


def test_guardrail_clause_2_admin_port_from_the_internet():
    scored = score_over_permissive(
        source="0.0.0.0/0", source_kind="cidr", protocol="tcp", port=3389,
        dest_tags=[], src_zone=ZONE_INTERNET, dst_zone=ZONE_INTERNAL)
    assert scored["forced_critical"] is True
    assert scored["forced_reasons"] == [
        "admin/lateral-movement port exposed to the internet"]


def test_guardrail_clause_3_sensitive_destination_from_the_internet():
    scored = score_over_permissive(
        source="0.0.0.0/0", source_kind="cidr", protocol="tcp", port=443,
        dest_tags=["pci"], src_zone=ZONE_INTERNET, dst_zone=ZONE_INTERNAL)
    assert scored["forced_critical"] is True
    assert scored["forced_reasons"] == [
        "regulated/crown-jewel asset reachable from the internet"]


@pytest.mark.parametrize("tag", sorted({"crown-jewel", "pci", "customer-data", "phi"}))
def test_guardrail_clause_3_fires_for_every_sensitive_tag(tag):
    scored = score_over_permissive(
        source="0.0.0.0/0", source_kind="cidr", protocol="tcp", port=443,
        dest_tags=[tag], src_zone=ZONE_INTERNET, dst_zone=ZONE_INTERNAL)
    assert scored["forced_critical"] is True


NOT_FORCED_CASES = [
    # an internal source, however bad the port or the destination
    ("10.0.0.0/8", "cidr", "tcp", 3389, None, ["pci"]),
    ("192.168.0.0/16", "cidr", "any", None, None, ["crown-jewel"]),
    ("100.64.0.0/10", "cidr", "tcp", 22, None, ["pci"]),        # CGNAT is not the internet
    # the internet, but none of the three clauses
    ("0.0.0.0/0", "cidr", "tcp", 443, None, ["prod"]),
    ("0.0.0.0/0", "cidr", "tcp", 5432, None, []),               # data store is not clause 2
    # an unresolvable label is not evidence of internet exposure
    ("web-tier", "identity", "tcp", 3389, None, ["pci"]),
]


@pytest.mark.parametrize("source,kind,protocol,port,port_end,tags", NOT_FORCED_CASES)
def test_the_floor_does_not_fire_when_no_clause_applies(source, kind, protocol, port,
                                                        port_end, tags):
    """A floor that fires on everything protects nothing. These are the
    near-misses, one per clause boundary."""
    scored = score_over_permissive(
        source=source, source_kind=kind, protocol=protocol, port=port, port_end=port_end,
        dest_tags=tags, src_zone=ZONE_INTERNAL, dst_zone=ZONE_INTERNAL)
    assert scored["forced_critical"] is False
    assert scored["forced_reasons"] == []


def test_full_port_range_from_the_internet_is_forced_critical():
    """Phase 1 exit criterion, and the audit's headline defect:
    `0.0.0.0/0 -> host tcp/1-65535` used to score P=0.5 from port 1, trip no
    guardrail and produce ZERO findings -- while the same rule written
    `tcp/3389` was forced critical. The range EXPOSES 3389; the floor must see
    that. Note the destination is untagged, so clause 3 cannot be what fires."""
    scored = score_over_permissive(
        source="0.0.0.0/0", source_kind="cidr", protocol="tcp", port=1, port_end=65535,
        dest_tags=[], src_zone=ZONE_INTERNET, dst_zone=ZONE_INTERNAL)
    assert scored["forced_critical"] is True
    assert scored["forced_reasons"] == [
        "admin/lateral-movement port exposed to the internet"]
    assert scored["port_class"] == PORT_CLASS_ANY_PORT
    assert scored["vector"] == {"E": 1.0, "P": 1.0, "D": 0.4, "B": 1.5}
    assert scored["severity"] == 60

    # the old behaviour, kept as the contrast the fix is measured against
    start_only = score_over_permissive(
        source="0.0.0.0/0", source_kind="cidr", protocol="tcp", port=1,
        dest_tags=[], src_zone=ZONE_INTERNET, dst_zone=ZONE_INTERNAL)
    assert start_only["forced_critical"] is False


def test_the_admin_port_guardrail_fires_on_every_admin_port_and_on_ranges():
    """One assertion per member of ADMIN_LATERAL_PORTS, plus the same port
    reached through a range. Emptying the set fails all of them."""
    for port in sorted(ADMIN_LATERAL_PORTS):
        exact = score_over_permissive(
            source="0.0.0.0/0", source_kind="cidr", protocol="tcp", port=port,
            dest_tags=[], src_zone=ZONE_INTERNET, dst_zone=ZONE_INTERNAL)
        spanned = score_over_permissive(
            source="0.0.0.0/0", source_kind="cidr", protocol="tcp",
            port=port - 1, port_end=port + 1,
            dest_tags=[], src_zone=ZONE_INTERNET, dst_zone=ZONE_INTERNAL)
        assert exact["forced_critical"] is True, port
        assert spanned["forced_critical"] is True, port
        assert exact["forced_reasons"] == spanned["forced_reasons"], port


def test_the_admin_port_guardrail_fires_on_a_comma_list():
    scored = score_over_permissive(
        source="0.0.0.0/0", source_kind="cidr", protocol="tcp", port=80,
        ports=[(80, 80), (3389, 3389)], dest_tags=[],
        src_zone=ZONE_INTERNET, dst_zone=ZONE_INTERNAL)
    assert scored["forced_critical"] is True
    assert scored["forced_reasons"] == [
        "admin/lateral-movement port exposed to the internet"]


def test_all_three_clauses_can_fire_at_once_and_each_is_reported():
    """The reasons list is what the change gate prints to an operator, so it
    carries every clause that fired, in table order, not just the first."""
    scored = score_over_permissive(
        source="0.0.0.0/0", source_kind="cidr", protocol="any", port=1, port_end=65535,
        dest_tags=["crown-jewel"], src_zone=ZONE_INTERNET, dst_zone=ZONE_INTERNAL)
    assert scored["forced_critical"] is True
    assert scored["forced_reasons"] == [
        "internet any/any",
        "admin/lateral-movement port exposed to the internet",
        "regulated/crown-jewel asset reachable from the internet",
    ]


# ==========================================================================
# 8 - "The internet" is public address space, not the string 0.0.0.0/0.
# ==========================================================================
PUBLIC_SOURCES = ["0.0.0.0/0", "0.0.0.0/1", "128.0.0.0/1", "1.0.0.0/8",
                  "52.20.10.0/24", "any", "all", "*", "::/0", "2000::/3"]
PRIVATE_SOURCES = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
                   "100.64.0.0/10", "169.254.0.0/16", "127.0.0.0/8",
                   "fc00::/7", "fe80::/10", "web-tier", "0.0.0.0"]
# Public address space, but ONE address: a named external peer, not the world.
SINGLE_PUBLIC_HOSTS = ["8.8.8.8/32", "52.20.10.10/32", "8.8.8.8",
                       "2606:4700::1111/128", "::ffff:8.8.8.8"]


@pytest.mark.parametrize("source", PUBLIC_SOURCES)
def test_public_sources_are_internet_sources(source):
    assert is_internet_source(source, "cidr") is True


@pytest.mark.parametrize("source", PRIVATE_SOURCES)
def test_private_sources_are_not_internet_sources(source):
    assert is_internet_source(source, "identity") is False


@pytest.mark.parametrize("source", SINGLE_PUBLIC_HOSTS)
def test_a_single_public_host_is_not_the_internet(source):
    """A DMZ load balancer's own address is globally routable, but the clause
    this gates says 'exposed to the internet' and a grant to one named external
    peer is a bounded, reviewable exception -- not a categorical emergency.
    Firing here would relabel every DMZ hop in the estate as internet-sourced;
    `graph.zones` refuses the mirror-image of this for the same reason. The
    narrowness is already priced in: E = 0.1 for a single host."""
    assert is_internet_source(source, "cidr") is False
    assert exposure_score(source, "cidr") == E_IDENTITY
    scored = score_over_permissive(
        source=source, source_kind="cidr", protocol="tcp", port=3389,
        dest_tags=["pci"], src_zone=ZONE_INTERNET, dst_zone=ZONE_INTERNAL)
    assert scored["forced_critical"] is False


def test_a_named_object_is_classified_by_what_it_resolves_to():
    assert is_internet_source("ANY-EXTERNAL", "identity", ["0.0.0.0/0"]) is True
    assert is_internet_source("DC-SUBNETS", "identity", ["10.0.0.0/8"]) is False
    # any public member makes the grant internet-facing
    assert is_internet_source("MIXED", "identity", ["10.0.0.0/8", "1.0.0.0/8"]) is True


def test_half_the_internet_scores_like_the_internet():
    """Phase 1 exit criterion. Writing a rule's source as two /1s -- or as an
    ordinary public /8 -- used to drop it from 90/critical to 56/medium and trip
    no guardrail at all, because 'the internet' meant `E >= 1.0`. Both halves of
    the criterion are asserted: the guardrail fires, and the smooth score stays
    within one band of the /0 spelling for the same destination and port."""
    def scored(source):
        return score_over_permissive(
            source=source, source_kind="cidr", protocol="tcp", port=3389,
            dest_tags=["pci"], src_zone=ZONE_INTERNET, dst_zone=ZONE_INTERNAL)

    baseline = scored("0.0.0.0/0")
    for source in ("0.0.0.0/1", "128.0.0.0/1", "1.0.0.0/8"):
        near = scored(source)
        assert near["forced_critical"] is True, source
        assert near["forced_reasons"] == baseline["forced_reasons"], source
        distance = abs(BAND_ORDER.index(band(near["severity"]))
                       - BAND_ORDER.index(band(baseline["severity"])))
        assert distance <= 1, (source, near["severity"], baseline["severity"])

    # and with a mild port to a non-sensitive destination, where nothing is
    # clamped at 100 and the bands could actually diverge
    def mild(source):
        return score_over_permissive(
            source=source, source_kind="cidr", protocol="tcp", port=443,
            dest_tags=[], src_zone=ZONE_INTERNET, dst_zone=ZONE_INTERNAL)["severity"]

    assert mild("0.0.0.0/0") == 42
    assert mild("0.0.0.0/1") == 39
    assert mild("1.0.0.0/8") == 39
    assert band(mild("0.0.0.0/1")) == band(mild("0.0.0.0/0"))


# ==========================================================================
# 9 - The four-encodings property (Phase 1 exit criterion).
# ==========================================================================
# One address space, four ways a real export spells it. The engine must not be
# able to tell them apart.
FOUR_ENCODINGS = [
    ("literal /0", "0.0.0.0/0", "cidr", []),
    ("wildcard word", "any", "cidr", []),
    ("named object", "ANY-EXTERNAL", "identity", ["0.0.0.0/0"]),
    ("address group", "EXTERNAL-NETS", "identity", ["0.0.0.0/0", "10.0.0.0/8"]),
]


# Two grants, and both zone pairs, because ONE saturating case cannot fail.
# `tcp/3389 -> pci` trips a guardrail floor AND clamps (`min(raw, 1.0) * 100`),
# so four different vectors all land on 100/critical/forced -- this test could
# not have detected a wrong E, and it could not have detected a wrong B either,
# because it hard-codes both zones. `tcp/443 -> untagged` fires no floor and
# lands nowhere near the clamp, so severity and band are free to move; running
# it across BOTH zone pairs is what stops "identical by construction".
#
# What this file can and cannot prove: `score_over_permissive` is handed its
# zones, so the layer that actually diverged (`graph.build` -> `zones.zone_of`,
# which was never given a group's address space) is not reachable from here. The
# end-to-end property is pinned in
# `test_analyzers.py::test_the_four_encodings_of_one_policy_score_identically`,
# which builds the four encodings from raw exports and hand-builds nothing.
FOUR_ENCODING_GRANTS = [
    ("rdp-to-pci-across-the-boundary", 3389, ["pci"], ZONE_INTERNET, 100, True),
    ("mild-across-the-boundary", 443, [], ZONE_INTERNET, 42, False),
    ("mild-inside-one-zone", 443, [], ZONE_INTERNAL, 28, False),
]


def _score_encoding(source, kind, cidrs, *, port=3389, dest_tags=("pci",),
                    src_zone=ZONE_INTERNET):
    return score_over_permissive(
        source=source, source_kind=kind, source_cidrs=cidrs,
        protocol="tcp", port=port, dest_tags=list(dest_tags),
        src_zone=src_zone, dst_zone=ZONE_INTERNAL)


@pytest.mark.parametrize("grant,port,dest_tags,src_zone,severity,forced",
                         FOUR_ENCODING_GRANTS, ids=[g[0] for g in FOUR_ENCODING_GRANTS])
@pytest.mark.parametrize("name,source,kind,cidrs", FOUR_ENCODINGS,
                         ids=[e[0] for e in FOUR_ENCODINGS])
def test_the_four_encodings_of_one_address_space_score_identically(
        name, source, kind, cidrs, grant, port, dest_tags, src_zone, severity, forced):
    """The property the whole 'carry the resolved value' workstream exists for.
    A named object used to short-circuit to E_IDENTITY (0.1, the score of a
    single host), so `ANY-EXTERNAL -> db-prod-01 tcp/3389` -- RDP to the PCI
    database from the entire internet -- scored medium and tripped no floor."""
    kw = {"port": port, "dest_tags": dest_tags, "src_zone": src_zone}
    baseline = _score_encoding("0.0.0.0/0", "cidr", [], **kw)
    actual = _score_encoding(source, kind, cidrs, **kw)
    assert actual["severity"] == baseline["severity"] == severity, (name, grant)
    assert band(actual["severity"]) == band(baseline["severity"]), (name, grant)
    assert actual["forced_critical"] == baseline["forced_critical"] is forced, (name, grant)
    assert actual["forced_reasons"] == baseline["forced_reasons"], (name, grant)
    assert actual["vector"] == baseline["vector"], (name, grant)


def test_the_four_encodings_property_is_not_true_only_because_it_saturates():
    """Guard on the guard. The shipped version of the test above used a single
    case that both clamps at 100 and forces critical, so every encoding agreed
    no matter what the vector said. At least one parametrised grant must be able
    to move -- if these ever start clamping or force-marking, the property above
    goes back to being true by construction."""
    movable = [g for g in FOUR_ENCODING_GRANTS
               if not _score_encoding("0.0.0.0/0", "cidr", [], port=g[1],
                                      dest_tags=g[2], src_zone=g[3])["forced_critical"]]
    assert movable, "every grant force-marks critical; band can no longer diverge"
    severities = {_score_encoding("0.0.0.0/0", "cidr", [], port=g[1], dest_tags=g[2],
                                  src_zone=g[3])["severity"] for g in movable}
    assert severities and max(severities) < 100, severities
    # ...and the two zone pairs must genuinely score differently, or hard-coding
    # `src_zone` has quietly stopped mattering.
    assert _score_encoding("0.0.0.0/0", "cidr", [], port=443, dest_tags=[],
                           src_zone=ZONE_INTERNET)["severity"] != \
        _score_encoding("0.0.0.0/0", "cidr", [], port=443, dest_tags=[],
                        src_zone=ZONE_INTERNAL)["severity"]


def test_the_four_encodings_agree_on_every_sub_score_too():
    """Not just the total: E, the internet classification and the exposure
    signal have to agree, or the explanation shown next to the finding
    contradicts the number above it."""
    for _, source, kind, cidrs in FOUR_ENCODINGS:
        assert exposure_score(source, kind, cidrs) == 1.0
        assert is_internet_source(source, kind, cidrs) is True
        assert prefixlen_of(source, kind, cidrs) == 0


# ==========================================================================
# 10 - The other scorers.
# ==========================================================================

def test_internet_facing_sensitive_asset_cannot_escape_the_cross_tool_floor():
    """Boundary inversion. The floor used to require
    `boundary == "internet->internal"`, a comparison against the DESTINATION's
    zone label -- so a PCI database also tagged `internet-facing` sat in the DMZ,
    the boundary read `internet->dmz`, and the single most exposed crown-jewel
    asset in the estate was the one the floor could not protect."""
    dmz = score_cross_tool_path({
        "entry": "0.0.0.0/0", "terminal_service": "tcp/5432",
        "terminal_tags": ["pci", "internet-facing"],
        "boundary": "internet->dmz", "boundary_multiplier": 1.0,
    })
    assert dmz["forced_critical"] is True
    assert dmz["reaches_sensitive"] is True
    assert dmz["severity"] == 86
    assert dmz["forced_reasons"] == [
        "cross-tool path enters from the internet and reaches a sensitive asset"]


def test_cross_tool_floor_still_needs_both_halves():
    """It is a floor, not a blanket: a public entry that reaches nothing
    regulated is not forced, and neither is a regulated terminal reached from
    inside the estate."""
    not_sensitive = score_cross_tool_path({
        "entry": "0.0.0.0/0", "terminal_service": "tcp/5432", "terminal_tags": ["prod"],
        "boundary": "internet->internal", "boundary_multiplier": 1.5,
    })
    assert not_sensitive["forced_critical"] is False
    assert not_sensitive["forced_reasons"] == []

    internal_entry = score_cross_tool_path({
        "entry": "10.0.0.0/8", "terminal_service": "tcp/5432", "terminal_tags": ["pci"],
        "boundary": "internal->internal", "boundary_multiplier": 1.0,
    })
    assert internal_entry["forced_critical"] is False


def test_cross_tool_path_scores_a_named_entry_from_its_resolved_space():
    """Same defect as `exposure_score`'s, one layer up: an entry node that is a
    named object must classify like the address space it dereferences to."""
    scored = score_cross_tool_path({
        "entry": "ANY-EXTERNAL", "entry_cidrs": ["0.0.0.0/0"],
        "terminal_service": "tcp/5432", "terminal_tags": ["pci"],
        "boundary": "unknown->internal", "boundary_multiplier": 1.5,
    })
    assert scored["vector"]["E"] == 1.0
    assert scored["forced_critical"] is True


def test_cross_tool_path_terminal_service_is_range_aware():
    scored = score_cross_tool_path({
        "entry": "0.0.0.0/0", "terminal_service": "tcp/1-65535",
        "terminal_tags": ["prod"], "boundary": "internet->internal",
        "boundary_multiplier": 1.5,
    })
    assert scored["port_class"] == PORT_CLASS_ANY_PORT
    assert scored["vector"]["P"] == P_ANY_PORT


OVERLAP_CASES = [
    # (tags_a, tags_b, source_a, kind_a, cidrs_a, source_b, kind_b, cidrs_b, severity)
    (["prod"], ["prod"], "10.1.0.0/16", "cidr", None, "10.1.0.0/24", "cidr", None, 10),
    (["pci"], ["prod"], "10.1.0.0/16", "cidr", None, "10.1.0.0/24", "cidr", None, 30),
    (["prod"], ["phi"], "10.1.0.0/16", "cidr", None, "10.1.0.0/24", "cidr", None, 30),
    (["prod"], ["prod"], "10.0.0.0/8", "cidr", None, "10.1.0.0/24", "cidr", None, 30),
    (["prod"], ["prod"], "10.1.0.0/24", "cidr", None, "10.0.0.0/8", "cidr", None, 30),
    # a named object that dereferences to broad space is broad
    (["prod"], ["prod"], "ANY-EXTERNAL", "identity", ["0.0.0.0/0"],
     "10.1.0.0/24", "cidr", None, 30),
    # ... and one that dereferences to a host is not
    (["prod"], ["prod"], "APP-01", "identity", ["10.1.0.5/32"],
     "10.1.0.0/24", "cidr", None, 10),
    # v6: a /16 is broader than any v4 /8, and must not be called narrow just
    # because 16 > the v4-calibrated overlap_broad_prefixlen of 8
    (["prod"], ["prod"], "2000::/16", "cidr", None, "2000::/32", "cidr", None, 30),
    (["prod"], ["prod"], "2001:db8::/48", "cidr", None, "2001:db8::/64", "cidr", None, 10),
]


@pytest.mark.parametrize(
    "tags_a,tags_b,source_a,kind_a,cidrs_a,source_b,kind_b,cidrs_b,expected", OVERLAP_CASES)
def test_score_overlap(tags_a, tags_b, source_a, kind_a, cidrs_a,
                       source_b, kind_b, cidrs_b, expected):
    """cidr_overlap is hygiene, not exposure: always 10 or 30, always low band."""
    severity = score_overlap(
        dest_tags_a=tags_a, dest_tags_b=tags_b,
        source_a=source_a, source_kind_a=kind_a, source_cidrs_a=cidrs_a,
        source_b=source_b, source_kind_b=kind_b, source_cidrs_b=cidrs_b)
    assert severity == expected
    assert band(severity) == "low"


def test_score_shadowed_allow_is_dead_config():
    scored = score_shadowed(
        shadowed_action="allow", source="0.0.0.0/0", source_kind="cidr",
        protocol="tcp", port=3389, dest_tags=["pci"],
        src_zone=ZONE_INTERNET, dst_zone=ZONE_INTERNAL)
    assert scored == {"severity": 10, "vector": {}, "forced_critical": False}
    assert band(scored["severity"]) == "low"


def test_score_shadowed_deny_scores_the_exposure_it_failed_to_block():
    scored = score_shadowed(
        shadowed_action="deny", source="0.0.0.0/0", source_kind="cidr",
        protocol="tcp", port=3389, dest_tags=["pci"],
        src_zone=ZONE_INTERNET, dst_zone=ZONE_INTERNAL)
    assert scored["severity"] == 100
    assert scored["vector"] == {"E": 1.0, "P": 1.0, "D": 0.9, "B": 1.5}


def test_score_shadowed_deny_is_range_aware():
    """The deny you wrote covered tcp/1-65535; the earlier allow lets all of it
    through. Scoring that as its start port is the same defect one type over."""
    scored = score_shadowed(
        shadowed_action="deny", source="0.0.0.0/0", source_kind="cidr",
        protocol="tcp", port=1, port_end=65535, dest_tags=["pci"],
        src_zone=ZONE_INTERNET, dst_zone=ZONE_INTERNAL)
    assert scored["vector"]["P"] == P_ANY_PORT
    assert scored["severity"] == 100


def test_score_transport_exposure_fallback_is_a_fixed_control_gap():
    def fallback(tags):
        return score_transport_exposure(
            subtype="tls_fallback_not_blocked", source="10.0.0.0/8", source_kind="cidr",
            protocol="tcp", port=443, l7_app="tls", dest_tags=tags,
            src_zone=ZONE_INTERNAL, dst_zone=ZONE_INTERNAL)["severity"]

    assert fallback([]) == 40
    assert fallback(["prod"]) == 40
    assert fallback(["pci"]) == 60


def test_score_transport_exposure_blind_spot_is_the_vector_plus_a_bump():
    scored = score_transport_exposure(
        subtype="quic_blind_spot", source="0.0.0.0/0", source_kind="cidr",
        protocol="udp", port=443, l7_app="quic", dest_tags=[],
        src_zone=ZONE_INTERNET, dst_zone=ZONE_INTERNAL)
    assert scored["vector"] == {"E": 1.0, "P": 0.4, "D": 0.4, "B": 1.5}
    assert scored["severity"] == severity_from_vector(1.0, 0.4, 0.4, 1.5) + 15 == 57
    assert scored["forced_critical"] is True


def test_score_transport_exposure_reads_the_resolved_source():
    """A QUIC blind spot entered through a named object that resolves to the
    internet is an internet blind spot."""
    scored = score_transport_exposure(
        subtype="quic_blind_spot", source="ANY-EXTERNAL", source_kind="identity",
        source_cidrs=["0.0.0.0/0"], protocol="udp", port=443, l7_app="quic",
        dest_tags=["pci"], src_zone=ZONE_INTERNET, dst_zone=ZONE_INTERNAL)
    assert scored["vector"]["E"] == 1.0
    assert scored["forced_critical"] is True


PREFIXLEN_CASES = [
    ("10.0.0.0/8", "cidr", None, 8),
    ("10.0.0.5/32", "cidr", None, 32),
    ("0.0.0.0/0", "cidr", None, 0),
    ("any", "cidr", None, 0),
    ("web-tier", "identity", None, None),
    ("garbage", "cidr", None, None),
    ("ANY-EXTERNAL", "identity", ["0.0.0.0/0", "10.0.0.0/8"], 0),
    ("DC-SUBNETS", "identity", ["10.1.0.0/16", "10.2.0.0/24"], 16),
]


@pytest.mark.parametrize("source,kind,cidrs,expected", PREFIXLEN_CASES)
def test_prefixlen_of(source, kind, cidrs, expected):
    """A display signal, but it has to tell the same story as E: printing
    `source_prefixlen: null` beside a finding whose object resolves to
    0.0.0.0/0 is the same lie in a smaller font."""
    assert prefixlen_of(source, kind, cidrs) == expected


# ==========================================================================
# 11 - Whole-model invariants.
# ==========================================================================

def test_severity_is_always_a_percentage():
    """0..100, integral, for every combination of published sub-scores. The
    formula clamps at 1.0 before scaling; nothing downstream should have to."""
    for E, P, D, B, _, _ in VECTOR_CASES:
        severity = severity_from_vector(E, P, D, B)
        assert isinstance(severity, int)
        assert 0 <= severity <= 100


def test_impact_is_capped_by_destination_value():
    """The property the model is designed around: a dev-sandbox finding can
    never out-rank a crown-jewel one at equal exposure, because impact <= D."""
    worst_dev = severity_from_vector(1.0, 1.0, TAG_SENSITIVITY["dev"], 1.5)
    mildest_jewel = severity_from_vector(0.1, 0.4, TAG_SENSITIVITY["crown-jewel"], 1.0)
    assert worst_dev < mildest_jewel


def test_boundary_multiplier_only_ever_raises_the_score():
    for B in (1.0, 1.25, 1.5):
        assert severity_from_vector(0.5, 0.9, 0.6, B) >= severity_from_vector(0.5, 0.9, 0.6, 1.0)


def test_scoring_is_deterministic_across_repeated_calls():
    """The product's determinism claim, at the level of this module: same inputs,
    byte-identical outputs, no dependence on the order of a resolved list."""
    kwargs = dict(source="G", source_kind="identity", protocol="tcp", port=80,
                  ports=[(80, 80), (3389, 3389)], dest_tags=["prod", "pci"],
                  src_zone=ZONE_INTERNET, dst_zone=ZONE_INTERNAL)
    first = score_over_permissive(source_cidrs=["0.0.0.0/0", "10.0.0.0/8"], **kwargs)
    for _ in range(5):
        assert score_over_permissive(source_cidrs=["0.0.0.0/0", "10.0.0.0/8"], **kwargs) == first
    assert score_over_permissive(source_cidrs=["10.0.0.0/8", "0.0.0.0/0"], **kwargs) == first
