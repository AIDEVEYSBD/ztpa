"""Pin the five analyzers' Phase 1 corrections, the snapshot content hash, and
per-analyzer isolation.

Everything the audit filed against `analyzers/` failed in the same direction:
the engine reasoned about how a rule was SPELLED (a label, a first port, a
destination name) instead of what it grants, and the failures were invisible
because nothing asserted on any analyzer's output -- the pre-existing suite
exercised the agent loop and never once checked a finding. So each test here
names the defect it pins, and several assert the *pre-fix* behaviour explicitly
(the stdlib TypeError, a comparison that must stay False) so a future
"simplification" cannot quietly undo the guard.

No database, no model, no clock, no randomness: every fixture is built in
memory, and `run()` is exercised against a monkeypatched `normalize_all` so the
demo export can never make one of these tests pass for the wrong reason.
"""

from __future__ import annotations

import dataclasses

import pytest

from src.analyzers import cidr_overlap, over_permissive, run_all, shadowing, transport_exposure
from src.analyzers.severity import score_over_permissive
from src.graph.build import build_graph
from src.identity import resolve_identities
from src.models import Asset, PolicyRecord
from src.netaddr import parse_net
from src.normalizers import algosec
from src.normalizers.common import NormalizeResult, ObservedEntity, is_cidr, parse_service


# --- fixtures ---------------------------------------------------------------

def make_rec(ref: str, source: str, destination: str, service: str = "tcp/443",
             **kw) -> PolicyRecord:
    """A canonical record built exactly the way a normalizer builds one.

    The service goes through the real `parse_service`, so a test can write
    "tcp/1-65535" or "tcp/80,443" and get the same port/port_end/label/l7 fields
    the engine would see from an export.
    """
    svc = parse_service(service)
    return PolicyRecord(
        id=ref, source_tool=kw.pop("tool", "algosec"), raw_ref=ref,
        source=source, source_kind=kw.pop("source_kind", "cidr" if is_cidr(source) else "identity"),
        destination=destination,
        destination_kind=kw.pop("destination_kind", "cidr" if is_cidr(destination) else "identity"),
        service=svc.label, port=svc.port, port_end=svc.port_end, protocol=svc.protocol,
        l7_app=svc.l7_app, l7_source=svc.l7_source,
        action=kw.pop("action", "allow"), order=kw.pop("order", None), **kw,
    )


def graph_for(records: list[PolicyRecord], assets: list[Asset] | None = None):
    return build_graph(records, assets or [], {})


def normalize_stub(*, tags=("prod",), cidr="10.30.0.0/16", abstract=True,
                   identifiers=None, records=None) -> NormalizeResult:
    """A one-object, two-rule stand-in for `normalize_all`.

    The four knobs are exactly the four inputs the audit proved could change the
    engine's verdict without changing the snapshot id: an asset TAG (it drives
    the D sub-score and all three guardrail floors), an object's CIDR (it drives
    the identity merge and therefore the graph), an object's TYPE (abstract vs
    concrete decides whether a node may be a path pivot) and the identifiers
    that scope a merge.
    """
    recs = list(records) if records is not None else [
        make_rec("R1", "10.0.0.0/8", "app-segment", "tcp/443",
                 source_cidrs=["10.0.0.0/8"], dest_cidrs=[cidr], dest_tags=list(tags)),
        make_rec("R2", "10.20.5.0/24", "app-segment", "tcp/443",
                 source_cidrs=["10.20.5.0/24"], dest_cidrs=[cidr], dest_tags=list(tags)),
    ]
    return NormalizeResult(
        records=recs,
        entities=[ObservedEntity(name="app-segment", kind="identity", tool="algosec",
                                 cidr=cidr, tags=list(tags), abstract=abstract,
                                 identifiers=dict(identifiers or {}))],
        resolved=[],
    )


def run_with(monkeypatch: pytest.MonkeyPatch, **kw):
    """`run()` over `normalize_stub`, so nothing here depends on the demo export."""
    stub_kw = {k: kw.pop(k) for k in ("tags", "cidr", "abstract", "identifiers", "records")
               if k in kw}
    monkeypatch.setattr(run_all, "normalize_all", lambda: normalize_stub(**stub_kw))
    return run_all.run(label="test", **kw)


# --- 1. the IPv6 crash (audit: "a 500 on every route, permanently") ----------

def test_stdlib_subnet_of_still_raises_across_families():
    """The behaviour the guard exists for. If CPython ever returns False here,
    the guards are merely redundant -- but until then, removing one is an outage."""
    v4, v6 = parse_net("10.0.0.0/8"), parse_net("2001:db8::/32")
    with pytest.raises(TypeError):
        v4.subnet_of(v6)


def test_cidr_overlap_guards_on_address_family():
    v4, v6 = parse_net("10.0.0.0/8"), parse_net("2001:db8::/32")
    assert cidr_overlap.covers([v4], [v6]) is False
    assert cidr_overlap._relation([v4], [v6]) is None
    recs = [make_rec("R1", "10.0.0.0/8", "db", source_cidrs=["10.0.0.0/8"]),
            make_rec("R2", "2001:db8::/32", "db", source_cidrs=["2001:db8::/32"])]
    assert cidr_overlap.analyze(recs) == []


def test_shadowing_guards_on_address_family():
    recs = [make_rec("R1", "::/0", "db", order=1, source_cidrs=["::/0"]),
            make_rec("R2", "10.0.0.0/8", "db", order=2, source_cidrs=["10.0.0.0/8"])]
    assert shadowing.analyze(recs, graph_for(recs), {}) == []


def test_mixed_ipv4_ipv6_record_set_completes_run(monkeypatch: pytest.MonkeyPatch):
    """Phase 1 exit criterion: a mixed record set completes run() without raising.

    Both families, both actions, an ordered rulebase and an overlapping pair --
    i.e. every code path that does subnet math -- in one snapshot.
    """
    recs = [
        make_rec("R1", "0.0.0.0/0", "db", "tcp/443", order=1, source_cidrs=["0.0.0.0/0"],
                 dest_cidrs=["10.50.0.10/32"]),
        make_rec("R2", "::/0", "db", "tcp/443", order=2, source_cidrs=["::/0"],
                 dest_cidrs=["10.50.0.10/32"]),
        make_rec("R3", "2001:db8::/32", "db", "tcp/443", order=3,
                 source_cidrs=["2001:db8::/32"], dest_cidrs=["10.50.0.10/32"]),
        make_rec("R4", "2001:db8:1::/48", "db", "tcp/443", order=4, action="deny",
                 source_cidrs=["2001:db8:1::/48"], dest_cidrs=["10.50.0.10/32"]),
    ]
    result = run_with(monkeypatch, records=recs)
    assert result.degraded_analyzers == []
    # Surviving the mixed set is not enough -- the v6 arithmetic must still
    # happen. ::/0 contains both v6 rules, so the two allows are redundant and
    # the later v6 deny is dead, while neither is comparable to the v4 rule.
    overlaps = [f for f in result.findings if f.type == "cidr_overlap"]
    assert [tuple(f.raw_refs) for f in overlaps] == [("R2", "R3")]
    shadowed = [f for f in result.findings if f.type == "shadowed_rule"]
    assert sorted(f.signals["shadowed_ref"] for f in shadowed) == ["R3", "R4"]


# --- 2. the resolved address space reaches the analyzers --------------------

def test_named_source_object_is_visible_to_cidr_overlap():
    """Gap theme 1: `if rec.source_kind != "cidr": continue` hid every rule whose
    source is an object -- i.e. most rules in a real export."""
    a = make_rec("R1", "DC-SUBNETS", "app-segment", source_cidrs=["10.0.0.0/8"])
    b = make_rec("R2", "10.20.5.0/24", "app-segment", source_cidrs=["10.20.5.0/24"])
    findings = cidr_overlap.analyze([a, b])
    assert len(findings) == 1
    signals = findings[0].signals
    assert signals["relation"] == "contains"
    assert signals["outer"] == "DC-SUBNETS"          # the label the operator sees
    assert signals["source_cidrs_a"] == ["10.0.0.0/8"]   # the space it dereferenced to


def test_an_unresolvable_named_source_is_still_skipped():
    """Empty means genuinely unresolvable, and nothing may be inferred from it:
    two rules sourced from two user groups are not redundant."""
    a = make_rec("R1", "sales-users", "app-segment")
    b = make_rec("R2", "10.20.5.0/24", "app-segment", source_cidrs=["10.20.5.0/24"])
    assert cidr_overlap.analyze([a, b]) == []


def test_overlap_groups_a_named_destination_with_its_own_cidr():
    """Two rules to one network written two ways are rules to the same place."""
    a = make_rec("R1", "10.0.0.0/8", "app-segment",
                 source_cidrs=["10.0.0.0/8"], dest_cidrs=["10.30.0.0/16"])
    b = make_rec("R2", "10.20.5.0/24", "10.30.0.0/16",
                 source_cidrs=["10.20.5.0/24"], dest_cidrs=["10.30.0.0/16"])
    findings = cidr_overlap.analyze([a, b])
    assert len(findings) == 1
    assert findings[0].signals["dest"] == "10.30.0.0/16"   # min() of the two labels


def test_address_group_containment_needs_every_member_covered():
    """A group is covered only when ALL of it is: partial cover is "overlaps"."""
    broad = make_rec("R1", "GROUP-A", "db", source_cidrs=["10.0.0.0/8"])
    partial = make_rec("R2", "GROUP-B", "db", source_cidrs=["10.1.0.0/16", "192.168.0.0/16"])
    findings = cidr_overlap.analyze([broad, partial])
    assert [f.signals["relation"] for f in findings] == ["overlaps"]


# --- 3. shadowing: the containment the resolved fields unlock ---------------

def test_broad_rule_at_the_top_shadows_the_host_rule_below_it():
    """The canonical production shadow the audit says was undetectable: the
    earlier rule's DESTINATION is a network containing the later rule's host."""
    earlier = make_rec("R1", "0.0.0.0/0", "10.0.0.0/8", "any", order=1,
                       source_cidrs=["0.0.0.0/0"], dest_cidrs=["10.0.0.0/8"])
    later = make_rec("R2", "10.20.5.0/24", "db-prod-01", "tcp/3389", order=2,
                     source_cidrs=["10.20.5.0/24"], dest_cidrs=["10.50.0.10/32"])
    findings = shadowing.analyze([earlier, later], graph_for([earlier, later]), {})
    assert len(findings) == 1
    assert findings[0].signals["shadowed_ref"] == "R2"
    assert findings[0].signals["shadowing_ref"] == "R1"


def test_a_service_range_covers_a_later_single_port():
    earlier = make_rec("R1", "10.0.0.0/8", "db", "tcp/1-65535", order=1,
                       source_cidrs=["10.0.0.0/8"], dest_cidrs=["10.50.0.10/32"])
    later = make_rec("R2", "10.0.0.0/8", "db", "tcp/443", order=2,
                     source_cidrs=["10.0.0.0/8"], dest_cidrs=["10.50.0.10/32"])
    findings = shadowing.analyze([earlier, later], graph_for([earlier, later]), {})
    assert [f.signals["shadowed_ref"] for f in findings] == ["R2"]


def test_a_comma_list_covers_one_of_its_ports():
    earlier = make_rec("R1", "10.0.0.0/8", "db", "tcp/80,443", order=1,
                       source_cidrs=["10.0.0.0/8"], dest_cidrs=["10.50.0.10/32"])
    later = make_rec("R2", "10.0.0.0/8", "db", "tcp/443", order=2,
                     source_cidrs=["10.0.0.0/8"], dest_cidrs=["10.50.0.10/32"])
    findings = shadowing.analyze([earlier, later], graph_for([earlier, later]), {})
    assert [f.signals["shadowed_ref"] for f in findings] == ["R2"]


def test_coverage_is_directional_not_an_overlap():
    """A narrow earlier rule does not shadow a wider later one -- it only covers
    part of it. The old test asked whether the services *overlapped*, which
    reported a live rule as dead."""
    earlier = make_rec("R1", "10.0.0.0/8", "db", "tcp/443", order=1,
                       source_cidrs=["10.0.0.0/8"], dest_cidrs=["10.50.0.10/32"])
    later = make_rec("R2", "10.0.0.0/8", "db", "tcp/1-65535", order=2,
                     source_cidrs=["10.0.0.0/8"], dest_cidrs=["10.50.0.10/32"])
    assert shadowing.analyze([earlier, later], graph_for([earlier, later]), {}) == []


def test_a_destination_outside_the_earlier_rule_is_not_shadowed():
    earlier = make_rec("R1", "0.0.0.0/0", "10.0.0.0/8", "any", order=1,
                       source_cidrs=["0.0.0.0/0"], dest_cidrs=["10.0.0.0/8"])
    later = make_rec("R2", "0.0.0.0/0", "other", "tcp/443", order=2,
                     source_cidrs=["0.0.0.0/0"], dest_cidrs=["192.168.4.4/32"])
    assert shadowing.analyze([earlier, later], graph_for([earlier, later]), {}) == []


def test_identical_identity_sources_still_shadow():
    """The pre-Phase-1 fallback must survive: two rules from one label, neither
    of which resolves to any address space at all."""
    earlier = make_rec("R1", "web-tier", "app-tier", "tcp/443", order=1)
    later = make_rec("R2", "web-tier", "app-tier", "tcp/443", order=2)
    findings = shadowing.analyze([earlier, later], graph_for([earlier, later]), {})
    assert [f.signals["shadowed_ref"] for f in findings] == ["R2"]


# --- 4. port ranges reach the score and the guardrail ----------------------

def test_full_range_from_the_internet_is_forced_critical():
    """Phase 1 exit criterion. `0.0.0.0/0 -> host tcp/1-65535` produced ZERO
    findings: P was read from port 1 ("unknown/ephemeral")."""
    rec = make_rec("R1", "0.0.0.0/0", "db-prod-01", "tcp/1-65535",
                   source_cidrs=["0.0.0.0/0"], dest_cidrs=["10.50.0.10/32"],
                   dest_tags=["pci"])
    findings = over_permissive.analyze([rec], graph_for([rec]), {})
    assert len(findings) == 1
    assert findings[0].forced_critical
    assert findings[0].severity_band == "critical"
    assert "admin/lateral-movement port exposed to the internet" in \
        findings[0].signals["forced_reasons"]


def test_a_range_is_not_named_after_its_first_port():
    """Titling tcp/22-2000 "SSH" is the same defect in prose."""
    rec = make_rec("R1", "0.0.0.0/0", "db-prod-01", "tcp/22-2000",
                   source_cidrs=["0.0.0.0/0"], dest_cidrs=["10.50.0.10/32"])
    findings = over_permissive.analyze([rec], graph_for([rec]), {})
    assert findings[0].signals["port_name"] is None
    assert "tcp/22-2000" in findings[0].title


# --- 4a. the guardrail floor has to reach the ANALYZER, not just the scorer -
#
# Every guardrail test in `test_severity.py` calls `score_over_permissive`
# DIRECTLY, and all of them passed for the whole of the release in which
# `over_permissive.analyze` -- the only caller that reports on an ingested
# rulebase -- threw the forced findings away before it ever scored them
# (PROD-READINESS-AUDIT-2 B2). `_reasons` ran first, the loop `continue`d when it
# was empty, and its internet test was `E >= 1.0`, which is true only for a /0.
# So the floor fired, said "categorically unacceptable", and nothing was emitted.
#
# These drive `analyze`. One minimal input per PUBLISHED clause, each built so
# the other two clauses cannot fire, so deleting a clause fails exactly one row
# and the row names what was lost. Every source is public address space NARROWER
# than a /0 -- which is the entire gap the defect lived in.

GUARDRAIL_CLAUSE_CASES = [
    # id, source, service, dest tags, the forced reason it alone must produce
    #
    # Clause 1 is included even though it survived the defect (its `_reasons`
    # arm is the any/any one, which never looked at E): the row set is the
    # published clause LIST, not the subset that happened to break, or the next
    # regression in an untested clause is invisible again.
    ("clause-1-internet-any-any", "45.60.70.0/24", "any", [],
     "internet any/any"),
    ("clause-2-admin-port-from-the-internet", "52.20.10.0/24", "tcp/3389", [],
     "admin/lateral-movement port exposed to the internet"),
    ("clause-3-regulated-asset-from-the-internet", "45.60.70.0/29", "tcp/443", ["pci"],
     "regulated/crown-jewel asset reachable from the internet"),
]


@pytest.mark.parametrize("case_id,source,service,dest_tags,forced_reason",
                         GUARDRAIL_CLAUSE_CASES,
                         ids=[c[0] for c in GUARDRAIL_CLAUSE_CASES])
def test_every_guardrail_clause_produces_a_finding_from_the_analyzer(
        case_id, source, service, dest_tags, forced_reason):
    """Exit criterion (A3). Each published clause, through `analyze`.

    The assertions are ordered the way the failure would be diagnosed: the
    finding exists at all; it is critical; it is critical for the RIGHT clause;
    and it says why in prose. The last one matters because a finding that is
    forced critical for an internet reason while its human-readable reasons never
    mention the internet contradicts its own floor -- see M56 in
    `test_mutation_guards.py`.
    """
    rec = make_rec("R1", source, "app-01", service,
                   source_cidrs=[source], dest_cidrs=["10.90.4.4/32"],
                   dest_tags=list(dest_tags))
    findings = over_permissive.analyze([rec], graph_for([rec]), {})

    assert len(findings) == 1, (
        f"{case_id}: the guardrail floor forces this critical and the analyzer "
        f"emitted {len(findings)} findings. A floor that no analyzer reports is "
        "not a floor.")
    finding = findings[0]
    assert finding.forced_critical is True, case_id
    assert finding.severity_band == "critical", case_id
    assert forced_reason in finding.signals["forced_reasons"], (
        f"{case_id}: forced for {finding.signals['forced_reasons']!r}, which does not "
        f"include {forced_reason!r} -- this row is no longer isolating its clause.")
    assert finding.signals["reasons"], (
        f"{case_id}: emitted with an empty `reasons` list. `analyze` may report a "
        "forced rule the reasons cannot explain, but the prose and the floor are "
        "two renderings of one fact and should not be able to disagree.")
    # The fixture is positioned INSIDE the gap the old `E >= 1.0` gate created:
    # if any source here ever becomes a /0 the row passes for the wrong reason.
    assert finding.signals["severity_vector"]["E"] < 1.0, (
        f"{case_id}: source {source!r} scores E=1.0, so this row no longer "
        "exercises the sub-/0 public space where the defect lived.")


def test_a_partner_public_slash_24_with_rdp_to_a_prod_host_is_critical():
    """Exit criterion (A3), the audit's named failure scenario, end to end.

        allow 52.20.10.0/24 -> app-01 tcp/3389

    A partner/vendor public /24 with RDP to a prod host -- the single most common
    real over-permissive shape -- produced ZERO findings from all five analyzers.
    E = 0.3, so the reason gate's `E >= 1.0` dropped it; the floor had already
    scored it 52 and forced it critical, and nothing downstream ever saw that.

    Built from raw export JSON through `algosec.normalize` (see `_score_end_to_end`),
    because the audit's second reproduction was through the real ingest path and a
    hand-built record could hide a normalizer that never produces this shape.
    """
    finding, node = _score_end_to_end("52.20.10.0/24", {}, "tcp/3389", ["prod"])

    assert finding.forced_critical is True
    assert finding.severity_band == "critical"
    assert finding.severity == 52          # the floor raises the BAND, not the number
    assert finding.signals["severity_vector"] == {"E": 0.3, "P": 1.0, "D": 0.6, "B": 1.5}
    assert finding.signals["forced_reasons"] == [
        "admin/lateral-movement port exposed to the internet"]
    assert node["zone"] == "internet"
    # The display label stays NARROW on purpose. `_is_wildcard_source` was not
    # unified with `is_internet_source`: "open from the internet" above a grant
    # from one partner's /24 would be a false sentence in the most-read line of
    # the finding. The source is named; the internet claim lives in the reasons.
    assert finding.title == "RDP open from 52.20.10.0/24 to db-prod-01"
    assert "the internet" not in finding.title
    assert "exposed directly to the internet" in finding.signals["reasons"]


def test_an_ordinary_internal_rule_is_still_not_a_finding():
    """The other half of A3, and the reason `_reasons` still exists.

    Inverting the control flow must not turn the analyzer into "report every
    allow": a floor that fires on everything protects nothing, and a console that
    lists every internal grant is one nobody reads. An internal /24 to one app
    port trips no clause and no reason, and is still silently clean.
    """
    rec = make_rec("R1", "10.20.5.0/24", "app-01", "tcp/443",
                   source_cidrs=["10.20.5.0/24"], dest_cidrs=["10.90.4.4/32"],
                   dest_tags=["prod"])
    assert over_permissive.analyze([rec], graph_for([rec]), {}) == []


def test_the_analyzer_reports_exactly_what_the_scorer_scored():
    """`_reasons` reads the scorer's own E and P rather than recomputing them.

    Two functions computing one sub-score from one record is how the two
    predicates drifted apart in the first place; this pins that the prose and the
    published vector are derived from a single evaluation.
    """
    rec = make_rec("R1", "0.0.0.0/0", "app-01", "tcp/3389",
                   source_cidrs=["0.0.0.0/0"], dest_cidrs=["10.90.4.4/32"],
                   dest_tags=["pci"])
    finding = over_permissive.analyze([rec], graph_for([rec]), {})[0]
    vector = finding.signals["severity_vector"]
    scored = score_over_permissive(
        source=rec.source, source_kind=rec.source_kind, protocol=rec.protocol,
        port=rec.port, dest_tags=rec.dest_tags,
        src_zone=finding.signals["src_zone"], dst_zone=finding.signals["dst_zone"],
        port_end=rec.port_end, ports=None, source_cidrs=rec.source_cidrs)
    assert (vector, finding.severity) == (scored["vector"], scored["severity"])
    assert vector["E"] == scored["E"] and vector["P"] == scored["P"]


# --- 4b. the four encodings, END TO END, with nothing hand-built ------------
#
# The four spellings of ONE address space, as a real AlgoSec export writes them:
# the token in the rule's `src` column plus the catalog entry (if any) behind it.
#
# This is deliberately expressed as an EXPORT and not as records + assets. The
# previous version of this test hand-built
# `Asset(asset_key=source, kind="abstract", ip_set=["0.0.0.0/0"])` for every
# case, including the address group -- and that ip_set is a value the real
# normalizer + identity pipeline never produced for a multi-member group. It
# produced `[]`, because `ObservedEntity.cidr` holds ONE string and a group
# resolves to several, so `zones.zone_of` classified the group ZONE_INTERNAL and
# the boundary multiplier collapsed 1.5 -> 1.0. The fixture supplied the very
# fact the product was losing, so the test passed while the property was false:
# scored end to end the group came out 90 against 100, and 57/medium against
# 86/critical once the guardrail floor was not masking the gap. Every fixture
# below is therefore raw export JSON, and every Asset, alias and graph node is
# built by the code under test.
FOUR_ENCODINGS = [
    ("literal /0", "0.0.0.0/0", {}),
    ("wildcard word", "any", {}),
    ("named object", "ANY-EXTERNAL", {"ANY-EXTERNAL": {"type": "network", "value": "0.0.0.0/0"}}),
    ("address group", "EXTERNAL-NETS",
     {"EXTERNAL-NETS": {"type": "group", "value": ["0.0.0.0/0", "10.0.0.0/8"]}}),
]

# Two grants, because ONE is not enough to prove the property. `tcp/3389 -> pci`
# both trips a guardrail floor (forcing the band to critical) and saturates
# (`min(raw, 1.0) * 100 == 100`), so four different vectors can all clamp onto
# one answer -- the old assertion could not have failed for the group even with
# B wrong. `tcp/1433 -> prod` fires no floor and lands well short of the clamp,
# so severity and band are free to move, and they did: 86/critical against
# 57/medium, two bands apart on the identical grant.
FOUR_ENCODING_GRANTS = [
    ("rdp-to-pci", "tcp/3389", ["pci"], (100, "critical", True)),
    ("mssql-to-prod", "tcp/1433", ["prod"], (86, "critical", False)),
]


def _four_encodings_export(token: str, objects: dict, service: str, dest_tags: list[str]) -> dict:
    """One AlgoSec export granting `token -> db-prod-01` on `service`."""
    return {
        "device": "afa-edge-fw-01",
        "objects": {**objects,
                    "db-prod-01": {"type": "host", "value": "10.50.0.10", "tags": dest_tags}},
        "rules": [{"rule_id": "R1", "order": 1, "src": token, "dst": "db-prod-01",
                   "service": service, "action": "allow"}],
    }


def _score_end_to_end(token: str, objects: dict, service: str, dest_tags: list[str]):
    """normalize -> resolve_identities -> build_graph -> analyze. No fixtures."""
    res = algosec.normalize(_four_encodings_export(token, objects, service, dest_tags))
    ident = resolve_identities(res.entities)
    graph = build_graph(res.records, ident.assets, ident.alias_map)
    findings = over_permissive.analyze(res.records, graph, ident.alias_map)
    assert len(findings) == 1, (token, service)
    return findings[0], graph.nodes[ident.alias_map.get(token, token)]


@pytest.mark.parametrize("grant,service,dest_tags,expected", FOUR_ENCODING_GRANTS,
                         ids=[g[0] for g in FOUR_ENCODING_GRANTS])
@pytest.mark.parametrize("name,token,objects", FOUR_ENCODINGS,
                         ids=[e[0] for e in FOUR_ENCODINGS])
def test_the_four_encodings_of_one_policy_score_identically(
        name, token, objects, grant, service, dest_tags, expected):
    """Phase 1 exit criterion, through the whole engine and with no hand-built
    assets: one policy, four spellings, one severity / band / forced_critical.

    The literal /0 is the baseline every other spelling is measured against --
    it is the one encoding the pre-Phase-1 engine scored correctly.
    """
    baseline, _base_node = _score_end_to_end("0.0.0.0/0", {}, service, dest_tags)
    finding, node = _score_end_to_end(token, objects, service, dest_tags)

    got = (finding.severity, finding.severity_band, finding.forced_critical)
    assert got == (baseline.severity, baseline.severity_band, baseline.forced_critical), name
    assert got == expected, name
    # The mechanism, not just the total: B is the term that diverged, and it
    # diverged because the group's node carried no address space at all.
    assert finding.signals["src_zone"] == "internet", name
    assert finding.signals["severity_vector"]["B"] == 1.5, name
    assert node["ip_set"], name           # [] is what made the group internal
    assert finding.signals["forced_reasons"] == baseline.signals["forced_reasons"], name


@pytest.mark.parametrize("name,token,objects", FOUR_ENCODINGS,
                         ids=[e[0] for e in FOUR_ENCODINGS])
def test_the_four_encodings_agree_on_the_resolved_address_space(name, token, objects):
    """The facts underneath the score, at every layer that holds one.

    Each layer used to hold a DIFFERENT answer for the group: the record knew
    the space, the asset had none, and the node was therefore internal. If they
    ever disagree again, the severity will follow -- so they are asserted here
    together rather than one per test file.
    """
    res = algosec.normalize(_four_encodings_export(token, objects, "tcp/1433", ["prod"]))
    ident = resolve_identities(res.entities)
    graph = build_graph(res.records, ident.assets, ident.alias_map)
    asset = next(a for a in ident.assets if a.asset_key == ident.alias_map.get(token, token))
    node = graph.nodes[asset.asset_key]

    assert "0.0.0.0/0" in res.records[0].source_cidrs, name       # the record
    assert "0.0.0.0/0" in asset.ip_set, name                      # the asset
    assert "0.0.0.0/0" in node["ip_set"], name                    # the graph node
    assert node["zone"] == "internet", name


def test_the_non_saturating_four_encodings_case_can_actually_move():
    """Guard on the guard: if `mssql-to-prod` ever starts clamping at 100 or
    force-marking critical, the parametrised test above goes back to being true
    by construction. This fails the day that happens."""
    finding, _node = _score_end_to_end("0.0.0.0/0", {}, "tcp/1433", ["prod"])
    assert finding.forced_critical is False
    assert finding.severity < 100
    assert finding.signals["severity_vector"]["B"] == 1.5


def test_a_multi_block_group_is_not_scored_as_if_it_never_crossed_the_boundary():
    """The defect itself, isolated, so its regression is unambiguous.

    An address group resolving to {0.0.0.0/0, 10.0.0.0/8} reached
    `zones.zone_of` with `Asset.ip_set == []` -- `ObservedEntity.cidr` is a
    single Optional[str] and none of several blocks is THE cidr -- so it was
    classified ZONE_INTERNAL and `boundary_multiplier(internal, internal)`
    returned 1.0 where the literal /0 got `internet->internal` 1.5. The record's
    `source_cidrs` carried the space correctly the whole time, which is why the
    E term was right and only B was wrong.
    """
    finding, node = _score_end_to_end(
        "EXTERNAL-NETS", {"EXTERNAL-NETS": {"type": "group",
                                            "value": ["0.0.0.0/0", "10.0.0.0/8"]}},
        "tcp/1433", ["prod"])
    assert node["ip_set"] == ["0.0.0.0/0", "10.0.0.0/8"]
    assert node["zone"] == "internet"
    vector = finding.signals["severity_vector"]
    assert vector["E"] == 1.0 and vector["B"] == 1.5
    assert finding.signals["boundary_crossed"] is True


@pytest.mark.parametrize("name,token,cidrs", [
    ("literal /0", "0.0.0.0/0", ["0.0.0.0/0"]),
    ("wildcard word", "any", ["0.0.0.0/0"]),
    ("named object", "ANY-EXTERNAL", ["0.0.0.0/0"]),
    ("address group", "EXTERNAL-NETS", ["0.0.0.0/0", "10.0.0.0/8"]),
], ids=["literal /0", "wildcard word", "named object", "address group"])
def test_the_four_encodings_agree_when_the_rule_arrives_as_an_applied_change(
        monkeypatch: pytest.MonkeyPatch, name, token, cidrs):
    """The same property through the OTHER door into the engine.

    A rule the operator accepted at the change gate is re-folded into every
    later run as an overlay, and `change.apply.ensure_entities` -- not a
    normalizer -- builds the entity for an endpoint the snapshot has never seen.
    It used to emit a bare identity with no address space and `abstract` False,
    which is two independent reasons `zones.zone_of` could not classify it: an
    empty ip_set, and the concrete short-circuit that (correctly) refuses to call
    a host the internet. Measured, three of the four spellings diverged here --
    86/critical for the literal /0 against 57/medium for the other three -- so
    accepting a rule at the gate could LOWER its score on the next recompute.
    """
    proposed = make_rec("GATE-1", token, "db-prod-01", "tcp/1433", order=99,
                        source_cidrs=cidrs, dest_cidrs=["10.50.0.10/32"],
                        dest_tags=["prod"])
    result = run_with(monkeypatch,
                      applied_changes=[{"kind": "add_allow", "payload": proposed.model_dump()}])
    finding = next(f for f in result.findings
                   if f.type == "over_permissive" and f.raw_refs == ["GATE-1"])
    assert (finding.severity, finding.severity_band, finding.forced_critical) \
        == (86, "critical", False), name
    assert finding.signals["src_zone"] == "internet", name
    assert finding.signals["severity_vector"]["B"] == 1.5, name
    node = result.graph.nodes[result.alias_map.get(token, token)]
    assert node["kind"] == "abstract", name       # a range is not a machine
    assert node["ip_set"], name


def test_an_overlay_endpoint_that_resolves_to_nothing_stays_a_concrete_identity(
        monkeypatch: pytest.MonkeyPatch):
    """The counterpart, so the rule above is a classification and not a blanket
    escalation: "we could not resolve this token" is not evidence of a range, and
    a node with no address space must stay concrete -- otherwise every
    unresolvable overlay label would become un-pivotable and quietly delete
    reachability."""
    proposed = make_rec("GATE-2", "ops-team", "db-prod-01", "tcp/1433", order=99,
                        source_cidrs=[], dest_cidrs=["10.50.0.10/32"], dest_tags=["prod"])
    result = run_with(monkeypatch,
                      applied_changes=[{"kind": "add_allow", "payload": proposed.model_dump()}])
    node = result.graph.nodes["ops-team"]
    assert node["kind"] == "concrete"
    assert node["ip_set"] == []
    assert node["zone"] == "internal"


def test_fallback_pair_matches_a_port_range():
    """transport_exposure compared `(protocol, port)` for equality, so a rule
    written tcp/400-500 opened 443 without ever matching the pair."""
    tcp = make_rec("R1", "10.0.0.0/8", "host-a", "tcp/400-500", source_cidrs=["10.0.0.0/8"])
    udp = make_rec("R2", "10.0.0.0/8", "host-a", "udp/443", source_cidrs=["10.0.0.0/8"])
    findings = transport_exposure.analyze([tcp, udp], graph_for([tcp, udp]), {})
    fallback = [f for f in findings if f.signals["subtype"] == "tls_fallback_not_blocked"]
    assert len(fallback) == 1
    assert fallback[0].signals["tcp_refs"] == ["R1"]


def test_fallback_pair_ignores_a_range_that_misses_the_port():
    tcp = make_rec("R1", "10.0.0.0/8", "host-a", "tcp/400-442", source_cidrs=["10.0.0.0/8"])
    udp = make_rec("R2", "10.0.0.0/8", "host-a", "udp/443", source_cidrs=["10.0.0.0/8"])
    findings = transport_exposure.analyze([tcp, udp], graph_for([tcp, udp]), {})
    assert [f for f in findings if f.signals["subtype"] == "tls_fallback_not_blocked"] == []


def test_an_any_service_rule_opens_both_halves_of_the_fallback_pair():
    """Quick win 3. The widest grant expressible was excluded from the check.

    `transport_exposure` filtered its input to `r.port is not None` -- and an
    `any` service is protocol "any" with NO port -- so a rule granting every
    protocol and every port was the one rule the fallback-pair check could not
    see, while `_opens`'s own docstring said "a rule whose protocol is `any`
    opens the port on every transport". One such rule ships in
    `data/mock/algosec_export.json` (ALGO-001), so the analyzer was skipping the
    worst rule in the product's own demo.

    One record is enough here: it opens BOTH halves by itself, which is exactly
    what makes it worse than the two-rule case the check was written for.
    """
    any_rule = make_rec("R1", "0.0.0.0/0", "host-a", "any", source_cidrs=["0.0.0.0/0"])
    assert (any_rule.protocol, any_rule.port) == ("any", None)     # the excluded shape
    findings = transport_exposure.analyze([any_rule], graph_for([any_rule]), {})
    fallback = [f for f in findings if f.signals["subtype"] == "tls_fallback_not_blocked"]
    assert len(fallback) == 1
    assert fallback[0].signals["tcp_refs"] == ["R1"]
    assert fallback[0].signals["udp_refs"] == ["R1"]


def test_a_port_that_failed_to_decode_is_not_treated_as_every_port():
    """The mirror-image error, pinned so the fix above cannot overshoot.

    Dropping the `port is not None` filter must not mean "a rule with no port
    opens everything". A `tcp` rule whose service did not decode is PORT UNKNOWN
    -- mid-risk, scored P_UNKNOWN -- and inventing a tcp/443 grant nobody wrote
    is the same class of error as hiding one, pointed the other way. Only a rule
    that also names no PROTOCOL is a grant of every port.
    """
    undecoded = make_rec("R1", "10.0.0.0/8", "host-a", "tcp/not-a-port",
                         source_cidrs=["10.0.0.0/8"])
    udp = make_rec("R2", "10.0.0.0/8", "host-a", "udp/443", source_cidrs=["10.0.0.0/8"])
    assert (undecoded.protocol, undecoded.port) == ("tcp", None)
    findings = transport_exposure.analyze([undecoded, udp], graph_for([undecoded, udp]), {})
    assert [f for f in findings if f.signals["subtype"] == "tls_fallback_not_blocked"] == []


# --- 5. the snapshot id is a content hash ----------------------------------

def test_identical_input_produces_an_identical_snapshot_id(monkeypatch: pytest.MonkeyPatch):
    """The other half of the property: a fingerprint that changes on everything
    is as useless as one that changes on nothing."""
    first, second = run_with(monkeypatch), run_with(monkeypatch)
    assert first.snapshot_id == second.snapshot_id
    assert [(f.id, f.severity, f.severity_band) for f in first.findings] == \
        [(f.id, f.severity, f.severity_band) for f in second.findings]


def test_changing_an_asset_tag_changes_the_snapshot_id(monkeypatch: pytest.MonkeyPatch):
    """Exit criterion. Retagging an asset `pci` flips the verdict from nothing to
    forced-critical; the old id said it was the same snapshot."""
    assert run_with(monkeypatch, tags=("prod",)).snapshot_id != \
        run_with(monkeypatch, tags=("prod", "pci")).snapshot_id


def test_changing_an_object_cidr_changes_the_snapshot_id(monkeypatch: pytest.MonkeyPatch):
    """Exit criterion. The object's CIDR drives the identity merge and therefore
    the graph shape."""
    assert run_with(monkeypatch, cidr="10.30.0.0/16").snapshot_id != \
        run_with(monkeypatch, cidr="10.31.0.0/16").snapshot_id


def test_changing_an_object_type_changes_the_snapshot_id(monkeypatch: pytest.MonkeyPatch):
    """Exit criterion. abstract vs concrete decides whether the node may be a
    path pivot, which decides whether the cross-tool path exists."""
    assert run_with(monkeypatch, abstract=True).snapshot_id != \
        run_with(monkeypatch, abstract=False).snapshot_id


def test_changing_the_manual_merges_changes_the_snapshot_id(monkeypatch: pytest.MonkeyPatch):
    """Exit criterion. `manual_merges` never reached the fingerprint at all, yet
    it changes the assets, the alias map, the graph and the findings."""
    assert run_with(monkeypatch).snapshot_id != \
        run_with(monkeypatch, manual_merges=[("app-segment", "app-tier")]).snapshot_id


def test_reordering_the_manual_merges_does_not_change_the_snapshot_id(
        monkeypatch: pytest.MonkeyPatch):
    """The merge is symmetric (union-find roots at min(name)), so the two spellings
    produce byte-identical assets -- and a content hash must say so."""
    assert run_with(monkeypatch, manual_merges=[("app-segment", "app-tier")]).snapshot_id == \
        run_with(monkeypatch, manual_merges=[("app-tier", "app-segment")]).snapshot_id


def test_an_overlay_that_changes_no_record_still_changes_the_snapshot_id(
        monkeypatch: pytest.MonkeyPatch):
    """A remediation whose target rule is absent is a no-op on the records, but
    it is a different APPLIED state -- and governance rows hang off the id."""
    overlay = [{"kind": "remediation", "payload": {"op": "remove", "target_ref": "NOPE"}}]
    plain = run_with(monkeypatch)
    with_overlay = run_with(monkeypatch, applied_changes=overlay)
    assert [r.raw_ref for r in plain.records] == [r.raw_ref for r in with_overlay.records]
    assert plain.snapshot_id != with_overlay.snapshot_id


@pytest.mark.parametrize("field_name,value", [
    ("dest_tags", ["pci"]),
    ("port", 8443),
    ("port_end", 8443),
    ("protocol", "udp"),
    ("l7_app", "quic"),
    ("source_cidrs", ["10.0.0.0/9"]),
    ("dest_cidrs", ["10.30.0.0/17"]),
    ("note", "changed comment"),
])
def test_every_omitted_record_field_now_moves_the_snapshot_id(
        monkeypatch: pytest.MonkeyPatch, field_name, value):
    """The audit's list of fields `_fingerprint` ignored, one test per field."""
    base = normalize_stub().records
    mutated = [base[0].model_copy(update={field_name: value}), base[1]]
    before = run_with(monkeypatch, records=base).snapshot_id
    after = run_with(monkeypatch, records=mutated).snapshot_id
    assert before != after


def test_the_snapshot_id_ignores_the_order_records_arrive_in(
        monkeypatch: pytest.MonkeyPatch):
    base = normalize_stub().records
    assert run_with(monkeypatch, records=base).snapshot_id == \
        run_with(monkeypatch, records=list(reversed(base))).snapshot_id


def test_fingerprint_covers_every_record_field():
    """If a later phase widens `PolicyRecord` (multi-valued src/dst, `enabled`,
    device, direction), this fails until the field is a deliberate part of the
    snapshot id -- which is how the id stops silently narrowing again."""
    assert set(run_all._RECORD_FIELDS) == set(PolicyRecord.model_fields)


def test_fingerprint_covers_every_entity_field():
    """Same guard for the object/entity view -- notably the `context` field the
    identity layer needs, which must reach the id the day it lands."""
    assert set(run_all._ENTITY_FIELDS) == \
        {f.name for f in dataclasses.fields(ObservedEntity)}


# --- 6. per-analyzer isolation ---------------------------------------------

def _boom(*_args, **_kwargs):
    raise ValueError("malformed rule")


def test_a_failing_analyzer_leaves_the_other_four_intact(monkeypatch: pytest.MonkeyPatch):
    """One bad rule in 40,000 used to abort the snapshot -- and, because the API
    caches the engine singleton, every subsequent request with it."""
    healthy = run_with(monkeypatch)
    assert [f.type for f in healthy.findings if f.type == "cidr_overlap"]

    monkeypatch.setattr(cidr_overlap, "analyze", _boom)
    degraded = run_with(monkeypatch)

    assert [d["analyzer"] for d in degraded.degraded_analyzers] == ["cidr_overlap"]
    assert degraded.degraded_analyzers[0]["error"] == "ValueError"
    assert "malformed rule" in degraded.degraded_analyzers[0]["message"]
    # Every other analyzer's findings survive, unchanged.
    assert [f.id for f in degraded.findings] == \
        [f.id for f in healthy.findings if f.type != "cidr_overlap"]


def test_a_healthy_run_records_no_degradation(monkeypatch: pytest.MonkeyPatch):
    """Empty is the only clean state -- the marker has to mean something."""
    assert run_with(monkeypatch).degraded_analyzers == []


def test_reanalyze_never_swallows_an_analyzer_failure(monkeypatch: pytest.MonkeyPatch):
    """`reanalyze` proves a proposed fix introduces no critical. Returning fewer
    findings because an analyzer died would answer "safe" for the wrong reason,
    so that path fails closed instead."""
    monkeypatch.setattr(cidr_overlap, "analyze", _boom)
    records = normalize_stub().records
    with pytest.raises(ValueError):
        run_all.reanalyze(records, [], {})
