"""The normalizers, against the input a real customer export actually contains.

Two failure classes are pinned here, and they fail in opposite directions.

**Loud.** The audit fed eleven malformed shapes through `run()` and measured
four of them killing the entire snapshot with an exception raised from inside a
normalizer and naming neither the tool nor the row: `KeyError: 'action'`,
`KeyError: 'src'`, `TypeError: argument of type 'NoneType' is not iterable`, and
`TypeError: string indices must be integers`. One malformed row out of 40,000
took down the whole run, and the API returned a 500 carrying the raw traceback.
Per-row skipping with an "N ingested, M skipped" report is Phase 3; what this
phase owes is a DIAGNOSABLE failure, so every one of those shapes now raises
`NormalizeError` naming the tool, the rule and the field. The tests below assert
the message, not just the type -- an exception nobody can act on is barely
better than the one it replaced.

**Silent, and far worse.** `999.999.999.999/8` and `10.0.0.0/33` failed
`is_cidr`, fell through to the identity branch, and became invented single-host
assets in the inventory: E=0.1, no tags, absent from `cidr_overlap` and from
shadowing. A typo in what is nearly always a BROAD rule LOWERED the reported
risk and nothing anywhere said so. Same class, different cause: a named object
or the keyword `any` kept only its LABEL on the record, so the identical rule
`allow <src> -> db-prod-01 tcp/3389` scored 100/critical/forced written as
`0.0.0.0/0` and produced NO FINDING AT ALL written as `any`, `ANY-EXTERNAL` or
`INTERNET` -- and real policies are written the second way.

So the equivalence tests here are the load-bearing ones: four spellings of one
grant must resolve to one address space, and a named /16 must be as abstract as
the same /16 written as a raw CIDR, because `reachability._valid_traversal`
decides whether the flagship attack path exists by reading exactly that flag.
"""

from __future__ import annotations

import json

import pytest

from src.identity import context_of, resolve_identities
from src.normalizers import algosec, guardicore, wiz
from src.normalizers.common import SCOPE_KEYS, ObservedEntity, merge_entities, scope_identifiers
from src.normalizers.profile import (
    FieldMap, NormalizeError, SourceProfile, apply_profile, field_report,
)

# --- fixtures: the smallest export shape each normalizer accepts -------------


def _algosec(rules, objects=None, **extra):
    return {"device": "fw-01", "objects": objects or {}, "rules": rules, **extra}


def _rule(**over):
    rule = {"rule_id": "R1", "order": 1, "src": "10.0.0.0/8", "dst": "10.20.0.0/16",
            "service": "tcp/443", "action": "allow"}
    rule.update(over)
    return rule


CATALOG = {
    "db-prod-01": {"type": "host", "value": "10.50.0.10", "tags": ["pci"]},
    "app-segment": {"type": "network", "value": "10.30.0.0/16", "tags": ["prod"]},
    "dc-subnets": {"type": "group", "value": ["10.30.0.0/16", "10.40.0.0/16"]},
    "vendor-range": {"type": "range", "value": "192.0.2.0/24"},
    "branch-subnet": {"type": "subnet", "value": "10.20.5.0/24"},
    "ANY-EXTERNAL": {"type": "network", "value": "0.0.0.0/0"},
    "INTERNET": {"type": "network", "value": "0.0.0.0/0"},
    "typo-net": {"type": "network", "value": "10.0.0.0/33"},
    "ops-team": {"type": "user_group", "value": None},
}


def _one(export):
    """Normalize an AlgoSec export expected to yield exactly one record."""
    res = algosec.normalize(export)
    assert len(res.records) == 1
    return res, res.records[0]


# --- 1. the shapes that used to take the whole snapshot down -----------------
# (label, export, the substrings the message must contain to be actionable)
CRASHING_SHAPES = [
    # The four the audit measured, in its order.
    ("missing action", _algosec([_rule(action=None)]), ("algosec", "R1", "action")),
    ("missing src", _algosec([{"rule_id": "R1", "dst": "10.0.0.0/8",
                               "service": "any", "action": "allow"}]), ("algosec", "R1", "src")),
    ("src is null", _algosec([_rule(src=None)]), ("algosec", "R1", "src")),
    ("rules is a dict", _algosec({"rule_id": "R1"}), ("algosec", "rules", "list")),
    # The rest of the audit's eleven, same class.
    ("src is a list", _algosec([_rule(src=["10.1.0.0/16", "10.2.0.0/16"])]),
     ("algosec", "R1", "src", "multi-valued")),
    ("rule row is a string", _algosec(["ALGO-001"]), ("algosec", "rule #1")),
    ("objects is a list", _algosec([_rule()], objects=["db-prod-01"]),
     ("algosec", "objects", "map")),
    ("missing rule_id", _algosec([{"src": "10.0.0.0/8", "dst": "10.1.0.0/16",
                                   "service": "any", "action": "allow"}]),
     ("algosec", "rule #1", "rule_id")),
    ("empty src", _algosec([_rule(src="   ")]), ("algosec", "R1", "src", "empty")),
    ("unmapped action verb", _algosec([_rule(action="log")]), ("algosec", "R1", "log")),
]


@pytest.mark.parametrize("label,export,expected",
                         CRASHING_SHAPES, ids=[c[0] for c in CRASHING_SHAPES])
def test_a_malformed_export_fails_diagnosably(label, export, expected):
    """It may refuse, but it must say what it refused and why.

    `NormalizeError` is a ValueError subclass, so a caller that already handles
    bad input keeps working; what changes is that the message names the tool,
    the rule and the field instead of being `KeyError: 'action'` from line 59 of
    a module the operator has never heard of.
    """
    with pytest.raises(NormalizeError) as excinfo:
        algosec.normalize(export)
    message = str(excinfo.value)
    for fragment in expected:
        assert fragment in message, f"{label}: {fragment!r} missing from {message!r}"


def test_the_guardicore_and_wiz_shapes_are_diagnosable_too():
    """The same guarantee on the other two coded normalizers.

    `wiz` with `kind='egress'` was `KeyError: 'src'` and `assets: null` was
    `AttributeError: 'NoneType' object has no attribute 'items'`; guardicore
    indexed `pol['src_label']` with no guard at all.
    """
    with pytest.raises(NormalizeError, match="guardicore.*GC-1.*src_label"):
        guardicore.normalize({"labels": {}, "policies": [
            {"policy_id": "GC-1", "dst_label": "db", "port": 443,
             "protocol": "tcp", "action": "allow"}]})
    with pytest.raises(NormalizeError, match="wiz.*WIZ-1.*egress"):
        wiz.normalize({"assets": {}, "exposures": [
            {"exposure_id": "WIZ-1", "kind": "egress", "dst": "db"}]})
    # `assets: null` is an EMPTY catalog, not an error: a Wiz export with no
    # asset inventory is a legitimate (if useless) export, and refusing it would
    # be the over-strict mirror of the bug being fixed.
    assert wiz.normalize({"assets": None, "exposures": None}).records == []


def test_a_missing_optional_section_is_an_empty_export_not_a_crash():
    """`{}` normalizes to nothing at all -- the empty case must stay quiet."""
    assert algosec.normalize({}).records == []
    assert guardicore.normalize({}).records == []
    assert wiz.normalize({}).records == []


# --- 2. the garbage CIDR: the silent case, which is the dangerous one --------

@pytest.mark.parametrize("token", ["10.0.0.0/33", "999.999.999.999/8", "300.1.1.1/24"])
def test_a_garbage_cidr_is_recorded_as_malformed_not_reclassified(token):
    """It must not quietly become a single-host asset with E=0.1.

    Three things have to be true at once: the address space is EMPTY (not a
    fabricated /32), the node is abstract so it can never act as an attack-path
    pivot, and the defect is written to the `resolved` audit trail where the
    Ingest Inspector renders it. Empty-and-flagged is honest; a host is a lie.
    """
    res, record = _one(_algosec([_rule(src=token)]))
    assert record.source == token          # the operator still sees what they wrote
    assert record.source_cidrs == []       # ... and the engine claims no address space
    entity = next(e for e in res.entities if e.name == token)
    assert entity.abstract is True
    assert entity.identifiers.get("malformed_address") is True
    audit = [r for r in res.resolved if r.object_name == "rule:R1"]
    assert audit, "the malformed token left no audit row"
    assert audit[0].object_kind == "address"
    assert list(audit[0].resolved["fields"]) == ["src"]
    assert token in audit[0].resolved["fields"]["src"][0]


def test_one_rule_with_two_bad_tokens_writes_exactly_one_audit_row():
    """`resolved_objects` is UNIQUE on (snapshot, device, name, kind).

    Two rows per rule would collide on that key and the upsert would keep one --
    losing the record of a loss. Both defects therefore share one row.
    """
    res, _record = _one(_algosec([_rule(src="10.0.0.0/33", dst="10.0.0.0/99")]))
    audit = [r for r in res.resolved if r.object_name == "rule:R1"
             and r.object_kind == "address"]
    assert len(audit) == 1
    assert list(audit[0].resolved["fields"]) == ["dst", "src"]


def test_audit_row_keys_are_unique_across_the_whole_export():
    """The DB key the rows are upserted on, asserted without a database."""
    res = algosec.normalize(_algosec(
        [_rule(rule_id="R1", src="10.0.0.0/33"), _rule(rule_id="R2", dst="10.0.0.0/33"),
         _rule(rule_id="R3", src="app-segment", service="tcp/70000")], objects=CATALOG))
    keys = [(r.source_tool, r.source_device, r.object_name, r.object_kind)
            for r in res.resolved]
    assert len(keys) == len(set(keys))


def test_a_malformed_object_value_is_flagged_on_the_catalog_row():
    """Same rule one level down: the typo is in the object, not the rule."""
    res, record = _one(_algosec([_rule(src="typo-net")], objects=CATALOG))
    assert record.source_cidrs == []
    row = next(r for r in res.resolved if r.object_name == "typo-net")
    assert row.resolved["warnings"] == ["unresolvable object value '10.0.0.0/33'"]
    assert next(e for e in res.entities if e.name == "typo-net").abstract is True


def test_a_bare_host_ip_joins_subnet_math_instead_of_dangling():
    """`src: 10.50.0.10` is extremely common and resolved to nothing at all.

    It keeps its own spelling as the node key, but the record now carries the
    host network so `cidr_overlap` and `exposure_score` can see it.
    """
    _res, record = _one(_algosec([_rule(src="10.50.0.10")]))
    assert record.source_cidrs == ["10.50.0.10/32"]


# --- 3. carry the resolved value, not the label ------------------------------

def test_a_named_object_resolves_to_its_catalog_cidr():
    _res, record = _one(_algosec([_rule(src="app-segment", dst="db-prod-01")], objects=CATALOG))
    assert record.source == "app-segment"          # label preserved for the console
    assert record.source_cidrs == ["10.30.0.0/16"]  # address space carried for the math
    assert record.dest_cidrs == ["10.50.0.10/32"]
    assert record.dest_tags == ["pci"]


def test_an_address_group_resolves_to_every_block_it_names():
    _res, record = _one(_algosec([_rule(src="dc-subnets")], objects=CATALOG))
    assert record.source_cidrs == ["10.30.0.0/16", "10.40.0.0/16"]


def test_an_object_with_no_address_resolves_to_nothing():
    """[] means "this object denotes no address space", and it is a FACT.

    `exposure_score` falls back to E_IDENTITY only on an empty list, so this
    case and "the normalizer forgot to look" must never be confusable. A user
    group genuinely has no CIDR; so does a label absent from the catalog.
    """
    _res, record = _one(_algosec([_rule(src="ops-team")], objects=CATALOG))
    assert record.source_cidrs == []
    _res, record = _one(_algosec([_rule(src="not-in-the-catalog")], objects=CATALOG))
    assert record.source_cidrs == []


# The four spellings of one grant from the audit's measurement. `any` resolves
# through the shared wildcard vocabulary; the two named objects resolve through
# the catalog; the literal always worked.
SAME_GRANT = ["0.0.0.0/0", "any", "ANY", "all", "*", "ANY-EXTERNAL", "INTERNET"]


@pytest.mark.parametrize("token", SAME_GRANT)
def test_every_spelling_of_the_internet_resolves_to_one_address_space(token):
    """The audit's headline: three of these four produced NO finding at all."""
    _res, record = _one(_algosec([_rule(src=token, dst="db-prod-01")], objects=CATALOG))
    assert record.source_cidrs == ["0.0.0.0/0"]


def test_the_same_policy_written_two_ways_carries_the_same_address_space():
    """Notation must not change the answer -- the phase's whole thesis."""
    _res, by_name = _one(_algosec([_rule(src="app-segment")], objects=CATALOG))
    _res, by_cidr = _one(_algosec([_rule(src="10.30.0.0/16")], objects=CATALOG))
    assert by_name.source_cidrs == by_cidr.source_cidrs == ["10.30.0.0/16"]


def test_resolved_cidrs_are_canonical_and_sorted_however_the_export_spells_them():
    """Host bits and ordering are normalized away, so one block is one string."""
    catalog = {"messy": {"type": "group", "value": ["10.40.0.1/16", "10.30.0.7/16"]}}
    _res, record = _one(_algosec([_rule(src="messy")], objects=catalog))
    assert record.source_cidrs == ["10.30.0.0/16", "10.40.0.0/16"]


# --- 4. abstract object types ------------------------------------------------
# (object name, expected abstract). A range cannot originate traffic, so
# `reachability._valid_traversal` refuses to pivot through it -- and the audit's
# `demo-grade` finding was that a named /16 pivoted while the identical raw /16
# did not.
ABSTRACT_CASES = [
    ("app-segment", True),    # type: network
    ("dc-subnets", True),     # type: group
    ("vendor-range", True),   # type: range
    ("branch-subnet", True),  # type: subnet
    ("ANY-EXTERNAL", True),   # the internet is the widest range there is
    ("db-prod-01", False),    # type: host -- a real machine, and a valid pivot
]


@pytest.mark.parametrize("name,expected", ABSTRACT_CASES, ids=[c[0] for c in ABSTRACT_CASES])
def test_range_objects_are_abstract_and_hosts_are_not(name, expected):
    res = algosec.normalize(_algosec([_rule(src=name, dst="db-prod-01")], objects=CATALOG))
    assert next(e for e in res.entities if e.name == name).abstract is expected


def test_the_address_decides_when_the_declared_type_is_wrong_or_unknown():
    """A vendor type we have never seen is judged on what it resolves to.

    An object called `host` whose value is a /16 is a subnet; an object of some
    unfamiliar type whose value is a /32 is a host. Reading the address rather
    than the vocabulary is what keeps this working on an export nobody has seen.
    """
    catalog = {"mislabelled": {"type": "host", "value": "10.40.0.0/16"},
               "exotic": {"type": "dynamic_address_object", "value": "10.40.0.9"}}
    res = algosec.normalize(_algosec(
        [_rule(src="mislabelled", dst="exotic")], objects=catalog))
    by_name = {e.name: e for e in res.entities}
    assert by_name["mislabelled"].abstract is True
    assert by_name["exotic"].abstract is False


def test_a_guardicore_segment_label_is_abstract_on_its_side_too():
    """Both tools' views must agree or the merged asset comes out concrete.

    `identity.resolve_identities` folds them with `abstract = all(...)`, so a
    segment that AlgoSec calls a network and Guardicore calls a segment needs
    BOTH normalizers to say so. `internal-app` is exactly that node, and it is
    the hop the demo's flagship attack path pivots through.
    """
    res = guardicore.normalize({"labels": {
        "internal-app": {"role": "segment", "env": "prod", "tags": ["prod"]},
        "web-tier": {"role": "web", "env": "prod", "tags": ["prod"]}}, "policies": []})
    by_name = {e.name: e for e in res.entities}
    assert by_name["internal-app"].abstract is True
    assert by_name["web-tier"].abstract is False


def test_a_named_segment_folds_to_an_abstract_asset_across_both_tools():
    """The end-to-end version of the rule above, through the identity layer."""
    algo = algosec.normalize(_algosec(
        [_rule(src="internal-app", dst="db-prod-01")],
        objects={**CATALOG, "internal-app": {"type": "network", "value": "10.40.0.0/16"}}))
    gc = guardicore.normalize({"labels": {"internal-app": {"role": "segment", "env": "prod"}},
                               "policies": []})
    idr = resolve_identities(algo.entities + gc.entities)
    assert next(a for a in idr.assets if a.asset_key == "internal-app").kind == "abstract"


def test_an_address_group_never_reaches_the_identity_layer_as_a_list():
    """`ObservedEntity.cidr` holds one string; the identity layer hashes it.

    A catalog whose `value` is a list used to be written there verbatim and blew
    up much later as `TypeError: unhashable type: 'list'` inside
    `resolve_identities`, with nothing pointing back at the object.

    ...but "not a list" must not mean "gone". `cidr` staying None for a group is
    correct and stays asserted; `cidrs` is where the several blocks now live,
    because dropping them left the group's ASSET with `ip_set == []`, which is
    what `graph.build` hands `zones.zone_of` -- so a group resolving to
    0.0.0.0/0 was classified ZONE_INTERNAL and scored two bands below the same
    space written as a literal /0.
    """
    res = algosec.normalize(_algosec([_rule(src="dc-subnets")], objects=CATALOG))
    entity = next(e for e in res.entities if e.name == "dc-subnets")
    assert entity.cidr is None                      # several blocks: none is THE cidr
    assert entity.cidrs == ["10.30.0.0/16", "10.40.0.0/16"]   # ...all of them are here
    idr = resolve_identities(res.entities)          # must not raise
    asset = next(a for a in idr.assets if a.asset_key == "dc-subnets")
    assert asset.ip_set == ["10.30.0.0/16", "10.40.0.0/16"]


def test_merging_two_views_of_one_node_unions_their_address_space():
    """`merge_entities` keeps the FIRST `ip`/`cidr` it sees, which is fine for a
    scalar -- but first-wins on a LIST silently discards blocks, and a lost block
    is how the group encoding's 0.0.0.0/0 went missing from the zone layer in the
    first place. The union is sorted because it feeds `Asset.ip_set`, which is
    persisted and fingerprinted."""
    entities: dict[str, ObservedEntity] = {}
    merge_entities(entities, ObservedEntity(name="grp", kind="identity", tool="algosec",
                                            cidrs=["10.0.0.0/8"], abstract=True))
    merge_entities(entities, ObservedEntity(name="grp", kind="identity", tool="algosec",
                                            cidrs=["0.0.0.0/0", "10.0.0.0/8"], abstract=True))
    assert entities["grp"].cidrs == ["0.0.0.0/0", "10.0.0.0/8"]


def test_a_profile_defined_address_group_carries_every_block_too():
    """The declarative normalizer resolves the same catalog shapes the coded ones
    do, so a group defined through a SourceProfile must not be the one spelling
    that still loses its address space."""
    profile = SourceProfile(tool="algosec", rules_path="rules", objects_path="objects",
                            fields=FieldMap(src="src", dst="dst", service="svc"))
    raw = {"objects": {"EXTERNAL-NETS": {"type": "group",
                                         "value": ["0.0.0.0/0", "10.0.0.0/8"]}},
           "rules": [{"src": "EXTERNAL-NETS", "dst": "db-prod-01", "svc": "tcp/3389"}]}
    res = apply_profile(raw, profile)
    entity = next(e for e in res.entities if e.name == "EXTERNAL-NETS")
    assert entity.cidr is None                                  # several blocks
    assert entity.cidrs == ["0.0.0.0/0", "10.0.0.0/8"]
    asset = next(a for a in resolve_identities(res.entities).assets
                 if a.asset_key == "EXTERNAL-NETS")
    assert asset.ip_set == ["0.0.0.0/0", "10.0.0.0/8"]


# --- 5. the other two normalizers carry address space as well ----------------

def test_wiz_carries_the_asset_addresses_on_both_ends():
    res = wiz.normalize({"assets": {
        "lb-public-01": {"cloud": "aws", "ip": "52.20.10.10", "tags": ["dmz"]},
        "appsrv-07": {"cloud": "aws", "ip": "10.30.7.7", "tags": ["prod"]}}, "exposures": [
        {"exposure_id": "WIZ-1", "kind": "internet_ingress", "dst": "lb-public-01",
         "port": 443, "protocol": "tcp"},
        {"exposure_id": "WIZ-2", "kind": "lateral", "src": "lb-public-01",
         "dst": "appsrv-07", "port": 8443, "protocol": "tcp"}]})
    ingress, lateral = res.records
    assert ingress.source_cidrs == ["0.0.0.0/0"]
    assert ingress.dest_cidrs == ["52.20.10.10/32"]
    assert lateral.source_cidrs == ["52.20.10.10/32"]
    assert lateral.dest_cidrs == ["10.30.7.7/32"]
    # A cloud host with a public address is a DMZ asset, not the internet.
    assert next(e for e in res.entities if e.name == "lb-public-01").abstract is False


def test_a_cloud_asset_with_an_unreadable_ip_is_not_merged_on_it():
    """`ObservedEntity.ip` is the identity layer's merge key.

    An unparseable string there is a key that matches nothing real but sorts and
    hashes like one, so it is withheld and flagged instead of passed along. The
    asset itself stays CONCRETE -- Wiz enumerated it, so it is a machine; only
    its address is unusable.
    """
    res = wiz.normalize({"assets": {"broken-01": {"cloud": "aws", "ip": "10.0.0.999"}},
                         "exposures": [{"exposure_id": "WIZ-1", "kind": "internet_ingress",
                                        "dst": "broken-01", "port": 443, "protocol": "tcp"}]})
    entity = next(e for e in res.entities if e.name == "broken-01")
    assert entity.ip is None
    assert entity.abstract is False
    assert entity.identifiers["malformed_address"] is True
    assert res.records[0].dest_cidrs == []
    row = next(r for r in res.resolved if r.object_name == "broken-01")
    assert row.resolved["warnings"] == ["unresolvable object value '10.0.0.999'"]


def test_guardicore_labels_resolve_to_nothing_unless_they_carry_a_subnet():
    """Empty here is CORRECT: Guardicore is identity-based by design."""
    res = guardicore.normalize({"labels": {
        "web-tier": {"role": "web", "tags": ["prod"]},
        "dmz-net": {"role": "segment", "cidr": "10.60.0.0/16"}}, "policies": [
        {"policy_id": "GC-1", "src_label": "web-tier", "dst_label": "dmz-net",
         "port": 443, "protocol": "tcp", "action": "allow"}]})
    record = res.records[0]
    assert record.source_cidrs == []
    assert record.dest_cidrs == ["10.60.0.0/16"]


# --- 6. the action vocabulary ------------------------------------------------
# Check Point writes drop/reject, Cisco permit, Junos pass -- and any of them may
# be capitalised. An unmapped verb must refuse rather than default to "allow".
ACTION_CASES = [("allow", "allow"), ("Allow", "allow"), ("PERMIT", "allow"),
                ("accept", "allow"), ("deny", "deny"), ("drop", "deny"),
                ("reject", "deny"), ("Block", "deny")]


@pytest.mark.parametrize("verb,expected", ACTION_CASES, ids=[c[0] for c in ACTION_CASES])
def test_vendor_action_verbs_decode_instead_of_dying_in_pydantic(verb, expected):
    _res, record = _one(_algosec([_rule(action=verb)]))
    assert record.action == expected


# --- 7. determinism ----------------------------------------------------------

def test_catalog_key_order_does_not_change_the_output():
    """The audit trail and the entity list are persisted and fingerprinted."""
    forward = algosec.normalize(_algosec([_rule(src="app-segment")], objects=CATALOG))
    reversed_catalog = dict(reversed(list(CATALOG.items())))
    backward = algosec.normalize(_algosec([_rule(src="app-segment")], objects=reversed_catalog))
    assert [r.object_name for r in forward.resolved] == [r.object_name for r in backward.resolved]
    assert [e.name for e in forward.entities] == [e.name for e in backward.entities]
    assert [r.model_dump() for r in forward.records] == [r.model_dump() for r in backward.records]


# --- 8. the declarative profile: the validator that certified nonsense -------

WRONG_PROFILE = SourceProfile(
    tool="acme-fw", rules_path="rules",
    fields=FieldMap(src="source", dst="destination", service="svc"),
)
SAMPLE = {"rules": [{"src_addr": "10.0.0.0/8", "dst_addr": "10.20.0.0/16",
                     "port": 443, "proto": "tcp"} for _ in range(3)]}


def test_a_profile_whose_field_names_are_all_wrong_never_says_None():
    """`str(None)` -> the TRUTHY string "None", and that was the whole bug.

    Every source became the literal `'None'`, which is not falsy, so
    `validate_profile`'s "is any field empty" check passed and the UI put a
    green "validated" badge over a table of `None -> None` rows.
    """
    result = apply_profile(SAMPLE, WRONG_PROFILE)
    for record in result.records:
        assert record.source == ""
        assert record.destination == ""
        assert "None" not in (record.source, record.destination, record.service)
    assert not any("None" in json.dumps(r.model_dump()) for r in result.records)


def test_the_existing_validator_now_reports_that_profile_invalid():
    """End to end through the caller that certifies a profile for a client."""
    from src.advisory.authoring import validate_profile
    validation = validate_profile(WRONG_PROFILE, SAMPLE)
    assert validation["valid"] is False
    assert validation["unmapped"] == ["destination", "source"]


def test_the_field_report_counts_what_each_mapped_field_resolved():
    """"0 of N rows resolved a source" is the number that makes it obvious."""
    report = field_report(SAMPLE, WRONG_PROFILE)
    assert report == {"rows": 3, "resolved": {"dst": 0, "service": 0, "src": 0},
                      "unresolved_fields": ["dst", "src"], "valid": False}


def test_a_correct_profile_still_validates_and_now_carries_address_space():
    right = SourceProfile(tool="acme-fw", rules_path="rules",
                          fields=FieldMap(src="src_addr", dst="dst_addr",
                                          port="port", protocol="proto"))
    result = apply_profile(SAMPLE, right)
    assert field_report(SAMPLE, right)["valid"] is True
    assert result.records[0].source_cidrs == ["10.0.0.0/8"]
    assert result.records[0].dest_cidrs == ["10.20.0.0/16"]


def test_a_profile_no_longer_turns_deny_into_allow():
    """`action if action in ("allow","deny") else "allow"` did exactly that."""
    sample = {"rules": [{"s": "10.0.0.0/8", "d": "10.1.0.0/16", "verdict": "drop"}]}
    profile = SourceProfile(tool="acme-fw", rules_path="rules",
                            fields=FieldMap(src="s", dst="d", action="verdict"))
    assert apply_profile(sample, profile).records[0].action == "deny"
    unknown = {"rules": [{"s": "10.0.0.0/8", "d": "10.1.0.0/16", "verdict": "log"}]}
    with pytest.raises(NormalizeError, match="acme-fw.*log"):
        apply_profile(unknown, profile)


def test_a_profile_resolves_named_objects_and_marks_ranges_abstract_too():
    """apply_profile is the path an authored connector takes; same rules apply."""
    sample = {"objects": {"DC": {"kind": "network", "addr": "10.70.0.0/16"}},
              "rules": [{"s": "DC", "d": "10.1.0.0/16"}]}
    profile = SourceProfile(tool="acme-fw", rules_path="rules", objects_path="objects",
                            object_value_key="addr", object_type_key="kind",
                            fields=FieldMap(src="s", dst="d"))
    result = apply_profile(sample, profile)
    assert result.records[0].source_cidrs == ["10.70.0.0/16"]
    assert next(e for e in result.entities if e.name == "DC").abstract is True


# --- 9. scope: the namespace an address is unique inside ---------------------
# `identity.resolve_identities` only fuses two names on a shared IP INSIDE one
# declared namespace -- and until this section existed, NO normalizer populated
# one, so `identity.context_of` returned None for every entity any shipped code
# produced. The scoped arm was unreachable in production and only the tests
# reached it, by `setattr`. These tests go the other way round: they build the
# entity with a real normalizer, from an export, and never touch the object.


def test_a_declared_namespace_reaches_the_identity_layer_from_a_real_export():
    """The whole path, with no `setattr` anywhere: two tools describe one host on
    10.30.7.7 and both exports name the VPC that assigns the address, so the
    identity layer may finally fuse them on it."""
    wiz_res = wiz.normalize({"assets": {
        "appsrv-07": {"cloud": "aws", "vpcId": "vpc-0a1b", "ip": "10.30.7.7",
                      "tags": ["prod"]}}, "exposures": []})
    algosec_res = algosec.normalize(_algosec(
        [_rule(dst="app-server-07")],
        {"app-server-07": {"type": "host", "value": "10.30.7.7", "vpc": "vpc-0a1b"}}))

    wiz_entity = next(e for e in wiz_res.entities if e.name == "appsrv-07")
    algosec_entity = next(e for e in algosec_res.entities if e.name == "app-server-07")
    assert wiz_entity.identifiers["vpc"] == "vpc-0a1b"
    assert context_of(wiz_entity) == context_of(algosec_entity) == "vpc-0a1b"

    r = resolve_identities([wiz_entity, algosec_entity])
    assert r.alias_map["appsrv-07"] == r.alias_map["app-server-07"]
    assert r.suppressed_merges == 0
    assert [(c.match_key, c.evidence.get("context")) for c in r.correlations
            if c.match_key == "context_ip"] == [("context_ip", "vpc-0a1b")]


def test_two_namespaces_on_one_address_still_do_not_fuse():
    """The same two exports, in two different VPCs -- the RFC 1918 reuse case.

    This is the half that matters: teaching the normalizers to declare a scope
    must not become a way to merge, it must become a way to be PRECISE about
    when merging is legitimate."""
    a = next(e for e in wiz.normalize({"assets": {
        "prod-web-01": {"vpcId": "vpc-prod", "ip": "10.0.1.5", "tags": ["pci"]}},
        "exposures": []}).entities if e.name == "prod-web-01")
    b = next(e for e in wiz.normalize({"assets": {
        "dev-web-01": {"vpcId": "vpc-dev", "ip": "10.0.1.5"}},
        "exposures": []}).entities if e.name == "dev-web-01")

    r = resolve_identities([a, b])
    assert r.alias_map["prod-web-01"] != r.alias_map["dev-web-01"]
    assert r.suppressed_by_reason == {"context_mismatch": 1}
    # ...and the pci tag did not leak onto the host that merely reuses the address.
    assert [x.tags for x in r.assets if x.asset_key == "dev-web-01"] == [[]]


def test_an_export_that_declares_no_namespace_is_unscoped_not_guessed():
    """The shipped demo's own shape, which is why its 10.30.7.7 collision is a
    review row: no VPC, no account, no VRF anywhere in the three exports."""
    entity = next(e for e in wiz.normalize({"assets": {
        "appsrv-07": {"cloud": "aws", "type": "ec2", "internet_facing": False,
                      "ip": "10.30.7.7", "tags": ["prod"]}},
        "exposures": []}).entities if e.name == "appsrv-07")

    assert context_of(entity) is None
    assert not any(k in entity.identifiers for k in SCOPE_KEYS)


@pytest.mark.parametrize("meta,expected", [
    ({"vpcId": "vpc-1"}, {"vpc": "vpc-1"}),
    ({"vpc_id": "vpc-1"}, {"vpc": "vpc-1"}),
    ({"VPC-ID": "  vpc-1  "}, {"vpc": "vpc-1"}),          # folded and stripped
    ({"vnet": "vnet-1"}, {"vpc": "vnet-1"}),              # Azure's word for it
    ({"accountId": 123456789012}, {"account": "123456789012"}),   # a JSON number
    ({"subscriptionId": "sub-1"}, {"subscription": "sub-1"}),
    ({"projectId": "proj-1"}, {"project": "proj-1"}),
    ({"tenant": "t-1"}, {"tenant": "t-1"}),
    ({"routing_instance": "vrf-blue"}, {"vrf": "vrf-blue"}),
    # ...and the fields that are NOT a namespace, however scope-ish they look.
    ({"env": "prod", "cloud": "aws", "region": "us-east-1", "type": "ec2"}, {}),
    ({"vpc": ""}, {}),                                    # declared but empty
    ({"vpc": True}, {}),                                  # a flag is not an id
    ({"vpc": ["a", "b"]}, {}),                            # not a scalar
    ({}, {}),
    (None, {}),
])
def test_only_a_real_namespace_field_counts_as_scope(meta, expected):
    """`env`/`cloud`/`region` are labels every account in the estate shares, so
    keying a merge on one would reintroduce exactly the collision the scope rule
    exists to prevent. Anything unusable answers {} -- "no scope declared" --
    which the merge reads as "do not fuse"."""
    assert scope_identifiers(meta) == expected


def test_scope_extraction_is_deterministic():
    """Key order in the source JSON cannot change the answer, and one namespace
    spelled twice resolves the same way every time."""
    assert scope_identifiers({"vpc": "a", "vpcId": "b"}) == {"vpc": "a"}
    assert scope_identifiers({"vpcId": "b", "vpc": "a"}) == {"vpc": "a"}
    both = scope_identifiers({"accountId": "acct-1", "vpcId": "vpc-1"})
    assert list(both) == ["vpc", "account"]        # emitted in SCOPE_KEYS order
    assert list(scope_identifiers({"vpcId": "vpc-1", "accountId": "acct-1"})) == list(both)


def test_a_guardicore_label_and_a_profile_object_can_declare_a_scope_too():
    """Every normalizer, not just Wiz: the identity layer's rule is only real if
    each ingest path can satisfy it."""
    label = next(e for e in guardicore.normalize({"labels": {
        "web-tier": {"role": "web", "env": "prod", "vrf": "vrf-blue"}}, "policies": [
        {"policy_id": "GC-1", "src_label": "web-tier", "dst_label": "web-tier",
         "port": 443, "protocol": "tcp", "action": "allow"}]}).entities
        if e.name == "web-tier")
    assert context_of(label) == "vrf-blue"

    sample = {"objects": {"DC-DB": {"kind": "host", "addr": "10.70.0.5",
                                    "tenant": "tenant-9"}},
              "rules": [{"s": "DC-DB", "d": "10.1.0.0/16"}]}
    profile = SourceProfile(tool="acme-fw", rules_path="rules", objects_path="objects",
                            object_value_key="addr", object_type_key="kind",
                            fields=FieldMap(src="s", dst="d"))
    obj = next(e for e in apply_profile(sample, profile).entities if e.name == "DC-DB")
    assert context_of(obj) == "tenant-9"
