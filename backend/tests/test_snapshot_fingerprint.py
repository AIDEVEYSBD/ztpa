r"""Pin the snapshot id's INJECTIVITY over the real export vocabulary.

`test_analyzers.py` already pins the Phase 1 exit criterion -- "changing only a
tag / a CIDR / an object type / the manual_merges list moves the id, identical
input does not" -- but it pins it against `normalize_stub`, a hand-built
`NormalizeResult` with `resolved=[]` whose "object type" knob is the flag
`abstract=True/False`. That asserts `_ENTITY_FIELDS` contains `abstract`; it does
not assert that an EXPORT's object `type` reaches the id. Three postures got
through that gap, each one a different id collision, each one measured end to end
before it was fixed:

  1. **A tag containing a comma.** `run_all._value` joined list members with ","
     while `_record_digest` joins FIELDS with \x1f, so ``['pci','customer-data',
     'prod']`` and ``['customer-data,pci','prod']`` flattened to the same string
     and fingerprinted byte-identically. `config.SENSITIVE_TAGS` matches `pci` by
     MEMBERSHIP, so the second spelling is not sensitive: on the demo export that
     single retag moved ALGO-030 70/high -> 47/medium and ALGO-002 100 -> 90,
     under one snapshot id and the same finding ids.

  2. **An unreferenced catalog object.** `normalizers/algosec.py` emits a
     `ResolvedObject` for every catalog entry but an `ObservedEntity` only for
     objects a rule references. An object nothing points at was therefore
     persisted (`resolved_objects`) and rendered (`IngestInspector`) while being
     outside the id: its CIDR, its type and its tags could all change and the
     snapshot id would not.

  3. **An object `type` on a multi-address value.** The declared type reached the
     entity only through `abstract`, and `object_is_abstract` is already True by
     resolved WIDTH for anything spanning more than one address. Flipping a
     `network` object to `host` therefore moved nothing hashed -- yet it rewrote
     the persisted `resolved` payload under the same snapshot id AND the same
     deterministic row id (`persist.py` keys the row on sid|tool|device|name|kind,
     not on the payload).

So every test below drives a real export through the real normalizer. No stub
result, no `setattr` on an entity: if the path from "an operator edited the
export" to "the id moved" ever breaks again, it breaks here.
"""

from __future__ import annotations

import copy
import dataclasses
import json
import random

import pytest

from src.analyzers import run_all
from src.ids import det_id
from src.normalizers import algosec
from src.normalizers.common import ResolvedObject

# One AlgoSec export exercising every knob the criterion names: a multi-address
# NETWORK object (`app-segment`) that two rules reference, a tagged HOST object
# (`db-prod-01`) that is the destination, and -- deliberately -- an object no
# rule mentions (`dmz-net`). It is small on purpose: a collision here is a
# collision, not a coincidence of a 40-rule fixture.
BASE_EXPORT: dict = {
    "device": "afa-edge-fw-01",
    "objects": {
        "app-segment": {"type": "network", "value": "10.30.0.0/16", "tags": ["prod"]},
        "db-prod-01": {"type": "host", "value": "10.50.0.10",
                       "tags": ["pci", "customer-data", "prod"]},
        "dmz-net": {"type": "network", "value": "192.168.0.0/16", "tags": []},
    },
    "rules": [
        {"rule_id": "R1", "order": 1, "src": "app-segment", "dst": "db-prod-01",
         "service": "tcp/1433", "action": "allow"},
        {"rule_id": "R2", "order": 2, "src": "0.0.0.0/0", "dst": "app-segment",
         "service": "tcp/443", "action": "allow"},
    ],
}


def snapshot_id_for(export: dict, monkeypatch: pytest.MonkeyPatch, **kw) -> str:
    """`run()` over ONE export, through the real AlgoSec normalizer.

    `normalize_all` is the only thing replaced -- `algosec.normalize` itself, the
    identity layer, the graph and the fingerprint all run for real, which is the
    whole point: the stubbed `NormalizeResult` is exactly what let an export-level
    edit hide from the id.
    """
    monkeypatch.setattr(run_all, "normalize_all", lambda: algosec.normalize(export))
    return run_all.run(label="fingerprint-test", **kw).snapshot_id


def with_object(name: str, **patch) -> dict:
    """`BASE_EXPORT` with one catalog object replaced field-by-field."""
    export = copy.deepcopy(BASE_EXPORT)
    export["objects"][name] = {**export["objects"][name], **patch}
    return export


# --- 0. the stability half --------------------------------------------------

def test_identical_exports_produce_an_identical_snapshot_id(monkeypatch: pytest.MonkeyPatch):
    """A fingerprint that changes on everything is as useless as one that changes
    on nothing, so every "it moved" assertion below is measured against this."""
    assert snapshot_id_for(copy.deepcopy(BASE_EXPORT), monkeypatch) == \
        snapshot_id_for(copy.deepcopy(BASE_EXPORT), monkeypatch)


def _reshuffle_keys(node, rng: random.Random):
    """The same data, every JSON OBJECT's keys emitted in a different order."""
    if isinstance(node, dict):
        keys = list(node)
        rng.shuffle(keys)
        return {k: _reshuffle_keys(node[k], rng) for k in keys}
    if isinstance(node, list):
        return [_reshuffle_keys(v, rng) for v in node]      # order preserved: see below
    return node


def test_the_snapshot_id_ignores_the_key_order_of_the_export(monkeypatch: pytest.MonkeyPatch):
    """JSON objects are unordered, so two dumps of one posture must be one id.

    This is the property the `sorted` in `_fingerprint`/`_value` exists for, and
    the one a naive "just hash the raw file" fix would break. Applied to every
    object at every depth -- the catalog, each catalog entry, each rule.
    """
    baseline = snapshot_id_for(copy.deepcopy(BASE_EXPORT), monkeypatch)
    rng = random.Random(1)
    for _ in range(5):
        assert snapshot_id_for(_reshuffle_keys(copy.deepcopy(BASE_EXPORT), rng),
                               monkeypatch) == baseline


def test_reordering_a_tag_ARRAY_does_move_the_id_and_that_is_deliberate(
        monkeypatch: pytest.MonkeyPatch):
    """The boundary of the rule above, pinned so it is a decision and not a bug.

    JSON *objects* are unordered; JSON *arrays* are not. `ResolvedObject.resolved`
    is the catalog payload persisted verbatim into `resolved_objects` and rendered
    verbatim by `IngestInspector`, so two exports whose tag arrays differ in order
    produce two different audit trails -- different bytes on the screen an
    operator signs off. The id describes engine OUTPUT, and that output differs.

    Deliberately NOT fixed by sorting lists nested inside the payload dict: that
    would be the collision-creating direction (a payload whose order IS content --
    an ordered NAT chain, a rule sequence -- would hash the same two ways), and
    this repair exists to remove collisions, not add one. Over-sensitivity is
    noise; under-sensitivity is the audit finding. The *engine's* reading of tags
    is order-free either way -- `_ENTITY_FIELDS`/`_value` sort them, and
    `SENSITIVE_TAGS` matches by membership -- so no score depends on this.
    """
    baseline = snapshot_id_for(copy.deepcopy(BASE_EXPORT), monkeypatch)
    reordered = with_object("db-prod-01", tags=["prod", "customer-data", "pci"])
    assert snapshot_id_for(reordered, monkeypatch) != baseline
    # ...and it is ONLY the audit payload that moved: the scored posture is identical.
    base_res, reordered_res = (algosec.normalize(copy.deepcopy(BASE_EXPORT)),
                               algosec.normalize(reordered))
    assert [sorted(e.tags) for e in base_res.entities] == \
        [sorted(e.tags) for e in reordered_res.entities]
    assert [sorted(r.dest_tags) for r in base_res.records] == \
        [sorted(r.dest_tags) for r in reordered_res.records]


# --- 1. the comma-bearing tag ----------------------------------------------

def test_a_list_field_cannot_encode_to_the_same_string_as_a_different_list():
    """The collision itself, at the unit that caused it.

    `['pci','customer-data','prod']` and `['customer-data,pci','prod']` are two
    different tag sets -- one has `pci` as a member, the other does not -- and
    `_value` returned one identical string for both.
    """
    assert run_all._value(["pci", "customer-data", "prod"]) != \
        run_all._value(["customer-data,pci", "prod"])


@pytest.mark.parametrize("separator", [",", "\x1f", "\x1e", '","', "\\"])
def test_a_tag_containing_a_separator_cannot_forge_another_tag_set(separator):
    """Generalised: no delimiter the encoder uses -- the list joiner, the field
    separator, the record separator, or the quote/backslash JSON itself
    introduces -- may be spellable from inside a value."""
    assert run_all._value([f"a{separator}b"]) != run_all._value(["a", "b"])


def test_a_tag_containing_a_comma_moves_the_snapshot_id(monkeypatch: pytest.MonkeyPatch):
    """Exit criterion, end to end: ONLY `db-prod-01`'s tags differ.

    Under the old encoding both spellings produced one id while the findings
    underneath them differed by two severity bands -- the audit's "same F_ id at
    two severities" failure, reachable with no control characters at all.
    """
    baseline = snapshot_id_for(copy.deepcopy(BASE_EXPORT), monkeypatch)
    forged = snapshot_id_for(with_object("db-prod-01", tags=["customer-data,pci", "prod"]),
                             monkeypatch)
    assert baseline != forged


def test_the_forged_tag_really_does_change_the_verdict(monkeypatch: pytest.MonkeyPatch):
    """Guard on the guard. If `pci` inside `'customer-data,pci'` ever started
    matching `SENSITIVE_TAGS` (a substring test, say), the test above would still
    pass while the collision had stopped mattering -- and a later encoder
    "simplification" would look free. This fails the day that happens.
    """
    def findings(export):
        monkeypatch.setattr(run_all, "normalize_all", lambda: algosec.normalize(export))
        return {(f.type, tuple(f.raw_refs)): (f.severity, f.severity_band)
                for f in run_all.run(label="fingerprint-test").findings}

    base = findings(copy.deepcopy(BASE_EXPORT))
    forged = findings(with_object("db-prod-01", tags=["customer-data,pci", "prod"]))
    assert base != forged


# --- 2. the unreferenced catalog object ------------------------------------

def test_an_object_no_rule_references_still_emits_a_resolved_row():
    """The asymmetry the hole grew in, asserted directly so the tests below
    cannot pass because `dmz-net` quietly stopped being emitted at all."""
    res = algosec.normalize(copy.deepcopy(BASE_EXPORT))
    assert "dmz-net" in {o.object_name for o in res.resolved}
    assert "dmz-net" not in {e.name for e in res.entities}


@pytest.mark.parametrize("field_name,value", [
    ("value", "0.0.0.0/0"),                       # the whole internet, unhashed
    ("type", "host"),
    ("tags", ["pci", "customer-data"]),
])
def test_editing_an_unreferenced_object_moves_the_snapshot_id(
        monkeypatch: pytest.MonkeyPatch, field_name, value):
    """Exit criterion for objects outside the rule graph.

    A catalog entry nothing references is persisted and rendered, so it is part
    of what the id is supposed to describe. All three of these used to produce
    the baseline id exactly, with a different `resolved_objects` payload.
    """
    baseline = snapshot_id_for(copy.deepcopy(BASE_EXPORT), monkeypatch)
    assert snapshot_id_for(with_object("dmz-net", **{field_name: value}), monkeypatch) != baseline


def test_adding_and_removing_an_unreferenced_object_moves_the_snapshot_id(
        monkeypatch: pytest.MonkeyPatch):
    """The catalog's MEMBERSHIP is content too, not just each member's fields."""
    without = copy.deepcopy(BASE_EXPORT)
    del without["objects"]["dmz-net"]
    assert snapshot_id_for(without, monkeypatch) != \
        snapshot_id_for(copy.deepcopy(BASE_EXPORT), monkeypatch)


def test_every_unreferenced_variant_gets_its_own_snapshot_id(monkeypatch: pytest.MonkeyPatch):
    """Pairwise, not just against the baseline: four postures, four ids. The
    original defect gave all four ONE id and four different persisted payloads.
    """
    variants = {
        "baseline": copy.deepcopy(BASE_EXPORT),
        "wide": with_object("dmz-net", value="0.0.0.0/0"),
        "host": with_object("dmz-net", type="host"),
        "tagged": with_object("dmz-net", tags=["pci", "customer-data"]),
    }
    ids = {name: snapshot_id_for(export, monkeypatch) for name, export in variants.items()}
    assert len(set(ids.values())) == len(ids), ids


# --- 3. the object type on a multi-address value ---------------------------

def test_object_type_reaches_the_id_even_when_abstract_does_not_move(
        monkeypatch: pytest.MonkeyPatch):
    """Exit criterion for the object TYPE, through the real normalizer.

    `app-segment` is a /16, so `object_is_abstract` returns True by WIDTH whatever
    the declared type says. Flipping `network` -> `host` therefore changes no
    entity field and no record field -- the entity view is byte-identical -- while
    changing the `resolved` payload that is persisted and rendered under a row id
    that does not depend on the payload either. The pre-fix run produced one
    snapshot id for both.
    """
    flipped = with_object("app-segment", type="host")

    base_res, flip_res = algosec.normalize(copy.deepcopy(BASE_EXPORT)), algosec.normalize(flipped)
    # The mechanism, stated: nothing the OLD fingerprint looked at moved.
    assert [dataclasses.astuple(e) for e in base_res.entities] == \
        [dataclasses.astuple(e) for e in flip_res.entities]
    assert [r.model_dump() for r in base_res.records] == \
        [r.model_dump() for r in flip_res.records]
    # ...and the thing an operator would actually read moved.
    assert [o.resolved for o in base_res.resolved] != [o.resolved for o in flip_res.resolved]

    assert snapshot_id_for(copy.deepcopy(BASE_EXPORT), monkeypatch) != \
        snapshot_id_for(flipped, monkeypatch)


def test_the_persisted_resolved_row_id_moves_with_the_payload(
        monkeypatch: pytest.MonkeyPatch):
    """The governance half of the object-type defect.

    `persist.py` keys a `resolved_objects` row on
    ``det_id("ro", sid, tool, device, name, kind)`` -- never on the payload -- so
    while the two postures shared a snapshot id they also shared the row id
    `ro_ea6381c0af5e312b`, and an upsert of one silently overwrote the other's
    `resolved` payload. Closed by the sid moving, since the sid is the first
    component of that key; asserted here because "the id moved" and "the audit row
    an operator reads is no longer ambiguous" are two different claims.
    """
    base_sid = snapshot_id_for(copy.deepcopy(BASE_EXPORT), monkeypatch)
    flip_sid = snapshot_id_for(with_object("app-segment", type="host"), monkeypatch)

    def row_id(sid: str) -> str:                       # mirrors persist.py:81
        return det_id("ro", sid, "algosec", "afa-edge-fw-01", "app-segment", "address")

    assert row_id(base_sid) != row_id(flip_sid)


def test_object_cidr_and_tags_reach_the_id_through_the_real_normalizer(
        monkeypatch: pytest.MonkeyPatch):
    """The other two knobs the criterion names, on a REFERENCED object, driven
    from the export rather than from a stubbed entity."""
    baseline = snapshot_id_for(copy.deepcopy(BASE_EXPORT), monkeypatch)
    assert snapshot_id_for(with_object("app-segment", value="10.31.0.0/16"),
                           monkeypatch) != baseline
    assert snapshot_id_for(with_object("app-segment", tags=["prod", "pci"]),
                           monkeypatch) != baseline


def test_manual_merges_reach_the_id_through_the_real_normalizer(
        monkeypatch: pytest.MonkeyPatch):
    """The fourth knob, and its symmetry, on the same real export."""
    export = copy.deepcopy(BASE_EXPORT)
    plain = snapshot_id_for(export, monkeypatch)
    merged = snapshot_id_for(export, monkeypatch,
                             manual_merges=[("app-segment", "db-prod-01")])
    reversed_ = snapshot_id_for(export, monkeypatch,
                                manual_merges=[("db-prod-01", "app-segment")])
    assert plain != merged
    assert merged == reversed_          # the union is symmetric; the id must say so


# --- 4. the structural guard ------------------------------------------------

def test_fingerprint_covers_every_resolved_field():
    """The same guard `test_analyzers.py` puts on records and entities. If
    `ResolvedObject` gains a field -- a confidence, a resolver version -- this
    fails until somebody decides, here, whether it belongs in the id."""
    assert set(run_all._RESOLVED_FIELDS) == \
        {f.name for f in dataclasses.fields(ResolvedObject)}


def test_the_resolved_blob_is_a_blob_of_its_own(monkeypatch: pytest.MonkeyPatch):
    """`_fingerprint` must hash the catalog SEPARATELY, not by luck through the
    entity view: an export whose entities and records are identical and whose
    catalog is not has to produce a different id. Asserted on the primitive so a
    refactor that drops the fifth blob fails here and not only end to end."""
    res = algosec.normalize(copy.deepcopy(BASE_EXPORT))
    extra = ResolvedObject("algosec", "ghost-object", "address",
                           {"value": "0.0.0.0/0", "type": "network"}, "afa-edge-fw-01")
    assert run_all._fingerprint(res.records, res.entities, res.resolved, [], []) != \
        run_all._fingerprint(res.records, res.entities, res.resolved + [extra], [], [])


def test_the_resolved_blob_ignores_the_order_the_catalog_arrives_in():
    """Sorted, like records and entities: an export listing its objects in a
    different order is the same posture."""
    res = algosec.normalize(copy.deepcopy(BASE_EXPORT))
    assert run_all._fingerprint(res.records, res.entities, res.resolved, [], []) == \
        run_all._fingerprint(res.records, res.entities, list(reversed(res.resolved)), [], [])


def test_none_and_the_empty_string_are_not_the_same_field_value():
    """`_value` mapped both to "" -- and `ResolvedObject.source_device` is
    Optional, so "no device" and "a device named ''" hashed alike. JSON keeps
    `null` and `""` apart, which is the same property, one layer down."""
    assert run_all._value(None) != run_all._value("")
    assert run_all._value(None) != run_all._value("None")
    assert run_all._value(0) != run_all._value("0")
    assert run_all._value(False) != run_all._value("False")


def test_the_encoded_field_can_never_contain_a_separator():
    """The invariant the injectivity argument rests on, asserted directly: if a
    future `_value` branch stops escaping, this fails before anything downstream
    silently collides."""
    hostile = ["a\x1fb", "a\x1eb", 'a"b', "a\\b", "a,b"]
    for value in hostile:
        for encoded in (run_all._value(value), run_all._value([value]),
                        run_all._value({"k": value})):
            assert run_all._FS not in encoded, (value, encoded)
            assert run_all._RS not in encoded, (value, encoded)


def test_the_demo_export_fingerprint_survives_a_full_json_round_trip():
    """Nothing in the fingerprint may depend on Python object identity or dict
    insertion order: re-parsing the seeded exports must reproduce the id."""
    from src import normalizers

    first = normalizers.normalize_all()
    second = normalizers.normalize_all()
    assert run_all._fingerprint(first.records, first.entities, first.resolved, [], []) == \
        run_all._fingerprint(second.records, second.entities, second.resolved, [], [])
    # ...and the payload dicts really are JSON-serializable, which is what
    # `_value`'s dict branch assumes before `default=str` has to rescue it.
    for obj in first.resolved:
        json.dumps(obj.resolved, sort_keys=True)
