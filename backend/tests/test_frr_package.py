"""The change-package drafter: the right proposal per check, honest availability
impact, rollback for every change, and none of the moves that cause outages."""

from __future__ import annotations

import json

import pytest

from src.frr import package as pk
from src.frr.review import review
from src.normalizers import checkpoint as cp
from tests import cp_fixture as fx


def _draft(export=None):
    p = cp.parse(export or fx.export())
    r = review(p)
    return pk.draft(json.loads(json.dumps(r.to_jsonable())), json.loads(json.dumps(p.to_jsonable())))


@pytest.fixture(scope="module")
def items():
    return {i["rule_number"]: i for i in _draft()["items"]}


def test_unused_any_any_is_disabled_not_narrowed(items) -> None:
    i = items[1]
    assert i["proposal"] == "disable_then_remove" and i["check"] == "any_any+unused"
    assert i["band"] == "critical" and i["availability_impact"] == "possible"
    assert any("enabled false" in c for c in i["commands"])
    assert any("enabled true" in c for c in i["rollback"])


def test_a_live_risky_rule_is_contained_and_needs_owner_input(items) -> None:
    i = items[5]
    assert i["proposal"] == "time_bound_and_narrow" and i["availability_impact"] == "likely"
    assert set(i["requires_owner_input"]) == {"allowed_sources", "allowed_services",
                                               "business_justification"}
    assert any("add time" in c for c in i["commands"]) and any("time.1 Any" in c for c in i["rollback"])


def test_dead_rules_are_removed_with_an_exact_restore(items) -> None:
    for n in (6, 7):
        i = items[n]
        assert i["proposal"] == "remove" and i["availability_impact"] == "none"
        restore = i["rollback"][0]
        assert restore.startswith("mgmt_cli add access-rule layer Network position %d" % n)
    assert "enabled false" in items[6]["rollback"][0]          # restored as it was: disabled
    assert "source.1 corp-net" in items[7]["rollback"][0]


def test_a_rule_shadowed_by_one_being_changed_is_not_removed(items) -> None:
    i = items[3]
    assert i["proposal"] == "revisit_after" and i["commands"] == []


def test_hits_refute_shadowing_so_live_rules_are_untouched(items) -> None:
    assert 2 not in items and 8 not in items and 10 not in items


def test_a_cleanup_rule_is_never_moved() -> None:
    e = fx.export()
    for item in e["access_layers"][0]["rulebase"]:
        for r in item.get("rulebase", [item]):
            if r.get("rule-number") == 10:
                r["hits"] = {"value": 0, "last-date": None}
    items = {i["rule_number"]: i for i in _draft(e)["items"]}
    assert items[10]["proposal"] == "revisit_after"
    assert not any("new-position" in c for i in items.values() for c in i["commands"])


def test_a_shadowed_deny_under_a_specific_allow_is_reordered() -> None:
    e = fx.export()
    layer = e["access_layers"][0]["rulebase"]
    layer.insert(1, {"type": "access-rule", "uid": "rule-11", "rule-number": 11, "name": "block web",
                     "enabled": True, "source": ["n-corp"], "destination": ["h-web1"],
                     "service": ["s-https"], "action": "act-drop", "time": [fx.ANY],
                     "install-on": ["pt"], "hits": {"value": 0, "last-date": None}})
    layer[1]["rule-number"] = 12
    layer.append(layer.pop(1))
    layer[0]["rulebase"][0]["enabled"] = False      # take the any-any (rule 1) out of play
    # Rule 2 (Any -> web-farm https, live, not being changed) now covers the deny.
    pkg = _draft(e)
    i = next(x for x in pkg["items"] if x["rule_number"] == 12)
    assert i["proposal"] == "reorder" and i["availability_impact"] == "changes_behaviour"
    assert "new-position 2" in i["commands"][0] and "new-position 12" in i["rollback"][0]


def test_every_change_has_a_rollback_and_nothing_writes_to_a_device() -> None:
    pkg = _draft()
    for i in pkg["items"]:
        if i["commands"]:
            assert i["rollback"], i["item_id"]
    assert "No change is applied by this product" in pkg["notes"][0]
    from pathlib import Path
    src = Path(pk.__file__).read_text()
    for forbidden in ("httpx", "requests", "subprocess", "paramiko", "servicenow"):
        assert f"import {forbidden}" not in src
