"""The rule-risk register over the Check Point fixture: every planted condition
is found on the right rule, with its evidence, and nothing is invented."""

from __future__ import annotations

import pytest

from src.frr import review as rv
from src.normalizers import checkpoint as cp
from tests import cp_fixture as fx


@pytest.fixture(scope="module")
def register():
    return {e.number: e for e in rv.review(cp.parse(fx.export())).register}


def checks(register, n):
    return {c.check: c for c in register[n].checks}


def test_any_any_is_critical_with_engine_evidence(register) -> None:
    c = checks(register, 1)["any_any"]
    assert c.band == "critical" and c.finding_id
    assert c.evidence["protocol"] == "any" and "internet any/any" in c.evidence["forced_reasons"]


def test_admin_ports_exposed_to_the_internet_are_critical(register) -> None:
    c = checks(register, 5)["admin_port_exposed"]
    assert c.band == "critical" and c.evidence["exposed_port"] == 22


def test_admin_ports_from_a_broad_internal_source_are_flagged(register) -> None:
    assert "admin_port_exposed" in checks(register, 4)


def test_shadowed_rules_name_the_rule_that_covers_them(register) -> None:
    c = checks(register, 3)["shadowed"]
    assert c.evidence["covered_by_rule"] == 1 and "rule 1" in c.title
    assert "shadowed" not in checks(register, 1)        # the coverer is not itself shadowed


def test_expired_disabled_and_unused(register) -> None:
    assert set(checks(register, 7)) == {"expired"}       # expired is not also "unused"
    assert set(checks(register, 6)) == {"disabled"}
    assert checks(register, 3)["unused"].evidence["hit_count"] == 0
    assert "unused" not in checks(register, 2)           # 15,200 hits, recent


def test_a_stale_last_hit_is_unused() -> None:
    e = fx.export()
    r4 = e["access_layers"][0]["rulebase"][2]["rulebase"][0]
    r4["hits"] = {"value": 31, "last-date": {"iso-8601": "2026-01-01T00:00:00Z"}}
    reg = {x.number: x for x in rv.review(cp.parse(e)).register}
    assert "last hit 2026-01-01" in {c.check: c for c in reg[4].checks}["unused"].title


def test_unknown_hits_never_produce_unused() -> None:
    e = fx.export()
    for item in e["access_layers"][0]["rulebase"]:
        for r in item.get("rulebase", [item]):
            r.pop("hits", None)
    review = rv.review(cp.parse(e))
    assert not any(c.check == "unused" for x in review.register for c in x.checks)
    assert any("hit counts absent" in l for l in review.limitations)


def test_a_clean_rule_has_no_checks_and_ranks_last() -> None:
    e = fx.export()
    review = rv.review(cp.parse(e))
    assert review.register[0].band == "critical"
    flagged = [x for x in review.register if x.checks]
    assert review.stats["rules_with_findings"] == len(flagged)


def test_register_is_serialisable_with_limitations(register) -> None:
    review = rv.review(cp.parse(fx.export()))
    out = review.to_jsonable()
    assert out["register"][0]["band"] == "critical"
    assert out["stats"]["by_check"]["any_any"] == 1
    assert any("negated" in l for l in next(r for r in out["register"] if r["number"] == 5)["limitations"])


# --- shadowing is per gateway ------------------------------------------------------
def _gateway_export(rule2_on, rule3_on):
    e = fx.export()
    e["access_layers"][0]["objects-dictionary"].append({"uid": "gw-2", "name": "edge-gw-2",
                                                        "type": "simple-gateway"})
    sections = e["access_layers"][0]["rulebase"]
    sections[0]["rulebase"][0]["enabled"] = False                  # take the any-any out of play
    sections[1]["rulebase"][0]["install-on"] = rule2_on            # rule 2: web-farm https
    sections[1]["rulebase"][1]["install-on"] = rule3_on            # rule 3: web-01 https (0 hits)
    sections[2]["rulebase"][0]["install-on"] = ["gw-2"]            # makes gw-2 a gateway
    return e


def test_a_rule_covered_on_one_gateway_but_live_on_another_is_not_shadowed() -> None:
    reg = {x.number: x for x in rv.review(cp.parse(_gateway_export(["gw-1"], ["pt"]))).register}
    assert "shadowed" not in {c.check for c in reg[3].checks}
    assert any("effective on edge-gw-2" in l for l in reg[3].limitations)


def test_a_rule_covered_on_every_gateway_it_is_installed_on_is_shadowed() -> None:
    reg = {x.number: x for x in rv.review(cp.parse(_gateway_export(["gw-1"], ["gw-1"]))).register}
    c = {c.check: c for c in reg[3].checks}["shadowed"]
    assert c.evidence["covered_by_rule"] == 2 and c.evidence["gateways"] == ["edge-gw-1"]


def test_the_effective_policy_model_is_per_gateway() -> None:
    out = rv.review(cp.parse(_gateway_export(["gw-1"], ["pt"])))
    ep = {(e["layer"], e["gateway"]): e for e in out.effective_policy}
    assert set(ep) == {("Network", "edge-gw-1"), ("Network", "edge-gw-2")}
    gw1, gw2 = ep[("Network", "edge-gw-1")], ep[("Network", "edge-gw-2")]
    assert 2 in gw1["effective_allow"] and 2 not in gw2["effective_allow"]
    assert 3 in gw1["shadowed"] and 3 in gw2["effective_allow"]
    assert 1 in gw1["inactive"] and 6 in gw1["inactive"] and 7 in gw1["inactive"]
