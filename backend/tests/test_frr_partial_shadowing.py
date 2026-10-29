"""A rule is "never matched" only when every one of its grants is covered.

A rule allowing ssh and https under a rule allowing only ssh still carries the
https traffic; reporting it shadowed would draft its removal, an outage."""

from __future__ import annotations

import json

from src.frr.package import draft
from src.frr.review import review
from src.normalizers import checkpoint as cp
from tests import cp_fixture as fx


def _parsed(rules):
    e = fx.export()
    e["access_layers"][0].update(rulebase=rules, to=len(rules), total=len(rules))
    e["nat_packages"] = []
    return cp.parse(e)


def _review(rules):
    return review(_parsed(rules))


def _entry(r, number):
    return next(x for x in r.register if x.number == number)


def _cleanup(n):
    return fx._rule(n, "cleanup", [fx.ANY], [fx.ANY], [fx.ANY], action="act-drop")


def test_a_partly_covered_rule_is_not_shadowed() -> None:
    r = _review([fx._rule(1, "ssh", ["n-corp"], ["n-dc"], ["s-ssh"]),
                 fx._rule(2, "ssh and https", ["n-corp"], ["n-dc"], ["s-ssh", "s-https"]),
                 _cleanup(3)])
    assert "shadowed" not in [c.check for c in _entry(r, 2).checks]


def test_a_fully_covered_rule_is_shadowed() -> None:
    r = _review([fx._rule(1, "ssh", ["n-corp"], ["n-dc"], ["s-ssh"]),
                 fx._rule(2, "ssh again", ["n-corp"], ["n-dc"], ["s-ssh"]),
                 _cleanup(3)])
    c = next(c for c in _entry(r, 2).checks if c.check == "shadowed")
    assert c.evidence["covered_by_rule"] == 1 and c.evidence["covered_by_rules"] == [1]
    assert "shadowed_record" not in c.evidence


def test_grants_covered_by_different_rules_name_every_coverer() -> None:
    r = _review([fx._rule(1, "ssh", ["n-corp"], ["n-dc"], ["s-ssh"]),
                 fx._rule(2, "https", ["n-corp"], ["n-dc"], ["s-https"]),
                 fx._rule(3, "both", ["n-corp"], ["n-dc"], ["s-ssh", "s-https"]),
                 _cleanup(4)])
    c = next(c for c in _entry(r, 3).checks if c.check == "shadowed")
    assert c.evidence["covered_by_rules"] == [1, 2] and c.evidence["covered_by_rule"] == 1
    assert "rules 1, 2" in c.title


def test_the_package_removal_names_every_coverer() -> None:
    rules = [fx._rule(1, "https", ["n-dc"], ["h-web1"], ["s-https"]),
             fx._rule(2, "dns", ["n-dc"], ["h-web1"], ["s-dns"]),
             fx._rule(3, "both", ["n-dc"], ["h-web1"], ["s-https", "s-dns"]),
             _cleanup(4)]
    p = _parsed(rules)
    r = review(p)
    pkg = draft(json.loads(json.dumps(r.to_jsonable())), json.loads(json.dumps(p.to_jsonable())))
    item = next(i for i in pkg["items"] if i["rule_number"] == 3)
    assert item["proposal"] == "remove", item
    assert "rules 1, 2 above it already allow everything" in item["rationale"]


def test_a_truncated_rule_is_never_claimed_shadowed(monkeypatch) -> None:
    monkeypatch.setattr(cp, "MAX_GRANTS_PER_RULE", 1)
    r = _review([fx._rule(1, "ssh", ["n-corp"], ["n-dc"], ["s-ssh"]),
                 fx._rule(2, "ssh and https", ["n-corp"], ["n-dc"], ["s-ssh", "s-https"]),
                 _cleanup(3)])
    e = _entry(r, 2)
    assert "shadowed" not in [c.check for c in e.checks]
    assert any("only the first 1 are analysed" in x for x in e.limitations)


def _partly_rules():
    return [fx._rule(1, "https", ["n-dc"], ["h-web1"], ["s-https"]),
            fx._rule(2, "block dns", ["n-dc"], ["h-web1"], ["s-dns"], action="act-drop"),
            fx._rule(3, "https dns ssh", ["n-dc"], ["h-web1"], ["s-https", "s-dns", "s-ssh"]),
            _cleanup(4)]


def test_a_partly_covered_rule_says_which_grants_are_taken_and_by_what() -> None:
    r = _review(_partly_rules())
    e = _entry(r, 3)
    assert e.coverage["grants"] == 3 and e.coverage["covered"] == 2 and e.coverage["by_rules"] == [1, 2]
    taken = {g["service"]: (g["by_rule"], g["by_action"]) for g in e.coverage["covered_grants"]}
    assert taken == {"tcp/443": (1, "allow"), "udp/53": (2, "deny")}
    assert r.effective_policy[0]["partly_covered"] == [3] and r.stats["rules_partly_covered"] == 1
    assert 3 in r.effective_policy[0]["effective_allow"]                  # still carries ssh


def test_a_shadowed_rule_carries_no_partial_coverage() -> None:
    r = _review([fx._rule(1, "https", ["n-dc"], ["h-web1"], ["s-https"]),
                 fx._rule(2, "https again", ["n-dc"], ["h-web1"], ["s-https"]),
                 _cleanup(3)])
    assert _entry(r, 2).coverage is None and r.stats["rules_partly_covered"] == 0
