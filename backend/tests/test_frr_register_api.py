"""Register CSV download and review comparison, on a real database."""

from __future__ import annotations

import csv
import io

from tests.test_frr_intake import (  # noqa: F401  (env is a fixture)
    ANALYST, _fresh, _settle, _upload, env, pytestmark,
)
from tests import cp_fixture as fx


def _accepted(c, doc) -> str:
    return _settle(c, _upload(c, doc).json()["export"]["export_id"])["export_id"]


def test_csv_streams_the_filtered_register(env) -> None:
    c = env
    eid = _accepted(c, _fresh())
    r = c.get(f"/api/exports/{eid}/register.csv", headers=ANALYST)
    assert r.status_code == 200 and r.headers["content-type"].startswith("text/csv")
    assert "network-layer-register.csv" in r.headers["content-disposition"]
    rows = list(csv.DictReader(io.StringIO(r.text)))
    assert len(rows) == 7 and rows[0]["worst_band"] == "critical"
    by_num = {x["rule_number"]: x for x in rows}
    assert by_num["3"]["hit_count"] == "0" and "unused" in by_num["3"]["checks"]
    crit = list(csv.DictReader(io.StringIO(c.get(f"/api/exports/{eid}/register.csv",
                                                 params={"band": "critical"}, headers=ANALYST).text)))
    assert {x["rule_number"] for x in crit} == {"1", "5"}
    every = list(csv.DictReader(io.StringIO(c.get(f"/api/exports/{eid}/register.csv",
                                                  params={"flagged_only": "false"}, headers=ANALYST).text)))
    assert len(every) == 10 and any(x["nat"].startswith("NAT 2") for x in every)


def test_compare_reports_exactly_what_changed(env) -> None:
    c = env
    base = _accepted(c, _fresh())
    nxt = _fresh()
    rb = nxt["access_layers"][0]["rulebase"]
    admin = rb[2]["rulebase"]
    admin.pop(next(i for i, r in enumerate(admin) if r["rule-number"] == 6))          # rule 6 removed
    rb[1]["rulebase"][1]["hits"] = {"value": 120, "last-date": {"iso-8601": nxt["exported_at"]}}  # rule 3 now used
    admin.append({"type": "access-rule", "uid": "rule-11", "rule-number": 11, "name": "new rdp", "enabled": True,
                  "source": [fx.ANY], "destination": ["n-dc"], "service": ["s-rdp"], "action": "act-accept",
                  "time": [fx.ANY], "install-on": ["pt"],
                  "hits": {"value": 5, "last-date": {"iso-8601": nxt["exported_at"]}}})       # new critical rule
    nxt["access_layers"][0].update({"to": 11, "total": 11})
    cur = _accepted(c, nxt)
    d = c.get(f"/api/exports/{cur}/compare", params={"baseline": base}, headers=ANALYST).json()
    s = d["summary"]
    assert s["rules_added"] == 1 and s["rules_removed"] == 1
    new = {(x["rule_uid"], x["check"]) for x in d["new_findings"]}
    resolved = {(x["rule_uid"], x["check"]) for x in d["resolved_findings"]}
    assert ("rule-11", "admin_port_exposed") in new
    assert next(x for x in d["new_findings"] if x["rule_uid"] == "rule-11")["new_rule"] is True
    assert ("rule-6", "disabled") in resolved
    assert next(x for x in d["resolved_findings"] if x["rule_uid"] == "rule-6")["rule_removed"] is True
    assert ("rule-3", "unused") in resolved
    assert d["new_findings"][0]["band"] == "critical"                                # worst first
    assert s["findings_new"] == len(d["new_findings"]) and s["findings_resolved"] == len(d["resolved_findings"])


def test_compare_needs_two_accepted_exports(env) -> None:
    c = env
    eid = _accepted(c, _fresh())
    assert c.get(f"/api/exports/{eid}/compare", params={"baseline": "not-a-uuid"}, headers=ANALYST).status_code == 404
    bad = _settle(c, _upload(c, _fresh(exported_at="2020-01-01T00:00:00Z")).json()["export"]["export_id"])["export_id"]
    assert c.get(f"/api/exports/{eid}/compare", params={"baseline": bad}, headers=ANALYST).status_code == 409
    d = c.get(f"/api/exports/{eid}/compare", params={"baseline": eid}, headers=ANALYST).json()
    assert d["summary"] == {"rules_added": 0, "rules_removed": 0, "findings_new": 0, "findings_resolved": 0,
                            "band_changes": 0}


def test_partly_covered_rules_are_an_indexed_filter_and_a_csv_column(env) -> None:
    c = env
    rules = [fx._rule(1, "https", ["n-dc"], ["h-web1"], ["s-https"]),
             fx._rule(2, "https dns", ["n-dc"], ["h-web1"], ["s-https", "s-dns"]),
             fx._rule(3, "cleanup", [fx.ANY], [fx.ANY], [fx.ANY], action="act-drop")]
    doc = _fresh()
    doc["access_layers"][0].update(rulebase=rules, to=3, total=3)
    eid = _accepted(c, doc)
    page = c.get(f"/api/exports/{eid}/review", params={"partly_covered": "true"}, headers=ANALYST).json()
    assert page["total"] == 1 and page["items"][0]["number"] == 2
    assert page["items"][0]["coverage"]["covered"] == 1
    assert page["stats"]["rules_partly_covered"] == 1
    assert page["effective_policy"][0]["partly_covered_count"] == 1
    rows = list(csv.DictReader(io.StringIO(c.get(f"/api/exports/{eid}/register.csv",
                                                 params={"partly_covered": "true"}, headers=ANALYST).text)))
    assert [x["rule_number"] for x in rows] == ["2"]
    assert rows[0]["covered_above"].startswith("1 of 2 grants matched above by rule(s) 1")
