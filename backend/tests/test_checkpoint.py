"""The Check Point parser: what it emits, what it refuses, what it approximates."""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from src.frr.rulebase import ExportRejected
from src.normalizers import checkpoint as cp
from tests import cp_fixture as fx


@pytest.fixture(scope="module")
def parsed():
    return cp.parse(fx.export())


def rule(parsed, n):
    return next(r for r in parsed.rules if r.number == n)


def grants(parsed, n):
    ids = set(rule(parsed, n).record_ids)
    return [r for r in parsed.result.records if r.id in ids]


def test_every_rule_is_inventoried_with_its_section(parsed) -> None:
    assert [r.number for r in parsed.rules] == list(range(1, 11))
    assert rule(parsed, 2).section == "Inbound" and rule(parsed, 10).section is None
    assert parsed.layers == ["Network"]
    assert parsed.exported_at == datetime(2026, 10, 27, 12, tzinfo=timezone.utc)


def test_any_any_is_one_grant_over_the_whole_space(parsed) -> None:
    (g,) = grants(parsed, 1)
    assert g.source == g.destination == "0.0.0.0/0" and g.protocol == "any"
    assert g.action == "allow" and g.order == 1


def test_groups_expand_per_member_space_and_nest(parsed) -> None:
    (g,) = grants(parsed, 2)
    assert g.destination == "web-farm" and g.dest_cidrs == ["10.10.1.10/32", "10.10.1.11/32"]
    assert g.service == "tcp/443" and g.port == 443


def test_a_service_group_expands_to_one_grant_per_service(parsed) -> None:
    gs = grants(parsed, 4)
    assert sorted(g.port for g in gs) == [22, 3389]
    assert all(g.source_cidrs == ["10.20.0.0/16"] and g.dest_cidrs == ["10.30.0.0/24"] for g in gs)


def test_a_negated_cell_is_read_as_any_and_says_so(parsed) -> None:
    (g,) = grants(parsed, 5)
    assert g.source == "0.0.0.0/0"
    assert any("negated" in l for l in rule(parsed, 5).limitations)


def test_a_disabled_rule_grants_nothing_but_stays_in_the_inventory(parsed) -> None:
    r = rule(parsed, 6)
    assert r.enabled is False and r.record_ids == []


def test_an_expired_rule_grants_nothing_and_records_its_expiry(parsed) -> None:
    r = rule(parsed, 7)
    assert r.expires_at == datetime(2026, 1, 31, tzinfo=timezone.utc) and r.record_ids == []


def test_a_time_bound_rule_still_in_its_window_is_live(parsed) -> None:
    r = rule(parsed, 8)
    assert r.expires_at.year == 2027 and len(r.record_ids) == 1


def test_application_rules_are_broadened_not_dropped(parsed) -> None:
    r = rule(parsed, 9)
    (g,) = grants(parsed, 9)
    assert r.action == "allow" and r.action_raw == "Ask"
    assert g.protocol == "any" and g.source == "Admins" and g.source_cidrs == []
    assert any("application Facebook" in l for l in r.limitations)


def test_cleanup_drop_is_a_deny(parsed) -> None:
    (g,) = grants(parsed, 10)
    assert g.action == "deny"


def test_hit_counts_are_carried_and_absence_is_not_zero(parsed) -> None:
    assert rule(parsed, 2).hit_count == 15200
    assert rule(parsed, 2).last_hit == datetime(2026, 10, 26, 9, tzinfo=timezone.utc)
    assert rule(parsed, 3).hit_count == 0
    e = fx.export()
    for item in e["access_layers"][0]["rulebase"]:
        for r in item.get("rulebase", [item]):
            r.pop("hits", None)
    p = cp.parse(e)
    assert all(r.hit_count is None for r in p.rules)
    assert any("hit counts absent" in l for l in p.limitations)


def test_address_ranges_summarise_to_cidrs() -> None:
    objs = cp._Objects(fx.OBJECTS)
    cidrs, warnings = objs.address_cidrs("r-jump")
    assert cidrs == ["10.40.0.10/31", "10.40.0.12/30", "10.40.0.16/30", "10.40.0.20/32"]
    assert warnings == []


def test_nat_rules_are_parsed_with_their_address_space(parsed) -> None:
    hide, static = parsed.nat
    assert hide.method == "hide" and hide.original_source_cidrs == ["10.20.0.0/16"]
    assert static.method == "static" and static.auto_generated
    assert static.original_destination_cidrs == ["10.10.1.10/32"]
    assert static.translated_destination_cidrs == ["10.10.1.11/32"]


def test_a_missing_object_is_unresolved_never_a_host() -> None:
    e = fx.export()
    e["access_layers"][0]["rulebase"][1]["rulebase"][0]["source"] = ["ghost-uid"]
    p = cp.parse(e)
    (g,) = grants(p, 2)
    assert g.source_unresolved is True and g.source_cidrs == []
    assert any("not in the export" in l for l in rule(p, 2).limitations)


def test_records_are_valid_for_the_engine(parsed) -> None:
    ids = [r.id for r in parsed.result.records]
    assert len(ids) == len(set(ids))
    assert parsed.summary()["grants"] == len(ids) and parsed.summary()["nat_rules"] == 2


def test_a_huge_rule_is_capped_and_limited(monkeypatch) -> None:
    monkeypatch.setattr(cp, "MAX_GRANTS_PER_RULE", 1)
    p = cp.parse(fx.export())
    assert len(rule(p, 4).record_ids) == 1
    assert any("expands to 2 grants" in l for l in rule(p, 4).limitations)


# --- refusals -------------------------------------------------------------------

@pytest.mark.parametrize("mutate, message", [
    (lambda e: e["access_layers"][0].pop("rulebase"), "no 'rulebase' list"),
    (lambda e: e["access_layers"][0].update(to=5, total=10), "one page"),
    (lambda e: e.update(access_layers=[]), "no access layer"),
    (lambda e: e["access_layers"][0].update(rulebase=[]), "contains no rules"),
    (lambda e: e["access_layers"][0]["rulebase"][-1].pop("action"), "no 'action'"),
    (lambda e: e["access_layers"][0]["rulebase"][-1].update(source=[]), "no 'source'"),
    (lambda e: e["nat_packages"][0].update(to=1, total=2), "NAT package Standard"),
])
def test_exports_that_would_misreport_are_refused(mutate, message) -> None:
    e = fx.export()
    mutate(e)
    with pytest.raises(ExportRejected, match=message):
        cp.parse(e)


def test_a_single_unbundled_response_is_accepted_without_age() -> None:
    single = fx.export()["access_layers"][0]
    p = cp.parse(single)
    assert len(p.rules) == 10 and p.exported_at is None
    assert any("export time unknown" in l for l in p.limitations)
