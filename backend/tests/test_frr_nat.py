"""NAT in the review: context on access rules and the NAT hygiene checks."""

from __future__ import annotations

from src.frr.review import review
from src.normalizers import checkpoint as cp
from tests import cp_fixture as fx


def _nat_rule(n, src, dst, svc, tdst, *, method="static", enabled=True, install=("pt",)):
    return {"type": "nat-rule", "uid": f"nat-{n}", "rule-number": n, "enabled": enabled, "method": method,
            "auto-generated": False, "original-source": src, "original-destination": dst,
            "original-service": svc, "translated-source": "Original", "translated-destination": tdst,
            "translated-service": "Original", "install-on": list(install)}


def _run(extra_nat=(), replace=None, drop_any_any=False):
    e = fx.export()
    if drop_any_any:                       # rule 1 reaches every address, so nothing is orphaned while it lives
        e["access_layers"][0]["rulebase"][0]["rulebase"][0]["enabled"] = False
    # A host no access rule mentions, for the orphan case.
    e["nat_packages"][0]["objects-dictionary"] = fx.OBJECTS + [
        {"uid": "h-island", "name": "island-01", "type": "host", "ipv4-address": "10.77.0.1"}]
    rb = e["nat_packages"][0]["rulebase"]
    if replace is not None:
        rb[:] = replace
    rb += list(extra_nat)
    e["nat_packages"][0].update({"to": len(rb), "total": len(rb)})
    r = review(cp.parse(e))
    return {f.check: f for f in r.nat_findings}, {x.number: x for x in r.register}, r


def test_internet_exposure_names_the_host_behind_static_nat() -> None:
    f, reg, r = _run()
    x = f["nat_internet_exposure"]
    assert x.band == "high" and x.nat_number == 2 and x.evidence["access_rules"] == [1, 2, 3]
    assert x.evidence["translated_destination_cidrs"] == ["10.10.1.11/32"]
    assert [c["nat_rule"] for c in reg[2].nat] == [2]
    assert any("not rewritten through NAT" in l for l in r.limitations)


def test_hide_nat_is_context_free() -> None:
    f, reg, _ = _run()
    assert all(c["nat_rule"] != 1 for e in reg.values() for c in e.nat)


def test_a_nat_rule_covered_by_an_earlier_one_is_shadowed() -> None:
    # Fixture NAT rule 2 is installed on edge-gw-1; rule 3 on the same gateway is covered by it.
    f, _, _ = _run([_nat_rule(3, fx.ANY, "h-web1", "s-https", "h-web2", install=["gw-1"])])
    assert f["nat_shadowed"].nat_number == 3 and f["nat_shadowed"].evidence["covered_by_nat_rule"] == 2


def test_a_gateway_specific_nat_rule_does_not_shadow_one_on_all_gateways() -> None:
    f, _, _ = _run([_nat_rule(3, fx.ANY, "h-web1", "s-https", "h-web2")])
    assert "nat_shadowed" not in f


def test_a_narrower_earlier_nat_rule_does_not_shadow() -> None:
    narrow_first = [_nat_rule(1, "n-corp", "h-web1", "s-https", "h-web2"),
                    _nat_rule(2, fx.ANY, "h-web1", "s-https", "h-web2")]
    f, _, _ = _run(replace=narrow_first)
    assert "nat_shadowed" not in f


def test_nat_on_other_gateways_does_not_shadow() -> None:
    f, _, _ = _run(replace=[_nat_rule(1, fx.ANY, "h-web1", "s-https", "h-web2", install=["gw-1"]),
                            _nat_rule(2, fx.ANY, "h-web1", "s-https", "h-web2")])
    assert "nat_shadowed" not in f


def test_disabled_and_orphan_nat() -> None:
    f, _, _ = _run(replace=[_nat_rule(1, fx.ANY, "h-web1", "s-https", "h-web2", enabled=False),
                            _nat_rule(2, fx.ANY, "r-jump", "s-ssh", "h-island")],    # nothing reaches either
                    drop_any_any=True)
    assert f["nat_disabled"].nat_number == 1
    assert f["nat_orphan"].nat_number == 2 and "jump-range" in f["nat_orphan"].title


def test_review_without_nat_has_no_nat_noise() -> None:
    e = fx.export()
    e.pop("nat_packages")
    r = review(cp.parse(e))
    assert r.nat_findings == [] and r.stats["nat"]["rules"] == 0
    assert not any("NAT" in l for l in r.limitations)
