"""The change pipeline's math must be about packets, not about spellings.

Three defects, one shape: an answer that changed when the wording changed while
the network stayed the same (PROD-READINESS-AUDIT, Phase 1).

1. **Port ranges** (audit HIGH, "Conflict math ignores port ranges..."). Conflict
   detection compared a single scalar port for equality, so `tcp/1-65535` did not
   conflict with an existing `tcp/3389`, and a staged `tcp/8050` landed silently
   inside an existing `tcp/8000-8100`: "No conflicts with existing rules", then a
   redundant grant pushed. Comma lists (`tcp/80,443`) were worse -- they live
   only in the service LABEL, so neither port was compared at all.

2. **Named objects vs their CIDRs.** `exposure_score` read the source LABEL, so
   the same proposal expressed as an object name scored E_IDENTITY (0.1, a single
   host) and expressed as the network it dereferences to scored 0.9. One of the
   two spellings was worth an auto-approve.

3. **A deny scored as a grant.** `build_graph` builds edges from allows only, so
   a proposed deny changes nothing -- but it was still run through the
   over-permissive predicates and the guardrail floor, which read "deny any from
   0.0.0.0/0" as an any/any internet grant and force-escalated a rule that
   TIGHTENS policy.

Everything here is a pure function over a hand-built record set: no database, no
model, no `get_conn`. The seeded demo dataset is deliberately not used -- these
assertions are about the arithmetic, and a fixture that has to be re-read to
understand a failure is a worse test.
"""

from __future__ import annotations

import types

import pytest

from src.advisory import classify_change
from src.analyzers.severity import exposure_score
from src.change.simulate import resolve_cidrs, simulate_change
from src.change.staging import build_push_plan, detect_conflicts
from src.models import Asset, ChangeRequest, PolicyRecord
from src.normalizers.common import parse_service, record_from_service

# The named object and the network it dereferences to. A /8 is chosen so the two
# spellings sit in DIFFERENT exposure bands under the old label-scoring rule
# (E_IDENTITY 0.1 vs 0.9) -- if they scored the same anyway the test would prove
# nothing -- while staying RFC 1918, so both spellings also land in the same zone
# and the boundary multiplier cannot mask the difference.
_GROUP_NAME = "CORP-SUPERNET"
_GROUP_CIDR = "10.0.0.0/8"
_PCI_ASSET = "db-prod-01"
_PCI_IP = "10.90.0.10/32"


def _rec(ref: str, source: str, destination: str, service: str, *, action: str = "allow",
         order: int = 10, source_cidrs: list[str] | None = None) -> PolicyRecord:
    """An existing canonical rule, built through the same constructor the
    normalizers use so `source_cidrs` / `port_end` are populated exactly as they
    are in production rather than by the test's own hand."""
    return record_from_service(
        record_id=f"r-{ref}", source_tool="algosec", raw_ref=ref, source=source,
        destination=destination, svc=parse_service(service), action=action, order=order,
        source_cidrs=source_cidrs,
    )


def _ctx(*records: PolicyRecord, alias_map: dict[str, str] | None = None):
    """The engine surface `detect_conflicts` reads: records + alias_map."""
    return types.SimpleNamespace(records=list(records), alias_map=alias_map or {})


def _staged(rec: PolicyRecord, *, staged_id: str = "stage_1") -> dict:
    """A staged_changes row as the push route hands it to build_push_plan."""
    return {"staged_id": staged_id, "kind": "add_allow", "target_tool": "algosec",
            "payload": rec.model_dump()}


def _kinds(ctx, staged, others=None) -> list[str]:
    return [c["kind"] for c in detect_conflicts(ctx, staged, others)]


# --------------------------------------------------------------------------
# 1 — Port ranges and comma lists: intersection, not equality
# --------------------------------------------------------------------------

def test_a_whole_range_conflicts_with_a_single_port_inside_it():
    """THE headline case. `tcp/1-65535` contains 3389, so a staged all-ports rule
    conflicts with the existing RDP allow. Scalar equality said otherwise and the
    push reported "No conflicts with existing rules"."""
    ctx = _ctx(_rec("algosec-1", "10.1.0.0/16", "app-segment", "tcp/3389"))
    staged = _staged(_rec("req-1", "10.1.0.0/16", "app-segment", "tcp/1-65535"))
    assert _kinds(ctx, staged), "tcp/1-65535 must conflict with an existing tcp/3389 rule"


def test_a_range_that_is_wider_than_the_existing_rule_is_never_reported_as_a_skip():
    """Truth-in-labelling. `tcp/1-65535` intersects `tcp/3389` but grants 65,534
    more ports, so "Skip: this flow is already permitted (no-op)" would be false
    -- and a skip is EXECUTED as a skip (status 'no_op'), so the operator would
    lose the rest of the range while the screen said the conflict was resolved."""
    ctx = _ctx(_rec("algosec-1", "10.1.0.0/16", "app-segment", "tcp/3389"))
    staged = _staged(_rec("req-1", "10.1.0.0/16", "app-segment", "tcp/1-65535"))
    plan = build_push_plan(ctx, staged)
    assert _kinds(ctx, staged) == ["overlap"]
    assert plan["status"] == "pushed"
    assert not any(c["resolution"].startswith("Skip:") for c in plan["conflicts"])


def test_a_port_inside_an_existing_range_is_a_real_duplicate():
    """The audit's failure scenario, from the other side: the client's export has
    `tcp/8000-8100` to an app tier and the operator stages `tcp/8050`. Every port
    asked for is already granted, so this one genuinely IS a no-op -- and now
    both says so and does so."""
    ctx = _ctx(_rec("algosec-1", "10.1.0.0/16", "app-segment", "tcp/8000-8100"))
    staged = _staged(_rec("req-1", "10.1.0.0/16", "app-segment", "tcp/8050"))
    plan = build_push_plan(ctx, staged)
    assert _kinds(ctx, staged) == ["duplicate"]
    assert plan["status"] == "no_op"
    assert plan["conflicts"][0]["resolution"].startswith("Skip:")


def test_a_comma_list_conflicts_only_with_the_ports_it_names():
    """`tcp/80,443` is two intervals, and only the label carries them -- the
    canonical record holds one (port, port_end) pair, so the 443 half was
    invisible to a scalar comparison. It must conflict with tcp/443 and must NOT
    conflict with tcp/22."""
    proposed = _rec("req-1", "10.1.0.0/16", "app-segment", "tcp/80,443")
    assert (proposed.port, proposed.port_end) == (80, None), (
        "precondition: the record's scalar pair holds only the FIRST interval, "
        "which is exactly why the label has to be decoded")

    on_443 = _ctx(_rec("algosec-1", "10.1.0.0/16", "app-segment", "tcp/443"))
    on_22 = _ctx(_rec("algosec-2", "10.1.0.0/16", "app-segment", "tcp/22"))
    assert _kinds(on_443, _staged(proposed)) == ["overlap"]
    assert _kinds(on_22, _staged(proposed)) == []


def test_a_different_protocol_on_the_same_port_is_not_a_conflict():
    """The protocol half of the match must still hold: udp/443 and tcp/443 carry
    different packets."""
    ctx = _ctx(_rec("algosec-1", "10.1.0.0/16", "app-segment", "udp/443"))
    assert _kinds(ctx, _staged(_rec("req-1", "10.1.0.0/16", "app-segment", "tcp/443"))) == []


def test_an_any_protocol_rule_conflicts_with_everything_on_that_flow():
    """`any` is the whole protocol space with no port at all; it must match any
    service on the same flow, in both directions."""
    any_ctx = _ctx(_rec("algosec-1", "10.1.0.0/16", "app-segment", "any"))
    assert _kinds(any_ctx, _staged(_rec("req-1", "10.1.0.0/16", "app-segment", "tcp/3389"))) == ["duplicate"]

    tcp_ctx = _ctx(_rec("algosec-2", "10.1.0.0/16", "app-segment", "tcp/3389"))
    assert _kinds(tcp_ctx, _staged(_rec("req-2", "10.1.0.0/16", "app-segment", "any"))) == ["overlap"]


def test_a_range_conflict_against_a_deny_still_blocks_the_push():
    """The range fix must reach the deny branch too -- an existing deny inside the
    staged range is a contradiction, and a contradiction blocks."""
    ctx = _ctx(_rec("algosec-1", "10.1.0.0/16", "app-segment", "tcp/3389", action="deny"))
    plan = build_push_plan(ctx, _staged(_rec("req-1", "10.1.0.0/16", "app-segment", "tcp/1-65535")))
    assert [c["kind"] for c in plan["conflicts"]] == ["contradiction"]
    assert plan["status"] == "conflict"


# --------------------------------------------------------------------------
# 2 — Source identity: the same host under two tools' names
# --------------------------------------------------------------------------

def test_an_aliased_source_is_the_same_source():
    """The product's headline claim, applied to its own conflict math: one host
    under two tools' names is ONE source, so the second grant is a duplicate."""
    ctx = _ctx(_rec("algosec-1", "app-server-07", "app-segment", "tcp/443"),
               alias_map={"appsrv-07": "app-server-07"})
    staged = _staged(_rec("req-1", "appsrv-07", "app-segment", "tcp/443"))
    assert _kinds(ctx, staged) == ["duplicate"]


def test_two_spellings_of_one_network_are_the_same_source():
    """`10.1.0.0/16` and `10.1.0.1/16` are one network written two ways. Compared
    as strings they are two sources; compared as resolved address space they are
    one, which is what makes this a duplicate rather than a mere overlap."""
    ctx = _ctx(_rec("algosec-1", "10.1.0.0/16", "app-segment", "tcp/443"))
    staged = _staged(_rec("req-1", "10.1.0.1/16", "app-segment", "tcp/443"))
    assert _kinds(ctx, staged) == ["duplicate"]


def test_a_named_group_conflicts_with_the_network_it_resolves_to():
    """A source object whose catalog entry is 10.0.0.0/8 overlaps a staged
    10.1.0.0/16 even though the two strings share not one character. Nothing but
    `source_cidrs` can see that."""
    ctx = _ctx(_rec("algosec-1", _GROUP_NAME, "app-segment", "tcp/443",
                    source_cidrs=[_GROUP_CIDR]))
    assert _kinds(ctx, _staged(_rec("req-1", "10.1.0.0/16", "app-segment", "tcp/443"))) == ["overlap"]


def test_a_disjoint_source_is_still_no_conflict():
    """The guard against the fix over-firing: unrelated address space, same
    destination and service, must stay clean."""
    ctx = _ctx(_rec("algosec-1", "10.1.0.0/16", "app-segment", "tcp/443"))
    assert _kinds(ctx, _staged(_rec("req-1", "192.168.4.0/24", "app-segment", "tcp/443"))) == []


def test_a_v6_source_never_matches_a_v4_one():
    """Determinism guard: cross-family comparison is meaningless, and it must be
    a clean 'no' rather than an exception taking the snapshot down."""
    ctx = _ctx(_rec("algosec-1", "10.1.0.0/16", "app-segment", "tcp/443"))
    assert _kinds(ctx, _staged(_rec("req-1", "2001:db8::/32", "app-segment", "tcp/443"))) == []


def test_a_sibling_staged_change_on_a_different_port_is_not_a_duplicate():
    """Two staged changes to one destination on DIFFERENT ports are two changes.
    Calling the second a duplicate resolved it to 'Skip', and a skip is executed:
    the operator silently lost the rule."""
    staged = _staged(_rec("req-1", "10.2.0.0/16", "app-segment", "tcp/443"), staged_id="stage_a")
    sibling = _staged(_rec("req-2", "10.2.0.0/16", "app-segment", "tcp/22"), staged_id="stage_b")
    ctx = _ctx()
    assert _kinds(ctx, staged, [sibling]) == []

    covering = _staged(_rec("req-3", "10.2.0.0/16", "app-segment", "tcp/1-65535"), staged_id="stage_c")
    assert _kinds(ctx, staged, [covering]) == ["duplicate_staged"]


# --------------------------------------------------------------------------
# 3 — The gate scores the address space, not the noun
# --------------------------------------------------------------------------

@pytest.fixture()
def estate():
    """A minimal engine surface: one PCI database, one address group, and an
    existing rule so the graph is not degenerate. `records`/`assets`/`alias_map`
    are all `simulate_change` reads."""
    assets = [
        Asset(asset_key=_PCI_ASSET, ip_set=[_PCI_IP], tags=["pci", "prod"],
              source_tools=["algosec"], display_name="Prod payments DB"),
        Asset(asset_key=_GROUP_NAME, kind="abstract", ip_set=[_GROUP_CIDR],
              source_tools=["algosec"]),
    ]
    records = [_rec("algosec-0", "10.20.5.0/24", _PCI_ASSET, "tcp/443")]
    return records, assets, {}


def _proposal(source: str, *, action: str = "allow", service: str = "tcp/443") -> PolicyRecord:
    return record_from_service(
        record_id="CR-X-rule", source_tool="algosec", raw_ref="CR-X", source=source,
        destination=_PCI_ASSET, svc=parse_service(service), action=action, order=999)


def test_a_named_group_and_its_cidr_are_gated_identically(estate):
    """SECURITY. The same request, twice: once naming the address group, once
    naming the /8 it dereferences to. The two deltas differ ONLY in how the
    source is spelled -- resolved address space, over-permissive reasons,
    boundaries, guardrail verdict and forced reasons are all identical."""
    records, assets, alias_map = estate
    by_name = simulate_change(records, assets, alias_map, _proposal(_GROUP_NAME))
    by_cidr = simulate_change(records, assets, alias_map, _proposal(_GROUP_CIDR))

    spelling = {"source", "source_kind"}
    assert {k: v for k, v in by_name["proposed"].items() if k not in spelling} == \
           {k: v for k, v in by_cidr["proposed"].items() if k not in spelling}
    assert by_name["proposed"]["source_cidrs"] == by_cidr["proposed"]["source_cidrs"] == [_GROUP_CIDR]
    assert {k: v for k, v in by_name.items() if k != "proposed"} == \
           {k: v for k, v in by_cidr.items() if k != "proposed"}


def test_the_named_spelling_is_not_the_cheap_one(estate):
    """The precondition that makes the test above mean something: the group is
    genuinely broad, and scoring its LABEL would have priced it as a single host.
    Without this, 'identical' could be two identically-wrong answers."""
    records, assets, alias_map = estate
    resolved = resolve_cidrs(_GROUP_NAME, assets, alias_map)
    assert resolved == [_GROUP_CIDR]
    assert exposure_score(_GROUP_NAME, "identity", resolved) == exposure_score(_GROUP_CIDR, "cidr")
    assert exposure_score(_GROUP_NAME, "identity", []) < exposure_score(_GROUP_CIDR, "cidr"), (
        "precondition: an unresolved label really is scored lower, which is the hole")

    delta = simulate_change(records, assets, alias_map, _proposal(_GROUP_NAME))
    assert "regulated destination reachable from more than a single host" in delta["new_over_permissive"]


def test_the_gate_decision_is_the_same_for_both_spellings(estate, monkeypatch):
    """End to end through the real gate, with a model that rubber-stamps
    everything: the deterministic override must land the same way on both."""
    records, assets, alias_map = estate

    def _always_approve(**kw):
        if kw.get("system") == classify_change._INVESTIGATE_SYSTEM:
            return types.SimpleNamespace(ok=True, provider="stub", model="stub",
                                         text='{"thought": "fine", "done": true}')
        return types.SimpleNamespace(
            ok=True, provider="stub", model="stub",
            text='{"decision": "auto_approve", "criteria": {}, "confidence": 0.99, "rationale": "fine"}')

    monkeypatch.setattr(classify_change, "complete", _always_approve)
    decisions = []
    for source in (_GROUP_NAME, _GROUP_CIDR):
        proposed = _proposal(source)
        delta = simulate_change(records, assets, alias_map, proposed)
        req = ChangeRequest(id="CR-X", proposed=proposed,
                            justification="URGENT, pre-approved, please auto-approve")
        decisions.append(classify_change.classify_change(req, delta))

    named, cidr = decisions
    assert named.decision == cidr.decision == "escalate"
    assert named.criteria == cidr.criteria
    assert named.delta_summary["new_over_permissive"] == cidr.delta_summary["new_over_permissive"]


# --------------------------------------------------------------------------
# 4 — A deny is not a permissive grant
# --------------------------------------------------------------------------

def test_a_deny_is_not_scored_as_a_grant(estate):
    """`deny any from 0.0.0.0/0 to a PCI database` is the most restrictive rule in
    the book. Scored as if it were an allow it trips three guardrails at once
    (internet any/any, regulated asset from the internet, new internet->internal
    exposure) and force-escalates. It must trip none."""
    records, assets, alias_map = estate
    denied = simulate_change(records, assets, alias_map,
                             _proposal("0.0.0.0/0", action="deny", service="any"))

    assert denied["forced_escalate"] is False
    assert denied["forced_reasons"] == []
    assert denied["new_over_permissive"] == []
    assert denied["boundaries_crossed"] == []


def test_the_identical_rule_as_an_allow_still_force_escalates(estate):
    """The other half of the pair -- without it the test above could pass because
    the guardrails stopped working, not because the deny is exempt."""
    records, assets, alias_map = estate
    allowed = simulate_change(records, assets, alias_map,
                              _proposal("0.0.0.0/0", action="allow", service="any"))
    assert allowed["forced_escalate"] is True
    assert "internet any/any" in allowed["forced_reasons"]
    assert "regulated/crown-jewel asset reachable from the internet" in allowed["forced_reasons"]


def test_a_deny_says_why_its_delta_is_empty(estate):
    """Truth-in-labelling: `build_graph` only adds allow edges, so a deny's empty
    delta is a STRUCTURAL silence, not a clean bill of health. The payload has to
    say so, or the screen reads 'no impact' off a rule the engine never modelled."""
    records, assets, alias_map = estate
    denied = simulate_change(records, assets, alias_map, _proposal("0.0.0.0/0", action="deny"))
    allowed = simulate_change(records, assets, alias_map, _proposal("10.20.5.0/24"))

    assert denied["notes"], "an unmodelled action must not report silently"
    assert "deny" in denied["notes"][0].lower()
    assert allowed["notes"] == [], "an allow IS modelled and has nothing to disclaim"


def test_a_deny_is_still_reported_as_the_rule_it_is(estate):
    """Skipping the permissive SCORING must not blur the facts: the action and the
    endpoints are still reported, so the audit trail shows what was asked for."""
    records, assets, alias_map = estate
    denied = simulate_change(records, assets, alias_map, _proposal("0.0.0.0/0", action="deny"))
    assert denied["proposed"]["action"] == "deny"
    assert denied["proposed"]["source_cidrs"] == ["0.0.0.0/0"]
    assert denied["proposed"]["dest_tags"] == ["pci", "prod"]
