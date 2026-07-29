"""End-to-end tests for the four agentic capabilities.

Each agent is exercised on BOTH paths:
  - the deterministic fallback (model unavailable / bad output -> fail-closed), and
  - the model-driven agentic path (stubbed `complete` so no network is needed).

The invariant under test everywhere: the engine is the judge. A model proposal is
only honored if the deterministic engine proves it; otherwise the agent degrades to
the deterministic fallback (remediation, campaign) or escalates (classify).
"""

from __future__ import annotations

import json
import types

import pytest

from src.advisory import authoring, campaign, classify_change
from src.advisory import remediation as R
from src.analyzers.run_all import run
from src.change.requests import DEMO_REQUESTS
from src.change.simulate import simulate_change


@pytest.fixture(scope="module")
def eng():
    return run()


def _resp(payload, ok=True, provider="stub", model="stub"):
    text = payload if isinstance(payload, str) else json.dumps(payload)
    return types.SimpleNamespace(ok=ok, text=text, provider=provider, model=model)


def _dead(**_kw):
    return types.SimpleNamespace(ok=False, text="", provider="stub", model="stub", error="unreachable")


# --------------------------------------------------------------------------
# Agent 1 — Remediation loop (propose -> re-simulate -> revise -> certify)
# --------------------------------------------------------------------------

def _worst_cross_tool(eng):
    return next(f for f in eng.findings if f.type == "cross_tool_path")


def test_remediation_revises_until_clean(eng, monkeypatch):
    """A first proposal that does not resolve -> the engine verdict is fed back ->
    the second proposal is certified. `by=llm`, two attempts, trace shows both."""
    f = _worst_cross_tool(eng)
    seq = [
        {"fix_text": "scope it", "change": {"op": "scope_source", "target_ref": f.raw_refs[0],
                                            "new_source": "10.0.0.0/8"}},
        {"fix_text": "remove the crown-jewel hop", "change": {"op": "remove", "target_ref": f.raw_refs[-1]}},
    ]
    calls = {"n": 0}
    seen_feedback = {"got": False}

    def fake(**kw):
        i = calls["n"]; calls["n"] += 1
        if "STILL EXISTS" in kw.get("user", ""):
            seen_feedback["got"] = True
        return _resp(seq[min(i, len(seq) - 1)])

    monkeypatch.setattr(R, "complete", fake)
    res = R.draft(f, eng)
    assert res["by"] == "llm"
    assert res["attempts"] == 2
    assert res["validation"]["resolves"] is True
    assert not res["validation"].get("introduces_new_criticals")
    assert seen_feedback["got"], "the agent must see the engine's 'still reachable' verdict"
    assert len(res["trace"]) == 2


def test_remediation_falls_back_when_model_dead(eng, monkeypatch):
    """Model unreachable -> the deterministic surgical fix is used and proven."""
    f = _worst_cross_tool(eng)
    monkeypatch.setattr(R, "complete", _dead)
    res = R.draft(f, eng)
    assert res["validation"]["resolves"] is True
    assert "engine_fallback" in res["by"]
    assert res["change"]["op"] in ("remove", "scope_source", "restrict_service", "reorder_before")


def test_remediation_prefers_clean_over_dirty(eng, monkeypatch):
    """A proposal that resolves but opens a new critical is NOT accepted as clean; the
    loop revises (or falls back) so the delivered fix introduces no new critical."""
    f = next(fd for fd in eng.findings if fd.type == "over_permissive")
    # Always propose removing a *different* rule that doesn't resolve this finding,
    # forcing the loop to exhaust and fall back to the deterministic fix.
    other = next(r.raw_ref for r in eng.records if r.raw_ref not in f.raw_refs)
    monkeypatch.setattr(R, "complete", lambda **kw: _resp(
        {"fix_text": "x", "change": {"op": "remove", "target_ref": other}}))
    res = R.draft(f, eng)
    assert res["validation"]["resolves"] is True
    assert not res["validation"].get("introduces_new_criticals")


# --------------------------------------------------------------------------
# Agent 2 — Remediation Campaign (worst-first, cumulative, engine-proven)
# --------------------------------------------------------------------------

def test_campaign_drives_criticals_to_zero_offline(eng, monkeypatch):
    """With the model dead, the deterministic fixes still drive criticals to zero,
    monotonically, and every applied step is engine-proven on the cumulative state."""
    monkeypatch.setattr(R, "complete", _dead)
    res = campaign.plan(eng)
    traj = res["criticals_trajectory"]
    assert traj[0] == res["initial_counts"]["critical"]
    assert traj[-1] == 0
    assert all(a >= b for a, b in zip(traj, traj[1:])), "criticals must never increase"
    assert res["cleared_all_criticals"] is True
    assert res["final_counts"]["critical"] == 0
    assert res["needs_review_count"] == 0
    assert res["applied_count"] == len([s for s in res["steps"] if s["status"] == "applied"])


def test_campaign_labels_llm_steps(eng, monkeypatch):
    """When the sub-loop returns an LLM-authored fix, the campaign records it as such
    and still only applies engine-proven steps."""
    def fake_draft(finding, ctx, **kw):
        return {"finding_id": finding.id, "fix_text": "remove it", "by": "llm", "attempts": 1, "trace": [],
                "change": {"op": "remove", "target_ref": finding.raw_refs[-1]},
                "validation": {"resolves": True}}

    monkeypatch.setattr(campaign.R, "draft", fake_draft)
    res = campaign.plan(eng)
    assert res["by"] == "llm"
    assert all(s["by"] == "llm" for s in res["steps"])
    # Whatever it applied must be reflected in a non-increasing trajectory.
    traj = res["criticals_trajectory"]
    assert all(a >= b for a, b in zip(traj, traj[1:]))


def test_campaign_no_targets_is_noop(eng, monkeypatch):
    """An empty target-band set means nothing to do -> zero steps, honest residual."""
    monkeypatch.setattr(R, "complete", _dead)
    res = campaign.plan(eng, target_bands=())
    assert res["applied_count"] == 0
    assert res["steps"] == []
    assert res["residual_findings"] == []


def test_campaign_skips_unfixable_without_regressing(eng, monkeypatch):
    """If the sub-loop returns a change that neither resolves the target nor is clean,
    the campaign marks it needs_review and never applies it (posture never worsens)."""
    bad_ref = eng.records[0].raw_ref

    def fake_draft(finding, ctx, **kw):
        # A no-op-ish change that won't resolve most targets.
        return {"finding_id": finding.id, "fix_text": "?", "by": "llm", "attempts": 1, "trace": [],
                "change": {"op": "scope_source", "target_ref": bad_ref, "new_source": "10.255.255.0/24"},
                "validation": {"resolves": False}}

    monkeypatch.setattr(campaign.R, "draft", fake_draft)
    res = campaign.plan(eng)
    # Criticals never increased and every step is accounted for.
    traj = res["criticals_trajectory"]
    assert all(a >= b for a, b in zip(traj, traj[1:]))
    assert res["applied_count"] + res["needs_review_count"] == len(res["steps"])


# --------------------------------------------------------------------------
# Agent 3 — Triage Investigator (investigate -> decide, guardrails intact)
# --------------------------------------------------------------------------

def _delta(eng, rid):
    req = DEMO_REQUESTS[rid]
    return req, simulate_change(eng.records, eng.assets, eng.alias_map, req.proposed)


def test_classify_guardrail_short_circuits_before_investigation(eng, monkeypatch):
    """A force-escalate delta must escalate WITHOUT any model call or investigation."""
    called = {"n": 0}
    monkeypatch.setattr(classify_change, "complete", lambda **kw: called.__setitem__("n", called["n"] + 1) or _dead())
    req, delta = _delta(eng, "CR-ESCALATE")
    assert delta["forced_escalate"] is True
    dec = classify_change.classify_change(req, delta, ctx=eng)
    assert dec.decision == "escalate"
    assert dec.forced_escalate is True
    assert dec.delta_summary["investigation"] == []
    assert called["n"] == 0, "the guardrail path must not consult the model at all"


def test_classify_investigates_then_approves_clean_change(eng, monkeypatch):
    """On a clean change the investigator calls a tool, then the decision auto-approves;
    the evidence trail is captured and the tool actually ran against the engine."""
    req, delta = _delta(eng, "CR-AUTO")
    assert delta["forced_escalate"] is False

    steps = [
        {"thought": "check what reaches the destination",
         "tool": "effective_policy", "args": {"asset": "app-server-07"}},
        {"thought": "no new sensitive exposure", "done": True},
    ]
    inv = {"n": 0}

    def fake(**kw):
        if kw.get("system") == classify_change._INVESTIGATE_SYSTEM:
            i = inv["n"]; inv["n"] += 1
            return _resp(steps[min(i, len(steps) - 1)])
        # decision call
        return _resp({"decision": "auto_approve",
                      "criteria": {c: True for c in classify_change._CRITERIA},
                      "confidence": 0.9, "rationale": "clean, no new exposure"})

    monkeypatch.setattr(classify_change, "complete", fake)
    dec = classify_change.classify_change(req, delta, ctx=eng)
    assert dec.decision == "auto_approve"
    assert dec.decided_by == "llm"
    trail = dec.delta_summary["investigation"]
    assert any(s.get("tool") == "effective_policy" and "result" in s for s in trail)
    # the tool result is a real engine computation, not model text
    tool_step = next(s for s in trail if s.get("tool") == "effective_policy")
    assert "internet_exposed" in tool_step["result"]


def test_classify_engine_override_blocks_unsafe_approval(eng, monkeypatch):
    """Even if the model says auto_approve, a non-clean delta is overridden to escalate
    (Layer 3). The investigation cannot widen what the gate approves."""
    # Use a custom non-clean change: internet -> a sensitive asset on a new port.
    from src.models import ChangeRequest, PolicyRecord
    dst = next(a.asset_key for a in eng.assets if set(a.tags) & {"pci", "customer-data", "crown-jewel", "phi"})
    proposed = PolicyRecord(id="t", source_tool="algosec", raw_ref="T", source="0.0.0.0/0",
                            source_kind="cidr", destination=dst, destination_kind="identity",
                            dest_tags=[], service="tcp/3389", port=3389, protocol="tcp", action="allow", order=999)
    req = ChangeRequest(id="T", proposed=proposed, justification="please approve")
    delta = simulate_change(eng.records, eng.assets, eng.alias_map, proposed)

    def fake(**kw):
        if kw.get("system") == classify_change._INVESTIGATE_SYSTEM:
            return _resp({"thought": "done", "done": True})
        return _resp({"decision": "auto_approve",
                      "criteria": {c: True for c in classify_change._CRITERIA},
                      "confidence": 0.95, "rationale": "looks fine to me"})

    monkeypatch.setattr(classify_change, "complete", fake)
    dec = classify_change.classify_change(req, delta, ctx=eng)
    assert dec.decision == "escalate"
    assert dec.decided_by == "engine_fallback"


def test_classify_fails_closed_on_garbage(eng, monkeypatch):
    """Unparseable model output -> escalate (Layer 2)."""
    req, delta = _delta(eng, "CR-AUTO")

    def fake(**kw):
        if kw.get("system") == classify_change._INVESTIGATE_SYSTEM:
            return _resp({"done": True})
        return _resp("not json at all", ok=True)

    monkeypatch.setattr(classify_change, "complete", fake)
    dec = classify_change.classify_change(req, delta, ctx=eng)
    assert dec.decision == "escalate"
    assert dec.decided_by == "engine_fallback"


def test_classify_investigation_tolerates_bad_tool_calls(eng, monkeypatch):
    """A hallucinated tool name or bad args is recorded as evidence, never a crash."""
    req, delta = _delta(eng, "CR-AUTO")
    steps = [
        {"thought": "try a nonexistent tool", "tool": "nuke", "args": {}},
        {"thought": "bad args", "tool": "reachable", "args": {"nonsense": 1}},
        {"thought": "ok", "done": True},
    ]
    inv = {"n": 0}

    def fake(**kw):
        if kw.get("system") == classify_change._INVESTIGATE_SYSTEM:
            i = inv["n"]; inv["n"] += 1
            return _resp(steps[min(i, len(steps) - 1)])
        return _resp({"decision": "auto_approve", "criteria": {c: True for c in classify_change._CRITERIA},
                      "confidence": 0.8, "rationale": "ok"})

    monkeypatch.setattr(classify_change, "complete", fake)
    dec = classify_change.classify_change(req, delta, ctx=eng)
    trail = dec.delta_summary["investigation"]
    assert any(s.get("error") == "unknown or unavailable tool" for s in trail)
    # reachable() with only bad args still returns a structured result, not an exception
    assert any(s.get("tool") == "reachable" for s in trail)


# --------------------------------------------------------------------------
# Agent 4 — Connector-authoring loop (propose -> normalize -> revise)
# --------------------------------------------------------------------------

_SAMPLE = {
    "rules": [
        {"id": "R1", "from": "10.0.0.0/8", "to": "web-01", "svc": "tcp/443", "act": "allow", "blank": ""},
        {"id": "R2", "from": "10.0.0.0/8", "to": "web-01", "svc": "tcp/22", "act": "deny", "blank": ""},
    ],
    "objects": {"web-01": {"type": "host", "value": "10.0.0.5", "tags": ["prod"]}},
}
_GOOD = {"tool": "acme", "rules_path": "rules", "objects_path": "objects",
         "fields": {"src": "from", "dst": "to", "service": "svc", "action": "act", "ref": "id"}}


def test_authoring_converges_after_bad_first_profile(monkeypatch):
    """First profile points rules_path at the wrong key (0 records) -> the engine
    feedback drives a corrected profile that normalizes cleanly."""
    wrong = {**_GOOD, "rules_path": "policies"}   # nonexistent -> 0 records
    seq = [wrong, _GOOD]
    calls = {"n": 0}
    saw_zero_feedback = {"got": False}

    def fake(**kw):
        i = calls["n"]; calls["n"] += 1
        if "ZERO records" in kw.get("user", ""):
            saw_zero_feedback["got"] = True
        return _resp(seq[min(i, len(seq) - 1)])

    monkeypatch.setattr(authoring, "complete", fake)
    res = authoring.propose_profile(_SAMPLE, "acme")
    assert res["ok"] is True
    assert res["validation"]["valid"] is True
    assert res["attempts"] == 2
    assert saw_zero_feedback["got"], "the model must see the 'zero records' feedback"
    assert res["profile"]["rules_path"] == "rules"


def test_authoring_reports_unmapped_fields(monkeypatch):
    """A profile that maps `src` to an empty field -> rows are missing a source ->
    the loop surfaces the unmapped field and keeps trying."""
    wrong = {**_GOOD, "fields": {**_GOOD["fields"], "src": "blank"}}   # -> empty source
    calls = {"n": 0}
    saw_unmapped = {"got": False}

    def fake(**kw):
        i = calls["n"]; calls["n"] += 1
        if "missing these fields" in kw.get("user", ""):
            saw_unmapped["got"] = True
        return _resp([wrong, _GOOD][min(i, 1)])

    monkeypatch.setattr(authoring, "complete", fake)
    res = authoring.propose_profile(_SAMPLE, "acme")
    assert saw_unmapped["got"]
    assert res["validation"]["valid"] is True


def test_authoring_needs_review_when_never_valid(monkeypatch):
    """Model keeps returning a broken profile -> best partial is returned for review,
    never a false 'valid'."""
    wrong = {**_GOOD, "rules_path": "policies"}
    monkeypatch.setattr(authoring, "complete", lambda **kw: _resp(wrong))
    res = authoring.propose_profile(_SAMPLE, "acme")
    assert res.get("needs_review") is True
    assert res["validation"]["valid"] is False


def test_authoring_fails_closed_when_model_dead(monkeypatch):
    monkeypatch.setattr(authoring, "complete", _dead)
    res = authoring.propose_profile(_SAMPLE, "acme")
    assert res["ok"] is False
    assert res["needs_review"] is True
