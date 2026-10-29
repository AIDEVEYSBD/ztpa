"""Eval-gated tuning: a configuration counts as evaluated only with a passing,
recorded evaluation of its exact fingerprint (offline)."""

from __future__ import annotations

import json

import pytest

from src.frr import agents, prompt_gate


def _metrics(failures=(), model="vertex:google/gemini-2.5-pro"):
    return {"model": model, "items": 20, "fallback_rate": 0.0, "ungrounded_rate": 0.0, "contradictions": 0,
            "citation_rate": 0.9, "owner_question_rate_on_narrowing": 1.0, "problems": ["detail not kept"],
            "package_summary": {"fallback": False, "ungrounded": [], "contradiction": None},
            "fingerprints": {k: agents.fingerprint(k) for k in prompt_gate.evaluated_agents()},
            "gate": {"thresholds": {"max_contradictions": 0}, "failures": list(failures)}}


def test_only_passing_gated_runs_are_recorded(tmp_path) -> None:
    ledger = tmp_path / "ledger.json"
    with pytest.raises(ValueError, match="not recorded"):
        prompt_gate.record(_metrics(["1 contradiction(s) > 0"]), path=ledger)
    with pytest.raises(ValueError, match="not gated"):
        prompt_gate.record({k: v for k, v in _metrics().items() if k != "gate"}, path=ledger)
    assert not ledger.exists()
    e = prompt_gate.record(_metrics(), path=ledger)
    assert "problems" not in e["metrics"] and e["metrics"]["package_summary"]["fallback"] is False
    assert len(json.loads(ledger.read_text())["evaluations"]) == 1


def test_a_changed_prompt_or_retrieval_setting_is_no_longer_evaluated(monkeypatch) -> None:
    ledger = [{"at": "2026-10-29T00:00:00+00:00", **{k: v for k, v in _metrics().items()
                                                     if k in ("model", "fingerprints")}}]
    assert all(v["evaluated"] for v in prompt_gate.status(ledger).values())
    monkeypatch.setattr(agents, "RETRIEVAL_K", 5)
    st = prompt_gate.status(ledger)
    assert not st["impact_assessor"]["evaluated"] and st["package_drafter"]["evaluated"]
    real = agents.prompt
    monkeypatch.setattr(agents, "prompt", lambda n: agents.Prompt(n, real(n).text + "\nBe brief."))
    assert not prompt_gate.status(ledger)["package_drafter"]["evaluated"]


def test_both_clouds_can_be_required(monkeypatch) -> None:
    one = [{"at": "2026-10-29T00:00:00+00:00", "model": "vertex:m", "fingerprints": _metrics()["fingerprints"]}]
    monkeypatch.setattr(prompt_gate, "MIN_MODELS", 2)
    assert not prompt_gate.status(one)["impact_assessor"]["evaluated"]
    two = one + [{**one[0], "model": "azure:gpt-4.1-mini"}]
    assert prompt_gate.status(two)["impact_assessor"]["models"] == ["azure:gpt-4.1-mini", "vertex:m"]
    assert prompt_gate.status(two)["impact_assessor"]["evaluated"]


def test_the_committed_ledger_covers_the_running_configuration() -> None:
    """What CI's prompt gate checks: change a prompt or retrieval setting and
    this fails until a passing evaluation of the change is recorded."""
    assert all(v["evaluated"] for v in prompt_gate.status().values()), prompt_gate.status()


def test_the_agents_endpoint_reports_evaluation() -> None:
    from app import frr_api
    by_key = {a["key"]: a for a in frr_api.list_agents()["agents"]}
    assert by_key["impact_assessor"]["evaluation"]["fingerprint"] == agents.fingerprint("impact_assessor")
    assert by_key["orchestrator"]["evaluation"] is None
