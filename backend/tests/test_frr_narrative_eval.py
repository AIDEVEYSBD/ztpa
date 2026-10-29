"""The narrative evaluator catches invented numbers, softened verdicts and
arguments against the proposal, and gates on them (offline, stub model)."""

from __future__ import annotations

import json
from dataclasses import dataclass

from src.frr import narrative_eval as ne


@dataclass
class R:
    text: str
    ok: bool = True
    provider: str = "stub"
    model: str = "m"
    error: str | None = None


def _llm(payload):
    return lambda **kw: R(json.dumps(payload))


ITEMS = ne.sample_items(150, 6)


def test_items_span_several_checks() -> None:
    assert len(ITEMS) == 6 and len({i["check"] for i in ITEMS}) >= 4


def test_a_grounded_narrative_passes() -> None:
    def llm(**kw):
        facts = json.loads(kw["user"])
        n = facts["item"]["rule_number"]
        return R(json.dumps({"summary": f"Rule {n} is flagged; SSH (22) from the internet is prohibited.",
                             "availability_note": "Disable for 30 days first.",
                             "owner_questions": ["Who uses it?"], "cites": ["std00001#0"]}))
    m = ne.evaluate(ITEMS, llm)
    assert m["fallback_rate"] == 0 and m["ungrounded_rate"] == 0 and m["contradictions"] == 0
    assert m["citation_rate"] == 1.0 and ne.gate(m) == []


def test_invented_numbers_are_caught() -> None:
    m = ne.evaluate(ITEMS, _llm({"summary": "This rule carried 48213 connections on port 8443 last week."}))
    assert m["ungrounded_rate"] > 0 and "48213" in str(m["problems"])
    assert any("ungrounded" in f for f in ne.gate(m))


def test_softening_a_critical_finding_is_a_contradiction() -> None:
    crit = [i for i in ne.sample_items(300, 30) if i["band"] == "critical"][:2]
    assert crit, "sample should contain critical items"
    m = ne.evaluate(crit, _llm({"summary": "This is a low-risk rule and not a concern."}))
    assert m["contradictions"] == len(crit) and any("contradiction" in f for f in ne.gate(m))


def test_fallbacks_are_counted_by_reason() -> None:
    m = ne.evaluate(ITEMS, lambda **kw: R("", ok=False, error="quota exceeded"))
    assert m["fallback_rate"] == 1.0 and m["fallback_reasons"] == {"quota exceeded": len(ITEMS)}
    assert m["contradictions"] == 0                    # engine text is never a contradiction
