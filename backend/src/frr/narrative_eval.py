"""Narrative quality evaluation (FRR-04.3): measure the impact assessor's output
against the facts it was given, deterministically.

    python -m src.frr.narrative_eval --rules 300 --items 20 --gate     # uses ADVISORY_PROVIDER
    ... --gate --record      # and, when it passes, add it to the eval ledger (prompt_gate.py)

Per item, the assessor runs exactly as in a review run (same prompt, same
retrieval shape), then each narrative is scored:

  fallback       the schema or citation check rejected the output (by reason)
  ungrounded     a number in the narrative appears nowhere in the facts or excerpts
                 the model was given -- an invented port, count or date
  contradiction  wording that softens the engine's verdict ("low risk" on a
                 critical item) or argues against the proposal ("keep the rule")
  cited          when an excerpt was retrieved, whether the narrative cited one
  asks_owner     narrowing items that ask the owner at least one question

The package drafter's executive summary is scored once per run the same way
(fallback, ungrounded numbers, softening wording) and gated strictly: one
summary, so any problem fails.

No second model judges the first: the checks are cheap, stable across runs and
explainable. The gate thresholds are deliberately strict on what must never
happen (contradictions) and tolerant on what is a quality signal (citation).
Costs one model call per item; run on demand or nightly, not on every commit.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import time
from typing import Any

from . import agents, package as package_mod
from .evals import generate
from .review import review
from ..normalizers import checkpoint

GATE = {
    "max_fallback_rate": float(os.environ.get("NPR_NEVAL_MAX_FALLBACK", "0.10")),
    "max_ungrounded_rate": float(os.environ.get("NPR_NEVAL_MAX_UNGROUNDED", "0.05")),
    "max_contradictions": int(os.environ.get("NPR_NEVAL_MAX_CONTRADICTIONS", "0")),
}

_NUM = re.compile(r"(?<![\w.])\d+(?:\.\d+)?(?![\w.])")
_SOFTENING = re.compile(r"\b(low[- ]risk|no (?:real )?risk|not (?:a )?(?:concern|risk|issue)|harmless|benign|safe to keep)\b", re.I)
_AGAINST_REMOVAL = re.compile(r"\b(should (?:be )?(?:kept|retained)|keep (?:this|the) rule|do not (?:remove|disable))\b", re.I)

# Facts the model sees that are not numbers it could plausibly need to invent:
# the excerpt and item text are searched as given.
CONTEXT = [
    {"cite": "std00001#0", "kind": "standard", "title": "Remote access standard", "heading": "SSH and RDP",
     "body": "SSH (22) and RDP (3389) from the internet are prohibited. Administrative access goes through the "
             "bastion hosts in 10.40.0.0/24."},
    {"cite": "run00002#0", "kind": "runbook", "title": "Rule cleanup runbook", "heading": "Unused and expired rules",
     "body": "Disable an unused rule for 30 days before deleting it; remove expired rules at the next change window. "
             "Rollback: re-enable the rule and publish."},
]


def ungrounded_numbers(text: str, facts_text: str) -> list[str]:
    out = []
    for n in _NUM.findall(text or ""):
        if n in facts_text:
            continue
        if len(n) == 1:                       # "1 source", "2 rules": too common to judge
            continue
        out.append(n)
    return out


def score(item: dict, context: list[dict], narrative: dict) -> dict:
    facts_text = json.dumps({"item": item, "context": context}, default=str)
    text = " ".join([narrative.get("summary", ""), narrative.get("availability_note", "")])
    fb = narrative.get("by") == "engine_fallback"
    contradiction = None
    if not fb:
        if item["band"] in ("critical", "high") and _SOFTENING.search(text):
            contradiction = f"softens a {item['band']} finding: '{_SOFTENING.search(text).group(0)}'"
        elif item["proposal"] in ("remove", "disable_then_remove") and _AGAINST_REMOVAL.search(text):
            contradiction = f"argues against the proposal: '{_AGAINST_REMOVAL.search(text).group(0)}'"
    return {
        "item": item["item_id"], "rule": item["rule_number"], "check": item["check"], "band": item["band"],
        "fallback": fb, "fallback_reason": narrative.get("fallback_reason"),
        "ungrounded": [] if fb else ungrounded_numbers(text, facts_text),
        "contradiction": contradiction,
        "cited": bool(narrative.get("cites")),
        "asks_owner": bool(narrative.get("owner_questions")),
        "narrowing": item["proposal"] == "time_bound_and_narrow",
    }


# "400 rules reviewed" / "analysed 183 firewall rules": a count presented as the
# number of rules reviewed must be that number, not the number of changes.
_RULES_COUNT = re.compile(r"(?:review(?:ed|s)?|analy[sz](?:ed|es|is)|examin(?:ed|es)|assess(?:ed|es))\D{0,20}?"
                          r"(\d[\d,]*)\s+(?:firewall\s+|access\s+)?rules"
                          r"|(\d[\d,]*)\s+(?:firewall\s+|access\s+)?rules\s+(?:were\s+|was\s+)?"
                          r"(?:reviewed|analy[sz]ed|examined|assessed|in the export)", re.I)


def miscounted_rules(text: str, rules_reviewed: int | None) -> list[str]:
    if rules_reviewed is None:
        return []
    out = []
    for m in _RULES_COUNT.finditer(text or ""):
        n = int((m.group(1) or m.group(2)).replace(",", ""))
        if n != rules_reviewed:
            out.append(m.group(0))
    return out


def score_summary(drafted: dict, narrative: dict) -> dict:
    facts_text = json.dumps({"stats": agents.summary_stats(drafted), "items": drafted["items"][:10],
                             "limitations": drafted["limitations"][:20]}, default=str)
    text = " ".join([narrative.get("summary", ""), *narrative.get("key_risks", []),
                     narrative.get("limitations_note", "")])
    fb = narrative.get("by") == "engine_fallback"
    worst = {i["band"] for i in drafted["items"][:10]}
    soft = _SOFTENING.search(text) if not fb and worst & {"critical", "high"} else None
    miscount = [] if fb else miscounted_rules(text, drafted["summary"].get("rules_reviewed"))
    contradiction = (f"softens a package with critical/high items: '{soft.group(0)}'" if soft else
                     f"misstates the rules reviewed ({drafted['summary']['rules_reviewed']}): '{miscount[0]}'"
                     if miscount else None)
    return {"fallback": fb, "ungrounded": [] if fb else ungrounded_numbers(text, facts_text),
            "contradiction": contradiction}


def evaluate(items: list[dict], llm=None, parallel: int = 6, drafted: dict | None = None) -> dict[str, Any]:
    from concurrent.futures import ThreadPoolExecutor
    p = agents.agent_prompt("impact_assessor")
    t0 = time.perf_counter()
    with ThreadPoolExecutor(max_workers=max(1, parallel)) as pool:
        narratives = list(pool.map(lambda it: agents.assess_item(it, CONTEXT, p, llm), items))
    elapsed = time.perf_counter() - t0
    rows = [score(it, CONTEXT, n) for it, n in zip(items, narratives)]
    n = len(rows) or 1
    live = [r for r in rows if not r["fallback"]]
    narrowing = [r for r in live if r["narrowing"]]
    reasons: dict[str, int] = {}
    for r in rows:
        if r["fallback"]:
            k = (r["fallback_reason"] or "unknown").split(":")[0]
            reasons[k] = reasons.get(k, 0) + 1
    out = {
        "prompt": p.version, "items": len(rows), "seconds": round(elapsed, 1),
        "model": next((x.get("by") for x in narratives if x.get("by") != "engine_fallback"), None),
        "fallback_rate": round(sum(r["fallback"] for r in rows) / n, 3), "fallback_reasons": reasons,
        "ungrounded_rate": round(sum(bool(r["ungrounded"]) for r in live) / max(1, len(live)), 3),
        "contradictions": sum(bool(r["contradiction"]) for r in rows),
        "citation_rate": round(sum(r["cited"] for r in live) / max(1, len(live)), 3),
        "owner_question_rate_on_narrowing": round(sum(r["asks_owner"] for r in narrowing) / max(1, len(narrowing)), 3),
        "problems": [r for r in rows if r["ungrounded"] or r["contradiction"]][:20],
        "fingerprints": {k: agents.fingerprint(k) for k in ("impact_assessor", "package_drafter")},
    }
    if drafted is not None:
        out["package_summary"] = score_summary(
            drafted, agents.summarise_package(drafted, agents.agent_prompt("package_drafter"), llm))
    return out


def gate(m: dict, g: dict = GATE) -> list[str]:
    fails = []
    if m["fallback_rate"] > g["max_fallback_rate"]:
        fails.append(f"fallback rate {m['fallback_rate']} > {g['max_fallback_rate']}")
    if m["ungrounded_rate"] > g["max_ungrounded_rate"]:
        fails.append(f"ungrounded-number rate {m['ungrounded_rate']} > {g['max_ungrounded_rate']}")
    if m["contradictions"] > g["max_contradictions"]:
        fails.append(f"{m['contradictions']} contradiction(s) > {g['max_contradictions']}")
    ps = m.get("package_summary")
    if ps is None:
        fails.append("the package summary was not evaluated")
    else:
        if ps["fallback"]:
            fails.append("the package summary fell back to the engine text")
        if ps["ungrounded"]:
            fails.append(f"the package summary has ungrounded numbers {ps['ungrounded']}")
        if ps["contradiction"]:
            fails.append(f"the package summary {ps['contradiction']}")
    return fails


def sample_items(rules: int, items: int, seed: int = 11) -> tuple[list[dict], dict]:
    """(items, drafted package) from the labelled synthetic rulebase; items
    spread across checks."""
    doc, _ = generate(rules, seed)
    parsed = checkpoint.parse(doc)
    rv = review(parsed)
    drafted = package_mod.draft(json.loads(json.dumps(rv.to_jsonable(), default=str)),
                                json.loads(json.dumps(parsed.to_jsonable(), default=str)))
    by_check: dict[str, list[dict]] = {}
    for it in drafted["items"]:
        by_check.setdefault(it["check"], []).append(it)
    out: list[dict] = []
    while len(out) < items and any(by_check.values()):
        for k in sorted(by_check):
            if by_check[k] and len(out) < items:
                out.append(by_check[k].pop(0))
    return out, drafted


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--rules", type=int, default=300)
    ap.add_argument("--items", type=int, default=20)
    ap.add_argument("--gate", action="store_true")
    ap.add_argument("--record", action="store_true",
                    help="append a passing, gated run to the eval ledger (src/frr/prompts/eval-ledger.json)")
    a = ap.parse_args(argv)
    if a.record and not a.gate:
        ap.error("--record needs --gate")
    items, drafted = sample_items(a.rules, a.items)
    m = evaluate(items, drafted=drafted)
    m["gate"] = {"thresholds": GATE, "failures": gate(m)}
    print(json.dumps(m, indent=2, default=str))
    if a.gate and m["gate"]["failures"]:
        return 1
    if a.record:
        from . import prompt_gate
        e = prompt_gate.record(m)
        print(f"recorded {', '.join(e['fingerprints'].values())} on {e['model']}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
