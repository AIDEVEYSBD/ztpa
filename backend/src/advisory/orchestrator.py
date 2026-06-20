"""Orchestrator agent: coordinates the deterministic engine + the advisory jobs
into one structured posture review (the detailed Posture Report).

It is a higher-order agent: it does no math itself, it ORCHESTRATES the existing
deterministic facts (summary, ranking, cross-tool paths) and asks the model only
for the narrative. Returns structured data the UI renders with visuals + numbers.

The report is split in two so the UI never hangs on a cold local model:
  - posture_facts():     instant, deterministic (incl. a deterministic narrative)
  - posture_narrative(): the slow LLM prose call, bounded + fail-closed
"""

from __future__ import annotations

import json
from collections import Counter

from ..config import SENSITIVE_TAGS
from ..models import Asset, Finding, RankedActions
from .client import complete
from .rank import rank
from .report import _fallback as _fallback_report, build_summary

_BAND = {"critical": 0, "high": 1, "medium": 2, "low": 3}
_BANDS = ("critical", "high", "medium", "low")

# The narrative model can be a large local model (cold-start minutes). Bound the
# call so the request returns the deterministic fallback instead of hanging the
# HTTP connection (which a dev proxy would reset).
_NARRATIVE_TIMEOUT = 180.0

_PROMPT = (
    "You are a principal security consultant writing a detailed, board-ready network posture report. "
    "You receive JSON facts (counts, severity breakdown, grouped actions, cross-tool paths, sensitive "
    "assets) that were computed deterministically. Write a thorough Markdown report with these ## "
    "sections: Executive summary; Risk landscape; Critical exposures (for each: what it allows, why it "
    "matters, and a concrete fix, citing the rule refs); Cross-tool attack paths; Compliance posture "
    "(PCI-DSS segmentation and Zero-Trust maturity, with specific gaps); Prioritised remediation plan "
    "(numbered, worst-first). Be specific: name the assets and rule refs from the data. Reason ONLY "
    "from the provided facts; invent nothing. No preamble."
)


def _assemble(findings: list[Finding], assets: list[Asset], ranked: RankedActions | None = None):
    """Deterministic assembly shared by both endpoints. `ranked` may be supplied
    from the persisted cache so the report does not re-run the (slow) ranking LLM."""
    summary = build_summary(findings, assets)
    if ranked is None:
        ranked = rank(findings)
    by_id = {f.id: f for f in findings}

    actions = []
    for a in ranked.actions:
        afs = [by_id[i] for i in a.finding_ids if i in by_id]
        band = min((f.severity_band for f in afs), key=lambda b: _BAND[b]) if afs else "low"
        actions.append({
            "action_id": a.action_id, "title": a.title, "priority": a.priority,
            "rationale": a.rationale, "band": band,
            "findings": [{"id": f.id, "title": f.signals.get("title") or f.title, "type": f.type,
                          "band": f.severity_band, "severity": f.severity, "refs": f.raw_refs,
                          "tools": f.source_tools} for f in afs],
        })

    paths = [f.signals for f in findings if f.type == "cross_tool_path"]
    sensitive = sorted({a.asset_key for a in assets if set(a.tags) & SENSITIVE_TAGS})
    breakdown = Counter(f.severity_band for f in findings)
    return summary, ranked, actions, paths, sensitive, breakdown


def posture_facts(findings: list[Finding], assets: list[Asset], ranked: RankedActions | None = None) -> dict:
    """Instant, deterministic report payload. Carries a deterministic narrative so
    the report is complete on its own; `narrative_pending` tells the UI to fetch
    the richer LLM narrative separately."""
    summary, ranked, actions, paths, sensitive, breakdown = _assemble(findings, assets, ranked)
    return {
        "summary": summary,
        "severity_breakdown": {b: breakdown.get(b, 0) for b in _BANDS},
        "by_type": dict(Counter(f.type for f in findings)),
        "actions": actions,
        "cross_tool_paths": paths,
        "sensitive_assets": sensitive,
        "narrative_md": _fallback_report(summary),
        "ranked_by": ranked.ranked_by,
        "by": "engine_fallback",
        "narrative_pending": True,
    }


def posture_narrative(findings: list[Finding], assets: list[Asset], ranked: RankedActions | None = None) -> dict:
    """The slow LLM narrative call, bounded and fail-closed. Returns just the
    narrative + provenance; the UI swaps it into the already-rendered report."""
    summary, ranked, actions, paths, sensitive, breakdown = _assemble(findings, assets, ranked)
    facts = {
        "summary": summary, "actions": actions, "sensitive_assets": sensitive,
        "cross_tool_paths": [{"terminal": p.get("terminal"), "tools": p.get("tools"),
                              "display_path": p.get("display_path"), "boundary": p.get("boundary"),
                              "terminal_tags": p.get("terminal_tags")} for p in paths],
    }
    r = complete(system=_PROMPT, user=json.dumps(facts, indent=2)[:9000], role="prose",
                 temperature=0.3, timeout=_NARRATIVE_TIMEOUT)
    if r.ok and r.text.strip():
        return {"narrative_md": r.text.strip(), "by": f"{r.provider}:{r.model}", "narrative_pending": False}
    return {"narrative_md": _fallback_report(summary), "by": "engine_fallback", "narrative_pending": False}


def posture_review(findings: list[Finding], assets: list[Asset]) -> dict:
    """Full blocking report (facts + LLM narrative in one). Kept for callers that
    want everything at once; the API prefers the split endpoints."""
    facts = posture_facts(findings, assets)
    facts.update(posture_narrative(findings, assets))
    return facts
