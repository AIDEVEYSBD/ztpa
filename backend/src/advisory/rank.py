"""Job 2 -- rank + group findings into a de-duplicated action list (judgment).

The engine's severity is the PRIMARY signal; the model groups by root cause and
orders worst-first. The guardrail is enforced deterministically AFTER the model:
no action containing a forced_critical finding can sit below one that doesn't."""

from __future__ import annotations

import json
from pathlib import Path

from ..models import Finding, RankedAction, RankedActions
from .client import complete, parse_json

_PROMPT = (Path(__file__).parent / "prompts" / "rank.txt").read_text()
_BAND_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3}


def _payload(findings: list[Finding]) -> list[dict]:
    return [{
        "id": f.id, "type": f.type, "title": f.title, "severity": f.severity,
        "severity_band": f.severity_band, "forced_critical": f.forced_critical,
        "involved": f.involved, "raw_refs": f.raw_refs, "tools": f.source_tools,
    } for f in findings]


def _by_id(findings: list[Finding]) -> dict[str, Finding]:
    return {f.id: f for f in findings}


def _enforce(actions: list[RankedAction], findings: list[Finding]) -> list[RankedAction]:
    """Deterministically re-sort + re-number so forced-critical actions lead."""
    fmap = _by_id(findings)

    def key(a: RankedAction):
        members = [fmap[i] for i in a.finding_ids if i in fmap]
        has_forced = any(m.forced_critical for m in members)
        max_sev = max((m.severity for m in members), default=0)
        worst_band = min((_BAND_RANK[m.severity_band] for m in members), default=3)
        return (0 if has_forced else 1, worst_band, -max_sev, a.finding_ids[0] if a.finding_ids else "")

    ordered = sorted(actions, key=key)
    for idx, a in enumerate(ordered, start=1):
        a.action_id = f"A{idx}"
        a.priority = idx
        members = [fmap[i] for i in a.finding_ids if i in fmap]
        worst = min(members, key=lambda m: _BAND_RANK[m.severity_band], default=None)
        a.severity_band = worst.severity_band if worst else "low"
    return ordered


def _coerce(data, findings: list[Finding]) -> list[RankedAction] | None:
    if not isinstance(data, dict) or not isinstance(data.get("actions"), list):
        return None
    valid_ids = set(_by_id(findings))
    actions: list[RankedAction] = []
    covered: set[str] = set()
    for i, a in enumerate(data["actions"], start=1):
        if not isinstance(a, dict):
            continue
        ids = [fid for fid in a.get("finding_ids", []) if fid in valid_ids]
        if not ids:
            continue
        covered.update(ids)
        actions.append(RankedAction(
            action_id=str(a.get("action_id") or f"A{i}"),
            title=str(a.get("title") or "Review findings")[:120],
            finding_ids=ids, priority=int(a.get("priority", i)),
            rationale=str(a.get("rationale") or "")[:300],
        ))
    if not actions:
        return None
    uncovered = [fid for fid in valid_ids if fid not in covered]
    if uncovered:
        actions.append(RankedAction(action_id=f"A{len(actions) + 1}", title="Review remaining findings",
                                    finding_ids=sorted(uncovered), priority=len(actions) + 1,
                                    rationale="Findings the grouping did not assign."))
    return actions


def _fallback(findings: list[Finding]) -> list[RankedAction]:
    buckets: list[tuple[str, str, list[str]]] = []

    def collect(pred) -> list[str]:
        return [f.id for f in findings if pred(f)]

    path_ids = collect(lambda f: f.type == "cross_tool_path")
    internet_crit = collect(lambda f: f.type == "over_permissive" and f.forced_critical)
    broad = collect(lambda f: f.type == "over_permissive" and not f.forced_critical)
    hygiene = collect(lambda f: f.type in ("cidr_overlap", "shadowed_rule"))

    if internet_crit:
        buckets.append(("Close internet-exposed access to critical assets", internet_crit,
                        "Internet-facing grants reach admin ports or regulated data -- fix first."))
    if path_ids:
        buckets.append(("Cut the cross-tool path to regulated data", path_ids,
                        "A chain across tools reaches a sensitive asset that no single tool reveals."))
    if broad:
        buckets.append(("Tighten broad admin/data access", broad,
                        "Admin/data ports are open to wide source ranges -- scope them down."))
    if hygiene:
        buckets.append(("Clean up redundant and dead rules", hygiene,
                        "Redundant and shadowed rules create false confidence and clutter."))

    return [RankedAction(action_id=f"A{i}", title=t, finding_ids=ids, priority=i, rationale=r)
            for i, (t, ids, r) in enumerate(buckets, start=1)]


def rank(findings: list[Finding]) -> RankedActions:
    if not findings:
        return RankedActions(actions=[], ranked_by="engine_fallback")
    r = complete(system=_PROMPT, user=json.dumps({"findings": _payload(findings)}),
                 role="judge", temperature=0.1, expect_json=True)
    actions = _coerce(parse_json(r.text, None), findings) if r.ok else None
    ranked_by = "llm" if actions else "engine_fallback"
    if not actions:
        actions = _fallback(findings)
    return RankedActions(actions=_enforce(actions, findings), ranked_by=ranked_by)
