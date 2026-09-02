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
    """Group findings by root cause without a model. EVERY finding lands in
    exactly one bucket -- see the catch-all at the end, and why it has to exist."""
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

    # Anything the four buckets above do not claim -- on the shipped demo that is
    # all eight `transport_exposure` findings, a fifth of the estate. The four
    # were written against the finding types that existed when they were, and a
    # new analyzer's output silently DISAPPEARED from the action list: the screen
    # said "N findings grouped into these actions" while N of them were in none of
    # them. `_coerce` has carried this same catch-all for the model's grouping
    # from the start (a model that omits a finding is not trusted to have meant
    # it); the deterministic path needed it more, not less, now that it is what
    # /api/actions serves on the request path rather than only when the model is
    # unreachable.
    covered = {fid for _t, ids, _r in buckets for fid in ids}
    remaining = [f.id for f in findings if f.id not in covered]
    if remaining:
        buckets.append(("Review remaining findings", remaining,
                        "Findings outside the grouped root causes -- review them individually."))

    return [RankedAction(action_id=f"A{i}", title=t, finding_ids=ids, priority=i, rationale=r)
            for i, (t, ids, r) in enumerate(buckets, start=1)]


def rank_deterministic(findings: list[Finding]) -> RankedActions:
    """The ranking with NO model call: the deterministic root-cause buckets, put
    through the same guardrail sort as an LLM answer.

    Named and exported because a caller sometimes has to be able to say "not
    now" to the model rather than take whatever `rank()` decides. Two do:
    GET /api/actions, which may not spend up to `OLLAMA_TIMEOUT` seconds on a
    request path (and used to, inside an open database transaction), and the
    degraded read that answers while the snapshot store is unreachable. Both need
    a real, ordered, complete action list -- an empty one would render as "nothing
    to do", which is the worst sentence this product can print by accident.

    `ranked_by` is "engine_fallback" here for the same reason it is when the model
    is unreachable: the caller is looking at the engine's grouping, and the UI
    says so."""
    if not findings:
        return RankedActions(actions=[], ranked_by="engine_fallback")
    return RankedActions(actions=_enforce(_fallback(findings), findings), ranked_by="engine_fallback")


def rank(findings: list[Finding]) -> RankedActions:
    if not findings:
        return RankedActions(actions=[], ranked_by="engine_fallback")
    r = complete(system=_PROMPT, user=json.dumps({"findings": _payload(findings)}),
                 role="judge", temperature=0.1, expect_json=True)
    actions = _coerce(parse_json(r.text, None), findings) if r.ok else None
    if not actions:
        return rank_deterministic(findings)
    return RankedActions(actions=_enforce(actions, findings), ranked_by="llm")
