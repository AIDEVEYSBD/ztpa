"""Capability #9 -- the Remediation Campaign agent (higher-order, agentic).

Where the remediation loop (capability #5) fixes ONE finding, the campaign agent
fixes the WHOLE posture: it plans a worst-first sequence and drives the critical
count down, re-simulating after every step so each fix is judged against the
*cumulative* state -- because fixing one rule changes the graph, which can resolve
OR introduce other findings.

It is agentic in the sequential-decision sense: pick the worst open finding ->
draft a fix (itself the propose/re-simulate/revise sub-loop) -> the engine proves
the fix on the accumulated records -> observe the new posture -> pick the next.
The engine is the judge at every step: a step is only APPLIED if it resolves its
target and introduces no new critical on the cumulative state; otherwise it is
recorded as needs-human and skipped, so the campaign never makes things worse.

Everything the agent reasons over is a deterministic fact. The math (reachability,
which findings remain, which criticals a step opens) is always the engine's.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from ..analyzers.run_all import reanalyze
from ..change.apply import apply_remediation
from ..models import Asset, Finding, PolicyRecord
from . import remediation as R

# Bands the campaign will actively work, worst first. Criticals are the money shot;
# highs are included so the campaign keeps going once criticals are cleared.
DEFAULT_TARGET_BANDS = ("critical", "high")
_BAND_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}

# Hard ceiling on steps as a runaway backstop, independent of the per-run budget
# (which is sized from the initial finding count). Keeps a pathological loop bounded.
_MAX_STEPS_CEILING = 40


@dataclass
class _Ctx:
    """A minimal EngineResult-shaped context so `remediation.draft` can re-simulate
    against the campaign's *evolving* record set rather than the original snapshot."""
    records: list[PolicyRecord]
    assets: list[Asset]
    alias_map: dict[str, str]
    findings: list[Finding] = field(default_factory=list)


def _worst_first(findings: list[Finding]) -> list[Finding]:
    return sorted(findings, key=lambda f: (
        0 if f.forced_critical else 1, -f.severity, _BAND_ORDER.get(f.severity_band, 9), f.type, f.id,
    ))


def _crit_sigs(findings: list[Finding]) -> set:
    return {R._sig(f) for f in findings if f.severity_band == "critical"}


def _all_sigs(findings: list[Finding]) -> set:
    return {R._sig(f) for f in findings}


def _count(findings: list[Finding], band: str) -> int:
    return sum(1 for f in findings if f.severity_band == band)


def _band_counts(findings: list[Finding]) -> dict[str, int]:
    return {b: _count(findings, b) for b in ("critical", "high", "medium", "low")}


def _finding_view(f: Finding) -> dict:
    return {"type": f.type, "title": f.title, "band": f.severity_band, "severity": f.severity,
            "refs": list(f.raw_refs), "tools": list(f.source_tools)}


def plan(ctx, target_bands: tuple[str, ...] = DEFAULT_TARGET_BANDS,
         max_steps: int | None = None, id_map: dict | None = None) -> dict:
    """Plan + prove a worst-first remediation campaign over `ctx` (an EngineResult).

    Returns the ordered steps, the critical-count trajectory the engine measured
    after each applied step, the residual findings that still need a human, and the
    final accumulated change set. Purely advisory: it computes and PROVES a plan;
    it does not persist or apply anything to the live snapshot.

    `id_map` optionally maps a finding signature -> the snapshot's stable finding id
    so the first-round steps can link back to the real findings in the UI.
    """
    records = list(ctx.records)
    assets, alias = ctx.assets, ctx.alias_map
    if id_map is None:
        snap_findings = getattr(ctx, "findings", None) or []
        id_map = {R._sig(f): f.id for f in snap_findings}

    findings = reanalyze(records, assets, alias)
    initial_counts = _band_counts(findings)
    trajectory = [initial_counts["critical"]]

    targetable_now = [f for f in findings if f.severity_band in target_bands]
    budget = min(max_steps if max_steps is not None else len(targetable_now) + 2, _MAX_STEPS_CEILING)

    steps: list[dict] = []
    applied_changes: list[dict] = []
    attempted: set = set()          # target sigs we tried but could not cleanly fix
    used_llm = False

    for _ in range(budget):
        open_targets = _worst_first([
            f for f in findings if f.severity_band in target_bands and R._sig(f) not in attempted
        ])
        if not open_targets:
            break
        target = open_targets[0]
        tsig = R._sig(target)

        # Draft a validated fix against the CURRENT accumulated state (the sub-loop:
        # propose -> engine re-simulates -> revise -> certify / fallback).
        shim = _Ctx(records=records, assets=assets, alias_map=alias, findings=findings)
        draft = R.draft(target, shim)
        change = draft.get("change") or {}
        if str(draft.get("by", "")).startswith("llm"):
            used_llm = True

        # Campaign-level gate: re-simulate the candidate on the cumulative records and
        # accept ONLY if it removes the target and opens no new critical. This is the
        # engine having the final say over the whole-estate effect, not just the finding.
        before_all, before_crit = _all_sigs(findings), _crit_sigs(findings)
        try:
            after_findings = reanalyze(apply_remediation(records, change), assets, alias)
        except Exception as e:  # noqa: BLE001 -- a malformed change must not kill the campaign
            attempted.add(tsig)
            steps.append({
                "n": len(steps) + 1, "status": "needs_review", "target": _finding_view(target),
                "finding_id": id_map.get(tsig), "change": change, "fix_text": draft.get("fix_text"),
                "by": draft.get("by"), "reason": f"could not apply the proposed change ({e})",
                "sub_attempts": draft.get("attempts"), "sub_trace": draft.get("trace"),
            })
            continue

        after_all, after_crit = _all_sigs(after_findings), _crit_sigs(after_findings)
        resolved_target = tsig not in after_all
        introduced_crit = sorted(f"{t}:{sorted(inv)}" for (t, inv) in (after_crit - before_crit))

        if resolved_target and not introduced_crit:
            # Accept the step. A good fix often cascades -- one rule can sit on
            # several findings' paths -- so count everything this step cleared.
            cleared_count = len(before_all - after_all)
            records = apply_remediation(records, change)
            applied_changes.append(change)
            findings = after_findings
            counts = _band_counts(findings)
            trajectory.append(counts["critical"])
            steps.append({
                "n": len(steps) + 1, "status": "applied", "target": _finding_view(target),
                "finding_id": id_map.get(tsig), "change": change, "fix_text": draft.get("fix_text"),
                "by": draft.get("by"), "sub_attempts": draft.get("attempts"), "sub_trace": draft.get("trace"),
                "criticals_before": len(before_crit), "criticals_after": counts["critical"],
                "findings_cleared": cleared_count, "band_counts_after": counts,
            })
        else:
            # Cannot cleanly fix this one on the current state -> hand to a human,
            # skip it, and keep driving the rest down.
            attempted.add(tsig)
            reason = ("the fix would open new critical(s): " + ", ".join(introduced_crit)) if introduced_crit \
                else "no validated fix resolves this finding on the current state"
            steps.append({
                "n": len(steps) + 1, "status": "needs_review", "target": _finding_view(target),
                "finding_id": id_map.get(tsig), "change": change, "fix_text": draft.get("fix_text"),
                "by": draft.get("by"), "reason": reason,
                "sub_attempts": draft.get("attempts"), "sub_trace": draft.get("trace"),
            })

    final_counts = _band_counts(findings)
    residual = [_finding_view(f) for f in _worst_first(findings) if f.severity_band in target_bands]
    applied = [s for s in steps if s["status"] == "applied"]
    return {
        "target_bands": list(target_bands),
        "initial_counts": initial_counts,
        "final_counts": final_counts,
        "criticals_trajectory": trajectory,
        "steps": steps,
        "applied_count": len(applied),
        "needs_review_count": len(steps) - len(applied),
        "residual_findings": residual,
        "cleared_all_criticals": final_counts["critical"] == 0,
        "applied_changes": applied_changes,
        "by": "llm" if used_llm else "engine_fallback",
    }
