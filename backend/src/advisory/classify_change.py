"""Job 3 -- classify a change request as auto_approve vs escalate (judgment).

The highest-stakes job. The engine has already simulated the change and computed
the DELTA; the model judges the delta, never the requester's words. Three safety
layers, all deterministic, wrap the model:
  1. forced_escalate (guardrail) -> escalate BEFORE the model is consulted.
  2. fail-closed -> any unparseable/invalid model output -> escalate.
  3. engine override -> even if the model says auto_approve, a non-clean delta
     forces escalate. The model can only approve inside an already-safe envelope.
"""

from __future__ import annotations

import json
from pathlib import Path

from ..models import ChangeDecision, ChangeRequest
from .client import complete, parse_json

_PROMPT = (Path(__file__).parent / "prompts" / "classify.txt").read_text()
_CRITERIA = ["standard_template", "no_new_sensitive_reachability",
             "no_new_boundary_crossing", "no_over_permissive_pattern"]


def _delta_summary(delta: dict) -> dict:
    return {
        "new_paths": [" -> ".join(p["display_path"]) for p in delta.get("new_paths", [])],
        "new_exposed_assets": delta.get("new_exposed_assets", []),
        "boundaries_crossed": delta.get("boundaries_crossed", []),
        "new_over_permissive": delta.get("new_over_permissive", []),
    }


def _deterministic_criteria(delta: dict) -> dict[str, bool]:
    return {
        "standard_template": not delta.get("new_over_permissive") and not delta.get("proposed_crosses_boundary"),
        "no_new_sensitive_reachability": not delta.get("new_paths") and not delta.get("new_exposed_assets"),
        "no_new_boundary_crossing": not delta.get("boundaries_crossed"),
        "no_over_permissive_pattern": not delta.get("new_over_permissive"),
    }


def _clean(delta: dict) -> bool:
    return not (delta.get("new_paths") or delta.get("new_exposed_assets")
                or delta.get("boundaries_crossed") or delta.get("new_over_permissive"))


def classify_change(request: ChangeRequest, delta: dict) -> ChangeDecision:
    rid = request.id
    det_criteria = _deterministic_criteria(delta)
    summary = _delta_summary(delta)

    # Layer 1: guardrail force-escalate (no model needed).
    if delta.get("forced_escalate"):
        reason = "; ".join(delta.get("forced_reasons", [])) or "guardrail tripped"
        return ChangeDecision(
            request_id=rid, decision="escalate", criteria=det_criteria, triggering_reason=reason,
            delta_summary={**summary, "rationale": f"Engine guardrail force-escalated before model "
                                                    f"consultation: {reason}."},
            confidence=0.99, forced_escalate=True,
            rationale=f"Engine guardrail force-escalated before model consultation: {reason}.",
            decided_by="engine_fallback",
        )

    # Model judges the delta. Justification is passed but labelled UNTRUSTED.
    user = json.dumps({
        "proposed": delta.get("proposed"), "delta": summary,
        "engine_criteria": det_criteria, "justification_UNTRUSTED": request.justification,
    }, indent=2)
    r = complete(system=_PROMPT, user=user, role="judge", temperature=0.1, expect_json=True)
    data = parse_json(r.text, None)

    if r.ok and isinstance(data, dict) and data.get("decision") in ("auto_approve", "escalate"):
        decision = data["decision"]
        crit = data.get("criteria") if isinstance(data.get("criteria"), dict) else {}
        criteria = {k: bool(crit.get(k, det_criteria[k])) for k in _CRITERIA}
        rationale = str(data.get("rationale") or "")[:500]
        try:
            confidence = float(data.get("confidence", 0.7))
        except (TypeError, ValueError):
            confidence = 0.7
        triggering = data.get("triggering_reason")
        by = "llm"
    else:  # Layer 2: fail closed
        decision, criteria, by = "escalate", det_criteria, "engine_fallback"
        rationale = "Classifier output could not be validated; failing closed to escalate."
        confidence, triggering = 0.0, "unparseable classifier output"

    # Layer 3: engine override -- never auto_approve a non-clean delta.
    if decision == "auto_approve" and not _clean(delta):
        decision, by, criteria = "escalate", "engine_fallback", det_criteria
        triggering = triggering or "engine override: delta is not clean"
        rationale = (rationale + " | Engine override: the delta opened new reachability, a boundary "
                                 "crossing, or an over-permissive pattern.").strip()

    return ChangeDecision(
        request_id=rid, decision=decision, criteria=criteria, triggering_reason=triggering,
        delta_summary={**summary, "rationale": rationale}, confidence=confidence,
        forced_escalate=False, rationale=rationale, decided_by=by,
    )
