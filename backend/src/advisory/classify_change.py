"""Job 3 -- classify a change request as auto_approve vs escalate (agentic judgment).

The highest-stakes job. The engine has already simulated the change and computed
the DELTA; the model judges the delta, never the requester's words.

Before ruling, the model runs an AGENTIC INVESTIGATION: it calls the deterministic
engine tools (effective_policy / find_paths / reachable / resolve / risk_findings)
to gather evidence about the proposed destination and what the change would expose
-- choosing which tool to call next itself, ReAct-style. It never computes
reachability; it only asks the engine and reasons over the structured answers. The
gathered evidence is then handed to the decision step and shown in the audit trail.

Three safety layers, all deterministic, still wrap the model regardless of what the
investigation concludes:
  1. forced_escalate (guardrail) -> escalate BEFORE any model call or investigation.
  2. fail-closed -> any unparseable/invalid model output -> escalate.
  3. engine override -> even if the model says auto_approve, a non-clean delta
     forces escalate. The model can only approve inside an already-safe envelope.
The investigation only adds evidence; it can never widen what the gate will approve.
"""

from __future__ import annotations

import json
from pathlib import Path

from ..agent.tools import (
    effective_policy as _t_effective_policy, find_paths as _t_find_paths,
    reachable as _t_reachable, resolve as _t_resolve, risk_findings as _t_risk_findings,
)
from ..metrics import record_metric
from ..models import ChangeDecision, ChangeRequest
from .client import complete, parse_json

_PROMPT = (Path(__file__).parent / "prompts" / "classify.txt").read_text()
_CRITERIA = ["standard_template", "no_new_sensitive_reachability",
             "no_new_boundary_crossing", "no_over_permissive_pattern"]

# How many evidence-gathering tool calls the investigator may make before it must
# decide. Bounds latency/cost; the decision proceeds with whatever it has gathered.
MAX_TOOL_CALLS = 4

# The read-only engine tools the investigator may call, with the arg names each
# accepts. We filter model-supplied args to these so a hallucinated kwarg can't
# raise -- an unknown tool or bad args degrades to a recorded error, never a crash.
_INVESTIGATE_TOOLS: dict[str, tuple] = {
    "effective_policy": (_t_effective_policy, ("asset",)),
    "find_paths": (_t_find_paths, ("src", "dst")),
    "reachable": (_t_reachable, ("src", "dst", "port")),
    "resolve": (_t_resolve, ("name",)),
    "risk_findings": (_t_risk_findings, ("type", "min_severity")),
}

_INVESTIGATE_SYSTEM = (
    "You are a change-review INVESTIGATOR for a zero-trust policy gate. A change has been "
    "proposed and the deterministic engine has already computed its delta. Before the gate "
    "rules, gather EVIDENCE by calling engine tools -- you never compute reachability or "
    "subnet math yourself, you ask the engine.\n"
    "Tools:\n"
    "- effective_policy(asset): what can currently reach an asset; is it internet-exposed.\n"
    "- find_paths(src, dst): every path between two endpoints, with the tools each hop crosses.\n"
    "- reachable(src, dst, port): can src reach dst (optionally on a port)?\n"
    "- resolve(name): the canonical asset for a name or CIDR (tags, zone, source tools).\n"
    "- risk_findings(type, min_severity): existing deterministic findings.\n"
    "Investigate the proposed DESTINATION: what already reaches it, whether it is sensitive, "
    "and whether the proposed source would open a path toward regulated data.\n"
    "Each turn respond with ONLY JSON. To gather more evidence: "
    "{\"thought\": \"why\", \"tool\": \"<name>\", \"args\": {...}}. "
    "When you have enough: {\"thought\": \"what the evidence shows\", \"done\": true}. "
    f"Use at most {MAX_TOOL_CALLS} tool calls."
)


def _run_tool(ctx, name: str, args: dict) -> dict:
    fn, allowed = _INVESTIGATE_TOOLS[name]
    kwargs = {k: v for k, v in (args or {}).items() if k in allowed}
    try:
        out = fn(ctx, **kwargs)
        ok, err = True, None
    except Exception as e:  # noqa: BLE001 -- a bad tool call is evidence, not a crash
        out, ok, err = {"error": f"{type(e).__name__}: {e}"}, False, str(e)
    record_metric(kind="agent_tool", capability="classify", tool_name=name,
                  provider="engine", model="deterministic", ok=ok, error=err, latency_ms=0)
    return out


def _trim(obj) -> object:
    """Cap a tool result so a large path list can't blow the decision prompt.
    Returns the object as-is when small; otherwise a truncated string marker."""
    s = json.dumps(obj)
    if len(s) <= 1500:
        return obj
    return {"_truncated": s[:1500]}


def investigate(ctx, request: ChangeRequest, delta: dict) -> list[dict]:
    """ReAct-style evidence gathering over the engine tools. Provider-portable and
    fail-open: if the model is unavailable or emits garbage, returns whatever
    evidence was collected (possibly empty) and the decision proceeds without it."""
    if ctx is None:
        return []
    context = json.dumps({
        "proposed": delta.get("proposed"),
        "computed_delta": {
            "new_paths": [" -> ".join(p["display_path"]) for p in delta.get("new_paths", [])],
            "new_exposed_assets": delta.get("new_exposed_assets", []),
            "boundaries_crossed": delta.get("boundaries_crossed", []),
            "new_over_permissive": delta.get("new_over_permissive", []),
        },
    })
    trace: list[dict] = []
    for _ in range(MAX_TOOL_CALLS):
        user = (f"Proposed change + computed delta:\n{context}\n\n"
                f"Evidence gathered so far:\n{json.dumps(trace)[:3000]}\n\nYour next action (JSON only).")
        r = complete(system=_INVESTIGATE_SYSTEM, user=user, role="judge", capability="classify",
                     temperature=0.0, expect_json=True, timeout=60.0, subject=request.id)
        if not r.ok:
            break
        data = parse_json(r.text, None)
        if not isinstance(data, dict):
            break
        if data.get("done"):
            if data.get("thought"):
                trace.append({"thought": str(data["thought"])[:300], "done": True})
            break
        tool = data.get("tool")
        args = data.get("args") if isinstance(data.get("args"), dict) else {}
        if tool not in _INVESTIGATE_TOOLS:
            trace.append({"thought": str(data.get("thought", ""))[:300], "tool": tool,
                          "error": "unknown or unavailable tool"})
            continue
        result = _run_tool(ctx, tool, args)
        trace.append({"thought": str(data.get("thought", ""))[:300], "tool": tool, "args": args,
                      "result": _trim(result)})
    return trace


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


def classify_change(request: ChangeRequest, delta: dict, ctx=None) -> ChangeDecision:
    """Rule on a change. When `ctx` (an EngineResult) is supplied the model first
    runs the agentic investigation; without it, it falls back to the one-shot
    delta judgment (used by tests and any caller that has no live engine)."""
    rid = request.id
    det_criteria = _deterministic_criteria(delta)
    summary = _delta_summary(delta)

    # Layer 1: guardrail force-escalate (no model, no investigation needed).
    if delta.get("forced_escalate"):
        reason = "; ".join(delta.get("forced_reasons", [])) or "guardrail tripped"
        return ChangeDecision(
            request_id=rid, decision="escalate", criteria=det_criteria, triggering_reason=reason,
            delta_summary={**summary, "investigation": [], "rationale": f"Engine guardrail force-escalated "
                           f"before model consultation: {reason}."},
            confidence=0.99, forced_escalate=True,
            rationale=f"Engine guardrail force-escalated before model consultation: {reason}.",
            decided_by="engine_fallback",
        )

    # Agentic investigation: the model gathers evidence from the engine tools first.
    # Fail-open -- an empty trace just means the decision proceeds on the delta alone.
    investigation = investigate(ctx, request, delta)

    # Model judges the delta + gathered evidence. Justification is UNTRUSTED.
    user = json.dumps({
        "proposed": delta.get("proposed"), "delta": summary,
        "engine_criteria": det_criteria, "justification_UNTRUSTED": request.justification,
        "investigation_evidence": investigation,
    }, indent=2)
    r = complete(system=_PROMPT, user=user, role="judge", capability="classify",
                 temperature=0.1, expect_json=True)
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
        delta_summary={**summary, "investigation": investigation, "rationale": rationale},
        confidence=confidence, forced_escalate=False, rationale=rationale, decided_by=by,
    )
