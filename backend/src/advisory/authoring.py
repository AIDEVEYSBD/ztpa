"""LLM connector-authoring assist (design-time), an AGENTIC self-correcting loop.

Given a SAMPLE of an unknown tool's export, the model proposes a SourceProfile
(declarative config). The engine then VALIDATES it deterministically by actually
normalizing the sample -- and when the profile is wrong (bad rules_path, unmapped
fields, rows missing source/dest/service) the concrete failure is fed back and the
model REVISES, up to `MAX_ATTEMPTS` rounds, until the sample normalizes cleanly.

A human approves before it is saved. At runtime the model is gone -- only the
deterministic profile_normalizer runs. The model authors validated config a human
signs off on; never opaque runtime code. The full attempt trace is returned so the
reviewer can see how the connector was derived (and that the engine, not the model,
certified it).
"""

from __future__ import annotations

import json

from ..normalizers.common import NormalizeResult
from ..normalizers.profile import SourceProfile, apply_profile
from .client import complete, parse_json

# Propose -> normalize the sample -> observe failures -> revise. Bounded so a cold
# model degrades to "needs review" with the best partial profile instead of hanging.
MAX_ATTEMPTS = 3

_PROMPT = (
    "You map an unknown network-policy tool's JSON export to a SourceProfile the deterministic "
    "normalizer can apply. You work in a LOOP: the engine will try to normalize the sample with "
    "your profile and tell you exactly what failed; fix it and try again.\n"
    "Inspect the sample and return ONLY JSON:\n"
    "{\"tool\": \"<short id e.g. sd_wan>\", \"rules_path\": \"<top-level key holding the list of rules>\", "
    "\"objects_path\": \"<key holding an object/label catalog, or null>\", "
    "\"fields\": {\"src\": \"<field>\", \"dst\": \"<field>\", \"action\": \"<field or null>\", "
    "\"default_action\": \"allow\", \"service\": \"<field giving tcp/443 or null>\", "
    "\"port\": \"<field giving int port or null>\", \"protocol\": \"<field or null>\", "
    "\"order\": \"<field or null>\", \"ref\": \"<field giving rule id or null>\"}}\n"
    "Pick the list that contains the allow/deny rules. Map source/destination/service/action precisely. "
    "If the engine reports zero records, your rules_path is wrong. If rows are missing a source, "
    "destination, or service, the corresponding field name is wrong -- inspect the sample's keys again."
)


def validate_profile(profile: SourceProfile, sample: dict) -> dict:
    try:
        nr: NormalizeResult = apply_profile(sample, profile)
    except Exception as e:  # noqa: BLE001
        return {"valid": False, "error": str(e), "records": 0, "unmapped": []}
    unmapped = sorted({
        field for r in nr.records for field, val in
        (("source", r.source), ("destination", r.destination), ("service", r.service)) if not val
    })
    ok = bool(nr.records) and not unmapped
    return {
        "valid": ok,
        "records": len(nr.records),
        "entities": len(nr.entities),
        "unmapped": unmapped,
        "sample_rows": [{"source": r.source, "destination": r.destination, "service": r.service,
                         "action": r.action} for r in nr.records[:4]],
    }


def _feedback(validation: dict) -> str:
    """Turn a validation result into a concise instruction for the next round."""
    if validation.get("error"):
        return (f"The engine could not apply the profile (error: {validation['error']}). The rules_path "
                "or a field name does not exist in the sample -- re-read the sample's top-level keys.")
    if not validation.get("records"):
        return ("The engine produced ZERO records -- rules_path does not point at the list of rules. "
                "Pick the top-level key whose value is the array of allow/deny rules.")
    if validation.get("unmapped"):
        return (f"Rows are missing these fields: {', '.join(validation['unmapped'])}. The field name(s) you "
                "mapped for them are wrong -- inspect the rule objects' keys and remap precisely.")
    return "The engine validated the profile."


def _build_user(sample: dict, tool_hint: str, prior: dict | None, feedback: str | None) -> str:
    user = (f"tool hint: {tool_hint}\n" if tool_hint else "") + "sample export:\n" + json.dumps(sample)[:6000]
    if prior or feedback:
        user += (f"\n\nYour previous profile did not validate -- revise it.\nPrevious profile: "
                 f"{json.dumps(prior or {})}\nEngine feedback: {feedback or ''}")
    return user


def propose_profile(sample: dict, tool_hint: str = "", max_attempts: int | None = None) -> dict:
    """Agentic connector authoring: propose -> the engine normalizes the sample ->
    observe the concrete failure -> revise, until the sample normalizes cleanly or
    the attempt budget is spent. Returns the best profile plus the full attempt
    trace; `ok=True` with `validation.valid=True` means the engine certified it."""
    max_attempts = MAX_ATTEMPTS if max_attempts is None else max_attempts
    trace: list[dict] = []
    best: dict | None = None          # best partial: a parseable profile that made the most records
    prior, feedback, by = None, None, "engine_fallback"

    for i in range(max_attempts):
        r = complete(system=_PROMPT, user=_build_user(sample, tool_hint, prior, feedback),
                     role="judge", capability="authoring", temperature=0.0, expect_json=True)
        by = f"{r.provider}:{r.model}"
        data = parse_json(r.text, None) if r.ok else None
        if not isinstance(data, dict):
            trace.append({"attempt": i + 1, "profile": None, "error": "model did not return a profile object"})
            break
        try:
            profile = SourceProfile(**data)
        except Exception as e:  # noqa: BLE001 -- schema-invalid: feed the error back and retry
            trace.append({"attempt": i + 1, "profile": data, "error": f"schema-invalid: {e}"})
            prior, feedback = data, f"The profile failed schema validation: {e}. Return all required keys."
            continue

        validation = validate_profile(profile, sample)
        pd = profile.model_dump()
        trace.append({"attempt": i + 1, "profile": pd, "validation": validation})
        if validation["valid"]:
            return {"ok": True, "profile": pd, "validation": validation, "attempts": len(trace),
                    "trace": trace, "approved": False, "by": by,
                    "note": "The engine normalized your sample cleanly. Review the rows, then approve to "
                            "register this connector."}
        if best is None or validation.get("records", 0) > (best[1].get("records", 0)):
            best = (pd, validation)
        prior, feedback = pd, _feedback(validation)

    # No clean profile within the budget -> return the best partial for human review.
    if best is not None:
        pd, validation = best
        return {"ok": True, "profile": pd, "validation": validation, "attempts": len(trace),
                "trace": trace, "approved": False, "needs_review": True, "by": by,
                "note": "The engine could not fully validate this profile automatically. Review the "
                        "highlighted gaps and correct the mapping before registering."}
    return {"ok": False, "needs_review": True, "attempts": len(trace), "trace": trace, "by": by,
            "reason": "The model did not return a usable profile for this sample."}
