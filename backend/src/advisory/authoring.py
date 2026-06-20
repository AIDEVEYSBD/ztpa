"""LLM connector-authoring assist (design-time).

Given a SAMPLE of an unknown tool's export, the model proposes a SourceProfile
(declarative config). The engine then VALIDATES it deterministically by actually
normalizing the sample. A human approves before it is saved. At runtime the model
is gone -- only the deterministic profile_normalizer runs. The model authors
validated config a human signs off on; never opaque runtime code.
"""

from __future__ import annotations

import json

from ..normalizers.common import NormalizeResult
from ..normalizers.profile import SourceProfile, apply_profile
from .client import complete, parse_json

_PROMPT = (
    "You map an unknown network-policy tool's JSON export to a SourceProfile the deterministic "
    "normalizer can apply. Inspect the sample and return ONLY JSON:\n"
    "{\"tool\": \"<short id e.g. sd_wan>\", \"rules_path\": \"<top-level key holding the list of rules>\", "
    "\"objects_path\": \"<key holding an object/label catalog, or null>\", "
    "\"fields\": {\"src\": \"<field>\", \"dst\": \"<field>\", \"action\": \"<field or null>\", "
    "\"default_action\": \"allow\", \"service\": \"<field giving tcp/443 or null>\", "
    "\"port\": \"<field giving int port or null>\", \"protocol\": \"<field or null>\", "
    "\"order\": \"<field or null>\", \"ref\": \"<field giving rule id or null>\"}}\n"
    "Pick the list that contains the allow/deny rules. Map source/destination/service/action precisely."
)


def validate_profile(profile: SourceProfile, sample: dict) -> dict:
    try:
        nr: NormalizeResult = apply_profile(sample, profile)
    except Exception as e:  # noqa: BLE001
        return {"valid": False, "error": str(e), "records": 0}
    ok = bool(nr.records) and all(r.source and r.destination and r.service for r in nr.records)
    return {
        "valid": ok,
        "records": len(nr.records),
        "entities": len(nr.entities),
        "sample_rows": [{"source": r.source, "destination": r.destination, "service": r.service,
                         "action": r.action} for r in nr.records[:4]],
    }


def propose_profile(sample: dict, tool_hint: str = "") -> dict:
    user = (f"tool hint: {tool_hint}\n" if tool_hint else "") + "sample export:\n" + json.dumps(sample)[:6000]
    r = complete(system=_PROMPT, user=user, role="judge", temperature=0.0, expect_json=True)
    data = parse_json(r.text, None) if r.ok else None
    if not isinstance(data, dict):
        return {"ok": False, "needs_review": True, "reason": "Model did not return a profile.",
                "raw": (r.text or "")[:300]}
    try:
        profile = SourceProfile(**data)
    except Exception as e:  # noqa: BLE001
        return {"ok": False, "needs_review": True, "reason": f"Proposed profile invalid: {e}", "proposed": data}
    validation = validate_profile(profile, sample)
    return {"ok": True, "profile": profile.model_dump(), "validation": validation,
            "approved": False, "by": f"{r.provider}:{r.model}",
            "note": "Review the profile + validated sample rows, then approve to register this connector."}
