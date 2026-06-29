"""Capability #5 -- remediation drafting (fix-as-code), VALIDATED by the engine.

The model drafts a concrete fix (human text + a structured rule change). The
engine then RE-SIMULATES that change deterministically and proves whether it (a)
resolves the finding and (b) introduces no new critical findings. AI proposes;
the engine is the judge. A deterministic fallback fix exists for every type."""

from __future__ import annotations

import json

from ..analyzers.run_all import reanalyze
from ..change.apply import apply_remediation as _apply
from ..models import Finding
from .client import complete, parse_json

_PROMPT = (
    "You are a network security engineer proposing a concrete fix for ONE finding.\n"
    "Return ONLY JSON: {\"fix_text\": \"2-3 sentences for the admin\", \"change\": {\"op\": "
    "\"remove|scope_source|restrict_service|reorder_before\", \"target_ref\": \"<rule ref>\", "
    "\"new_source\": \"<cidr, for scope_source>\", \"new_service\": \"<proto/port, for restrict_service>\"}}.\n"
    "Choose the most surgical change that closes the exposure. Use a rule ref from the finding's raw_refs. "
    "Reason only from the finding's facts."
)


def _facts(f: Finding) -> dict:
    return {"id": f.id, "type": f.type, "title": f.title, "raw_refs": f.raw_refs,
            "involved": f.involved, "signals": {k: v for k, v in f.signals.items()
                                                if k not in ("severity_vector",)}}


def _sig(f: Finding):
    return (f.type, frozenset(f.involved))


def _fallback_change(f: Finding, records) -> dict:
    s = f.signals
    if f.type == "over_permissive":
        return {"op": "remove", "target_ref": f.raw_refs[0]}
    if f.type == "cross_tool_path":
        return {"op": "remove", "target_ref": f.raw_refs[-1]}   # break the hop into the crown jewel
    if f.type == "cidr_overlap":
        inner = s.get("inner")
        ref = next((r.raw_ref for r in records if r.source == inner and r.destination == s.get("dest")
                    and r.service == s.get("service")), f.raw_refs[0])
        return {"op": "remove", "target_ref": ref}
    if f.type == "shadowed_rule":
        return {"op": "reorder_before", "target_ref": s.get("shadowed_ref"),
                "shadowing_ref": s.get("shadowing_ref")}
    if f.type == "transport_exposure":
        # Drop the uninspectable (QUIC/UDP) grant. For fallback-not-blocked that is
        # the udp side specifically (keep the inspectable TLS path); for a blind
        # spot it is the rule itself.
        if s.get("subtype") == "tls_fallback_not_blocked":
            udp_refs = s.get("udp_refs") or f.raw_refs
            return {"op": "remove", "target_ref": udp_refs[0]}
        return {"op": "remove", "target_ref": f.raw_refs[0]}
    return {"op": "remove", "target_ref": f.raw_refs[0]}


def _fallback_text(f: Finding, change: dict) -> str:
    op = change.get("op")
    ref = change.get("target_ref")
    if op == "remove":
        return f"Remove rule {ref}, which creates this exposure. Re-validate that no legitimate flow depended on it."
    if op == "scope_source":
        return f"Scope rule {ref}'s source to {change.get('new_source')} so only intended hosts retain access."
    if op == "reorder_before":
        return f"Move rule {ref} above {change.get('shadowing_ref')} so the intended deny actually takes effect."
    return f"Adjust rule {ref} to remove the over-permissive grant."


def _coerce_change(data, f: Finding) -> dict | None:
    if not isinstance(data, dict) or not isinstance(data.get("change"), dict):
        return None
    ch = data["change"]
    if ch.get("op") not in ("remove", "scope_source", "restrict_service", "reorder_before"):
        return None
    if not ch.get("target_ref"):
        return None
    if f.type == "shadowed_rule" and not ch.get("shadowing_ref"):
        ch["shadowing_ref"] = f.signals.get("shadowing_ref")
    return ch


def _validate(ctx, finding: Finding, change: dict) -> dict:
    target = _sig(finding)
    before = ctx.findings
    try:
        after = reanalyze(_apply(ctx.records, change), ctx.assets, ctx.alias_map)
        before_crit = {_sig(x) for x in before if x.severity_band == "critical"}
        after_crit = {_sig(x) for x in after if x.severity_band == "critical"}
        return {
            "resolves": target not in {_sig(x) for x in after},
            "introduces_new_criticals": sorted(f"{t}:{sorted(inv)}" for (t, inv) in (after_crit - before_crit)),
            "findings_before": len(before), "findings_after": len(after),
        }
    except Exception as e:  # noqa: BLE001
        return {"resolves": False, "error": str(e)}


def draft(finding: Finding, ctx, comment: str | None = None, prior: dict | None = None) -> dict:
    # Bounded so a cold local model degrades to the deterministic fix instead of
    # hanging the request (which a dev proxy resets). The fix is still validated
    # by re-simulation regardless of whether the model or the fallback proposed it.
    # `comment` + `prior` let the Risk-To-Do thread iterate: the model revises the
    # previous proposal in light of the reviewer's feedback rather than starting cold.
    user = json.dumps(_facts(finding))
    if comment or prior:
        user += (
            "\n\nThe reviewer is iterating on a prior proposal. Revise it to address their"
            f" comment.\nPrior fix: {json.dumps(prior or {})}\nReviewer comment: {comment or ''}"
        )
    r = complete(system=_PROMPT, user=user, role="judge", capability="remediate",
                 temperature=0.2, expect_json=True, timeout=120.0, subject=finding.id)
    data = parse_json(r.text, None) if r.ok else None
    llm_change = _coerce_change(data, finding)
    llm_text = data.get("fix_text") if isinstance(data, dict) else None

    change, by = llm_change, "llm"
    validation = _validate(ctx, finding, change) if change else None

    # AI proposes; the engine is the judge. If the AI's fix does not hold, fall
    # back to the deterministic surgical fix and re-validate -- so what we present
    # always provably resolves the finding (or honestly reports it cannot).
    if not (validation and validation.get("resolves")):
        fallback = _fallback_change(finding, ctx.records)
        fb_validation = _validate(ctx, finding, fallback)
        if llm_change:
            fb_validation["engine_corrected_ai"] = True
        change, validation = fallback, fb_validation
        by = "llm+engine_fallback" if llm_change else "engine_fallback"

    fix_text = llm_text or _fallback_text(finding, change)
    return {"finding_id": finding.id, "fix_text": str(fix_text)[:500], "change": change,
            "validation": validation, "by": by}
