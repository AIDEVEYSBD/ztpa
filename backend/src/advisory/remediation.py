"""Capability #5 -- remediation drafting (fix-as-code), VALIDATED by the engine.

The model drafts a concrete fix (human text + a structured rule change). The
engine then RE-SIMULATES that change deterministically and proves whether it (a)
resolves the finding and (b) introduces no new critical findings. AI proposes;
the engine is the judge. A deterministic fallback fix exists for every type."""

from __future__ import annotations

import json

from ..analyzers.run_all import reanalyze
from ..models import Finding
from ..normalizers.common import is_cidr, parse_service
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


def _apply(records, change: dict):
    op, ref = change.get("op"), change.get("target_ref")
    order_of = {r.raw_ref: r.order for r in records if r.order is not None}
    shadowing_order = order_of.get(change.get("shadowing_ref"))
    out = []
    for rec in records:
        if rec.raw_ref == ref:
            if op == "remove":
                continue
            if op == "scope_source" and change.get("new_source"):
                ns = change["new_source"]
                rec = rec.model_copy(update={"source": ns, "source_kind": "cidr" if is_cidr(ns) else "identity"})
            elif op == "restrict_service" and change.get("new_service"):
                proto, port, label = parse_service(change["new_service"])
                rec = rec.model_copy(update={"service": label, "port": port, "protocol": proto})
            elif op == "reorder_before" and shadowing_order is not None:
                rec = rec.model_copy(update={"order": shadowing_order - 1})
        out.append(rec)
    return out


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


def draft(finding: Finding, ctx) -> dict:
    # Bounded so a cold local model degrades to the deterministic fix instead of
    # hanging the request (which a dev proxy resets). The fix is still validated
    # by re-simulation regardless of whether the model or the fallback proposed it.
    r = complete(system=_PROMPT, user=json.dumps(_facts(finding)), role="judge",
                 temperature=0.2, expect_json=True, timeout=120.0)
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
