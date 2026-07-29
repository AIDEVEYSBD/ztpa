"""Capability #5 -- remediation drafting (fix-as-code), an AGENTIC loop VALIDATED
by the engine.

The model drafts a concrete fix (human text + a structured rule change). The
engine then RE-SIMULATES that change deterministically and proves whether it (a)
resolves the finding and (b) introduces no new critical findings. AI proposes;
the engine is the judge.

Rather than take a single shot, the model works the problem: it proposes a fix,
SEES the engine's verdict (still reachable? introduced a new critical?), and
REVISES -- up to `MAX_ATTEMPTS` rounds -- until the engine certifies a *clean*
fix (resolves the finding AND opens no new critical). The full attempt trace is
returned so the UI can show exactly how the agent converged. A deterministic
fallback fix exists for every type and is the guaranteed safety net if the loop
never lands a clean fix -- so what we present always provably resolves the
finding (or honestly reports it cannot)."""

from __future__ import annotations

import json

from ..analyzers.run_all import reanalyze
from ..change.apply import apply_remediation as _apply
from ..models import Finding
from .client import complete, parse_json

# How many propose->simulate->observe->revise rounds the agent gets before it
# degrades to the deterministic fallback. Each round is one model call + one
# engine re-simulation, so this bounds worst-case latency (and a cold local
# model's exposure) while giving the agent room to self-correct.
MAX_ATTEMPTS = 3

_PROMPT = (
    "You are a network security engineer fixing ONE finding, working in a LOOP with a "
    "deterministic policy engine that re-simulates every fix you propose.\n"
    "Return ONLY JSON: {\"fix_text\": \"2-3 sentences for the admin\", \"reasoning\": "
    "\"one line: why this change and, if revising, what you changed vs last time\", "
    "\"change\": {\"op\": \"remove|scope_source|restrict_service|reorder_before\", "
    "\"target_ref\": \"<rule ref>\", \"new_source\": \"<cidr, for scope_source>\", "
    "\"new_service\": \"<proto/port, for restrict_service>\"}}.\n"
    "Choose the most surgical change that closes the exposure WITHOUT opening a new critical. "
    "Use a rule ref from the finding's raw_refs. Reason only from the finding's facts.\n"
    "If the engine tells you your previous change did not resolve the finding, pick a more "
    "complete change (e.g. remove the rule instead of merely scoping it, or target a different "
    "ref). If it tells you your change introduced a NEW critical, pick a narrower change (e.g. "
    "scope the source or restrict the service instead of a broad remove)."
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


def _is_clean(v: dict | None) -> bool:
    """A fix the engine certifies: it resolves the finding AND opens no new critical."""
    return bool(v) and bool(v.get("resolves")) and not v.get("introduces_new_criticals")


def _verdict_feedback(v: dict | None) -> str:
    """Turn an engine validation result into a concise instruction the agent acts on."""
    if not v or v.get("error"):
        return ("The engine could not apply that change (bad op or target_ref). Pick a valid "
                "rule ref from the finding's raw_refs and a supported op.")
    if not v.get("resolves"):
        return ("The engine re-simulated your change and the finding STILL EXISTS -- that fix "
                "does not close the exposure. Choose a more complete or better-targeted change.")
    nc = v.get("introduces_new_criticals") or []
    if nc:
        return ("Your change resolved the finding BUT the engine detected it introduces new "
                f"critical finding(s): {', '.join(nc)}. Revise so it closes the original exposure "
                "without creating a new critical -- prefer a narrower change.")
    return "The engine certified this fix."


def _build_user(finding: Finding, prior_change: dict | None, feedback: str | None) -> str:
    """The facts, plus (when iterating) the prior proposal and the feedback to act on.
    Unifies two iteration sources: a reviewer's comment and the engine's own verdict."""
    user = json.dumps(_facts(finding))
    if prior_change or feedback:
        user += (
            "\n\nYou are iterating -- revise the prior proposal in light of the feedback below.\n"
            f"Prior change: {json.dumps(prior_change or {})}\nFeedback: {feedback or ''}"
        )
    return user


def _result(finding: Finding, fix_text, change: dict, validation: dict, by: str,
            trace: list[dict]) -> dict:
    return {"finding_id": finding.id,
            "fix_text": str(fix_text or _fallback_text(finding, change))[:500],
            "change": change, "validation": validation, "by": by,
            "attempts": sum(1 for t in trace if t.get("change")), "trace": trace}


def draft(finding: Finding, ctx, comment: str | None = None, prior: dict | None = None,
          max_attempts: int | None = None) -> dict:
    """Agentic remediation: propose -> engine re-simulates -> observe -> revise, until
    the engine certifies a clean fix or the attempt budget is spent. Each round is
    bounded (one model call + one re-simulation) so a cold local model degrades to the
    deterministic fallback instead of hanging the request. `comment` + `prior` seed the
    first round from a reviewer's feedback (Risk-To-Do thread); subsequent rounds are
    seeded from the engine's own verdict."""
    max_attempts = MAX_ATTEMPTS if max_attempts is None else max_attempts
    trace: list[dict] = []
    best: tuple[dict, object, dict] | None = None  # an AI fix that at least resolves
    tried_llm = False
    prior_change, feedback = prior, comment

    for i in range(max_attempts):
        r = complete(system=_PROMPT, user=_build_user(finding, prior_change, feedback),
                     role="judge", capability="remediate", temperature=0.2,
                     expect_json=True, timeout=120.0, subject=finding.id)
        data = parse_json(r.text, None) if r.ok else None
        change = _coerce_change(data, finding)
        text = data.get("fix_text") if isinstance(data, dict) else None
        reasoning = data.get("reasoning") if isinstance(data, dict) else None
        if not change:
            trace.append({"attempt": i + 1, "by": "llm", "change": None, "validation": None,
                          "note": "model proposed no valid change"})
            break

        tried_llm = True
        validation = _validate(ctx, finding, change)
        trace.append({"attempt": i + 1, "by": "llm", "change": change,
                      "fix_text": (str(text)[:500] if text else None),
                      "reasoning": (str(reasoning)[:300] if reasoning else None),
                      "validation": validation})
        if _is_clean(validation):
            return _result(finding, text, change, validation, "llm", trace)
        if validation.get("resolves") and best is None:
            best = (change, text, validation)  # keep the first resolving fix as a floor
        prior_change, feedback = change, _verdict_feedback(validation)

    # The loop never certified a clean fix. Fall back to the deterministic surgical
    # fix (guaranteed for every finding type) and re-validate it.
    fallback = _fallback_change(finding, ctx.records)
    fb_validation = _validate(ctx, finding, fallback)
    trace.append({"attempt": len(trace) + 1, "by": "engine_fallback",
                  "change": fallback, "validation": fb_validation})

    # Prefer a clean deterministic fallback; otherwise, if some AI attempt at least
    # resolved the finding, keep that over a fallback that itself isn't clean.
    if _is_clean(fb_validation) or best is None:
        by = "llm+engine_fallback" if tried_llm else "engine_fallback"
        v = {**fb_validation, "engine_corrected_ai": True} if tried_llm else fb_validation
        return _result(finding, _fallback_text(finding, fallback), fallback, v, by, trace)
    change, text, validation = best
    return _result(finding, text, change, validation, "llm", trace)
