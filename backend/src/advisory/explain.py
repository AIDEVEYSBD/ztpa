"""Job 1 -- explain a finding in plain English (language).

Reasons only from the finding's facts; adds domain knowledge (what a port is, the
attack pattern) but invents no network-specific facts. Always returns something:
if the model is unavailable, a deterministic, fact-grounded fallback is used."""

from __future__ import annotations

import json
from pathlib import Path

from ..models import Finding
from .client import complete

_PROMPT = (Path(__file__).parent / "prompts" / "explain.txt").read_text()


def _facts(f: Finding) -> dict:
    signals = {k: v for k, v in f.signals.items() if k != "severity_vector"}
    return {
        "id": f.id, "type": f.type, "title": f.title, "severity": f.severity,
        "severity_band": f.severity_band, "forced_critical": f.forced_critical,
        "raw_refs": f.raw_refs, "source_tools": f.source_tools, "signals": signals,
    }


def _fallback(f: Finding) -> str:
    s = f.signals
    ref = ", ".join(f.raw_refs)
    if f.type == "over_permissive":
        access = "any protocol/port" if s.get("protocol") == "any" else (s.get("port_name") or s.get("service"))
        src = "the internet (0.0.0.0/0)" if s.get("source") == "0.0.0.0/0" else s.get("source")
        tags = ", ".join(s.get("dest_tags") or []) or "internal"
        # A LABEL, not a subordinate clause. `_reasons` returns bare predicate
        # phrases in the operator's words ("exposed directly to the internet"),
        # and the old frame read "over-permissive because allows every protocol
        # and port; exposed directly to the internet" -- ungrammatical from the
        # second phrase on. Rewording the phrases to fit the clause would have
        # put the explainer in the business of editing analyzer output, so the
        # frame moved instead.
        why = "; ".join(s.get("reasons", [])) or "the grant is broader than necessary"
        return (f"Rule {ref} allows {access} from {src} to {s.get('dest_display')} ({tags}). "
                f"Over-permissive: {why}. "
                f"Suggested fix: scope the source to only the hosts that genuinely need "
                f"{access}, and remove any internet exposure.")
    if f.type == "cross_tool_path":
        path = s.get("display_path", [])
        return (f"A reachability chain crosses {len(s.get('tools', []))} tools "
                f"({', '.join(s.get('tools', []))}) from {path[0] if path else '?'} to "
                f"{path[-1] if path else '?'} ({', '.join(s.get('terminal_tags', []))}) -- a "
                f"{s.get('boundary')} crossing that no single tool reveals. Break one hop "
                f"(e.g. rule {f.raw_refs[0] if f.raw_refs else '?'}) to cut the chain.")
    if f.type == "cidr_overlap":
        return (f"Rules {ref} are redundant: {s.get('outer')} already covers {s.get('inner')} for "
                f"{s.get('dest')} ({s.get('service')}). Remove the narrower rule to cut policy clutter.")
    if f.type == "shadowed_rule":
        return (f"{s.get('reason', 'A later rule can never fire because an earlier rule matches first.')} "
                f"Reorder or remove rule {s.get('shadowed_ref')} so the intended policy is actually enforced.")
    if f.type == "transport_exposure":
        app = (s.get("l7_app") or "").upper() or s.get("service")
        how = ("the export named it" if s.get("l7_source") == "declared"
               else "we decoded it from the protocol and port")
        src = "the internet (0.0.0.0/0)" if s.get("source") == "0.0.0.0/0" else s.get("source")
        tags = ", ".join(s.get("dest_tags") or []) or "internal"
        if s.get("subtype") == "quic_blind_spot":
            return (f"{app} ({s.get('service')}) is reachable from {src} to "
                    f"{s.get('dest_display')} ({tags}). QUIC carries HTTP inside UDP and is "
                    f"encrypted end to end, so most inspection stacks see an opaque UDP flow "
                    f"rather than the web traffic it actually is -- the rule looks narrow and the "
                    f"visibility is not there. Identified because {how}. Suggested fix: block "
                    f"{s.get('service')} so clients fall back to the inspectable TCP path, or "
                    f"terminate and inspect QUIC explicitly.")
        return (f"{app} ({s.get('service')}) is reachable from {src} to "
                f"{s.get('dest_display')} ({tags}), on a transport this estate is unlikely to be "
                f"inspecting. Identified because {how}. Suggested fix: restrict the source, or "
                f"move the service onto a transport the inspection stack actually decodes.")
    # Deliberately NOT a generic "see the signals". `title` is the analyzer's own
    # deterministic one-line statement of the finding, and `raw_refs` says which
    # rules it came from -- together they are a real sentence, not a placeholder.
    return f"{f.title} (refs: {ref})." if ref else f.title


def engine_explanation(f: Finding) -> str:
    """The deterministic explanation. ALWAYS available, no model, no network.

    This exists because the console used to render "No explanation has been
    written for this finding yet" on every finding nobody had manually clicked
    "Ask the advisory layer" for -- which was false. The engine can always say
    what a finding means; it computed it. What it cannot do without a model is
    write *prose*, and those are different claims.

    So the two travel in separate fields and stay separately attributed:
    `engine_explanation` (this, always) and `explanation` (model prose, null
    until asked). A reader is never shown an absence where a fact exists, and
    never shown a deterministic sentence dressed up as model judgment.
    """
    return _fallback(f)


def explain(f: Finding, timeout: float | None = None) -> dict:
    r = complete(system=_PROMPT, user=json.dumps(_facts(f), indent=2), role="prose", temperature=0.4, timeout=timeout)
    if r.ok and r.text.strip():
        return {"explanation": r.text.strip(), "by": f"{r.provider}:{r.model}"}
    return {"explanation": _fallback(f), "by": "engine_fallback"}
