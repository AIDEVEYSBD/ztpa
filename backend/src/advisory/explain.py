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
        why = "; ".join(s.get("reasons", [])) or "the grant is broader than necessary"
        return (f"Rule {ref} allows {access} from {src} to {s.get('dest_display')} ({tags}). "
                f"This is over-permissive because {why}. Suggested fix: scope the source to only the "
                f"hosts that genuinely need {access}, and remove any internet exposure.")
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
    return f"{f.title} (refs: {ref})."


def explain(f: Finding, timeout: float | None = None) -> dict:
    r = complete(system=_PROMPT, user=json.dumps(_facts(f), indent=2), role="prose", temperature=0.4, timeout=timeout)
    if r.ok and r.text.strip():
        return {"explanation": r.text.strip(), "by": f"{r.provider}:{r.model}"}
    return {"explanation": _fallback(f), "by": "engine_fallback"}
