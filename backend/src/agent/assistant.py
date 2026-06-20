"""'Ask your network' assistant: a tool-calling loop over the deterministic tools.

The model decides which tool to call next; the engine answers with facts; the
model narrates. Every claim is grounded in a tool result. Returns the answer plus
the full tool trace (so the UI can show exactly what was computed)."""

from __future__ import annotations

import json

import httpx

from .. import settings
from ..advisory.client import complete
from . import tools as T

_SYSTEM = (
    "You are the ZeroTrust Policy Advisor assistant. Answer questions about the network "
    "policy by CALLING TOOLS -- never compute reachability, subnet math, or paths yourself. "
    "Ground every statement in tool results and cite the concrete path when something is "
    "reachable. If unsure which asset the user means, call resolve or risk_findings first. "
    "Be concise and concrete; prefer naming the exact rule refs and hops."
)


def _normalize_args(args) -> dict:
    if isinstance(args, dict):
        return args
    if isinstance(args, str):
        try:
            return json.loads(args)
        except Exception:
            return {}
    return {}


def _ollama_loop(ctx, question: str, max_iters: int = 5) -> dict:
    messages = [{"role": "system", "content": _SYSTEM}, {"role": "user", "content": question}]
    trace: list[dict] = []
    for _ in range(max_iters):
        payload = {"model": settings.OLLAMA_JUDGE_MODEL, "messages": messages,
                   "tools": T.SCHEMAS, "stream": False, "options": {"temperature": 0.1}}
        resp = httpx.post(f"{settings.OLLAMA_HOST}/api/chat", json=payload, timeout=settings.OLLAMA_TIMEOUT)
        resp.raise_for_status()
        msg = resp.json().get("message", {}) or {}
        calls = msg.get("tool_calls") or []
        if not calls:
            return {"answer": (msg.get("content") or "").strip(), "trace": trace,
                    "by": f"ollama:{settings.OLLAMA_JUDGE_MODEL}"}
        messages.append({"role": "assistant", "content": msg.get("content", ""), "tool_calls": calls})
        for c in calls:
            fn = c.get("function", {}) or {}
            name = fn.get("name", "")
            args = _normalize_args(fn.get("arguments"))
            result = T.dispatch(ctx, name, args)
            trace.append({"tool": name, "args": args, "result": result})
            messages.append({"role": "tool", "tool_name": name, "content": json.dumps(result)[:4000]})
    # ran out of tool iterations -> summarize from the trace
    fr = complete(system=_SYSTEM, role="judge", temperature=0.1,
                  user=f"Question: {question}\n\nTool results so far:\n{json.dumps(trace)[:6000]}\n\nAnswer now.")
    return {"answer": fr.text.strip(), "trace": trace, "by": f"{fr.provider}:{fr.model}"}


def _grounded_fallback(ctx, question: str) -> dict:
    """No tool-calling available -> still ground the answer in deterministic facts."""
    facts = {"findings": T.risk_findings(ctx)}
    fr = complete(
        system=_SYSTEM + "\n(No live tools available; answer ONLY from the provided facts.)",
        user=f"Question: {question}\n\nFacts:\n{json.dumps(facts)[:6000]}",
        role="judge", temperature=0.2,
    )
    return {"answer": fr.text.strip() if fr.ok else "The model is unavailable right now.",
            "trace": [{"tool": "risk_findings", "args": {}, "result": facts["findings"]}],
            "by": f"{fr.provider}:{fr.model}" if fr.ok else "engine_fallback"}


def ask(ctx, question: str) -> dict:
    try:
        if settings.active_provider() == "ollama":
            return _ollama_loop(ctx, question)
    except Exception:
        pass
    return _grounded_fallback(ctx, question)
