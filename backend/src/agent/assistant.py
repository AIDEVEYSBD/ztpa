"""'Ask your network' assistant: a tool-calling loop over the deterministic tools.

The model decides which tool to call next; the engine answers with facts; the
model narrates. Every claim is grounded in a tool result. Returns the answer plus
the full tool trace (so the UI can show exactly what was computed).

WHEN THAT SENTENCE IS NOT TRUE, THE ANSWER NOW SAYS SO
------------------------------------------------------
The tool-calling loop is implemented for Ollama only. On any other provider --
including the shipped hosted deployment, which pins ADVISORY_PROVIDER=openai --
`ask()` fell through to `_grounded_fallback`: ONE completion over a list of
finding titles, no reachability data, no ports, no hops, while the system prompt
still instructs the model to "cite the concrete path when something is
reachable". The result was labelled `by: "openai:gpt-4o"`, styled identically to
a real tool-grounded answer, and the UI rendered a "Tool trace" header above it.
A confabulated path is the worst output this product can produce, and nothing
anywhere recorded that it had happened.

Implementing hosted tool-calling is a Phase 4 workstream and is NOT done here.
What is done is making the degradation impossible to miss:

  * the returned dict carries `tool_calling: bool` and, when false, a `degraded`
    block naming the reason and the provider -- so a caller (and the UI) can
    branch instead of inferring intent from a provenance string;
  * `by` says "grounded fallback" in words rather than impersonating the
    tool-calling path;
  * both the provider gate and a mid-loop crash emit a structured log line.

`ask()` also no longer treats *every* exception as "the model is unavailable":
see the catch for which ones degrade and which now crash honestly."""

from __future__ import annotations

import json
import logging
import time

import httpx

from .. import settings
from ..advisory.client import complete
from ..metrics import record_metric
from . import tools as T

# Child of the API logger; see advisory/client.py for the convention.
log = logging.getLogger("npr.api.assistant")

# What a broken Ollama tool-calling turn actually raises: httpx for
# transport/status, ValueError (json.JSONDecodeError) for an unparseable body,
# and TypeError/KeyError/AttributeError for a 200 whose JSON is not the shape
# the API documents. `tools.dispatch` never raises -- it returns {"error": ...}
# -- so a tool failure stays inside the loop and reaches the model as evidence.
_LOOP_ERRORS = (httpx.HTTPError, ValueError, TypeError, KeyError, AttributeError)

_SYSTEM = (
    "You are the Network Policy Reviewer assistant. Answer questions about the network "
    "policy by CALLING TOOLS -- never compute reachability, subnet math, or paths yourself. "
    "Ground every statement in tool results and cite the concrete path when something is "
    "reachable. If unsure which asset the user means, call resolve or risk_findings first. "
    "Be concise and concrete; prefer naming the exact rule refs and hops. "
    "Refer to findings by their human title in quotes (e.g. \"Cross-tool path: Internet can "
    "reach db-prod-01\"). NEVER print internal identifiers such as the F_... finding IDs or "
    "snap_... snapshot IDs -- those are database keys, not for the user."
)


def _normalize_args(args) -> tuple[dict, str | None]:
    """(arguments, why they are empty). Ollama sends a dict, OpenAI-style
    function calling sends a JSON string; either may arrive malformed.

    The error half is the point. `{}` used to mean both "the model called this
    tool with no arguments" and "the model emitted arguments we could not
    parse", and the two produce very different tools: `reachable()` with no
    arguments is a TypeError the dispatcher turns into an error result the model
    can react to, while `risk_findings()` with no arguments is a perfectly valid
    call that answers a DIFFERENT question than the one the model asked. The
    caller records the reason on the trace so the operator reading it can see
    which happened.
    """
    if isinstance(args, dict):
        return args, None
    if args is None:
        return {}, None                       # the model genuinely passed nothing
    if isinstance(args, str):
        try:
            parsed = json.loads(args)
        except ValueError as e:               # json.JSONDecodeError is a ValueError
            return {}, f"unparseable arguments ({type(e).__name__}: {e})"
        if isinstance(parsed, dict):
            return parsed, None
        return {}, f"arguments were {type(parsed).__name__}, expected an object"
    return {}, f"arguments were {type(args).__name__}, expected an object or a JSON string"


def _ollama_loop(ctx, question: str, max_iters: int = 5) -> dict:
    messages = [{"role": "system", "content": _SYSTEM}, {"role": "user", "content": question}]
    trace: list[dict] = []
    for _ in range(max_iters):
        payload = {"model": settings.OLLAMA_JUDGE_MODEL, "messages": messages,
                   "tools": T.SCHEMAS, "stream": False, "options": {"temperature": 0.1}}
        t0 = time.perf_counter()
        resp = httpx.post(f"{settings.OLLAMA_HOST}/api/chat", json=payload, timeout=settings.OLLAMA_TIMEOUT)
        resp.raise_for_status()
        body = resp.json()
        record_metric(kind="llm", capability="assistant", provider="ollama",
                      model=settings.OLLAMA_JUDGE_MODEL,
                      latency_ms=round((time.perf_counter() - t0) * 1000),
                      prompt_tokens=int(body.get("prompt_eval_count") or 0),
                      completion_tokens=int(body.get("eval_count") or 0), ok=True)
        msg = body.get("message", {}) or {}
        calls = msg.get("tool_calls") or []
        if not calls:
            return {"answer": (msg.get("content") or "").strip(), "trace": trace,
                    "by": f"ollama:{settings.OLLAMA_JUDGE_MODEL}",
                    "tool_calling": True, "degraded": None}
        messages.append({"role": "assistant", "content": msg.get("content", ""), "tool_calls": calls})
        for c in calls:
            fn = c.get("function", {}) or {}
            name = fn.get("name", "")
            args, args_error = _normalize_args(fn.get("arguments"))
            if args_error:
                # The tool still runs -- an argument-less call often has a valid
                # meaning and the dispatcher fails closed when it does not -- but
                # the trace no longer presents `args: {}` as if the model had
                # chosen it.
                log.warning("tool call arguments could not be parsed; calling with no arguments",
                            extra={"event": "assistant_bad_tool_args", "tool": name,
                                   "error": args_error})
            result = T.dispatch(ctx, name, args)
            entry = {"tool": name, "args": args, "result": result}
            if args_error:
                entry["args_error"] = args_error
            trace.append(entry)
            messages.append({"role": "tool", "tool_name": name, "content": json.dumps(result)[:4000]})
    # ran out of tool iterations -> summarize from the trace. Still tool-grounded:
    # every fact in `trace` came from the deterministic engine.
    log.info("assistant exhausted its tool-call budget; summarizing from the trace",
             extra={"event": "assistant_iterations_exhausted", "max_iters": max_iters,
                    "tool_calls": len(trace)})
    fr = complete(system=_SYSTEM, role="judge", temperature=0.1,
                  user=f"Question: {question}\n\nTool results so far:\n{json.dumps(trace)[:6000]}\n\nAnswer now.")
    return {"answer": fr.text.strip(), "trace": trace, "by": f"{fr.provider}:{fr.model}",
            "tool_calling": True, "degraded": None}


def _grounded_fallback(ctx, question: str, *, reason: str, provider: str,
                       detail: str | None = None) -> dict:
    """No tool-calling available -> still ground the answer in deterministic facts.

    "Grounded" is doing less work than it sounds like: the one fact blob is
    `risk_findings`, which carries {id, type, title, severity, band,
    forced_critical} and NO paths, ports or hops. The model is nonetheless asked
    a question it may only be able to answer with a path. `reason`/`provider`
    travel into the payload so the caller can say that out loud instead of the
    UI inferring "grounded" from the word `trace`.
    """
    facts = {"findings": T.risk_findings(ctx)}
    fr = complete(
        system=_SYSTEM + "\n(No live tools available; answer ONLY from the provided facts.)",
        user=f"Question: {question}\n\nFacts:\n{json.dumps(facts)[:6000]}",
        role="judge", temperature=0.2,
    )
    return {
        "answer": fr.text.strip() if fr.ok else "The model is unavailable right now.",
        "trace": [{"tool": "risk_findings", "args": {}, "result": facts["findings"]}],
        # Provenance that does not impersonate the tool-calling path. `by` is
        # what the console prints under every answer ("via ..."), so the words
        # have to carry the caveat even for a reader who never opens the JSON.
        "by": (f"{fr.provider}:{fr.model} (grounded fallback — no tool calling)"
               if fr.ok else "engine_fallback"),
        "tool_calling": False,
        "degraded": {"reason": reason, "provider": provider, "detail": detail,
                     "facts": "risk_findings only — no reachability, ports or hops"},
    }


def ask(ctx, question: str) -> dict:
    """Answer `question`, preferring the tool-calling loop and SAYING when it did not.

    Two ways to end up in the fallback, and they are different events:

      * the active provider has no tool-calling implementation here (every
        provider except Ollama). Expected, configuration-driven, logged at
        WARNING because the shipped hosted deployment sits in it permanently;
      * the loop started and broke. Logged at ERROR with the traceback.

    The catch is narrow on purpose. It used to be `except Exception: pass`,
    which meant a NameError or a typo in the loop silently downgraded the
    product's flagship feature to a confabulating single-shot for every user,
    forever, with no log line. Only the transport/decode failures in
    `_LOOP_ERRORS` are "the model is unavailable"; anything else is a defect in
    this file and must surface as a 500 the global handler stamps with a request
    id.
    """
    provider = settings.active_provider()
    if provider != "ollama":
        log.warning("tool calling is not implemented for this provider; answering from a "
                    "findings summary instead", extra={
                        "event": "assistant_no_tool_calling", "provider": provider})
        return _grounded_fallback(
            ctx, question, provider=provider,
            reason=f"tool calling is not implemented for provider '{provider}'")
    try:
        return _ollama_loop(ctx, question)
    except _LOOP_ERRORS as e:
        log.error("the tool-calling loop failed; answering from a findings summary instead",
                  exc_info=True, extra={"event": "assistant_loop_failed", "provider": provider,
                                        "error": f"{type(e).__name__}: {e}"})
        return _grounded_fallback(ctx, question, provider=provider,
                                  reason="the tool-calling loop failed",
                                  detail=f"{type(e).__name__}: {e}")
