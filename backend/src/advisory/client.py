"""Provider-pluggable AI client. Ollama is the local-dev default (no key,
offline, topology never leaves the box); Anthropic/OpenAI are used when a key is
present and selected. One contract, fail-closed everywhere.

The model only ever produces *language and judgment*. Every fact it reasons over
is computed by the deterministic engine and handed to it.

FAIL-CLOSED IS NOT THE SAME AS FAIL-SILENT
------------------------------------------
Every function here degrades rather than raises, which is the right shape for a
security tool: a dead model must never take the deterministic engine down with
it. But the audit's finding was that the degradation left NO trace anywhere --
four `except Exception: pass` on this file alone -- so a capability the UI
labels "model-generated" could be running entirely on deterministic fallback and
the only way to find out was to read the code.

Three things changed, and none of them alters when we degrade:

  * every swallowed failure now emits one structured line on `npr.api.llm`,
    carrying the request id bound by the API middleware, so "the explanation
    went generic at 14:02" maps to a provider, a model and an error string;
  * the exception types are named where the call surface is knowable (httpx and
    `json` for the Ollama/parse paths). The two vendor-SDK paths stay broad on
    purpose and say why at the catch;
  * `embed()` could not tell its caller apart from "no texts" and "the embedding
    provider is down" -- both were `[]`. `embed_texts()` returns the outcome, so
    a caller that would behave differently can ask. See its docstring.
"""

from __future__ import annotations

import json
import logging
import re
import time
from dataclasses import dataclass, field

import httpx

from .. import settings
from ..metrics import record_metric

# A child of the API's logger, so a degraded model call comes out as one JSON
# line with the request id already attached (app/main.py configures "npr.api").
# Outside the API -- scripts, the test suite -- it propagates to the root
# logger, which is where pytest's caplog can see it.
log = logging.getLogger("npr.api.llm")

# The failure surface of an Ollama call: httpx for transport/status,
# json.JSONDecodeError (a ValueError) for a body that is not JSON, and
# TypeError/AttributeError for a 200 whose JSON is not the object shape the API
# documents. Named rather than `except Exception` so a genuine defect in this
# module -- a NameError, a bad f-string -- still surfaces as a crash instead of
# being silently reclassified as "the model is down".
_HTTP_JSON_ERRORS = (httpx.HTTPError, ValueError, TypeError, AttributeError)


@dataclass
class LLMResponse:
    text: str
    provider: str
    model: str
    ok: bool = True
    error: str | None = None
    tool_calls: list | None = None
    prompt_tokens: int = 0
    completion_tokens: int = 0


def model_for(provider: str, role: str) -> str:
    if provider == "ollama":
        return settings.OLLAMA_JUDGE_MODEL if role == "judge" else settings.OLLAMA_PROSE_MODEL
    if provider == "anthropic":
        return settings.ANTHROPIC_MODEL
    if provider == "openai":
        return settings.OPENAI_MODEL
    return settings.OLLAMA_JUDGE_MODEL


# --- per-provider single-shot completion -----------------------------------

def _ollama_complete(system, user, model, temperature, expect_json, timeout=None) -> LLMResponse:
    payload = {
        "model": model,
        "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}],
        "stream": False,
        "options": {"temperature": temperature},
    }
    if expect_json:
        payload["format"] = "json"
    r = httpx.post(f"{settings.OLLAMA_HOST}/api/chat", json=payload, timeout=timeout or settings.OLLAMA_TIMEOUT)
    r.raise_for_status()
    data = r.json()
    return LLMResponse(text=data.get("message", {}).get("content", ""), provider="ollama", model=model,
                       prompt_tokens=int(data.get("prompt_eval_count") or 0),
                       completion_tokens=int(data.get("eval_count") or 0))


# Reuse one client per provider for the process lifetime. The first request on a
# fresh client pays ~6s of TLS + connection setup; a kept-alive client makes every
# later call ~1s. Building a client per call (the old behavior) paid that setup on
# every single completion.
_OPENAI_CLIENT = None
_ANTHROPIC_CLIENT = None
_LLM_TIMEOUT = 60.0
_LLM_RETRIES = 1


def _get_openai_client():
    global _OPENAI_CLIENT
    if _OPENAI_CLIENT is None:
        from openai import OpenAI

        _OPENAI_CLIENT = OpenAI(api_key=settings.OPENAI_API_KEY,
                                timeout=_LLM_TIMEOUT, max_retries=_LLM_RETRIES)
    return _OPENAI_CLIENT


def _get_anthropic_client():
    global _ANTHROPIC_CLIENT
    if _ANTHROPIC_CLIENT is None:
        import anthropic

        _ANTHROPIC_CLIENT = anthropic.Anthropic(api_key=settings.ANTHROPIC_API_KEY,
                                                timeout=_LLM_TIMEOUT, max_retries=_LLM_RETRIES)
    return _ANTHROPIC_CLIENT


def _anthropic_complete(system, user, model, temperature, expect_json) -> LLMResponse:
    client = _get_anthropic_client()
    if expect_json:
        system = system + "\nRespond with ONLY valid JSON. No prose, no code fences."
    msg = client.messages.create(
        model=model, max_tokens=1500, temperature=temperature, system=system,
        messages=[{"role": "user", "content": user}],
    )
    text = "".join(getattr(b, "text", "") for b in msg.content if getattr(b, "type", "") == "text")
    usage = getattr(msg, "usage", None)
    return LLMResponse(text=text, provider="anthropic", model=model,
                       prompt_tokens=int(getattr(usage, "input_tokens", 0) or 0),
                       completion_tokens=int(getattr(usage, "output_tokens", 0) or 0))


def _openai_complete(system, user, model, temperature, expect_json) -> LLMResponse:
    client = _get_openai_client()
    kwargs = {"response_format": {"type": "json_object"}} if expect_json else {}
    resp = client.chat.completions.create(
        model=model, temperature=temperature,
        messages=[{"role": "system", "content": system}, {"role": "user", "content": user}],
        **kwargs,
    )
    usage = getattr(resp, "usage", None)
    return LLMResponse(text=resp.choices[0].message.content or "", provider="openai", model=model,
                       prompt_tokens=int(getattr(usage, "prompt_tokens", 0) or 0),
                       completion_tokens=int(getattr(usage, "completion_tokens", 0) or 0))


def complete(*, system: str, user: str, role: str = "judge", temperature: float = 0.1,
             expect_json: bool = False, provider: str | None = None,
             timeout: float | None = None, capability: str | None = None,
             subject: str | None = None) -> LLMResponse:
    """Single-shot completion. Never raises — returns ok=False on any failure so
    callers can fall back deterministically (fail-closed). `timeout` (seconds)
    bounds the local-model call so a cold/slow model degrades to the fallback
    instead of hanging the request. `capability` labels the call for the metrics
    dashboards (defaults to the role); every call (success or failure) is recorded."""
    provider = provider or settings.active_provider()
    model = model_for(provider, role)
    cap = capability or role
    t0 = time.perf_counter()
    try:
        if provider == "anthropic":
            res = _anthropic_complete(system, user, model, temperature, expect_json)
        elif provider == "openai":
            res = _openai_complete(system, user, model, temperature, expect_json)
        else:
            res = _ollama_complete(system, user, model, temperature, expect_json, timeout)
    except Exception as e:  # noqa: BLE001 — fail closed, never crash the pipeline
        # Deliberately broad: two of the three branches are vendor SDKs
        # (openai, anthropic) with their own exception hierarchies, and both are
        # imported lazily inside the branch, so an ImportError on a machine
        # without the package lands here too. Narrowing would mean importing the
        # SDKs at module scope purely to name their errors, which is the cost
        # this file's lazy imports exist to avoid.
        #
        # The metric below already records ok=False, but it is written to the
        # SAME database that may be the reason this call failed, and its own
        # write is fail-closed -- so the metric alone is not an observation. The
        # log line is.
        res = LLMResponse(text="", provider=provider, model=model, ok=False, error=str(e))
        log.warning("model call failed; the caller will use its deterministic fallback",
                    exc_info=True, extra={"event": "llm_call_failed", "capability": cap,
                                          "provider": provider, "model": model,
                                          "error": f"{type(e).__name__}: {e}"})
    record_metric(kind="llm", capability=cap, provider=res.provider, model=res.model,
                  latency_ms=round((time.perf_counter() - t0) * 1000),
                  prompt_tokens=res.prompt_tokens, completion_tokens=res.completion_tokens,
                  ok=res.ok, error=res.error, subject=subject)
    return res


# --- embeddings (always prefer local nomic; degrade gracefully) ------------

@dataclass
class EmbeddingResult:
    """Vectors plus whether they were actually computed.

    `embed()` answers `[]` for BOTH "you asked for nothing" and "every embedding
    provider is down", and `entity_suggest.suggest_merges` cannot tell those
    apart: with no vectors it scores `name_similarity: 0.0` for every candidate
    pair and still emits the suggestion, so a dead embedding server renders as
    the positive claim "these two PCI assets do not resemble each other". Zero
    similarity computed from zero data is not a measurement.

    So the failure is carried in the value. `ok=False` means the numbers are
    absent, not small; `provider` names who answered ("none" when nobody did).
    """
    vectors: list[list[float]] = field(default_factory=list)
    ok: bool = True
    provider: str = "none"
    error: str | None = None


def embed_texts(texts: list[str]) -> EmbeddingResult:
    """Embed `texts`, reporting the outcome rather than only the vectors.

    Prefers the local model (the topology stays on the box), then a hosted key.
    Never raises: an embedding failure degrades a *suggestion* feature, which is
    not worth a 500 -- but it is worth a caller knowing, which is what the
    result carries and what the log lines below record.
    """
    if not texts:
        # Genuinely empty, and a success: nothing was asked for, so nothing
        # failed. This is the case `ok` exists to separate from the ones below.
        return EmbeddingResult(vectors=[], ok=True, provider="none")
    t0 = time.perf_counter()
    errors: list[str] = []
    if settings.ollama_available():  # local model exists -> keep embeddings on the box
        try:
            r = httpx.post(f"{settings.OLLAMA_HOST}/api/embed",
                           json={"model": settings.OLLAMA_EMBED_MODEL, "input": texts},
                           timeout=settings.OLLAMA_TIMEOUT)
            r.raise_for_status()
            vecs = r.json().get("embeddings", [])
            if vecs:
                record_metric(kind="embed", capability="embed", provider="ollama",
                              model=settings.OLLAMA_EMBED_MODEL,
                              latency_ms=round((time.perf_counter() - t0) * 1000), ok=True)
                return EmbeddingResult(vectors=vecs, ok=True, provider="ollama")
            # A 200 carrying no embeddings is a failure of the same kind as a
            # timeout -- the caller has no numbers either way -- so it is
            # recorded rather than falling through as if nothing happened.
            errors.append("ollama returned no embeddings")
            log.warning("local embedding provider returned an empty result",
                        extra={"event": "embed_empty", "provider": "ollama",
                               "model": settings.OLLAMA_EMBED_MODEL, "texts": len(texts)})
        except _HTTP_JSON_ERRORS as e:
            errors.append(f"ollama: {type(e).__name__}: {e}")
            log.warning("local embedding provider failed; trying the hosted key",
                        exc_info=True, extra={"event": "embed_provider_failed",
                                              "provider": "ollama",
                                              "model": settings.OLLAMA_EMBED_MODEL,
                                              "error": f"{type(e).__name__}: {e}"})
    if settings.has_openai():
        try:
            client = _get_openai_client()
            resp = client.embeddings.create(model="text-embedding-3-small", input=texts)
            usage = getattr(resp, "usage", None)
            record_metric(kind="embed", capability="embed", provider="openai",
                          model="text-embedding-3-small",
                          latency_ms=round((time.perf_counter() - t0) * 1000),
                          prompt_tokens=int(getattr(usage, "prompt_tokens", 0) or 0), ok=True)
            return EmbeddingResult(vectors=[d.embedding for d in resp.data],
                                   ok=True, provider="openai")
        except Exception as e:  # noqa: BLE001 — vendor SDK hierarchy, imported lazily
            # Broad for the same reason as `complete()`: the openai package is
            # imported inside `_get_openai_client`, so ImportError and every
            # `openai.*Error` land here and naming them would force a
            # module-scope import of the SDK.
            errors.append(f"openai: {type(e).__name__}: {e}")
            log.warning("hosted embedding provider failed", exc_info=True,
                        extra={"event": "embed_provider_failed", "provider": "openai",
                               "model": "text-embedding-3-small",
                               "error": f"{type(e).__name__}: {e}"})
    detail = "; ".join(errors) or "no embedding provider available"
    record_metric(kind="embed", capability="embed", provider="engine", model="none",
                  latency_ms=round((time.perf_counter() - t0) * 1000), ok=False,
                  error=detail)
    log.error("no embedding provider produced vectors; similarity-based features are blind",
              extra={"event": "embed_unavailable", "texts": len(texts), "error": detail})
    return EmbeddingResult(vectors=[], ok=False, provider="none", error=detail)


def embed(texts: list[str]) -> list[list[float]]:
    """Vectors only, for callers that genuinely cannot act on a failure.

    Kept so the failure mode is a deliberate choice at the call site rather than
    the only option: prefer `embed_texts` and branch on `.ok` wherever the
    difference between "no similarity" and "no measurement" reaches a user.
    """
    return embed_texts(texts).vectors  # fail-safe: features degrade to "no suggestions"


# --- fail-closed JSON parsing ----------------------------------------------

def parse_json(text: str, default):
    """Strip code fences, parse; on any failure return `default` (fail-closed).

    Returning `default` is correct -- a model that emits prose where JSON was
    demanded must not be believed -- but it is also the exact moment a
    capability stops being model-driven, and it used to happen behind two
    `except Exception: pass`. Both are now `ValueError` (`json.JSONDecodeError`
    is one; nothing else here can raise), and the give-up is logged with a
    bounded sample of what the model actually said, which is the only thing that
    makes "why did remediation go generic?" answerable after the fact.
    """
    if not text:
        # Not a parse failure: an empty body means the CALL failed, and
        # `complete()` has already logged that with the provider and the error.
        return default
    t = text.strip()
    if t.startswith("```"):
        t = re.sub(r"^```[a-zA-Z]*\n?", "", t)
        t = re.sub(r"\n?```$", "", t).strip()
    try:
        return json.loads(t)
    except ValueError:
        pass                                   # fall through to the substring salvage
    for open_c, close_c in (("{", "}"), ("[", "]")):
        i, j = t.find(open_c), t.rfind(close_c)
        if i != -1 and j > i:
            try:
                return json.loads(t[i:j + 1])
            except ValueError:
                continue
    log.warning("model output was not JSON; falling back to the caller's default",
                extra={"event": "llm_json_unparseable", "chars": len(t),
                       "sample": t[:200]})
    return default


# --- status (for the UI banner) --------------------------------------------

def provider_status() -> dict:
    active = settings.active_provider()
    ollama_ok, ollama_models = settings.ollama_probe()  # shared, cached probe
    return {
        "active_provider": active,
        "judge_model": model_for(active, "judge"),
        "prose_model": model_for(active, "prose"),
        "embed_model": settings.OLLAMA_EMBED_MODEL,
        "ollama_reachable": ollama_ok,
        "ollama_models": ollama_models,
        "anthropic_available": settings.has_anthropic(),
        "openai_available": settings.has_openai(),
        "data_residency": "local" if active == "ollama" else "hosted",
    }
