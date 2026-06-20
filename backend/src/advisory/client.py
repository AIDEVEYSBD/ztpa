"""Provider-pluggable AI client. Ollama is the local-dev default (no key,
offline, topology never leaves the box); Anthropic/OpenAI are used when a key is
present and selected. One contract, fail-closed everywhere.

The model only ever produces *language and judgment*. Every fact it reasons over
is computed by the deterministic engine and handed to it.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass

import httpx

from .. import settings


@dataclass
class LLMResponse:
    text: str
    provider: str
    model: str
    ok: bool = True
    error: str | None = None
    tool_calls: list | None = None


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
    return LLMResponse(text=data.get("message", {}).get("content", ""), provider="ollama", model=model)


def _anthropic_complete(system, user, model, temperature, expect_json) -> LLMResponse:
    import anthropic

    client = anthropic.Anthropic(api_key=settings.ANTHROPIC_API_KEY)
    if expect_json:
        system = system + "\nRespond with ONLY valid JSON. No prose, no code fences."
    msg = client.messages.create(
        model=model, max_tokens=1500, temperature=temperature, system=system,
        messages=[{"role": "user", "content": user}],
    )
    text = "".join(getattr(b, "text", "") for b in msg.content if getattr(b, "type", "") == "text")
    return LLMResponse(text=text, provider="anthropic", model=model)


def _openai_complete(system, user, model, temperature, expect_json) -> LLMResponse:
    from openai import OpenAI

    client = OpenAI(api_key=settings.OPENAI_API_KEY)
    kwargs = {"response_format": {"type": "json_object"}} if expect_json else {}
    resp = client.chat.completions.create(
        model=model, temperature=temperature,
        messages=[{"role": "system", "content": system}, {"role": "user", "content": user}],
        **kwargs,
    )
    return LLMResponse(text=resp.choices[0].message.content or "", provider="openai", model=model)


def complete(*, system: str, user: str, role: str = "judge", temperature: float = 0.1,
             expect_json: bool = False, provider: str | None = None,
             timeout: float | None = None) -> LLMResponse:
    """Single-shot completion. Never raises — returns ok=False on any failure so
    callers can fall back deterministically (fail-closed). `timeout` (seconds)
    bounds the local-model call so a cold/slow model degrades to the fallback
    instead of hanging the request."""
    provider = provider or settings.active_provider()
    model = model_for(provider, role)
    try:
        if provider == "anthropic":
            return _anthropic_complete(system, user, model, temperature, expect_json)
        if provider == "openai":
            return _openai_complete(system, user, model, temperature, expect_json)
        return _ollama_complete(system, user, model, temperature, expect_json, timeout)
    except Exception as e:  # noqa: BLE001 — fail closed, never crash the pipeline
        return LLMResponse(text="", provider=provider, model=model, ok=False, error=str(e))


# --- embeddings (always prefer local nomic; degrade gracefully) ------------

def embed(texts: list[str]) -> list[list[float]]:
    if not texts:
        return []
    try:
        r = httpx.post(f"{settings.OLLAMA_HOST}/api/embed",
                       json={"model": settings.OLLAMA_EMBED_MODEL, "input": texts},
                       timeout=settings.OLLAMA_TIMEOUT)
        r.raise_for_status()
        vecs = r.json().get("embeddings", [])
        if vecs:
            return vecs
    except Exception:
        pass
    if settings.has_openai():
        try:
            from openai import OpenAI

            client = OpenAI(api_key=settings.OPENAI_API_KEY)
            resp = client.embeddings.create(model="text-embedding-3-small", input=texts)
            return [d.embedding for d in resp.data]
        except Exception:
            pass
    return []  # fail-safe: embedding-based features degrade to "no suggestions"


# --- fail-closed JSON parsing ----------------------------------------------

def parse_json(text: str, default):
    """Strip code fences, parse; on any failure return `default` (fail-closed)."""
    if not text:
        return default
    t = text.strip()
    if t.startswith("```"):
        t = re.sub(r"^```[a-zA-Z]*\n?", "", t)
        t = re.sub(r"\n?```$", "", t).strip()
    try:
        return json.loads(t)
    except Exception:
        pass
    for open_c, close_c in (("{", "}"), ("[", "]")):
        i, j = t.find(open_c), t.rfind(close_c)
        if i != -1 and j > i:
            try:
                return json.loads(t[i:j + 1])
            except Exception:
                continue
    return default


# --- status (for the UI banner) --------------------------------------------

def provider_status() -> dict:
    active = settings.active_provider()
    ollama_ok, ollama_models = False, []
    try:
        r = httpx.get(f"{settings.OLLAMA_HOST}/api/tags", timeout=5)
        if r.status_code == 200:
            ollama_ok = True
            ollama_models = sorted(m["name"] for m in r.json().get("models", []))
    except Exception:
        pass
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
