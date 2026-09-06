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

AZURE AI FOUNDRY, AND WHAT WAS ACTUALLY MEASURED
------------------------------------------------
The `azure` provider talks to the customer's OWN model deployment, in their
subscription and their region. It is served by the `openai` package's
`AzureOpenAI` client rather than a second inference SDK, and that is a measured
fact rather than a convenient assumption: a Foundry `AIServices` account exposes
BOTH a classic Azure-OpenAI route and an `/models` inference route, and a
deployment whose model is not an OpenAI one might have answered on only one of
them. Probed against the live account this was built for
(`api-endpoint-inference-resource`, resource group `Foundry-RG`) with a
`DefaultAzureCredential` bearer token on `https://cognitiveservices.azure.com/`:

    POST {ep}/openai/deployments/{deployment}/chat/completions
         ?api-version=2024-10-21                       -> 200 for BOTH deployments
    POST {ep}/models/chat/completions?api-version=2024-05-01-preview   -> 200 for BOTH
    POST {ep}/openai/v1/chat/completions                               -> 200 for BOTH
    POST {ep}/chat/completions?api-version=2024-05-01-preview          -> 404

...even though `Mistral-Large-3` has model format "Mistral AI" and
`Kimi-K2.7-Code` has "MoonshotAI"; neither is an OpenAI model and the account
has no GPT deployment at all. `response_format={"type": "json_object"}` is
honoured by both, in both auth modes. So the classic route is what this file
uses and no new SDK was added -- see backend/requirements.txt.

Two things the probe found that this code has to survive, because assuming
otherwise is how "we pointed it at a real model" quietly becomes a worse product
than the deterministic engine the model was supposed to improve on:

  * `Kimi-K2.7-Code` is a REASONING deployment. It spends completion tokens in
    `reasoning_content` before it writes any `content`, so a budget that is
    generous for a chat model comes back as `content: ""` with
    `finish_reason: "length"` -- an HTTP 200, with a usage block, containing
    nothing. A truncated, filtered or empty answer is `ok=False` here and its
    partial text is DROPPED rather than passed on as if it were whole.
  * the account rate-limits per deployment (`429 RateLimitReached`) long before
    the advertised per-minute ceiling. That is an `ok=False` with the reason on
    it, and the caller's deterministic fallback engages; see the retry note on
    `_get_azure_client` for why it is not retried here.
"""

from __future__ import annotations

import hashlib
import json
import logging
import re
import threading
import time
from dataclasses import dataclass, field
from typing import Any

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
    # Why the model stopped, verbatim from the provider, when it says. Carried
    # rather than only consumed because "the answer is short" and "the answer
    # was cut off" are the same string to a reader and different facts to an
    # auditor. Only the Azure path fills it in today; the others do not report
    # it in a form worth inventing a value for.
    finish_reason: str | None = None
    # How JSON was actually obtained when `expect_json` was asked for:
    # "native" = the service enforced a JSON response mode; "instruction" = the
    # deployment has no such mode and was merely ASKED for JSON in the prompt,
    # so the text is unvalidated and `parse_json` may legitimately fall back.
    # None = JSON was not requested. This exists so a capability degrading from
    # enforced to hoped-for structure is a visible fact and not a shrug.
    json_mode: str | None = None


def model_for(provider: str, role: str) -> str:
    if provider == "ollama":
        return settings.OLLAMA_JUDGE_MODEL if role == "judge" else settings.OLLAMA_PROSE_MODEL
    if provider == "anthropic":
        return settings.ANTHROPIC_MODEL
    if provider == "openai":
        return settings.OPENAI_MODEL
    if provider == "azure":
        # The DEPLOYMENT name, because that is what an operator selects on the
        # Configuration page and what identifies the target on the account. It
        # is NOT always the model id the service reports back (a deployment
        # named "Mistral-Large-3" answers with model "mistral-large-3"), and one
        # Foundry account commonly has a single deployment serving both roles.
        # Empty when nothing is configured, which `_azure_complete` turns into
        # an ok=False naming the missing piece rather than a call to a blank URL.
        return settings.azure_target().azure_deployment
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


# --- Azure AI Foundry: the customer's own deployment -----------------------
# WHICH deployment is `src/ai_config.py`'s problem (a stored row, an operator's
# name on it, an environment fallback). Everything below is about making the
# call and telling the truth about what came back.

# The `finish_reason` values that mean "this is not the whole answer", with the
# sentence an operator gets. A 200 carrying half an answer is the most dangerous
# shape a model call has: it parses, it reads like prose, and nothing downstream
# can tell. Both are ok=False.
_AZURE_INCOMPLETE: dict[str, str] = {
    "length": "the deployment stopped at its token limit, so the answer is a fragment",
    "content_filter": "Azure content filtering blocked the response",
}

# Completion budget, larger than the Anthropic path's 1500 on purpose. A
# REASONING deployment -- Kimi-K2.7-Code on the account this was verified
# against -- spends completion tokens in `reasoning_content` before it emits any
# `content`, so a budget sized for a chat model's answer is gone before the
# answer starts and comes back empty with finish_reason='length'. Measured: at
# max_tokens=16 that deployment returned `content: ""` and 16 reasoning tokens.
_AZURE_MAX_TOKENS = 4000

# Appended when a deployment has no native JSON mode -- the same sentence the
# Anthropic path uses, for the same reason and with the same weakness: it is a
# request, not a guarantee, which is exactly why the response records that this
# is what happened (`LLMResponse.json_mode == "instruction"`).
_JSON_ONLY = "\nRespond with ONLY valid JSON. No prose, no code fences."

# Facts LEARNED about a specific deployment from its own 400, so the same
# rejection is not paid for on every subsequent call. Only ever set when the
# service's error NAMES the parameter we sent (see `_azure_quirk_for`), and
# surfaced by `provider_status()` -- a deployment that cannot enforce JSON
# changes what the advisory layer is able to promise, and an operator should not
# have to read logs to discover that.
_QUIRK_NO_JSON_MODE = "no_json_mode"
_QUIRK_MAX_COMPLETION_TOKENS = "max_completion_tokens"
_AZURE_QUIRKS: dict[str, set[str]] = {}

# One credential per identity and one client per resolved target. Both are
# keyed rather than global because the target is no longer fixed at import: an
# operator can repoint the product at a different account mid-process from the
# Configuration page, and a single cached client would keep talking to the
# previous one.
_AZURE_CREDENTIALS: dict[str, Any] = {}
_AZURE_CLIENTS: dict[tuple, Any] = {}
# Small, because the number of distinct targets a process legitimately sees is
# the number of times someone edits the configuration. The cap exists so a
# pathological caller cannot grow the dict without bound, not to be tuned.
_AZURE_CLIENT_CACHE_MAX = 8


def _quirk_key(target) -> str:
    """Quirks belong to a DEPLOYMENT on an ACCOUNT, not to the process. Two
    deployments on one endpoint differ (Mistral enforces JSON, a reasoning model
    might not), and the same deployment name on a different account is a
    different thing entirely."""
    return f"{target.azure_endpoint}|{target.azure_deployment}"


def _azure_credential(client_id: str | None):
    """One credential object per identity, kept for the process lifetime.

    Reuse is not a micro-optimisation: the credential owns the token cache, so a
    fresh one per call re-authenticates every time -- an IMDS round trip inside
    Container Apps, and a whole `az account get-access-token` SUBPROCESS on a
    developer machine.

    A named client id gets `ManagedIdentityCredential`, NOT
    `DefaultAzureCredential(managed_identity_client_id=...)`, even though the
    latter would also work on a developer laptop. Naming an identity is an
    instruction about WHO the product authenticates as; the chained credential
    answers a failure to reach that identity by silently authenticating as
    whoever else is lying around -- a developer's `az login`, an environment
    service principal -- and a security tool that quietly acts as a different
    principal than its own configuration names is precisely the substitution
    this codebase refuses everywhere else. No client id -> the chain, which is
    what lets one code path serve both Container Apps and `az login`.
    """
    key = client_id or ""
    cred = _AZURE_CREDENTIALS.get(key)
    if cred is None:
        # Late import for the same reason as the OpenAI/Anthropic clients: a
        # deployment that never selects Azure should not pay for the package,
        # and a machine without it should get an honest ImportError at the point
        # of use rather than an import failure of the whole advisory layer.
        from azure.identity import DefaultAzureCredential, ManagedIdentityCredential
        cred = (ManagedIdentityCredential(client_id=client_id) if client_id
                else DefaultAzureCredential())
        _AZURE_CREDENTIALS[key] = cred
    return cred


# The credential probe behind `provider_status()`. Cached like `ollama_probe`,
# and for the same reason -- it is on the health path -- but with two
# differences that its shape follows from:
#   * a SUCCESS is good for much longer than a probe of a local server: an AAD
#     token is minted for an hour and the credential caches it, so re-asking
#     every 30s would be pure subprocess churn on a developer machine;
#   * a FAILURE can be slow. `DefaultAzureCredential` walks a chain, and on a
#     machine where nothing is configured the walk takes tens of seconds. That
#     cannot be allowed to become the latency of `/api/health`, so the probe
#     runs on a daemon thread and the caller waits only a small budget for it.
_AZURE_CRED_TTL = 300.0
_AZURE_CRED_FAIL_TTL = 30.0
_AZURE_CRED_BUDGET = 2.0
_AZURE_CRED: dict[str, Any] = {"key": None, "at": 0.0, "ok": None, "detail": None,
                               "thread": None}
_AZURE_CRED_LOCK = threading.Lock()


def _azure_probe_once(client_id: str | None) -> None:
    """Ask the credential chain for one data-plane token and record the answer.

    Runs on the probe thread, so it may not raise and may not log at error --
    the caller decides what an unauthenticated deployment means.
    """
    ok, detail = False, None
    try:
        _azure_credential(client_id).get_token(settings.AZURE_AI_SCOPE)
        ok, detail = True, f"a token was issued for {settings.AZURE_AI_SCOPE}"
    except Exception as exc:  # noqa: BLE001 — a status probe reports, it does not crash
        # Broad on purpose: the credential chain raises its own hierarchy
        # (ClientAuthenticationError, CredentialUnavailableError), the package
        # may not be installed at all (ImportError), and the underlying
        # transport contributes OSError. All three are the same answer here --
        # "no, and here is what it said".
        detail = f"{type(exc).__name__}: {exc}"
    with _AZURE_CRED_LOCK:
        _AZURE_CRED.update(key=client_id or "", at=time.monotonic(), ok=ok, detail=detail)


def azure_credential_state(auth_mode: str, client_id: str | None,
                           budget: float = _AZURE_CRED_BUDGET) -> tuple[bool | None, str]:
    """`(ok, detail)` for "could this configuration actually authenticate?".

    THREE answers, not two. `None` means "not known yet" and is not a synonym
    for False: reporting a slow first probe as "the credential does not work"
    would send an operator to fix a role assignment that is fine. The probe
    keeps running in the background and the next call gets the real answer.

    Key mode is answered without any network at all -- the only question is
    whether the secret reached this process's environment, and it either did or
    it did not.
    """
    if auth_mode == "key":
        if settings.AZURE_AI_API_KEY:
            return True, "an API key is present in this deployment's environment"
        return False, ("azure_auth_mode is 'key' but AZURE_AI_API_KEY is not set in this "
                       "deployment's environment (keys are never stored in the database; "
                       "put it in a Container Apps secret)")

    key = client_id or ""
    now = time.monotonic()
    with _AZURE_CRED_LOCK:
        ttl = _AZURE_CRED_TTL if _AZURE_CRED["ok"] else _AZURE_CRED_FAIL_TTL
        if (_AZURE_CRED["key"] == key and _AZURE_CRED["ok"] is not None
                and now - _AZURE_CRED["at"] < ttl):
            return _AZURE_CRED["ok"], _AZURE_CRED["detail"]
        worker = _AZURE_CRED["thread"]
        if worker is None or not worker.is_alive():
            worker = threading.Thread(target=_azure_probe_once, args=(client_id,),
                                      name="npr-azure-credential-probe", daemon=True)
            _AZURE_CRED["thread"] = worker
            worker.start()
    worker.join(budget)                    # bounded: health must not wait on AAD
    with _AZURE_CRED_LOCK:
        if _AZURE_CRED["key"] == key and _AZURE_CRED["ok"] is not None:
            return _AZURE_CRED["ok"], _AZURE_CRED["detail"]
    return None, (f"a credential check for this identity is still running; it did not answer "
                  f"within {budget:g}s, so this is reported as unknown rather than guessed")


def reset_azure_caches() -> None:
    """Drop every cached Azure object.

    The product never needs this: each cache is keyed on the very thing that
    would invalidate it -- clients on the resolved target, quirks on
    endpoint+deployment, the credential on the identity -- so an operator
    repointing the configuration is served a new one automatically. Tests do
    need it, and a supported entry point is better than a test reaching into
    module globals and guessing which ones matter.
    """
    _AZURE_CREDENTIALS.clear()
    _AZURE_CLIENTS.clear()
    _AZURE_QUIRKS.clear()
    with _AZURE_CRED_LOCK:
        _AZURE_CRED.update(key=None, at=0.0, ok=None, detail=None, thread=None)


def _get_azure_client(target):
    """An `openai.AzureOpenAI` bound to one resolved target, cached on it.

    The cache key is everything that changes WHERE the call goes or AS WHOM: a
    saved configuration change must not be served the previous account's client.
    The API key is keyed by digest rather than by value so a rotated secret
    still builds a fresh client without the secret itself living in a dict key
    that a `repr` or a traceback could print.

    `max_retries=0`, unlike the OpenAI and Anthropic clients above, and that is
    deliberate. `complete()` hands this path a caller-supplied timeout and
    documents it as a bound; an SDK retry makes the true worst case a multiple
    of that bound, and it would do it on exactly the failure this kind of
    account produces most (`429 RateLimitReached`, whose Retry-After the SDK
    honours by sleeping). Every advisory capability has a deterministic
    fallback, so a bounded degradation now is worth more than an unbounded wait
    for a slightly better answer.
    """
    from openai import AzureOpenAI

    fingerprint = ""
    if target.azure_auth_mode == "key":
        fingerprint = hashlib.sha256(settings.AZURE_AI_API_KEY.encode()).hexdigest()[:12]
    cache_key = (target.azure_endpoint, target.azure_api_version, target.azure_auth_mode,
                 target.azure_client_id or "", fingerprint)
    client = _AZURE_CLIENTS.get(cache_key)
    if client is None:
        if target.azure_auth_mode == "key":
            auth = {"api_key": settings.AZURE_AI_API_KEY}
        else:
            from azure.identity import get_bearer_token_provider
            # A PROVIDER, not a token: the SDK calls it per request, and the
            # credential underneath serves a cached token until it is close to
            # expiry. A token captured once here would be a client that works
            # for an hour and then 401s forever.
            auth = {"azure_ad_token_provider": get_bearer_token_provider(
                _azure_credential(target.azure_client_id), settings.AZURE_AI_SCOPE)}
        client = AzureOpenAI(azure_endpoint=target.azure_endpoint,
                             api_version=target.azure_api_version,
                             timeout=_LLM_TIMEOUT, max_retries=0, **auth)
        if len(_AZURE_CLIENTS) >= _AZURE_CLIENT_CACHE_MAX:
            _AZURE_CLIENTS.clear()
        _AZURE_CLIENTS[cache_key] = client
    return client


def _azure_quirk_for(exc: Exception, *, sent_json_mode: bool, token_param: str) -> str | None:
    """The adaptation a 400 is asking for, or None to let the error stand.

    Deliberately narrow: only a 400 whose OWN message names the parameter this
    call actually sent produces an adaptation. A loop that retried on any 400
    would turn one honest failure into three, and would bury a real rejection --
    a malformed prompt, a content policy -- under "we tried something else".
    """
    if getattr(exc, "status_code", None) != 400:
        return None
    message = str(exc).lower()
    if sent_json_mode and "response_format" in message:
        return _QUIRK_NO_JSON_MODE
    if token_param == "max_tokens" and "max_completion_tokens" in message:
        return _QUIRK_MAX_COMPLETION_TOKENS
    return None


def _azure_complete(system, user, model, temperature, expect_json, timeout=None) -> LLMResponse:
    """One completion against the configured Azure AI Foundry deployment.

    Returns `ok=False` rather than raising for the states that are not
    exceptional -- not configured, truncated, filtered, empty -- so the reason
    reaches the log and the metric in the same shape a transport error does. A
    genuine transport or SDK failure still raises and is caught by `complete()`.

    `timeout` is a budget for the WHOLE call including any learned retry, not a
    per-attempt allowance: it is subtracted from a deadline before each attempt,
    so three attempts cannot cost three timeouts.
    """
    # Late import: `ai_config` pulls in psycopg and the connection pool, and
    # nothing else in this module needs a database. The direction of the arrow
    # is the same one settings.py documents -- policy on top, never a cycle.
    from .. import ai_config

    target = settings.azure_target()
    ready, why = ai_config.azure_ready(target)
    if not ready:
        # NOT an exception: a deployment nobody has configured is a state, not a
        # fault, and a traceback for it would be noise in the one log an
        # operator reads to find out why their capability went generic.
        return LLMResponse(text="", provider="azure", model=model or "(unconfigured)",
                           ok=False,
                           error=f"the azure provider is selected but cannot make a call: {why}")

    deployment = target.azure_deployment
    client = _get_azure_client(target)
    quirks = _AZURE_QUIRKS.setdefault(_quirk_key(target), set())
    budget = float(timeout) if timeout else _LLM_TIMEOUT
    deadline = time.monotonic() + budget

    raw = None
    native_json = False
    for attempt in range(3):        # the call, plus at most the two learned adaptations
        native_json = bool(expect_json) and _QUIRK_NO_JSON_MODE not in quirks
        token_param = ("max_completion_tokens" if _QUIRK_MAX_COMPLETION_TOKENS in quirks
                       else "max_tokens")
        # Only weaken the prompt when the service will not enforce the shape.
        # Under native JSON mode the instruction is redundant, and appending it
        # anyway would mean two providers' prompts differ for no reason.
        prompt = system if (native_json or not expect_json) else system + _JSON_ONLY
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError(
                f"the {budget:g}s budget for this completion was spent before attempt "
                f"{attempt + 1} could be made")
        kwargs: dict[str, Any] = {token_param: _AZURE_MAX_TOKENS}
        if native_json:
            kwargs["response_format"] = {"type": "json_object"}
        try:
            raw = client.chat.completions.create(
                model=deployment, temperature=temperature, timeout=remaining,
                messages=[{"role": "system", "content": prompt},
                          {"role": "user", "content": user}],
                **kwargs)
        except Exception as exc:  # noqa: BLE001 — re-raised unless the 400 teaches us something
            quirk = _azure_quirk_for(exc, sent_json_mode=native_json, token_param=token_param)
            if quirk is None or quirk in quirks:
                raise
            quirks.add(quirk)
            log.warning("the Azure deployment rejected a parameter this call sent; adapting "
                        "and retrying once within the same timeout budget",
                        extra={"event": "azure_deployment_quirk", "quirk": quirk,
                               "deployment": deployment, "endpoint": target.azure_endpoint,
                               "error": _error_reason(exc)})
            continue
        break
    else:
        raise RuntimeError(f"the Azure deployment {deployment!r} rejected every parameter "
                           f"combination this client knows how to adapt to")

    # Provenance, decided before anything can go wrong with the body: if JSON was
    # asked for, say which KIND of JSON promise is behind the text.
    json_mode = ("native" if native_json else "instruction") if expect_json else None
    usage = getattr(raw, "usage", None)
    prompt_tokens = int(getattr(usage, "prompt_tokens", 0) or 0)
    completion_tokens = int(getattr(usage, "completion_tokens", 0) or 0)

    choices = getattr(raw, "choices", None) or []
    if not choices:
        return LLMResponse(text="", provider="azure", model=deployment, ok=False,
                           error="the deployment returned a response with no choices",
                           prompt_tokens=prompt_tokens, completion_tokens=completion_tokens,
                           json_mode=json_mode)
    choice = choices[0]
    finish = getattr(choice, "finish_reason", None)
    text = getattr(getattr(choice, "message", None), "content", None) or ""

    incomplete = _AZURE_INCOMPLETE.get(finish or "")
    if incomplete:
        # The fragment is DROPPED rather than returned alongside ok=False.
        # `.text` is what every caller reads, several of them behind an `if
        # r.ok` that a later edit could lose, and half an answer that reads like
        # a whole one is the exact failure this check exists to prevent. A
        # bounded sample goes to the log, so a human can still see what came
        # back. The token counts are kept: a truncated call still cost money.
        log.warning("the Azure deployment returned an incomplete answer; the caller will use "
                    "its deterministic fallback",
                    extra={"event": "azure_incomplete", "deployment": deployment,
                           "finish_reason": finish, "completion_tokens": completion_tokens,
                           "sample": text[:200]})
        return LLMResponse(text="", provider="azure", model=deployment, ok=False,
                           error=(f"{incomplete} (finish_reason={finish!r}, "
                                  f"{completion_tokens} completion tokens)"),
                           prompt_tokens=prompt_tokens, completion_tokens=completion_tokens,
                           finish_reason=finish, json_mode=json_mode)
    if not text.strip():
        # A 200 with a usage block and nothing in it. Measured on the reasoning
        # deployment of the verified account, and indistinguishable from a
        # working model to anything that only checks the status code.
        return LLMResponse(text="", provider="azure", model=deployment, ok=False,
                           error=(f"the deployment returned an empty message "
                                  f"(finish_reason={finish!r}, {completion_tokens} completion "
                                  f"tokens). A reasoning deployment can spend its entire "
                                  f"budget in `reasoning_content` and emit no content at all."),
                           prompt_tokens=prompt_tokens, completion_tokens=completion_tokens,
                           finish_reason=finish, json_mode=json_mode)
    return LLMResponse(text=text, provider="azure", model=deployment,
                       prompt_tokens=prompt_tokens, completion_tokens=completion_tokens,
                       finish_reason=finish, json_mode=json_mode)


def _error_reason(exc: BaseException, *, depth: int = 3) -> str:
    """`Type: message`, with the chained causes appended.

    A vendor SDK re-raises a transport failure as its own type with a message
    that has thrown away the reason: a DNS failure, a refused connection, a TLS
    error and an unreachable host are ALL `openai.APIConnectionError("Connection
    error.")` from the outside. That string is what ends up in
    `LLMResponse.error`, in the `ai_metrics` row and in the health payload, and
    "Connection error." answers none of the questions an operator has at 2am.
    The `__cause__` chain is where the actual reason is, so it comes along.

    `__cause__` only, never `__context__`: an explicit `raise ... from err` is a
    statement that the two are the same failure, while implicit context is often
    an unrelated exception that merely happened to be in flight, and appending
    that would be inventing a causal claim.
    """
    parts: list[str] = []
    seen: set[int] = set()
    current: BaseException | None = exc
    while current is not None and len(parts) < depth and id(current) not in seen:
        seen.add(id(current))
        parts.append(f"{type(current).__name__}: {current}")
        current = current.__cause__
    return " <- ".join(parts)


def complete(*, system: str, user: str, role: str = "judge", temperature: float = 0.1,
             expect_json: bool = False, provider: str | None = None,
             timeout: float | None = None, capability: str | None = None,
             subject: str | None = None) -> LLMResponse:
    """Single-shot completion. Never raises — returns ok=False on any failure so
    callers can fall back deterministically (fail-closed). `timeout` (seconds)
    bounds the Ollama and Azure calls, whose endpoints can be cold, slow or
    gone, so they degrade to the fallback instead of hanging the request; on the
    Azure path it is a budget for the WHOLE call, learned retries included.
    (Anthropic and OpenAI take the fixed `_LLM_TIMEOUT` on their clients: no
    caller passes a timeout to them today, and inventing one here would change
    two providers' behaviour to document a third's.) `capability` labels the
    call for the metrics dashboards (defaults to the role); every call (success
    or failure) is recorded."""
    provider = provider or settings.active_provider()
    model = model_for(provider, role)
    cap = capability or role
    t0 = time.perf_counter()
    try:
        if provider == "anthropic":
            res = _anthropic_complete(system, user, model, temperature, expect_json)
        elif provider == "openai":
            res = _openai_complete(system, user, model, temperature, expect_json)
        elif provider == "azure":
            res = _azure_complete(system, user, model, temperature, expect_json, timeout)
        else:
            res = _ollama_complete(system, user, model, temperature, expect_json, timeout)
    except Exception as e:  # noqa: BLE001 — fail closed, never crash the pipeline
        # Deliberately broad: three of the four branches are vendor SDKs
        # (openai, anthropic, and azure via openai + azure-identity) with their
        # own exception hierarchies, and all of them are imported lazily inside
        # the branch, so an ImportError on a machine without the package lands
        # here too. Narrowing would mean importing the SDKs at module scope
        # purely to name their errors, which is the cost this file's lazy
        # imports exist to avoid.
        #
        # The metric below already records ok=False, but it is written to the
        # SAME database that may be the reason this call failed, and its own
        # write is fail-closed -- so the metric alone is not an observation. The
        # log line is.
        reason = _error_reason(e)
        res = LLMResponse(text="", provider=provider, model=model, ok=False, error=reason)
        log.warning("model call failed; the caller will use its deterministic fallback",
                    exc_info=True, extra={"event": "llm_call_failed", "capability": cap,
                                          "provider": provider, "model": model,
                                          "error": reason})
    else:
        # A provider may also answer 200 with something unusable -- a truncated
        # completion, a filtered one, an empty body, a target nobody configured.
        # Those are `ok=False` WITHOUT an exception, and they degrade a
        # capability exactly as loudly as a transport error does, so they get the
        # same one line. Without this branch the only trace of a truncation
        # would be a metric row in a database that is not always reachable --
        # which is the observability gap this module was rewritten to close.
        if not res.ok:
            log.warning("the model call did not produce a usable answer; the caller will use "
                        "its deterministic fallback",
                        extra={"event": "llm_call_unusable", "capability": cap,
                               "provider": res.provider, "model": res.model,
                               "finish_reason": res.finish_reason, "error": res.error})
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

def _azure_status(target, ready: bool, reason: str | None, active: str) -> dict:
    """What the Azure provider is pointed at, and whether it could actually run.

    "Configured" and "will authenticate" are kept apart here for the same reason
    `ai_config.azure_ready` keeps them apart: a deployment that is completely
    filled in on the Configuration page, whose identity has no role assignment
    on the account, is a 401 that reads to a user as a weak model. So the
    credential is PROBED rather than inferred from the fact that somebody typed
    a client id in.

    The probe is skipped entirely when no Azure target is configured and azure
    is not the selected provider. That keeps `/api/health` on a deployment that
    has never heard of Azure -- and the offline test suite -- free of any
    network call or background thread from this function.
    """
    if target.azure_target_configured or active == "azure":
        credential_ok, credential_detail = azure_credential_state(
            target.azure_auth_mode, target.azure_client_id)
    else:
        credential_ok = None
        credential_detail = "not checked: no Azure deployment is configured"
    quirks = sorted(_AZURE_QUIRKS.get(_quirk_key(target), ()))
    if target.azure_auth_mode == "key":
        identity = "an API key from this deployment's environment"
    elif target.azure_client_id:
        identity = f"user-assigned managed identity {target.azure_client_id}"
    else:
        identity = "the default credential chain (managed identity, then `az login`)"
    return {
        "configured": target.azure_target_configured,
        "endpoint": target.azure_endpoint,
        "deployment": target.azure_deployment,
        "api_version": target.azure_api_version,
        "auth_mode": target.azure_auth_mode,
        "client_id": target.azure_client_id,
        "identity": identity,
        "origin": target.azure_origin,
        "config_source": target.config_source,
        "endpoint_error": target.azure_endpoint_error,
        "ready": ready,
        "reason": reason,
        # None = not established. Not False: see `azure_credential_state`.
        "credential_ok": credential_ok,
        "credential_detail": credential_detail,
        # "native" until this deployment's own 400 says otherwise, at which
        # point every `expect_json` call against it is asking rather than
        # enforcing -- a real reduction in what the advisory layer guarantees,
        # and therefore something the status payload states out loud.
        "json_mode": "instruction" if _QUIRK_NO_JSON_MODE in quirks else "native",
        "quirks": quirks,
    }


def provider_status() -> dict:
    # Late, and only here: `ai_config` reaches psycopg, and this module must
    # stay importable by scripts that never touch a database.
    from .. import ai_config

    active = settings.active_provider()
    ollama_ok, ollama_models = settings.ollama_probe()  # shared, cached probe
    azure_target = settings.azure_target()              # cached read; one per status call
    azure_ok, azure_why = ai_config.azure_ready(azure_target)
    return {
        "active_provider": active,
        "judge_model": model_for(active, "judge"),
        "prose_model": model_for(active, "prose"),
        "embed_model": settings.OLLAMA_EMBED_MODEL,
        "ollama_reachable": ollama_ok,
        "ollama_models": ollama_models,
        "anthropic_available": settings.has_anthropic(),
        "openai_available": settings.has_openai(),
        # Availability, not mere configuration -- the same predicate `auto` uses
        # to decide whether it may route here, so the banner and the router
        # cannot disagree.
        "azure_available": azure_ok,
        "azure": _azure_status(azure_target, azure_ok, azure_why, active),
        # Azure is "hosted": the topology does leave this box. It leaves it for
        # the CUSTOMER'S OWN subscription rather than a third party's, which is
        # why `auto` prefers it over OpenAI/Anthropic (settings.active_provider)
        # -- but "hosted" is the honest word for the chip, and softening it here
        # would be the residency claim quietly getting weaker.
        "data_residency": "local" if active == "ollama" else "hosted",
    }
