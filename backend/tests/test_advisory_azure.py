"""The Azure AI Foundry provider: what it sends, and what it refuses to believe.

Every test here but one runs offline. They drive the REAL `openai.AzureOpenAI`
client over an `httpx.MockTransport`, rather than stubbing the client itself,
because the questions worth asking about this provider are almost all about the
wire: does an identity-mode call carry a bearer token and no key, does a
key-mode call carry a key and never touch the credential chain, does the request
land on `/openai/deployments/{deployment}/chat/completions` with the configured
api-version, and does `expect_json` actually put `response_format` in the body.
A hand-rolled stub of the SDK would answer none of those and would keep
answering them after the SDK changed its URL shape.

WHY SO MUCH OF THIS FILE IS ABOUT FAILURE
-----------------------------------------
The round-2 audit's finding about the AI layer was that a deterministic fallback
and a real model call were labelled identically, so "the model looked at this"
could not be distinguished from "nothing did". A hosted provider adds three new
ways to produce that same lie, and all three are HTTP 200:

  * a truncated completion (`finish_reason: "length"`) -- a fragment that parses
    and reads like an answer;
  * a filtered one (`finish_reason: "content_filter"`) -- a 200 with nothing in
    it;
  * an EMPTY one from a reasoning deployment, which spends its whole completion
    budget in `reasoning_content` and emits `content: ""` while reporting
    `finish_reason: "stop"`.

The third is not hypothetical. It is what `Kimi-K2.7-Code` on the live account
this was built against does, measured, at a budget that is generous for a chat
model. So each of the three is asserted to be `ok=False`, with the partial text
DROPPED rather than handed on, and with the token counts kept -- a truncated
call still cost money and still belongs in the metrics.

THE LIVE TEST
-------------
`test_live_completion_against_a_real_foundry_deployment` is the only one that
opens a socket, and it follows `backend/tests/test_db_governance.py`'s pattern
exactly, for the same reason: an offline default that CI can run, and a LOUD
failure when a real target was asked for and could not be reached, because a run
that was told to prove something against the real service and quietly skipped
has proved nothing and must not exit 0.

    NPR_TEST_AZURE_ENDPOINT=https://api-endpoint-inference-resource.cognitiveservices.azure.com/ \
    NPR_TEST_AZURE_DEPLOYMENT=Mistral-Large-3 \
      backend/.venv/bin/python -m pytest backend/tests/test_advisory_azure.py -k live -s

Both variables are required to opt in. The deployment deliberately has no
default: guessing a deployment name on somebody else's account produces a
`DeploymentNotFound` that reads like a product bug rather than like a missing
environment variable.
"""

from __future__ import annotations

import json
import os
import threading
import time
from typing import Any, Callable, Iterator

import httpx
import openai
import pytest
from azure.core.credentials import AccessToken, AccessTokenInfo

from src import ai_config, settings
from src.advisory import client as llm
from tests.dbharness import FAIL, RUN, SKIP

ENDPOINT = "https://acct.cognitiveservices.azure.com/"
DEPLOYMENT = "Mistral-Large-3"
API_VERSION = "2024-10-21"


# --------------------------------------------------------------------------
# harness
# --------------------------------------------------------------------------

class FakeCredential:
    """A `TokenProvider` that answers instantly and records who asked.

    Implements BOTH `get_token` and `get_token_info`: azure-core's
    `BearerTokenCredentialPolicy` prefers the newer one when a credential
    exposes it, and a fake that only had the old one would be exercising a code
    path the real `DefaultAzureCredential` no longer takes.
    """

    def __init__(self, token: str = "fake-aad-token", *, fail: Exception | None = None,
                 client_id: str | None = None) -> None:
        self.token = token
        self.fail = fail
        self.client_id = client_id
        self.scopes: list[tuple[str, ...]] = []

    def _issue(self, scopes: tuple[str, ...]) -> None:
        if self.fail is not None:
            raise self.fail
        self.scopes.append(scopes)

    def get_token(self, *scopes: str, **_kwargs: Any) -> AccessToken:
        self._issue(scopes)
        return AccessToken(self.token, int(time.time()) + 3600)

    def get_token_info(self, *scopes: str, **_kwargs: Any) -> AccessTokenInfo:
        self._issue(scopes)
        return AccessTokenInfo(self.token, int(time.time()) + 3600)


def completion_body(content: str = "an answer", *, finish: str = "stop",
                    model: str = "mistral-large-3", prompt_tokens: int = 11,
                    completion_tokens: int = 3) -> dict[str, Any]:
    """The chat-completion envelope the real account returns, field for field.

    Copied from a recorded response rather than invented, including `model`
    reporting the underlying model id (`mistral-large-3`) where the DEPLOYMENT
    is named `Mistral-Large-3` -- the two are not the same string, and a fixture
    that made them the same would hide the case `model_for` documents.
    """
    return {
        "id": "e8c9bb4a4f3c469880b8b28ab5fb5465",
        "object": "chat.completion",
        "created": 1788696655,
        "model": model,
        "choices": [{"index": 0, "finish_reason": finish,
                     "message": {"role": "assistant", "content": content}}],
        "usage": {"prompt_tokens": prompt_tokens, "completion_tokens": completion_tokens,
                  "total_tokens": prompt_tokens + completion_tokens},
    }


class Wire:
    """Every request the SDK actually put on the wire, and the replies given."""

    def __init__(self, *replies: Callable[[httpx.Request], httpx.Response]) -> None:
        self.replies = list(replies)
        self.requests: list[httpx.Request] = []

    def rearm(self, *replies: Callable[[httpx.Request], httpx.Response]) -> "Wire":
        """New replies down the SAME transport, and a fresh request log.

        Installing a second recorder would not work: `_get_azure_client` caches
        the client on the resolved target, so a later call in the same test
        keeps the transport it was built with. Re-arming is also what makes
        "the rejection was LEARNED" testable at all -- dropping the client cache
        would drop the learned quirk with it, which is the thing under test.
        """
        self.replies = list(replies)
        self.requests.clear()
        return self

    def handle(self, request: httpx.Request) -> httpx.Response:
        # `request.read()` before the reply, because a MockTransport reply may
        # close the stream and a test that inspects the body afterwards would
        # otherwise get an empty one.
        request.read()
        self.requests.append(request)
        reply = self.replies[min(len(self.requests) - 1, len(self.replies) - 1)]
        return reply(request)

    # -- readers, so the assertions below read like sentences ---------------
    def body(self, i: int = 0) -> dict[str, Any]:
        return json.loads(self.requests[i].content)

    def timeout(self, i: int = 0) -> float:
        return float(self.requests[i].extensions["timeout"]["read"])

    @property
    def count(self) -> int:
        return len(self.requests)


def ok(content: str = "an answer", **kw: Any) -> Callable[[httpx.Request], httpx.Response]:
    return lambda _request: httpx.Response(200, json=completion_body(content, **kw))


def status(code: int, message: str) -> Callable[[httpx.Request], httpx.Response]:
    return lambda _request: httpx.Response(
        code, json={"error": {"code": str(code), "message": message}})


def boom(exc: Exception) -> Callable[[httpx.Request], httpx.Response]:
    def raise_it(_request: httpx.Request) -> httpx.Response:
        raise exc
    return raise_it


@pytest.fixture(autouse=True)
def _clean_azure_state(request: pytest.FixtureRequest,
                       monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    """No cached client, credential, quirk or probe result crosses a test -- and
    no test reaches the REAL credential chain by accident.

    `reset_azure_caches()` exists for exactly this; `ai_config.invalidate()`
    drops the resolver's own 30s cache so a fixture that repoints the
    environment takes effect on the next call rather than up to a TTL later.

    The second half is the one that was missing. `provider_status()` probes the
    credential whenever an Azure target is configured or `azure` is the active
    provider, on a background thread, and the probe swallows every exception by
    design (`_azure_probe_once`: "a status probe reports, it does not crash").
    So a test that set up an Azure target but forgot the `credential` fixture
    did not fail -- it called `DefaultAzureCredential().get_token()` against
    real AAD, from the offline suite, and then asserted on the fields it did
    care about while that probe ran. `test_provider_status_reports_a_malformed
    _endpoint_rather_than_using_it` was doing exactly that; the outbound-socket
    guard in backend/conftest.py is what surfaced it.

    A refusing default turns "forgot to opt in" into a deterministic
    `credential_ok is False` with a legible detail, and any test that wants a
    working (or specifically-failing) credential still asks for it by name via
    the `credential` fixture, which overrides this. Tests marked `live` are
    exempt: reaching the real chain is their entire subject.
    """
    llm.reset_azure_caches()
    ai_config.invalidate()
    if not request.node.get_closest_marker("live"):
        import azure.identity

        def _refuse(*_a: Any, **_k: Any) -> Any:
            raise AssertionError(
                "this test reached the real Azure credential chain. The offline "
                "suite may not authenticate against AAD -- ask for the "
                "`credential` fixture (FakeCredential) if the test needs a "
                "credential, or mark it `live` if it genuinely needs the real one."
            )

        monkeypatch.setattr(azure.identity, "DefaultAzureCredential", _refuse)
    yield
    llm.reset_azure_caches()
    ai_config.invalidate()


@pytest.fixture()
def azure(monkeypatch: pytest.MonkeyPatch) -> None:
    """Point the resolver at a fake account through the ENVIRONMENT half of the
    resolution order.

    Not by stubbing `settings.azure_target()`: `resolve()` and `azure_ready()`
    are the code that decides whether a call may be attempted at all, and a test
    that handed the client a pre-built `Resolved` would never run them.
    """
    monkeypatch.setattr(settings, "ADVISORY_PROVIDER", "azure")
    monkeypatch.setattr(settings, "AZURE_AI_ENDPOINT", ENDPOINT)
    monkeypatch.setattr(settings, "AZURE_AI_DEPLOYMENT", DEPLOYMENT)
    monkeypatch.setattr(settings, "AZURE_AI_API_VERSION", API_VERSION)
    monkeypatch.setattr(settings, "AZURE_AI_AUTH_MODE", "identity")
    monkeypatch.setattr(settings, "AZURE_AI_CLIENT_ID", "")
    monkeypatch.setattr(settings, "AZURE_AI_API_KEY", "")


@pytest.fixture()
def wire(monkeypatch: pytest.MonkeyPatch) -> Callable[..., Wire]:
    """Install a mock transport under the REAL `openai.AzureOpenAI`.

    A subclass rather than a stub, so URL construction, the api-version query
    parameter, the `api-key` header and the `azure_ad_token_provider` handshake
    are all still the SDK's own code. `_get_azure_client` does
    `from openai import AzureOpenAI` inside the function, so rebinding the
    attribute on the package is what reaches it.
    """
    def install(*replies: Callable[[httpx.Request], httpx.Response]) -> Wire:
        recorder = Wire(*(replies or (ok(),)))
        real = openai.AzureOpenAI

        class Capturing(real):  # type: ignore[misc, valid-type]
            def __init__(self, **kwargs: Any) -> None:
                kwargs["http_client"] = httpx.Client(
                    transport=httpx.MockTransport(recorder.handle))
                super().__init__(**kwargs)

        monkeypatch.setattr(openai, "AzureOpenAI", Capturing)
        return recorder

    return install


@pytest.fixture()
def credential(monkeypatch: pytest.MonkeyPatch) -> Callable[..., FakeCredential]:
    """Replace the whole credential chain with one that answers instantly."""
    def install(**kwargs: Any) -> FakeCredential:
        fake = FakeCredential(**kwargs)
        import azure.identity
        monkeypatch.setattr(azure.identity, "DefaultAzureCredential",
                            lambda *a, **k: fake)
        return fake

    return install


def complete(**kwargs: Any) -> llm.LLMResponse:
    """`complete()` with the Azure provider named explicitly, so a test asserts
    about the provider rather than about routing (which `active_provider` owns
    and `test_provider_status_*` covers)."""
    kwargs.setdefault("system", "You are a firewall policy reviewer.")
    kwargs.setdefault("user", "Is 0.0.0.0/0 on tcp/22 acceptable?")
    kwargs.setdefault("provider", "azure")
    return llm.complete(**kwargs)


# --------------------------------------------------------------------------
# what goes on the wire, per auth mode
# --------------------------------------------------------------------------

def test_identity_mode_calls_the_deployment_route_with_a_bearer_token(
        azure: None, wire: Callable[..., Wire], credential: Callable[..., FakeCredential]) -> None:
    """The mode that works on Container Apps with no secret anywhere."""
    fake = credential()
    sent = wire(ok("firewalls are not opinions"))

    res = complete()

    assert sent.count == 1
    request = sent.requests[0]
    assert request.url.path == f"/openai/deployments/{DEPLOYMENT}/chat/completions"
    assert dict(request.url.params) == {"api-version": API_VERSION}
    assert request.headers["authorization"] == "Bearer fake-aad-token"
    # A bearer call must not ALSO carry a key: two credentials on one request is
    # how a leaked key keeps working long after someone believes it was retired.
    assert "api-key" not in request.headers
    # The scope is the data plane's, not ARM's. Getting this wrong yields a
    # perfectly valid token that the inference endpoint answers 401 to.
    assert fake.scopes == [("https://cognitiveservices.azure.com/.default",)]

    assert (res.ok, res.provider, res.model) == (True, "azure", DEPLOYMENT)
    assert res.text == "firewalls are not opinions"
    assert (res.prompt_tokens, res.completion_tokens) == (11, 3)
    assert res.finish_reason == "stop"
    assert res.json_mode is None            # JSON was not asked for


def test_key_mode_sends_a_key_and_never_touches_the_credential_chain(
        azure: None, monkeypatch: pytest.MonkeyPatch, wire: Callable[..., Wire],
        credential: Callable[..., FakeCredential]) -> None:
    """The manual escape hatch, and local dev.

    The credential is installed but must go UNUSED: a key-mode deployment that
    still walked the chain would work on a developer's machine and stall for the
    chain's full timeout in a container that has no identity.
    """
    monkeypatch.setattr(settings, "AZURE_AI_AUTH_MODE", "key")
    monkeypatch.setattr(settings, "AZURE_AI_API_KEY", "s3cret-from-the-environment")
    fake = credential()
    sent = wire()

    res = complete()

    request = sent.requests[0]
    assert request.headers["api-key"] == "s3cret-from-the-environment"
    assert "authorization" not in request.headers
    assert fake.scopes == []
    assert res.ok and res.provider == "azure"


def test_key_mode_without_a_key_never_leaves_the_process(
        azure: None, monkeypatch: pytest.MonkeyPatch, wire: Callable[..., Wire]) -> None:
    """Configured is not the same as usable, and the difference is stated.

    A key-mode target whose secret never reached the container would 401 on
    every call; unauthenticated 401s read to a user as a weak model, so this is
    refused before the request rather than after it.
    """
    monkeypatch.setattr(settings, "AZURE_AI_AUTH_MODE", "key")
    monkeypatch.setattr(settings, "AZURE_AI_API_KEY", "")
    sent = wire()

    res = complete()

    assert sent.count == 0
    assert res.ok is False
    assert "AZURE_AI_API_KEY" in (res.error or "")


def test_a_named_client_id_uses_managed_identity_and_only_that(
        azure: None, monkeypatch: pytest.MonkeyPatch, wire: Callable[..., Wire]) -> None:
    """Naming an identity is an instruction about WHO, not a hint.

    `DefaultAzureCredential` must not be constructed at all: its chain would
    answer an unreachable user-assigned identity by authenticating as whoever
    else is around, and a security tool acting as a principal its configuration
    does not name is the substitution this codebase refuses everywhere.
    """
    client_id = "cf31bca1-7a3d-4bb9-9c62-5b18f7667c04"
    monkeypatch.setattr(settings, "AZURE_AI_CLIENT_ID", client_id)
    seen: dict[str, Any] = {}
    import azure.identity

    def managed(**kwargs: Any) -> FakeCredential:
        seen.update(kwargs)
        return FakeCredential()

    def default(*_a: Any, **_k: Any) -> FakeCredential:
        raise AssertionError("DefaultAzureCredential was constructed despite a named client id")

    monkeypatch.setattr(azure.identity, "ManagedIdentityCredential", managed)
    monkeypatch.setattr(azure.identity, "DefaultAzureCredential", default)
    sent = wire()

    res = complete()

    assert seen == {"client_id": client_id}
    assert res.ok and sent.count == 1


# --------------------------------------------------------------------------
# expect_json
# --------------------------------------------------------------------------

def test_expect_json_asks_the_service_to_enforce_it(
        azure: None, wire: Callable[..., Wire],
        credential: Callable[..., FakeCredential]) -> None:
    """Native JSON mode: the service enforces the shape, so the prompt is not
    weakened with a plea for it, and the response says which promise is behind
    the text."""
    credential()
    sent = wire(ok('{"verdict": "allow"}'))

    res = complete(expect_json=True)

    body = sent.body()
    assert body["response_format"] == {"type": "json_object"}
    assert body["messages"][0]["content"] == "You are a firewall policy reviewer."
    assert res.json_mode == "native"
    assert llm.parse_json(res.text, None) == {"verdict": "allow"}


def test_a_deployment_that_rejects_json_mode_degrades_visibly_not_silently(
        azure: None, wire: Callable[..., Wire], credential: Callable[..., FakeCredential],
        caplog: pytest.LogCaptureFixture) -> None:
    """The honest fallback the brief asks for.

    A deployment with no JSON response mode is asked for JSON in the prompt
    instead -- which works often enough to be worth doing and is a strictly
    weaker promise -- and the response SAYS SO (`json_mode == "instruction"`).
    The alternative, retrying quietly, is how a capability stops being
    structured without anything recording the moment.
    """
    credential()
    sent = wire(
        status(400, "Unsupported parameter: 'response_format' is not supported with this model."),
        ok('{"verdict": "allow"}'),
    )

    with caplog.at_level("WARNING"):
        res = complete(expect_json=True)

    assert sent.count == 2
    assert "response_format" in sent.body(0)
    assert "response_format" not in sent.body(1)
    assert "ONLY valid JSON" in sent.body(1)["messages"][0]["content"]
    assert res.ok is True
    assert res.json_mode == "instruction"
    assert any(getattr(r, "event", "") == "azure_deployment_quirk" for r in caplog.records)

    # ...and the rejection is LEARNED: the next call pays one request, not two.
    sent.rearm(ok('{"verdict": "deny"}'))
    again = complete(expect_json=True)
    assert sent.count == 1
    assert "response_format" not in sent.body(0)
    assert again.json_mode == "instruction"


def test_a_400_that_does_not_name_a_parameter_we_sent_is_not_retried(
        azure: None, wire: Callable[..., Wire],
        credential: Callable[..., FakeCredential]) -> None:
    """Adaptation is narrow on purpose. A content-policy rejection or a
    malformed prompt is a real answer, and retrying it would turn one honest
    failure into several and bury the reason."""
    credential()
    sent = wire(status(400, "The prompt was filtered by the content management policy."))

    res = complete(expect_json=True)

    assert sent.count == 1
    assert res.ok is False
    assert "content management policy" in (res.error or "")


# --------------------------------------------------------------------------
# answers that are not answers
# --------------------------------------------------------------------------

def test_a_truncated_completion_is_not_reported_as_a_complete_one(
        azure: None, wire: Callable[..., Wire], credential: Callable[..., FakeCredential],
        caplog: pytest.LogCaptureFixture, monkeypatch: pytest.MonkeyPatch) -> None:
    """`finish_reason: "length"` is a 200 carrying a fragment.

    The fragment is dropped rather than returned beside `ok=False`, because
    `.text` is what every caller reads and half an answer reads exactly like a
    whole one. The token counts survive: a truncated call still cost money and
    still belongs in the metrics.
    """
    credential()
    wire(ok("# The Importance of Firewalls in Cybersec", finish="length",
            completion_tokens=12))
    metrics: list[dict[str, Any]] = []
    monkeypatch.setattr(llm, "record_metric", lambda **kw: metrics.append(kw))

    with caplog.at_level("WARNING"):
        res = complete()

    assert res.ok is False
    assert res.text == ""
    assert res.finish_reason == "length"
    assert "finish_reason='length'" in (res.error or "")
    assert (res.prompt_tokens, res.completion_tokens) == (11, 12)
    # The fragment is recoverable by a human, from the log, without being
    # returnable by a caller.
    incomplete = [r for r in caplog.records if getattr(r, "event", "") == "azure_incomplete"]
    assert incomplete and "Importance of Firewalls" in incomplete[0].sample
    assert [(m["ok"], m["completion_tokens"]) for m in metrics] == [(False, 12)]


def test_a_filtered_completion_is_ok_false(
        azure: None, wire: Callable[..., Wire],
        credential: Callable[..., FakeCredential]) -> None:
    credential()
    wire(ok("", finish="content_filter", completion_tokens=0))

    res = complete()

    assert res.ok is False
    assert "content filtering" in (res.error or "")
    assert res.finish_reason == "content_filter"


def test_an_empty_answer_from_a_reasoning_deployment_is_ok_false(
        azure: None, wire: Callable[..., Wire],
        credential: Callable[..., FakeCredential]) -> None:
    """Measured on `Kimi-K2.7-Code`: a 200, a usage block with real completion
    tokens spent in `reasoning_content`, `finish_reason: "stop"` -- and no
    content. Everything that only checks the status code calls this a success.
    """
    credential()
    wire(ok("", finish="stop", model="Kimi-K2.7-Code", completion_tokens=39))

    res = complete()

    assert res.ok is False
    assert res.text == ""
    assert "empty message" in (res.error or "")
    assert "reasoning_content" in (res.error or "")
    assert res.completion_tokens == 39


def test_a_transport_error_is_ok_false_and_never_raises(
        azure: None, wire: Callable[..., Wire], credential: Callable[..., FakeCredential],
        caplog: pytest.LogCaptureFixture) -> None:
    """The whole point of the fail-closed contract: a dead endpoint degrades one
    capability to its deterministic fallback, it does not 500 a request."""
    credential()
    wire(boom(httpx.ConnectError("dial tcp: no route to host")))

    with caplog.at_level("WARNING"):
        res = complete()

    assert res.ok is False
    assert res.provider == "azure" and res.model == DEPLOYMENT
    # The SDK renders every network failure as APIConnectionError("Connection
    # error."), which answers nothing. `_error_reason` keeps the cause, so the
    # metric row and the health payload say what actually went wrong.
    assert res.error == ("APIConnectionError: Connection error. "
                         "<- ConnectError: dial tcp: no route to host")
    assert any(getattr(r, "event", "") == "llm_call_failed" for r in caplog.records)


def test_an_unauthorized_deployment_is_ok_false(
        azure: None, wire: Callable[..., Wire],
        credential: Callable[..., FakeCredential]) -> None:
    """A credential that mints a token the ACCOUNT will not accept -- a missing
    role assignment, the commonest way managed identity is half-configured."""
    credential()
    wire(status(401, "PermissionDenied: Principal does not have access to API/Operation."))

    res = complete()

    assert res.ok is False
    assert "PermissionDenied" in (res.error or "")


def test_an_unconfigured_target_is_answered_without_a_request(
        azure: None, monkeypatch: pytest.MonkeyPatch, wire: Callable[..., Wire]) -> None:
    """Selected but not pointed anywhere. Not an exception: a deployment nobody
    has configured is a state, not a fault, and it names the missing piece."""
    monkeypatch.setattr(settings, "AZURE_AI_ENDPOINT", "")
    sent = wire()

    res = complete()

    assert sent.count == 0
    assert res.ok is False
    assert "no Azure endpoint is configured" in (res.error or "")
    assert res.provider == "azure"


def test_an_unusable_response_is_logged_like_a_failed_one(
        azure: None, wire: Callable[..., Wire], credential: Callable[..., FakeCredential],
        caplog: pytest.LogCaptureFixture) -> None:
    """A 200 that degrades a capability must leave the same trace a transport
    error does. The metric alone is not an observation -- it is written to a
    database that may itself be the reason the call failed."""
    credential()
    wire(ok("half an ans", finish="length"))

    with caplog.at_level("WARNING"):
        complete(capability="explain")

    unusable = [r for r in caplog.records if getattr(r, "event", "") == "llm_call_unusable"]
    assert len(unusable) == 1
    assert unusable[0].capability == "explain"
    assert unusable[0].provider == "azure"
    assert unusable[0].finish_reason == "length"


# --------------------------------------------------------------------------
# timeouts
# --------------------------------------------------------------------------

def test_the_caller_supplied_timeout_reaches_the_socket(
        azure: None, wire: Callable[..., Wire],
        credential: Callable[..., FakeCredential]) -> None:
    credential()
    sent = wire()

    complete(timeout=7.5)

    assert sent.timeout(0) == pytest.approx(7.5, abs=0.5)


def test_the_timeout_is_a_budget_for_the_call_not_for_each_attempt(
        azure: None, wire: Callable[..., Wire],
        credential: Callable[..., FakeCredential]) -> None:
    """A learned retry spends the caller's budget, it does not double it.

    The first reply sleeps, so the shrink is a real measurement rather than a
    float comparison that happens to hold.
    """
    credential()

    def slow_reject(_request: httpx.Request) -> httpx.Response:
        time.sleep(0.10)
        return httpx.Response(400, json={"error": {"code": "400", "message":
                              "Unsupported parameter: 'response_format'"}})

    sent = wire(slow_reject, ok('{"ok": true}'))

    res = complete(expect_json=True, timeout=5.0)

    assert sent.count == 2 and res.ok
    assert sent.timeout(0) == pytest.approx(5.0, abs=0.5)
    assert sent.timeout(1) <= sent.timeout(0) - 0.09


def test_an_exhausted_budget_fails_instead_of_making_the_call(
        azure: None, wire: Callable[..., Wire],
        credential: Callable[..., FakeCredential]) -> None:
    """A budget so small it is gone before the retry is a failure, not a call
    with no deadline on it."""
    credential()

    def slow_reject(_request: httpx.Request) -> httpx.Response:
        time.sleep(0.05)
        return httpx.Response(400, json={"error": {"code": "400", "message":
                              "Unsupported parameter: 'response_format'"}})

    sent = wire(slow_reject, ok())

    res = complete(expect_json=True, timeout=0.04)

    assert sent.count == 1
    assert res.ok is False
    assert "budget" in (res.error or "")


# --------------------------------------------------------------------------
# provider_status
# --------------------------------------------------------------------------

def test_provider_status_reports_a_working_azure_target(
        azure: None, credential: Callable[..., FakeCredential]) -> None:
    fake = credential()

    status_payload = llm.provider_status()

    assert status_payload["active_provider"] == "azure"
    assert status_payload["judge_model"] == DEPLOYMENT
    assert status_payload["azure_available"] is True
    # Azure is the customer's own subscription, but the topology still leaves
    # this box. The chip must not soften.
    assert status_payload["data_residency"] == "hosted"

    az = status_payload["azure"]
    assert az["configured"] is True
    assert (az["endpoint"], az["deployment"], az["api_version"]) == (
        ENDPOINT, DEPLOYMENT, API_VERSION)
    assert az["auth_mode"] == "identity"
    assert az["identity"].startswith("the default credential chain")
    assert az["origin"] == ai_config.ORIGIN_ENVIRONMENT
    assert (az["ready"], az["reason"]) == (True, None)
    assert az["credential_ok"] is True
    assert "token was issued" in az["credential_detail"]
    assert az["json_mode"] == "native" and az["quirks"] == []
    assert fake.scopes == [("https://cognitiveservices.azure.com/.default",)]


def test_provider_status_reports_a_credential_that_cannot_be_obtained(
        azure: None, credential: Callable[..., FakeCredential]) -> None:
    """The half-configured managed identity, which is what a role assignment
    nobody made looks like. Configured stays True; the credential is the thing
    that is False, and the two are different fixes."""
    credential(fail=RuntimeError("ManagedIdentityCredential authentication unavailable"))

    az = llm.provider_status()["azure"]

    assert az["configured"] is True and az["ready"] is True
    assert az["credential_ok"] is False
    assert "authentication unavailable" in az["credential_detail"]


def test_provider_status_reports_key_mode_without_a_key(
        azure: None, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "AZURE_AI_AUTH_MODE", "key")
    monkeypatch.setattr(settings, "AZURE_AI_API_KEY", "")

    payload = llm.provider_status()
    az = payload["azure"]

    assert payload["azure_available"] is False
    assert az["auth_mode"] == "key"
    assert az["identity"] == "an API key from this deployment's environment"
    assert az["ready"] is False and "AZURE_AI_API_KEY" in az["reason"]
    assert az["credential_ok"] is False


def test_provider_status_makes_no_azure_call_when_azure_is_not_in_play(
        monkeypatch: pytest.MonkeyPatch) -> None:
    """The default deployment has never heard of Azure. `/api/health` on it --
    and this offline suite -- must not start a thread or open a socket to say
    so."""
    monkeypatch.setattr(settings, "ADVISORY_PROVIDER", "auto")
    monkeypatch.setattr(settings, "AZURE_AI_ENDPOINT", "")
    monkeypatch.setattr(settings, "AZURE_AI_DEPLOYMENT", "")
    def refuse(*_a: Any, **_k: Any) -> None:
        raise AssertionError("a credential was constructed for a deployment with no Azure target")

    import azure.identity
    monkeypatch.setattr(azure.identity, "DefaultAzureCredential", refuse)
    before = threading.active_count()

    az = llm.provider_status()["azure"]

    assert az["configured"] is False
    assert az["credential_ok"] is None
    assert az["credential_detail"] == "not checked: no Azure deployment is configured"
    assert threading.active_count() == before


def test_provider_status_reports_a_malformed_endpoint_rather_than_using_it(
        azure: None, monkeypatch: pytest.MonkeyPatch) -> None:
    """An `AZURE_AI_ENDPOINT` typed into a container spec is not validated by
    `ai_config.save()`, because it never went through it."""
    monkeypatch.setattr(settings, "AZURE_AI_ENDPOINT",
                        "https://acct.cognitiveservices.azure.com/?api-key=leaked")

    az = llm.provider_status()["azure"]

    assert az["ready"] is False
    assert az["endpoint"] == ""
    assert az["endpoint_error"]
    assert "unusable" in az["reason"]


def test_model_for_azure_is_the_deployment_name(azure: None) -> None:
    """Not the model id: one Foundry account commonly serves both roles from one
    deployment, and the deployment name is what an operator picked."""
    assert llm.model_for("azure", "judge") == DEPLOYMENT
    assert llm.model_for("azure", "prose") == DEPLOYMENT


# --------------------------------------------------------------------------
# the live test, and the decision that gates it
# --------------------------------------------------------------------------

ENDPOINT_ENV = "NPR_TEST_AZURE_ENDPOINT"
DEPLOYMENT_ENV = "NPR_TEST_AZURE_DEPLOYMENT"


def live_collection_decision(endpoint: str, deployment: str,
                             probe_error: str | None) -> tuple[str, str]:
    """`(SKIP | RUN | FAIL, reason)` for the live Foundry test.

    The same three-way split as `tests/dbharness.collection_decision`, and for
    the same reason: "I asked for the real service and it silently did not run"
    is the one outcome that must be red, because a green run with a skip in it
    is what a pipeline reads as proof.
    """
    if not endpoint.strip():
        return SKIP, (f"no live Azure target ({ENDPOINT_ENV} is not set); set {ENDPOINT_ENV} "
                      f"and {DEPLOYMENT_ENV} to run the real-inference test")
    if not deployment.strip():
        return FAIL, (f"{ENDPOINT_ENV} is set but {DEPLOYMENT_ENV} is not. A deployment name "
                      f"is not guessable -- guessing one yields DeploymentNotFound, which "
                      f"reads like a product bug rather than a missing variable.")
    if probe_error:
        return FAIL, (
            f"{ENDPOINT_ENV} is set but no credential could be obtained for "
            f"{settings.AZURE_AI_SCOPE}: {probe_error}. This is the only test that calls a "
            f"real model, so it is a hard failure rather than a skip -- a run that was asked "
            f"for real inference and did not get it has proved nothing. Unset {ENDPOINT_ENV} "
            f"to run offline, or `az login`.")
    return RUN, "the live Foundry test is running against a real deployment"


@pytest.mark.parametrize("endpoint, deployment, probe, expected", [
    ("", "", None, SKIP),                        # the documented offline default
    ("  ", "Mistral-Large-3", None, SKIP),       # whitespace is unset
    ("https://a/", "", None, FAIL),              # asked for it, half configured
    ("https://a/", "Mistral-Large-3", "CredentialUnavailableError: az login", FAIL),
    ("https://a/", "Mistral-Large-3", None, RUN),
])
def test_the_live_gate_fails_loudly_when_it_was_asked_for(
        endpoint: str, deployment: str, probe: str | None, expected: str) -> None:
    """The gate itself, offline. Without this the FAIL branch is code nobody has
    ever executed, which is exactly the branch that has to work."""
    assert live_collection_decision(endpoint, deployment, probe)[0] == expected


def _live_probe(client_id: str | None) -> str | None:
    """Ask for one real data-plane token; return why not if it fails."""
    try:
        llm._azure_credential(client_id).get_token(settings.AZURE_AI_SCOPE)
        return None
    except Exception as exc:                       # any failure is the gate's input
        return f"{type(exc).__name__}: {exc}"


_LIVE_ENDPOINT = os.environ.get(ENDPOINT_ENV, "").strip()
_LIVE_DEPLOYMENT = os.environ.get(DEPLOYMENT_ENV, "").strip()
_LIVE_DECISION, _LIVE_REASON = live_collection_decision(
    _LIVE_ENDPOINT, _LIVE_DEPLOYMENT,
    _live_probe(None) if (_LIVE_ENDPOINT and _LIVE_DEPLOYMENT) else None)

if _LIVE_DECISION == FAIL:
    # Fails COLLECTION, like test_db_governance.py. A skip here would exit 0 on
    # a run that believed it had proved the provider works against the real
    # service.
    raise RuntimeError(_LIVE_REASON)


@pytest.mark.live
@pytest.mark.skipif(_LIVE_DECISION == SKIP, reason=_LIVE_REASON)
def test_live_completion_against_a_real_foundry_deployment(
        monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    """One real completion, on a real deployment, with a real managed-identity
    token -- the only assertion in this file that the protocol choice in
    `client.py`'s docstring is still true.

    It asks for JSON, because `expect_json` is what the whole advisory layer
    depends on and a provider that cannot produce parseable structure is not
    usable here no matter how well it chats.
    """
    monkeypatch.setattr(settings, "ADVISORY_PROVIDER", "azure")
    monkeypatch.setattr(settings, "AZURE_AI_ENDPOINT", _LIVE_ENDPOINT)
    monkeypatch.setattr(settings, "AZURE_AI_DEPLOYMENT", _LIVE_DEPLOYMENT)
    monkeypatch.setattr(settings, "AZURE_AI_API_VERSION", ai_config.DEFAULT_AZURE_API_VERSION)
    monkeypatch.setattr(settings, "AZURE_AI_AUTH_MODE", "identity")
    monkeypatch.setattr(settings, "AZURE_AI_CLIENT_ID", "")
    ai_config.invalidate()

    res = llm.complete(
        provider="azure", expect_json=True, timeout=90.0, capability="live-check",
        system=("You are a firewall policy reviewer. Answer only with a JSON object having "
                'the keys "verdict" (one of "allow", "deny") and "reason" (one short string).'),
        user="A rule permits 0.0.0.0/0 to reach tcp/22 on a PCI database host. Verdict?")

    with capsys.disabled():
        print(f"\n  LIVE {_LIVE_ENDPOINT} deployment={_LIVE_DEPLOYMENT}\n"
              f"       ok={res.ok} provider={res.provider} model={res.model}\n"
              f"       finish_reason={res.finish_reason} json_mode={res.json_mode} "
              f"tokens={res.prompt_tokens}/{res.completion_tokens}\n"
              f"       error={res.error}\n"
              f"       text={res.text!r}")

    assert res.ok is True, res.error
    assert res.provider == "azure" and res.model == _LIVE_DEPLOYMENT
    assert res.finish_reason == "stop"
    assert res.completion_tokens > 0
    # Structure, not vibes: the advisory layer parses this, so the test does too.
    parsed = llm.parse_json(res.text, None)
    assert isinstance(parsed, dict), f"not JSON: {res.text!r}"
    assert parsed.get("verdict") in ("allow", "deny"), parsed


@pytest.mark.live
@pytest.mark.skipif(_LIVE_DECISION == SKIP, reason=_LIVE_REASON)
def test_live_provider_status_sees_the_real_credential(
        monkeypatch: pytest.MonkeyPatch) -> None:
    """`provider_status()` against the real thing, with a real token behind it,
    and with a budget long enough for a cold credential chain (the default 2s is
    sized for a warm one on the health path, not for a first `az` subprocess)."""
    monkeypatch.setattr(settings, "ADVISORY_PROVIDER", "azure")
    monkeypatch.setattr(settings, "AZURE_AI_ENDPOINT", _LIVE_ENDPOINT)
    monkeypatch.setattr(settings, "AZURE_AI_DEPLOYMENT", _LIVE_DEPLOYMENT)
    monkeypatch.setattr(settings, "AZURE_AI_AUTH_MODE", "identity")
    monkeypatch.setattr(settings, "AZURE_AI_CLIENT_ID", "")
    ai_config.invalidate()
    assert llm.azure_credential_state("identity", None, budget=30.0)[0] is True

    az = llm.provider_status()["azure"]
    assert az["ready"] is True and az["credential_ok"] is True
    assert az["deployment"] == _LIVE_DEPLOYMENT


@pytest.mark.live
@pytest.mark.skipif(_LIVE_DECISION == SKIP, reason=_LIVE_REASON)
@pytest.mark.skipif(not settings.AZURE_AI_API_KEY,
                    reason=("AZURE_AI_API_KEY is not set, so the live KEY-mode path cannot be "
                            "exercised; identity mode is the one that matters in Container "
                            "Apps and is covered above"))
def test_live_key_mode_completion_against_a_real_foundry_deployment(
        monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    """The manual escape hatch, against the real account.

    Gated on the secret being where the design says it lives -- this process's
    environment -- rather than on a test-only variable, because a key-mode test
    that read the key from somewhere else would be proving a path the product
    does not have.
    """
    monkeypatch.setattr(settings, "ADVISORY_PROVIDER", "azure")
    monkeypatch.setattr(settings, "AZURE_AI_ENDPOINT", _LIVE_ENDPOINT)
    monkeypatch.setattr(settings, "AZURE_AI_DEPLOYMENT", _LIVE_DEPLOYMENT)
    monkeypatch.setattr(settings, "AZURE_AI_AUTH_MODE", "key")
    monkeypatch.setattr(settings, "AZURE_AI_CLIENT_ID", "")
    ai_config.invalidate()

    res = llm.complete(provider="azure", expect_json=True, timeout=90.0,
                       capability="live-check-key",
                       system="Answer only with a JSON object having the key \"auth\".",
                       user='Return {"auth": "key"}.')

    with capsys.disabled():
        print(f"\n  LIVE key-mode ok={res.ok} model={res.model} "
              f"finish_reason={res.finish_reason} json_mode={res.json_mode} "
              f"tokens={res.prompt_tokens}/{res.completion_tokens}\n"
              f"       error={res.error}\n       text={res.text!r}")

    assert res.ok is True, res.error
    assert llm.parse_json(res.text, None) is not None
