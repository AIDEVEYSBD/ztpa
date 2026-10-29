"""The Google Vertex AI provider: what it sends, and what it refuses to believe.

Offline. Like test_advisory_azure.py, these drive the REAL `openai.OpenAI`
client over an `httpx.MockTransport`, so the URL, the bearer header and the
JSON mode are the SDK's own wire and not a stub's. ADC is faked at
`google.auth.default`, so no test reaches the real credential chain.
"""

from __future__ import annotations

import json
from typing import Any

import httpx
import pytest

from src import ai_config, settings
from src.advisory import client as llm


class FakeCredentials:
    """The slice of a google-auth credential `_vertex_credentials` touches."""

    def __init__(self, tokens: list[str]) -> None:
        self._tokens = tokens
        self.token: str | None = None
        self.valid = False
        self.refreshes = 0

    def refresh(self, _request: Any) -> None:
        self.token = self._tokens[min(self.refreshes, len(self._tokens) - 1)]
        self.refreshes += 1
        self.valid = True


def body(content: str, finish: str = "stop") -> dict[str, Any]:
    return {"id": "c", "object": "chat.completion", "created": 0, "model": "google/gemini-2.5-flash",
            "choices": [{"index": 0, "finish_reason": finish,
                         "message": {"role": "assistant", "content": content}}],
            "usage": {"prompt_tokens": 7, "completion_tokens": 3, "total_tokens": 10}}


@pytest.fixture(autouse=True)
def _clean(monkeypatch: pytest.MonkeyPatch):
    llm.reset_vertex_caches()
    monkeypatch.setattr(settings, "VERTEX_PROJECT", "")
    monkeypatch.setattr(settings, "VERTEX_LOCATION", "global")
    monkeypatch.setattr(settings, "VERTEX_MODEL", "google/gemini-2.5-flash")
    monkeypatch.setattr(llm, "record_metric", lambda **_k: None)
    yield
    llm.reset_vertex_caches()


@pytest.fixture()
def adc(monkeypatch: pytest.MonkeyPatch):
    import google.auth

    creds = FakeCredentials(["tok-1", "tok-2"])
    monkeypatch.setattr(google.auth, "default", lambda scopes=None: (creds, "adc-project"))
    return creds


@pytest.fixture()
def wire(monkeypatch: pytest.MonkeyPatch):
    import openai

    seen: list[httpx.Request] = []
    replies: list[dict[str, Any]] = []

    def handle(request: httpx.Request) -> httpx.Response:
        request.read()
        seen.append(request)
        return httpx.Response(200, json=replies[min(len(seen) - 1, len(replies) - 1)])

    real = openai.OpenAI

    class Recorded(real):  # type: ignore[misc, valid-type]
        def __init__(self, **kw: Any) -> None:
            super().__init__(http_client=httpx.Client(transport=httpx.MockTransport(handle)), **kw)

    monkeypatch.setattr(openai, "OpenAI", Recorded)
    return seen, replies


def test_vertex_is_an_explicit_provider_that_the_store_accepts() -> None:
    assert "vertex" in settings.EXPLICIT_PROVIDERS
    assert "vertex" in ai_config.PROVIDERS
    assert ai_config.validate(ai_config.AiConfig(provider="vertex")).provider == "vertex"


@pytest.fixture()
def auto_nothing_else(monkeypatch: pytest.MonkeyPatch):
    """`auto`, with no local model, no Azure target and no BYOK key."""
    monkeypatch.setattr(settings, "ADVISORY_PROVIDER", "auto")
    monkeypatch.setattr(settings, "ollama_available", lambda: False)
    monkeypatch.setattr(settings, "OPENAI_API_KEY", "")
    monkeypatch.setattr(settings, "ANTHROPIC_API_KEY", "")
    monkeypatch.setattr(settings, "AZURE_AI_ENDPOINT", "")
    monkeypatch.setattr(settings, "AZURE_AI_DEPLOYMENT", "")
    monkeypatch.setattr(ai_config, "stored", lambda: ai_config.AiConfig())
    ai_config.invalidate()
    yield
    ai_config.invalidate()


def test_auto_never_routes_to_vertex_off_gcp(monkeypatch: pytest.MonkeyPatch, adc,
                                             auto_nothing_else) -> None:
    """ADC exists on every machine with gcloud; auto must not treat that as consent."""
    monkeypatch.setattr(settings, "NPR_PLATFORM", "local")
    assert settings.active_provider() != "vertex"


def test_on_cloud_run_auto_prefers_the_native_vertex(monkeypatch: pytest.MonkeyPatch, adc,
                                                     auto_nothing_else) -> None:
    monkeypatch.setattr(settings, "NPR_PLATFORM", "auto")
    monkeypatch.setenv("K_SERVICE", "frr-backend")
    monkeypatch.delenv("CONTAINER_APP_NAME", raising=False)
    monkeypatch.setattr(settings, "OPENAI_API_KEY", "sk-byok")   # native still wins
    assert settings.platform() == "gcp"
    assert settings.active_provider() == "vertex"


def test_on_gcp_without_a_usable_vertex_auto_falls_back_to_a_byok_key(
        monkeypatch: pytest.MonkeyPatch, auto_nothing_else) -> None:
    import google.auth
    from google.auth.exceptions import DefaultCredentialsError

    def none(scopes=None):
        raise DefaultCredentialsError("no ADC")

    monkeypatch.setattr(google.auth, "default", none)
    monkeypatch.setattr(settings, "NPR_PLATFORM", "gcp")
    monkeypatch.setattr(settings, "OPENAI_API_KEY", "sk-byok")
    assert settings.active_provider() == "openai"


def test_container_apps_is_detected_as_azure(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "NPR_PLATFORM", "auto")
    monkeypatch.delenv("K_SERVICE", raising=False)
    monkeypatch.delenv("CLOUD_RUN_JOB", raising=False)
    monkeypatch.setenv("CONTAINER_APP_NAME", "frr-backend")
    assert settings.platform() == "azure"


def test_byok_reports_key_names_never_values(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-secret")
    names = settings.byok_keys()
    assert "ANTHROPIC_API_KEY" in names and "sk-ant-secret" not in repr(names)


@pytest.mark.parametrize("location, host", [
    ("global", "https://aiplatform.googleapis.com/"),
    ("europe-west4", "https://europe-west4-aiplatform.googleapis.com/"),
])
def test_the_request_lands_on_the_projects_openai_endpoint_with_a_bearer_token(
        monkeypatch: pytest.MonkeyPatch, adc, wire, location: str, host: str) -> None:
    seen, replies = wire
    replies.append(body('{"ok": true}'))
    monkeypatch.setattr(settings, "VERTEX_LOCATION", location)
    res = llm.complete(system="s", user="u", provider="vertex", expect_json=True)
    assert res.ok and res.provider == "vertex" and res.json_mode == "native"
    req = seen[0]
    assert str(req.url) == (f"{host}v1/projects/adc-project/locations/{location}"
                            f"/endpoints/openapi/chat/completions")
    assert req.headers["authorization"] == "Bearer tok-1"
    sent = json.loads(req.content)
    assert sent["model"] == "google/gemini-2.5-flash"
    assert sent["response_format"] == {"type": "json_object"}


def test_an_explicit_project_wins_over_the_adc_project(monkeypatch: pytest.MonkeyPatch, adc, wire) -> None:
    seen, replies = wire
    replies.append(body("hi"))
    monkeypatch.setattr(settings, "VERTEX_PROJECT", "chosen-project")
    assert llm.complete(system="s", user="u", provider="vertex").ok
    assert "/projects/chosen-project/" in str(seen[0].url)


def test_a_refreshed_token_rebuilds_the_client(adc, wire) -> None:
    seen, replies = wire
    replies.append(body("hi"))
    llm.complete(system="s", user="u", provider="vertex")
    adc.valid = False                       # the hour is up
    llm.complete(system="s", user="u", provider="vertex")
    assert [r.headers["authorization"] for r in seen] == ["Bearer tok-1", "Bearer tok-2"]


@pytest.mark.parametrize("content, finish", [("half an ans", "length"), ("", "content_filter"), ("", "stop")])
def test_a_truncated_filtered_or_empty_answer_is_not_believed(adc, wire, content: str, finish: str) -> None:
    _seen, replies = wire
    replies.append(body(content, finish))
    res = llm.complete(system="s", user="u", provider="vertex")
    assert res.ok is False and res.text == ""
    assert res.prompt_tokens == 7                # it still cost money


def test_missing_adc_degrades_with_the_reason(monkeypatch: pytest.MonkeyPatch) -> None:
    import google.auth
    from google.auth.exceptions import DefaultCredentialsError

    def none(scopes=None):
        raise DefaultCredentialsError("Your default credentials were not found.")

    monkeypatch.setattr(google.auth, "default", none)
    res = llm.complete(system="s", user="u", provider="vertex")
    assert res.ok is False and "DefaultCredentialsError" in (res.error or "")
    assert llm.vertex_ready()[0] is False


def test_a_missing_credential_is_not_reprobed_on_every_call(monkeypatch: pytest.MonkeyPatch) -> None:
    """On GCP `auto` asks per model call; a slow metadata probe must not be paid each time."""
    import google.auth
    from google.auth.exceptions import DefaultCredentialsError

    calls = []

    def none(scopes=None):
        calls.append(1)
        raise DefaultCredentialsError("no ADC")

    monkeypatch.setattr(google.auth, "default", none)
    for _ in range(50):
        assert llm.vertex_ready()[0] is False
    assert len(calls) == 1


# --- BYOK: a service-account key given as content -------------------------
# Secret Manager and Key Vault inject a secret as an environment variable, so a
# key reaches the process as its JSON, not as a file path.

def _sa_key(project: str = "byok-project") -> str:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    pem = rsa.generate_private_key(public_exponent=65537, key_size=2048).private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()).decode()
    return json.dumps({"type": "service_account", "project_id": project, "private_key_id": "k1",
                       "private_key": pem, "client_email": f"frr@{project}.iam.gserviceaccount.com",
                       "client_id": "1", "token_uri": "https://oauth2.googleapis.com/token"})


@pytest.fixture()
def key_refresh(monkeypatch: pytest.MonkeyPatch):
    """No network: a key credential's refresh just sets a token."""
    import google.auth
    from google.oauth2 import service_account

    def refresh(self, _request):
        self.token = "key-token"
        self.expiry = None                                             # google-auth: no expiry = valid
    monkeypatch.setattr(service_account.Credentials, "refresh", refresh)

    def no_adc(*_a, **_k):
        raise AssertionError("ADC must not be consulted when a key is given")
    monkeypatch.setattr(google.auth, "default", no_adc)
    monkeypatch.delenv("GOOGLE_APPLICATION_CREDENTIALS", raising=False)
    monkeypatch.delenv("GOOGLE_APPLICATION_CREDENTIALS_JSON", raising=False)


def test_a_key_given_as_content_is_used_with_its_project(monkeypatch, key_refresh) -> None:
    monkeypatch.setenv("GOOGLE_APPLICATION_CREDENTIALS_JSON", _sa_key())
    creds, project = llm._vertex_credentials()
    assert project == "byok-project" and creds.token == "key-token"
    assert "GOOGLE_APPLICATION_CREDENTIALS_JSON" in settings.byok_keys()


def test_json_in_the_path_variable_is_read_as_content(monkeypatch, key_refresh) -> None:
    monkeypatch.setenv("GOOGLE_APPLICATION_CREDENTIALS", _sa_key("from-gac"))
    assert llm._vertex_credentials()[1] == "from-gac"


def test_a_path_still_goes_through_adc(monkeypatch, adc) -> None:
    monkeypatch.delenv("GOOGLE_APPLICATION_CREDENTIALS_JSON", raising=False)
    monkeypatch.setenv("GOOGLE_APPLICATION_CREDENTIALS", "/secrets/key.json")
    assert settings.vertex_key_json() == ""
    assert llm._vertex_credentials()[1] == "adc-project"


@pytest.mark.parametrize("raw,why", [
    ('{"type": "service_account", "private_key": "SECRET-MATERIAL', "not valid JSON"),
    ('{"type": "authorized_user", "refresh_token": "SECRET-MATERIAL"}', "service-account key"),
    ('{"type": "service_account", "private_key": "SECRET-MATERIAL"}', "incomplete"),
])
def test_a_bad_key_is_refused_without_echoing_it(monkeypatch, key_refresh, raw, why) -> None:
    monkeypatch.setenv("GOOGLE_APPLICATION_CREDENTIALS_JSON", raw)
    ok, reason = llm.vertex_ready()
    assert not ok and why in reason and "SECRET-MATERIAL" not in reason


def test_off_gcp_auto_uses_a_provided_key_but_never_a_bare_login(monkeypatch, adc, auto_nothing_else) -> None:
    monkeypatch.setattr(settings, "NPR_PLATFORM", "local")
    monkeypatch.delenv("GOOGLE_APPLICATION_CREDENTIALS_JSON", raising=False)
    monkeypatch.delenv("GOOGLE_APPLICATION_CREDENTIALS", raising=False)
    assert settings.active_provider() != "vertex"                     # ADC alone is not consent
    from google.oauth2 import service_account
    monkeypatch.setattr(service_account.Credentials, "refresh",
                        lambda self, _r: setattr(self, "token", "t") or setattr(self, "expiry", None))
    monkeypatch.setenv("GOOGLE_APPLICATION_CREDENTIALS_JSON", _sa_key())
    llm.reset_vertex_caches()
    ai_config.invalidate()
    assert settings.active_provider() == "vertex"
