"""Azure resource discovery and the AI-configuration admin API.

WHAT THIS FILE IS DEFENDING, AND WHY IT IS THE SAME DEFECT TWICE
---------------------------------------------------------------
The Configuration page exists so that pointing this product at a customer's own
Azure AI Foundry deployment is three dropdowns instead of three environment
variables typed from memory. Filling those dropdowns means asking Azure Resource
Manager, on a request path, with an identity that may not be allowed to ask --
and the failure mode of that is exactly the failure mode this whole codebase's
remediation has been about:

    an empty dropdown that means "this app has no permission to look"
    is indistinguishable, on screen, from
    an empty dropdown that means "you own no Foundry accounts".

The first sentence is a bug in the deployment and is fixed by granting a role.
The second is a fact about the customer's estate and is fixed by creating a
resource. An operator who reads the second when the first is true goes and
creates something they already own. So the central assertion here is not "the
happy path parses" -- it is that EVERY way of failing to look produces a typed
error and never `[]`, and the tests below enumerate those ways: no credential,
no Reader role, a rejected token, a timeout, an unreachable ARM, a 200 whose
body is not the shape ARM documents, and no visible subscription at all.

The second half of the file is the same argument applied to `/api/admin/ai/test`.
That button's whole job is to tell an operator their configuration works, so the
one thing it must never do is pass on a configuration that would fail in use.
Three ways it could, and does not: a provider the advisory client does not
implement falls through to Ollama and answers `ok=True` from a completely
different model (`test_a_provider_substitution_is_reported_as_a_failure`); a
reasoning deployment returns HTTP 200 with an empty `content`
(`test_an_empty_completion_is_not_a_pass`); and a form the operator has not
saved would be silently ignored in favour of the stored row
(`test_testing_unsaved_values_is_refused_rather_than_answered_about_the_row`).

Nothing here opens a socket except the one live test at the bottom, which is
marked `@pytest.mark.live` and is therefore OPT-IN: `backend/conftest.py` skips
it at collection unless `NPR_RUN_LIVE=1`, and blocks non-loopback `connect` for
everything else, so the default `pytest` run cannot reach Azure even by mistake.
It used to be opt-OUT, which made a green suite a claim about somebody else's
resource group -- see `tests/livegate.py` for what that cost.

The rest replaces `azure_arm._http_client` with an `httpx.MockTransport`, which
means the parsing, pagination, filtering, bounding and error mapping under test
are the real code rather than a re-implementation of it.
"""

from __future__ import annotations

import ast
import inspect
import json
import textwrap

import httpx
import pytest
from fastapi.testclient import TestClient

from app import main
from src import ai_config, azure_arm, settings
from tests import livegate

# --- identities ------------------------------------------------------------
VIEWER = {"x-npr-role": "viewer", "x-npr-email": "auditor@example.com"}
ANALYST = {"x-npr-role": "analyst", "x-npr-email": "analyst@example.com"}
ADMIN = {"x-npr-role": "admin", "x-npr-email": "admin@example.com"}

# The live subscription this feature was built against. Used as a well-formed
# GUID in the stubs, and for real in the live test at the bottom.
SUBSCRIPTION = "5d4c70ac-de53-4f3b-9a20-62ce17561c9f"
LIVE_RESOURCE_GROUP = "Foundry-RG"
LIVE_ACCOUNT = "api-endpoint-inference-resource"
LIVE_DEPLOYMENTS = ("Kimi-K2.7-Code", "Mistral-Large-3")


# --- ARM fixtures ----------------------------------------------------------
# Trimmed from the ACTUAL responses of the live account, not invented: the
# account whose resource group is `centralindia` while the account itself is
# `southindia`, the deployment whose model version is a date, the `sku.name` of
# `GlobalStandard`. A stub built from imagination tests the imagination.

_SUBSCRIPTIONS = {"value": [
    {"subscriptionId": SUBSCRIPTION, "displayName": "F-S-CONSULTING-SBP10F", "state": "Enabled",
     "id": f"/subscriptions/{SUBSCRIPTION}"},
]}

_RESOURCE_GROUPS = {"value": [
    {"id": f"/subscriptions/{SUBSCRIPTION}/resourceGroups/npr-demo-rg",
     "name": "npr-demo-rg", "location": "centralindia"},
    {"id": f"/subscriptions/{SUBSCRIPTION}/resourceGroups/{LIVE_RESOURCE_GROUP}",
     "name": LIVE_RESOURCE_GROUP, "location": "centralindia"},
]}

# Four Cognitive Services accounts in one resource group, of which TWO can serve
# a chat completion. The other two are the point of the filter: a Speech and a
# Vision resource both have a name, an endpoint and a location, so an unfiltered
# list looks like a perfectly good model dropdown right up until somebody picks
# one.
_ACCOUNTS = {"value": [
    {"name": LIVE_ACCOUNT, "kind": "AIServices", "location": "southindia",
     "properties": {"endpoint": f"https://{LIVE_ACCOUNT}.cognitiveservices.azure.com/",
                    "provisioningState": "Succeeded"}},
    {"name": "npr-speech", "kind": "SpeechServices", "location": "centralindia",
     "properties": {"endpoint": "https://npr-speech.cognitiveservices.azure.com/",
                    "provisioningState": "Succeeded"}},
    {"name": "npr-vision", "kind": "ComputerVision", "location": "centralindia",
     "properties": {"endpoint": "https://npr-vision.cognitiveservices.azure.com/",
                    "provisioningState": "Succeeded"}},
    {"name": "legacy-openai", "kind": "OpenAI", "location": "eastus",
     "properties": {"endpoint": "https://legacy-openai.openai.azure.com/",
                    "provisioningState": "Succeeded"}},
]}

_DEPLOYMENTS = {"value": [
    {"name": "Kimi-K2.7-Code",
     "properties": {"model": {"format": "MoonshotAI", "name": "Kimi-K2.7-Code",
                              "version": "2026-06-12"},
                    "capabilities": {"chatCompletion": "true"},
                    "provisioningState": "Succeeded"},
     "sku": {"name": "GlobalStandard", "capacity": 100}},
    {"name": "Mistral-Large-3",
     "properties": {"model": {"format": "Mistral AI", "name": "Mistral-Large-3", "version": "1"},
                    "capabilities": {"chatCompletion": "true"},
                    "provisioningState": "Succeeded"},
     "sku": {"name": "GlobalStandard", "capacity": 1000}},
]}

# ARM's real 403 body. The `message` names the exact action and scope that were
# refused, which is the single most useful string in a discovery failure and the
# reason `ArmError.detail` exists at all.
_AUTHORIZATION_FAILED = {"error": {
    "code": "AuthorizationFailed",
    "message": ("The client 'cf31bca1-7a3d-4bb9-9c62-5b18f7667c04' with object id "
                "'cf31bca1-7a3d-4bb9-9c62-5b18f7667c04' does not have authorization to perform "
                "action 'Microsoft.Resources/subscriptions/resourcegroups/read' over scope "
                f"'/subscriptions/{SUBSCRIPTION}'."),
}}


def _executable_body(fn) -> str:
    """`fn`'s source with its docstring and every comment removed.

    A source-level assertion about what a function DOES has to read only what
    runs. This codebase documents each function at length -- `list_deployments`
    explains the deployment-name-vs-model-name trap using `gpt4o-prod` as the
    worked example -- so a substring scan over `inspect.getsource` flags the
    explanation and is unusable. `ast.unparse` drops comments by construction;
    the docstring is dropped explicitly.
    """
    node = ast.parse(textwrap.dedent(inspect.getsource(fn))).body[0]
    body = getattr(node, "body", [])
    if (body and isinstance(body[0], ast.Expr)
            and isinstance(body[0].value, ast.Constant)
            and isinstance(body[0].value.value, str)):
        node.body = body[1:]
    return ast.unparse(node)


def _arm_transport(*, subscriptions=_SUBSCRIPTIONS, resource_groups=_RESOURCE_GROUPS,
                   accounts=_ACCOUNTS, deployments=_DEPLOYMENTS, calls=None):
    """An `httpx.MockTransport` handler that speaks ARM's four list endpoints.

    Each argument may be a body dict OR an `httpx.Response` (or a callable
    returning one), so a test can replace exactly one listing with a 403, a
    timeout or a malformed body while the rest keep working -- which is what
    makes "this endpoint failed and did not answer []" a statement about one
    route rather than about the whole stub.
    """
    def _answer(spec, request):
        if callable(spec):
            return spec(request)
        if isinstance(spec, httpx.Response):
            return spec
        return httpx.Response(200, json=spec)

    def handler(request: httpx.Request) -> httpx.Response:
        if calls is not None:
            calls.append(request)
        # Every ARM call must be authenticated; a stub that answers an
        # unauthenticated request would hide a missing header forever.
        assert request.headers.get("Authorization", "").startswith("Bearer "), request.url
        path = request.url.path
        if path == "/subscriptions":
            return _answer(subscriptions, request)
        if path.endswith("/resourcegroups"):
            return _answer(resource_groups, request)
        if path.endswith("/providers/Microsoft.CognitiveServices/accounts"):
            return _answer(accounts, request)
        if path.endswith("/deployments"):
            return _answer(deployments, request)
        return httpx.Response(404, json={"error": {"code": "NotFound", "message": path}})

    return handler


@pytest.fixture(autouse=True)
def _no_cached_azure_state(monkeypatch):
    """Every test starts with no cached credential, token or configuration.

    All three are process-global caches with 30s-to-an-hour lifetimes, so
    without this a test that stubs a failing credential would be served the
    previous test's working token -- and, worse, the LIVE test at the bottom
    would leave a real bearer token in `_TOKENS` for the stubbed tests to reuse.
    """
    azure_arm.reset_credentials()
    ai_config.invalidate()
    monkeypatch.setattr(azure_arm.settings, "AZURE_SUBSCRIPTION_ID", "")
    yield
    azure_arm.reset_credentials()
    ai_config.invalidate()


@pytest.fixture
def client(monkeypatch):
    # No `with`: entering the context manager runs the lifespan, which starts a
    # real engine build in a background thread. Same reasoning as
    # test_api_authz.py's client fixture; none of these routes touch the engine.
    monkeypatch.delenv("NPR_PROXY_SECRET", raising=False)
    return TestClient(main.app)


@pytest.fixture
def arm(monkeypatch):
    """Wire `azure_arm` to a stub ARM and a stub token.

    Returns a `configure(**kwargs)` callable so a test can install a different
    ARM behaviour after the fixture is set up. The token is stubbed rather than
    the credential so that the credential-failure tests below can exercise the
    real `_token` path.
    """
    monkeypatch.setattr(azure_arm, "_token", lambda *_a, **_kw: "stub-token")

    def configure(**kwargs):
        calls: list[httpx.Request] = kwargs.pop("calls", None) or []
        handler = _arm_transport(calls=calls, **kwargs)
        monkeypatch.setattr(azure_arm, "_http_client",
                            lambda: httpx.Client(transport=httpx.MockTransport(handler),
                                                 timeout=azure_arm.ARM_TIMEOUT))
        return calls

    configure()
    return configure


# --------------------------------------------------------------------------
# 1. authorization
# --------------------------------------------------------------------------
# Every route added for the Configuration page, with a body where one is needed.
# Discovery ENUMERATES THE CUSTOMER'S CLOUD ESTATE -- a list of resource group
# names is an inventory of what they run and roughly where -- and /api/admin/ai/test
# spends model tokens on demand. The round-2 audit's finding was routes that
# write state or spend money reachable by a viewer; both halves apply here, so
# both halves are asserted rather than assumed.

ADMIN_ROUTES = [
    ("GET", "/api/admin/azure/subscriptions", None),
    ("GET", "/api/admin/azure/resource-groups", None),
    ("GET", f"/api/admin/azure/accounts?resource_group={LIVE_RESOURCE_GROUP}", None),
    ("GET", f"/api/admin/azure/deployments?resource_group={LIVE_RESOURCE_GROUP}"
            f"&account={LIVE_ACCOUNT}", None),
    ("GET", "/api/admin/ai/config", None),
    ("PUT", "/api/admin/ai/config", {"provider": "ollama"}),
    ("POST", "/api/admin/ai/test", None),
]
_IDS = [f"{m}:{p.split('?')[0]}" for m, p, _b in ADMIN_ROUTES]


@pytest.fixture
def savable(monkeypatch):
    """Make the configuration store writable without a database.

    The offline suite blanks DATABASE_URL (backend/conftest.py), so `save()`
    would raise `AiConfigUnavailable` -> 503 and the "admin is admitted" half of
    the authorization test could not tell a working guard from a broken store.
    """
    saved: dict = {}

    def _save(cfg, actor=None):
        stored = ai_config.validate(cfg)
        saved["cfg"], saved["actor"] = stored, actor
        return ai_config.replace(stored, source=ai_config.SOURCE_DATABASE,
                                 configured_by=actor)

    monkeypatch.setattr(ai_config, "save", _save)
    return saved


@pytest.fixture
def stub_llm(monkeypatch):
    """Replace the advisory client's `complete` with a recorder.

    /api/admin/ai/test makes a REAL model call by design, so every test of it
    other than the live one has to stub the call -- and stubbing it at
    `main.llm_client` (the name main.py looks the function up through) is what
    makes the substitution check below observable.
    """
    calls: list[dict] = []
    answer = {"text": "ok", "ok": True, "error": None, "provider": None, "model": "stub-model"}

    def _complete(**kwargs):
        calls.append(kwargs)
        provider = answer["provider"] or kwargs.get("provider") or "ollama"
        return main.llm_client.LLMResponse(
            text=answer["text"], provider=provider, model=answer["model"],
            ok=answer["ok"], error=answer["error"])

    monkeypatch.setattr(main.llm_client, "complete", _complete)
    return {"calls": calls, "answer": answer}


@pytest.mark.parametrize(("method", "path", "body"), ADMIN_ROUTES, ids=_IDS)
def test_a_viewer_is_refused_every_configuration_route(client, arm, method, path, body):
    """`x-npr-role: viewer` -- the role an auditor is given -- gets 403 from all of
    them. A viewer reads findings; a viewer does not enumerate the tenant."""
    r = client.request(method, path, json=body, headers=VIEWER)
    assert r.status_code == 403, f"{method} {path} answered {r.status_code}: {r.text[:200]}"
    assert r.json()["detail"] == "admin only"


@pytest.mark.parametrize(("method", "path", "body"), ADMIN_ROUTES, ids=_IDS)
def test_an_analyst_is_refused_every_configuration_route(client, arm, method, path, body):
    """Not only the viewer. An analyst may approve a firewall change and still may
    not repoint the product's model provider or read the cloud inventory: these
    are `require_admin`, not `require_approver`, and the difference is worth
    asserting because a guard is easy to widen by accident."""
    r = client.request(method, path, json=body, headers=ANALYST)
    assert r.status_code == 403, f"{method} {path} answered {r.status_code}: {r.text[:200]}"


@pytest.mark.parametrize(("method", "path", "body"), ADMIN_ROUTES, ids=_IDS)
def test_the_guard_admits_an_admin(client, arm, savable, stub_llm, method, path, body):
    """The other half: each guard lets an admin through to a real answer. A guard
    that 403s everybody would pass the two tests above and ship a dead page."""
    r = client.request(method, path, json=body, headers=ADMIN)
    assert r.status_code == 200, f"{method} {path} answered {r.status_code}: {r.text[:300]}"


def test_every_configuration_route_carries_the_admin_dependency():
    """Guard the guard, reflectively -- the idiom test_api_authz.py uses.

    The parametrised tests above only cover the routes somebody remembered to
    list. This one reads the live routing table, so a fifth discovery endpoint
    added later without `Depends(require_admin)` fails here even if nobody adds
    it to `ADMIN_ROUTES`."""
    unguarded = []
    for route in main.app.routes:
        path = getattr(route, "path", "")
        if not (path.startswith("/api/admin/azure/") or path.startswith("/api/admin/ai/")):
            continue
        guards = {d.call for d in route.dependant.dependencies}
        if main.require_admin not in guards:
            unguarded.append(f"{sorted(route.methods)} {path}")
    assert not unguarded, f"configuration routes with no admin guard: {unguarded}"
    # ...and the scan is not matching nothing, which is how a reflective check
    # passes by seeing no routes at all.
    assert len([r for r in main.app.routes
                if getattr(r, "path", "").startswith("/api/admin/azure/")]) >= 4


# --------------------------------------------------------------------------
# 2. the central rule: a failure to look is never an empty list
# --------------------------------------------------------------------------

DISCOVERY_PATHS = [
    "/api/admin/azure/subscriptions",
    "/api/admin/azure/resource-groups",
    f"/api/admin/azure/accounts?resource_group={LIVE_RESOURCE_GROUP}",
    f"/api/admin/azure/deployments?resource_group={LIVE_RESOURCE_GROUP}&account={LIVE_ACCOUNT}",
]
_DPATH_IDS = [p.split("?")[0].rsplit("/", 1)[-1] for p in DISCOVERY_PATHS]


class _DeadCredential:
    """A credential whose chain produced nothing -- no managed identity in the
    container, no `az login` on the laptop. Exactly what a fresh deployment with
    no identity attached looks like."""

    def get_token(self, *_scopes, **_kwargs):
        from azure.identity import CredentialUnavailableError

        raise CredentialUnavailableError(
            "DefaultAzureCredential failed to retrieve a token from the included credentials.")


@pytest.mark.parametrize("path", DISCOVERY_PATHS, ids=_DPATH_IDS)
def test_a_missing_credential_is_a_typed_error_and_not_an_empty_list(client, monkeypatch, path):
    """THE CENTRAL ASSERTION OF THIS FILE.

    With no credential, every discovery endpoint answers 503 with
    `code: "azure_credential_unavailable"` and a sentence saying the lists are
    UNKNOWN. The negative half is asserted explicitly and matters more than the
    positive one: the body must not be a list, and in particular must not be
    `[]`. An operator handed an empty dropdown reads "you own no Foundry
    accounts" and goes and creates one they already have.
    """
    monkeypatch.setattr(azure_arm, "_credential", lambda _cid: _DeadCredential())
    r = client.get(path, headers=ADMIN)

    assert r.status_code == 503, r.text
    body = r.json()
    assert not isinstance(body, list), "a failure to look was rendered as a listing"
    assert body != []
    assert body["code"] == azure_arm.KIND_CREDENTIAL_UNAVAILABLE
    # The sentence has to carry the fix for both places this runs.
    assert "UNKNOWN, not empty" in body["detail"]
    assert "az login" in body["detail"] and "managed identity" in body["detail"]
    assert body["request_id"] == r.headers["x-request-id"]


@pytest.mark.parametrize("path", DISCOVERY_PATHS, ids=_DPATH_IDS)
def test_a_missing_reader_role_is_a_typed_error_and_not_an_empty_list(client, arm, path):
    """The other way to see nothing: the credential works, ARM says 403.

    This is the likelier production failure -- a managed identity IS attached to
    the Container App (it has to be, to pull the image) and simply has no Reader
    assignment on the subscription. `[]` here would be the same lie as above, and
    the fix ("grant Reader") is one nobody can guess from an empty dropdown.

    The status is 502, deliberately NOT 403: a 403 from `/api/admin/*` already
    means "you are not an admin of this product", and putting two unrelated
    problems fixed by two different people behind one number is how an operator
    spends an afternoon in the wrong console.
    """
    forbidden = httpx.Response(403, json=_AUTHORIZATION_FAILED)
    arm(subscriptions=forbidden, resource_groups=forbidden, accounts=forbidden,
        deployments=forbidden)
    r = client.get(path, headers=ADMIN)

    assert r.status_code == 502, r.text
    body = r.json()
    assert not isinstance(body, list)
    assert body["code"] == azure_arm.KIND_FORBIDDEN
    assert "Reader" in body["detail"]
    # ARM's own message names the exact action and scope refused. Dropping it
    # would leave the operator with "403" and nothing to act on.
    assert "AuthorizationFailed" in body["azure_detail"]
    assert "Microsoft.Resources/subscriptions/resourcegroups/read" in body["azure_detail"]


def test_an_authenticated_identity_with_no_subscriptions_says_so(client, arm):
    """Zero subscriptions is not zero resource groups.

    A credential that authenticates but sees no subscription holds no role
    assignment anywhere. Left alone it would flow through as an empty resource
    group list -- a true statement about a subscription that was never
    enumerated, which is the most misleading kind of true.
    """
    arm(subscriptions={"value": []})
    r = client.get("/api/admin/azure/resource-groups", headers=ADMIN)

    assert r.status_code == 502, r.text
    assert r.json()["code"] == azure_arm.KIND_NO_SUBSCRIPTIONS
    assert "no role assignment" in r.json()["detail"]


def test_several_visible_subscriptions_are_refused_rather_than_guessed(client, arm):
    """With more than one subscription there is no defensible default.

    Picking the first would enumerate somebody else's estate and then report the
    operator's own Foundry account as missing -- a wrong answer delivered with
    total confidence. The error names the candidates so the page can offer them.
    """
    arm(subscriptions={"value": [
        {"subscriptionId": SUBSCRIPTION, "displayName": "prod", "state": "Enabled"},
        {"subscriptionId": "11111111-2222-3333-4444-555555555555", "displayName": "sandbox",
         "state": "Enabled"},
    ]})
    r = client.get("/api/admin/azure/resource-groups", headers=ADMIN)

    assert r.status_code == 400, r.text
    assert r.json()["code"] == azure_arm.KIND_SUBSCRIPTION_AMBIGUOUS
    assert "prod" in r.json()["detail"] and "sandbox" in r.json()["detail"]


def test_a_timeout_is_a_typed_error_and_not_an_empty_list(client, arm):
    """A slow ARM must not read as a small estate."""
    def _slow(_request):
        raise httpx.ReadTimeout("timed out")

    arm(resource_groups=_slow)
    r = client.get("/api/admin/azure/resource-groups", headers=ADMIN)
    assert r.status_code == 504, r.text
    assert r.json()["code"] == azure_arm.KIND_TIMEOUT


def test_an_unreachable_arm_is_a_typed_error_and_not_an_empty_list(client, arm):
    """No outbound network from the container is a deployment fault with a name."""
    def _dead(_request):
        raise httpx.ConnectError("no route to host")

    arm(resource_groups=_dead)
    r = client.get("/api/admin/azure/resource-groups", headers=ADMIN)
    assert r.status_code == 502, r.text
    assert r.json()["code"] == azure_arm.KIND_UNREACHABLE
    assert "outbound network" in r.json()["detail"]


def test_a_200_that_is_not_the_documented_shape_is_a_failure(client, arm):
    """A 200 with no `value` array means the pinned api-version stopped being
    served. Treating it as "no resource groups" would turn a dependency breaking
    into a silent, permanent, confident empty page."""
    arm(resource_groups=httpx.Response(200, json={"unexpected": "shape"}))
    r = client.get("/api/admin/azure/resource-groups", headers=ADMIN)
    assert r.status_code == 502, r.text
    assert r.json()["code"] == azure_arm.KIND_BAD_RESPONSE
    assert "api-version" in r.json()["detail"]


def test_a_rejected_token_is_distinguished_from_a_missing_role(client, arm):
    """401 and 403 mean different things -- wrong tenant vs missing role -- and
    get different codes, because they are fixed differently."""
    arm(resource_groups=httpx.Response(401, json={"error": {"code": "InvalidAuthenticationToken",
                                                            "message": "expired"}}))
    r = client.get("/api/admin/azure/resource-groups", headers=ADMIN)
    assert r.status_code == 502
    assert r.json()["code"] == azure_arm.KIND_UNAUTHORIZED
    assert "tenant" in r.json()["detail"]


def test_an_empty_list_still_means_empty(client, arm):
    """The other side of the rule, and the reason it is worth having.

    A genuinely empty answer -- ARM was asked, ARM said none -- is a 200 with
    `[]`. If every empty listing were an error, the page could not distinguish
    them either, and the fix would be as bad as the defect.
    """
    arm(resource_groups={"value": []})
    r = client.get("/api/admin/azure/resource-groups", headers=ADMIN)
    assert r.status_code == 200
    assert r.json() == []


# --------------------------------------------------------------------------
# 3. parsing: the ARM shape becomes the contract shape
# --------------------------------------------------------------------------

def test_resource_groups_are_parsed_into_the_contract_shape(client, arm):
    r = client.get("/api/admin/azure/resource-groups", headers=ADMIN)
    assert r.status_code == 200, r.text
    # Sorted case-insensitively by name, so the dropdown is stable across calls
    # rather than in whatever order ARM happened to page them.
    assert r.json() == [
        {"name": "Foundry-RG", "location": "centralindia"},
        {"name": "npr-demo-rg", "location": "centralindia"},
    ]


def test_accounts_are_parsed_into_the_contract_shape(client, arm):
    r = client.get(f"/api/admin/azure/accounts?resource_group={LIVE_RESOURCE_GROUP}",
                   headers=ADMIN)
    assert r.status_code == 200, r.text
    accounts = r.json()
    foundry = next(a for a in accounts if a["name"] == LIVE_ACCOUNT)
    assert foundry["endpoint"] == f"https://{LIVE_ACCOUNT}.cognitiveservices.azure.com/"
    assert foundry["kind"] == "AIServices"
    # The account's own region, not its resource group's: they differ on the live
    # account (RG centralindia, account southindia) and an operator choosing a
    # model for a data-residency reason needs the one that is true.
    assert foundry["location"] == "southindia"
    assert {"name", "endpoint", "kind", "location"} <= set(foundry)


def test_deployments_are_parsed_into_the_contract_shape(client, arm):
    r = client.get(f"/api/admin/azure/deployments?resource_group={LIVE_RESOURCE_GROUP}"
                   f"&account={LIVE_ACCOUNT}", headers=ADMIN)
    assert r.status_code == 200, r.text
    got = {d["name"]: d for d in r.json()}
    assert set(got) == set(LIVE_DEPLOYMENTS)
    assert got["Mistral-Large-3"]["model"] == "Mistral-Large-3"
    assert got["Mistral-Large-3"]["version"] == "1"
    assert got["Mistral-Large-3"]["sku"] == "GlobalStandard"
    # The model FORMAT is not the model name, and on this account neither is an
    # OpenAI one -- which is the fact that made "just use the OpenAI SDK route"
    # worth measuring rather than assuming.
    assert got["Mistral-Large-3"]["format"] == "Mistral AI"
    assert got["Kimi-K2.7-Code"]["format"] == "MoonshotAI"


def test_a_gpt_deployment_is_not_treated_differently(client, arm):
    """No model family is privileged, filtered or renamed on the way out.

    This replaces a LIVE assertion that had no business being live. The old test
    pinned "the fixture account has no GPT deployment" against the real
    `Foundry-RG` -- true when it was written, and a statement about what a
    stranger had not deployed yet rather than about this code. Somebody deployed
    `gpt-5.1-codex-mini` and the suite went red while `list_deployments` was
    returning ARM's answer verbatim: the test failed, the code did not.

    The invariant underneath it is real and belongs here, where it is
    deterministic. `Kimi-K2.7-Code` and `Mistral-Large-3` are not OpenAI models,
    which is why the provider path was PROBED rather than assumed (see the
    header of src/advisory/client.py) -- and the mirror of "do not assume GPT"
    is "do not special-case it either". A dropdown that quietly drops, reorders
    or promotes a family is the same lie as an empty one: the operator cannot
    tell "you do not have that deployment" from "we decided not to show it".

    Both directions are asserted below, over a stub that carries three families
    at once, because a filter written for either reason reads identically.
    """
    arm(deployments={"value": [
        {"name": "gpt4o-prod",
         "properties": {"model": {"format": "OpenAI", "name": "gpt-4o", "version": "2024-08-06"},
                        "capabilities": {"chatCompletion": "true"},
                        "provisioningState": "Succeeded"},
         "sku": {"name": "GlobalStandard", "capacity": 50}},
        *_DEPLOYMENTS["value"],
        {"name": "text-embedding-3-large",
         "properties": {"model": {"format": "OpenAI", "name": "text-embedding-3-large",
                                  "version": "1"},
                        "capabilities": {"embeddings": "true"},
                        "provisioningState": "Succeeded"},
         "sku": {"name": "Standard", "capacity": 10}},
    ]})
    r = client.get(f"/api/admin/azure/deployments?resource_group={LIVE_RESOURCE_GROUP}"
                   f"&account={LIVE_ACCOUNT}", headers=ADMIN)
    assert r.status_code == 200, r.text
    got = {d["name"]: d for d in r.json()}
    assert set(got) == {"gpt4o-prod", "text-embedding-3-large", *LIVE_DEPLOYMENTS}, (
        f"a model family was filtered out of the dropdown: {sorted(got)}")
    # The DEPLOYMENT name is what goes in the request path and the MODEL name is
    # what it is a deployment of; conflating them is the 404 this dropdown exists
    # to prevent, and a GPT deployment is where they most often differ.
    assert got["gpt4o-prod"]["model"] == "gpt-4o"
    assert got["gpt4o-prod"]["sku"] == "GlobalStandard"
    # A non-chat deployment is REPORTED with its capabilities rather than hidden
    # (list_deployments' docstring), so the UI can mark it as unusable for
    # advisory rather than leave the operator wondering where it went.
    assert got["text-embedding-3-large"]["sku"] == "Standard"
    # ...and the deployment lister does not name a model family anywhere in its
    # executable body. `_executable_body` drops the docstring and the comments,
    # which is what makes this checkable at all: every function in this codebase
    # explains itself at length, and `list_deployments` uses `gpt4o-prod` as its
    # worked example of a deployment name that is not its model name.
    #
    # Deliberately NOT applied to `list_ai_accounts`: `OpenAI` is an ARM ACCOUNT
    # KIND there, not a model family, and it is on the allowed list precisely so
    # a classic Azure-OpenAI resource still appears
    # (test_non_inference_account_kinds_are_filtered_out asserts that it does).
    low = _executable_body(azure_arm.list_deployments).lower()
    assert "gpt" not in low and "openai" not in low, (
        "list_deployments branches on a model family; it must report what ARM "
        f"holds and let the operator choose:\n{low}")


def test_an_account_still_provisioning_is_listed_rather_than_hidden(arm):
    """An account whose `endpoint` has not appeared yet is a real account the
    operator is probably waiting for. Hiding it would be indistinguishable from
    it not existing -- this module's one rule -- so it is listed with an endpoint
    derived from its subdomain and its provisioning state carried through."""
    arm(accounts={"value": [{"name": "brand-new", "kind": "AIServices", "location": "westeurope",
                             "properties": {"customSubDomainName": "brand-new",
                                            "provisioningState": "Creating"}}]})
    got = azure_arm.list_ai_accounts(SUBSCRIPTION, LIVE_RESOURCE_GROUP)
    assert got == [{"name": "brand-new",
                    "endpoint": "https://brand-new.cognitiveservices.azure.com/",
                    "kind": "AIServices", "location": "westeurope",
                    "provisioning_state": "Creating"}]


# --------------------------------------------------------------------------
# 4. the kind filter
# --------------------------------------------------------------------------

def test_non_inference_account_kinds_are_filtered_out(client, arm):
    """A Speech resource in a model dropdown is not a longer list, it is a trap.

    It has a name, an endpoint and a location, so it renders identically to a
    Foundry account -- and the operator only finds out it cannot serve a chat
    completion when every capability in the product has silently degraded to the
    deterministic fallback.
    """
    r = client.get(f"/api/admin/azure/accounts?resource_group={LIVE_RESOURCE_GROUP}",
                   headers=ADMIN)
    assert r.status_code == 200
    names = [a["name"] for a in r.json()]
    assert names == [LIVE_ACCOUNT, "legacy-openai"], names
    assert "npr-speech" not in names and "npr-vision" not in names
    # Guard the guard: the stub really did offer the noise, so the filter is
    # doing work rather than the fixture being clean.
    assert azure_arm.kinds_filtered_out(_ACCOUNTS["value"]) == ["ComputerVision", "SpeechServices"]


def test_the_kind_filter_is_case_insensitive(arm):
    """ARM's casing of `kind` has changed before, and a filter that turns on
    exact case would empty the dropdown the day it changes again -- silently,
    and looking exactly like "you have no Foundry accounts"."""
    arm(accounts={"value": [
        {"name": "a", "kind": "aiservices", "location": "x", "properties": {"endpoint": "https://a/"}},
        {"name": "b", "kind": "OPENAI", "location": "x", "properties": {"endpoint": "https://b/"}},
    ]})
    assert [a["name"] for a in azure_arm.list_ai_accounts(SUBSCRIPTION, LIVE_RESOURCE_GROUP)] == ["a", "b"]


# --------------------------------------------------------------------------
# 5. bounds
# --------------------------------------------------------------------------

@pytest.mark.parametrize("bad", [0, -1, azure_arm.MAX_LIMIT + 1])
def test_the_limit_is_bounded_at_the_route(client, arm, bad):
    """`Query(..., ge=1, le=MAX_LIMIT)`. An unbounded fan-out to somebody else's
    API on a request path is the pattern Phase 2 removed."""
    r = client.get(f"/api/admin/azure/resource-groups?limit={bad}", headers=ADMIN)
    assert r.status_code == 422, r.text


def test_a_truncated_listing_is_marked_rather_than_silently_short(client, arm):
    """The body is the bare array the shared contract specifies, so the fact that
    there were MORE has nowhere to live in it -- and a dropdown cut off at the
    limit fails exactly like an empty one. It rides on a header, and the module
    has already logged it with the request id."""
    many = {"value": [{"name": f"rg-{i:03d}", "location": "eastus"} for i in range(50)]}
    arm(resource_groups=many)
    r = client.get("/api/admin/azure/resource-groups?limit=10", headers=ADMIN)
    assert r.status_code == 200
    assert len(r.json()) == 10
    assert r.headers["x-npr-result-truncated"] == "true"
    assert r.headers["x-npr-result-truncated-by"] == "limit"
    # ...and an untruncated listing says nothing, or the header means nothing.
    ok = client.get("/api/admin/azure/resource-groups?limit=200", headers=ADMIN)
    assert "x-npr-result-truncated" not in ok.headers


def test_pagination_is_followed_and_bounded(arm):
    """ARM pages with `nextLink`. Not following it truncates at the first page;
    following it forever is an unbounded loop driven by a remote server."""
    pages = {"n": 0}

    def _paged(_request):
        pages["n"] += 1
        body = {"value": [{"name": f"rg-page-{pages['n']}", "location": "eastus"}],
                "nextLink": ("https://management.azure.com/subscriptions/"
                             f"{SUBSCRIPTION}/resourcegroups?$skipToken={pages['n']}")}
        return httpx.Response(200, json=body)

    arm(resource_groups=_paged)
    state: dict = {}
    got = azure_arm.list_resource_groups(SUBSCRIPTION, state=state)
    assert len(got) == azure_arm.MAX_PAGES, "pagination stopped early or never started"
    assert pages["n"] == azure_arm.MAX_PAGES, "the page cap did not hold"
    assert state["truncated"] is True and state["bound"] == "pages"


def test_every_arm_call_carries_a_timeout():
    """Measured on the client this module actually builds, not asserted in a
    comment. A discovery call with no timeout is a hung admin page."""
    with azure_arm._http_client() as c:
        assert c.timeout.connect == azure_arm.ARM_TIMEOUT
        assert c.timeout.read == azure_arm.ARM_TIMEOUT
        assert c.timeout.write == azure_arm.ARM_TIMEOUT
        assert c.timeout.pool == azure_arm.ARM_TIMEOUT


@pytest.mark.parametrize("bad_rg", ["../../subscriptions", "a/b", "rg name", "x" * 91, "trailing."])
def test_a_malformed_resource_group_is_refused_before_any_call(client, arm, bad_rg):
    """These names are interpolated into an ARM URL PATH. They are validated
    against Azure's own naming rules first -- not because ARM would be fooled,
    but because a request built from unvalidated caller input is a request whose
    target nobody can state, and because the refusal names the field instead of
    surfacing an ARM 404 that reads as "your resource group does not exist"."""
    calls = arm()
    r = client.get("/api/admin/azure/accounts", params={"resource_group": bad_rg}, headers=ADMIN)
    assert r.status_code in (400, 422), r.text
    if r.status_code == 400:
        assert r.json()["code"] == azure_arm.KIND_INVALID_NAME
    assert not [c for c in calls if "Microsoft.CognitiveServices" in str(c.url)], (
        "a malformed name reached Azure")


# --------------------------------------------------------------------------
# 6. GET / PUT /api/admin/ai/config
# --------------------------------------------------------------------------

def test_the_config_payload_separates_stored_from_in_force(client, arm, monkeypatch):
    """Three questions, three answers, never collapsed: what is STORED, what is
    IN FORCE, and whether what is in force can make a call. A deployment can have
    no stored row and still be routed at Azure by its container spec, and a saved
    row can be complete and still unable to make one call."""
    monkeypatch.setattr(settings, "AZURE_AI_ENDPOINT",
                        "https://env-account.cognitiveservices.azure.com/")
    monkeypatch.setattr(settings, "AZURE_AI_DEPLOYMENT", "env-deployment")
    monkeypatch.setattr(settings, "ADVISORY_PROVIDER", "azure")

    body = client.get("/api/admin/ai/config", headers=ADMIN).json()
    assert body["is_stored"] is False                      # nothing saved
    assert body["provider"] is None
    assert body["resolved"]["provider"] == "azure"          # ...but Azure is in force
    assert body["resolved"]["provider_origin"] == ai_config.ORIGIN_ENVIRONMENT
    assert body["resolved"]["azure_deployment"] == "env-deployment"
    assert body["azure_ready"] is True


def test_the_config_payload_never_carries_a_key(client, arm, monkeypatch):
    """The API key lives in a Container Apps secret, never in the table and never
    in this payload. Presence is a BOOLEAN so the page can say "you chose key
    auth and this deployment has no key" without the key crossing the boundary."""
    monkeypatch.setattr(settings, "AZURE_AI_API_KEY", "sk-super-secret-value")
    r = client.get("/api/admin/ai/config", headers=ADMIN)
    assert r.status_code == 200
    assert "sk-super-secret-value" not in r.text
    assert r.json()["azure_api_key_present"] is True
    for key in r.json():
        assert not any(p in key.lower() for p in ("secret", "password", "token", "credential"))


def test_saving_a_configuration_validates_attributes_and_takes_effect(client, arm, savable):
    r = client.put("/api/admin/ai/config", headers=ADMIN, json={
        "provider": "azure",
        "azure_endpoint": f"https://{LIVE_ACCOUNT}.cognitiveservices.azure.com",
        "azure_deployment": "Mistral-Large-3",
        "azure_api_version": "2024-10-21",
        "azure_auth_mode": "identity",
    })
    assert r.status_code == 200, r.text
    saved = savable["cfg"]
    # Normalized on the way in: exactly one trailing slash, so the provider's
    # f-string interpolation cannot produce a double slash in the request path.
    assert saved.azure_endpoint == f"https://{LIVE_ACCOUNT}.cognitiveservices.azure.com/"
    assert saved.azure_deployment == "Mistral-Large-3"
    # Attributed to the caller, from the request context, not from the body.
    assert savable["actor"] == ADMIN["x-npr-email"]


def test_a_half_configured_azure_provider_is_refused_with_a_reason(client, arm, savable):
    """400 naming the missing field, not a 500 and not a silent save: a provider
    of 'azure' with no deployment routes every model call at nothing and degrades
    to the deterministic fallback, which reads to a user as a weak model rather
    than an unfinished form."""
    r = client.put("/api/admin/ai/config", headers=ADMIN,
                   json={"provider": "azure",
                         "azure_endpoint": "https://a.cognitiveservices.azure.com/"})
    assert r.status_code == 400, r.text
    assert "deployment" in r.json()["detail"]


def test_a_plaintext_endpoint_is_refused(client, arm, savable):
    """This product sends firewall rules, asset names and reachability paths to
    the model. `http://` to a remote host is not a configuration choice."""
    r = client.put("/api/admin/ai/config", headers=ADMIN,
                   json={"provider": "azure", "azure_endpoint": "http://evil.example.com/",
                         "azure_deployment": "x"})
    assert r.status_code == 400, r.text
    assert "https" in r.json()["detail"]


def test_an_unreadable_store_is_503_and_not_an_empty_form(client, arm, monkeypatch):
    """"No row is stored" and "the store could not be read" have different fixes.
    Answering the second with the defaults would show an operator a blank form
    for a provider that is in fact configured and running."""
    def _boom():
        raise ai_config.AiConfigUnavailable("could not read ztpa.ai_config: connection refused")

    monkeypatch.setattr(ai_config, "load", _boom)
    r = client.get("/api/admin/ai/config", headers=ADMIN)
    assert r.status_code == 503, r.text
    assert "ai_config" in r.json()["detail"]


def test_saving_drops_the_cached_azure_credential(client, arm, savable, monkeypatch):
    """A changed `azure_client_id` is a changed IDENTITY. Without the reset,
    discovery would keep authenticating as the previous one until the process
    restarted -- a configuration change that appears to do nothing, which is how
    an operator concludes the page is broken and goes back to the container spec.
    """
    azure_arm._CREDENTIALS["stale"] = object()
    client.put("/api/admin/ai/config", headers=ADMIN, json={"provider": "ollama"})
    assert azure_arm._CREDENTIALS == {}


# --------------------------------------------------------------------------
# 7. POST /api/admin/ai/test -- the button that must not lie
# --------------------------------------------------------------------------

@pytest.fixture
def azure_in_force(monkeypatch):
    """Put a complete, ready Azure configuration in force through the
    environment, so the test endpoint has something real to report on without a
    database."""
    monkeypatch.setattr(settings, "ADVISORY_PROVIDER", "azure")
    monkeypatch.setattr(settings, "AZURE_AI_ENDPOINT",
                        f"https://{LIVE_ACCOUNT}.cognitiveservices.azure.com/")
    monkeypatch.setattr(settings, "AZURE_AI_DEPLOYMENT", "Mistral-Large-3")
    monkeypatch.setattr(settings, "AZURE_AI_AUTH_MODE", "identity")
    monkeypatch.setattr(settings, "AZURE_AI_API_KEY", "")
    ai_config.invalidate()


def test_a_working_configuration_reports_ok_with_what_it_called(client, azure_in_force, stub_llm):
    r = client.post("/api/admin/ai/test", headers=ADMIN)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["ok"] is True
    assert body["provider"] == "azure"
    assert body["deployment"] == "Mistral-Large-3"
    assert body["endpoint"] == f"https://{LIVE_ACCOUNT}.cognitiveservices.azure.com/"
    assert body["latency_ms"] >= 0
    assert body["error"] is None
    # The answer names its own subject and carries proof something replied, so
    # `ok` is not the only thing the operator has to take on trust.
    assert body["sample"] == "ok"
    assert stub_llm["calls"] and stub_llm["calls"][0]["provider"] == "azure"


def test_a_provider_substitution_is_reported_as_a_failure(client, azure_in_force, stub_llm):
    """THE WORST POSSIBLE PASS, AND WHY IT IS CHECKED.

    `advisory.client.complete()` is fail-closed by contract: a provider it does
    not implement falls through to the Ollama branch and comes back `ok=True`
    from a completely different model. On this endpoint that is a green tick
    that appears to prove the Azure endpoint works, produced by a local model
    that never touched it -- and the operator walks away believing a
    configuration that will degrade every capability in the product.
    """
    stub_llm["answer"]["provider"] = "ollama"          # what a substitution looks like
    r = client.post("/api/admin/ai/test", headers=ADMIN)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["ok"] is False
    assert "did NOT reach the configured endpoint" in body["error"]
    assert "azure" in body["error"] and "ollama" in body["error"]


def test_an_empty_completion_is_not_a_pass(client, azure_in_force, stub_llm):
    """Not hypothetical. The reasoning deployment on the live Foundry account
    spends its whole budget in `reasoning_content` and returns HTTP 200 with
    `content: ""` -- a working endpoint and an unusable configuration. Nothing in
    this product can be served by an empty completion."""
    stub_llm["answer"]["text"] = "   "
    r = client.post("/api/admin/ai/test", headers=ADMIN)
    assert r.json()["ok"] is False
    assert "empty completion" in r.json()["error"]


def test_a_provider_failure_is_passed_through_verbatim(client, azure_in_force, stub_llm):
    stub_llm["answer"].update(ok=False, error="401 Unauthorized: PermissionDenied", text="")
    body = client.post("/api/admin/ai/test", headers=ADMIN).json()
    assert body["ok"] is False
    assert body["error"] == "401 Unauthorized: PermissionDenied"


def test_a_configuration_that_cannot_call_is_reported_without_calling(client, monkeypatch,
                                                                      stub_llm):
    """Key auth selected with no key in the environment is a complete-looking
    form that cannot make one call. Reported as the reason, not attempted -- a
    401 the operator has to decode is a worse answer than the sentence."""
    monkeypatch.setattr(settings, "ADVISORY_PROVIDER", "azure")
    monkeypatch.setattr(settings, "AZURE_AI_ENDPOINT",
                        f"https://{LIVE_ACCOUNT}.cognitiveservices.azure.com/")
    monkeypatch.setattr(settings, "AZURE_AI_DEPLOYMENT", "Mistral-Large-3")
    monkeypatch.setattr(settings, "AZURE_AI_AUTH_MODE", "key")
    monkeypatch.setattr(settings, "AZURE_AI_API_KEY", "")
    ai_config.invalidate()

    body = client.post("/api/admin/ai/test", headers=ADMIN).json()
    assert body["ok"] is False
    assert "AZURE_AI_API_KEY" in body["error"]
    assert not stub_llm["calls"], "tokens were spent on a configuration that cannot work"


def test_testing_unsaved_values_is_refused_rather_than_answered_about_the_row(
        client, azure_in_force, stub_llm):
    """`complete()` reads its Azure target from the RESOLVED configuration, so
    there is no seam through which a draft could be tested. Accepting a draft
    body and silently reporting on the stored row would put a green tick next to
    a form that is not what this deployment is running -- so the draft is refused,
    naming the fields, with "save first"."""
    body = client.post("/api/admin/ai/test", headers=ADMIN, json={
        "provider": "azure",
        "azure_endpoint": "https://a-different-account.cognitiveservices.azure.com/",
        "azure_deployment": "Kimi-K2.7-Code",
    }).json()
    assert body["ok"] is False
    assert body["tested"] == "nothing"
    assert "azure_endpoint" in body["error"] and "azure_deployment" in body["error"]
    assert "Save" in body["error"]
    assert not stub_llm["calls"], "tokens were spent testing a configuration nobody is running"


def test_posting_the_values_that_are_in_force_tests_them(client, azure_in_force, stub_llm):
    """The other half: a body that MATCHES what is running is not drift, and a
    trailing slash or an unset api-version is not a difference. A false alarm
    here would teach an operator to ignore the message that matters."""
    body = client.post("/api/admin/ai/test", headers=ADMIN, json={
        "provider": "azure",
        # No trailing slash, and no api_version at all: both normalize to what
        # is in force.
        "azure_endpoint": f"https://{LIVE_ACCOUNT}.cognitiveservices.azure.com",
        "azure_deployment": "Mistral-Large-3",
        "azure_auth_mode": "identity",
    }).json()
    assert body["ok"] is True, body
    assert stub_llm["calls"]


def test_an_empty_body_is_accepted_as_no_body(client, azure_in_force, stub_llm):
    """A diagnostic endpoint that 422s the request is the least useful possible
    answer to "is my configuration working?", so `{}`, a partial form and no body
    at all are all accepted."""
    assert client.post("/api/admin/ai/test", headers=ADMIN, json={}).json()["ok"] is True


def test_the_model_call_is_not_made_inside_an_open_transaction(client, azure_in_force,
                                                               monkeypatch):
    """Phase 2 removed exactly this from /api/actions: a live LLM call with a
    database transaction held open across it, so a slow model pinned a
    connection from the pool for its whole duration. The shape here is the one
    /api/campaign/plan uses -- read, close, call, then a second short
    transaction for the audit row."""
    open_conns = {"n": 0, "during_call": None}

    class _Cur:
        def execute(self, *_a, **_kw): return self
        def fetchone(self): return None
        def fetchall(self): return []
        def __enter__(self): return self
        def __exit__(self, *_e): return False

    class _Conn:
        def cursor(self): return _Cur()
        def __enter__(self):
            open_conns["n"] += 1
            return self
        def __exit__(self, *_e):
            open_conns["n"] -= 1
            return False

    monkeypatch.setattr(main, "get_conn", lambda: _Conn())
    monkeypatch.setattr(main, "audit", lambda *_a, **_kw: None)

    def _complete(**kwargs):
        open_conns["during_call"] = open_conns["n"]
        return main.llm_client.LLMResponse(text="ok", provider=kwargs["provider"], model="m")

    monkeypatch.setattr(main.llm_client, "complete", _complete)

    assert client.post("/api/admin/ai/test", headers=ADMIN).json()["ok"] is True
    assert open_conns["during_call"] == 0, (
        "a database connection was held open across the model call")
    assert open_conns["n"] == 0, "a connection was leaked"


def test_the_test_endpoint_survives_an_unwritable_audit_trail(client, azure_in_force, stub_llm,
                                                              monkeypatch, caplog):
    """The probe's answer is what the operator came for, so a database that
    cannot take the audit row must not turn a successful probe into a 500 --
    but it must not be silent either."""
    def _boom():
        raise RuntimeError("no database")

    monkeypatch.setattr(main, "get_conn", _boom)
    with caplog.at_level("WARNING", logger="npr.api"):
        assert client.post("/api/admin/ai/test", headers=ADMIN).json()["ok"] is True
    assert any("could not be audited" in r.message for r in caplog.records)


def test_the_test_endpoint_is_the_only_route_that_spends_tokens_here():
    """Guard the guard on the audit's "routes that spend money" finding: the four
    discovery routes must not reach the model client at all, or a dropdown that
    refreshes on every keystroke becomes a bill."""
    for endpoint in (main.azure_subscriptions, main.azure_resource_groups,
                     main.azure_accounts, main.azure_deployments, main.ai_config_get):
        assert "llm_client" not in inspect.getsource(endpoint)
    assert "llm_client.complete" in inspect.getsource(main.ai_config_test)


# --------------------------------------------------------------------------
# 8. THE LIVE TEST
# --------------------------------------------------------------------------

def _skip_live_reason() -> str | None:
    """Why the live test cannot run, or None when it can.

    OPT-IN, and it was not always. This gate used to be opt-OUT -- it returned
    None unless `NPR_SKIP_AZURE_LIVE` was set -- on the reasoning that a
    discovery layer only ever exercised against a stub has api-versions,
    response shapes and a credential chain that are all assumptions. That
    reasoning is right about the VALUE of the live test and wrong about its
    DEFAULT, for two measured reasons:

      * `backend/conftest.py` states the suite's contract in its first
        paragraph -- "it has no business opening a socket" -- and blanks
        DATABASE_URL to enforce the database half of it. An opt-out gate made
        the plain `pytest` command dial ARM on any machine with a working
        `az login`, which is every developer machine this was built on. The
        suite's own guard rails said one thing and one test did another.
      * it asserted a MUTABLE property of a resource group nobody in this repo
        controls, so somebody adding a deployment in `Foundry-RG` turned this
        suite red with no change to this repo at all. That is what happened:
        a `gpt-5.1-codex-mini` deployment appeared and the run went red while
        discovery was behaving perfectly -- it returned exactly what ARM held.

    So: green by default means "everything this repo controls is correct", and
    the live probe is a thing you ASK for (`NPR_RUN_LIVE=1 pytest -m live`) when
    you want to know whether Azure still answers the shape this code parses.

    The decision itself lives in `tests/livegate.py` and is enforced at
    COLLECTION by `backend/conftest.py`, so this function is a second, local
    statement of the same rule rather than the only thing standing between a
    default `pytest` and somebody else's subscription. `NPR_SKIP_AZURE_LIVE` is
    still honoured there and still wins over the opt-in.
    """
    return livegate.skip_reason()


@pytest.mark.live
def test_live_azure_discovery_finds_the_foundry_account(client, monkeypatch):
    """Against the REAL Azure, through the REAL endpoints, with whatever
    credential this machine has. OPT-IN: `NPR_RUN_LIVE=1 pytest -m live`.

    Skipped cleanly -- with the typed reason on the skip message, which is the
    same sentence the endpoint would show an operator -- when it is not asked
    for, when Azure is not reachable, or when this identity cannot look.

    WHAT IT MAY ASSERT, AND WHAT IT MAY NOT
    ---------------------------------------
    `Foundry-RG` is somebody else's resource group and its contents change
    without reference to this repo. So the assertions here are confined to two
    kinds of claim:

      * facts this code would be WRONG about if they were false -- the account
        is `AIServices`, its endpoint is the `cognitiveservices.azure.com` form
        the provider builds request URLs from, the two deployments this feature
        was built and probed against are present and `GlobalStandard`;
      * shape -- every row ARM returns comes back with the fields the dropdown
        binds to, whatever they happen to be.

    It may NOT assert the ABSENCE of anything, because absence in a live
    resource group is a statement about what a stranger has not done yet. The
    previous version of this test pinned "this account has no GPT deployment";
    someone deployed `gpt-5.1-codex-mini` and the suite went red while discovery
    was returning ARM's answer exactly. The invariant that assertion was
    reaching for -- that nothing in this code filters or privileges an
    OpenAI-family model -- is a property of THIS REPO, so it is pinned offline
    and deterministically in `test_a_gpt_deployment_is_not_treated_differently`.

    This is still the test that would catch a wrong api-version, a renamed
    response field, a credential scope typo or a filter that drops the very kind
    the product needs -- none of which a stub can fail on, because a stub is
    written from the same understanding as the code.
    """
    reason = _skip_live_reason()
    if reason:
        pytest.skip(reason)
    # The offline conftest blanks DATABASE_URL, so `_azure_client_id()` resolves
    # through the environment: DefaultAzureCredential, i.e. this machine's
    # `az login` or the container's managed identity.
    try:
        rgs = client.get("/api/admin/azure/resource-groups", headers=ADMIN)
    except Exception as exc:                      # transport-level, before any response
        pytest.skip(f"Azure is not reachable from this machine: {type(exc).__name__}: {exc}")
    if rgs.status_code != 200:
        pytest.skip(f"live Azure discovery unavailable ({rgs.status_code} "
                    f"{rgs.json().get('code')}): {rgs.json().get('detail')}")

    names = [g["name"] for g in rgs.json()]
    assert LIVE_RESOURCE_GROUP in names, f"{LIVE_RESOURCE_GROUP} not among {names}"

    accounts = client.get("/api/admin/azure/accounts",
                          params={"resource_group": LIVE_RESOURCE_GROUP}, headers=ADMIN)
    assert accounts.status_code == 200, accounts.text
    by_name = {a["name"]: a for a in accounts.json()}
    assert LIVE_ACCOUNT in by_name, f"{LIVE_ACCOUNT} not among {sorted(by_name)}"
    assert by_name[LIVE_ACCOUNT]["kind"] == "AIServices"
    assert by_name[LIVE_ACCOUNT]["endpoint"] == \
        f"https://{LIVE_ACCOUNT}.cognitiveservices.azure.com/"

    deployments = client.get("/api/admin/azure/deployments",
                             params={"resource_group": LIVE_RESOURCE_GROUP,
                                     "account": LIVE_ACCOUNT}, headers=ADMIN)
    assert deployments.status_code == 200, deployments.text
    deployed = {d["name"]: d for d in deployments.json()}
    for expected in LIVE_DEPLOYMENTS:
        assert expected in deployed, f"{expected} not among {sorted(deployed)}"
        assert deployed[expected]["sku"] == "GlobalStandard"
    # Shape, over EVERY row -- including ones added since this was written. A
    # deployment the dropdown cannot render is the failure worth catching here;
    # a deployment somebody added is not a failure at all.
    for name, row in sorted(deployed.items()):
        assert set(row) >= {"name", "model", "version", "sku"}, f"{name}: {sorted(row)}"
        assert row["name"] and row["model"], f"{name} came back with an empty field: {row}"

    print("\nLIVE /api/admin/azure/resource-groups -> " + json.dumps(rgs.json()))
    print("LIVE /api/admin/azure/accounts -> " + json.dumps(accounts.json()))
    print("LIVE /api/admin/azure/deployments -> " + json.dumps(deployments.json()))


def test_a_continuation_link_off_azure_is_refused_rather_than_followed(client, arm):
    """`nextLink` is a URL chosen by the SERVER, and the pagination loop attaches
    this application's ARM bearer token to every request it makes. A link naming
    another host would be handed a token that reads the customer's entire
    subscription, so the origin is checked -- and the refusal is a typed error,
    because silently returning the pages fetched so far would present a truncated
    list as a complete one."""
    calls = arm(resource_groups=httpx.Response(200, json={
        "value": [{"name": "rg-1", "location": "eastus"}],
        "nextLink": "https://evil.example.com/subscriptions/x/resourcegroups"}))
    r = client.get("/api/admin/azure/resource-groups", headers=ADMIN)
    assert r.status_code == 502, r.text
    assert r.json()["code"] == azure_arm.KIND_BAD_RESPONSE
    assert "evil.example.com" in r.json()["azure_detail"]
    assert not [c for c in calls if c.url.host == "evil.example.com"], (
        "the ARM bearer token was sent to a host ARM named")
