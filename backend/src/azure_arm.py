"""Azure Resource Manager discovery: the dropdowns on the Configuration page.

WHY THIS MODULE EXISTS
----------------------
Pointing this product at a customer's own Azure AI Foundry deployment needs
three facts an operator does not carry in their head: the resource group, the
Foundry account, and the DEPLOYMENT name on that account (which is routinely not
the model name -- `Kimi-K2.7-Code` is a deployment of a model called
`Kimi-K2.7-Code`, but `gpt4o-prod` is a perfectly normal deployment name for
`gpt-4o`). Typing any of the three wrong produces a configuration that saves
cleanly, passes validation, and then 404s on every model call -- which reaches a
user as "the AI is bad", not as "the endpoint is wrong".

So the Configuration page asks Azure instead of asking the operator. This module
is the ask.

WHY REST AND NOT `azure-mgmt-cognitiveservices`
-----------------------------------------------
Four list calls. The management SDKs would add `azure-mgmt-core`, `msrest`,
`isodate` and a second HTTP stack with its own retry, telemetry and pipeline
policies, to do four GETs whose response shapes are three keys deep and stable
across every api-version since 2021. `httpx` is already a dependency (the Ollama
provider path and the test suite both use it) and `azure-identity` is needed for
the inference path regardless. The cost of the SDK is real and permanent; the
benefit here is a `.list()` method.

WHAT THIS MODULE REFUSES TO DO
------------------------------
It never answers `[]` for a question it could not ask. Every failure -- no
credential, a credential the ARM refuses, a timeout, a body that is not the
shape ARM documents -- raises `ArmError` carrying a `kind` the API layer turns
into a typed error envelope. An empty list from here means Azure was asked and
said "none", and nothing else.

That distinction is the whole point of the module. A dropdown that is empty
because the app's managed identity has no `Reader` assignment looks exactly like
a dropdown that is empty because the subscription has no Foundry accounts, and
an operator who reads the second sentence when the first is true goes and
creates a resource that already exists. The audit that produced this codebase's
remediation is full of that shape: a failure rendered as a fact.

BOUNDS
------
Everything is bounded, because this runs on a request path against somebody
else's API: a connect/read/write timeout on every call, a cap on how many pages
of a paginated ARM listing are followed, and a cap on how many items come back.
Truncation is not silent -- it is logged, and the API layer marks the response.
"""

from __future__ import annotations

import logging
import os
import re
import threading
import time
from typing import Any, Iterable, Iterator
from urllib.parse import quote

import httpx

from . import settings

# A child of the API's logger, so a discovery failure comes out as one JSON line
# carrying the request id the middleware bound (app/main.py configures "npr.api").
log = logging.getLogger("npr.api.azure")


# --- bounds ---------------------------------------------------------------
# One connect/read/write timeout for every ARM call. ARM's own p99 for a list
# call is well under a second; 15s is "the network is broken", not "Azure is
# busy", and it is short enough that a Configuration page whose backing identity
# cannot reach ARM fails visibly rather than hanging a browser tab.
#
# Read here rather than from src/settings.py, which holds the environment values
# the PRODUCT is configured with: this is an escape hatch for one pathological
# network, not a knob an operator is expected to find. The three ARM values that
# ARE product configuration -- endpoint, scope, subscription -- live in settings.
ARM_TIMEOUT: float = float(os.environ.get("AZURE_ARM_TIMEOUT", "15").strip() or 15)

# ARM paginates with `nextLink`. Following it forever is an unbounded loop
# driven by a remote server; following it not at all silently truncates at the
# first page (100 items for most providers). 25 pages x 100 is 2,500 items,
# comfortably past any real subscription and finite either way.
MAX_PAGES: int = 25

# The default and the ceiling for how many items an endpoint returns. The
# ceiling is generous because the failure mode of a cap that is too low is the
# one this module exists to prevent: an operator's resource group missing from
# the dropdown, which reads as "it does not exist".
DEFAULT_LIMIT: int = 200
MAX_LIMIT: int = 500

# How long a fetched AAD token is reused. `get_token` is itself cached by
# azure-identity, but DefaultAzureCredential's chain probes IMDS and can shell
# out to `az`, so a miss is expensive enough to be worth not paying per request.
# The margin is subtracted from the token's own expiry, never added to it.
_TOKEN_MARGIN: float = 300.0


# --- api versions ---------------------------------------------------------
# Pinned, not "latest": an api-version is the contract, and the response shapes
# parsed below (`properties.model.name`, `properties.endpoint`) belong to these
# specific ones. Verified live against the account this feature was built for
# (api-endpoint-inference-resource in Foundry-RG).
API_VERSION_SUBSCRIPTIONS = "2022-12-01"
API_VERSION_RESOURCE_GROUPS = "2021-04-01"
API_VERSION_COGNITIVE = "2023-05-01"

# The Cognitive Services `kind`s that can serve a chat completion. An Azure
# subscription's `Microsoft.CognitiveServices/accounts` list mixes Speech,
# Vision, Language, Content Safety and Form Recognizer resources in with the
# model-hosting ones, and every one of them has a `name`, an `endpoint` and a
# `location` -- so an unfiltered list looks like a perfectly good model dropdown
# right up until the operator picks a Speech resource and every model call 404s.
#
# `AIServices` is the modern Foundry account kind (what the live account is);
# `OpenAI` is the older Azure OpenAI account kind, still the majority of
# deployed estates. Compared case-insensitively because ARM's casing of `kind`
# has changed before.
INFERENCE_KINDS: frozenset[str] = frozenset({"aiservices", "openai"})


# --- typed failures -------------------------------------------------------
# Every `kind` an ArmError can carry. Named as constants (and exported as a
# tuple) so the API layer's status mapping and the tests key off the same
# strings rather than off literals that can drift apart.
KIND_CREDENTIAL_UNAVAILABLE = "azure_credential_unavailable"
KIND_UNAUTHORIZED = "azure_unauthorized"
KIND_FORBIDDEN = "azure_forbidden"
KIND_NOT_FOUND = "azure_not_found"
KIND_THROTTLED = "azure_throttled"
KIND_TIMEOUT = "azure_timeout"
KIND_UNREACHABLE = "azure_unreachable"
KIND_BAD_RESPONSE = "azure_bad_response"
KIND_ERROR = "azure_error"
KIND_NO_SUBSCRIPTIONS = "azure_no_subscriptions"
KIND_SUBSCRIPTION_AMBIGUOUS = "azure_subscription_ambiguous"
KIND_INVALID_NAME = "azure_invalid_name"

KINDS: tuple[str, ...] = (
    KIND_CREDENTIAL_UNAVAILABLE, KIND_UNAUTHORIZED, KIND_FORBIDDEN, KIND_NOT_FOUND,
    KIND_THROTTLED, KIND_TIMEOUT, KIND_UNREACHABLE, KIND_BAD_RESPONSE, KIND_ERROR,
    KIND_NO_SUBSCRIPTIONS, KIND_SUBSCRIPTION_AMBIGUOUS, KIND_INVALID_NAME,
)


class ArmError(RuntimeError):
    """A discovery call that could not be made, or was refused.

    Carries a machine-readable `kind` and the HTTP `status` the API layer should
    answer with, so the frontend can tell "you have no Foundry accounts" from
    "this app cannot see your subscription" WITHOUT parsing an English sentence.

    `status` is chosen so it is never confused with the caller's own
    authorization: an ARM 403 (the app's identity lacks Reader) becomes a 502,
    not a 403, because a 403 on `/api/admin/azure/...` already means "you are not
    an admin" and the two need different fixes by different people.
    """

    def __init__(self, kind: str, message: str, *, status: int = 502,
                 detail: str | None = None) -> None:
        super().__init__(message)
        self.kind = kind
        self.message = message
        self.status = status
        self.detail = detail

    def payload(self) -> dict[str, Any]:
        return {"code": self.kind, "detail": self.message, "error": self.message,
                "azure_detail": self.detail}


# --- name validation ------------------------------------------------------
# Every one of these is interpolated into an ARM URL PATH, so they are validated
# against Azure's own naming rules before they are used -- not because ARM would
# be fooled by `../`, but because a request built from unvalidated caller input
# is a request whose target nobody can state. Rejecting here also produces a
# sentence naming the field, instead of a 404 from ARM that reads as "your
# resource group does not exist".
_SUBSCRIPTION_RE = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
                              r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
# Resource group: up to 90 chars of word characters, unicode letters, '-', '.',
# '(', ')'; may not end in '.'.
_RESOURCE_GROUP_RE = re.compile(r"^[-\w\.\(\)]{1,90}$", re.UNICODE)
# Cognitive Services account: 2-64 alphanumerics and hyphens, starting and
# ending alphanumeric.
_ACCOUNT_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9-]{0,62}[A-Za-z0-9]$")


def _check(value: str | None, pattern: re.Pattern[str], field: str, hint: str) -> str:
    raw = (value or "").strip()
    if not raw:
        raise ArmError(KIND_INVALID_NAME, f"{field} is required", status=400)
    if raw.endswith(".") or not pattern.match(raw):
        raise ArmError(KIND_INVALID_NAME, f"{field} is not a valid Azure {hint}: {raw!r}",
                       status=400)
    return raw


# --- credential -----------------------------------------------------------
# Cached per client id, and guarded by a lock: FastAPI runs sync endpoints on a
# threadpool, so two admins opening the Configuration page at once would
# otherwise each build a DefaultAzureCredential (each of which probes IMDS and
# may shell out to `az`).
_CRED_LOCK = threading.Lock()
_CREDENTIALS: dict[str, Any] = {}
_TOKENS: dict[tuple[str, str], tuple[str, float]] = {}


def _credential(client_id: str | None):
    """The credential to authenticate discovery with.

    `client_id` set -> `ManagedIdentityCredential(client_id=...)`, the SAME
    user-assigned identity the inference path will use, so discovery answers the
    question the operator is actually asking ("can THIS app see my Foundry
    account?") rather than a different one about the developer's `az login`.

    `client_id` empty -> `DefaultAzureCredential`, which is the app's
    system-assigned managed identity in Container Apps and the developer's
    `az login` on a laptop. That fallback is why discovery needs no stored
    secret anywhere.

    Imported lazily so a deployment without `azure-identity` installed fails
    with THIS module's typed error naming the missing package, rather than an
    ImportError at app import time that takes the whole API down over a feature
    nobody may be using.
    """
    key = client_id or ""
    with _CRED_LOCK:
        cred = _CREDENTIALS.get(key)
        if cred is not None:
            return cred
        try:
            from azure.identity import DefaultAzureCredential, ManagedIdentityCredential
        except ImportError as exc:                              # pragma: no cover - packaging
            raise ArmError(
                KIND_CREDENTIAL_UNAVAILABLE,
                "azure-identity is not installed in this deployment, so Azure resource "
                "discovery cannot authenticate. Add `azure-identity` to "
                "backend/requirements.txt and redeploy.",
                status=503, detail=str(exc)) from exc
        # `process_timeout` bounds the developer-machine legs of the chain (the
        # ones that shell out to `az` / `azd` / PowerShell). Without it a hung
        # CLI subprocess is an unbounded wait on a request path -- the exact
        # pattern the round-2 audit removed elsewhere.
        cred = (ManagedIdentityCredential(client_id=client_id) if client_id
                else DefaultAzureCredential(process_timeout=int(ARM_TIMEOUT)))
        _CREDENTIALS[key] = cred
        return cred


def reset_credentials() -> None:
    """Drop the cached credentials and tokens.

    Called when the stored configuration changes (a different `azure_client_id`
    means a different identity), and by tests. Without it, saving a new
    user-assigned identity would keep authenticating as the old one until the
    process restarted -- a configuration change that appears to do nothing.
    """
    with _CRED_LOCK:
        stale = list(_CREDENTIALS.values())
        _CREDENTIALS.clear()
        _TOKENS.clear()
    # Outside the lock, and best-effort: azure-identity credentials hold an HTTP
    # session, so dropping the reference without closing it leaks a connection
    # pool per reconfiguration. A credential that refuses to close is not worth
    # failing a save over -- the process is about to stop using it either way.
    for cred in stale:
        try:
            cred.close()
        except Exception as exc:  # noqa: BLE001 - vendor object, best-effort cleanup
            log.debug("an Azure credential did not close cleanly",
                      extra={"event": "azure_credential_close_failed", "error": str(exc)})


def _token(client_id: str | None, scope: str | None = None) -> str:
    """A bearer token for ARM, cached until shortly before it expires.

    Raises `ArmError(KIND_CREDENTIAL_UNAVAILABLE)` when no credential in the
    chain could produce one -- which on a developer machine means `az login` has
    not been run, and in Container Apps means no managed identity is attached
    (or the configured user-assigned one is not assigned to this app).
    """
    scope = scope or settings.AZURE_ARM_SCOPE
    key = (client_id or "", scope)
    now = time.time()
    with _CRED_LOCK:
        cached = _TOKENS.get(key)
        if cached and cached[1] > now:
            return cached[0]
    cred = _credential(client_id)
    try:
        access = cred.get_token(scope)
    except Exception as exc:  # noqa: BLE001 - the credential chain's error surface
        # Deliberately broad. azure-identity raises ClientAuthenticationError and
        # CredentialUnavailableError (a subclass) for the expected cases, but the
        # chain also surfaces transport errors from IMDS, subprocess failures
        # from the CLI legs and ValueError for a malformed client id -- and every
        # one of them means the same thing to an operator: this app cannot prove
        # who it is to Azure. Naming a subset would let the rest become a 500.
        who = f"the user-assigned managed identity {client_id}" if client_id else \
            "DefaultAzureCredential (managed identity in Azure, `az login` locally)"
        raise ArmError(
            KIND_CREDENTIAL_UNAVAILABLE,
            f"could not obtain an Azure token with {who}. Azure resource discovery is "
            f"unavailable, so the lists on this page are UNKNOWN, not empty. In the "
            f"deployed app, attach a managed identity with the Reader role on the "
            f"subscription; on a developer machine, run `az login`.",
            status=503, detail=f"{type(exc).__name__}: {exc}") from exc
    expires = float(getattr(access, "expires_on", now)) - _TOKEN_MARGIN
    with _CRED_LOCK:
        _TOKENS[key] = (access.token, expires)
    return access.token


# --- transport ------------------------------------------------------------

def _http_client() -> httpx.Client:
    """The HTTP client for one discovery call.

    A factory rather than a module-level singleton, and the single seam the
    tests replace: `test_azure_discovery.py` swaps this for a client wired to an
    `httpx.MockTransport`, which means the parsing, pagination, filtering and
    error mapping below are the code under test rather than a re-implementation
    of them.
    """
    return httpx.Client(timeout=ARM_TIMEOUT)


def _arm_error_detail(response: httpx.Response) -> str:
    """ARM's own error text, if it sent any.

    ARM answers `{"error": {"code": "AuthorizationFailed", "message": "The client
    '...' does not have authorization to perform action ... over scope ..."}}`,
    and that message names the exact missing permission and the exact scope. It
    is the single most useful string in a discovery failure, so it is carried
    through to the operator instead of being replaced with "403".
    """
    try:
        body = response.json()
    except ValueError:
        return (response.text or "")[:500]
    err = body.get("error") if isinstance(body, dict) else None
    if isinstance(err, dict):
        code, message = err.get("code"), err.get("message")
        return f"{code}: {message}"[:500] if code or message else str(body)[:500]
    return str(body)[:500]


def _raise_for_status(response: httpx.Response, what: str) -> None:
    """Map an ARM status onto a typed failure. Never lets a non-2xx through.

    The mapping is deliberately NOT `status -> same status`: this endpoint's own
    403 means "you are not an admin of this product" and ARM's 403 means "this
    product's Azure identity has no Reader role". Returning 403 for both would
    put two unrelated problems, fixed by two different people, behind one number.
    """
    if response.is_success:
        return
    detail = _arm_error_detail(response)
    status = response.status_code
    if status == 401:
        raise ArmError(
            KIND_UNAUTHORIZED,
            f"Azure rejected this application's credentials while {what}. The token was "
            f"obtained but is not accepted for Azure Resource Manager -- check that the "
            f"identity is in the right tenant.",
            status=502, detail=detail)
    if status == 403:
        raise ArmError(
            KIND_FORBIDDEN,
            f"this application's Azure identity is not authorized to {what}. Grant it the "
            f"built-in `Reader` role on the subscription (or on the resource group) and "
            f"try again. Until then these lists are UNKNOWN, not empty.",
            status=502, detail=detail)
    if status == 404:
        raise ArmError(
            KIND_NOT_FOUND,
            f"Azure could not find what was asked for while {what}. Check the subscription, "
            f"resource group and account names.",
            status=404, detail=detail)
    if status == 429:
        raise ArmError(
            KIND_THROTTLED,
            f"Azure Resource Manager is throttling this application while {what}. Wait a "
            f"moment and retry.",
            status=429, detail=detail)
    raise ArmError(
        KIND_ERROR,
        f"Azure Resource Manager answered {status} while {what}.",
        status=502, detail=detail)


def _next_link(body: dict[str, Any], what: str) -> str | None:
    """The next page's URL, refused unless it is still Azure Resource Manager.

    `nextLink` is a fully-qualified URL chosen by the SERVER, and the loop that
    follows it attaches this application's ARM bearer token to every request it
    makes. Following it without checking the origin would mean a compromised or
    spoofed ARM response could name any host in the world and be handed a token
    that reads the customer's entire subscription. The check costs one string
    comparison and removes the whole class.

    Refusing is a typed failure, not a quiet stop: silently returning the pages
    fetched so far would be a truncated list presented as a complete one, which
    is this module's one prohibited outcome.
    """
    link = (body.get("nextLink") or "").strip()
    if not link:
        return None
    origin = settings.AZURE_ARM_ENDPOINT.rstrip("/")
    if link == origin or link.startswith(origin + "/") or link.startswith(origin + "?"):
        return link
    raise ArmError(
        KIND_BAD_RESPONSE,
        f"Azure Resource Manager returned a continuation link pointing somewhere other than "
        f"{origin} while {what}, so the listing was stopped rather than followed. The result "
        f"you would otherwise have seen would be incomplete.",
        status=502, detail=link[:200])


def _get_pages(path: str, params: dict[str, str], *, client_id: str | None,
               what: str, limit: int, state: dict[str, Any] | None = None,
               ) -> Iterator[dict[str, Any]]:
    """GET an ARM list endpoint, following `nextLink`, yielding raw items.

    Bounded three ways and every bound is observable: `limit` items, `MAX_PAGES`
    pages, and `ARM_TIMEOUT` on every request. A truncated listing logs a warning
    naming the bound that stopped it AND records it in `state`, which the API
    layer turns into a response header -- so an operator whose resource group is
    missing from a dropdown has something to read rather than an absence to
    interpret. Truncation is measured HERE, on the raw ARM items, because a
    caller that filters (`list_ai_accounts` drops non-inference kinds) can return
    fewer than `limit` rows from a listing that really was cut short, and
    `len(result) >= limit` would then miss it.
    """
    token = _token(client_id)
    url: str | None = f"{settings.AZURE_ARM_ENDPOINT}{path}"
    query: dict[str, str] | None = params
    seen = 0
    pages = 0
    with _http_client() as client:
        while url and pages < MAX_PAGES:
            pages += 1
            try:
                response = client.get(url, params=query,
                                      headers={"Authorization": f"Bearer {token}",
                                               "Accept": "application/json"})
            except httpx.TimeoutException as exc:
                raise ArmError(
                    KIND_TIMEOUT,
                    f"Azure Resource Manager did not respond within {ARM_TIMEOUT:g}s while "
                    f"{what}.",
                    status=504, detail=f"{type(exc).__name__}: {exc}") from exc
            except httpx.HTTPError as exc:
                raise ArmError(
                    KIND_UNREACHABLE,
                    f"could not reach Azure Resource Manager while {what}. Check this "
                    f"deployment's outbound network access to "
                    f"{settings.AZURE_ARM_ENDPOINT}.",
                    status=502, detail=f"{type(exc).__name__}: {exc}") from exc
            _raise_for_status(response, what)
            try:
                body = response.json()
            except ValueError as exc:
                raise ArmError(
                    KIND_BAD_RESPONSE,
                    f"Azure Resource Manager returned a body that is not JSON while {what}.",
                    status=502, detail=(response.text or "")[:500]) from exc
            if not isinstance(body, dict) or not isinstance(body.get("value"), list):
                # A 200 whose shape is not the documented one is a failure, not
                # an empty list. Serving `[]` here is the same lie as serving it
                # for a 403: the question was never answered.
                raise ArmError(
                    KIND_BAD_RESPONSE,
                    f"Azure Resource Manager returned an unexpected shape while {what} "
                    f"(no `value` array). This usually means the pinned api-version is no "
                    f"longer served.",
                    status=502, detail=str(body)[:500])
            for item in body["value"]:
                if isinstance(item, dict):
                    yield item
                    seen += 1
                    if seen >= limit:
                        if state is not None:
                            state.update(truncated=True, bound="limit", limit=limit)
                        log.warning("azure discovery result truncated at the item limit",
                                    extra={"event": "azure_discovery_truncated", "what": what,
                                           "limit": limit, "bound": "limit"})
                        return
            url = _next_link(body, what)
            query = None            # nextLink already carries the api-version and skip token
        if url:
            if state is not None:
                state.update(truncated=True, bound="pages", pages=pages)
            log.warning("azure discovery stopped following pagination at the page limit",
                        extra={"event": "azure_discovery_truncated", "what": what,
                               "pages": pages, "bound": "pages"})


def _clamp(limit: int | None) -> int:
    return max(1, min(int(limit or DEFAULT_LIMIT), MAX_LIMIT))


def _text(value: Any) -> str:
    """A JSON scalar as a string, with `None` becoming `""` rather than `"None"`."""
    return "" if value is None else str(value)


# --- the four listings ----------------------------------------------------

def list_subscriptions(*, client_id: str | None = None, limit: int | None = None,
                       state: dict[str, Any] | None = None) -> list[dict[str, str]]:
    """`[{id, name}]` for every subscription this application's identity can see.

    An empty list here is a real answer and a serious one: the credential
    authenticated but has no role assignment anywhere. `resolve_subscription`
    turns that into a typed error rather than letting it fall through as "no
    resource groups".
    """
    limit = _clamp(limit)
    out = []
    for item in _get_pages("/subscriptions", {"api-version": API_VERSION_SUBSCRIPTIONS},
                           client_id=client_id, what="listing subscriptions", limit=limit,
                           state=state):
        sub_id = _text(item.get("subscriptionId"))
        if not sub_id:
            continue
        out.append({"id": sub_id,
                    "name": _text(item.get("displayName")) or sub_id,
                    "state": _text(item.get("state"))})
    return out


def resolve_subscription(explicit: str | None = None, *, client_id: str | None = None) -> str:
    """Which subscription discovery should enumerate, in a stated order.

    1. what the caller asked for (the Configuration page's subscription picker);
    2. `AZURE_SUBSCRIPTION_ID` from the environment, for a deployment that is
       pinned to one;
    3. the only subscription the identity can see.

    Step 3 stops at "the only": with several visible there is no defensible
    guess, and quietly picking the first would enumerate somebody else's estate
    and then report the operator's own Foundry account as missing. Zero visible
    is a typed error naming the missing role assignment, which is the difference
    between "you have no resource groups" and "this app cannot see them".
    """
    if explicit:
        return _check(explicit, _SUBSCRIPTION_RE, "subscription", "subscription id (a GUID)")
    if settings.AZURE_SUBSCRIPTION_ID:
        return _check(settings.AZURE_SUBSCRIPTION_ID, _SUBSCRIPTION_RE,
                      "AZURE_SUBSCRIPTION_ID", "subscription id (a GUID)")
    subs = list_subscriptions(client_id=client_id)
    if not subs:
        raise ArmError(
            KIND_NO_SUBSCRIPTIONS,
            "this application's Azure identity authenticated but can see no subscriptions, "
            "which means it holds no role assignment. Grant it `Reader` on the subscription "
            "that owns your Azure AI Foundry account, or set AZURE_SUBSCRIPTION_ID.",
            status=502)
    if len(subs) > 1:
        names = ", ".join(f"{s['name']} ({s['id']})" for s in subs[:10])
        raise ArmError(
            KIND_SUBSCRIPTION_AMBIGUOUS,
            f"this application's Azure identity can see {len(subs)} subscriptions, so there "
            f"is no single one to enumerate. Choose one, or set AZURE_SUBSCRIPTION_ID. "
            f"Visible: {names}.",
            status=400)
    return subs[0]["id"]


def list_resource_groups(subscription: str, *, client_id: str | None = None,
                         limit: int | None = None,
                         state: dict[str, Any] | None = None) -> list[dict[str, str]]:
    """`[{name, location}]` for one subscription."""
    sub = _check(subscription, _SUBSCRIPTION_RE, "subscription", "subscription id (a GUID)")
    limit = _clamp(limit)
    out = []
    for item in _get_pages(f"/subscriptions/{quote(sub, safe='')}/resourcegroups",
                           {"api-version": API_VERSION_RESOURCE_GROUPS},
                           client_id=client_id,
                           what=f"listing the resource groups in subscription {sub}",
                           limit=limit, state=state):
        name = _text(item.get("name"))
        if not name:
            continue
        out.append({"name": name, "location": _text(item.get("location"))})
    out.sort(key=lambda r: r["name"].lower())
    return out


def _account_endpoint(props: dict[str, Any], name: str) -> str:
    """The data-plane endpoint to store for an account.

    `properties.endpoint` is the account's own host and the one the shared
    contract stores -- `https://<account>.cognitiveservices.azure.com/`. The
    `properties.endpoints` MAP is deliberately not consulted: on the live
    AIServices account it holds FORTY-SIX entries across three different hosts
    (`.services.ai.azure.com`, `.openai.azure.com`, `.cognitiveservices.azure.com`),
    keyed by human-readable capability names like "OpenAI Whisper API", and
    picking among them is a guess about which API the chosen deployment speaks.
    The classic `{endpoint}/openai/deployments/{deployment}/chat/completions`
    route works on the account host for every deployment on it, including the
    non-OpenAI-format ones, so the account host is the answer that needs no guess.

    The `customSubDomainName` fallback covers an account that is still
    provisioning, where `endpoint` is briefly absent.
    """
    endpoint = _text(props.get("endpoint")).strip()
    if endpoint:
        return endpoint
    subdomain = _text(props.get("customSubDomainName")).strip() or name
    return f"https://{subdomain}.cognitiveservices.azure.com/" if subdomain else ""


def list_ai_accounts(subscription: str, resource_group: str, *, client_id: str | None = None,
                     limit: int | None = None,
                     state: dict[str, Any] | None = None) -> list[dict[str, str]]:
    """`[{name, endpoint, kind, location}]` for the INFERENCE-capable Cognitive
    Services accounts in one resource group.

    Non-inference kinds (Speech, Vision, Language, ContentSafety, FormRecognizer,
    ...) are dropped -- see `INFERENCE_KINDS`. The filter is applied here rather
    than in the UI so that "which of my resources can host a model?" is answered
    once, by the layer that knows, instead of being an operator's problem.
    """
    sub = _check(subscription, _SUBSCRIPTION_RE, "subscription", "subscription id (a GUID)")
    rg = _check(resource_group, _RESOURCE_GROUP_RE, "resource_group", "resource group name")
    limit = _clamp(limit)
    path = (f"/subscriptions/{quote(sub, safe='')}/resourceGroups/{quote(rg, safe='')}"
            f"/providers/Microsoft.CognitiveServices/accounts")
    out = []
    for item in _get_pages(path, {"api-version": API_VERSION_COGNITIVE}, client_id=client_id,
                           what=f"listing the Azure AI accounts in resource group {rg}",
                           limit=limit, state=state):
        kind = _text(item.get("kind"))
        if kind.lower() not in INFERENCE_KINDS:
            continue
        name = _text(item.get("name"))
        if not name:
            continue
        props = item.get("properties") if isinstance(item.get("properties"), dict) else {}
        out.append({
            "name": name,
            "endpoint": _account_endpoint(props, name),
            "kind": kind,
            "location": _text(item.get("location")),
            # Not part of the contract's four keys, and not filtered on: an
            # account that is still provisioning is a real account the operator
            # is probably waiting for, and hiding it would be the empty-dropdown
            # lie again. Carried so the UI can say why a pick might not work yet.
            "provisioning_state": _text(props.get("provisioningState")),
        })
    out.sort(key=lambda a: a["name"].lower())
    return out


def list_deployments(subscription: str, resource_group: str, account: str, *,
                     client_id: str | None = None, limit: int | None = None,
                     state: dict[str, Any] | None = None) -> list[dict[str, Any]]:
    """`[{name, model, version, sku}]` for one account's model deployments.

    `name` is the DEPLOYMENT name -- what goes in `azure_deployment` and into the
    request path -- and `model` is what it is a deployment OF. They are often
    different, which is precisely why this dropdown exists rather than a text
    box: on the live account they happen to coincide (`Mistral-Large-3` is a
    deployment of `Mistral-Large-3`), and an operator who learns the habit from
    that account and then types `gpt-4o` for a deployment called `gpt4o-prod`
    gets a 404 on every model call.

    Nothing is filtered out. A non-chat deployment (an embedding model, Whisper)
    is reported with its capabilities so the UI can mark it, because the
    alternative -- hiding it -- is indistinguishable from the deployment not
    existing, and this module's whole rule is that those two must never look the
    same.
    """
    sub = _check(subscription, _SUBSCRIPTION_RE, "subscription", "subscription id (a GUID)")
    rg = _check(resource_group, _RESOURCE_GROUP_RE, "resource_group", "resource group name")
    acct = _check(account, _ACCOUNT_RE, "account", "Cognitive Services account name")
    limit = _clamp(limit)
    path = (f"/subscriptions/{quote(sub, safe='')}/resourceGroups/{quote(rg, safe='')}"
            f"/providers/Microsoft.CognitiveServices/accounts/{quote(acct, safe='')}/deployments")
    out = []
    for item in _get_pages(path, {"api-version": API_VERSION_COGNITIVE}, client_id=client_id,
                           what=f"listing the model deployments on account {acct}", limit=limit,
                           state=state):
        name = _text(item.get("name"))
        if not name:
            continue
        props = item.get("properties") if isinstance(item.get("properties"), dict) else {}
        model = props.get("model") if isinstance(props.get("model"), dict) else {}
        sku = item.get("sku") if isinstance(item.get("sku"), dict) else {}
        caps = props.get("capabilities") if isinstance(props.get("capabilities"), dict) else {}
        out.append({
            "name": name,
            "model": _text(model.get("name")),
            "version": _text(model.get("version")),
            "sku": _text(sku.get("name")),
            # Additive, all documented above: the model FORMAT ("Mistral AI",
            # "MoonshotAI", "OpenAI") tells the operator what they picked, the
            # provisioning state tells them whether it is live yet, and `chat`
            # is how the UI can mark a deployment that cannot serve this
            # product's calls without hiding it.
            "format": _text(model.get("format")),
            "capacity": int(sku.get("capacity") or 0),
            "provisioning_state": _text(props.get("provisioningState")),
            "chat": _text(caps.get("chatCompletion")).lower() == "true",
        })
    out.sort(key=lambda d: d["name"].lower())
    return out


def kinds_filtered_out(items: Iterable[dict[str, Any]]) -> list[str]:
    """The `kind`s dropped by `list_ai_accounts`, for logging and for tests.

    Kept as a function rather than inlined so the filter's effect is inspectable:
    "we hid four of your seven Cognitive Services resources" is a claim that
    should be checkable, not folded into a list comprehension.
    """
    return sorted({_text(i.get("kind")) for i in items
                   if _text(i.get("kind")).lower() not in INFERENCE_KINDS})
