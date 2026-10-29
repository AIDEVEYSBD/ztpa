"""Per-request actor context (role + email + SSO subject) and the proxy trust
boundary, carried in ContextVars.

The backend sits behind the Next.js auth proxy, which injects `x-npr-role`,
`x-npr-email` and `x-npr-sub` headers (see frontend/middleware.ts). The role is
resolved there from the AutoX `autox:app_roles` claim on the current access
token; `x-npr-sub` is the AutoX `sub` -- the stable user key (emails can be
reused across recreated accounts, `sub` cannot). A FastAPI middleware reads those
headers and stashes them here so deep code paths -- metric recording, per-role
tool enforcement -- can attribute work without threading the request object
everywhere. Defaults to a least-privileged anonymous actor when absent (e.g. CLI
scripts, direct backend access).

THE TRUST BOUNDARY. This backend does not validate AutoX tokens; it believes the
`x-npr-*` headers. That is only sound if nothing but the proxy can set them, and
the shipped Render blueprint deploys the API as a public web service -- so
"keep it private" was a deployment convention, not a control. `NPR_PROXY_SECRET`
turns it into one:

  * SET (production): every request must present the same value in
    `x-npr-proxy-secret`. `_ActorMiddleware` compares it with
    `hmac.compare_digest` and answers 401 without it.
  * UNSET (local dev, and any deployment that has not configured it): behaviour
    is exactly as before -- the headers are trusted as-is -- but `/api/health`
    reports `proxy_auth: false` so the gap is visible on the status payload
    instead of being an undocumented assumption.

THE SECRET AUTHENTICATES THE REQUEST, NOT THE CLAIM. This is the correction a
five-lens security review forced, and the distinction is the whole control. The
first implementation demanded the secret only from a request that *claimed* an
identity (`if claims_identity and not verify(...)`), on the reasoning that a
request claiming nothing has nothing to forge. But the anonymous default is not
"no access" -- it is `Actor(role="viewer")`, a real principal that reads every
finding, every rule, the whole asset inventory and the reachability graph of the
customer's network. So with the secret correctly configured and the proxy
correctly forwarding it, `curl https://api.example.com/api/findings` with NO
HEADERS AT ALL still got a full answer: the control that the entire Phase 0
authorization model rests on had a hole exactly the shape of sending nothing.

A request is now refused unless it presents the secret, whatever it claims. Two
exemptions, both narrow and both listed in `UNAUTHENTICATED_PATHS` /
`secret_required_for` below rather than scattered through the middleware:

  * `/api/live` -- the platform's liveness probe (render.yaml healthCheckPath).
    Render cannot be given the secret, and a probe that 401s restart-loops a
    healthy process. It returns `{"status": "alive"}` and touches nothing.
  * CORS preflight (`OPTIONS`) -- a browser sends no custom headers on a
    preflight by design, so requiring one would make every cross-origin call
    fail at the preflight, before the request that carries the secret is ever
    sent. A preflight carries no credentials and reaches no handler; it is
    answered by CORSMiddleware with headers only. A preflight that nonetheless
    CLAIMS an identity is still refused -- exempting the blanket requirement is
    not the same as trusting a forged header.

The proxy still strips any client-supplied `x-npr-*` headers before setting its
own; the shared secret is what makes that stripping non-bypassable by talking to
the backend directly."""

from __future__ import annotations

import contextvars
import hmac
import os
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Iterator

VALID_ROLES = ("admin", "analyst", "viewer")

# Header the proxy uses to prove it *is* the proxy, and the prefix whose presence
# means a request is claiming an identity (and therefore needs that proof).
PROXY_SECRET_HEADER = "x-npr-proxy-secret"
ACTOR_HEADER_PREFIX = "x-npr-"

# The only paths served without the shared secret while the boundary is enforced.
# Deliberately a frozenset of exact paths, not a prefix match: "/api/live" must
# not admit "/api/livewire" or "/api/live/../findings" through a startswith().
UNAUTHENTICATED_PATHS = frozenset({"/api/live"})


@dataclass(frozen=True)
class Actor:
    role: str = "viewer"      # least-privileged default
    email: str | None = None
    sub: str | None = None    # AutoX `sub` (stable identity key)


_ctx: contextvars.ContextVar[Actor] = contextvars.ContextVar("npr_actor", default=Actor())
_request_id: contextvars.ContextVar[str | None] = contextvars.ContextVar("npr_request_id", default=None)
# True while background work acts for the person who started it (acting_as).
_on_behalf: contextvars.ContextVar[bool] = contextvars.ContextVar("npr_on_behalf", default=False)


def set_actor(role: str | None, email: str | None, sub: str | None = None) -> None:
    r = (role or "").strip().lower()
    if r not in VALID_ROLES:
        r = "viewer"
    _ctx.set(Actor(role=r, email=(email or None), sub=(sub or None)))


def current() -> Actor:
    return _ctx.get()


@contextmanager
def acting_as(sub: str | None = None, email: str | None = None) -> Iterator[None]:
    """Background work (a job) done for the person who requested it: what it
    writes is attributed to them, and audit rows record it as agent work on
    their behalf (`on_behalf()`), with no role claimed -- the job never checked
    one. Restores the previous identity on exit, so a worker thread running many
    jobs cannot carry one requester's identity into the next job."""
    t1 = _ctx.set(Actor(email=(email or None), sub=(sub or None)))
    t2 = _on_behalf.set(bool(sub or email))
    try:
        yield
    finally:
        _on_behalf.reset(t2)
        _ctx.reset(t1)


def on_behalf() -> bool:
    return _on_behalf.get()


def role() -> str:
    return _ctx.get().role


def sub() -> str | None:
    return _ctx.get().sub


# --- request id ------------------------------------------------------------
# Minted (or accepted from the proxy) per request by _ActorMiddleware, echoed on
# the response as X-Request-Id and stamped on every log line + error body, so a
# user report ("the findings disappeared") maps to exactly one server-side trace.

def set_request_id(value: str | None) -> None:
    _request_id.set(value or None)


def request_id() -> str | None:
    return _request_id.get()


# --- proxy trust boundary --------------------------------------------------

def proxy_secret() -> str:
    """The configured shared secret, or "" when the boundary is unenforced.

    Read from the environment on every call rather than bound at import: the
    module is imported before `settings` has run load_dotenv() on some paths,
    and reading late also lets a test toggle the boundary with monkeypatch.
    """
    return (os.environ.get("NPR_PROXY_SECRET") or "").strip()


def proxy_auth_enabled() -> bool:
    """Whether the shared-secret boundary is actually being enforced. Surfaced on
    /api/health so an unconfigured deployment is visible rather than silent."""
    return bool(proxy_secret())


def verify_proxy_secret(presented: str | None) -> bool:
    """Constant-time comparison of the presented `x-npr-proxy-secret`.

    Returns True when the boundary is unconfigured (dev parity: the headers are
    trusted exactly as they were before this existed). `compare_digest` is used
    rather than `==` so a network attacker cannot recover the secret byte by byte
    from response timing."""
    expected = proxy_secret()
    if not expected:
        return True
    return hmac.compare_digest(presented or "", expected)


def secret_required_for(path: str, method: str) -> bool:
    """Must THIS request present the shared secret, whatever it claims?

    The answer for a configured boundary is "yes" for everything except the two
    exemptions the module docstring justifies: the platform liveness probe, and a
    CORS preflight. Unconfigured, always False -- dev and every deployment that
    has not set NPR_PROXY_SECRET behave exactly as they did before.

    Kept here, next to the docstring that explains it, rather than inline in the
    middleware: the shape of this predicate IS the trust boundary, and a test can
    ask it a question without standing up an ASGI app."""
    if not proxy_auth_enabled():
        return False
    if method.upper() == "OPTIONS":
        return False
    return path not in UNAUTHENTICATED_PATHS
