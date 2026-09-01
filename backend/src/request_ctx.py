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

  * SET (production): the proxy must present the same value in
    `x-npr-proxy-secret`. `_ActorMiddleware` compares it with
    `hmac.compare_digest` and rejects any request carrying an `x-npr-*` header
    without a valid secret with 401 -- so a forged role header from the open
    internet is refused rather than believed.
  * UNSET (local dev, and any deployment that has not configured it): behaviour
    is exactly as before -- the headers are trusted as-is -- but `/api/health`
    reports `proxy_auth: false` so the gap is visible on the status payload
    instead of being an undocumented assumption.

The proxy still strips any client-supplied `x-npr-*` headers before setting its
own; the shared secret is what makes that stripping non-bypassable by talking to
the backend directly."""

from __future__ import annotations

import contextvars
import hmac
import os
from dataclasses import dataclass

VALID_ROLES = ("admin", "analyst", "viewer")

# Header the proxy uses to prove it *is* the proxy, and the prefix whose presence
# means a request is claiming an identity (and therefore needs that proof).
PROXY_SECRET_HEADER = "x-npr-proxy-secret"
ACTOR_HEADER_PREFIX = "x-npr-"


@dataclass(frozen=True)
class Actor:
    role: str = "viewer"      # least-privileged default
    email: str | None = None
    sub: str | None = None    # AutoX `sub` (stable identity key)


_ctx: contextvars.ContextVar[Actor] = contextvars.ContextVar("npr_actor", default=Actor())
_request_id: contextvars.ContextVar[str | None] = contextvars.ContextVar("npr_request_id", default=None)


def set_actor(role: str | None, email: str | None, sub: str | None = None) -> None:
    r = (role or "").strip().lower()
    if r not in VALID_ROLES:
        r = "viewer"
    _ctx.set(Actor(role=r, email=(email or None), sub=(sub or None)))


def current() -> Actor:
    return _ctx.get()


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
