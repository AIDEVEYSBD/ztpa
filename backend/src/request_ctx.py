"""Per-request actor context (role + email + SSO subject), carried in a ContextVar.

The backend sits behind the Next.js auth proxy, which injects `x-npr-role`,
`x-npr-email` and `x-npr-sub` headers (see frontend/middleware.ts). The role is
resolved there from the AutoX `autox:app_roles` claim on the current access
token; `x-npr-sub` is the AutoX `sub` -- the stable user key (emails can be
reused across recreated accounts, `sub` cannot). A FastAPI middleware reads those
headers and stashes them here so deep code paths -- metric recording, per-role
tool enforcement -- can attribute work without threading the request object
everywhere. Defaults to a least-privileged anonymous actor when absent (e.g. CLI
scripts, direct backend access).

The proxy strips any client-supplied `x-npr-*` headers before setting its own, so
this backend must stay private (reachable only through the proxy); it does not
independently validate AutoX tokens."""

from __future__ import annotations

import contextvars
from dataclasses import dataclass

VALID_ROLES = ("admin", "analyst", "viewer")


@dataclass(frozen=True)
class Actor:
    role: str = "viewer"      # least-privileged default
    email: str | None = None
    sub: str | None = None    # AutoX `sub` (stable identity key)


_ctx: contextvars.ContextVar[Actor] = contextvars.ContextVar("npr_actor", default=Actor())


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
