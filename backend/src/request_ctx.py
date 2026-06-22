"""Per-request actor context (role + email), carried in a ContextVar.

The backend sits behind the Next.js auth proxy, which injects `x-ztpa-role` and
`x-ztpa-email` headers (see frontend/middleware.ts). A FastAPI middleware reads
those headers and stashes them here so deep code paths -- metric recording,
per-role tool enforcement -- can attribute work to a role/user without threading
the request object everywhere. Defaults to a least-privileged anonymous actor
when absent (e.g. CLI scripts, direct backend access)."""

from __future__ import annotations

import contextvars
from dataclasses import dataclass

VALID_ROLES = ("admin", "analyst", "viewer")


@dataclass(frozen=True)
class Actor:
    role: str = "viewer"      # least-privileged default
    email: str | None = None


_ctx: contextvars.ContextVar[Actor] = contextvars.ContextVar("ztpa_actor", default=Actor())


def set_actor(role: str | None, email: str | None) -> None:
    r = (role or "").strip().lower()
    if r not in VALID_ROLES:
        r = "viewer"
    _ctx.set(Actor(role=r, email=(email or None)))


def current() -> Actor:
    return _ctx.get()


def role() -> str:
    return _ctx.get().role
