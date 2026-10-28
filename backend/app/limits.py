"""Request-size and rate limits for the API.

`BodyLimitMiddleware` refuses an oversized body before the app parses it:
from the Content-Length header when one is sent, and by reading up to the cap
when it is not (chunked), so a client cannot get around the cap by leaving the
header off. Paths under `STREAMED_PATH_PREFIXES` are exempt; they enforce
their own, larger caps while streaming to object storage.

`LLM_LIMITED` is the dependency list for every route that makes a model call.
"""

from __future__ import annotations

import json

from fastapi import Depends, HTTPException

from src import ratelimit, request_ctx, settings

STREAMED_PATH_PREFIXES: tuple[str, ...] = ("/api/exports",)


def _reject(limit: int) -> tuple[dict, bytes]:
    body = json.dumps({"detail": f"request body exceeds {limit} bytes",
                       "error": f"request body exceeds {limit} bytes",
                       "request_id": request_ctx.request_id()}).encode()
    head = {"type": "http.response.start", "status": 413,
            "headers": [(b"content-type", b"application/json"),
                        (b"content-length", str(len(body)).encode())]}
    return head, body


class BodyLimitMiddleware:
    def __init__(self, app, max_bytes: int | None = None) -> None:
        self.app = app
        self.max_bytes = max_bytes

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http" or scope.get("path", "").startswith(STREAMED_PATH_PREFIXES):
            return await self.app(scope, receive, send)
        limit = self.max_bytes or settings.NPR_MAX_BODY_BYTES
        declared = dict(scope.get("headers") or []).get(b"content-length")
        if declared is not None and declared.isdigit() and int(declared) > limit:
            head, body = _reject(limit)
            await send(head)
            await send({"type": "http.response.body", "body": body})
            return
        if declared is not None and declared.isdigit():
            return await self.app(scope, receive, send)   # length is known and within the cap
        # No length declared (chunked): read up to the cap here, then replay it.
        # Bounded by `limit`, so buffering costs at most one capped body.
        chunks, seen = [], 0
        while True:
            message = await receive()
            if message["type"] != "http.request":
                return                                    # client went away
            chunk = message.get("body", b"")
            seen += len(chunk)
            if seen > limit:
                head, body = _reject(limit)
                await send(head)
                await send({"type": "http.response.body", "body": body})
                return
            chunks.append(chunk)
            if not message.get("more_body", False):
                break
        replayed = False

        async def replay():
            nonlocal replayed
            if not replayed:
                replayed = True
                return {"type": "http.request", "body": b"".join(chunks), "more_body": False}
            return await receive()

        await self.app(scope, replay, send)


def _actor_key() -> str | None:
    a = request_ctx.current()
    return a.sub or a.email


def llm_rate_limit() -> None:
    d = ratelimit.hit("llm", _actor_key(),
                      per_identity=settings.NPR_RATE_LLM_PER_IDENTITY,
                      per_deployment=settings.NPR_RATE_LLM_PER_DEPLOYMENT)
    if not d.allowed:
        who = "you have" if d.scope == "identity" else "this deployment has"
        raise HTTPException(
            429, f"{who} reached the limit of {d.limit} model-backed requests per minute; "
                 f"retry in {d.retry_after_s}s",
            headers={"Retry-After": str(d.retry_after_s)})


LLM_LIMITED = [Depends(llm_rate_limit)]
