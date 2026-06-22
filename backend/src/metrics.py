"""Record one row per AI / agent-tool invocation into ztpa.ai_metrics.

Fail-closed: a metric write must never break the call it measures, so every DB
touch is wrapped and swallowed. Reads the actor (role/email) from request_ctx so
usage is attributable per-role for the admin dashboards. Cost is computed from
the per-MTok price map in config (local Ollama = $0)."""

from __future__ import annotations

from . import config, request_ctx
from .db import get_conn, insert


def record_metric(
    *,
    kind: str,                       # llm | agent_tool | embed
    capability: str,
    provider: str | None = None,
    model: str | None = None,
    latency_ms: int | None = None,
    prompt_tokens: int = 0,
    completion_tokens: int = 0,
    ok: bool = True,
    error: str | None = None,
    tool_name: str | None = None,
    snapshot_id: str | None = None,
    subject: str | None = None,
) -> None:
    actor = request_ctx.current()
    total = (prompt_tokens or 0) + (completion_tokens or 0)
    cost = config.est_cost_usd(provider or "", model or "", prompt_tokens or 0, completion_tokens or 0)
    try:
        with get_conn() as conn, conn.cursor() as cur:
            insert(cur, "ai_metrics", {
                "kind": kind,
                "capability": capability,
                "tool_name": tool_name or capability,
                "provider": provider,
                "model": model,
                "role": actor.role,
                "actor_email": actor.email,
                "latency_ms": latency_ms,
                "prompt_tokens": prompt_tokens or 0,
                "completion_tokens": completion_tokens or 0,
                "total_tokens": total,
                "est_cost_usd": cost,
                "ok": ok,
                "error": (error or None) and str(error)[:500],
                "snapshot_id": snapshot_id,
                "subject": subject,
            })
    except Exception:
        pass  # metrics are best-effort; never break the measured call
