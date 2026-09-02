"""Record one row per AI / agent-tool invocation into ztpa.ai_metrics.

Fail-closed: a metric write must never break the call it measures, so every DB
touch is wrapped and swallowed. Reads the actor (role/email) from request_ctx so
usage is attributable per-role for the admin dashboards. Cost is computed from
the per-MTok price map in config (local Ollama = $0).

SWALLOWED IS NOT THE SAME AS UNRECORDED
---------------------------------------
Swallowing is still right -- nobody should lose an answer because the telemetry
table is unreachable -- but `except Exception: pass` made the admin AI-usage
dashboard unfalsifiable: "0 calls today" read identically for a quiet Sunday and
for a metrics sink that has rejected every insert since the last deploy, and the
cost ceiling Phase 4 wants to enforce would be computed from a table silently
missing rows. Every drop now emits one structured line naming the failure, so
the dashboard's number can be checked against the log instead of trusted.

Two states are separated because they have different fixes: the sink is not
CONFIGURED (no DATABASE_URL -- the state this repo ships in, and a deployment
mistake rather than a runtime fault) and the sink FAILED. The first is reported
once per process; the second every time, because each occurrence is a row that
no longer exists."""

from __future__ import annotations

import logging
import sys

from . import config, db, request_ctx
from .db import get_conn, insert

# Child of the API logger; see advisory/client.py for the convention.
log = logging.getLogger("npr.api.metrics")

# One line per process for the unconfigured case: it cannot change without a
# restart, so repeating it on every model call would be noise that buries the
# genuine write failures below it.
_UNCONFIGURED_REPORTED = False


def _report_drop(exc: BaseException, *, kind: str, capability: str, tool_name: str) -> None:
    """One structured line per dropped metric row -- see the module docstring."""
    global _UNCONFIGURED_REPORTED
    if not db.DATABASE_URL:
        if _UNCONFIGURED_REPORTED:
            return
        _UNCONFIGURED_REPORTED = True
        log.warning("no metrics sink configured; AI usage, cost and per-role attribution "
                    "will read as zero for this process",
                    extra={"event": "metric_sink_unconfigured", "error": str(exc)})
        return
    log.warning("metric row dropped; the AI usage dashboard is undercounting", exc_info=True,
                extra={"event": "metric_write_failed", "kind": kind, "capability": capability,
                       "tool_name": tool_name, "error": f"{type(exc).__name__}: {exc}"})


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
    except Exception as exc:  # noqa: BLE001
        # Deliberately broad, and it stays broad: this function wraps an
        # arbitrary driver stack (psycopg, the pool, TLS, DNS) whose failure
        # modes are not enumerable here, and its ONE job is to never propagate
        # into the call it measures. Narrowing would trade a logged dropped
        # metric for a 500 on a working answer, which is the wrong bargain.
        try:
            _report_drop(exc, kind=kind, capability=capability,
                         tool_name=tool_name or capability)
        except Exception as report_error:  # noqa: BLE001
            # The module promises that a metrics problem never costs the caller
            # its answer, and this workstream put a log call on that path -- so
            # the REPORTING now has to honour the promise too. `logging` does not
            # guarantee it: `Handler.handle` calls `emit` directly, and only the
            # stdlib handlers wrap themselves in the `handleError` convention, so
            # a third-party sink that raises would propagate straight through a
            # working request. stderr is the same last resort `handleError`
            # itself falls back to. If stderr is gone too the exception escapes,
            # which is the honest end of the line rather than another layer.
            print(f"npr: metric drop could not be reported: {report_error!r}",
                  file=sys.stderr)
