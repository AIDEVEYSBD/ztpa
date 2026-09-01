"""Network Policy Reviewer API.

Dashboard reads come from Postgres (the precomputed snapshot, the system of
record). Live LLM/agent calls (explain, classify, ask, remediate, report,
suggest, connector-authoring) run on demand. The deterministic engine is held in
memory for live reachability/simulation (identical data to the persisted snapshot).
"""

from __future__ import annotations

import contextlib
import json
import logging
import os
import sys
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))  # backend root

from fastapi import Depends, FastAPI, HTTPException, Query, Request  # noqa: E402
from fastapi.middleware.cors import CORSMiddleware  # noqa: E402
from fastapi.responses import JSONResponse  # noqa: E402
from psycopg.types.json import Jsonb  # noqa: E402
from pydantic import BaseModel, Field  # noqa: E402
from starlette.exceptions import HTTPException as StarletteHTTPException  # noqa: E402

from src import request_ctx, settings, tools_registry  # noqa: E402
from src.advisory import authoring, campaign as campaign_mod, classify_change, entity_suggest, explain as explain_mod  # noqa: E402
from src.advisory import intake as intake_mod, orchestrator, rank as rank_mod, remediation, report as report_mod  # noqa: E402
from src.advisory.client import provider_status  # noqa: E402
from src.agent.assistant import ask as agent_ask  # noqa: E402
from src.analyzers.run_all import EngineResult, reanalyze, run  # noqa: E402
from src.change import staging as staging_mod  # noqa: E402
from src.change.requests import DEMO_REQUESTS  # noqa: E402
from src.change.simulate import simulate_change  # noqa: E402
from src.scenarios import SCENARIOS, write_scenario  # noqa: E402
from src.db import audit, delete_snapshot_children, fetch_all, fetch_one, get_conn, ping, upsert  # noqa: E402
from src.graph.zones import zone_of  # noqa: E402
from src.ids import det_id  # noqa: E402
from src.models import ChangeRequest, RankedAction, RankedActions  # noqa: E402
from src.persist import (  # noqa: E402
    accept_remediation_revision, cache_explanation, delete_asset_merge, ensure_change_request_status,
    asset_rows, canonical_rule_rows, correlation_rows, finding_rows, graph_edge_rows,
    graph_node_rows, load_applied_changes, load_asset_merges,
    load_campaign_plan, load_remediation_thread, persist_asset_merge, persist_campaign_plan,
    persist_change_decision, persist_engine_result, persist_ranked_actions, persist_remediation_revision,
    persist_staged_change, reject_change_request, reset_change_workflow, resolved_object_rows,
    snapshot_counts, snapshot_row,
)

# --- structured logging ----------------------------------------------------
# The audit's finding was "zero logging statements in ~6,500 LOC": every failure
# that changed the answer was swallowed by `except Exception: pass`, so a user
# reporting "the findings disappeared" left nothing to investigate with. One
# stdlib JSON formatter (no new dependency) gives every line a request id, the
# actor and the event name, which is what makes the swallowed paths below
# observable instead of merely non-fatal.

class _JsonFormatter(logging.Formatter):
    """One JSON object per line: greppable in Render's log stream and parseable
    by any collector, without pulling in structlog. Extra fields set via
    `logger.warning(..., extra={...})` are merged in; the request id and actor
    are read from request_ctx at format time (same context as the call site)."""

    _SKIP = frozenset(logging.LogRecord("", 0, "", 0, "", (), None).__dict__) | {"message", "asctime", "taskName"}

    def format(self, record: logging.LogRecord) -> str:
        payload: dict = {
            "ts": datetime.fromtimestamp(record.created, tz=timezone.utc).isoformat(timespec="milliseconds"),
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
        }
        rid = request_ctx.request_id()
        if rid:
            payload["request_id"] = rid
        actor = request_ctx.current()
        payload["role"] = actor.role
        if actor.email:
            payload["actor"] = actor.email
        payload.update({k: v for k, v in record.__dict__.items() if k not in self._SKIP})
        if record.exc_info:
            payload["exc"] = self.formatException(record.exc_info)
        return json.dumps(payload, default=str)


log = logging.getLogger("npr.api")
if not log.handlers:                       # idempotent: uvicorn reloads re-import this module
    _handler = logging.StreamHandler(sys.stdout)
    _handler.setFormatter(_JsonFormatter())
    log.addHandler(_handler)
    log.propagate = False                  # don't double-print through uvicorn's root handler
log.setLevel(os.environ.get("NPR_LOG_LEVEL", "INFO").upper())


@contextlib.asynccontextmanager
async def _lifespan(_app: FastAPI):
    """Startup/shutdown. A lifespan handler rather than @app.on_event, which is
    deprecated (and, with warnings-as-errors in pyproject.toml, fails the suite
    on import). The body resolves _warm_engine at call time, so it can live where
    it reads best -- next to engine()."""
    _warm_engine()
    yield


app = FastAPI(title="Network Policy Reviewer", version="1.0", lifespan=_lifespan)
app.add_middleware(
    CORSMiddleware, allow_origins=[settings.FRONTEND_ORIGIN, "http://localhost:3000"],
    allow_methods=["*"], allow_headers=["*"], expose_headers=["x-request-id"],
)


class _ActorMiddleware:
    """Pure-ASGI middleware: mint the request id, ENFORCE the proxy trust boundary,
    then read the proxy-injected role/email headers and stash them in request_ctx
    so metric recording + per-role tool enforcement can attribute work. Set in the
    async context before the (threadpooled) endpoint runs, so anyio copies the
    values into the worker thread.

    The boundary: when NPR_PROXY_SECRET is configured, a request may only claim an
    identity (`x-npr-*`) if it also presents the secret -- otherwise 401, and the
    actor is never set from those headers. Unconfigured, the headers are trusted
    exactly as before and /api/health reports `proxy_auth: false`. See
    src/request_ctx.py for why this exists."""

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope.get("type") != "http":
            await self.app(scope, receive, send)
            return
        h = {k.decode("latin-1").lower(): v.decode("latin-1") for k, v in scope.get("headers", [])}
        # Reuse the proxy's id when it set one, so a single request has one id
        # end to end; otherwise mint one.
        rid = (h.get("x-request-id") or "").strip()[:64] or uuid.uuid4().hex
        request_ctx.set_request_id(rid)
        request_ctx.set_actor(None, None, None)   # reset: contextvars outlive a pooled worker

        claims_identity = any(k.startswith(request_ctx.ACTOR_HEADER_PREFIX) for k in h)
        if claims_identity and not request_ctx.verify_proxy_secret(h.get(request_ctx.PROXY_SECRET_HEADER)):
            log.warning("rejected forged actor headers", extra={
                "event": "proxy_auth_failed", "path": scope.get("path"),
                "client": (scope.get("client") or ("-",))[0]})
            response = JSONResponse(
                status_code=401,
                content={"detail": "invalid or missing proxy secret", "error": "invalid or missing proxy secret",
                         "request_id": rid},
                headers={"x-request-id": rid})
            await response(scope, receive, send)
            return
        request_ctx.set_actor(h.get("x-npr-role"), h.get("x-npr-email"), h.get("x-npr-sub"))

        async def _send(message):
            if message["type"] == "http.response.start":
                headers = list(message.get("headers") or [])
                headers.append((b"x-request-id", rid.encode("latin-1")))
                message["headers"] = headers
            await send(message)

        await self.app(scope, receive, _send)


app.add_middleware(_ActorMiddleware)


# --- authorization ---------------------------------------------------------
# Three role gates, attached as FastAPI dependencies so they run BEFORE the
# endpoint body (and before any DB work) and cannot be forgotten on a branch --
# which is how nine mutating routes shipped with no guard at all.
#
#   approver (admin|analyst) -- governance: plan/submit/stage/reject a change.
#     The same set that could already approve an escalation in stage_change.
#   operator (admin)         -- changes the system of record itself: recompute
#     and re-persist a snapshot, merge/unmerge identities, push to a data source.
_APPROVER_ROLES = ("admin", "analyst")
_OPERATOR_ROLES = ("admin",)


def require_admin() -> None:
    if request_ctx.role() != "admin":
        raise HTTPException(403, "admin only")


def require_approver() -> None:
    """Governance actions: proposing, approving, staging or declining a change."""
    if request_ctx.role() not in _APPROVER_ROLES:
        raise HTTPException(403, "approver role required (admin or analyst)")


def require_operator() -> None:
    """Actions that mutate the system of record or reach a data source."""
    if request_ctx.role() not in _OPERATOR_ROLES:
        raise HTTPException(403, "operator role required (admin)")


def _require_capability(key: str) -> None:
    """403 a disabled AI capability for the caller's role (fail-closed).

    NOT an authorization layer: an absent tool_settings row defaults to every
    role, so this is a feature toggle. The require_* dependencies above are what
    gate a mutating route."""
    if not tools_registry.is_enabled(key):
        raise HTTPException(403, f"capability '{key}' is disabled for role {request_ctx.role()}")

_ENGINE: EngineResult | None = None
_DEFAULT_SCENARIO = "demo"
_ACTIVE_SCENARIO = _DEFAULT_SCENARIO

# What the last engine build could and could not do. Read by /api/health so a
# degraded snapshot is reported rather than served as if it were authoritative.
_ENGINE_STATE: dict = {
    "inputs_ok": True,        # confirmed merges + pushed changes actually loaded
    "inputs_error": None,     # why they didn't, if they didn't
    "persisted": None,        # True/False/None(not attempted) for the active snapshot
    "persist_error": None,
    "build_error": None,      # the last engine BUILD that raised, if one did
}


def _run_label(scenario: str) -> str:
    """The snapshot LABEL to run a scenario under.

    `snapshot_id = snap_hash(label, content_fingerprint)`, so the label is half
    the cache key of everything keyed on a snapshot -- the AI explanation cache
    above all. scripts/precompute.py persists the default corpus under
    settings.DEFAULT_SNAPSHOT_LABEL ("seed-demo") while this API used to pass the
    raw scenario id ("demo"), so the two ends minted DIFFERENT snapshot ids over
    byte-identical data and not one precomputed explanation was ever served.
    Non-default scenarios keep their own label: they are a different corpus and
    precompute never wrote them."""
    return settings.DEFAULT_SNAPSHOT_LABEL if scenario == _DEFAULT_SCENARIO else scenario


def _load_merges() -> tuple[list[tuple[str, str]], bool]:
    """Human-confirmed asset merges, applied by the identity layer on every run.

    Returns (merges, loaded_ok). The flag matters more than the list: `[]` used to
    mean both "nothing confirmed" and "the DB was briefly unreachable", and the
    caller then recomputed the whole snapshot WITHOUT the operator's merges and
    persisted it as authoritative."""
    try:
        with get_conn() as conn, conn.cursor() as cur:
            return load_asset_merges(cur), True
    except Exception as exc:
        log.warning("confirmed asset merges could not be loaded", exc_info=True,
                    extra={"event": "load_merges_failed", "error": str(exc)})
        return [], False


def _load_applied() -> tuple[list[dict], bool]:
    """Operator-accepted changes (pushed from staging), re-applied to the records
    on every run so a recompute reflects the applied state. Returns
    (changes, loaded_ok) for the same reason as _load_merges."""
    try:
        with get_conn() as conn, conn.cursor() as cur:
            return load_applied_changes(cur), True
    except Exception as exc:
        log.warning("applied changes could not be loaded", exc_info=True,
                    extra={"event": "load_applied_failed", "error": str(exc)})
        return [], False


def _run_engine(scenario: str) -> EngineResult:
    """Run the deterministic engine for a scenario, recording on _ENGINE_STATE
    whether its two DB-backed inputs actually loaded. Every rebuild goes through
    here so no call site can quietly recompute on a truncated input set."""
    merges, merges_ok = _load_merges()
    applied, applied_ok = _load_applied()
    missing = [n for n, ok in (("confirmed merges", merges_ok), ("applied changes", applied_ok)) if not ok]
    _ENGINE_STATE.update(
        inputs_ok=not missing,
        inputs_error=("could not load " + " and ".join(missing) + " from the database") if missing else None,
        persisted=None, persist_error=None,
    )
    if missing:
        log.error("engine rebuilt on incomplete inputs", extra={
            "event": "engine_inputs_degraded", "missing": missing, "scenario": scenario})
    return run(label=_run_label(scenario), manual_merges=merges, applied_changes=applied)


def _build_engine(scenario: str) -> EngineResult:
    """`_run_engine` with a bad dataset turned into a diagnosable 4xx.

    A normalizer or analyzer that raises on one malformed record used to leave two
    marks. The request got an opaque 500 naming nothing the operator could act on;
    and, because `switch_dataset` reassigns `_ACTIVE_SCENARIO` before it builds,
    the FAILING scenario stayed active -- so every later lazy `engine()` rebuilt
    the same broken dataset and 500'd forever. A permanently poisoned singleton
    out of one bad input file.

    So: the exception becomes a 422 that names the scenario and the error (the
    dataset is caller-supplied content, not a server defect, and 'unprocessable
    content' is exactly the claim), it is recorded on `_ENGINE_STATE` for
    /api/health, and it is logged with the traceback -- the only place that is
    kept. Every caller assigns the RESULT, so a failed rebuild leaves the previous
    good `_ENGINE` in place and the app keeps serving the snapshot it has.
    """
    try:
        built = _run_engine(scenario)
    except Exception as exc:
        detail = f"{type(exc).__name__}: {exc}"
        _ENGINE_STATE["build_error"] = f"dataset '{scenario}' could not be analyzed ({detail})"
        log.error("engine build failed", exc_info=True, extra={
            "event": "engine_build_failed", "scenario": scenario, "error": detail})
        raise HTTPException(422, f"the dataset '{scenario}' could not be analyzed: {detail}")
    _ENGINE_STATE["build_error"] = None
    return built


def _require_trustworthy_inputs() -> None:
    """Refuse to PERSIST a snapshot computed without the operator's confirmed
    merges / pushed changes. Recomputing them away and writing that to the system
    of record is the failure the audit called the worst one in the product:
    identical pixels for "clean estate" and "the database blinked"."""
    if not _ENGINE_STATE["inputs_ok"]:
        raise HTTPException(503, f"refusing to persist a degraded snapshot: {_ENGINE_STATE['inputs_error']}")


def engine() -> EngineResult:
    """Cached deterministic engine; persists the snapshot if the DB lacks it."""
    global _ENGINE
    if _ENGINE is None:
        try:
            write_scenario(_ACTIVE_SCENARIO)   # keep data/mock consistent with the active scenario
        except Exception as exc:
            log.warning("scenario regeneration failed; using the data/mock files on disk",
                        exc_info=True, extra={"event": "write_scenario_failed",
                                              "scenario": _ACTIVE_SCENARIO, "error": str(exc)})
        _ENGINE = _build_engine(_ACTIVE_SCENARIO)
        if not _ENGINE_STATE["inputs_ok"]:
            # Live-only degraded mode: serve the snapshot but never write it, so a
            # transient DB error cannot overwrite the real one with a truncated
            # recompute. /api/health reports the degradation.
            _ENGINE_STATE.update(persisted=False, persist_error=_ENGINE_STATE["inputs_error"])
            return _ENGINE
        try:
            with get_conn() as conn, conn.cursor() as cur:
                row = fetch_one(cur, "SELECT snapshot_id FROM ztpa.snapshots WHERE snapshot_id=%s",
                                [_ENGINE.snapshot_id])
                if not row:
                    persist_engine_result(cur, _ENGINE)
            _ENGINE_STATE.update(persisted=True, persist_error=None)
        except Exception as exc:
            # DB optional for live-only ops -- but no longer SILENT: the snapshot
            # being served is not in the system of record, and health says so.
            _ENGINE_STATE.update(persisted=False, persist_error=str(exc))
            log.error("snapshot could not be persisted; serving it live-only", exc_info=True,
                      extra={"event": "persist_snapshot_failed", "snapshot_id": _ENGINE.snapshot_id,
                             "error": str(exc)})
    return _ENGINE


def sid() -> str:
    return engine().snapshot_id


def view_sid(snapshot: str | None) -> str:
    """Snapshot to READ from: an explicit historical one, else the active one."""
    return snapshot or engine().snapshot_id


def _finding(fid: str):
    return next((f for f in engine().findings if f.id == fid), None)


def _warm_engine() -> None:
    """Build the deterministic engine in a background thread at boot, so the first
    finding a user opens doesn't pay the ~10s cold engine build on the request
    path. Daemon thread: never blocks startup, never crashes the server if the DB
    is briefly unavailable (engine() degrades to live-only and records why)."""
    import threading

    def _go() -> None:
        try:
            engine()
        except Exception as exc:
            log.error("warm engine build failed; a real request will retry lazily",
                      exc_info=True, extra={"event": "warm_engine_failed", "error": str(exc)})

    threading.Thread(target=_go, name="warm-engine", daemon=True).start()


# --- error handling --------------------------------------------------------
# Every error leaves the API with the request id that is also on the response
# header and on every log line for that request, so a screenshot of a failure is
# enough to find the trace. `detail` is preserved on HTTPException so the
# frontend's typed ApiError keeps rendering the real message.

@app.exception_handler(StarletteHTTPException)
def _http_exception(request: Request, exc: StarletteHTTPException) -> JSONResponse:
    rid = request_ctx.request_id()
    if exc.status_code >= 500:
        log.error("request failed", extra={"event": "http_error", "status": exc.status_code,
                                           "path": request.url.path, "detail": str(exc.detail)})
    return JSONResponse(
        status_code=exc.status_code,
        content={"detail": exc.detail, "error": exc.detail, "request_id": rid},
        headers=exc.headers,
    )


@app.exception_handler(Exception)
def _unhandled_exception(request: Request, exc: Exception) -> JSONResponse:
    """Anything that isn't an HTTPException: log the traceback (the only place it
    is ever recorded) and return the id, never the stack, to the caller."""
    rid = request_ctx.request_id()
    log.error("unhandled exception", exc_info=exc, extra={
        "event": "unhandled_exception", "path": request.url.path, "method": request.method})
    return JSONResponse(status_code=500,
                        content={"detail": "internal server error", "error": "internal server error",
                                 "request_id": rid})


# --------------------------------------------------------------------------
@app.get("/api/live")
def live():
    """Liveness ONLY: is this process running and serving? Deliberately touches
    nothing else -- no DB, no engine -- so the platform restarts the container
    only when the container is actually dead. /api/health is the readiness +
    truth endpoint and returns 503 when the app cannot do its job; pointing a
    liveness probe at that would restart-loop a healthy process whose database
    is down."""
    return {"status": "alive"}


@app.get("/api/health")
def health() -> JSONResponse:
    """Readiness + honesty. Returns 503 with status='degraded' when the DB is
    unreachable, when the active snapshot is missing from the system of record,
    or when the engine was rebuilt on inputs that failed to load -- the states in
    which the dashboard would otherwise render a confident, empty, WRONG estate.

    Payload is additive: `status`, `db`, `snapshot_id` and `ai` keep their
    meanings for existing callers; `degraded_reasons`, `proxy_auth`, `snapshot`
    and `request_id` are new."""
    reasons: list[str] = []

    db_ok = False
    try:
        db_ok = ping()
    except Exception as exc:
        log.warning("database ping failed", exc_info=True,
                    extra={"event": "db_ping_failed", "error": str(exc)})
    if not db_ok:
        reasons.append("database unreachable")

    snapshot_id: str | None = None
    try:
        snapshot_id = sid()
    except Exception as exc:
        reasons.append(f"deterministic engine unavailable: {exc}")
        log.error("engine unavailable on health check", exc_info=True,
                  extra={"event": "engine_unavailable", "error": str(exc)})

    # Is the snapshot we are SERVING actually the one in the system of record?
    snapshot_persisted: bool | None = None
    if db_ok and snapshot_id:
        try:
            with get_conn() as conn, conn.cursor() as cur:
                snapshot_persisted = bool(fetch_one(
                    cur, "SELECT snapshot_id FROM ztpa.snapshots WHERE snapshot_id=%s", [snapshot_id]))
        except Exception as exc:
            log.warning("snapshot presence check failed", exc_info=True,
                        extra={"event": "snapshot_check_failed", "error": str(exc)})
        if snapshot_persisted is False:
            reasons.append("active snapshot is not persisted in the database")
    # A build that raised while a PREVIOUS good snapshot is still being served is
    # otherwise invisible: sid() succeeds, every screen renders, and the estate on
    # screen is silently stale. (When the build failure is total, sid() raised
    # above and reported itself -- hence the snapshot_id guard, so one failure is
    # not listed twice.)
    if snapshot_id and _ENGINE_STATE.get("build_error"):
        reasons.append(f"the last engine rebuild failed: {_ENGINE_STATE['build_error']}")
    if _ENGINE_STATE["inputs_error"]:
        reasons.append(_ENGINE_STATE["inputs_error"])
    if _ENGINE_STATE["persist_error"]:
        reasons.append(f"snapshot persistence failed: {_ENGINE_STATE['persist_error']}")

    try:
        ai = provider_status()
    except Exception as exc:                                  # never let the status page 500
        ai = {"error": str(exc)}
        reasons.append(f"AI provider status unavailable: {exc}")

    payload = {
        "status": "ok" if not reasons else "degraded",
        "db": db_ok,
        "snapshot_id": snapshot_id,
        "ai": ai,
        "scenario": _ACTIVE_SCENARIO,
        "snapshot": {"persisted": snapshot_persisted, "inputs_ok": _ENGINE_STATE["inputs_ok"]},
        # False = the x-npr-* identity headers are trusted with no shared secret.
        "proxy_auth": request_ctx.proxy_auth_enabled(),
        "degraded_reasons": reasons,
        "request_id": request_ctx.request_id(),
    }
    if reasons:
        log.warning("health degraded", extra={"event": "health_degraded", "reasons": reasons})
    return JSONResponse(payload, status_code=200 if not reasons else 503)


@app.post("/api/recompute")
def recompute(_: None = Depends(require_operator)):
    """Re-run the deterministic engine LIVE and reset the AI caches, so the next
    rank/explain/classify recompute live too. Lets a demo show computation happening
    on stage. Deterministic: same seed -> same snapshot id and rows."""
    global _ENGINE
    try:
        write_scenario(_ACTIVE_SCENARIO)   # regenerate the active scenario so data/mock stays consistent
    except Exception as exc:
        log.warning("scenario regeneration failed; recomputing from the data/mock files on disk",
                    exc_info=True, extra={"event": "write_scenario_failed",
                                          "scenario": _ACTIVE_SCENARIO, "error": str(exc)})
    _ENGINE = _build_engine(_ACTIVE_SCENARIO)
    _require_trustworthy_inputs()
    snap = _ENGINE.snapshot_id
    with get_conn() as conn, conn.cursor() as cur:
        summary = persist_engine_result(cur, _ENGINE)
        summary["timings"] = _ENGINE.timings
        summary["paths"] = sum(1 for f in _ENGINE.findings if f.type == "cross_tool_path")
        cur.execute("DELETE FROM ztpa.ranked_actions WHERE snapshot_id=%s", [snap])
        cur.execute("UPDATE ztpa.findings SET explanation=NULL WHERE snapshot_id=%s", [snap])
        audit(cur, "user", "recompute_snapshot", subject=snap, snapshot_id=snap, detail=summary)
    return {"ok": True, "summary": summary}


@app.get("/api/scenarios")
def scenarios():
    return {"scenarios": SCENARIOS, "active": _ACTIVE_SCENARIO}


class DatasetBody(BaseModel):
    scenario: str
    # Bounded: `n` drives a synchronous scenario write + full engine rebuild, so an
    # unbounded value is a one-request denial of service for anyone who can reach
    # the API. 2000 synthetic assets is already past what the demo needs.
    n: int = Field(500, ge=1, le=2000)


@app.post("/api/admin/dataset")
def switch_dataset(body: DatasetBody, _: None = Depends(require_admin)):
    """Regenerate the simulated exports for a scenario, then recompute live."""
    global _ENGINE, _ACTIVE_SCENARIO
    try:
        write_scenario(body.scenario, body.n)
    except ValueError as e:
        raise HTTPException(400, str(e))
    # Build FIRST, rebind after. Assigning _ACTIVE_SCENARIO up front meant a
    # scenario that fails to analyze became the active one anyway, and every
    # subsequent request rebuilt it: one bad dataset switch bricked the process.
    # (data/mock on disk now holds the new scenario's files, but the next
    # engine()/recompute calls write_scenario(_ACTIVE_SCENARIO) first, which
    # regenerates the one still active -- so the failed switch leaves no residue.)
    built = _build_engine(body.scenario)
    _ACTIVE_SCENARIO, _ENGINE = body.scenario, built
    _require_trustworthy_inputs()
    snap = _ENGINE.snapshot_id
    with get_conn() as conn, conn.cursor() as cur:
        summary = persist_engine_result(cur, _ENGINE)
        summary["timings"] = _ENGINE.timings
        summary["paths"] = sum(1 for f in _ENGINE.findings if f.type == "cross_tool_path")
        cur.execute("DELETE FROM ztpa.ranked_actions WHERE snapshot_id=%s", [snap])
        cur.execute("UPDATE ztpa.findings SET explanation=NULL WHERE snapshot_id=%s", [snap])
        audit(cur, "user", "switch_dataset", subject=body.scenario, snapshot_id=snap, detail=summary)
    return {"ok": True, "scenario": body.scenario, "summary": summary}


# --- degraded reads: the engine answers for its own snapshot ---------------
# Every dashboard read below is served from Postgres, the system of record.
# With the database unreachable -- the state this repo ships in, and the state
# /api/health already reports as `degraded` -- each of them raised
# `RuntimeError: DATABASE_URL is not set` out of get_conn and answered 500. Five
# of the console's six feeds failed at once, so a backend that was running,
# answering, and holding a fully computed snapshot rendered as five red panels:
# DEGRADED made pixel-identical to DEAD, which is the same lie as EMPTY made
# pixel-identical to FAILED and is filed against this codebase for the same
# reason.
#
# The data is not gone. The deterministic engine holds the ACTIVE snapshot in
# memory -- the same snapshot_id /api/health reports -- and `src.persist`
# projects it into the exact rows these queries SELECT. So a failed persisted
# read falls back to that projection and SAYS SO in the payload: `served_from`
# names the source and `degraded_reason` says why. That disclosure is the whole
# difference between this and the empty-payload lie: the caller is told which
# source answered and is never handed a fabricated emptiness.
#
# Three limits, all deliberate:
#   * only the ACTIVE snapshot is in memory. A read of a HISTORICAL one has
#     nothing to fall back TO, so it stays an error that names the store --
#     never an empty answer that reads as "that snapshot held nothing".
#   * an HTTPException raised inside the block (the 422 from an unanalyzable
#     dataset) is re-raised untouched: it is an answer, not a database failure.
#   * only the FETCH is wrapped, never the shaping that follows it, so a bug in
#     our own post-processing still surfaces as a 500 instead of being masked by
#     a fallback.

_DB_SOURCE = "database"            # read from the persisted snapshot
_MEMORY_SOURCE = "engine_memory"   # computed by the running engine, not persisted
_NO_SOURCE = "unavailable"         # neither could answer; the payload is empty ON PURPOSE


def _memory_fallback(t: str, resource: str, exc: Exception) -> tuple[EngineResult, dict]:
    """The in-memory engine plus the provenance block to merge into the payload.

    Raises 503 when memory cannot honestly answer for snapshot `t` -- a
    historical snapshot exists only in the database, and inventing the live one
    in its place would answer a question nobody asked."""
    log.error("persisted read failed; falling back to the in-memory engine", exc_info=exc,
              extra={"event": "degraded_read", "resource": resource, "snapshot_id": t,
                     "error": str(exc)})
    live = engine()
    if t != live.snapshot_id:
        raise HTTPException(503, (
            f"{resource} for snapshot {t} exists only in the snapshot database, which is "
            f"unreachable ({exc}). The running engine holds {live.snapshot_id} and nothing else, "
            f"so this is unknown rather than empty."))
    reason = (f"the snapshot database is unreachable ({exc}), so {resource} could not be read from "
              f"the persisted snapshot; the running engine computed it in memory instead")
    if not _ENGINE_STATE["inputs_ok"]:
        # The same outage that broke the read also robbed the rebuild of the
        # operator's confirmed merges. Say both, or the numbers on screen look
        # better sourced than they are.
        reason += f"; {_ENGINE_STATE['inputs_error']}"
    return live, {"served_from": _MEMORY_SOURCE, "degraded_reason": reason}


def _narrow(rows: list[dict], cols: tuple[str, ...]) -> list[dict]:
    """Project full table rows down to the columns a query SELECTs. A wider dict
    out of the fallback is a contract drift only the degraded path would show."""
    return [{c: row[c] for c in cols} for row in rows]


_RULE_COLS = ("source_tool", "source_device", "raw_rule_id", "rule_order", "action",
              "src_kind", "src_value", "dst_kind", "dst_value", "protocol", "ports", "tags")


@app.get("/api/rule/{ref}")
def rule_detail(ref: str, snapshot: str | None = None):
    """A single canonical rule by its raw ref (for click-through rule links)."""
    t = view_sid(snapshot)
    try:
        with get_conn() as conn, conn.cursor() as cur:
            rows = fetch_all(cur, "SELECT source_tool,source_device,raw_rule_id,rule_order,action,src_kind,src_value,dst_kind,dst_value,protocol,ports,tags FROM ztpa.canonical_rules WHERE snapshot_id=%s AND raw_rule_id=%s", [t, ref])
    except HTTPException:
        raise
    except Exception as exc:
        # RuleRef prints "Rule X is not in this snapshot" for an empty list -- a
        # positive claim about the rulebase -- so this one must never degrade to [].
        live, provenance = _memory_fallback(t, f"rule {ref}", exc)
        rows = _narrow(sorted((r for r in canonical_rule_rows(live) if r["raw_rule_id"] == ref),
                              key=lambda r: (r["source_tool"], r["rule_order"])), _RULE_COLS)
        return {"ref": ref, "rules": rows, **provenance}
    return {"ref": ref, "rules": rows, "served_from": _DB_SOURCE}


# The ingest inspector's rule query: the same columns as _RULE_COLS, but keyed by
# rule_uid instead of naming the device.
_INGEST_RULE_COLS = ("rule_uid", "source_tool", "raw_rule_id", "rule_order", "action",
                     "src_kind", "src_value", "dst_kind", "dst_value", "protocol", "ports", "tags")
_RESOLVED_COLS = ("source_tool", "object_name", "object_kind", "resolved", "is_dynamic")


@app.get("/api/ingest")
def ingest(snapshot: str | None = None):
    """What actually got ingested for the snapshot (admin inspector)."""
    t = view_sid(snapshot)
    try:
        with get_conn() as conn, conn.cursor() as cur:
            sources = fetch_all(cur, "SELECT DISTINCT source_tool AS tool, source_device AS device FROM ztpa.canonical_rules WHERE snapshot_id=%s ORDER BY source_tool", [t])
            resolved = fetch_all(cur, "SELECT source_tool,object_name,object_kind,resolved,is_dynamic FROM ztpa.resolved_objects WHERE snapshot_id=%s ORDER BY source_tool,object_name", [t])
            rules = fetch_all(cur, "SELECT rule_uid,source_tool,raw_rule_id,rule_order,action,src_kind,src_value,dst_kind,dst_value,protocol,ports,tags FROM ztpa.canonical_rules WHERE snapshot_id=%s ORDER BY source_tool,rule_order", [t])
    except HTTPException:
        raise
    except Exception as exc:
        # "Nothing was ingested" is the single most misleading thing this screen
        # could say, and it is what an empty degraded answer would render as.
        live, provenance = _memory_fallback(t, "the ingest inspector", exc)
        rule_list = canonical_rule_rows(live)
        sources = [{"tool": tool, "device": device} for tool, device in
                   sorted({(r["source_tool"], r["source_device"]) for r in rule_list})]
        resolved = _narrow(sorted(resolved_object_rows(live),
                                  key=lambda r: (r["source_tool"], r["object_name"])), _RESOLVED_COLS)
        rules = _narrow(sorted(rule_list, key=lambda r: (r["source_tool"], r["rule_order"])),
                        _INGEST_RULE_COLS)
        return {"active_scenario": _ACTIVE_SCENARIO, "sources": sources,
                "resolved_objects": resolved, "canonical_rules": rules, **provenance}
    return {"active_scenario": _ACTIVE_SCENARIO, "sources": sources, "resolved_objects": resolved,
            "canonical_rules": rules, "served_from": _DB_SOURCE}


@app.get("/api/snapshots")
def snapshots_list():
    """The timeline of PERSISTED runs -- the one read with no fallback worth
    having, because a history of snapshots written to the system of record does
    not exist when there is no system of record.

    So it answers 200 with an empty list rather than 500 (a dead feed would drag
    the whole console down with it over the one thing that is genuinely absent),
    and `served_from: "unavailable"` + `degraded_reason` say that the list is
    UNKNOWN, not empty. Rendering it as "no snapshots yet" would be the exact
    lie the rest of this file exists to prevent, so the UI renders the reason."""
    try:
        with get_conn() as conn, conn.cursor() as cur:
            rows = fetch_all(cur, """
                SELECT s.snapshot_id, s.label, s.status, s.created_at,
                  (SELECT count(*) FROM ztpa.assets a WHERE a.snapshot_id=s.snapshot_id) AS assets,
                  (SELECT count(*) FROM ztpa.canonical_rules r WHERE r.snapshot_id=s.snapshot_id) AS rules,
                  (SELECT count(*) FROM ztpa.findings f WHERE f.snapshot_id=s.snapshot_id) AS findings,
                  (SELECT count(*) FROM ztpa.findings f WHERE f.snapshot_id=s.snapshot_id AND f.type='cross_tool_path') AS paths,
                  (SELECT count(*) FROM ztpa.findings f WHERE f.snapshot_id=s.snapshot_id AND f.severity_band='critical') AS critical
                FROM ztpa.snapshots s ORDER BY s.created_at DESC""")
    except HTTPException:
        raise
    except Exception as exc:
        log.error("the snapshot timeline could not be read", exc_info=exc,
                  extra={"event": "degraded_read", "resource": "the snapshot timeline",
                         "error": str(exc)})
        return {"snapshots": [], "active": sid(), "served_from": _NO_SOURCE,
                "degraded_reason": (f"the snapshot database is unreachable ({exc}), so the history of "
                                    f"persisted runs could not be read. This list is unknown, not empty.")}
    return {"snapshots": rows, "active": sid(), "served_from": _DB_SOURCE}


@app.delete("/api/snapshots/{snapshot_id}")
def delete_snapshot(snapshot_id: str, _: None = Depends(require_admin)):
    if snapshot_id == sid():
        raise HTTPException(400, "Cannot delete the active snapshot. Switch dataset or recompute first.")
    with get_conn() as conn, conn.cursor() as cur:
        delete_snapshot_children(cur, snapshot_id)   # deletes the snapshot row; children cascade
        audit(cur, "user", "delete_snapshot", subject=snapshot_id, detail={})
    return {"ok": True, "deleted": snapshot_id}


@app.get("/api/snapshot")
def snapshot_meta(snapshot: str | None = None):
    t = view_sid(snapshot)
    try:
        with get_conn() as conn, conn.cursor() as cur:
            snap = fetch_one(cur, "SELECT * FROM ztpa.snapshots WHERE snapshot_id=%s", [t])
            counts = {}
            for tbl in ("assets", "canonical_rules", "graph_nodes", "graph_edges",
                        "findings", "resolved_objects", "asset_correlations", "ranked_actions"):
                counts[tbl] = fetch_one(cur, f"SELECT count(*) n FROM ztpa.{tbl} WHERE snapshot_id=%s", [t])["n"]
    except HTTPException:
        raise
    except Exception as exc:
        live, provenance = _memory_fallback(t, "the snapshot summary", exc)
        # `created_at` is a database default, so the projection cannot know it --
        # null rather than a fabricated now(), which would also break determinism.
        return {"snapshot": {**snapshot_row(live), "created_at": None},
                "counts": snapshot_counts(live), "viewing": t, "active": live.snapshot_id,
                **provenance}
    return {"snapshot": snap, "counts": counts, "viewing": t, "active": sid(), "served_from": _DB_SOURCE}


# The node/edge column lists the two graph queries SELECT, named once so the
# in-memory projection below narrows to exactly the same shape the database
# would have returned -- a wider dict from the fallback is a contract drift the
# only exercised path would never catch.
_GRAPH_NODE_COLS = ("node_id", "kind", "label", "tags", "ip_set")
_GRAPH_EDGE_COLS = ("src_node", "dst_node", "source_tool", "ports", "l7_app", "rule_uid")


def _graph_payload(nodes: list[dict], edges: list[dict], cross_rows: list[dict]) -> dict:
    """Shape graph rows into the console's payload: one edge per (src,dst) pair
    with its tools/services/apps merged. Lifted out of the route so the persisted
    rows and the in-memory projection are shaped by the same code, not by two
    copies that can disagree about what an edge is."""
    for n in nodes:
        n["zone"] = zone_of(n["node_id"], n.get("tags") or [])
    grouped: dict[tuple, dict] = {}
    for ed in edges:
        key = (ed["src_node"], ed["dst_node"])
        g = grouped.setdefault(key, {"src": ed["src_node"], "dst": ed["dst_node"], "tools": set(),
                                     "services": set(), "apps": set()})
        g["tools"].add(ed["source_tool"])
        if ed.get("l7_app"):
            g["apps"].add(ed["l7_app"])
        for p in (ed.get("ports") or []):
            start, end = p.get("port_start"), p.get("port_end")
            g["services"].add(f"{p.get('proto')}/{start}" if end in (None, start) else f"{p.get('proto')}/{start}-{end}")
        if not ed.get("ports"):
            g["services"].add("any")
    edge_list = [{"src": v["src"], "dst": v["dst"], "tools": sorted(v["tools"]),
                  "services": sorted(v["services"]), "apps": sorted(v["apps"])} for v in grouped.values()]
    cross = [r["signals"] for r in cross_rows]
    highlight = cross[0].get("path") if cross else []
    return {"nodes": nodes, "edges": edge_list, "highlight_path": highlight, "cross_tool_paths": cross}


@app.get("/api/graph")
def graph(snapshot: str | None = None):
    t = view_sid(snapshot)
    try:
        with get_conn() as conn, conn.cursor() as cur:
            nodes = fetch_all(cur, "SELECT node_id,kind,label,tags,ip_set FROM ztpa.graph_nodes WHERE snapshot_id=%s", [t])
            edges = fetch_all(cur, "SELECT src_node,dst_node,source_tool,ports,l7_app,rule_uid FROM ztpa.graph_edges WHERE snapshot_id=%s", [t])
            ct = fetch_all(cur, "SELECT signals FROM ztpa.findings WHERE snapshot_id=%s AND type='cross_tool_path' ORDER BY finding_id", [t])
        provenance = {"served_from": _DB_SOURCE}
    except HTTPException:
        raise
    except Exception as exc:
        live, provenance = _memory_fallback(t, "the reachability graph", exc)
        nodes = _narrow(graph_node_rows(live), _GRAPH_NODE_COLS)
        edges = _narrow(graph_edge_rows(live), _GRAPH_EDGE_COLS)
        # ORDER BY finding_id, explicitly: the highlighted path is cross[0], so a
        # different order here would highlight a different chain than the DB read.
        ct = sorted((row for row in finding_rows(live) if row["type"] == "cross_tool_path"),
                    key=lambda row: row["finding_id"])
    return {**_graph_payload(nodes, edges, ct), **provenance}


_FINDING_COLS = ("finding_id", "type", "severity", "severity_band", "forced_critical",
                 "signals", "involved", "raw_refs", "source_tools", "explanation")


@app.get("/api/findings")
def findings(snapshot: str | None = None):
    t = view_sid(snapshot)
    try:
        with get_conn() as conn, conn.cursor() as cur:
            rows = fetch_all(cur, """
                SELECT finding_id,type,severity,severity_band,forced_critical,signals,involved,raw_refs,
                       source_tools,explanation FROM ztpa.findings WHERE snapshot_id=%s
                ORDER BY forced_critical DESC, severity DESC, type""", [t])
    except HTTPException:
        raise
    except Exception as exc:
        live, provenance = _memory_fallback(t, "findings", exc)
        # The SQL's ORDER BY, plus finding_id as the tiebreak Postgres leaves to
        # the planner -- this API's answer has to be byte-stable, so nothing may
        # be left to an arbitrary order.
        rows = sorted(_narrow(finding_rows(live), _FINDING_COLS),
                      key=lambda row: (not row["forced_critical"], -row["severity"],
                                       row["type"], row["finding_id"]))
        return {"findings": rows, **provenance}
    return {"findings": rows, "served_from": _DB_SOURCE}


@app.get("/api/findings/{fid}")
def finding_detail(fid: str):
    with get_conn() as conn, conn.cursor() as cur:
        row = fetch_one(cur, "SELECT * FROM ztpa.findings WHERE finding_id=%s AND snapshot_id=%s", [fid, sid()])
    if not row:
        raise HTTPException(404, "finding not found")
    return row


_EXPLAIN_TIMEOUT = 180.0
_explaining: set[str] = set()   # findings whose LLM explanation is being computed in the background


def _bg_explain(fid: str, f) -> None:
    """Compute the LLM explanation off the request path and cache it. Cold local
    models can take minutes; doing this in the background means the HTTP request
    (which a dev proxy would reset) already returned the deterministic version."""
    try:
        result = explain_mod.explain(f, timeout=_EXPLAIN_TIMEOUT)
        if result.get("by") != "engine_fallback" and result.get("explanation", "").strip():
            with get_conn() as conn, conn.cursor() as cur:
                cache_explanation(cur, fid, result["explanation"], result.get("by"))
                audit(cur, "agent", "explain_finding", subject=fid, snapshot_id=sid(), detail={"by": result["by"]})
    finally:
        _explaining.discard(fid)


@app.post("/api/findings/{fid}/explain")
def explain_finding(fid: str):
    _require_capability("explain")
    f = _finding(fid)
    if not f:
        raise HTTPException(404, "finding not found")
    with get_conn() as conn, conn.cursor() as cur:
        row = fetch_one(cur, "SELECT explanation, explanation_by FROM ztpa.findings WHERE finding_id=%s", [fid])
    if row and row.get("explanation"):
        # Report the original provider:model (e.g. "openai:gpt-4o (cached)") when we
        # captured it; older rows without provenance fall back to a bare "cache".
        src = row.get("explanation_by")
        by = f"{src} (cached)" if src else "cache"
        return {"explanation": row["explanation"], "by": by, "cached": True, "pending": False}
    # Not cached: return the deterministic explanation immediately and compute the
    # richer LLM one on a real daemon thread (de-duped per finding). FastAPI
    # BackgroundTasks run as part of the response lifecycle and kept the request
    # open until the LLM finished — a true thread returns the fallback instantly.
    if fid not in _explaining:
        _explaining.add(fid)
        threading.Thread(target=_bg_explain, args=(fid, f), name=f"explain-{fid}", daemon=True).start()
    # tell the UI which provider will produce the richer explanation, so it can
    # label the "refining…" state truthfully (local model vs a hosted one).
    return {"explanation": explain_mod._fallback(f), "by": "engine_fallback",
            "cached": False, "pending": True, "provider": settings.active_provider()}


@app.post("/api/findings/{fid}/remediate")
def remediate_finding(fid: str, _: None = Depends(require_approver)):
    """Draft a fix for a finding. Guarded, for two independent reasons: it appends
    a row to `remediation_revisions` -- a GOVERNANCE table (src/db.py), the thread
    an approver later reads and accepts -- and it spends model tokens. Proposing a
    change to the estate is analyst work; a viewer reads the posture, and a viewer
    is the role an auditor is given."""
    _require_capability("remediate")
    f = _finding(fid)
    if not f:
        raise HTTPException(404, "finding not found")
    result = remediation.draft(f, engine())
    with get_conn() as conn, conn.cursor() as cur:
        rev = persist_remediation_revision(cur, sid(), fid, result)
        audit(cur, "agent", "remediate_finding", subject=fid, snapshot_id=sid(),
              detail={"by": result["by"], "resolves": result["validation"].get("resolves")})
    return {**result, "thread_id": rev["thread_id"], "seq": rev["seq"], "revision_id": rev["revision_id"]}


class RefineBody(BaseModel):
    comment: str
    prior_change: dict | None = None


@app.post("/api/findings/{fid}/remediate/refine")
def remediate_refine(fid: str, body: RefineBody, _: None = Depends(require_approver)):
    """Iterate on a remediation: fold the reviewer's comment into a revised draft,
    re-validate it deterministically, and append it to the finding's thread.

    Same guard as the draft it revises -- it appends to the same governance thread
    and spends the same tokens."""
    _require_capability("remediate")
    f = _finding(fid)
    if not f:
        raise HTTPException(404, "finding not found")
    result = remediation.draft(f, engine(), comment=body.comment, prior=body.prior_change)
    with get_conn() as conn, conn.cursor() as cur:
        rev = persist_remediation_revision(cur, sid(), fid, result, comment=body.comment)
    return {**result, "thread_id": rev["thread_id"], "seq": rev["seq"], "revision_id": rev["revision_id"]}


@app.get("/api/findings/{fid}/remediation-thread")
def remediation_thread(fid: str):
    with get_conn() as conn, conn.cursor() as cur:
        return {"revisions": load_remediation_thread(cur, sid(), fid)}


class CampaignBody(BaseModel):
    target_bands: list[str] | None = None    # default: critical + high


@app.get("/api/campaign/plan")
def campaign_get():
    """The persisted campaign plan for the active snapshot (or {plan: null} if none
    has been planned yet). Read on page load so navigating away and back re-uses the
    proven plan instead of paying another planning pass."""
    _require_capability("campaign")
    with get_conn() as conn, conn.cursor() as cur:
        return {"plan": load_campaign_plan(cur, sid())}


@app.post("/api/campaign/plan")
def campaign_plan(body: CampaignBody, _: None = Depends(require_approver)):
    """Plan + PROVE a worst-first remediation campaign across the whole snapshot:
    the agent drafts a fix for the worst open finding, the engine re-simulates on the
    cumulative state, and it repeats until the critical count is driven to zero (or a
    finding needs a human). Advisory only — nothing is applied to the live snapshot;
    accepted fixes go to the Change Gate via /api/campaign/submit. The plan is
    persisted per snapshot so it survives navigation."""
    _require_capability("campaign")
    e = engine()
    bands = tuple(body.target_bands) if body.target_bands else campaign_mod.DEFAULT_TARGET_BANDS
    result = campaign_mod.plan(e, target_bands=bands)
    with get_conn() as conn, conn.cursor() as cur:
        persist_campaign_plan(cur, sid(), result)
        audit(cur, "agent", "campaign_plan", snapshot_id=sid(),
              detail={"applied": result["applied_count"], "needs_review": result["needs_review_count"],
                      "trajectory": result["criticals_trajectory"],
                      "cleared_all_criticals": result["cleared_all_criticals"]})
    return result


class CampaignSubmitBody(BaseModel):
    justification: str | None = None


@app.post("/api/campaign/submit")
def campaign_submit(body: CampaignSubmitBody, _: None = Depends(require_approver)):
    """Send every proven fix in the persisted campaign to the Change Gate. Each
    applied step becomes its own change request, re-evaluated and ruled on by the
    gate individually (so the audit trail and staging/push flow are unchanged);
    steps the campaign flagged needs-review, or that no longer map to a live finding,
    are skipped and reported. Idempotent: re-submitting upserts the same requests."""
    _require_capability("classify")
    with get_conn() as conn, conn.cursor() as cur:
        plan = load_campaign_plan(cur, sid())
        if not plan:
            raise HTTPException(400, "no campaign plan to submit; plan the campaign first")
        submitted, skipped = [], []
        for step in plan.get("steps", []):
            fid, change = step.get("finding_id"), step.get("change")
            if step.get("status") != "applied" or not fid or not change:
                skipped.append({"n": step.get("n"), "title": step.get("target", {}).get("title"),
                                "reason": step.get("reason") or "not an applied, live-finding fix"})
                continue
            if not _finding(fid):   # finding no longer exists in the live snapshot
                skipped.append({"n": step.get("n"), "title": step.get("target", {}).get("title"),
                                "reason": "finding not in the current snapshot"})
                continue
            res = _submit_remediation(cur, fid, change, justification=body.justification, origin="campaign")
            submitted.append({"n": step.get("n"), "finding_id": fid, "request_id": res["request_id"],
                              "decision": res["decision"]["decision"]})
        audit(cur, "user", "campaign_submit", snapshot_id=sid(),
              detail={"submitted": len(submitted), "skipped": len(skipped)})
    return {"submitted": submitted, "skipped": skipped,
            "auto_approved": sum(1 for s in submitted if s["decision"] == "auto_approve"),
            "escalated": sum(1 for s in submitted if s["decision"] == "escalate")}


@app.get("/api/actions")
def actions(snapshot: str | None = None):
    t = view_sid(snapshot)
    try:
        with get_conn() as conn, conn.cursor() as cur:
            rows = fetch_all(cur, "SELECT action_id,title,finding_ids,priority,rationale FROM ztpa.ranked_actions WHERE snapshot_id=%s ORDER BY priority", [t])
            if rows or t != sid():
                return {"actions": rows, "ranked_by": "cache", "served_from": _DB_SOURCE}   # historical: show cache only
            ranked = rank_mod.rank(engine().findings)
            persist_ranked_actions(cur, t, ranked)
            rows = fetch_all(cur, "SELECT action_id,title,finding_ids,priority,rationale FROM ztpa.ranked_actions WHERE snapshot_id=%s ORDER BY priority", [t])
    except HTTPException:
        raise
    except Exception as exc:
        # Ranking needs findings, not the database -- the cache is an
        # optimisation, so losing it costs a recompute, not the answer.
        live, provenance = _memory_fallback(t, "prioritized actions", exc)
        ranked = rank_mod.rank(live.findings)
        rows = sorted(({"action_id": a.action_id, "title": a.title, "finding_ids": list(a.finding_ids),
                        "priority": a.priority, "rationale": a.rationale} for a in ranked.actions),
                      key=lambda row: (row["priority"], row["action_id"]))
        return {"actions": rows, "ranked_by": ranked.ranked_by, **provenance}
    return {"actions": rows, "ranked_by": ranked.ranked_by, "served_from": _DB_SOURCE}


@app.post("/api/actions/recompute")
def recompute_actions(_: None = Depends(require_operator)):
    ranked = rank_mod.rank(engine().findings)
    with get_conn() as conn, conn.cursor() as cur:
        persist_ranked_actions(cur, sid(), ranked)
    return {"actions": [a.model_dump() for a in ranked.actions], "ranked_by": ranked.ranked_by}


_ASSET_COLS = ("asset_id", "asset_key", "kind", "context", "identifiers", "ip_set", "tags", "source_tools")
_CORRELATION_COLS = ("asset_id", "match_key", "confidence", "evidence")


@app.get("/api/assets")
def assets(snapshot: str | None = None):
    t = view_sid(snapshot)
    try:
        with get_conn() as conn, conn.cursor() as cur:
            a = fetch_all(cur, "SELECT asset_id,asset_key,kind,context,identifiers,ip_set,tags,source_tools FROM ztpa.assets WHERE snapshot_id=%s ORDER BY asset_key", [t])
            c = fetch_all(cur, "SELECT asset_id,match_key,confidence,evidence FROM ztpa.asset_correlations WHERE snapshot_id=%s", [t])
    except HTTPException:
        raise
    except Exception as exc:
        live, provenance = _memory_fallback(t, "the asset inventory", exc)
        a = _narrow(sorted(asset_rows(live), key=lambda r: r["asset_key"]), _ASSET_COLS)
        # The correlation query has no ORDER BY; this answer still has to be
        # byte-stable, so the tiebreak Postgres leaves to the planner is explicit.
        c = _narrow(sorted(correlation_rows(live), key=lambda r: (r["asset_id"], r["match_key"], r["id"])),
                    _CORRELATION_COLS)
        return {"assets": a, "correlations": c, **provenance}
    return {"assets": a, "correlations": c, "served_from": _DB_SOURCE}


@app.get("/api/assets/merge-suggestions")
def merge_suggestions():
    _require_capability("entity_suggest")
    return {"suggestions": entity_suggest.suggest_merges(engine().assets)}


class MergeBody(BaseModel):
    a: str
    b: str


def _apply_merges_and_persist(action: str, a: str, b: str) -> dict:
    """Re-resolve identities with the current confirmed merges, then re-persist the
    snapshot (delete_snapshot_children + reinsert) so DB-backed reads reflect it."""
    global _ENGINE
    _ENGINE = _build_engine(_ACTIVE_SCENARIO)
    _require_trustworthy_inputs()
    snap = _ENGINE.snapshot_id
    with get_conn() as conn, conn.cursor() as cur:
        persist_engine_result(cur, _ENGINE)
        cur.execute("DELETE FROM ztpa.ranked_actions WHERE snapshot_id=%s", [snap])
        cur.execute("UPDATE ztpa.findings SET explanation=NULL WHERE snapshot_id=%s", [snap])
        audit(cur, "user", action, subject=f"{a}~{b}", snapshot_id=snap, detail={"a": a, "b": b})
    return {"assets": len(_ENGINE.assets), "snapshot_id": snap}


@app.post("/api/assets/merge")
def confirm_merge(body: MergeBody, _: None = Depends(require_operator)):
    """Human-confirm that two suggested duplicates are the same logical asset. The
    decision is durable; the identity layer unifies them on every run from now on."""
    if not body.a or not body.b or body.a == body.b:
        raise HTTPException(400, "provide two distinct asset keys")
    with get_conn() as conn, conn.cursor() as cur:
        persist_asset_merge(cur, body.a, body.b, by="human")
    summary = _apply_merges_and_persist("confirm_merge", body.a, body.b)
    return {"ok": True, "merged": [body.a, body.b], **summary}


@app.post("/api/assets/unmerge")
def undo_merge(body: MergeBody, _: None = Depends(require_operator)):
    """Reverse a previously confirmed merge (the assets split back apart)."""
    with get_conn() as conn, conn.cursor() as cur:
        delete_asset_merge(cur, body.a, body.b)
    summary = _apply_merges_and_persist("undo_merge", body.a, body.b)
    return {"ok": True, "unmerged": [body.a, body.b], **summary}


@app.get("/api/assets/merges")
def list_merges():
    """Confirmed merges (the human-decision audit trail for identity)."""
    with get_conn() as conn, conn.cursor() as cur:
        return {"merges": [{"a": a, "b": b} for a, b in load_asset_merges(cur)]}


@app.get("/api/change-requests")
def change_requests():
    return {"requests": [{"id": r.id, "title": r.title, "requested_by": r.requested_by,
                          "justification": r.justification,
                          "proposed": {"source": r.proposed.source, "destination": r.proposed.destination,
                                       "service": r.proposed.service, "action": r.proposed.action}}
                         for r in DEMO_REQUESTS.values()]}


class ClassifyBody(BaseModel):
    request_id: str | None = None
    source: str | None = None
    destination: str | None = None
    service: str | None = None
    justification: str | None = None


@app.post("/api/change/classify")
def classify(body: ClassifyBody, _: None = Depends(require_approver)):
    """Evaluate a proposed change and rule on it.

    Guarded as an approver action. It was exempted as "advisory" and it is not:
    every call persists a `change_requests` row and a `change_decisions` row (see
    the persist_change_decision below), both GOVERNANCE tables -- so an
    unauthenticated viewer could write into the compliance trail the product's
    whole story rests on, and spend model tokens doing it. Evaluating a proposed
    change is analyst work; reading the posture is viewer work."""
    _require_capability("classify")
    e = engine()
    if body.request_id and body.request_id in DEMO_REQUESTS:
        req = DEMO_REQUESTS[body.request_id]
    elif body.source and body.destination and body.service:
        from src.normalizers.common import parse_service, record_from_service
        # parse_service returns a 6-field DecodedService, never a 3-tuple: the old
        # `proto, port, label = parse_service(...)` raised TypeError on EVERY custom
        # change since the initial commit. Building the record through
        # record_from_service also keeps port_end and the decoded App-ID, which the
        # hand-rolled constructor dropped -- so "tcp/8000-8100" is scored as the
        # range it is instead of a single port.
        svc = parse_service(body.service)
        # Deterministic id from the proposed tuple: re-simulating the same change
        # updates its record (idempotent), but distinct changes accumulate as
        # separate audit entries in change_requests/change_decisions.
        cr_id = det_id("cr", body.source, body.destination, svc.label)
        # dest_tags are deliberately NOT taken from the request: simulate_change
        # re-derives them from the engine's assets, so a caller cannot understate
        # the sensitivity of what it is asking to reach and buy an auto-approve.
        req = ChangeRequest(id=cr_id, title=f"{body.source} -> {body.destination} {svc.label}",
                            proposed=record_from_service(
                                record_id=f"{cr_id}-rule", source_tool="algosec", raw_ref=cr_id,
                                source=body.source, destination=body.destination, svc=svc,
                                action="allow", dest_tags=[], order=999),
                            requested_by="custom", justification=body.justification)
    else:
        raise HTTPException(400, "provide request_id or source+destination+service")
    delta = simulate_change(e.records, e.assets, e.alias_map, req.proposed)
    decision = classify_change.classify_change(req, delta, ctx=e)
    with get_conn() as conn, conn.cursor() as cur:
        persist_change_decision(cur, sid(), req, decision)
    return {"request": {"id": req.id, "title": req.title, "justification": req.justification},
            "delta": delta, "decision": decision.model_dump()}


@app.get("/api/change-decisions")
def change_decisions_log(limit: int = Query(25, ge=1, le=200)):
    """The change audit trail: every evaluated request joined to how the gate
    ruled on it (decision, guardrail, who decided, when). Reads the
    change_requests + change_decisions tables that classify() writes."""
    with get_conn() as conn, conn.cursor() as cur:
        ensure_change_request_status(cur)
        rows = fetch_all(cur, """
            SELECT d.decision_id, d.request_id, d.decision, d.forced_escalate, d.confidence,
                   d.model AS decided_by, d.triggering_reason, d.decided_at,
                   d.criteria, d.delta_summary,
                   r.proposed, r.justification, r.requested_by, r.kind, r.origin,
                   r.status AS request_status, r.rejected_by, r.reject_reason,
                   s.staged_id, s.status AS staged_status
            FROM ztpa.change_decisions d
            JOIN ztpa.change_requests r ON r.request_id = d.request_id
            LEFT JOIN ztpa.staged_changes s ON s.request_id = d.request_id
            ORDER BY d.decided_at DESC NULLS LAST
            LIMIT %s
        """, [limit])
    return {"decisions": rows}


# --- Risk To-Do -> Change Gate: submit an accepted remediation -------------
class SubmitBody(BaseModel):
    kind: str = "remediation"
    finding_id: str | None = None
    change: dict | None = None
    revision_id: str | None = None
    justification: str | None = None


def _submit_remediation(cur, finding_id: str, change: dict, revision_id: str | None = None,
                        justification: str | None = None, origin: str = "risk_todo") -> dict:
    """Core of a remediation -> Change Gate submission: the engine re-simulates the
    fix and the gate rules (auto_approve if it resolves its finding and opens no new
    critical, else escalate). Shared by the single-fix route and the campaign batch.
    Writes the change_request + change_decision rows and returns the response shape."""
    f = _finding(finding_id)
    if not f:
        raise HTTPException(404, f"finding not found: {finding_id}")
    validation = remediation._validate(engine(), f, change)
    resolves = bool(validation.get("resolves"))
    new_crit = validation.get("introduces_new_criticals") or []
    decision = "auto_approve" if (resolves and not new_crit) else "escalate"
    request_id = det_id("cr", finding_id, revision_id or change)
    decision_id = det_id("dec", sid(), request_id)
    ref = change.get("target_ref")
    rule = next((r for r in engine().records if r.raw_ref == ref), None)
    target_tool = rule.source_tool if rule else "algosec"
    proposed = {**change, "finding_id": finding_id, "target_tool": target_tool,
                "summary": f"{change.get('op')} {ref}".strip()}
    crit = {"resolves": resolves, "no_new_criticals": not new_crit}
    trig = ("introduces new critical findings: " + ", ".join(new_crit)) if new_crit else (
        None if resolves else "the fix does not resolve the finding")
    upsert(cur, "change_requests", {
        "request_id": request_id, "snapshot_id": sid(), "proposed": proposed,
        "requested_by": request_ctx.current().email or origin, "justification": justification,
        "kind": "remediation", "origin": origin}, ["request_id"])
    upsert(cur, "change_decisions", {
        "decision_id": decision_id, "request_id": request_id, "decision": decision, "criteria": crit,
        "triggering_reason": trig if decision == "escalate" else None, "delta_summary": validation,
        "confidence": 1.0 if resolves else 0.5, "forced_escalate": bool(new_crit), "model": "engine"},
        ["decision_id"])
    if revision_id:
        accept_remediation_revision(cur, revision_id)
    audit(cur, "user", "submit_remediation", subject=finding_id, snapshot_id=sid(),
          detail={"decision": decision, "request_id": request_id, "origin": origin})
    return {"request_id": request_id, "kind": "remediation", "finding_id": finding_id,
            "decision": {"request_id": request_id, "decision": decision, "criteria": crit,
                         "triggering_reason": trig, "delta_summary": validation,
                         "confidence": 1.0 if resolves else 0.5, "forced_escalate": bool(new_crit),
                         "decided_by": "engine"},
            "target_tool": target_tool}


@app.post("/api/change/submit")
def change_submit(body: SubmitBody, _: None = Depends(require_approver)):
    """Submit an accepted Risk-To-Do remediation to the Change Gate. The engine
    re-simulates it deterministically and the gate decides: auto_approve if it
    resolves its finding and introduces no new criticals, else escalate."""
    _require_capability("classify")
    if body.kind != "remediation":
        raise HTTPException(400, "unsupported submit kind")
    if not body.finding_id or not body.change:
        raise HTTPException(400, "remediation submit needs finding_id and change")
    with get_conn() as conn, conn.cursor() as cur:
        return _submit_remediation(cur, body.finding_id, body.change, body.revision_id, body.justification)


# --- Staging area ----------------------------------------------------------
class StageBody(BaseModel):
    request_id: str
    target_tool: str | None = None
    manual_approve: bool = False


@app.post("/api/staging")
def stage_change(body: StageBody, _: None = Depends(require_approver)):
    """Stage an approved change for push. Approver-gated UNCONDITIONALLY: the role
    check used to live inside the `escalate` branch, so the auto_approve path --
    four fifths of the traffic -- staged for anyone, including a viewer."""
    with get_conn() as conn, conn.cursor() as cur:
        ensure_change_request_status(cur)
        row = fetch_one(cur, """
            SELECT d.decision, r.proposed, r.kind, r.origin, r.snapshot_id, r.status
            FROM ztpa.change_decisions d JOIN ztpa.change_requests r ON r.request_id = d.request_id
            WHERE d.request_id = %s""", [body.request_id])
        if not row:
            raise HTTPException(404, "change request/decision not found")
        if row.get("status") == "rejected":
            raise HTTPException(409, "this change request was rejected and cannot be staged")
        if row["decision"] == "escalate":
            # The role half of this check is now the route dependency; what stays
            # is the EXPLICIT act of approval an escalated change additionally needs.
            if not body.manual_approve:
                raise HTTPException(400, "escalated change requires manual approval to stage")
            staged_decision = "manual_approved"
        else:
            staged_decision = "auto_approve"
        proposed = row["proposed"] or {}
        target = body.target_tool or proposed.get("target_tool") or "algosec"
        staged_id = det_id("stage", body.request_id)
        persist_staged_change(cur, {
            "staged_id": staged_id, "snapshot_id": row.get("snapshot_id") or sid(),
            "request_id": body.request_id, "origin": row.get("origin") or "change_gate",
            "kind": row.get("kind") or "add_allow", "target_tool": target, "payload": proposed,
            "decision": staged_decision, "status": "staged"})
    return {"ok": True, "staged_id": staged_id, "status": "staged", "target_tool": target}


@app.get("/api/staging")
def staging_list():
    with get_conn() as conn, conn.cursor() as cur:
        rows = fetch_all(cur, """
            SELECT s.staged_id, s.snapshot_id, s.request_id, s.origin, s.kind, s.target_tool, s.payload,
                   s.decision, s.status, s.conflicts, s.resolution, s.push_steps, s.created_at, s.pushed_at,
                   r.justification, r.requested_by
            FROM ztpa.staged_changes s LEFT JOIN ztpa.change_requests r ON r.request_id = s.request_id
            ORDER BY s.created_at DESC""")
    return {"staged": rows}


@app.post("/api/staging/{staged_id}/push")
def staging_push(staged_id: str, _: None = Depends(require_operator)):
    """Simulated, stepped push. Conflicts are detected with real engine math and
    resolved deterministically; the UI animates the returned steps."""
    with get_conn() as conn, conn.cursor() as cur:
        row = fetch_one(cur, "SELECT * FROM ztpa.staged_changes WHERE staged_id=%s", [staged_id])
        if not row:
            raise HTTPException(404, "staged change not found")
        others = fetch_all(cur, """
            SELECT staged_id, kind, target_tool, payload FROM ztpa.staged_changes
            WHERE target_tool=%s AND staged_id<>%s AND status IN ('staged','pushed')""",
            [row["target_tool"], staged_id])
        plan = staging_mod.build_push_plan(engine(), row, others)
        cur.execute(
            "UPDATE ztpa.staged_changes SET status=%s, conflicts=%s, resolution=%s, push_steps=%s, "
            "pushed_at=now() WHERE staged_id=%s",
            [plan["status"], Jsonb(plan["conflicts"]), Jsonb(plan["resolution"]),
             Jsonb(plan["push_steps"]), staged_id])
        audit(cur, "user", "push_staged_change", subject=staged_id, snapshot_id=row.get("snapshot_id"),
              detail={"status": plan["status"], "target_tool": row.get("target_tool")})
    return {"staged_id": staged_id, **plan}


@app.delete("/api/staging/{staged_id}")
def staging_delete(staged_id: str, _: None = Depends(require_approver)):
    with get_conn() as conn, conn.cursor() as cur:
        cur.execute("DELETE FROM ztpa.staged_changes WHERE staged_id=%s", [staged_id])
        audit(cur, "user", "discard_staged_change", subject=staged_id, detail={})
    return {"ok": True, "deleted": staged_id}


# --- Change Gate: reject a request -----------------------------------------
class RejectBody(BaseModel):
    request_id: str
    reason: str | None = None


@app.post("/api/change/reject")
def reject_change(body: RejectBody, _: None = Depends(require_approver)):
    """Decline a change request. A governance action, so only an approver
    (admin/analyst) may reject -- mirrors who can approve an escalation. The
    request moves out of Actions into the Decision log marked 'rejected', and can
    no longer be staged."""
    by = request_ctx.current().email or "reviewer"
    with get_conn() as conn, conn.cursor() as cur:
        n = reject_change_request(cur, body.request_id, by, body.reason)
        if not n:
            raise HTTPException(404, "change request not found")
    return {"ok": True, "request_id": body.request_id, "status": "rejected", "rejected_by": by}


# --- Admin: reset the change-gate demo -------------------------------------
@app.post("/api/admin/reset-demo")
def reset_demo(_: None = Depends(require_admin)):
    """Clear the change-governance working set (requests, decisions, staged
    changes, remediation threads) and recompute a clean baseline. Use this to
    re-run the demo: any pushed change is cleared, so the resolved finding
    reappears on the next recompute."""
    global _ENGINE
    with get_conn() as conn, conn.cursor() as cur:
        cleared = reset_change_workflow(cur)
        audit(cur, "user", "reset_demo", detail=cleared)
    _ENGINE = _build_engine(_ACTIVE_SCENARIO)
    _require_trustworthy_inputs()
    snap = _ENGINE.snapshot_id
    with get_conn() as conn, conn.cursor() as cur:
        summary = persist_engine_result(cur, _ENGINE)
        summary["timings"] = _ENGINE.timings
        summary["paths"] = sum(1 for f in _ENGINE.findings if f.type == "cross_tool_path")
        cur.execute("DELETE FROM ztpa.ranked_actions WHERE snapshot_id=%s", [snap])
        cur.execute("UPDATE ztpa.findings SET explanation=NULL WHERE snapshot_id=%s", [snap])
    return {"ok": True, "cleared": cleared, "snapshot_id": snap, "summary": summary}


# --- Admin: tools registry + per-role toggles ------------------------------
@app.get("/api/admin/tools")
def admin_tools(_: None = Depends(require_admin)):
    with get_conn() as conn, conn.cursor() as cur:
        roles_map = {r["tool_key"]: r["enabled_roles"]
                     for r in fetch_all(cur, "SELECT tool_key, enabled_roles FROM ztpa.tool_settings")}
        agg = {r["tool_name"]: r for r in fetch_all(cur, """
            SELECT tool_name, count(*) AS uses, COALESCE(round(avg(latency_ms)),0) AS avg_latency_ms,
                   COALESCE(sum(total_tokens),0) AS total_tokens, COALESCE(sum(est_cost_usd),0) AS est_cost_usd,
                   sum(CASE WHEN ok THEN 0 ELSE 1 END) AS errors, max(ts) AS last_used
            FROM ztpa.ai_metrics GROUP BY tool_name""")}
    out = []
    for t in tools_registry.TOOLS:
        a = agg.get(t["key"], {})
        out.append({**t, "enabled_roles": roles_map.get(t["key"], list(tools_registry.ALL_ROLES)),
                    "metrics": {"uses": int(a.get("uses") or 0), "avg_latency_ms": int(a.get("avg_latency_ms") or 0),
                                "total_tokens": int(a.get("total_tokens") or 0),
                                "est_cost_usd": float(a.get("est_cost_usd") or 0),
                                "errors": int(a.get("errors") or 0), "last_used": a.get("last_used")}})
    return {"tools": out, "roles": list(tools_registry.ALL_ROLES)}


class ToolRolesBody(BaseModel):
    enabled_roles: list[str]


@app.post("/api/admin/tools/{key}")
def admin_set_tool(key: str, body: ToolRolesBody, _: None = Depends(require_admin)):
    if key not in tools_registry.TOOLS_BY_KEY:
        raise HTTPException(404, "unknown tool")
    roles = [r for r in body.enabled_roles if r in tools_registry.ALL_ROLES]
    with get_conn() as conn, conn.cursor() as cur:
        upsert(cur, "tool_settings", {"tool_key": key, "enabled_roles": roles,
               "updated_by": request_ctx.current().email or "admin"}, ["tool_key"])
        audit(cur, "user", "set_tool_roles", subject=key, detail={"enabled_roles": roles})
    tools_registry.invalidate_cache()
    return {"ok": True, "tool_key": key, "enabled_roles": roles}


# --- Admin: KPI / cost dashboard -------------------------------------------
@app.get("/api/admin/metrics")
def admin_metrics(days: int = Query(30, ge=1, le=365), _: None = Depends(require_admin)):
    with get_conn() as conn, conn.cursor() as cur:
        win = "ts > now() - make_interval(days => %s)"
        totals = fetch_one(cur, f"""
            SELECT count(*) AS calls, COALESCE(sum(total_tokens),0) AS tokens,
                   COALESCE(sum(est_cost_usd),0) AS cost, COALESCE(round(avg(latency_ms)),0) AS avg_latency,
                   sum(CASE WHEN ok THEN 0 ELSE 1 END) AS errors
            FROM ztpa.ai_metrics WHERE {win}""", [days])
        latency = fetch_one(cur, f"""
            SELECT COALESCE(percentile_disc(0.5) WITHIN GROUP (ORDER BY latency_ms),0) AS p50,
                   COALESCE(percentile_disc(0.95) WITHIN GROUP (ORDER BY latency_ms),0) AS p95
            FROM ztpa.ai_metrics WHERE latency_ms IS NOT NULL AND {win}""", [days])
        by_provider = fetch_all(cur, f"""
            SELECT provider, model, count(*) AS calls, COALESCE(sum(total_tokens),0) AS tokens,
                   COALESCE(sum(est_cost_usd),0) AS cost
            FROM ztpa.ai_metrics WHERE {win} GROUP BY provider, model ORDER BY calls DESC""", [days])
        by_capability = fetch_all(cur, f"""
            SELECT capability, count(*) AS calls, COALESCE(sum(total_tokens),0) AS tokens,
                   COALESCE(sum(est_cost_usd),0) AS cost, COALESCE(round(avg(latency_ms)),0) AS avg_latency
            FROM ztpa.ai_metrics WHERE {win} GROUP BY capability ORDER BY calls DESC""", [days])
        by_role = fetch_all(cur, f"""
            SELECT role, count(*) AS calls, COALESCE(sum(total_tokens),0) AS tokens
            FROM ztpa.ai_metrics WHERE {win} GROUP BY role ORDER BY calls DESC""", [days])
        timeseries = fetch_all(cur, f"""
            SELECT to_char(date_trunc('day', ts), 'YYYY-MM-DD') AS day, count(*) AS calls,
                   COALESCE(sum(total_tokens),0) AS tokens, COALESCE(sum(est_cost_usd),0) AS cost
            FROM ztpa.ai_metrics WHERE {win} GROUP BY 1 ORDER BY 1""", [days])
        top_tools = fetch_all(cur, f"""
            SELECT tool_name, count(*) AS uses, COALESCE(sum(total_tokens),0) AS tokens
            FROM ztpa.ai_metrics WHERE {win} GROUP BY tool_name ORDER BY uses DESC LIMIT 8""", [days])
        decisions = fetch_all(cur, "SELECT decision, count(*) AS n FROM ztpa.change_decisions GROUP BY decision")
        staging = fetch_all(cur, "SELECT status, count(*) AS n FROM ztpa.staged_changes GROUP BY status")
        snaps = fetch_one(cur, "SELECT count(*) AS n FROM ztpa.snapshots")
        finds = fetch_one(cur, """
            SELECT count(*) AS findings,
                   COALESCE(sum(CASE WHEN severity_band='critical' THEN 1 ELSE 0 END),0) AS critical
            FROM ztpa.findings WHERE snapshot_id=%s""", [sid()])
    return {
        "days": days,
        "totals": {**totals, "p50_latency": latency["p50"], "p95_latency": latency["p95"]},
        "by_provider": by_provider, "by_capability": by_capability, "by_role": by_role,
        "timeseries": timeseries, "top_tools": top_tools,
        "decisions": {r["decision"]: r["n"] for r in decisions},
        "staging": {r["status"]: r["n"] for r in staging},
        "snapshots": snaps["n"], "findings": finds["findings"], "critical": finds["critical"],
        "active_snapshot": sid(),
    }


class AskBody(BaseModel):
    question: str


@app.post("/api/agent/ask")
def agent(body: AskBody):
    _require_capability("assistant")
    result = agent_ask(engine(), body.question)
    with get_conn() as conn, conn.cursor() as cur:
        audit(cur, "user", "agent_ask", snapshot_id=sid(),
              detail={"question": body.question[:200], "tools": [t["tool"] for t in result.get("trace", [])]})
    return result


@app.get("/api/agent/suggestions")
def agent_suggestions():
    """Question suggestions derived from THIS snapshot's facts (not hardcoded):
    a real cross-tool path terminal, a regulated asset, a real over-permissive
    exposure, and the guardrail-forced findings."""
    from src.config import SENSITIVE_TAGS
    e = engine()
    qs: list[str] = []
    paths = [f for f in e.findings if f.type == "cross_tool_path"]
    if paths and paths[0].signals.get("terminal"):
        qs.append(f"Can the internet reach {paths[0].signals['terminal']}, and through which path and tools?")
    sens = sorted({a.asset_key for a in e.assets if set(a.tags) & SENSITIVE_TAGS})
    if sens:
        qs.append(f"What can reach {sens[0]}?")
    op = [f for f in e.findings if f.type == "over_permissive"]
    if op:
        sig = op[0].signals
        src, dst, svc = sig.get("source"), sig.get("dest_display") or sig.get("dest"), sig.get("service")
        if src and dst:
            qs.append(f"What would happen if I open {svc or 'tcp/22'} from {src} to {dst}?")
    if any(f.forced_critical for f in e.findings):
        qs.append("Which findings are forced-critical, and why?")
    qs.append("Summarize the riskiest exposure in this snapshot.")
    out: list[str] = []
    for q in qs:
        if q not in out:
            out.append(q)
    return {"suggestions": out[:4]}


def _ranked_cached(cur) -> RankedActions:
    """Reuse the persisted ranked actions (same cache /api/actions uses) so the
    report never re-runs the slow ranking model. Computes + persists only if absent."""
    t = sid()
    rows = fetch_all(cur, "SELECT action_id,title,finding_ids,priority,rationale FROM ztpa.ranked_actions WHERE snapshot_id=%s ORDER BY priority", [t])
    if rows:
        return RankedActions(
            actions=[RankedAction(action_id=r["action_id"], title=r["title"], finding_ids=r["finding_ids"],
                                  priority=r["priority"], rationale=r["rationale"]) for r in rows],
            ranked_by="llm",
        )
    ranked = rank_mod.rank(engine().findings)
    persist_ranked_actions(cur, t, ranked)
    return ranked


@app.get("/api/report")
def report():
    """Instant, deterministic report (visuals + numbers + a deterministic narrative).
    The richer LLM narrative is fetched separately so the page never hangs."""
    _require_capability("report")
    e = engine()
    with get_conn() as conn, conn.cursor() as cur:
        ranked = _ranked_cached(cur)
    return orchestrator.posture_facts(e.findings, e.assets, ranked)


@app.get("/api/report/narrative")
def report_narrative():
    """The slow, board-ready LLM narrative (bounded + fail-closed)."""
    _require_capability("report")
    e = engine()
    with get_conn() as conn, conn.cursor() as cur:
        ranked = _ranked_cached(cur)
    return orchestrator.posture_narrative(e.findings, e.assets, ranked)


class IntakeBody(BaseModel):
    text: str


@app.post("/api/intake")
def intake(body: IntakeBody):
    _require_capability("intake")
    return intake_mod.extract(body.text)


class ProposeBody(BaseModel):
    sample: dict
    tool_hint: str = ""


@app.post("/api/connectors/propose")
def propose_connector(body: ProposeBody):
    _require_capability("authoring")
    return authoring.propose_profile(body.sample, body.tool_hint)


@app.get("/api/audit")
def audit_log(limit: int = Query(50, ge=1, le=200)):
    with get_conn() as conn, conn.cursor() as cur:
        rows = fetch_all(cur, "SELECT ts,actor,action,subject,detail FROM ztpa.audit_log ORDER BY ts DESC LIMIT %s",
                         [limit])
    return {"audit": rows}
