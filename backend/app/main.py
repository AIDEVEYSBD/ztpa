"""Network Policy Reviewer API.

Dashboard reads come from Postgres (the precomputed snapshot, the system of
record). Live LLM/agent calls (explain, classify, ask, remediate, report,
suggest, connector-authoring) run on demand. The deterministic engine is held in
memory for live reachability/simulation (identical data to the persisted snapshot).
"""

from __future__ import annotations

import base64
import contextlib
import contextvars
import json
import logging
import os
import sys
import threading
import time
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

from src import ai_config, azure_arm, request_ctx, settings, tools_registry  # noqa: E402
from src.advisory import authoring, campaign as campaign_mod, classify_change, entity_suggest, explain as explain_mod  # noqa: E402
from src.advisory import intake as intake_mod, orchestrator, rank as rank_mod, remediation, report as report_mod  # noqa: E402
from src.advisory import client as llm_client  # noqa: E402
from src.advisory.explain import engine_explanation  # noqa: E402
from src.advisory.client import provider_status  # noqa: E402
from src.agent.assistant import ask as agent_ask  # noqa: E402
from src.analyzers.run_all import EngineResult, reanalyze, run  # noqa: E402
from src.change import staging as staging_mod  # noqa: E402
from src.change.requests import DEMO_REQUESTS  # noqa: E402
from src.change.simulate import simulate_change  # noqa: E402
from src.scenarios import SCENARIOS, write_scenario  # noqa: E402
# `delete_snapshot` is aliased because the admin route below is also called
# `delete_snapshot`: the route definition would otherwise shadow the import, and
# the route would call itself. The alias keeps the two names distinguishable at
# every call site instead of relying on definition order.
from src.db import (  # noqa: E402
    audit, delete_snapshot as delete_snapshot_row, fetch_all, fetch_one, get_conn, ping, upsert,
)
from src.graph.zones import zone_of  # noqa: E402
from src.ids import det_id  # noqa: E402
from src.models import ChangeRequest, RankedAction, RankedActions  # noqa: E402
from src.persist import (  # noqa: E402
    accept_remediation_revision, cache_explanation, delete_asset_merge,
    asset_rows, canonical_rule_rows, correlation_rows, finding_rows, graph_edge_rows,
    graph_node_rows, load_applied_changes, load_asset_merges,
    load_campaign_plan, load_remediation_thread, persist_asset_merge, persist_campaign_plan,
    persist_change_decision, persist_change_decision_row, persist_change_request_row,
    persist_engine_result, persist_ranked_actions, persist_remediation_revision,
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
    allow_methods=["*"], allow_headers=["*"],
    # `x-npr-result-truncated*` rides on the Azure discovery listings: their body is
    # the bare array the shared contract specifies, which has no room to say "there
    # were more". A browser cannot read a response header it was not given
    # permission to, so leaving these off would make the one signal that a dropdown
    # is incomplete invisible to the page that renders it.
    expose_headers=["x-request-id", "x-npr-result-truncated", "x-npr-result-truncated-by"],
)


class _ActorMiddleware:
    """Pure-ASGI middleware: mint the request id, ENFORCE the proxy trust boundary,
    then read the proxy-injected role/email headers and stash them in request_ctx
    so metric recording + per-role tool enforcement can attribute work. Set in the
    async context before the (threadpooled) endpoint runs, so anyio copies the
    values into the worker thread.

    The boundary: when NPR_PROXY_SECRET is configured, EVERY request must present
    the secret -- not only one that claims an identity. The earlier form
    (`claims_identity and not verify(...)`) authenticated the claim rather than
    the request, so a header-less call from the open internet was served as the
    default `viewer`, which reads the entire estate. `request_ctx` documents that
    at length; `request_ctx.secret_required_for` holds the two exemptions
    (/api/live, CORS preflight). Unconfigured, the headers are trusted exactly as
    before and /api/health reports `proxy_auth: false`.

    Order matters and is not accidental: this middleware is added LAST, so it is
    the OUTERMOST layer and sees a request before CORSMiddleware. That is why the
    preflight exemption lives here rather than being left to CORS -- a 401 with no
    CORS headers on the preflight fails the real request before it is ever sent."""

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

        # Two independent reasons to demand the secret, OR'd: the request claims
        # an identity (forged-header defence, unchanged), or the boundary is
        # enforced for this request at all (anonymous-access defence, new).
        claims_identity = any(k.startswith(request_ctx.ACTOR_HEADER_PREFIX) for k in h)
        must_present = request_ctx.secret_required_for(scope.get("path") or "", scope.get("method") or "")
        if (claims_identity or must_present) and not request_ctx.verify_proxy_secret(
                h.get(request_ctx.PROXY_SECRET_HEADER)):
            log.warning("rejected a request that did not come through the proxy", extra={
                "event": "proxy_auth_failed", "path": scope.get("path"),
                "claimed_identity": claims_identity,
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
    """403 a capability the admin Tools screen has turned off for the caller's role.

    Its exact strength, stated in full because this docstring twice claimed more
    than the code delivered ("fail-closed" over a lookup that failed open, then
    "stops the spend even in the outage" over a lookup that exempted admin):

      * a capability nobody has ever configured is ON for every role -- this is an
        opt-out toggle, not an authorization layer. The require_* dependencies
        above are what gate a mutating route, and they run as FastAPI
        dependencies so they cannot be reached around;
      * a capability that has been turned off is OFF, and stays off when the
        database holding that decision becomes unreachable. Every key reached
        from here is an `ai_capability`, and an unreadable ztpa.tool_settings
        resolves those to NOBODY -- admin included (src/tools_registry.py,
        UNKNOWN_SPEND_ROLES). Admin is not carved out precisely because admin is
        who can spend: /api/actions/recompute is admin-only, so an admin
        carve-out was the whole bypass. What an operator keeps during the outage
        is the diagnostic surface -- GET /api/admin/tools, /api/health and every
        read of the estate are gated by ROLE, and never come through here;
      * a disable that was successfully written survives the store breaking
        afterwards: the toggle is applied to the in-process map, and a map that
        can no longer be refreshed decays to the fail-closed answer after
        `_MAX_STALE` rather than being served forever. That decay is also the
        bound on the one residual window -- a sibling worker the toggle never
        reached, holding a map read before it.

    Called from the endpoint BODY rather than as a dependency on purpose: it is
    the second question, asked after the role guard has answered the first, and
    several routes need it only on the branch that actually spends."""
    if not tools_registry.is_enabled(key):
        raise HTTPException(403, f"capability '{key}' is disabled for role {request_ctx.role()}")

_ENGINE: EngineResult | None = None
_DEFAULT_SCENARIO = "demo"
_ACTIVE_SCENARIO = _DEFAULT_SCENARIO

# What the last engine build could and could not do. Read by /api/health so a
# degraded snapshot is reported rather than served as if it were authoritative.
#
# Everything about the snapshot BEING SERVED is read off `_ENGINE` itself
# (`EngineResult.complete` / `.integrity_reasons()`), never mirrored here: a
# second copy of "is this analysis complete?" is a second copy that can go
# stale, and a stale copy of that particular fact reads as a clean estate. What
# lives here is only what the result cannot know about itself -- whether its
# INPUTS loaded, whether it was written, and whether a LATER build was refused.
#
# Every read of a key added after the original five uses `.get()`: several test
# modules replace this dict wholesale with the five they know about, and a
# KeyError in /api/health would turn the honesty endpoint into a 500.
_ENGINE_STATE: dict = {
    "inputs_ok": True,        # confirmed merges + pushed changes actually loaded
    "inputs_error": None,     # why they didn't, if they didn't
    "persisted": None,        # True/False/None(not attempted) for the active snapshot
    "persist_error": None,
    "build_error": None,      # the last engine BUILD that raised, if one did
    # The last build that COMPLETED but was refused publication -- a degraded
    # analysis, or one computed without the operator's merges. The process keeps
    # serving the previous complete snapshot, which is invisible without this.
    "rejected_snapshot": None,
    "rejected_reason": None,
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


EngineInputs = tuple[list[tuple[str, str]], list[dict]]   # (confirmed merges, applied changes)


def _run_engine(scenario: str, inputs: EngineInputs | None = None) -> EngineResult:
    """Run the deterministic engine for a scenario, recording on _ENGINE_STATE
    whether its two DB-backed inputs actually loaded. Every rebuild goes through
    here so no call site can quietly recompute on a truncated input set.

    `inputs` lets a caller that ALREADY holds a transaction hand the two inputs in
    rather than have this function open two more connections to re-read them.
    That is what makes the merge/reset routes atomic: the rows they just wrote are
    not visible to a different connection until they commit, so a rebuild that
    re-read them would recompute the snapshot WITHOUT the change it is persisting
    the consequences of. Passing them in means loaded_ok is true by construction:
    they came off a live cursor."""
    if inputs is not None:
        merges, applied = inputs
        merges_ok = applied_ok = True
    else:
        merges, merges_ok = _load_merges()
        applied, applied_ok = _load_applied()
    missing = [n for n, ok in (("confirmed merges", merges_ok), ("applied changes", applied_ok)) if not ok]
    _ENGINE_STATE.update(
        inputs_ok=not missing,
        inputs_error=("could not load " + " and ".join(missing) + " from the database") if missing else None,
        persisted=None, persist_error=None,
        # A new build supersedes the last refusal: a degraded state that cannot
        # clear is its own lie, and the banner would stay up after one transient
        # bad file. Set again by `_require_publishable_snapshot` if this build is
        # refused too.
        rejected_snapshot=None, rejected_reason=None,
    )
    if missing:
        log.error("engine rebuilt on incomplete inputs", extra={
            "event": "engine_inputs_degraded", "missing": missing, "scenario": scenario})
    return run(label=_run_label(scenario), manual_merges=merges, applied_changes=applied)


def _build_engine(scenario: str, inputs: EngineInputs | None = None) -> EngineResult:
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
        built = _run_engine(scenario, inputs)
    except Exception as exc:
        detail = f"{type(exc).__name__}: {exc}"
        _ENGINE_STATE["build_error"] = f"dataset '{scenario}' could not be analyzed ({detail})"
        log.error("engine build failed", exc_info=True, extra={
            "event": "engine_build_failed", "scenario": scenario, "error": detail})
        raise HTTPException(422, f"the dataset '{scenario}' could not be analyzed: {detail}")
    _ENGINE_STATE["build_error"] = None
    return built


def _publication_block(built: EngineResult) -> str | None:
    """Why this result may not be published as the authoritative snapshot -- or
    None when it may.

    ONE predicate for the two halves of the same question, because they were
    two: the INPUT half ("did the operator's confirmed merges actually load?")
    was fail-closed from Phase 2, and the ANALYSIS half ("did every analyzer
    actually run?") was not gated at all. Phase 1 had replaced "one malformed
    rule aborts the snapshot" with per-analyzer isolation, which is right, but
    the partial result then flowed through the SAME writes as a healthy one --
    and because the snapshot id was a hash of the INPUTS, it landed on the
    healthy run's own rows. Measured: 30 findings replaced by 7 under one id,
    `/api/health` `ok`, `/api/findings` `served_from: "database"`, the compliance
    report 23 findings short, and nothing on any screen saying so.

    A TRUNCATED (`partial`) run is deliberately NOT blocked. Its findings are
    real, it is the only answer that exists for those inputs, and blocking it
    would leave a large estate with no snapshot at all -- so it is written under
    its own id, marked `failed` in the timeline by `persist.snapshot_row`, and
    listed on /api/health. Suppressed nowhere, trusted as a total nowhere.

    `built` is REQUIRED, with no default. An optional result would let a call
    site check the input half and skip the analysis half by omission -- a
    signature whose easiest use is the incomplete check is the same defect this
    function exists to close, one level up.
    """
    if not _ENGINE_STATE.get("inputs_ok", True):
        return _ENGINE_STATE.get("inputs_error") or "the engine's database-backed inputs did not load"
    if built.degraded:
        return ("; ".join(built.integrity_reasons())
                + ". Publishing it would clear the rows of the last complete run")
    return None


def _require_publishable_snapshot(built: EngineResult) -> None:
    """Refuse to PERSIST a snapshot that is not a complete analysis of the
    operator's real inputs -- and record the refusal so it is visible.

    Called BEFORE `_ENGINE` (or `_ACTIVE_SCENARIO`) is rebound on every write
    path, which is what makes the exit criterion hold: the 503 leaves the
    previous complete snapshot both SERVED and PERSISTED, rather than leaving the
    process holding a partial one it has already refused to write."""
    blocked = _publication_block(built)
    if blocked is None:
        return
    _ENGINE_STATE.update(rejected_snapshot=built.snapshot_id, rejected_reason=blocked)
    log.error("refusing to publish a snapshot that is not authoritative", extra={
        "event": "snapshot_publication_refused", "reason": blocked,
        "snapshot_id": built.snapshot_id,
        "degraded_analyzers": sorted(d["analyzer"] for d in built.degraded_analyzers),
    })
    raise HTTPException(503, f"refusing to persist a degraded snapshot: {blocked}")


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
        blocked = _publication_block(_ENGINE)
        if blocked:
            # Live-only degraded mode: serve the snapshot but never write it, so a
            # transient DB error cannot overwrite the real one with a truncated
            # recompute, and a run that lost a finding class cannot overwrite one
            # that did not. /api/health reports the degradation, and every read
            # payload carries `analysis_complete` / `degraded_analyzers`.
            #
            # This is the one path that SERVES a degraded result: it is the cold
            # build, so there is no previous complete snapshot to fall back to and
            # the alternative is a process that answers nothing. Disclosed
            # everywhere, written nowhere -- the write paths refuse it outright.
            _ENGINE_STATE.update(persisted=False, persist_error=blocked)
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


@app.exception_handler(azure_arm.ArmError)
def _arm_exception(request: Request, exc: azure_arm.ArmError) -> JSONResponse:
    """Azure discovery failures, as a TYPED envelope rather than an empty list.

    This handler is the mechanism behind the one rule `src/azure_arm.py` exists
    to hold: a dropdown that is empty because the app's identity has no `Reader`
    assignment must not look like a dropdown that is empty because the customer
    owns no Foundry accounts. So no discovery route ever catches an `ArmError`
    itself -- it cannot be forgotten on a branch, and it cannot decay into
    `return []` under a later edit.

    The envelope is `{detail, error, code, azure_detail, request_id}`: `detail`
    and `error` are the same human sentence every other error in this API
    carries (frontend/lib/api.ts flattens `detail` and renders it), `code` is the
    machine-readable `ArmError.kind` so the UI can branch without parsing
    English, and `azure_detail` is ARM's own message -- which for the
    authorization case names the exact missing permission and scope, and is the
    single most useful string an operator can be handed.

    `exc.status` is chosen by the raising module and is deliberately NOT a
    passthrough of ARM's status: ARM's 403 ("this app's identity lacks Reader")
    becomes 502 here, because a 403 from `/api/admin/*` already means "you are
    not an admin of this product" and the two are fixed by different people.
    """
    log.warning("azure discovery failed", extra={
        "event": "azure_discovery_failed", "code": exc.kind, "status": exc.status,
        "path": request.url.path, "azure_detail": exc.detail})
    return JSONResponse(status_code=exc.status,
                        content={**exc.payload(), "request_id": request_ctx.request_id()})


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

    # Is the ANALYSIS behind the snapshot we are serving complete? Read off the
    # result itself rather than a mirror of it (see `_ENGINE_STATE`). This is the
    # gap the audit measured: with two analyzers raising, this endpoint answered
    # 200 `"status":"ok"` `degraded_reasons: []` over a snapshot missing 23 of its
    # 30 findings, because `degraded_analyzers` was populated, logged, and read by
    # nothing. A missing finding class and a path scan that ran out of budget are
    # both listed, in the served result's own words.
    served = _ENGINE
    analysis: dict = {"complete": None, "degraded_analyzers": None, "truncated": None}
    if served is not None:
        reasons.extend(served.integrity_reasons())
        analysis = {
            "complete": served.complete,
            "degraded_analyzers": sorted(d["analyzer"] for d in served.degraded_analyzers),
            "truncated": served.partial,
        }
    # A build that came back incomplete and was refused publication: reads keep
    # working off the last complete snapshot -- which is the correct thing to
    # serve, and completely invisible without this line.
    if _ENGINE_STATE.get("rejected_reason"):
        reasons.append(
            f"the last engine rebuild was refused publication and the previous complete snapshot "
            f"is still being served ({_ENGINE_STATE['rejected_snapshot']}): "
            f"{_ENGINE_STATE['rejected_reason']}")

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
        "snapshot": {"persisted": snapshot_persisted, "inputs_ok": _ENGINE_STATE["inputs_ok"],
                     # The completeness of the ANALYSIS, beside the completeness
                     # of its inputs -- the two halves of "is this snapshot worth
                     # believing?", which used to have one half answered.
                     "analysis": analysis,
                     "rejected_snapshot": _ENGINE_STATE.get("rejected_snapshot")},
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
    # Built into a LOCAL first: `_ENGINE = _build_engine(...)` published the new
    # result before anything had checked it, so a rebuild that lost an analyzer
    # became the snapshot this process served even though the 503 below refused
    # to write it -- the served estate and the system of record then disagreed,
    # silently, in the under-reporting direction.
    built = _build_engine(_ACTIVE_SCENARIO)
    _require_publishable_snapshot(built)
    _ENGINE = built
    snap = _ENGINE.snapshot_id
    with get_conn() as conn, conn.cursor() as cur:
        summary = persist_engine_result(cur, _ENGINE)
        summary["timings"] = _ENGINE.timings
        summary["paths"] = sum(1 for f in _ENGINE.findings if f.type == "cross_tool_path")
        cur.execute("DELETE FROM ztpa.ranked_actions WHERE snapshot_id=%s", [snap])
        cur.execute("UPDATE ztpa.findings SET explanation=NULL WHERE snapshot_id=%s", [snap])
        audit(cur, "recompute_snapshot", subject=snap, snapshot_id=snap, detail=summary)
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
    # The publication gate runs BEFORE the rebind, for the same reason the build
    # does: a scenario whose analysis came back incomplete must leave no residue
    # either, or the failing dataset becomes the active one and every later lazy
    # rebuild reproduces it.
    _require_publishable_snapshot(built)
    _ACTIVE_SCENARIO, _ENGINE = body.scenario, built
    snap = _ENGINE.snapshot_id
    with get_conn() as conn, conn.cursor() as cur:
        summary = persist_engine_result(cur, _ENGINE)
        summary["timings"] = _ENGINE.timings
        summary["paths"] = sum(1 for f in _ENGINE.findings if f.type == "cross_tool_path")
        cur.execute("DELETE FROM ztpa.ranked_actions WHERE snapshot_id=%s", [snap])
        cur.execute("UPDATE ztpa.findings SET explanation=NULL WHERE snapshot_id=%s", [snap])
        audit(cur, "switch_dataset", subject=body.scenario, snapshot_id=snap, detail=summary)
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


def _analysis_block(t: str) -> dict:
    """How complete the analysis behind snapshot `t` was, for the payload.

    `degraded_analyzers` was populated by the engine, logged, and read by
    NOTHING -- `grep -rn degraded_analyzers backend/app frontend db` returned
    zero hits, so a compliance report 23 findings short rendered exactly like a
    complete one. It is carried here on every read that makes a claim about the
    estate as a whole.

    THREE-VALUED ON PURPOSE. `null` is not `[]`. The in-memory result describes
    the ACTIVE snapshot only, so a read of a HISTORICAL one gets `null` --
    "this process cannot say", which is true -- rather than `[]`, which would be
    a positive claim that a snapshot it has never analyzed was complete. (The
    `snapshots` table has no column for this yet; a client that needs it for a
    historical run needs the migration named in the remediation report.)"""
    live = _ENGINE
    if live is None or t != live.snapshot_id:
        return {"analysis_complete": None, "degraded_analyzers": None, "truncations": None}
    block = {
        "analysis_complete": live.complete,
        "degraded_analyzers": sorted(d["analyzer"] for d in live.degraded_analyzers),
        "truncations": live.truncations,
    }
    if _ENGINE_STATE.get("rejected_reason"):
        # This payload is complete, and it is also not the newest analysis: a
        # later rebuild was refused. Both facts, or the reader concludes the
        # estate is current when it is deliberately frozen.
        block["last_build_rejected"] = _ENGINE_STATE["rejected_reason"]
    return block


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
    """Drop a snapshot: its engine-derived rows AND the `snapshots` row itself.

    `delete_snapshot_row` (src.db.delete_snapshot), not
    `delete_snapshot_children`. Phase 2 split that one function in two --
    "clear the engine's cache for this snapshot" and "remove this snapshot" --
    because the old single implementation cleared children by deleting the
    PARENT row and letting the cascade take everything, governance included.
    This route kept calling the children-only half under a comment claiming it
    deleted the parent, so a 200 `{"deleted": ...}` left the row exactly where it
    was, with its findings gone: the snapshot list still showed it, now reading
    0 findings / 0 assets. The governance record survives this either way -- the
    request keeps its decision and loses only its baseline pointer, which
    db/migrations/0001 made `ON DELETE SET NULL` for exactly this case.
    """
    if snapshot_id == sid():
        raise HTTPException(400, "Cannot delete the active snapshot. Switch dataset or recompute first.")
    with get_conn() as conn, conn.cursor() as cur:
        delete_snapshot_row(cur, snapshot_id)
        audit(cur, "delete_snapshot", subject=snapshot_id, detail={})
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
                **_analysis_block(t), **provenance}
    return {"snapshot": snap, "counts": counts, "viewing": t, "active": sid(),
            **_analysis_block(t), "served_from": _DB_SOURCE}


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
        # FOUR arguments, not two. `zone_of` grew `cidrs` and `kind` precisely so
        # that a NAMED object classifies like the address space it dereferences
        # to -- and this call site kept the old 2-argument form, so the console
        # re-derived a different zone than the engine scored with.
        #
        # Measured: `ANY-EXTERNAL` (ip_set ["0.0.0.0/0"]) came back "internal"
        # here while `graph.build` filed it "internet". The boundary multiplier
        # the severity used was 1.5; the zone the screen printed implied 1.0. A
        # user reading the map saw an internal-to-internal grant sitting on a
        # finding scored as an internet ingress, with no way to tell which was
        # right. Named objects are how real AlgoSec / Palo Alto / Check Point
        # policies overwhelmingly express `any`, so this was the common case.
        #
        # `graph_nodes.kind` is the DB vocabulary (internet | subnet | asset),
        # which is `node_db_kind`'s output, so it is mapped back onto the
        # concrete/abstract axis `zone_of` reads. "internet" maps to abstract
        # because it denotes address space rather than being a host.
        db_kind = n.get("kind")
        n["zone"] = zone_of(n["node_id"], n.get("tags") or [], n.get("ip_set") or [],
                            "concrete" if db_kind == "asset" else "abstract")
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

# --- /api/findings paging --------------------------------------------------
# The endpoint had no limit at all. Measured on a 51-node mesh: 57.8 MB in one
# response, 975 MB process RSS, and a browser that stops being able to render
# the console at all -- while /api/health answered `ok` in 3.5 s. A page bounds
# the blast radius of an estate this API cannot yet analyze in bounded time
# (that is workstream C1); it does not pretend the estate is smaller, which is
# what `total` is for.
#
# 500 rows is the page. Measured: a demo finding serializes to 962 bytes on
# average and 1,261 at its widest (500 -> 0.63 MB), and the mesh findings behind
# the 57.8 MB measurement average ~2.9 KB because `signals.path` carries a whole
# chain (500 -> ~1.5 MB). Both clear the audit's "< 2 MB by default" bar, and 500
# is far more than the demo's 31 -- so the demo, and any estate of a realistic
# size, is unpaged and byte-identical to what this endpoint returned before.
_FINDINGS_LIMIT_DEFAULT = 500
_FINDINGS_LIMIT_MAX = 5000

# The total order both sources page on. `ORDER BY forced_critical DESC, severity
# DESC, type` is NOT a total order -- the demo alone has 31 findings across 5
# types, so ties are the norm, and a keyset cursor over a non-total order silently
# skips and repeats rows across pages. `finding_id` breaks every tie; the SQL
# says so explicitly rather than leaving the tiebreak to the planner (the
# in-memory fallback has always sorted this way, so this also removes a real
# disagreement between the two sources).
_FINDINGS_ORDER = "ORDER BY forced_critical DESC, severity DESC, type, finding_id"


def _finding_sort_key(row: dict) -> tuple:
    """`_FINDINGS_ORDER` as a Python key, so the memory fallback pages the same
    rows in the same order the database would have returned."""
    return (not row["forced_critical"], -row["severity"], row["type"], row["finding_id"])


def _encode_cursor(row: dict) -> str:
    """The last row of a page, as an opaque continuation token.

    Keyset, not OFFSET: an offset over a table the engine re-writes on every
    recompute walks a moving list, so page 2 can skip a critical finding that
    page 1 already pushed down. The token carries the WHOLE sort key, so the
    continuation is exact rather than positional, and a token whose shape no
    longer matches fails the decode below loudly rather than resuming from an
    arbitrary place."""
    payload = json.dumps([bool(row["forced_critical"]), int(row["severity"]),
                          str(row["type"]), str(row["finding_id"])], separators=(",", ":"))
    return base64.urlsafe_b64encode(payload.encode("utf-8")).decode("ascii").rstrip("=")


def _decode_cursor(cursor: str) -> tuple[bool, int, str, str]:
    """The token back into its sort key -- or a 400 that names the field.

    A malformed cursor must never fall back to "page 1": a client looping until
    `next_cursor` is null would then loop forever over the first page and read it
    as the whole estate. Every failure here is the caller's, and is answered as
    one."""
    try:
        padded = cursor + "=" * (-len(cursor) % 4)
        forced, severity, type_, finding_id = json.loads(base64.urlsafe_b64decode(padded))
        return bool(forced), int(severity), str(type_), str(finding_id)
    except Exception:
        # `from None`: the base64/JSON error is about the token, not about this
        # API, and chaining it would put a decoder traceback in the 400's context
        # for something the caller can fix by resending `next_cursor` verbatim.
        raise HTTPException(400, "cursor is not a continuation token from a previous "
                                 "/api/findings page (pass the response's next_cursor "
                                 "verbatim)") from None


@app.get("/api/findings")
def findings(snapshot: str | None = None,
             limit: int = Query(_FINDINGS_LIMIT_DEFAULT, ge=1, le=_FINDINGS_LIMIT_MAX),
             cursor: str | None = None):
    """One page of findings, worst first, with the size of the whole set.

    `{findings, total, limit, next_cursor, has_more}`: `total` is the count for
    the snapshot, so a page is never mistakable for the estate -- a screen that
    cannot say "500 of 20,431" invites the reader to assume they are seeing
    everything, which is this product's characteristic failure. `next_cursor` is
    null exactly when this page is the last one: the query asks for `limit + 1`
    rows and returns `limit`, so "is there more?" is answered by a row that
    exists rather than by comparing against a `total` counted in a separate
    statement.

    Also carries `analysis_complete` / `degraded_analyzers` / `truncations`: a
    count of findings is only as meaningful as the analysis behind it, and this
    is the payload that publishes the count."""
    t = view_sid(snapshot)
    after = _decode_cursor(cursor) if cursor else None
    try:
        with get_conn() as conn, conn.cursor() as cur:
            total = int((fetch_one(cur, "SELECT count(*) AS n FROM ztpa.findings WHERE snapshot_id=%s",
                                   [t]) or {}).get("n", 0) or 0)
            # Row-wise comparison on the ASCENDING spelling of the sort key, so
            # one predicate expresses "everything after this row" across all four
            # columns -- the alternative (a nest of OR'd equalities) is where
            # keyset paging bugs live. `NOT forced_critical` and `-severity` turn
            # the two DESC columns into ASC ones; false sorts before true, so a
            # forced-critical row is `false` here and pages first.
            where, params = "snapshot_id=%s", [t]
            if after is not None:
                where += " AND (NOT forced_critical, -severity, type, finding_id) > (%s,%s,%s,%s)"
                params += [not after[0], -after[1], after[2], after[3]]
            rows = fetch_all(cur, f"""
                SELECT finding_id,type,severity,severity_band,forced_critical,signals,involved,raw_refs,
                       source_tools,explanation FROM ztpa.findings WHERE {where}
                {_FINDINGS_ORDER} LIMIT %s""", params + [limit + 1])
        provenance = {"served_from": _DB_SOURCE}
    except HTTPException:
        raise
    except Exception as exc:
        live, provenance = _memory_fallback(t, "findings", exc)
        # The SQL's ORDER BY, plus finding_id as the tiebreak Postgres leaves to
        # the planner -- this API's answer has to be byte-stable, so nothing may
        # be left to an arbitrary order.
        every = sorted(_narrow(finding_rows(live), _FINDING_COLS), key=_finding_sort_key)
        total = len(every)
        if after is not None:
            every = [row for row in every
                     if _finding_sort_key(row) > (not after[0], -after[1], after[2], after[3])]
        rows = every[:limit + 1]
    # The overshoot row is the answer to "is there more?", and it never leaves
    # this function. Computing it from `total` instead would be wrong on the
    # persisted path, where the count and the page are two statements with a
    # possible recompute between them.
    has_more = len(rows) > limit
    rows = rows[:limit]
    next_cursor = _encode_cursor(rows[-1]) if has_more and rows else None
    _attach_engine_explanations(rows)
    return {"findings": rows, "total": total, "limit": limit,
            "next_cursor": next_cursor, "has_more": has_more,
            **_analysis_block(t), **provenance}


def _attach_engine_explanations(rows: list[dict]) -> None:
    """Give every finding the explanation the ENGINE can always write.

    The console rendered "No explanation has been written for this finding yet"
    on every finding nobody had manually pressed "Ask the advisory layer" for.
    That sentence was false. The engine computed the finding; it can always say
    what it means. What it cannot do without a model is write PROSE, and those
    are two different claims that were collapsed into one empty panel.

    So two fields travel, separately attributed and never merged:

      engine_explanation  deterministic, always present, no model, no network
      explanation         model prose, null until somebody asks for it

    The UI shows the first immediately and offers the second as an upgrade. A
    reader is never shown an absence where a fact exists, and a deterministic
    sentence is never dressed up as model judgment.

    Built from the row's own signals rather than from a lookup, so it works
    identically on the persisted path and the in-memory fallback.
    """
    for row in rows:
        try:
            row["engine_explanation"] = engine_explanation(_FindingLike(row))
        except Exception:
            # A malformed signals blob must not take down the findings list --
            # but it must not pass in silence either. The title is the
            # analyzer's own deterministic one-liner and is still a true
            # sentence about the finding, so the row degrades to that.
            log.warning("could not build the engine explanation for a finding",
                        exc_info=True,
                        extra={"event": "engine_explanation_failed",
                               "finding_id": row.get("finding_id"),
                               "finding_type": row.get("type")})
            row["engine_explanation"] = row.get("signals", {}).get("title") or row.get("type", "")


class _FindingLike:
    """Adapts a findings ROW to the attribute access `explain._fallback` expects.

    The row comes back from SQL as a dict and from the memory path as a dict
    too, while `_fallback` was written against the pydantic `Finding`. Adapting
    here keeps one implementation of every explanation rather than a second copy
    that reads dicts -- two copies of this prose would drift, and the drift would
    only show on whichever path is less exercised.
    """

    def __init__(self, row: dict) -> None:
        self.id = row.get("finding_id", "")
        self.type = row.get("type", "")
        self.signals = row.get("signals") or {}
        self.raw_refs = row.get("raw_refs") or []
        self.source_tools = row.get("source_tools") or []
        self.severity = row.get("severity", 0)
        self.severity_band = row.get("severity_band", "low")
        self.forced_critical = row.get("forced_critical", False)
        self.title = self.signals.get("title") or row.get("title") or ""


@app.get("/api/findings/{fid}")
def finding_detail(fid: str):
    with get_conn() as conn, conn.cursor() as cur:
        row = fetch_one(cur, "SELECT * FROM ztpa.findings WHERE finding_id=%s AND snapshot_id=%s", [fid, sid()])
    if not row:
        raise HTTPException(404, "finding not found")
    return row


_EXPLAIN_TIMEOUT = 180.0
_explaining: set[str] = set()   # findings whose LLM explanation is being computed in the background


def _spawn(name: str, fn, *args) -> None:
    """Start a daemon thread that INHERITS this request's context.

    `threading.Thread` starts with an empty ContextVar context, so work moved off
    the request path lost the actor and the request id: an explanation a named
    admin asked for was recorded against the anonymous `viewer` default in
    ai_metrics, and (now that db.audit reads the actor itself) would be written
    into the audit trail under the same fiction. `contextvars.copy_context()`
    snapshots role, email, sub and request id here, in the request, and
    `ctx.run` re-establishes them inside the thread -- so the background work is
    attributed to whoever caused it and its log lines carry the same request id
    as the response that started it."""
    ctx = contextvars.copy_context()
    threading.Thread(target=ctx.run, args=(fn, *args), name=name, daemon=True).start()


def _bg_explain(fid: str, f) -> None:
    """Compute the LLM explanation off the request path and cache it. Cold local
    models can take minutes; doing this in the background means the HTTP request
    (which a dev proxy would reset) already returned the deterministic version."""
    try:
        result = explain_mod.explain(f, timeout=_EXPLAIN_TIMEOUT)
        if result.get("by") != "engine_fallback" and result.get("explanation", "").strip():
            with get_conn() as conn, conn.cursor() as cur:
                cache_explanation(cur, fid, result["explanation"], result.get("by"))
                audit(cur, "explain_finding", subject=fid, snapshot_id=sid(),
                      detail={"by": result["by"]}, actor_kind="agent")
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
        _spawn(f"explain-{fid}", _bg_explain, fid, f)
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
        audit(cur, "remediate_finding", subject=fid, snapshot_id=sid(), actor_kind="agent",
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
        audit(cur, "campaign_plan", snapshot_id=sid(), actor_kind="agent",
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
    are skipped and reported. Idempotent: re-submitting upserts the same requests.

    Three phases, and the middle one holds nothing: READ the plan, RULE on every
    step (a full engine re-analysis each, no connection), then WRITE the whole
    batch in one short transaction. It used to be a single transaction wrapped
    around all three, so a 40-step campaign pinned a pooled connection through 40
    re-analyses -- with ten connections in the pool, two concurrent submissions
    and the console went down with them."""
    _require_capability("classify")
    with get_conn() as conn, conn.cursor() as cur:
        plan = load_campaign_plan(cur, sid())
    if not plan:
        raise HTTPException(400, "no campaign plan to submit; plan the campaign first")

    ruled, skipped = [], []
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
        ruled.append((step, _rule_remediation(fid, change, justification=body.justification,
                                              origin="campaign")))

    submitted = []
    with get_conn() as conn, conn.cursor() as cur:
        # One transaction for the batch, deliberately: a campaign submission is an
        # all-or-nothing act, and half a campaign in the Change Gate is worse than
        # none. What changed is that nothing expensive happens inside it any more.
        for step, r in ruled:
            res = _record_remediation(cur, r)
            submitted.append({"n": step.get("n"), "finding_id": res["finding_id"],
                              "request_id": res["request_id"], "decision": res["decision"]["decision"]})
        audit(cur, "campaign_submit", subject=sid(), snapshot_id=sid(),
              detail={"submitted": len(submitted), "skipped": len(skipped)})
    return {"submitted": submitted, "skipped": skipped,
            "auto_approved": sum(1 for s in submitted if s["decision"] == "auto_approve"),
            "escalated": sum(1 for s in submitted if s["decision"] == "escalate")}


# --- ranking: the model call, and where it is allowed to happen --------------
# THE RULE THIS SECTION EXISTS FOR: no model call may run while a pooled database
# connection is checked out. `rank()` is the worst offender in the codebase --
# `settings.OLLAMA_TIMEOUT` defaults to 600 seconds and the pool is ten
# connections deep with a 30s acquire timeout, so eleven people opening the Risks
# tab on a cold model starved every other endpoint in the process. It also ran on
# a GET, so a prefetch or a double render fired two of them.
#
# What replaces it:
#   * GET /api/actions is a PURE READ. Cache hit -> the persisted rows. Cache
#     miss -> the deterministic ranking (no model, no connection, instant), the
#     LLM ranking started on a background thread, and `pending: true` on the
#     payload so the UI can say which one it is showing.
#   * POST /api/actions/recompute is where a caller ASKS for the model, and it
#     computes first and opens a transaction second.
#   * both go through `_rank_once`, which is single-flighted: ten concurrent
#     callers share ONE ranking run instead of paying for ten.

_ACTION_COLS = "action_id,title,finding_ids,priority,rationale"
_ACTIONS_SQL = (f"SELECT {_ACTION_COLS} FROM ztpa.ranked_actions "
                "WHERE snapshot_id=%s ORDER BY priority")


class _SingleFlight:
    """One in-flight computation per key; everyone else waits and shares its result.

    Not an lru_cache and not a lock: a plain lock would serialise ten callers into
    ten SEQUENTIAL ranking runs, which is worse than the concurrent ten it
    replaces. Here the first caller computes and the rest block on its Event, so
    the model is asked once. The leader's exception is re-raised to the
    followers -- a failure shared is still one answer, and a follower that
    silently got `None` would look like an empty estate."""

    class _Call:
        __slots__ = ("done", "value", "error")

        def __init__(self) -> None:
            self.done = threading.Event()
            self.value: object = None
            self.error: BaseException | None = None

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._calls: dict[str, "_SingleFlight._Call"] = {}

    def run(self, key: str, fn):
        with self._lock:
            call = self._calls.get(key)
            leader = call is None
            if leader:
                call = self._Call()
                self._calls[key] = call
        if not leader:
            call.done.wait()
            if call.error is not None:
                raise call.error
            return call.value
        try:
            call.value = fn()
        except BaseException as exc:      # noqa: BLE001 - re-raised below, after the followers are freed
            call.error = exc
            raise
        finally:
            with self._lock:
                # Popped before the Event is set, so a caller arriving after this
                # point starts a fresh run instead of joining a finished one.
                self._calls.pop(key, None)
            call.done.set()
        return call.value


_RANKING = _SingleFlight()


def _rank_once(t: str, findings) -> RankedActions:
    """The LLM ranking for snapshot `t`, computed at most once at a time, with NO
    connection held. `_require_capability('rank')` is checked HERE, at the point
    of spend, so every path that could reach the model goes past the kill switch:
    the recompute route, the report's cache miss, and the background refresh."""
    _require_capability("rank")
    return _RANKING.run(t, lambda: rank_mod.rank(findings))


def _action_rows(ranked: RankedActions) -> list[dict]:
    """A RankedActions in the shape `_ACTIONS_SQL` returns, ordered the same way
    (priority, then action_id -- the tiebreak Postgres would leave to the planner)."""
    return sorted(({"action_id": a.action_id, "title": a.title, "finding_ids": list(a.finding_ids),
                    "priority": a.priority, "rationale": a.rationale} for a in ranked.actions),
                  key=lambda row: (row["priority"], row["action_id"]))


def _persist_ranking(t: str, ranked: RankedActions) -> bool:
    """Write a ranking to the cache in a transaction of its own; returns whether
    it landed. Failure is logged and does not raise: the ranking has already been
    computed and is about to be returned, so losing the CACHE is a cost, not a
    wrong answer -- but the caller that asked for a recompute is TOLD, rather than
    getting a 200 that implies a durable write that did not happen."""
    try:
        with get_conn() as conn, conn.cursor() as cur:
            persist_ranked_actions(cur, t, ranked)
        return True
    except Exception as exc:
        log.error("ranked actions could not be cached; they were computed and served live",
                  exc_info=True, extra={"event": "persist_ranking_failed", "snapshot_id": t,
                                        "error": str(exc)})
        return False


_ranking_bg: set[str] = set()      # snapshots whose LLM ranking is being computed off-request


def _bg_rank(t: str, findings) -> None:
    """Compute the LLM ranking off the request path and cache it, exactly as
    `_bg_explain` does for explanations. The request that triggered this has
    already answered with the deterministic ranking."""
    try:
        ranked = _rank_once(t, findings)
        if ranked.actions:
            _persist_ranking(t, ranked)
    except Exception as exc:
        log.warning("background ranking failed; the deterministic ranking stands",
                    exc_info=True, extra={"event": "bg_rank_failed", "snapshot_id": t,
                                          "error": str(exc)})
    finally:
        _ranking_bg.discard(t)


def _start_bg_rank(t: str, findings) -> bool:
    """Kick off the background ranking unless one is already running for `t`, or
    the caller's role may not spend on ranking at all. Returns whether a richer
    ranking is now on its way, which is what `pending` on the payload means."""
    if not tools_registry.is_enabled("rank"):
        return False                       # the kill switch, applied before the thread
    if t in _ranking_bg:
        return True
    _ranking_bg.add(t)
    _spawn(f"rank-{t}", _bg_rank, t, findings)
    return True


@app.get("/api/actions")
def actions(snapshot: str | None = None):
    """The Risk To-Do list: a READ of the ranked-actions cache.

    It used to be a GET that ran a 600-second-timeout model call inside an open
    transaction and wrote the result. Now the only thing it can spend is a
    deterministic sort, and the model ranking that replaces it arrives on the
    next poll (`pending: true` says so). `ranked_by` names which one you are
    looking at: "cache" (persisted, model-authored), "engine_fallback" (the
    deterministic grouping), or "llm" on the degraded path."""
    t = view_sid(snapshot)
    try:
        with get_conn() as conn, conn.cursor() as cur:
            rows = fetch_all(cur, _ACTIONS_SQL, [t])
    except HTTPException:
        raise
    except Exception as exc:
        # Ranking needs findings, not the database -- the cache is an
        # optimisation, so losing it costs the model's grouping, not the answer.
        # The deterministic ranking is used rather than the model one: this is a
        # GET on a degraded system, and nothing about a database outage makes it
        # the right moment to start a minutes-long model call on the request path.
        live, provenance = _memory_fallback(t, "prioritized actions", exc)
        ranked = rank_mod.rank_deterministic(live.findings)
        return {"actions": _action_rows(ranked), "ranked_by": ranked.ranked_by,
                "pending": False, **provenance}
    if rows or t != sid():
        # Historical snapshots show the cache and nothing else: their findings are
        # not in memory, so there is nothing to rank live even if we wanted to.
        return {"actions": rows, "ranked_by": "cache", "pending": False, "served_from": _DB_SOURCE}
    ranked = rank_mod.rank_deterministic(engine().findings)
    pending = _start_bg_rank(t, engine().findings)
    return {"actions": _action_rows(ranked), "ranked_by": ranked.ranked_by, "pending": pending,
            "served_from": _MEMORY_SOURCE,
            "degraded_reason": ("the model-authored ranking for this snapshot has not been computed yet, "
                                "so these actions are the engine's deterministic grouping"
                                + (" (the model ranking is being computed now)" if pending else
                                   "; ranking is disabled for your role, so it will not be refined"))}


@app.post("/api/actions/recompute")
def recompute_actions(_: None = Depends(require_operator)):
    """Ask the model to re-group and re-rank. THE model call happens here, and it
    happens outside every transaction -- compute first, persist second, which is
    the shape /api/campaign/plan already had right."""
    t = sid()
    ranked = _rank_once(t, engine().findings)
    persisted = _persist_ranking(t, ranked)
    return {"actions": [a.model_dump() for a in ranked.actions], "ranked_by": ranked.ranked_by,
            # An operator who pressed Recompute is told whether the result was
            # written down, rather than reading a 200 as "cached" when the cache
            # write failed and the next page load will recompute all over again.
            "persisted": persisted}


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


def _merge_and_repersist(write, action: str, a: str, b: str) -> dict:
    """Record an identity decision AND the snapshot that follows from it, in ONE
    transaction.

    `write(cur)` is the decision itself (confirm or undo). Everything after it --
    re-reading the merge set, re-resolving identities, re-persisting the snapshot,
    clearing the AI caches keyed on it, the audit row -- happens on the same
    cursor, so the pair either both land or neither does.

    It used to be two transactions with a rebuild between them, and the failure
    that shape allows is specific: the merge commits, the re-persist fails, and
    the estate on screen is now derived from an identity decision the system of
    record does not reflect. Every read after that is a confident wrong answer.

    Reading the inputs off THIS cursor is also what makes it correct: the merge is
    uncommitted, so a rebuild that opened its own connection (which is what
    `_build_engine()` does by default) would not see it and would recompute the
    snapshot WITHOUT the merge, then persist that as the consequence of applying
    it. The engine build is deterministic, in-process and bounded -- no model call
    and no network -- which is the only reason it is allowed inside a transaction
    at all."""
    global _ENGINE
    with get_conn() as conn, conn.cursor() as cur:
        write(cur)
        built = _build_engine(_ACTIVE_SCENARIO, inputs=(load_asset_merges(cur), load_applied_changes(cur)))
        _require_publishable_snapshot(built)
        snap = built.snapshot_id
        persist_engine_result(cur, built)
        cur.execute("DELETE FROM ztpa.ranked_actions WHERE snapshot_id=%s", [snap])
        cur.execute("UPDATE ztpa.findings SET explanation=NULL WHERE snapshot_id=%s", [snap])
        audit(cur, action, subject=f"{a}~{b}", snapshot_id=snap, detail={"a": a, "b": b})
    # Rebound only after the commit: a rolled-back merge must not leave the
    # process serving the snapshot that merge would have produced.
    _ENGINE = built
    return {"assets": len(built.assets), "snapshot_id": snap}


@app.post("/api/assets/merge")
def confirm_merge(body: MergeBody, _: None = Depends(require_operator)):
    """Human-confirm that two suggested duplicates are the same logical asset. The
    decision is durable; the identity layer unifies them on every run from now on."""
    if not body.a or not body.b or body.a == body.b:
        raise HTTPException(400, "provide two distinct asset keys")
    summary = _merge_and_repersist(lambda cur: persist_asset_merge(cur, body.a, body.b, by="human"),
                                   "confirm_merge", body.a, body.b)
    return {"ok": True, "merged": [body.a, body.b], **summary}


@app.post("/api/assets/unmerge")
def undo_merge(body: MergeBody, _: None = Depends(require_operator)):
    """Reverse a previously confirmed merge (the assets split back apart)."""
    summary = _merge_and_repersist(lambda cur: delete_asset_merge(cur, body.a, body.b),
                                   "undo_merge", body.a, body.b)
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
    delta = simulate_change(e.records, e.assets, e.alias_map, req.proposed, e.resolved)
    decision = classify_change.classify_change(req, delta, ctx=e)
    # The ruling is computed from the engine in memory and needs no database. The
    # RECORD of it does, and that write is the one thing here that can fail on its
    # own -- so it is not allowed to take the answer down with it. With no
    # DATABASE_URL (the state this repo ships in) this route used to 500 out of an
    # unguarded get_conn, so the flagship "simulate a custom change" card was dead
    # on any deployment without Postgres even though every input it needs was
    # already in memory. Phase 1 fixed the read endpoints this way; this is the
    # same fix on the one write that can honestly degrade.
    #
    # It degrades LOUDLY: `persisted: false` plus a reason, because a change gate
    # whose decision is not in the compliance trail has done half its job, and the
    # half it skipped is the half the product is sold on.
    persisted, degraded_reason = True, None
    try:
        with get_conn() as conn, conn.cursor() as cur:
            persist_change_decision(cur, sid(), req, decision)
    except Exception as exc:
        persisted = False
        degraded_reason = (f"the decision database is unreachable ({exc}), so this ruling was NOT "
                           f"recorded in the change-decision trail. The decision itself is the "
                           f"engine's and is unaffected; it simply has not been written down.")
        log.error("a change decision could not be persisted; it was returned but not recorded",
                  exc_info=True, extra={"event": "classify_persist_failed", "request_id_cr": req.id,
                                        "decision": decision.decision, "error": str(exc)})
    out = {"request": {"id": req.id, "title": req.title, "justification": req.justification},
           "delta": delta, "decision": decision.model_dump(), "persisted": persisted}
    if degraded_reason:
        out["degraded_reason"] = degraded_reason
    return out


# The change-decision log, as a named constant rather than a literal inside the
# route, so `backend/tests/test_db_governance.py` can execute THE query against a
# real database instead of a copy of it. A test holding its own transcription of
# a query cannot notice the day the route's WHERE clause loses
# `archived_at IS NULL` -- and this is the filter that makes a demo reset look
# like a reset without deleting the compliance record, so it is exactly the one
# worth pinning to the real thing.
LIVE_DECISIONS_SQL = """
    SELECT d.decision_id, d.request_id, d.decision, d.forced_escalate, d.confidence,
           d.model AS decided_by, d.triggering_reason, d.decided_at,
           d.criteria, d.delta_summary,
           r.proposed, r.justification, r.requested_by, r.kind, r.origin,
           r.status AS request_status, r.rejected_by, r.reject_reason,
           s.staged_id, s.status AS staged_status
    FROM ztpa.change_decisions d
    JOIN ztpa.change_requests r ON r.request_id = d.request_id
    LEFT JOIN ztpa.staged_changes s ON s.request_id = d.request_id
    WHERE d.archived_at IS NULL AND r.archived_at IS NULL
    ORDER BY d.decided_at DESC NULLS LAST
    LIMIT %s
"""


@app.get("/api/change-decisions")
def change_decisions_log(limit: int = Query(25, ge=1, le=200)):
    """The change audit trail: every evaluated request joined to how the gate
    ruled on it (decision, guardrail, who decided, when). Reads the
    change_requests + change_decisions tables that classify() writes.

    LIVE rows only. `/api/admin/reset-demo` retires a request and its decision by
    stamping `archived_at` instead of deleting them (src/persist.py), so this
    filter is what makes the reset look like a reset on screen while the rows
    stay in the system of record. Without it the console would show the whole
    history of every demo ever run; without the archive, the reset would still be
    destroying the compliance artifact to get the same picture."""
    with get_conn() as conn, conn.cursor() as cur:
        rows = fetch_all(cur, LIVE_DECISIONS_SQL, [limit])
    return {"decisions": rows}


# --- Risk To-Do -> Change Gate: submit an accepted remediation -------------
class SubmitBody(BaseModel):
    kind: str = "remediation"
    finding_id: str | None = None
    change: dict | None = None
    revision_id: str | None = None
    justification: str | None = None


# A remediation submission is split in two halves on purpose, and the seam is the
# transaction boundary. `_rule_remediation` is the whole ruling -- a full engine
# re-analysis per submission (`remediation._validate` -> `reanalyze`) -- and it
# opens no connection. `_record_remediation` is four statements. The campaign
# batch is what forced the split: it looped `_submit_remediation` inside ONE open
# transaction, so a 40-step campaign held a pooled connection across 40 full
# re-analyses, and any failure discarded every submission that came before it.

def _rule_remediation(finding_id: str, change: dict, revision_id: str | None = None,
                      justification: str | None = None, origin: str = "risk_todo") -> dict:
    """Re-simulate the fix and rule on it: auto_approve if it resolves its finding
    and opens no new critical, else escalate. Pure computation over the in-memory
    engine -- NO database access -- returning the rows to write and the response
    to send. Raises 404 for a finding that is not in the live snapshot."""
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
    return {
        "finding_id": finding_id, "revision_id": revision_id, "origin": origin,
        "request_row": {
            "request_id": request_id, "snapshot_id": sid(), "proposed": proposed,
            "requested_by": request_ctx.current().email or origin, "justification": justification,
            "kind": "remediation", "origin": origin},
        "decision_row": {
            "decision_id": decision_id, "request_id": request_id, "decision": decision, "criteria": crit,
            "triggering_reason": trig if decision == "escalate" else None, "delta_summary": validation,
            "confidence": 1.0 if resolves else 0.5, "forced_escalate": bool(new_crit), "model": "engine"},
        "response": {
            "request_id": request_id, "kind": "remediation", "finding_id": finding_id,
            "decision": {"request_id": request_id, "decision": decision, "criteria": crit,
                         "triggering_reason": trig, "delta_summary": validation,
                         "confidence": 1.0 if resolves else 0.5, "forced_escalate": bool(new_crit),
                         "decided_by": "engine"},
            "target_tool": target_tool},
    }


def _record_remediation(cur, ruled: dict) -> dict:
    """Write one ruling from `_rule_remediation` and return its response shape.
    Statements only: no engine work, so a batch of these is a short transaction."""
    # Through the persist helpers, never a bare upsert: they are the one place
    # that clears `archived_at`, so re-submitting a remediation whose request was
    # retired by a demo reset brings it back onto the board instead of writing a
    # live decision into a row every screen filters out. Ids are deterministic
    # content hashes, so "the same submission again" is the normal case.
    persist_change_request_row(cur, ruled["request_row"])
    persist_change_decision_row(cur, ruled["decision_row"])
    if ruled["revision_id"]:
        accept_remediation_revision(cur, ruled["revision_id"])
    audit(cur, "submit_remediation", subject=ruled["finding_id"], snapshot_id=sid(),
          detail={"decision": ruled["decision_row"]["decision"],
                  "request_id": ruled["request_row"]["request_id"], "origin": ruled["origin"]})
    return ruled["response"]


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
    ruled = _rule_remediation(body.finding_id, body.change, body.revision_id, body.justification)
    with get_conn() as conn, conn.cursor() as cur:
        return _record_remediation(cur, ruled)


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
        # LIVE rows only, like the decision log: a request retired by a demo
        # reset is history, and staging it would push a change nobody currently
        # holds a ruling on. It reads as a 404 -- that request is no longer open.
        row = fetch_one(cur, """
            SELECT d.decision, r.proposed, r.kind, r.origin, r.snapshot_id, r.status
            FROM ztpa.change_decisions d JOIN ztpa.change_requests r ON r.request_id = d.request_id
            WHERE d.request_id = %s AND d.archived_at IS NULL AND r.archived_at IS NULL""",
            [body.request_id])
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
        audit(cur, "push_staged_change", subject=staged_id, snapshot_id=row.get("snapshot_id"),
              detail={"status": plan["status"], "target_tool": row.get("target_tool")})
    return {"staged_id": staged_id, **plan}


@app.delete("/api/staging/{staged_id}")
def staging_delete(staged_id: str, _: None = Depends(require_approver)):
    with get_conn() as conn, conn.cursor() as cur:
        cur.execute("DELETE FROM ztpa.staged_changes WHERE staged_id=%s", [staged_id])
        audit(cur, "discard_staged_change", subject=staged_id, detail={})
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
    """Retire the change-governance working set and recompute a clean baseline.
    Use this to re-run the demo: any pushed change is cleared, so the resolved
    finding reappears on the next recompute.

    It RETIRES rather than deletes the compliance record: `change_requests` and
    `change_decisions` are stamped `archived_at` and stay in the table (the reads
    that feed the console filter them out, so the screen still empties), while
    the working set proper -- staged changes, remediation threads, the cached
    campaign plan -- is deleted. `cleared` reports both, per table. See
    src/persist.reset_change_workflow for why the distinction is the exit
    criterion rather than a nicety.

    ONE transaction, for the same reason the merge routes are: clearing the
    working set and recomputing the baseline that clearing implies are one act.
    Split across two, a failure between them left the governance tables emptied
    and the snapshot still showing the state they described -- a demo reset that
    silently half-happened. The engine rebuild inside the transaction reads its
    inputs off this cursor, so it sees the cleared `staged_changes` (whose pushed
    rows ARE an engine input) rather than the pre-reset overlay a separate
    connection would still have seen."""
    global _ENGINE
    with get_conn() as conn, conn.cursor() as cur:
        cleared = reset_change_workflow(cur)
        built = _build_engine(_ACTIVE_SCENARIO, inputs=(load_asset_merges(cur), load_applied_changes(cur)))
        _require_publishable_snapshot(built)
        snap = built.snapshot_id
        summary = persist_engine_result(cur, built)
        summary["timings"] = built.timings
        summary["paths"] = sum(1 for f in built.findings if f.type == "cross_tool_path")
        cur.execute("DELETE FROM ztpa.ranked_actions WHERE snapshot_id=%s", [snap])
        cur.execute("UPDATE ztpa.findings SET explanation=NULL WHERE snapshot_id=%s", [snap])
        audit(cur, "reset_demo", subject=snap, snapshot_id=snap, detail=cleared)
    _ENGINE = built
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
        audit(cur, "set_tool_roles", subject=key, detail={"enabled_roles": roles})
    # apply_setting, not invalidate_cache: invalidating alone left the PRE-toggle
    # map in place as the fallback, so a settings read that failed right after a
    # successful disable served the capability as still ENABLED, for every role.
    # The row is committed at this point, so the value is knowledge, not a guess.
    tools_registry.apply_setting(key, roles)
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
        # Live rows only: the KPI tile counts the decisions currently on the
        # board, so a demo reset must zero it -- the retired ones are still in
        # the table, they are just not this quarter's work.
        decisions = fetch_all(cur, "SELECT decision, count(*) AS n FROM ztpa.change_decisions "
                                   "WHERE archived_at IS NULL GROUP BY decision")
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


# --- Admin: the AI provider configuration, and Azure resource discovery -----
# THE PROBLEM THESE ROUTES SOLVE. Pointing this product at a customer's own
# Azure AI Foundry deployment used to be a container-spec edit: three environment
# variables, a new revision, no record of who decided it, and no way to tell a
# wrong endpoint from a weak model. The Configuration page replaces that with a
# stored, attributable row (`ztpa.ai_config`, owned by src/ai_config.py) whose
# three Azure fields are DISCOVERED from the operator's own subscription rather
# than typed from memory.
#
# Four properties hold across every route below, and each is a finding from the
# round-2 audit rather than a preference:
#
#   * ADMIN ONLY. Discovery enumerates the customer's cloud estate -- resource
#     group names alone are an inventory -- and /api/admin/ai/test spends model
#     tokens. Both are `Depends(require_admin)`, which runs before the handler
#     body and so cannot be missed on a branch.
#
#   * BOUNDED. Every list route takes `Query(..., ge=1, le=MAX_LIMIT)`, every ARM
#     call carries a timeout, and pagination stops at a page cap. An unbounded
#     synchronous call to somebody else's API on a request path is the exact
#     pattern Phase 2 removed.
#
#   * NO SILENT EMPTY LIST. `[]` from here means Azure was asked and answered
#     "none". Everything else -- no credential, no Reader role, a timeout, a body
#     that is not the documented shape -- raises `ArmError` and leaves as a typed
#     error envelope through `_arm_exception`. No route below catches one, so the
#     distinction cannot decay into `return []` under a later edit.
#
#   * NO MODEL CALL INSIDE AN OPEN TRANSACTION. /api/admin/ai/test reads the
#     configuration, CLOSES the connection, makes the call, then opens a second
#     short transaction for the audit row -- the shape /api/campaign/plan already
#     uses, and the one Phase 2 imposed after /api/actions held a transaction
#     open across a live LLM call.


def _azure_client_id() -> str | None:
    """The user-assigned managed identity discovery should authenticate as.

    Read from the RESOLVED configuration, not straight from the environment, so
    discovery answers the question the operator is actually asking: "can the
    identity this app will use for INFERENCE see my Foundry account?"
    Authenticating discovery as the developer's `az login` while inference runs
    as a managed identity would make the dropdowns fill beautifully and every
    model call 403 -- the two have to be the same principal or the page proves
    nothing.

    `resolve()` never raises and is cached for 30s, so this is safe on a request
    path. `None` means DefaultAzureCredential: the app's system-assigned identity
    in Container Apps, `az login` on a laptop.
    """
    return ai_config.resolve().azure_client_id or None


def _azure_list(items: list, state: dict) -> JSONResponse:
    """A discovery listing, with truncation marked rather than implied.

    The BODY is the bare array the shared contract specifies. The one thing an
    array cannot carry is "there were more" -- and a dropdown silently cut off at
    the limit fails exactly like an empty one: the operator's resource group is
    missing and the page gives them nothing to read. So the bound that stopped
    the listing rides on a header (exposed through CORS above), and
    src/azure_arm.py has already logged it with the request id.
    """
    if not state.get("truncated"):
        return JSONResponse(content=items)
    return JSONResponse(content=items, headers={
        "x-npr-result-truncated": "true",
        "x-npr-result-truncated-by": str(state.get("bound") or "limit"),
    })


@app.get("/api/admin/azure/subscriptions")
def azure_subscriptions(
    limit: int = Query(azure_arm.DEFAULT_LIMIT, ge=1, le=azure_arm.MAX_LIMIT),
    _: None = Depends(require_admin),
) -> JSONResponse:
    """`[{id, name, state}]` -- the subscriptions this app's Azure identity can see.

    Not in the original endpoint contract, and additive on purpose: with more
    than one subscription visible there is no defensible guess about which estate
    to enumerate (`azure_arm.resolve_subscription` refuses to make one), so the
    page needs a way to ask. With exactly one, it is the answer and the other
    three routes default to it without the frontend passing anything.
    """
    state: dict = {}
    return _azure_list(azure_arm.list_subscriptions(client_id=_azure_client_id(),
                                                    limit=limit, state=state), state)


@app.get("/api/admin/azure/resource-groups")
def azure_resource_groups(
    subscription: str | None = Query(None, max_length=64),
    limit: int = Query(azure_arm.DEFAULT_LIMIT, ge=1, le=azure_arm.MAX_LIMIT),
    _: None = Depends(require_admin),
) -> JSONResponse:
    """`[{name, location}]` -- the first dropdown on the Configuration page."""
    state: dict = {}
    client_id = _azure_client_id()
    sub = azure_arm.resolve_subscription(subscription, client_id=client_id)
    return _azure_list(azure_arm.list_resource_groups(sub, client_id=client_id,
                                                      limit=limit, state=state), state)


@app.get("/api/admin/azure/accounts")
def azure_accounts(
    resource_group: str = Query(..., min_length=1, max_length=90),
    subscription: str | None = Query(None, max_length=64),
    limit: int = Query(azure_arm.DEFAULT_LIMIT, ge=1, le=azure_arm.MAX_LIMIT),
    _: None = Depends(require_admin),
) -> JSONResponse:
    """`[{name, endpoint, kind, location}]` -- the accounts in one resource group
    that can actually serve a model call.

    Filtered to `azure_arm.INFERENCE_KINDS`. A Speech or Vision resource has a
    name, an endpoint and a location too, so an unfiltered list looks like a
    perfectly good model dropdown right up until the operator picks one and every
    model call 404s.
    """
    state: dict = {}
    client_id = _azure_client_id()
    sub = azure_arm.resolve_subscription(subscription, client_id=client_id)
    return _azure_list(azure_arm.list_ai_accounts(sub, resource_group, client_id=client_id,
                                                  limit=limit, state=state), state)


@app.get("/api/admin/azure/deployments")
def azure_deployments(
    resource_group: str = Query(..., min_length=1, max_length=90),
    account: str = Query(..., min_length=1, max_length=64),
    subscription: str | None = Query(None, max_length=64),
    limit: int = Query(azure_arm.DEFAULT_LIMIT, ge=1, le=azure_arm.MAX_LIMIT),
    _: None = Depends(require_admin),
) -> JSONResponse:
    """`[{name, model, version, sku}]` -- the model deployments on one account.

    `name` is the DEPLOYMENT name (what goes into the request path and into
    `azure_deployment`); `model` is what it is a deployment OF. They routinely
    differ, which is the whole reason this is a dropdown and not a text box.
    """
    state: dict = {}
    client_id = _azure_client_id()
    sub = azure_arm.resolve_subscription(subscription, client_id=client_id)
    return _azure_list(azure_arm.list_deployments(sub, resource_group, account,
                                                  client_id=client_id, limit=limit,
                                                  state=state), state)


# --- Admin: the stored provider configuration ------------------------------

class AiConfigBody(BaseModel):
    """The Configuration page's form. Mirrors `ztpa.ai_config` exactly, and
    notably has NO key field: the API key for `azure_auth_mode='key'` lives in a
    Container Apps secret surfaced as `AZURE_AI_API_KEY`, never in the database
    and never in a request body that could be echoed back or logged."""

    provider: str
    azure_endpoint: str | None = None
    azure_deployment: str | None = None
    azure_api_version: str | None = None
    azure_auth_mode: str = "identity"
    azure_client_id: str | None = None


class AiTestBody(BaseModel):
    """What /api/admin/ai/test accepts, and why every field is optional.

    The test button posts nothing in the simple case. It MAY post the form's
    current values, and when it does they are compared with what is stored --
    see `ai_config_test`. Every field is optional (`provider` included, unlike
    `AiConfigBody`) so that an empty object, a partial form and no body at all
    are all accepted rather than 422'd: a diagnostic endpoint that refuses the
    request is the least useful possible answer to "is my configuration
    working?".
    """

    provider: str | None = None
    azure_endpoint: str | None = None
    azure_deployment: str | None = None
    azure_api_version: str | None = None
    azure_auth_mode: str | None = None
    azure_client_id: str | None = None

    def is_empty(self) -> bool:
        return not any(v for v in self.model_dump().values())


def _ai_config_payload(cfg: ai_config.AiConfig) -> dict:
    """The stored row, what it RESOLVES to, and whether that can make a call.

    Three questions the Configuration page has to answer at once, and they have
    different answers often enough that collapsing them is a bug: a deployment
    can have no stored row and still be routed at Azure by its container spec
    (`azure_origin: "environment"`), and a row can be complete, saved,
    attributable and still unable to make a single call because it selects key
    auth on a deployment whose `AZURE_AI_API_KEY` was never set.

    Flat, with the stored row's own fields at the top level, because that is what
    the shared contract's `GET -> the current stored config` describes; the
    resolution and readiness blocks are additive alongside it.
    """
    resolved = ai_config.resolve(cfg)
    ready, reason = ai_config.azure_ready(resolved)
    return {
        **cfg.public(),
        "resolved": {
            "provider": resolved.provider,
            "provider_origin": resolved.provider_origin,
            "azure_endpoint": resolved.azure_endpoint,
            "azure_deployment": resolved.azure_deployment,
            "azure_api_version": resolved.azure_api_version,
            "azure_auth_mode": resolved.azure_auth_mode,
            "azure_client_id": resolved.azure_client_id,
            "azure_origin": resolved.azure_origin,
            "config_source": resolved.config_source,
            "azure_endpoint_error": resolved.azure_endpoint_error,
        },
        "azure_ready": ready,
        "azure_reason": reason,
        # A BOOLEAN, never the value: the page has to be able to say "you chose
        # key auth and this deployment has no key" without the key itself ever
        # crossing the API boundary.
        "azure_api_key_present": bool(settings.AZURE_AI_API_KEY),
        "providers": list(ai_config.PROVIDERS),
        "auth_modes": list(ai_config.AZURE_AUTH_MODES),
        "default_api_version": ai_config.DEFAULT_AZURE_API_VERSION,
    }


def _ai_config_or_503(reader):
    """Run a store call, mapping src/ai_config.py's two failures onto the two
    statuses they mean.

    `AiConfigUnavailable` is 503 and NOT an empty configuration -- the whole
    reason that exception type exists is that "no row is stored" and "the store
    could not be read" have different fixes, and answering the second with the
    defaults would show an operator a blank form for a provider that is in fact
    configured and running. `AiConfigError` is 400: the input was refused, and
    the message names the field.
    """
    try:
        return reader()
    except ai_config.AiConfigError as exc:
        raise HTTPException(400, str(exc)) from exc
    except ai_config.AiConfigUnavailable as exc:
        log.error("the AI configuration store is unreachable", extra={
            "event": "ai_config_store_unavailable", "error": str(exc)})
        raise HTTPException(503, str(exc)) from exc


@app.get("/api/admin/ai/config")
def ai_config_get(_: None = Depends(require_admin)) -> dict:
    """The stored advisory-provider configuration. Holds no secret and returns
    none -- see `AiConfigBody` and `ai_config.SECRET_COLUMN_PATTERNS`."""
    return _ai_config_payload(_ai_config_or_503(ai_config.load))


@app.put("/api/admin/ai/config")
def ai_config_put(body: AiConfigBody, _: None = Depends(require_admin)) -> dict:
    """Save the configuration. Validated, audited and attributed by
    `ai_config.save()` inside one transaction, so the row and the record of who
    changed it can never disagree."""
    cfg = ai_config.AiConfig(
        provider=body.provider,
        azure_endpoint=body.azure_endpoint,
        azure_deployment=body.azure_deployment,
        azure_api_version=body.azure_api_version,
        azure_auth_mode=body.azure_auth_mode,
        azure_client_id=body.azure_client_id,
    )
    actor = request_ctx.current().email
    saved = _ai_config_or_503(lambda: ai_config.save(cfg, actor))
    # A changed `azure_client_id` is a changed IDENTITY. Without this, discovery
    # would keep authenticating as the previous one until the process restarted
    # -- a configuration change that appears to do nothing, which is how an
    # operator concludes the page is broken and goes back to the container spec.
    azure_arm.reset_credentials()
    log.info("AI provider configuration saved", extra={
        "event": "ai_config_saved_api", "provider": saved.provider,
        "azure_deployment": saved.azure_deployment})
    return _ai_config_payload(saved)


# The probe. Deliberately trivial and deliberately not JSON: the question is "can
# this deployment reach that model at all", and a model that answers the wrong
# word is still a model that answered, which is the fact under test. Temperature
# 0 so the call is as cheap and as repeatable as the provider allows.
_AI_TEST_SYSTEM = ("You are a connectivity probe for a network policy review tool. "
                   "Answer with a single word and nothing else.")
_AI_TEST_USER = "Reply with the single word: ok"

# The fields compared between a posted test body and the configuration that is
# actually in force. Shared by the drift check and its error message so the two
# cannot list different things.
_AI_CONFIG_FIELDS: tuple[str, ...] = (
    "provider", "azure_endpoint", "azure_deployment", "azure_api_version",
    "azure_auth_mode", "azure_client_id",
)


def _ai_config_drift(body: AiTestBody, resolved: ai_config.Resolved) -> list[str]:
    """Which fields of a posted configuration differ from the one in force.

    Compared through `ai_config.validate()` so both sides are NORMALIZED:
    `https://acct.cognitiveservices.azure.com` and the same string with a
    trailing slash are one configuration, and refusing to test over a slash would
    be a false alarm that teaches an operator to ignore the message. The api
    version is defaulted on both sides for the same reason -- an unset field and
    the default it resolves to are not a difference.

    A body that cannot be validated at all is drift by definition: it is not what
    is stored, because what is stored is valid.
    """
    try:
        posted = ai_config.validate(ai_config.AiConfig(
            provider=body.provider, azure_endpoint=body.azure_endpoint,
            azure_deployment=body.azure_deployment, azure_api_version=body.azure_api_version,
            azure_auth_mode=body.azure_auth_mode or "identity",
            azure_client_id=body.azure_client_id))
    except ai_config.AiConfigError as exc:
        return [f"the values sent are not a valid configuration ({exc})"]
    default_version = ai_config.DEFAULT_AZURE_API_VERSION
    out = []
    for field in _AI_CONFIG_FIELDS:
        mine = getattr(posted, field) or ""
        theirs = getattr(resolved, field) or ""
        if field == "azure_api_version":
            mine, theirs = mine or default_version, theirs or default_version
        if mine != theirs:
            out.append(field)
    return out


@app.post("/api/admin/ai/test")
def ai_config_test(body: AiTestBody | None = None, _: None = Depends(require_admin)) -> dict:
    """Make ONE real call through the configured provider and report what happened.

    `{ok, provider, model, latency_ms, error}`, plus the endpoint and deployment
    that were actually used so the answer names its own subject. This is the
    button an operator presses to find out whether the configuration they just
    saved works, so it must never pass on a configuration that would fail in use.
    Four ways it refuses to.

    IT TESTS WHAT IS IN FORCE, AND SAYS SO. `advisory.client.complete()` reads its
    Azure target from the resolved configuration (`settings.azure_target()`), so
    there is no seam through which an UNSAVED draft could be tested -- a body of
    draft values would be accepted, ignored, and answered with a green tick
    describing the old row. Rather than that, a body that DIFFERS from what is in
    force is refused, naming the fields, with "save it first". Posting no body,
    an empty object, or the stored values tests what is running.

    A PROVIDER SUBSTITUTION IS A FAILURE, NOT A PASS. `complete()` is fail-closed
    by contract: a provider it does not implement falls through to the Ollama
    branch and comes back `ok=True` from a completely different model. Here that
    would be the worst possible answer -- a green tick that appears to prove the
    Azure endpoint works, produced by a local model that never touched it. So the
    provider that answered is compared with the one that was asked for.

    AN EMPTY COMPLETION IS A FAILURE. A 200 carrying no text cannot serve any
    capability in this product. It is also not hypothetical: the reasoning
    deployment on the live Foundry account spends its whole budget in
    `reasoning_content` and returns `content: ""` with `finish_reason: "length"`,
    which is a working endpoint and an unusable configuration.

    A CONFIGURATION THAT CANNOT CALL IS REPORTED, NOT ATTEMPTED. `azure_ready()`
    already knows when key auth is selected with no key in the environment; the
    reason is returned instead of a 401 the operator would have to decode.

    No connection is held across the model call.
    """
    cfg = _ai_config_or_503(ai_config.load)
    resolved = ai_config.resolve(cfg)
    base = {"endpoint": resolved.azure_endpoint or None,
            "deployment": resolved.azure_deployment or None,
            "auth_mode": resolved.azure_auth_mode,
            "config_source": resolved.config_source}

    if body is not None and not body.is_empty():
        drifted = _ai_config_drift(body, resolved)
        if drifted:
            return {**base, "ok": False, "provider": resolved.provider, "model": None,
                    "latency_ms": 0, "tested": "nothing", "sample": "",
                    "error": ("this tests the configuration this deployment is RUNNING, and the "
                              f"values you sent differ from it ({', '.join(drifted)}). Save "
                              "first, then test -- otherwise the result would describe a "
                              "configuration nobody is using.")}

    provider = resolved.provider
    if provider == "auto":
        # `auto` is not a destination, it is the instruction to pick one, so the
        # test resolves it the same way a real call will -- otherwise the button
        # reports on a provider no capability would ever reach.
        provider = settings.active_provider()

    if provider == "azure":
        ready, why = ai_config.azure_ready(resolved)
        if not ready:
            # No call is made, because there is nothing to call. A 200 with
            # ok=False rather than a 4xx: the operator asked "does this work?"
            # and this IS the answer; an HTTP error would leave the page
            # rendering a transport failure instead of the reason.
            return {**base, "ok": False, "provider": provider,
                    "model": resolved.azure_deployment or None, "latency_ms": 0,
                    "error": why, "tested": "the configuration in force", "sample": ""}

    t0 = time.perf_counter()
    res = llm_client.complete(system=_AI_TEST_SYSTEM, user=_AI_TEST_USER, role="judge",
                              temperature=0.0, provider=provider,
                              capability="ai_config_test", subject="config-page")
    latency_ms = round((time.perf_counter() - t0) * 1000)

    ok, error = res.ok, res.error
    if ok and res.provider != provider:
        ok = False
        error = (f"the configured provider is '{provider}' but the advisory client answered as "
                 f"'{res.provider}'. The call did NOT reach the configured endpoint, so this "
                 f"result says nothing about it: '{provider}' is not implemented in "
                 f"src/advisory/client.py on this build.")
    elif ok and not (res.text or "").strip():
        ok = False
        error = ("the provider accepted the call and returned an empty completion"
                 + (f" (finish_reason: {res.finish_reason})" if getattr(res, "finish_reason", None)
                    else "")
                 + ". Nothing in this product can be served by that, so it is not a working "
                   "configuration.")

    payload = {
        **base, "ok": ok, "provider": res.provider, "model": res.model,
        "latency_ms": latency_ms, "error": error, "tested": "the configuration in force",
        # Bounded proof that something really answered, so `ok` is not the only
        # thing the operator has to take on trust.
        "sample": (res.text or "").strip()[:200],
    }
    if provider != "azure":
        payload.update(endpoint=None, deployment=None, auth_mode=None)
    log.info("AI provider test call completed", extra={
        "event": "ai_config_test", "ok": ok, "provider": res.provider, "model": res.model,
        "latency_ms": latency_ms, "error": error})
    # Second transaction, AFTER the call: an admin action that spends tokens is
    # attributable. Best-effort -- a failed audit must not turn a successful
    # probe into a 500, because the probe's answer is what the operator came for
    # -- but never silent.
    try:
        with get_conn() as conn, conn.cursor() as cur:
            audit(cur, "ai_config_test", subject=res.provider,
                  detail={k: payload[k] for k in ("ok", "provider", "model", "latency_ms",
                                                  "error", "endpoint", "deployment")})
    except Exception as exc:  # noqa: BLE001 — the probe's result outranks its audit row
        log.warning("the AI provider test could not be audited", exc_info=True, extra={
            "event": "ai_config_test_audit_failed", "error": str(exc)})
    return payload


class AskBody(BaseModel):
    question: str


@app.post("/api/agent/ask")
def agent(body: AskBody):
    _require_capability("assistant")
    result = agent_ask(engine(), body.question)
    with get_conn() as conn, conn.cursor() as cur:
        audit(cur, "agent_ask", snapshot_id=sid(),
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


def _ranked_cached() -> RankedActions:
    """The ranked actions the report renders, WITHOUT ever holding a connection
    across the model.

    Three steps, each with its own short transaction or none at all:
      1. read the cache (the same rows /api/actions serves);
      2. on a miss, rank OUTSIDE any transaction -- single-flighted, and only if
         `rank` is enabled for this caller, so an admin who turned ranking off
         stops the spend here as well as on the actions screen;
      3. persist, in a transaction of its own.

    It took a cursor before, which is what put a 600-second-timeout model call
    inside the report's open transaction: two people opening the Report tab on a
    cold model held two of the pool's ten connections for the duration.

    A cache read that FAILS is not fatal -- the report is about findings, and
    the ranking is a grouping of them, so a dead database costs the model's
    grouping (and, with it, the persistence of the new one), not the report."""
    t = sid()
    try:
        with get_conn() as conn, conn.cursor() as cur:
            rows = fetch_all(cur, _ACTIONS_SQL, [t])
    except Exception as exc:
        log.warning("the ranked-actions cache could not be read for the report",
                    exc_info=True, extra={"event": "degraded_read", "resource": "ranked actions",
                                          "snapshot_id": t, "error": str(exc)})
        return rank_mod.rank_deterministic(engine().findings)
    if rows:
        return RankedActions(
            actions=[RankedAction(action_id=r["action_id"], title=r["title"], finding_ids=r["finding_ids"],
                                  priority=r["priority"], rationale=r["rationale"]) for r in rows],
            ranked_by="llm",
        )
    ranked = _rank_once(t, engine().findings)
    _persist_ranking(t, ranked)
    return ranked


@app.get("/api/report")
def report():
    """Instant, deterministic report (visuals + numbers + a deterministic narrative).
    The richer LLM narrative is fetched separately so the page never hangs.

    Carries the analysis block for the bluntest reason in the product: this is
    the compliance artefact. The audit's measured case had it reporting
    `total_findings: 7` for an estate whose complete analysis found 30 -- a
    document 23 findings short, with nothing on it to say so. A report that
    cannot state the completeness of the analysis behind its own numbers is not
    a compliance artefact."""
    _require_capability("report")
    e = engine()
    ranked = _ranked_cached()
    return {**orchestrator.posture_facts(e.findings, e.assets, ranked),
            **_analysis_block(e.snapshot_id)}


@app.get("/api/report/narrative")
def report_narrative():
    """The slow, board-ready LLM narrative (bounded + fail-closed)."""
    _require_capability("report")
    e = engine()
    ranked = _ranked_cached()
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


# --- the audit trail's reader ----------------------------------------------
# The trail had 20+ write sites, one endpoint nobody called, and no screen. A
# governance record nobody can read is not a governance record: "every action is
# audited" was true of the INSERTs and false of everything a compliance function
# would do with them.
#
# Admin-only, because this is the one place the actor of every action in the
# system is enumerated -- who recomputed what, who merged which identities, whose
# email approved which change. That is exactly the read an auditor is given the
# ADMIN role for, and exactly the read a viewer is not.
_AUDIT_COLS = ("id, ts, actor, actor_email, actor_sub, actor_role, action, subject, "
               "snapshot_id, detail")


@app.get("/api/audit")
def audit_log(limit: int = Query(50, ge=1, le=200), offset: int = Query(0, ge=0),
              _: None = Depends(require_admin)):
    """The audit trail, newest first, paginated.

    `{items, total, limit, offset}` -- `total` because a page of 50 out of an
    unknown number is not a trail anyone can reason about, and a screen that
    cannot say "50 of 4,213" invites the reader to assume they are seeing
    everything.

    `limit` is bounded by FastAPI (ge=1, le=200) rather than by a hand-rolled
    check, so an out-of-range value is a 422 naming the field instead of a
    silently clamped page or an unbounded scan of the whole table.

    ORDER BY ts DESC, id DESC: `ts` alone is not a total order -- every row
    written inside one transaction shares a `now()` -- so paging on it would
    repeat and skip rows across pages. The id breaks the tie deterministically.

    The actor columns (`actor_email`, `actor_sub`, `actor_role`) are populated
    inside `db.audit()` from `request_ctx`, never by a call site, which is what
    makes them impossible to forget on one branch out of fifteen."""
    with get_conn() as conn, conn.cursor() as cur:
        total = (fetch_one(cur, "SELECT count(*) AS n FROM ztpa.audit_log") or {}).get("n", 0)
        rows = fetch_all(cur, f"SELECT {_AUDIT_COLS} FROM ztpa.audit_log "
                              "ORDER BY ts DESC, id DESC LIMIT %s OFFSET %s", [limit, offset])
    return {"items": rows, "total": int(total or 0), "limit": limit, "offset": offset}


# ═══════════════════════════════════════════════════════════════════════════
# THE INFRASTRUCTURE API — sources, inventory, topology, address drill-down
#
# Five reads that describe the NETWORK rather than the policy on it. They follow
# the same structural contract as every other read in this file: try the
# persisted snapshot, fall back to the running engine through `_memory_fallback`
# (which refuses to answer for a historical snapshot it has never analyzed), and
# carry the provenance block so a caller can tell a persisted answer from a
# recomputed one.
#
# The projections come from `src.topology.project`, the same module
# `persist_engine_result` writes through, so the degraded path serves what the
# database would have held rather than a second implementation of it.
# ═══════════════════════════════════════════════════════════════════════════

from src.sources import BY_KEY as _SOURCE_SPECS, REGISTRY as _SOURCE_REGISTRY  # noqa: E402
from src.topology.reconstruct import LANE_ORDER, LANE_SOURCE_HINT  # noqa: E402
from src.analyzers.resilience import assess as assess_resilience  # noqa: E402
from src.models import Topology  # noqa: E402
from src.netaddr import is_public, parse_net  # noqa: E402
from src.sources import tier_of  # noqa: E402

_LANE_LABEL = {
    "internet": "Internet", "circuit": "WAN circuits", "modem": "Modems / CPE",
    "edge": "Edge routers", "perimeter": "Perimeter firewalls",
    "core": "Core / distribution", "access": "Access layer",
    "segment": "Segments (VLANs & subnets)", "endpoint": "Hosts & workloads",
}

_INVENTORY_LIMIT_DEFAULT, _INVENTORY_LIMIT_MAX = 200, 2000


def _topology_of(t: str) -> tuple[Topology, dict]:
    """The topology for snapshot `t`, plus its provenance block.

    Reads the running engine when it holds `t`, and otherwise refuses via
    `_memory_fallback` rather than serving the live estate under a historical
    id. The persisted read is deliberately NOT attempted separately: the six
    infrastructure tables are written from `topology.project`, so the in-memory
    projection and the stored rows are the same shape by construction, and the
    engine is authoritative for the snapshot it holds.
    """
    live = engine()
    if t == live.snapshot_id:
        # Labelled `engine_memory`, which is what it is. The six infrastructure
        # tables hold byte-identical content (both come from `topology.project`),
        # but this read does not go through them, and a payload claiming
        # `database` would be asserting a round trip that did not happen. The
        # console renders that label as "came from the running engine rather than
        # the persisted snapshot", which is exactly true.
        #
        # An earlier version probed the database with `SELECT 1` to decide the
        # label. With no database configured that probe waited out the pool's
        # 30-second timeout on EVERY request to these five endpoints, so the
        # screens the revamp exists for were the slowest in the product.
        return live.topology, {"served_from": _MEMORY_SOURCE}
    fallback, provenance = _memory_fallback(
        t, "the infrastructure inventory",
        RuntimeError("the running engine holds a different snapshot"))
    return fallback.topology, provenance


def _counts(topo: Topology, live) -> dict:
    """The header readout: "I have these many subnets, these many VLANs...".

    A quantity NO ONBOARDED SOURCE DECLARES is `None`, never 0. That distinction
    is the difference between "this estate has no VLANs" -- a statement about the
    client's network we are in no position to make -- and "nothing we can read
    enumerates VLANs", which is a statement about our coverage and is actionable.
    """
    def declared(items, value):
        return value if items else None
    public = sorted({ip for c in topo.circuits for ip in c.public_ips})
    return {
        "devices": declared(topo.devices, len(topo.devices)),
        "interfaces": declared(topo.interfaces, len(topo.interfaces)),
        "vlans": declared(topo.vlans, len(topo.vlans)),
        # The UNION of both sources of subnet knowledge. Reading only the
        # `subnets` table reported 1 while seven VLANs each declared their own
        # block -- the header said "1 subnet" for a network with eight.
        "subnets": declared(
            topo.subnets or topo.vlans,
            len({s.cidr for s in topo.subnets} | {s for v in topo.vlans for s in v.subnets})),
        "public_ips": declared(topo.circuits, len(public)),
        "circuits": declared(topo.circuits, len(topo.circuits)),
        "assets": len(live.assets),
    }


@app.get("/api/sources")
def sources(snapshot: str | None = None):
    """What we read, from which rung of the ladder, and what it cannot tell us.

    `blind_to` is the field that matters most here and it is why this endpoint
    serves the whole registry rather than only the connected tools: an operator
    looking at an empty access lane needs to know whether that means "no access
    layer" or "nothing onboarded enumerates access switches", and only the
    catalogue can answer the second.

    A source that is NOT connected carries `contributed: null`, never a row of
    zeros -- a zero there reads as "we connected and found nothing".
    """
    t = view_sid(snapshot)
    live = engine()
    topo, provenance = _topology_of(t)

    contributed: dict[str, dict] = {}
    for rec in live.records:
        contributed.setdefault(rec.source_tool, _empty_contribution())["records"] += 1
    for e in getattr(live, "entities", ()) or ():
        contributed.setdefault(e.tool, _empty_contribution())["entities"] += 1
    for field, group in (("devices", topo.devices), ("interfaces", topo.interfaces),
                         ("links", topo.links), ("vlans", topo.vlans),
                         ("subnets", topo.subnets), ("circuits", topo.circuits)):
        for item in group:
            for tool in {item.provenance.source_tool,
                         *(o["tool"] for o in getattr(item, "observed_by", ()) if o.get("tool"))}:
                contributed.setdefault(tool, _empty_contribution())[field] += 1

    simulated = {item.provenance.simulated
                 for group in (topo.devices, topo.interfaces, topo.circuits)
                 for item in group}
    cards = []
    for spec in _SOURCE_REGISTRY:
        connected = spec.key in contributed
        cards.append({
            "tool": spec.key, "label": spec.label, "vendor": spec.vendor,
            "tier": spec.tier, "api": spec.api, "auth": spec.auth,
            "yields": list(spec.yields), "blind_to": list(spec.blind_to),
            "notes": spec.notes or None,
            "connected": connected,
            # Every export in this build is seeded. Stated per card rather than
            # once at the top, because a card is what gets screenshotted.
            "simulated": bool(simulated) and connected,
            "device": spec.device or None,
            "last_sync": None,
            "contributed": contributed.get(spec.key) if connected else None,
        })
    # Anything that contributed but is not in the registry: a bring-your-own
    # profile. Shown as itself rather than dropped, or the screen would omit a
    # source whose rows are visibly on the next screen.
    for tool in sorted(set(contributed) - set(_SOURCE_SPECS)):
        cards.append({
            "tool": tool, "label": tool, "vendor": "(custom profile)",
            "tier": "device", "api": "operator-supplied SourceProfile", "auth": "n/a",
            "yields": [], "blind_to": [], "notes": "Not a shipped integration: this "
            "name comes from an operator's own connector profile.",
            "connected": True, "simulated": bool(simulated), "device": tool,
            "last_sync": None, "contributed": contributed[tool],
        })

    return {
        "sources": cards,
        "counts": {"connected": sum(1 for c in cards if c["connected"]),
                   "available": sum(1 for c in cards if not c["connected"])},
        **_analysis_block(t), **provenance,
    }


def _cidrs_of(live, row: dict) -> list[str]:
    """The source address space behind a matched rule, for the public test.

    Read off the record rather than off the label: a named object like
    `ANY-EXTERNAL` carries its resolved space on `source_cidrs`, and scoring the
    string instead is the exact defect `algosec.py` was rewritten to fix.
    """
    for rec in live.records:
        if rec.raw_ref == row["rule_ref"] and rec.source_tool == row["source_tool"]:
            return list(rec.source_cidrs)
    return []


def _empty_contribution() -> dict:
    return {"records": 0, "entities": 0, "devices": 0, "interfaces": 0,
            "links": 0, "vlans": 0, "subnets": 0, "circuits": 0}


def _vlan_of(addresses: list[str], topo: Topology) -> tuple[int | None, str | None, str | None]:
    """The VLAN and subnet an address set sits in, or (None, None, None).

    Containment against the VLAN's declared subnets, not a name match: the whole
    point of the inventory's "which VLAN" column is that it is computed from
    address space rather than from a label somebody typed.
    """
    for addr in addresses:
        net = parse_net(addr)
        if net is None:
            continue
        for v in topo.vlans:
            for raw in v.subnets:
                block = parse_net(raw)
                if block is not None and net.subnet_of(block):
                    return v.vlan_id, v.name, str(block)
    return None, None, None


def _inventory_items(topo: Topology, live) -> list[dict]:
    """Every entity, in one vocabulary.

    Devices, VLANs, subnets, public IPs and circuits are DIFFERENT KINDS OF
    THING, and the ask lists them side by side for a reason -- a reviewer counts
    them together. So they are projected into one row shape with a `kind`, rather
    than served as five lists the UI has to reconcile.
    """
    items: list[dict] = []
    by_dev: dict[str, list] = {}
    for i in topo.interfaces:
        by_dev.setdefault(i.device_key, []).append(i)
    finding_by_entity: dict[str, list[str]] = {}
    for f in live.findings:
        for name in f.involved:
            finding_by_entity.setdefault(name, []).append(f.id)

    for d in topo.devices:
        ifaces = by_dev.get(d.device_key, [])
        addrs = sorted({a for i in ifaces for a in i.addresses})
        vlan_id, vlan_name, subnet = _vlan_of(addrs, topo)
        items.append({
            "key": d.device_key, "name": d.name, "kind": d.role,
            "role": d.role, "role_source": d.role_source, "role_reason": d.role_reason,
            "vendor": d.vendor, "model": d.model, "os_version": d.os_version,
            "addresses": addrs,
            "vlan_id": vlan_id, "vlan_name": vlan_name, "subnet": subnet,
            "zone": next((i.zone for i in ifaces if i.zone), None),
            "tags": list(d.tags),
            "layer": d.layer, "layer_source": d.layer_source, "layer_reason": d.layer_reason,
            "observed_by": list(d.observed_by) or [{
                "tool": d.provenance.source_tool, "tier": d.provenance.source_tier,
                "raw_ref": d.provenance.raw_ref}],
            "conflicts": list(d.conflicts),
            "finding_ids": sorted(finding_by_entity.get(d.device_key, [])),
        })

    for v in topo.vlans:
        items.append({
            "key": f"vlan-{v.vlan_id}", "name": v.name or f"VLAN {v.vlan_id}", "kind": "vlan",
            "role": None, "role_source": "declared", "role_reason": "",
            "vendor": None, "model": None, "os_version": None,
            "addresses": list(v.subnets), "vlan_id": v.vlan_id, "vlan_name": v.name,
            "subnet": v.subnets[0] if v.subnets else None, "zone": None,
            "tags": list(v.tags), "layer": "segment", "layer_source": "derived",
            "layer_reason": "a VLAN is a segment by definition",
            "observed_by": [{"tool": v.provenance.source_tool,
                             "tier": v.provenance.source_tier,
                             "raw_ref": v.provenance.raw_ref}],
            "conflicts": [], "finding_ids": [],
        })

    for s in topo.subnets:
        items.append({
            "key": f"subnet-{s.cidr}", "name": s.name or s.cidr, "kind": "subnet",
            "role": None, "role_source": "declared", "role_reason": "",
            "vendor": None, "model": None, "os_version": None,
            "addresses": [s.cidr], "vlan_id": s.vlan_id, "vlan_name": None,
            "subnet": s.cidr, "zone": s.zone, "tags": list(s.tags),
            "layer": "segment", "layer_source": "derived",
            "layer_reason": "a subnet is a segment by definition",
            "observed_by": [{"tool": s.provenance.source_tool,
                             "tier": s.provenance.source_tier,
                             "raw_ref": s.provenance.raw_ref}],
            "conflicts": [], "finding_ids": [],
        })

    for c in topo.circuits:
        items.append({
            "key": c.circuit_id, "name": c.circuit_id, "kind": "wan_circuit",
            "role": None, "role_source": "declared",
            "role_reason": f"{c.technology.upper()} from {c.provider or 'an undeclared carrier'}",
            "vendor": c.provider, "model": c.technology, "os_version": None,
            "addresses": list(c.public_ips), "vlan_id": None, "vlan_name": None,
            "subnet": None, "zone": "untrust", "tags": [],
            "layer": "circuit", "layer_source": "declared",
            "layer_reason": "declared by the carrier record",
            "observed_by": [{"tool": c.provenance.source_tool,
                             "tier": c.provenance.source_tier,
                             "raw_ref": c.provenance.raw_ref}],
            "conflicts": [], "finding_ids": [],
        })
        for ip in c.public_ips:
            items.append({
                "key": f"pubip-{ip}", "name": ip, "kind": "public_ip",
                "role": None, "role_source": "declared",
                "role_reason": f"assigned to {c.circuit_id} by {c.provider or 'the carrier'}",
                "vendor": c.provider, "model": None, "os_version": None,
                "addresses": [ip], "vlan_id": None, "vlan_name": None, "subnet": None,
                "zone": "untrust", "tags": [], "layer": "circuit",
                "layer_source": "declared", "layer_reason": "carrier-assigned block",
                "observed_by": [{"tool": c.provenance.source_tool,
                                 "tier": c.provenance.source_tier,
                                 "raw_ref": c.provenance.raw_ref}],
                "conflicts": [], "finding_ids": [],
            })

    # The policy layer's assets. Included so the inventory is ONE list rather
    # than two screens a reviewer has to cross-reference -- "is it an asset, a
    # workstation, a router, a switch" is one question in the ask, not two.
    dev_keys = {d.device_key for d in topo.devices}
    for a in live.assets:
        if a.asset_key in dev_keys:
            continue
        vlan_id, vlan_name, subnet = _vlan_of(list(a.ip_set), topo)
        items.append({
            "key": a.asset_key, "name": a.display_name or a.asset_key,
            "kind": "subnet" if a.kind == "abstract" else "asset",
            "role": None, "role_source": "derived",
            "role_reason": f"{a.kind} asset from the policy layer",
            "vendor": None, "model": None, "os_version": None,
            "addresses": list(a.ip_set), "vlan_id": vlan_id, "vlan_name": vlan_name,
            "subnet": subnet, "zone": None, "tags": list(a.tags),
            "layer": "endpoint" if a.kind == "concrete" else "segment",
            "layer_source": "derived",
            "layer_reason": "placed from the policy layer, not from a cable",
            "observed_by": [{"tool": tool, "tier": tier_of(tool), "raw_ref": a.asset_key}
                            for tool in sorted(a.source_tools)],
            "conflicts": [],
            "finding_ids": sorted(finding_by_entity.get(a.asset_key, [])),
        })
    items.sort(key=lambda i: (i["kind"], i["key"]))
    return items


def _ip_matches(item: dict, needle, mode: str) -> bool:
    """Whether an inventory row's address space relates to `needle` under `mode`.

    Four modes because "does this IP appear here" has four different useful
    meanings, and collapsing them is how a reviewer searching for 10.30.0.0/16
    gets told there is nothing there while three hosts sit inside it.
    """
    for raw in item["addresses"]:
        net = parse_net(raw)
        if net is None:
            continue
        if mode == "exact" and net == needle:
            return True
        if mode == "contains" and needle.subnet_of(net):
            return True
        if mode == "contained_by" and net.subnet_of(needle):
            return True
        if mode == "intersects" and (net.subnet_of(needle) or needle.subnet_of(net)):
            return True
    return False


@app.get("/api/inventory")
def inventory(snapshot: str | None = None,
              kind: str | None = Query(None, max_length=32),
              source: str | None = Query(None, max_length=64),
              vlan: int | None = Query(None, ge=1, le=4094),
              zone: str | None = Query(None, max_length=32),
              ip: str | None = Query(None, max_length=64),
              ip_mode: str = Query("intersects",
                                   pattern="^(intersects|contains|contained_by|exact)$"),
              q: str | None = Query(None, max_length=200),
              limit: int = Query(_INVENTORY_LIMIT_DEFAULT, ge=1, le=_INVENTORY_LIMIT_MAX),
              offset: int = Query(0, ge=0)):
    """The estate, in one list, with the provenance of every row.

    `total` and `has_more` are on the envelope because a page silently presented
    as a whole is the same defect as a count taken from a failed fetch: the
    reader believes they have seen everything.
    """
    t = view_sid(snapshot)
    live = engine()
    topo, provenance = _topology_of(t)
    items = _inventory_items(topo, live)

    # Facets are computed over the UNFILTERED set, so a chip's count tells you
    # what selecting it would give you rather than what is already on screen.
    facets = {
        "kinds": _tally(i["kind"] for i in items),
        "sources": _tally(o["tool"] for i in items for o in i["observed_by"]),
        "vlans": _tally(str(i["vlan_id"]) for i in items if i["vlan_id"] is not None),
        "zones": _tally(i["zone"] for i in items if i["zone"]),
    }

    if kind:
        items = [i for i in items if i["kind"] == kind]
    if source:
        items = [i for i in items if any(o["tool"] == source for o in i["observed_by"])]
    if vlan is not None:
        items = [i for i in items if i["vlan_id"] == vlan]
    if zone:
        items = [i for i in items if i["zone"] == zone]
    if ip:
        needle = parse_net(ip)
        if needle is None:
            raise HTTPException(400, f"{ip!r} is not an address or a CIDR block")
        items = [i for i in items if _ip_matches(i, needle, ip_mode)]
    if q:
        needle_q = q.lower()
        items = [i for i in items
                 if needle_q in i["name"].lower()
                 or needle_q in i["key"].lower()
                 or any(needle_q in a.lower() for a in i["addresses"])
                 or any(needle_q in tag.lower() for tag in i["tags"])
                 or (i["model"] or "").lower().find(needle_q) >= 0
                 or (i["vendor"] or "").lower().find(needle_q) >= 0]

    total = len(items)
    page = items[offset:offset + limit]
    return {
        "items": page, "total": total, "has_more": offset + len(page) < total,
        "counts": _counts(topo, live), "facets": facets,
        **_analysis_block(t), **provenance,
    }


def _tally(values) -> dict[str, int]:
    out: dict[str, int] = {}
    for v in values:
        out[v] = out.get(v, 0) + 1
    return dict(sorted(out.items()))


@app.get("/api/topology")
def topology(snapshot: str | None = None, lane_cap: int = Query(40, ge=5, le=400)):
    """The layered picture, lane by lane.

    A lane with no observed node is returned with `observed: false`, its reason,
    and the console API that would fill it. It is NOT omitted, and it does not
    carry placeholder nodes. Both of those are ways of answering "what does the
    access layer look like" with something other than "nothing we can read
    enumerates access switches", which is the only true answer available.
    """
    t = view_sid(snapshot)
    live = engine()
    topo, provenance = _topology_of(t)

    finding_by_entity: dict[str, list[str]] = {}
    for f in live.findings:
        for name in f.involved:
            finding_by_entity.setdefault(name, []).append(f.id)

    vlans_by_dev: dict[str, set[int]] = {}
    for i in topo.interfaces:
        if i.vlan_id is not None:
            vlans_by_dev.setdefault(i.device_key, set()).add(i.vlan_id)
    # Interfaces travel WITH the node rather than behind a second request. The
    # explorer's node drawer is the screen that answers "what is this box", and
    # its ports are most of the answer -- a drawer that has to round-trip before
    # it can say anything is a drawer nobody opens twice. `admin_up` is carried
    # as the three-valued thing it is: null means the source did not report link
    # state, and a UI that renders that as "down" invents an outage.
    ifaces_by_dev: dict[str, list[dict]] = {}
    for i in topo.interfaces:
        ifaces_by_dev.setdefault(i.device_key, []).append({
            "name": i.name, "addresses": list(i.addresses), "vlan_id": i.vlan_id,
            "zone": i.zone, "admin_up": i.admin_up, "oper_up": i.oper_up,
            "speed_mbps": i.speed_mbps, "lag_group": i.lag_group,
            "description": i.description,
            "neighbor_device": i.neighbor_device, "neighbor_interface": i.neighbor_interface,
            "networks_behind": list(i.networks_behind),
        })
    addrs_by_dev: dict[str, set[str]] = {}
    for i in topo.interfaces:
        addrs_by_dev.setdefault(i.device_key, set()).update(i.addresses)

    unlinked = {u["device_key"]: u for u in topo.unlinked_devices}

    def node(d) -> dict:
        gap = unlinked.get(d.device_key)
        return {
            "key": d.device_key, "name": d.name, "kind": d.role, "role": d.role,
            "vendor": d.vendor, "model": d.model,
            "addresses": sorted(addrs_by_dev.get(d.device_key, ())),
            "vlan_ids": sorted(vlans_by_dev.get(d.device_key, ())),
            "interfaces": sorted(ifaces_by_dev.get(d.device_key, []),
                                 key=lambda x: x["name"]),
            "ha_group": d.ha_group, "ha_role": d.ha_role,
            "role_source": d.role_source, "role_reason": d.role_reason,
            "os_version": d.os_version, "serial": d.serial, "site": d.site,
            "mgmt_ip": d.mgmt_ip, "tags": list(d.tags),
            "conflicts": list(d.conflicts),
            "layer_reason": d.layer_reason,
            "observed_by": list(d.observed_by) or [{
                "tool": d.provenance.source_tool, "tier": d.provenance.source_tier,
                "raw_ref": d.provenance.raw_ref}],
            "finding_ids": sorted(finding_by_entity.get(d.device_key, [])),
            "unlinked_reason": gap["reason"] if gap else None,
            "would_be_filled_by": gap["would_be_filled_by"] if gap else None,
        }

    by_lane: dict[str, list] = {}
    for d in topo.devices:
        by_lane.setdefault(d.layer or "unplaced", []).append(d)

    # PRESENTATIONAL redundancy grouping, computed here and deliberately NOT on
    # the model.
    #
    # The UI needs to tint the criss-cross together. No console reports such a
    # grouping, so it has to be derived -- and an earlier version derived it onto
    # `NetLink.redundant_group`, which the resilience analyzer reads to decide
    # whether a link has a live sibling. That immediately deleted real findings:
    # every access->core uplink landed in one group, so `asw-acc-03`'s SINGLE
    # uplink looked redundant and stopped being reported.
    #
    # The deeper reason it cannot live on the model is that redundancy is
    # DIRECTIONAL. `rtr-edge-01` has two modems, so the pair of links is
    # redundancy FOR THE ROUTER; each modem has one router, so the same links are
    # a single point of failure FOR EACH MODEM. One field cannot hold both, and
    # the analyzer is right to compute it per-direction itself.
    #
    # So this is display only: a link is grouped for the endpoint DEEPER in the
    # network (the one that would be stranded), and only when that endpoint has
    # two or more links to the tier above it. `redundant_group` set by a source
    # always wins -- an observation outranks a presentation choice.
    lane_ix = {layer: i for i, layer in enumerate(LANE_ORDER)}
    lane_of = {d.device_key: d.layer for d in topo.devices}
    upstream: dict[tuple, list] = {}
    for l in topo.links:
        la, lb = lane_of.get(l.a_device), lane_of.get(l.b_device)
        if la is None or lb is None or lane_ix.get(la) == lane_ix.get(lb):
            continue
        deep, shallow = ((l.a_device, lb) if lane_ix[la] > lane_ix[lb]
                         else (l.b_device, la))
        upstream.setdefault((deep, shallow), []).append(l)
    display_groups: dict[str, str] = {}
    for (deep, shallow_lane), group in sorted(upstream.items()):
        peers = {l.b_device if l.a_device == deep else l.a_device for l in group}
        if len(peers) < 2:
            continue                      # one way up is not redundancy
        for l in group:
            display_groups[l.link_key] = f"{deep}-{shallow_lane}"

    unobserved = {u["layer"]: u for u in topo.unobserved_layers}
    lanes, shown, capped, total_nodes = [], 0, [], 0
    for layer in LANE_ORDER:
        members = sorted(by_lane.get(layer, []), key=lambda d: d.device_key)
        # Three lanes are NOT made of devices, and rendering only devices left
        # them reading "not observed" while the data sat in the payload:
        #   internet  the boundary itself -- never our equipment, drawn as the
        #             conventional OUTLINE cloud
        #   circuit   the carrier services
        #   endpoint  the policy layer's hosts and workloads
        # An unobserved lane and an unrendered one look identical on screen, so
        # this is a correctness bug, not a cosmetic one.
        if layer == "internet" and topo.circuits:
            nodes = [{
                "key": "0.0.0.0/0", "name": "Internet", "kind": "cloud", "role": None,
                "vendor": None, "model": None, "addresses": ["0.0.0.0/0"],
                "vlan_ids": [], "ha_group": None, "ha_role": None,
                "layer_reason": "the boundary this estate's circuits terminate against",
                "observed_by": sorted(
                    ({"tool": c.provenance.source_tool, "tier": c.provenance.source_tier,
                      "raw_ref": c.circuit_id} for c in topo.circuits),
                    key=lambda o: o["raw_ref"]),
                "finding_ids": [], "unlinked_reason": None, "would_be_filled_by": None,
            }]
        elif layer == "circuit" and topo.circuits:
            nodes = [{
                "key": c.circuit_id,
                "name": f"{c.circuit_id} · {c.technology.upper()}",
                "kind": "wan_circuit", "role": None,
                "vendor": c.provider, "model": c.technology,
                "addresses": list(c.public_ips), "vlan_ids": [],
                "ha_group": None, "ha_role": None,
                "layer_reason": (f"{c.bandwidth_mbps} Mbps from "
                                 f"{c.provider or 'an undeclared carrier'}"
                                 if c.bandwidth_mbps else
                                 f"from {c.provider or 'an undeclared carrier'}"),
                "observed_by": [{"tool": c.provenance.source_tool,
                                 "tier": c.provenance.source_tier,
                                 "raw_ref": c.provenance.raw_ref}],
                "finding_ids": sorted(finding_by_entity.get(c.circuit_id, [])),
                "unlinked_reason": None, "would_be_filled_by": None,
            } for c in topo.circuits]
        elif layer == "endpoint" and live.assets:
            # The hosts the POLICY layer knows. They have no cable and no lane of
            # their own otherwise, and leaving them out would draw a network with
            # nothing on it -- the findings all terminate here.
            dev_keys = {d.device_key for d in topo.devices}
            nodes = [{
                "key": a.asset_key, "name": a.display_name or a.asset_key,
                "kind": "server" if a.kind == "concrete" else "subnet", "role": None,
                "vendor": None, "model": None, "addresses": list(a.ip_set),
                "vlan_ids": sorted({vid for vid, _n, _s in
                                    [_vlan_of(list(a.ip_set), topo)] if vid is not None}),
                "ha_group": None, "ha_role": None,
                "layer_reason": "a host from the policy layer, placed by address, not by cable",
                "observed_by": [{"tool": tool, "tier": tier_of(tool), "raw_ref": a.asset_key}
                                for tool in sorted(a.source_tools)],
                "finding_ids": sorted(finding_by_entity.get(a.asset_key, [])),
                "unlinked_reason": None, "would_be_filled_by": None,
            } for a in sorted(live.assets, key=lambda a: a.asset_key)
                if a.kind == "concrete" and a.asset_key not in dev_keys]
        elif layer == "segment" and (topo.vlans or topo.subnets):
            nodes = [{
                "key": f"vlan-{v.vlan_id}", "name": v.name or f"VLAN {v.vlan_id}",
                "kind": "vlan", "role": None, "vendor": None, "model": None,
                "addresses": list(v.subnets), "vlan_ids": [v.vlan_id],
                "ha_group": None, "ha_role": None,
                "layer_reason": "a VLAN is a segment by definition",
                "observed_by": [{"tool": v.provenance.source_tool,
                                 "tier": v.provenance.source_tier,
                                 "raw_ref": v.provenance.raw_ref}],
                "finding_ids": [], "unlinked_reason": None, "would_be_filled_by": None,
            } for v in topo.vlans]
        else:
            nodes = [node(d) for d in members]
        total_nodes += len(nodes)
        if len(nodes) > lane_cap:
            capped.append(layer)
            nodes = nodes[:lane_cap]
        shown += len(nodes)
        gap = unobserved.get(layer)
        lanes.append({
            "layer": layer, "label": _LANE_LABEL[layer], "nodes": nodes,
            "observed": bool(nodes),
            "reason": (gap or {}).get("reason") if not nodes else None,
            "would_be_filled_by": ((gap or {}).get("would_be_filled_by")
                                   or LANE_SOURCE_HINT.get(layer)) if not nodes else None,
        })

    return {
        "lanes": lanes,
        "links": [{
            "id": l.link_key, "a": l.a_device, "b": l.b_device,
            "a_iface": l.a_interface, "b_iface": l.b_interface,
            "evidence": l.evidence, "evidence_detail": l.evidence_detail,
            "redundant_group": l.redundant_group or display_groups.get(l.link_key),
            "aggregated": l.aggregated,
            "member_count": l.member_count, "observed_by": list(l.observed_by),
        } for l in topo.links],
        "vlans": [{"vlan_id": v.vlan_id, "name": v.name, "subnets": list(v.subnets),
                   "gateways": list(v.gateways)} for v in topo.vlans],
        "counts": _counts(topo, live),
        "source_conflicts": list(topo.source_conflicts),
        "unlinked_devices": list(topo.unlinked_devices),
        # On the payload from the first commit rather than added when it grows:
        # a silently truncated lane reads exactly like a complete one.
        # `nodes_total` must count the same population `nodes_shown` does, or the
        # ratio is meaningless: every lane contributes, not just the device ones.
        "caps": {"nodes_shown": shown, "nodes_total": total_nodes,
                 "capped_lanes": capped},
        **_analysis_block(t), **provenance,
    }


@app.get("/api/ip")
def ip_lookup(address: str = Query(..., min_length=1, max_length=64),
              mode: str = Query("intersects",
                                pattern="^(intersects|contains|contained_by|exact)$"),
              snapshot: str | None = None):
    """What is at this address, and every policy that touches it.

    THE GROUPING IS THE ANSWER. `covering` -- rules that permit this address
    without ever naming it -- is the group a reviewer cannot get from a console's
    own search box, and it is usually where the risk is. Returning one flat list
    would bury it among the exact matches.
    """
    needle = parse_net(address)
    if needle is None:
        raise HTTPException(400, f"{address!r} is not an address or a CIDR block")
    t = view_sid(snapshot)
    live = engine()
    topo, provenance = _topology_of(t)

    def relation(raw_cidrs: list[str]) -> tuple[str | None, str]:
        for raw in raw_cidrs:
            net = parse_net(raw)
            if net is None:
                continue
            if net == needle:
                return "exact", "the rule names this address"
            if needle.subnet_of(net):
                return "covering", f"{needle} sits inside the rule's {net}"
            if net.subnet_of(needle):
                return "contained", f"the rule's {net} sits inside {needle}"
        return None, ""

    grouped: dict[str, list[dict]] = {"exact": [], "covering": [], "contained": []}
    # Rules where this address is the DESTINATION, kept apart from rules where it
    # is the source. Conflating them made every address in the estate "reachable
    # from the internet": an any->internal rule has source 0.0.0.0/0, which
    # contains every address, so 192.0.2.77 matched as a COVERING source and the
    # reachability check then saw an internet source on a matched rule and said
    # yes. Reachability is a claim about traffic ARRIVING here.
    inbound: list[dict] = []
    finding_refs: dict[str, list[str]] = {}
    for f in live.findings:
        for ref in f.raw_refs:
            finding_refs.setdefault(ref, []).append(f.id)

    for rec in live.records:
        for side, cidrs, token in (("source", rec.source_cidrs, rec.source),
                                   ("destination", rec.dest_cidrs, rec.destination)):
            rel, why = relation(cidrs)
            if rel is None:
                continue
            row = {
                "rule_ref": rec.raw_ref, "source_tool": rec.source_tool,
                "source": rec.source, "destination": rec.destination,
                "service": rec.service, "action": rec.action,
                "relation": rel,
                "matched_via": f"containment on the {side} ({why})",
                "matched_side": side,
                "finding_ids": sorted(finding_refs.get(rec.raw_ref, [])),
            }
            grouped[rel].append(row)
            if side == "destination" and rec.action == "allow":
                inbound.append(row)
            break

    matched_assets = [a for a in live.assets
                      if any((n := parse_net(x)) is not None
                             and (n.subnet_of(needle) or needle.subnet_of(n))
                             for x in a.ip_set)]
    matched_ifaces = [i for i in topo.interfaces
                      if any((n := parse_net(x)) is not None
                             and (n.subnet_of(needle) or needle.subnet_of(n))
                             for x in i.addresses)]
    dev_keys = {i.device_key for i in matched_ifaces}
    vlan_id, vlan_name, subnet = _vlan_of([str(needle)], topo)

    return {
        "address": str(needle), "mode": mode,
        "matches": {k: sorted(v, key=lambda r: (r["source_tool"], r["rule_ref"]))
                    for k, v in grouped.items()},
        "assets": [{"asset_key": a.asset_key, "kind": a.kind, "tags": list(a.tags),
                    "source_tools": list(a.source_tools)} for a in matched_assets],
        "devices": [{"key": d.device_key, "name": d.name, "kind": d.role, "role": d.role,
                     "vendor": d.vendor, "model": d.model,
                     "addresses": [], "vlan_ids": [], "ha_group": d.ha_group,
                     "ha_role": d.ha_role, "layer_reason": d.layer_reason,
                     "observed_by": list(d.observed_by), "finding_ids": [],
                     "unlinked_reason": None, "would_be_filled_by": None}
                    for d in topo.devices if d.device_key in dev_keys],
        "interfaces": [{"interface_key": i.interface_key, "device_key": i.device_key,
                        "name": i.name, "addresses": list(i.addresses),
                        "vlan_id": i.vlan_id} for i in matched_ifaces],
        "vlan": {"vlan_id": vlan_id, "name": vlan_name} if vlan_id is not None else None,
        "subnet": subnet,
        "finding_ids": sorted({fid for group in grouped.values()
                               for row in group for fid in row["finding_ids"]}),
        "effective": {
            # `null`, not False, when nothing matched: "no rule mentions this
            # address" is not the same claim as "this address is unreachable",
            # and only the first is supported by what we read.
            # Only rules where this address is the DESTINATION, and only ALLOW
            # rules, and only when the source denotes public space -- tested with
            # the same `is_public` classifier the severity engine and the zone
            # layer use, rather than a list of spellings, so `ANY-EXTERNAL`,
            # `0.0.0.0/1` and `any` all answer the same way here as they do there.
            "reachable_from_internet": (
                any(is_public(r["source"]) or any(is_public(c) for c in _cidrs_of(live, r))
                    for r in inbound)
                if inbound else None),
            "caveat": ("The engine models the union of ALLOW edges and does not implement "
                       "deny precedence (ENGINE.md §10.1), so “not reachable” here "
                       "means “no allow path was found”, not “provably "
                       "blocked”. A deny rule that would stop this traffic is reported "
                       "separately as a shadowed rule rather than subtracted from this "
                       "answer."),
        },
        **provenance,
    }


@app.get("/api/resilience")
def resilience(snapshot: str | None = None):
    """Single points of failure, and what each one takes down with it.

    `analysed: false` with a reason is returned when there was nothing to analyse.
    An empty `findings` list must never be readable as a clean bill of health,
    which is exactly how "no topology onboarded" would otherwise render.
    """
    t = view_sid(snapshot)
    topo, provenance = _topology_of(t)
    if not topo.devices:
        return {
            "analysed": False,
            "reason": ("no infrastructure was ingested for this snapshot, so there is no "
                       "topology to analyse. This is not a finding that the network is "
                       "resilient -- nothing was examined. Onboard a management console "
                       "(Catalyst Center, FortiManager, Meraki) or a carrier portal."),
            "caveats": [],
            "findings": [], "blast_radius": [], "blast_basis": "",
            "adjacency_count": 0, "device_count": 0,
            "excluded_adjacencies": [], "suppressed": [],
            **provenance,
        }
    # Named `assessment`, not `report`: `report` is also the name of the
    # /api/report route function at module scope, and the authz check resolves
    # every name a handler references against main's namespace. A local called
    # `report` therefore made this read look like it reached
    # `persist_ranked_actions` -- a GET that writes, which is exactly what that
    # check exists to catch. The check is right to be conservative; the variable
    # was wrong to shadow.
    assessment = assess_resilience(topo)
    return {
        # The analyzer's own word, not a re-derivation. It distinguishes "we
        # examined this network and it has no single points of failure" from "we
        # could not examine it", and the second one dressed as the first is the
        # most damaging sentence this product could produce.
        "analysed": assessment.analysable,
        "reason": "; ".join(assessment.not_analysable_reasons) or None,
        # What was examined but deliberately NOT flagged, and what the analysis
        # could not see. Carried to the client because an empty findings list is
        # only readable alongside them.
        "caveats": list(assessment.caveats),
        "findings": [{
            "id": f.id, "kind": f.kind, "title": f.title, "detail": f.detail,
            "severity": f.severity, "severity_band": f.severity_band,
            "severity_vector": dict(f.vector),
            # `failing` is the element whose loss causes the damage; `devices` is
            # everything the finding turns on. The UI highlights the first and
            # dims to the second, so both travel.
            "involved": sorted({*f.devices, *f.failing, *f.circuits, *f.links}),
            "failing": list(f.failing),
            "devices": list(f.devices),
            "circuits": list(f.circuits),
            "source_tools": list(f.source_tools),
            "raw_refs": list(f.raw_refs),
        } for f in assessment.findings],
        "blast_radius": [{
            "device_key": b.device_key, "paths_lost": b.paths_lost,
            "paths_before": b.paths_before, "fraction": b.fraction,
            "circuits_stranded": list(b.circuits_stranded),
            "devices_isolated": list(b.devices_isolated),
            "devices_degraded": b.devices_degraded,
            "components_after": b.components_after,
        } for b in assessment.blast_radius],
        "blast_basis": assessment.blast_basis,
        "adjacency_count": assessment.adjacency_count,
        "device_count": assessment.device_count,
        "excluded_adjacencies": list(assessment.excluded_adjacencies),
        "suppressed": list(assessment.suppressed),
        **provenance,
    }
