"""FRR agent runs and the knowledge base.

    GET  /api/frr/agents                         the agents, model policy, prompt versions, evaluation
    POST /api/exports/{export_id}/review-runs    start an orchestrated run (admin, analyst) -> 202
    GET  /api/frr/runs/{run_id}                  run status and every agent's step
    POST /api/knowledge?kind=&title=             add a standard / exception / runbook (admin; text body)
    GET  /api/knowledge                          documents
    GET  /api/knowledge/search?q=                retrieval, as the assessor sees it
    DELETE /api/knowledge/{doc_id}               remove a document (admin)
"""

from __future__ import annotations

from typing import Literal

from fastapi import APIRouter, HTTPException, Query, Request

from src import request_ctx
from src.db import audit, get_conn
from src.frr import agents, knowledge, prompt_gate
from src.jobs import queue

from app.packages_api import _jsonable

router = APIRouter()


def _actor() -> str | None:
    a = request_ctx.current()
    return a.sub or a.email


@router.get("/api/frr/me")
def my_duties():
    """The caller's FRR duties, so the UI offers only the actions they can take.
    Display only: every action is still checked server-side."""
    from src.frr import workflow
    with get_conn() as conn, conn.cursor() as cur:
        p = workflow.principals()
        cur.execute("SELECT duty, scope FROM ztpa.frr_approvers WHERE principal = ANY(%s) "
                    "ORDER BY duty, scope", [p or [""]])
        duties = cur.fetchall()
    a = request_ctx.current()
    return {"email": a.email, "role": a.role, "duties": duties,
            "can_upload": a.role in ("admin", "analyst"), "is_admin": a.role == "admin"}


@router.get("/api/frr/agents")
def list_agents():
    out = []
    evaluated = prompt_gate.status()
    for a in agents.AGENTS:
        out.append({"key": a.key, "role": a.role, "model": a.model,
                    "prompt": agents.prompt(a.prompt).version if a.prompt else None,
                    # Whether the running configuration passed a recorded evaluation (05.5).
                    "evaluation": evaluated.get(a.key)})
    return {"agents": out, "narrate_top": agents.NARRATE_TOP}


@router.post("/api/exports/{export_id}/review-runs", status_code=202)
def start_run(export_id: str):
    if request_ctx.role() not in ("admin", "analyst"):
        raise HTTPException(403, "starting a review run requires the admin or analyst role")
    with get_conn() as conn, conn.cursor() as cur:
        try:
            cur.execute("SELECT status FROM ztpa.exports WHERE export_id = %s", [export_id])
        except Exception:  # noqa: BLE001 — a malformed uuid is "no such export"
            conn.rollback()
            raise HTTPException(404, "no such export")
        row = cur.fetchone()
        if row is None:
            raise HTTPException(404, "no such export")
        if row["status"] != "accepted":
            raise HTTPException(409, f"export is {row['status']}")
        cur.execute("INSERT INTO ztpa.frr_runs (export_id, created_by) VALUES (%s, %s) RETURNING *",
                    [export_id, _actor()])
        run = cur.fetchone()
        job, _ = queue.enqueue(conn, "frr.review_run", {"run_id": str(run["run_id"])},
                               idempotency_key=f"frr-run:{run['run_id']}", priority=60,
                               created_by=_actor())
        cur.execute("UPDATE ztpa.frr_runs SET job_id = %s WHERE run_id = %s RETURNING *",
                    [job.job_id, run["run_id"]])
        run = cur.fetchone()
        audit(cur, "frr_run_started", subject=str(run["run_id"]), detail={"export_id": export_id})
    return _jsonable(run)


@router.get("/api/frr/runs/{run_id}")
def get_run(run_id: str):
    with get_conn() as conn, conn.cursor() as cur:
        try:
            cur.execute("SELECT * FROM ztpa.frr_runs WHERE run_id = %s", [run_id])
        except Exception:  # noqa: BLE001
            conn.rollback()
            raise HTTPException(404, "no such run")
        row = cur.fetchone()
    if row is None:
        raise HTTPException(404, "no such run")
    return _jsonable(row)


@router.post("/api/knowledge", status_code=201)
async def add_document(request: Request, kind: Literal["standard", "exception", "runbook"],
                       title: str = Query(..., min_length=1, max_length=300)):
    if request_ctx.role() != "admin":
        raise HTTPException(403, "admin only")
    body = await request.body()
    if len(body) > knowledge.MAX_DOC_BYTES:
        raise HTTPException(413, f"document exceeds {knowledge.MAX_DOC_BYTES} bytes")
    try:
        text = body.decode("utf-8")
    except UnicodeDecodeError:
        raise HTTPException(422, "document must be UTF-8 text or Markdown")
    from fastapi.concurrency import run_in_threadpool

    def _add():
        with get_conn() as conn, conn.cursor() as cur:
            return knowledge.add(cur, kind, title, text, _actor())
    try:
        doc = await run_in_threadpool(_add)
    except ValueError as e:
        raise HTTPException(422, str(e))
    return _jsonable(doc)


@router.get("/api/knowledge")
def list_documents():
    with get_conn() as conn, conn.cursor() as cur:
        cur.execute("""SELECT d.*, (SELECT count(*) FROM ztpa.knowledge_chunks c WHERE c.doc_id = d.doc_id)
                              AS chunks FROM ztpa.knowledge_docs d ORDER BY uploaded_at DESC""")
        return {"items": _jsonable(cur.fetchall())}


@router.get("/api/knowledge/search")
def search_documents(q: str = Query(..., min_length=2, max_length=500), k: int = Query(5, ge=1, le=20)):
    with get_conn() as conn, conn.cursor() as cur:
        return {"items": _jsonable(knowledge.search(cur, q, k=k))}


@router.delete("/api/knowledge/{doc_id}")
def delete_document(doc_id: str):
    if request_ctx.role() != "admin":
        raise HTTPException(403, "admin only")
    with get_conn() as conn, conn.cursor() as cur:
        try:
            cur.execute("DELETE FROM ztpa.knowledge_docs WHERE doc_id = %s", [doc_id])
        except Exception:  # noqa: BLE001
            conn.rollback()
            raise HTTPException(404, "no such document")
        if cur.rowcount != 1:
            raise HTTPException(404, "no such document")
        audit(cur, "knowledge_doc_deleted", subject=doc_id)
    return {"deleted": True}
