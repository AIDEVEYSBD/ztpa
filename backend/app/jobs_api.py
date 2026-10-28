"""HTTP surface of the job queue: status polling for the person who started a
job, and queue health for operators.

Long operations answer `202 {job_id}` and the client polls
`GET /api/jobs/{job_id}`. A job is visible to the identity that created it and
to admins; to anyone else it does not exist (404, not 403, so ids cannot be
probed for).
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException

from src import request_ctx
from src.db import get_conn
from src.jobs import queue

router = APIRouter()


def actor_key() -> str | None:
    """How a job records who started it: the stable SSO subject when present,
    else the email. Same value on enqueue and on read."""
    a = request_ctx.current()
    return a.sub or a.email


def _require_admin() -> None:
    if request_ctx.role() != "admin":
        raise HTTPException(403, "admin only")


def _visible(job: queue.Job | None) -> queue.Job:
    if job is None:
        raise HTTPException(404, "no such job")
    if request_ctx.role() != "admin" and (job.created_by is None or job.created_by != actor_key()):
        raise HTTPException(404, "no such job")
    return job


@router.get("/api/jobs/{job_id}")
def job_status(job_id: str):
    with get_conn() as conn:
        return _visible(queue.get(conn, job_id)).public()


@router.post("/api/jobs/{job_id}/cancel")
def job_cancel(job_id: str):
    with get_conn() as conn:
        _visible(queue.get(conn, job_id))
        if not queue.cancel(conn, job_id):
            raise HTTPException(409, "only a job that has not started can be cancelled")
        return queue.get(conn, job_id).public()


@router.get("/api/admin/jobs/stats")
def job_stats(_: None = Depends(_require_admin)):
    with get_conn() as conn:
        return {"kinds": queue.stats(conn)}


@router.post("/api/admin/jobs/ping", status_code=202)
def job_ping(_: None = Depends(_require_admin)):
    """Enqueue a `system.ping`: the post-deploy smoke test polls it to prove a
    worker is consuming the queue end to end."""
    with get_conn() as conn:
        job, _created = queue.enqueue(conn, "system.ping", {"echo": request_ctx.request_id()},
                                      priority=10, max_attempts=1, created_by=actor_key())
        return job.public()
