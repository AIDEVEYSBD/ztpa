"""Context datasets (CMDB/IPAM, flows).

    POST /api/context/{kind}?filename=   kind = cmdb | flows; body = CSV (admin, analyst) -> 202
    GET  /api/context                    datasets, newest first; the active one per kind flagged
    GET  /api/context/owners?net=        CMDB rows overlapping a network (any role)
"""

from __future__ import annotations

import hashlib
import os
import tempfile
from typing import Literal

from fastapi import APIRouter, HTTPException, Query, Request
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import JSONResponse

from src import request_ctx, storage
from src.db import audit, get_conn
from src.frr import context
from src.jobs import queue

from app.packages_api import _jsonable

router = APIRouter()
MAX_CONTEXT_BYTES = int(os.environ.get("NPR_MAX_CONTEXT_BYTES", str(500 * 1024 * 1024)))


def _actor() -> str | None:
    a = request_ctx.current()
    return a.sub or a.email


def _record(path: str, kind: str, digest: str, size: int, filename: str | None):
    with get_conn() as conn, conn.cursor() as cur:
        cur.execute("SELECT * FROM ztpa.context_datasets WHERE kind = %s AND sha256 = %s", [kind, digest])
        existing = cur.fetchone()
        if existing:
            return existing, False
        key = context.original_key(kind, digest)
        with open(path, "rb") as fh:
            storage.store().put_file(key, fh, "text/csv")
        cur.execute("""INSERT INTO ztpa.context_datasets (kind, filename, sha256, size_bytes, storage_key, uploaded_by)
                       VALUES (%s, %s, %s, %s, %s, %s) RETURNING *""",
                    [kind, filename, digest, size, key, _actor()])
        ds = cur.fetchone()
        job, _ = queue.enqueue(conn, "context.ingest", {"dataset_id": str(ds["dataset_id"])},
                               idempotency_key=f"context:{kind}:{digest}", priority=70, created_by=_actor())
        cur.execute("UPDATE ztpa.context_datasets SET job_id = %s WHERE dataset_id = %s RETURNING *",
                    [job.job_id, ds["dataset_id"]])
        ds = cur.fetchone()
        audit(cur, "context_dataset_uploaded", subject=str(ds["dataset_id"]), detail={"kind": kind, "bytes": size})
        return ds, True


@router.post("/api/context/{kind}")
async def upload_context(request: Request, kind: Literal["cmdb", "flows"],
                         filename: str | None = Query(None, max_length=200)):
    if request_ctx.role() not in ("admin", "analyst"):
        raise HTTPException(403, "uploading context requires the admin or analyst role")
    h, size = hashlib.sha256(), 0
    fd, path = tempfile.mkstemp(prefix="npr-context-")
    try:
        with os.fdopen(fd, "wb") as out:
            async for chunk in request.stream():
                size += len(chunk)
                if size > MAX_CONTEXT_BYTES:
                    raise HTTPException(413, f"file exceeds {MAX_CONTEXT_BYTES} bytes")
                h.update(chunk)
                out.write(chunk)
        if size == 0:
            raise HTTPException(422, "the request body is empty")
        ds, created = await run_in_threadpool(_record, path, kind, h.hexdigest(), size, filename)
    finally:
        try:
            os.unlink(path)
        except FileNotFoundError:
            pass
    return JSONResponse({"dataset": _jsonable(ds), "duplicate": not created}, status_code=202 if created else 200)


@router.get("/api/context")
def list_context():
    with get_conn() as conn, conn.cursor() as cur:
        cur.execute("""SELECT dataset_id, kind, filename, size_bytes, status, rejection_reason, summary,
                              uploaded_by, uploaded_at FROM ztpa.context_datasets ORDER BY uploaded_at DESC LIMIT 100""")
        rows = cur.fetchall()
        active = {k: (context.active(cur, k) or {}).get("dataset_id") for k in ("cmdb", "flows")}
    for r in rows:
        r["active"] = r["dataset_id"] == active.get(r["kind"])
    return {"items": _jsonable(rows)}


@router.get("/api/context/owners")
def owners(net: str = Query(..., min_length=3, max_length=64)):
    import ipaddress
    try:
        ipaddress.ip_network(net, strict=False)
    except ValueError:
        raise HTTPException(422, "net must be an address or CIDR")
    with get_conn() as conn, conn.cursor() as cur:
        return {"items": context.owners_for(cur, [net])}
