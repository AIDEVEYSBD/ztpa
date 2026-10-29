"""Multipart export uploads, for exports larger than one request may carry.

    POST /api/exports/uploads                     {source, filename?, exported_at?} -> {upload_id, part_size}
    PUT  /api/exports/uploads/{id}/parts/{n}      raw bytes, n = 1.., each <= PART_MAX
    POST /api/exports/uploads/{id}/complete       {parts} -> 202 {upload}
    GET  /api/exports/uploads/{id}                status; export_id once done

Parts may arrive in any order and be retried; `complete` checks every part
1..parts arrived, assembles them in storage (Azure block commit, GCS compose,
local concatenation) and enqueues `export.finalize`, which stream-hashes the
object, de-duplicates against existing exports by sha256, and hands a new one
to the normal `export.ingest`. The same validation (checksum, age, shape)
applies as for a single-request upload.
"""

from __future__ import annotations

import os
from datetime import datetime
from typing import Optional

from fastapi import APIRouter, HTTPException, Request
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from src import request_ctx, storage
from src.db import audit, get_conn
from src.frr import intake
from src.jobs import queue

from app.exports_api import _parse_when
from app.packages_api import _jsonable

router = APIRouter()
PART_SIZE = 8 * 1024 * 1024
PART_MAX = 16 * 1024 * 1024
MAX_UPLOAD_BYTES = int(os.environ.get("NPR_MAX_UPLOAD_BYTES", str(1024 * 1024 * 1024)))


def _actor() -> Optional[str]:
    a = request_ctx.current()
    return a.sub or a.email


def _require_uploader() -> None:
    if request_ctx.role() not in ("admin", "analyst"):
        raise HTTPException(403, "uploading exports requires the admin or analyst role")


def _session(cur, upload_id: str, *, lock: bool = False) -> dict:
    try:
        cur.execute("SELECT * FROM ztpa.export_uploads WHERE upload_id = %s" + (" FOR UPDATE" if lock else ""),
                    [upload_id])
    except Exception:  # noqa: BLE001 — a malformed uuid is "no such upload"
        cur.connection.rollback()
        raise HTTPException(404, "no such upload")
    row = cur.fetchone()
    if row is None or (row["uploaded_by"] != _actor() and request_ctx.role() != "admin"):
        raise HTTPException(404, "no such upload")
    return row


class StartBody(BaseModel):
    source: str = Field(..., pattern="^[a-z][a-z0-9_]{0,31}$")
    filename: Optional[str] = Field(None, max_length=200, pattern=r"^[\w .()\-]{1,200}$")
    exported_at: Optional[str] = None


@router.post("/api/exports/uploads", status_code=201)
def start_upload(body: StartBody):
    _require_uploader()
    if body.source not in intake.PARSERS:
        raise HTTPException(422, f"unsupported source {body.source!r}; supported: {sorted(intake.PARSERS)}")
    declared = _parse_when(body.exported_at)
    with get_conn() as conn, conn.cursor() as cur:
        cur.execute("SELECT gen_random_uuid() AS id")
        uid = cur.fetchone()["id"]
        cur.execute("""INSERT INTO ztpa.export_uploads (upload_id, source_type, filename, declared_exported_at,
                                                         uploaded_by, storage_key)
                       VALUES (%s, %s, %s, %s, %s, %s) RETURNING *""",
                    [uid, body.source, body.filename, declared, _actor(), f"uploads/{uid}/data"])
        row = cur.fetchone()
    return {**_jsonable(row), "part_size": PART_SIZE, "part_max": PART_MAX}


@router.put("/api/exports/uploads/{upload_id}/parts/{n}")
async def put_part(upload_id: str, n: int, request: Request):
    _require_uploader()
    if not 1 <= n <= storage.MAX_PARTS:
        raise HTTPException(422, f"part number must be 1..{storage.MAX_PARTS}")
    data = bytearray()
    async for chunk in request.stream():
        data += chunk
        if len(data) > PART_MAX:
            raise HTTPException(413, f"a part may be at most {PART_MAX} bytes")
    if not data:
        raise HTTPException(422, "empty part")

    def _store():
        with get_conn() as conn, conn.cursor() as cur:
            s = _session(cur, upload_id, lock=True)
            if s["status"] != "open":
                raise HTTPException(409, f"upload is {s['status']}")
            cur.execute("SELECT coalesce(sum(bytes), 0) AS b FROM ztpa.export_upload_parts "
                        "WHERE upload_id = %s AND part <> %s", [upload_id, n])
            if cur.fetchone()["b"] + len(data) > MAX_UPLOAD_BYTES:
                raise HTTPException(413, f"upload would exceed {MAX_UPLOAD_BYTES} bytes")
            storage.store().put_part(s["storage_key"], n, bytes(data))
            cur.execute("""INSERT INTO ztpa.export_upload_parts (upload_id, part, bytes) VALUES (%s, %s, %s)
                           ON CONFLICT (upload_id, part) DO UPDATE SET bytes = EXCLUDED.bytes,
                                                                       received_at = now()""",
                        [upload_id, n, len(data)])
    await run_in_threadpool(_store)
    return {"part": n, "bytes": len(data)}


class CompleteBody(BaseModel):
    parts: int = Field(..., ge=1, le=2000)


@router.post("/api/exports/uploads/{upload_id}/complete", status_code=202)
def complete_upload(upload_id: str, body: CompleteBody):
    _require_uploader()
    with get_conn() as conn, conn.cursor() as cur:
        s = _session(cur, upload_id, lock=True)
        if s["status"] != "open":
            raise HTTPException(409, f"upload is {s['status']}")
        cur.execute("SELECT part, bytes FROM ztpa.export_upload_parts WHERE upload_id = %s ORDER BY part",
                    [upload_id])
        got = {r["part"]: r["bytes"] for r in cur.fetchall()}
        missing = [p for p in range(1, body.parts + 1) if p not in got]
        extra = [p for p in got if p > body.parts]
        if missing or extra:
            raise HTTPException(409, f"parts do not match: missing {missing[:20]}, unexpected {extra[:20]}")
        size = storage.store().complete_parts(s["storage_key"], body.parts, "application/octet-stream")
        if size != sum(got.values()):
            raise HTTPException(500, f"assembled {size} bytes, expected {sum(got.values())}")
        cur.execute("""UPDATE ztpa.export_uploads SET status = 'completing', parts = %s, bytes = %s
                        WHERE upload_id = %s RETURNING *""", [body.parts, size, upload_id])
        row = cur.fetchone()
        queue.enqueue(conn, "export.finalize", {"upload_id": upload_id},
                      idempotency_key=f"upload:{upload_id}", priority=40, created_by=_actor())
        audit(cur, "export_upload_completed", subject=upload_id, detail={"parts": body.parts, "bytes": size})
    return _jsonable(row)


@router.get("/api/exports/uploads/{upload_id}")
def upload_status(upload_id: str):
    with get_conn() as conn, conn.cursor() as cur:
        return _jsonable(_session(cur, upload_id))
