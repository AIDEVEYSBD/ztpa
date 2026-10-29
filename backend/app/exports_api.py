"""Policy export upload and the review it produces.

    POST /api/exports?source=checkpoint&filename=..&exported_at=<ISO-8601>
         body: the export bytes (application/json or application/octet-stream)
         -> 202 {export, job} (new) | 200 {export} (same bytes already uploaded)
    GET  /api/exports                  newest first, cursor-paginated
    GET  /api/exports/{id}             status, summary, rejection reason
    GET  /api/exports/{id}/review      the rule-risk register (filter + paginate)

The body is STREAMED to a temp file under a size cap and hashed on the way, so
upload size does not become API memory, and the global 1 MB body cap does not
apply here (app/limits.py exempts /api/exports). Who may upload: admin and
analyst. Who may read: any signed-in role.
"""

from __future__ import annotations

import functools
import hashlib
import json
import os
import re
import tempfile
from datetime import datetime

from fastapi import APIRouter, HTTPException, Query, Request
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import JSONResponse

from src import request_ctx, storage
from src.db import get_conn
from src.frr import intake
from src.jobs import queue

router = APIRouter()

MAX_EXPORT_BYTES = int(os.environ.get("NPR_MAX_EXPORT_BYTES", str(100 * 1024 * 1024)))
_UPLOAD_ROLES = ("admin", "analyst")
_FILENAME_RE = re.compile(r"^[\w .()\-]{1,200}$")
_COLS = ("export_id, sha256, source_type, filename, size_bytes, declared_exported_at, exported_at, "
         "uploaded_by, uploaded_at, status, rejection_reason, summary, job_id, updated_at")


def _actor() -> str | None:
    a = request_ctx.current()
    return a.sub or a.email


def _public(row: dict) -> dict:
    out = {}
    for k, v in row.items():
        out[k] = v.isoformat() if isinstance(v, datetime) else (str(v) if k in ("export_id", "job_id") and v else v)
    return out


def _parse_when(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        raise HTTPException(422, "exported_at must be ISO-8601, e.g. 2026-10-27T12:00:00Z")
    if dt.tzinfo is None:
        raise HTTPException(422, "exported_at must carry a timezone (e.g. Z or +01:00)")
    return dt


def _store_and_record(path: str, digest: str, size: int, source: str, filename: str | None,
                      declared: datetime | None) -> tuple[dict, dict | None, bool]:
    with get_conn() as conn, conn.cursor() as cur:
        cur.execute(f"SELECT {_COLS} FROM ztpa.exports WHERE sha256 = %s", [digest])
        existing = cur.fetchone()
        if existing:
            return existing, None, False
        key = intake.original_key(digest)
        with open(path, "rb") as fh:
            storage.store().put_file(key, fh, "application/octet-stream")
        cur.execute(
            f"""INSERT INTO ztpa.exports (sha256, source_type, filename, size_bytes, storage_key,
                                          declared_exported_at, uploaded_by)
                VALUES (%s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT (sha256) DO NOTHING RETURNING {_COLS}""",
            [digest, source, filename, size, key, declared, _actor()])
        row = cur.fetchone()
        if row is None:                               # lost a race with an identical upload
            cur.execute(f"SELECT {_COLS} FROM ztpa.exports WHERE sha256 = %s", [digest])
            return cur.fetchone(), None, False
        job, _ = queue.enqueue(conn, "export.ingest", {"export_id": str(row["export_id"])},
                               idempotency_key=f"export:{digest}", priority=50,
                               created_by=_actor())
        cur.execute("UPDATE ztpa.exports SET job_id = %s WHERE export_id = %s RETURNING " + _COLS,
                    [job.job_id, row["export_id"]])
        return cur.fetchone(), job.public(), True


@router.post("/api/exports")
async def upload_export(request: Request,
                        source: str = Query(..., pattern="^[a-z][a-z0-9_]{0,31}$"),
                        filename: str | None = Query(None, max_length=200),
                        exported_at: str | None = Query(None)):
    if request_ctx.role() not in _UPLOAD_ROLES:
        raise HTTPException(403, "uploading exports requires the admin or analyst role")
    if source not in intake.PARSERS:
        raise HTTPException(422, f"unsupported source {source!r}; supported: {sorted(intake.PARSERS)}")
    if filename is not None and not _FILENAME_RE.match(filename):
        raise HTTPException(422, "filename may contain letters, digits, space and . _ - ( ) only")
    declared = _parse_when(exported_at)
    declared_len = request.headers.get("content-length")
    if declared_len and declared_len.isdigit() and int(declared_len) > MAX_EXPORT_BYTES:
        raise HTTPException(413, f"export exceeds {MAX_EXPORT_BYTES} bytes")

    h, size = hashlib.sha256(), 0
    fd, path = tempfile.mkstemp(prefix="npr-export-")
    try:
        with os.fdopen(fd, "wb") as out:
            async for chunk in request.stream():
                size += len(chunk)
                if size > MAX_EXPORT_BYTES:
                    raise HTTPException(413, f"export exceeds {MAX_EXPORT_BYTES} bytes")
                h.update(chunk)
                out.write(chunk)
        if size == 0:
            raise HTTPException(422, "the request body is empty")
        row, job, created = await run_in_threadpool(
            _store_and_record, path, h.hexdigest(), size, source, filename, declared)
    finally:
        try:
            os.unlink(path)
        except FileNotFoundError:
            pass
    body = {"export": _public(row), "job": job, "duplicate": not created}
    return JSONResponse(body, status_code=202 if created else 200)


@router.get("/api/exports")
def list_exports(limit: int = Query(50, ge=1, le=200), before: str | None = Query(None)):
    with get_conn() as conn, conn.cursor() as cur:
        if before:
            cur.execute(f"SELECT {_COLS} FROM ztpa.exports WHERE uploaded_at < %s "
                        "ORDER BY uploaded_at DESC LIMIT %s", [_parse_when(before), limit])
        else:
            cur.execute(f"SELECT {_COLS} FROM ztpa.exports ORDER BY uploaded_at DESC LIMIT %s", [limit])
        rows = [_public(r) for r in cur.fetchall()]
    return {"items": rows, "next_before": rows[-1]["uploaded_at"] if len(rows) == limit else None}


@functools.lru_cache(maxsize=16)
def _review_doc(review_key: str) -> dict:
    """The stored review, parsed once per process. Safe to cache: review keys are
    content-addressed (exports/<sha256>/review.json) and never rewritten, so a
    cached copy cannot go stale. Bounded so a busy replica holds at most 16."""
    return json.loads(storage.store().get_bytes(review_key))


def _get(export_id: str) -> dict:
    with get_conn() as conn, conn.cursor() as cur:
        try:
            cur.execute(f"SELECT {_COLS}, review_key, review_head FROM ztpa.exports WHERE export_id = %s",
                        [export_id])
        except Exception:  # noqa: BLE001 — a malformed uuid is "no such export"
            conn.rollback()
            raise HTTPException(404, "no such export")
        row = cur.fetchone()
    if row is None:
        raise HTTPException(404, "no such export")
    return row


@router.get("/api/exports/{export_id}")
def get_export(export_id: str):
    row = _get(export_id)
    row.pop("review_key", None)
    row.pop("review_head", None)
    return _public(row)


def _ep_summary(ep: list) -> list:
    """Per-gateway counts only. The rule lists are large (468 KiB of a 522 KiB
    page at 70,000 rules) and were re-sent with every register page; they are
    fetched per gateway from /effective-policy when a row is opened."""
    return [{"layer": g["layer"], "gateway": g["gateway"], "rules_installed": g["rules_installed"],
             **{f"{k}_count": len(g.get(k) or [])
                for k in ("effective_allow", "shadowed", "deny", "inactive", "partly_covered")}}
            for g in ep]


def _review_from_rows(export_id: str, head: dict, band, check, flagged_only, limit, offset,
                      partly_covered=False) -> dict:
    """One indexed count and one indexed page, whatever the rulebase size."""
    where, params = ["export_id = %s"], [export_id]
    if partly_covered:
        where.append("partly_covered")              # mostly unflagged: not combined with flagged_only
    elif flagged_only or band:
        where.append("flagged")
    if band:
        where.append("band = %s")
        params.append(band)
    if check:
        where.append("checks @> ARRAY[%s]::text[]")
        params.append(check)
    clause = " AND ".join(where)
    with get_conn() as conn, conn.cursor() as cur:
        cur.execute(f"SELECT count(*) AS n FROM ztpa.review_entries WHERE {clause}", params)
        total = cur.fetchone()["n"]
        cur.execute(f"SELECT entry FROM ztpa.review_entries WHERE {clause} ORDER BY ord LIMIT %s OFFSET %s",
                    params + [limit, offset])
        items = [r["entry"] for r in cur.fetchall()]
    return {"export_id": export_id, "stats": head["stats"], "limitations": head["limitations"],
            "reference_time": head["reference_time"], "total": total,
            "effective_policy": _ep_summary(head.get("effective_policy", [])),
            "nat_findings": head.get("nat_findings", []),
            "items": items, "limit": limit, "offset": offset}


@router.get("/api/exports/{export_id}/review")
def get_review(export_id: str, band: str | None = Query(None, pattern="^(critical|high|medium|low)$"),
               check: str | None = Query(None, max_length=40),
               flagged_only: bool = Query(True),
               partly_covered: bool = Query(False, description="rules some of whose grants are matched above"),
               limit: int = Query(100, ge=1, le=1000), offset: int = Query(0, ge=0)):
    row = _get(export_id)
    if row["status"] != "accepted":
        raise HTTPException(409, f"export is {row['status']}"
                                 + (f": {row['rejection_reason']}" if row.get("rejection_reason") else ""))
    if row.get("review_head"):
        return _review_from_rows(export_id, row["review_head"], band, check, flagged_only, limit, offset,
                                 partly_covered)
    # Exports reviewed before migration 0018: the stored document.
    doc = _review_doc(row["review_key"])
    entries = doc["register"]
    if partly_covered:
        entries = [e for e in entries if e.get("coverage")]
    elif flagged_only:
        entries = [e for e in entries if e["checks"]]
    if band:
        entries = [e for e in entries if e["checks"] and e["band"] == band]
    if check:
        entries = [e for e in entries if any(c["check"] == check for c in e["checks"])]
    return {"export_id": export_id, "stats": doc["stats"], "limitations": doc["limitations"],
            "reference_time": doc["reference_time"], "total": len(entries),
            "effective_policy": _ep_summary(doc.get("effective_policy", [])),
            "nat_findings": doc.get("nat_findings", []),
            "items": entries[offset:offset + limit], "limit": limit, "offset": offset}


@router.get("/api/exports/{export_id}/effective-policy")
def get_effective_policy(export_id: str, layer: str = Query(..., max_length=200),
                         gateway: str = Query(..., max_length=200)):
    """One gateway's effective policy: the rule numbers in each class."""
    row = _get(export_id)
    if row["status"] != "accepted":
        raise HTTPException(409, f"export is {row['status']}")
    ep = (row.get("review_head") or _review_doc(row["review_key"])).get("effective_policy", [])
    g = next((x for x in ep if x["layer"] == layer and x["gateway"] == gateway), None)
    if g is None:
        raise HTTPException(404, "no such layer / gateway in this review")
    return g
