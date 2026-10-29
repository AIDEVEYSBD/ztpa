"""FRR change packages and the approver matrix.

    POST /api/exports/{export_id}/change-package[?supersede=true]   draft (admin, analyst)
    GET  /api/change-packages/{id}                                   package + items (any role)
    PUT  /api/change-packages/{id}/items/{item_id}                   owner decision (network_owner)
    POST /api/change-packages/{id}/validate                          owner validates (network_owner)
    POST /api/change-packages/{id}/decision                          approve/reject (security_approver,
                                                                     not the validator)
    GET  /api/change-packages/{id}/runbook                           text, approved packages only
    GET/POST/DELETE /api/admin/frr/approvers                         the matrix (admin)
"""

from __future__ import annotations

import json
from datetime import datetime
from typing import Literal, Optional

from fastapi import APIRouter, HTTPException, Query
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel, Field, field_validator

from src import request_ctx, storage
from src.db import get_conn
from src.frr import package as package_mod
from src.frr import workflow as wf

router = APIRouter()


def _jsonable(row):
    if isinstance(row, list):
        return [_jsonable(r) for r in row]
    if isinstance(row, dict):
        return {k: _jsonable(v) for k, v in row.items()}
    if isinstance(row, datetime):
        return row.isoformat()
    if hasattr(row, "hex") and not isinstance(row, (bytes, str)):   # uuid.UUID
        return str(row)
    return row


def _run(fn, *args, **kw):
    try:
        with get_conn() as conn, conn.cursor() as cur:
            return fn(cur, *args, **kw)
    except wf.WorkflowError as e:
        raise HTTPException(e.status, str(e))


@router.post("/api/exports/{export_id}/change-package", status_code=201)
def draft_package(export_id: str, supersede: bool = Query(False)):
    if request_ctx.role() not in ("admin", "analyst"):
        raise HTTPException(403, "drafting a change package requires the admin or analyst role")
    with get_conn() as conn, conn.cursor() as cur:
        try:
            cur.execute("SELECT status, review_key, parsed_key FROM ztpa.exports WHERE export_id = %s",
                        [export_id])
        except Exception:  # noqa: BLE001 — a malformed uuid is "no such export"
            conn.rollback()
            raise HTTPException(404, "no such export")
        row = cur.fetchone()
    if row is None:
        raise HTTPException(404, "no such export")
    if row["status"] != "accepted":
        raise HTTPException(409, f"export is {row['status']}; only an accepted export has a register")
    store = storage.store()
    parsed = json.loads(store.get_bytes(row["parsed_key"]))
    drafted = package_mod.draft(json.loads(store.get_bytes(row["review_key"])), parsed)

    def _create(cur):
        from src.frr import context
        context.enrich_package(cur, drafted, parsed)
        return wf.create(cur, export_id, drafted, supersede=supersede)
    pkg = _run(_create)
    return _jsonable(_run(wf.get, str(pkg["package_id"])))


@router.get("/api/change-packages/{package_id}")
def get_package(package_id: str):
    """Header, summary, narrative and facet counts; items inline when the
    package is small (`items_inline`), otherwise from /items."""
    return _jsonable(_run(wf.get, package_id))


@router.get("/api/change-packages/{package_id}/items")
def get_package_items(package_id: str,
                      band: Optional[str] = Query(None, pattern="^(critical|high|medium|low)$"),
                      proposal: Optional[str] = Query(None, max_length=40),
                      impact: Optional[str] = Query(None, max_length=40),
                      layer: Optional[str] = Query(None, max_length=200),
                      decided: Optional[bool] = Query(None),
                      limit: int = Query(100, ge=1, le=500), offset: int = Query(0, ge=0)):
    return _jsonable(_run(wf.items, package_id, band=band, proposal=proposal, impact=impact, layer=layer,
                          decided=decided, limit=limit, offset=offset))


class ItemDecision(BaseModel):
    decision: Literal["accept", "reject", "modify"]
    input: Optional[dict] = None
    note: Optional[str] = Field(None, max_length=4000)

    @field_validator("input")
    @classmethod
    def _small(cls, v):
        if v is not None and len(json.dumps(v)) > 16_000:
            raise ValueError("owner input must be at most 16 KB")
        return v


@router.put("/api/change-packages/{package_id}/items/{item_id}")
def decide_item(package_id: str, item_id: str, body: ItemDecision):
    return _jsonable(_run(wf.decide_item, package_id, item_id, body.decision, body.input, body.note))


class BulkDecision(BaseModel):
    decision: Literal["accept", "reject"]
    note: Optional[str] = Field(None, max_length=4000)
    band: Optional[Literal["critical", "high", "medium", "low"]] = None
    proposal: Optional[str] = Field(None, max_length=40)
    impact: Optional[str] = Field(None, max_length=40)
    layer: Optional[str] = Field(None, max_length=200)
    undecided_only: bool = True


@router.post("/api/change-packages/{package_id}/items/bulk")
def decide_bulk(package_id: str, body: BulkDecision):
    return _run(wf.decide_bulk, package_id, body.decision, body.note, band=body.band, proposal=body.proposal,
                impact=body.impact, layer=body.layer, undecided_only=body.undecided_only)


class Note(BaseModel):
    note: Optional[str] = Field(None, max_length=4000)


@router.post("/api/change-packages/{package_id}/validate")
def validate_package(package_id: str, body: Note):
    return _jsonable(_run(wf.validate, package_id, body.note))


class Decision(BaseModel):
    decision: Literal["approve", "reject"]
    note: Optional[str] = Field(None, max_length=4000)


@router.post("/api/change-packages/{package_id}/decision")
def decide_package(package_id: str, body: Decision):
    return _jsonable(_run(wf.decide, package_id, body.decision, body.note))


@router.get("/api/change-packages/{package_id}/runbook", response_class=PlainTextResponse)
def package_runbook(package_id: str):
    return PlainTextResponse(_run(wf.runbook, package_id),
                             headers={"content-disposition": f'attachment; filename="frr-{package_id}.txt"'})


# --- approver matrix (admin) -----------------------------------------------------
def _admin() -> None:
    if request_ctx.role() != "admin":
        raise HTTPException(403, "admin only")


class Grant(BaseModel):
    principal: str = Field(..., min_length=3, max_length=320)
    duty: Literal["network_owner", "security_approver"]
    scope: str = Field("*", min_length=1, max_length=200)


@router.get("/api/admin/frr/approvers")
def list_approvers():
    _admin()
    with get_conn() as conn, conn.cursor() as cur:
        cur.execute("SELECT * FROM ztpa.frr_approvers ORDER BY duty, scope, principal")
        return {"items": _jsonable(cur.fetchall())}


@router.post("/api/admin/frr/approvers", status_code=201)
def grant_duty(body: Grant):
    _admin()
    return _jsonable(_run(wf.grant, body.principal, body.duty, body.scope))


@router.delete("/api/admin/frr/approvers")
def revoke_duty(principal: str, duty: str, scope: str = "*"):
    _admin()
    if not _run(wf.revoke, principal, duty, scope):
        raise HTTPException(404, "no such grant")
    return {"revoked": True}
