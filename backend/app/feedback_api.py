"""Reviewer feedback on the rule-risk register, and labels derived from it.

    PUT /api/exports/{id}/review/{rule_uid}/feedback   {check, verdict, suggested_band?, comment?}
    GET /api/exports/{id}/feedback                     verdicts + agreement summary per check
    GET /api/exports/{id}/labels                       eval labels (admin): engine checks minus
                                                       disagreed ones; band = reviewers' suggestion
                                                       when they gave one, else the engine's

Verdict semantics: AGREE with a raised check; DISAGREE with a raised check = a
false positive; DISAGREE naming a check the review did NOT raise = a missed
finding (a false negative). A disagreement needs a comment: it is the evidence a
tuning change will cite.
"""

from __future__ import annotations

import json
from collections import Counter, defaultdict
from typing import Literal, Optional

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from src import request_ctx, storage
from src.db import audit, get_conn

from app.packages_api import _jsonable

router = APIRouter()
_REVIEW_ROLES = ("admin", "analyst")


class Feedback(BaseModel):
    check: str = Field(..., pattern=r"^[a-z_+]{2,40}$")
    verdict: Literal["agree", "disagree"]
    suggested_band: Optional[Literal["none", "low", "medium", "high", "critical"]] = None
    comment: Optional[str] = Field(None, max_length=2000)


def _reviewer() -> str:
    a = request_ctx.current()
    who = (a.email or a.sub or "").lower()
    if not who:
        raise HTTPException(403, "feedback needs an identified reviewer")
    return who


def _register(cur, export_id: str) -> dict:
    try:
        cur.execute("SELECT status, review_key FROM ztpa.exports WHERE export_id = %s", [export_id])
    except Exception:  # noqa: BLE001 — a malformed uuid is "no such export"
        cur.connection.rollback()
        raise HTTPException(404, "no such export")
    row = cur.fetchone()
    if row is None:
        raise HTTPException(404, "no such export")
    if row["status"] != "accepted":
        raise HTTPException(409, f"export is {row['status']}")
    return json.loads(storage.store().get_bytes(row["review_key"]))


@router.put("/api/exports/{export_id}/review/{rule_uid}/feedback")
def give_feedback(export_id: str, rule_uid: str, body: Feedback):
    duty_holder = False
    with get_conn() as conn, conn.cursor() as cur:
        if request_ctx.role() not in _REVIEW_ROLES:
            from src.frr import workflow
            duty_holder = workflow.has_duty(cur, "network_owner", {"*"}) or \
                workflow.has_duty(cur, "security_approver", {"*"})
            if not duty_holder:
                raise HTTPException(403, "feedback requires the admin or analyst role or an FRR duty")
        reg = _register(cur, export_id)
        entry = next((e for e in reg["register"] if e["rule_uid"] == rule_uid), None)
        if entry is None:
            raise HTTPException(404, "no such rule in this review")
        if body.check not in {c["check"] for c in entry["checks"]} and body.verdict == "agree":
            raise HTTPException(422, "cannot agree with a check the review did not raise; "
                                     "to report a missed finding, disagree naming that check")
        if body.verdict == "disagree" and not (body.comment or "").strip():
            raise HTTPException(422, "a disagreement needs a comment saying why")
        if body.verdict == "disagree" and body.check not in {c["check"] for c in entry["checks"]} \
                and not body.suggested_band:
            raise HTTPException(422, "a missed finding needs the band it should have had")
        cur.execute(
            """INSERT INTO ztpa.frr_feedback (export_id, rule_uid, check_kind, reviewer, verdict,
                                              suggested_band, comment)
               VALUES (%s, %s, %s, %s, %s, %s, %s)
               ON CONFLICT (export_id, rule_uid, check_kind, reviewer) DO UPDATE SET
                 verdict = EXCLUDED.verdict, suggested_band = EXCLUDED.suggested_band,
                 comment = EXCLUDED.comment, updated_at = now()
               RETURNING *""",
            [export_id, rule_uid, body.check, _reviewer(), body.verdict, body.suggested_band, body.comment])
        out = cur.fetchone()
        audit(cur, "frr_feedback", subject=f"{export_id}/{rule_uid}",
              detail={"check": body.check, "verdict": body.verdict, "suggested_band": body.suggested_band})
    return _jsonable(out)


@router.get("/api/exports/{export_id}/feedback")
def list_feedback(export_id: str):
    with get_conn() as conn, conn.cursor() as cur:
        _register(cur, export_id)
        cur.execute("SELECT * FROM ztpa.frr_feedback WHERE export_id = %s ORDER BY rule_uid, check_kind",
                    [export_id])
        rows = cur.fetchall()
    per: dict[str, Counter] = defaultdict(Counter)
    shifts: Counter = Counter()
    for r in rows:
        per[r["check_kind"]][r["verdict"]] += 1
        if r["suggested_band"]:
            shifts[f"{r['check_kind']}->{r['suggested_band']}"] += 1
    summary = {k: {"agree": v["agree"], "disagree": v["disagree"],
                   "agreement": round(v["agree"] / (v["agree"] + v["disagree"]), 3)}
               for k, v in sorted(per.items())}
    return {"items": _jsonable(rows), "summary": summary, "suggested_bands": dict(shifts.most_common(20))}


@router.get("/api/exports/{export_id}/labels")
def export_labels(export_id: str):
    if request_ctx.role() != "admin":
        raise HTTPException(403, "admin only")
    with get_conn() as conn, conn.cursor() as cur:
        reg = _register(cur, export_id)
        cur.execute("SELECT * FROM ztpa.frr_feedback WHERE export_id = %s", [export_id])
        fb = cur.fetchall()
    by_rule: dict[str, list] = defaultdict(list)
    for r in fb:
        by_rule[r["rule_uid"]].append(r)
    labels = {}
    for e in reg["register"]:
        rows = by_rule.get(e["rule_uid"], [])
        if not rows:
            continue                                   # only reviewed rules become labels
        raised = {c["check"] for c in e["checks"]}
        disagreed = {r["check_kind"] for r in rows if r["verdict"] == "disagree"}
        checks = sorted((raised - disagreed) | (disagreed - raised))   # drop FPs, add misses
        bands = Counter(r["suggested_band"] for r in rows if r["suggested_band"])
        # A reviewer's band wins; otherwise the engine's, unless every check was
        # rejected, in which case the rule is clean.
        band = bands.most_common(1)[0][0] if bands else (e["band"] if checks else "none")
        labels[e["rule_uid"]] = {"checks": checks, "band": band, "reviewers": len({r["reviewer"] for r in rows})}
    return labels
