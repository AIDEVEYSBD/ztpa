"""The register beyond the screen: CSV download, and comparison with an earlier review.

    GET /api/exports/{id}/register.csv?band=&check=&flagged_only=   streamed; any size
    GET /api/exports/{id}/compare?baseline={earlier id}&limit=     what changed since then

Both read the indexed rows (migration 0018), so they need exports reviewed after it.
The CSV streams through a server-side cursor in batches: a 70,000-rule register is
never held in memory. The comparison is set arithmetic in SQL over (rule uid,
check) pairs, keyed by the Check Point rule uid, which is stable across exports
while rule numbers shift.
"""

from __future__ import annotations

import csv
import io
from typing import Iterator

from fastapi import APIRouter, HTTPException, Query
from fastapi.responses import StreamingResponse

from src.db import get_conn

router = APIRouter()
_BATCH = 1000
_COLUMNS = ["rule_number", "rule_name", "layer", "section", "action", "enabled", "sources", "destinations",
            "services", "hit_count", "last_hit", "expires_at", "worst_band", "severity", "checks",
            "check_titles", "limitations", "nat", "rule_uid"]


def _accepted_with_rows(cur, export_id: str) -> dict:
    try:
        cur.execute("SELECT export_id, filename, status, review_head IS NOT NULL AS has_rows "
                    "FROM ztpa.exports WHERE export_id = %s", [export_id])
    except Exception:  # noqa: BLE001 — a malformed uuid is "no such export"
        cur.connection.rollback()
        raise HTTPException(404, "no such export")
    row = cur.fetchone()
    if row is None:
        raise HTTPException(404, "no such export")
    if row["status"] != "accepted":
        raise HTTPException(409, f"export is {row['status']}")
    if not row["has_rows"]:
        raise HTTPException(409, "this export was reviewed before the register was stored as rows; "
                                 "re-upload it to download or compare")
    return row


def _where(export_id: str, band, check, flagged_only) -> tuple[str, list]:
    where, params = ["export_id = %s"], [export_id]
    if flagged_only or band:
        where.append("flagged")
    if band:
        where.append("band = %s")
        params.append(band)
    if check:
        where.append("checks @> ARRAY[%s]::text[]")
        params.append(check)
    return " AND ".join(where), params


def _csv_row(e: dict) -> list:
    join = "; ".join
    return [e.get("number"), e.get("name"), e.get("layer"), e.get("section"), e.get("action"), e.get("enabled"),
            join(e.get("sources") or []), join(e.get("destinations") or []), join(e.get("services") or []),
            "" if e.get("hit_count") is None else e["hit_count"], e.get("last_hit") or "", e.get("expires_at") or "",
            e.get("band") if e.get("checks") else "", e.get("severity") or 0,
            join(c["check"] for c in e.get("checks") or []), join(c["title"] for c in e.get("checks") or []),
            join(e.get("limitations") or []),
            join(f"NAT {n.get('nat_rule')}: {', '.join(n.get('original_destination') or [])} -> "
                 f"{', '.join(n.get('translated_destination') or [])}" for n in e.get("nat") or []),
            e.get("rule_uid")]


@router.get("/api/exports/{export_id}/register.csv")
def register_csv(export_id: str, band: str | None = Query(None, pattern="^(critical|high|medium|low)$"),
                 check: str | None = Query(None, max_length=40), flagged_only: bool = Query(True)):
    with get_conn() as conn, conn.cursor() as cur:
        exp = _accepted_with_rows(cur, export_id)
    clause, params = _where(export_id, band, check, flagged_only)

    def rows() -> Iterator[str]:
        buf = io.StringIO()
        w = csv.writer(buf)
        w.writerow(_COLUMNS)
        yield buf.getvalue()
        with get_conn() as conn, conn.cursor(name="register_csv") as cur:     # server-side cursor
            cur.itersize = _BATCH
            cur.execute(f"SELECT entry FROM ztpa.review_entries WHERE {clause} ORDER BY ord", params)
            while batch := cur.fetchmany(_BATCH):
                buf.seek(0)
                buf.truncate()
                for r in batch:
                    w.writerow(_csv_row(r["entry"]))
                yield buf.getvalue()

    name = (exp["filename"] or "export").rsplit(".", 1)[0]
    return StreamingResponse(rows(), media_type="text/csv; charset=utf-8",
                             headers={"content-disposition": f'attachment; filename="{name}-register.csv"'})


@router.get("/api/exports/{export_id}/compare")
def compare(export_id: str, baseline: str = Query(...), limit: int = Query(200, ge=1, le=2000)):
    with get_conn() as conn, conn.cursor() as cur:
        _accepted_with_rows(cur, export_id)
        _accepted_with_rows(cur, baseline)
        params = {"cur": export_id, "base": baseline, "lim": limit}
        # Bulk set arithmetic: hash joins are always right here. Without this a
        # just-loaded, not-yet-analysed pair planned as nested loops (357 s at
        # 70,000 rules vs 0.5 s analysed). Scoped to this transaction only.
        cur.execute("SET LOCAL enable_nestloop = off")
        # Anti-joins, not NOT IN: NOT IN (subquery) cannot become a hash anti-join
        # (NULL semantics) and degraded to a per-row scan -- 85 s at 70,000 rules.
        cur.execute("""
            WITH c AS (SELECT rule_uid, band, flagged FROM ztpa.review_entries WHERE export_id = %(cur)s),
                 b AS (SELECT rule_uid, band, flagged FROM ztpa.review_entries WHERE export_id = %(base)s),
                 cc AS (SELECT rule_uid, unnest(checks) AS chk FROM ztpa.review_entries WHERE export_id = %(cur)s),
                 bc AS (SELECT rule_uid, unnest(checks) AS chk FROM ztpa.review_entries WHERE export_id = %(base)s)
            SELECT
              (SELECT count(*) FROM c LEFT JOIN b USING (rule_uid) WHERE b.rule_uid IS NULL) AS rules_added,
              (SELECT count(*) FROM b LEFT JOIN c USING (rule_uid) WHERE c.rule_uid IS NULL) AS rules_removed,
              (SELECT count(*) FROM (SELECT * FROM cc EXCEPT SELECT * FROM bc) x) AS findings_new,
              (SELECT count(*) FROM (SELECT * FROM bc EXCEPT SELECT * FROM cc) x) AS findings_resolved,
              (SELECT count(*) FROM c JOIN b USING (rule_uid)
                WHERE c.flagged AND b.flagged AND c.band <> b.band) AS band_changes""", params)
        summary = cur.fetchone()

        def listing(sql: str) -> list[dict]:
            cur.execute(sql, params)
            return cur.fetchall()

        new_findings = listing("""
            SELECT n.rule_uid, n.chk AS "check", c.entry->>'number' AS number, c.entry->>'name' AS name,
                   c.entry->>'layer' AS layer, c.band,
                   (SELECT x->>'title' FROM jsonb_array_elements(c.entry->'checks') x
                     WHERE x->>'check' = n.chk LIMIT 1) AS title,
                   NOT EXISTS (SELECT 1 FROM ztpa.review_entries b
                                WHERE b.export_id = %(base)s AND b.rule_uid = n.rule_uid) AS new_rule
              FROM (SELECT rule_uid, unnest(checks) AS chk FROM ztpa.review_entries WHERE export_id = %(cur)s
                    EXCEPT
                    SELECT rule_uid, unnest(checks) FROM ztpa.review_entries WHERE export_id = %(base)s) n
              JOIN ztpa.review_entries c ON c.export_id = %(cur)s AND c.rule_uid = n.rule_uid
             ORDER BY CASE c.band WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 ELSE 3 END, c.ord
             LIMIT %(lim)s""")
        resolved = listing("""
            SELECT r.rule_uid, r.chk AS "check", b.entry->>'number' AS number, b.entry->>'name' AS name,
                   b.entry->>'layer' AS layer, b.band,
                   NOT EXISTS (SELECT 1 FROM ztpa.review_entries c
                                WHERE c.export_id = %(cur)s AND c.rule_uid = r.rule_uid) AS rule_removed
              FROM (SELECT rule_uid, unnest(checks) AS chk FROM ztpa.review_entries WHERE export_id = %(base)s
                    EXCEPT
                    SELECT rule_uid, unnest(checks) FROM ztpa.review_entries WHERE export_id = %(cur)s) r
              JOIN ztpa.review_entries b ON b.export_id = %(base)s AND b.rule_uid = r.rule_uid
             ORDER BY b.ord LIMIT %(lim)s""")
        band_changes = listing("""
            SELECT c.rule_uid, c.entry->>'number' AS number, c.entry->>'name' AS name, b.band AS was, c.band AS now
              FROM ztpa.review_entries c JOIN ztpa.review_entries b
                ON b.export_id = %(base)s AND b.rule_uid = c.rule_uid
             WHERE c.export_id = %(cur)s AND c.flagged AND b.flagged AND c.band <> b.band
             ORDER BY c.ord LIMIT %(lim)s""")
    return {"export_id": export_id, "baseline": baseline, "summary": summary,
            "new_findings": new_findings, "resolved_findings": resolved, "band_changes": band_changes,
            "limit": limit}
