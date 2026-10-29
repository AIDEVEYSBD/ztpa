"""Export intake: from uploaded bytes to an accepted, reviewed rulebase -- or a
rejection that says why.

The upload endpoint (app/exports_api.py) stores the bytes content-addressed and
enqueues `export.ingest`. This handler, in a worker:

  1. re-hashes the stored object and refuses it if it does not match the sha256
     recorded at upload (corruption in storage, or a tampered object);
  2. decodes and parses it with the source type's parser, which refuses shapes
     that would misreport (see normalizers/checkpoint.py);
  3. checks export AGE: the export must state when it was taken (in the file or
     declared at upload), not be older than NPR_EXPORT_MAX_AGE_DAYS, and not be
     from the future -- a stale export reviewed as current is a wrong review;
  4. runs the deterministic review and stores the parsed rulebase and the
     rule-risk register next to the original.

Rejection is an OUTCOME, not a failure: the job succeeds and the export row
says `rejected` with the reason. Only infrastructure errors are retried.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
from datetime import datetime, timedelta, timezone
from typing import Callable

from psycopg.types.json import Jsonb

from .. import storage
from ..jobs import JobContext, handler
from ..normalizers import checkpoint
from .review import review
from .rulebase import ExportRejected, ParsedRulebase

log = logging.getLogger("npr.api.intake")

MAX_AGE_DAYS = int(os.environ.get("NPR_EXPORT_MAX_AGE_DAYS", "30"))
# Exports are parsed in one pass (JSON in memory, several times its size as
# Python objects). Above this the worker would risk running out of memory and
# being killed mid-job, retried, killed again: refuse with a reason instead.
MAX_PARSE_BYTES = int(os.environ.get("NPR_MAX_PARSE_BYTES", str(300 * 1024 * 1024)))
_FUTURE_SLACK = timedelta(hours=24)

# source_type -> parser(export_json, exported_at) -> ParsedRulebase
PARSERS: dict[str, Callable[..., ParsedRulebase]] = {
    "checkpoint": checkpoint.parse,
}


def original_key(sha256: str) -> str:
    return f"exports/{sha256}/original"


def _check_age(when: datetime | None, now: datetime) -> None:
    if when is None:
        raise ExportRejected("the export does not say when it was taken; re-upload with "
                             "exported_at declared, so its age can be checked")
    if when > now + _FUTURE_SLACK:
        raise ExportRejected(f"the export claims to be taken at {when.isoformat()}, in the future; "
                             "check the declared time or the exporting host's clock")
    if when < now - timedelta(days=MAX_AGE_DAYS):
        raise ExportRejected(f"the export was taken {when.date()}, more than {MAX_AGE_DAYS} days "
                             "ago; review a current export")


def process(row: dict, *, now: datetime | None = None) -> tuple[str, dict]:
    """(status, fields to update). Pure apart from storage reads/writes."""
    now = now or datetime.now(timezone.utc)
    if row["size_bytes"] > MAX_PARSE_BYTES:
        return "rejected", {"rejection_reason": f"the export is {row['size_bytes']:,} bytes; exports above "
                                                f"{MAX_PARSE_BYTES:,} bytes are not parsed in one pass yet. "
                                                "Export each access layer separately and upload them one by one"}
    store = storage.store()
    data = store.get_bytes(row["storage_key"])
    if hashlib.sha256(data).hexdigest() != row["sha256"]:
        return "rejected", {"rejection_reason": "stored export does not match the checksum "
                                                "recorded at upload; re-upload it"}
    parser = PARSERS.get(row["source_type"])
    if parser is None:
        return "rejected", {"rejection_reason": f"no parser for source type {row['source_type']!r}"}
    try:
        try:
            doc = json.loads(data)
        except (UnicodeDecodeError, ValueError) as e:
            raise ExportRejected(f"the export is not valid JSON ({e})") from None
        parsed = parser(doc, exported_at=None)
        when = parsed.exported_at or row.get("declared_exported_at")
        _check_age(when, now)
        parsed.exported_at = when
        result = review(parsed, now=now)
    except ExportRejected as e:
        return "rejected", {"rejection_reason": str(e)}

    base = f"exports/{row['sha256']}"
    review_doc = result.to_jsonable()
    store.put_bytes(f"{base}/parsed.json", json.dumps(parsed.to_jsonable()).encode(),
                    "application/json")
    store.put_bytes(f"{base}/review.json", json.dumps(review_doc).encode(), "application/json")
    summary = {**parsed.summary(), "review": result.stats,
               "limitations_total": len(result.limitations)
               + sum(len(e.limitations) for e in result.register)}
    return "accepted", {"exported_at": when, "summary": summary, "review_doc": review_doc,
                        "parsed_key": f"{base}/parsed.json", "review_key": f"{base}/review.json"}


def store_register(cur, export_id, review_doc: dict) -> int:
    """The register as indexed rows (migration 0018) plus the small head on the
    export, in the caller's transaction. Idempotent: replaces any earlier rows."""
    from psycopg.types.json import Jsonb as _J
    cur.execute("DELETE FROM ztpa.review_entries WHERE export_id = %s", [export_id])
    with cur.copy("COPY ztpa.review_entries (export_id, ord, rule_uid, flagged, band, severity, checks, entry) "
                  "FROM STDIN") as cp:
        for i, e in enumerate(review_doc["register"]):
            flagged = bool(e["checks"])
            cp.write_row((export_id, i, e["rule_uid"], flagged, e["band"] if flagged else None,
                          int(e.get("severity") or 0), sorted({c["check"] for c in e["checks"]}),
                          json.dumps(e, default=str)))
    head = {k: v for k, v in review_doc.items() if k != "register"}
    cur.execute("UPDATE ztpa.exports SET review_head = %s WHERE export_id = %s", [_J(head), export_id])
    return len(review_doc["register"])


@handler("export.ingest")
def ingest(ctx: JobContext) -> dict:
    with ctx.conn.cursor() as cur:
        cur.execute("SELECT * FROM ztpa.exports WHERE export_id = %s", [ctx.payload["export_id"]])
        row = cur.fetchone()
    if row is None:
        return {"skipped": "export row no longer exists"}
    ctx.progress(step="parsing")
    status, fields = process(row)
    ctx.check()
    with ctx.conn.cursor() as cur:
        cur.execute(
            """UPDATE ztpa.exports SET status = %s, rejection_reason = %s, exported_at = %s,
                      summary = %s, parsed_key = %s, review_key = %s, updated_at = now()
                WHERE export_id = %s""",
            [status, fields.get("rejection_reason"), fields.get("exported_at"),
             Jsonb(fields["summary"]) if fields.get("summary") is not None else None,
             fields.get("parsed_key"), fields.get("review_key"), row["export_id"]])
        if status == "accepted":
            # Same transaction as the status: an accepted export always has its rows.
            store_register(cur, row["export_id"], fields["review_doc"])
    log.info("export processed", extra={"event": "export_processed", "export_id": str(row["export_id"]),
                                        "status": status, "reason": fields.get("rejection_reason")})
    return {"status": status, "reason": fields.get("rejection_reason"),
            "summary": fields.get("summary")}


@handler("export.finalize")
def finalize_upload(ctx: JobContext) -> dict:
    """An assembled multipart upload -> an export: stream-hash it, reuse an
    existing export with the same bytes, otherwise register it and enqueue
    ingest. The object stays where it was assembled; `storage_key` points at it."""
    from ..jobs import queue

    cur = ctx.conn.cursor()
    cur.execute("SELECT * FROM ztpa.export_uploads WHERE upload_id = %s", [ctx.payload["upload_id"]])
    up = cur.fetchone()
    if up is None or up["status"] != "completing":
        return {"skipped": f"upload is {up['status'] if up else 'gone'}"}
    h, size = hashlib.sha256(), 0
    for chunk in storage.store().iter_chunks(up["storage_key"]):
        h.update(chunk)
        size += len(chunk)
        ctx.check()
    digest = h.hexdigest()
    if size != up["bytes"]:
        reason = f"assembled object is {size} bytes, expected {up['bytes']}"
        cur.execute("UPDATE ztpa.export_uploads SET status='failed', failure_reason=%s WHERE upload_id=%s",
                    [reason, up["upload_id"]])
        return {"status": "failed", "reason": reason}
    cur.execute("SELECT export_id FROM ztpa.exports WHERE sha256 = %s", [digest])
    existing = cur.fetchone()
    if existing:
        storage.store().delete(up["storage_key"])
        cur.execute("UPDATE ztpa.export_uploads SET status='done', export_id=%s, duplicate=true WHERE upload_id=%s",
                    [existing["export_id"], up["upload_id"]])
        return {"status": "duplicate", "export_id": str(existing["export_id"])}
    cur.execute("""INSERT INTO ztpa.exports (sha256, source_type, filename, size_bytes, storage_key,
                                             declared_exported_at, uploaded_by)
                   VALUES (%s, %s, %s, %s, %s, %s, %s) RETURNING export_id""",
                [digest, up["source_type"], up["filename"], size, up["storage_key"],
                 up["declared_exported_at"], up["uploaded_by"]])
    eid = cur.fetchone()["export_id"]
    job, _ = queue.enqueue(ctx.conn, "export.ingest", {"export_id": str(eid)},
                           idempotency_key=f"export:{digest}", priority=50, created_by=up["uploaded_by"])
    cur.execute("UPDATE ztpa.exports SET job_id = %s WHERE export_id = %s", [job.job_id, eid])
    cur.execute("UPDATE ztpa.export_uploads SET status='done', export_id=%s WHERE upload_id=%s",
                [eid, up["upload_id"]])
    return {"status": "registered", "export_id": str(eid), "bytes": size}
