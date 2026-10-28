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
    store.put_bytes(f"{base}/parsed.json", json.dumps(parsed.to_jsonable()).encode(),
                    "application/json")
    store.put_bytes(f"{base}/review.json", json.dumps(result.to_jsonable()).encode(),
                    "application/json")
    summary = {**parsed.summary(), "review": result.stats,
               "limitations_total": len(result.limitations)
               + sum(len(e.limitations) for e in result.register)}
    return "accepted", {"exported_at": when, "summary": summary,
                        "parsed_key": f"{base}/parsed.json", "review_key": f"{base}/review.json"}


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
    log.info("export processed", extra={"event": "export_processed", "export_id": str(row["export_id"]),
                                        "status": status, "reason": fields.get("rejection_reason")})
    return {"status": status, "reason": fields.get("rejection_reason"),
            "summary": fields.get("summary")}
