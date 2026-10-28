"""The Postgres job queue protocol (table: ztpa.jobs, migration 0009).

Every function takes a psycopg connection the caller owns and commits nothing
itself unless it says so -- `enqueue` is usually called inside the transaction
that records what the job is about (an upload row, an approval), so either both
exist or neither does.

THE CLAIM
---------
One statement: pick the best runnable row with `FOR UPDATE SKIP LOCKED`, mark it
running under a lease, return it. SKIP LOCKED is what makes N workers safe
without a coordinator: two workers racing for the same row never block on each
other, the loser simply takes the next one.

A row is runnable when it is `queued` and due, OR `running` with an expired
lease (its worker died or was descheduled past the lease). A reclaimed job has
already used an attempt; once attempts reach `max_attempts` the reaper marks it
dead instead of handing it out again, so a job that crashes its worker cannot
crash every worker in turn.

THE LEASE
---------
A worker heartbeats while it runs (`heartbeat`). Every state change it makes
afterwards is conditional on still holding the lease (`locked_by = me AND
status = 'running'`). If it lost the lease -- paused past `locked_until` and
someone else reclaimed the job -- its late `complete` or `fail` is a no-op that
returns False, so two workers can never both record an outcome.
"""

from __future__ import annotations

import json
import random
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Sequence

import psycopg
from psycopg.types.json import Jsonb

TABLE = "ztpa.jobs"
DEFAULT_LEASE_S = 60
# Retry delay = min(cap, base * 2^(attempt-1)) with +-20% jitter, so a downstream
# outage does not get a synchronized retry storm from every worker at once.
BACKOFF_BASE_S = 5.0
BACKOFF_CAP_S = 600.0
_ERROR_MAX = 4000


@dataclass(frozen=True)
class Job:
    job_id: str
    kind: str
    payload: dict
    status: str
    attempts: int
    max_attempts: int
    priority: int
    locked_by: str | None
    locked_until: datetime | None
    idempotency_key: str | None
    progress: dict | None
    result: dict | None
    last_error: str | None
    created_by: str | None
    created_at: datetime
    started_at: datetime | None
    finished_at: datetime | None

    @classmethod
    def from_row(cls, r: dict[str, Any]) -> "Job":
        return cls(job_id=str(r["job_id"]), kind=r["kind"], payload=r["payload"] or {},
                   status=r["status"], attempts=r["attempts"], max_attempts=r["max_attempts"],
                   priority=r["priority"], locked_by=r["locked_by"],
                   locked_until=r["locked_until"], idempotency_key=r["idempotency_key"],
                   progress=r["progress"], result=r["result"], last_error=r["last_error"],
                   created_by=r["created_by"], created_at=r["created_at"],
                   started_at=r["started_at"], finished_at=r["finished_at"])

    def public(self) -> dict[str, Any]:
        """The API shape: no lease internals."""
        return {"job_id": self.job_id, "kind": self.kind, "status": self.status,
                "attempts": self.attempts, "max_attempts": self.max_attempts,
                "progress": self.progress, "result": self.result, "error": self.last_error,
                "created_by": self.created_by,
                "created_at": self.created_at.isoformat() if self.created_at else None,
                "started_at": self.started_at.isoformat() if self.started_at else None,
                "finished_at": self.finished_at.isoformat() if self.finished_at else None}


def _rows(cur: psycopg.Cursor) -> list[dict[str, Any]]:
    cols = [d.name for d in cur.description or []]
    return [r if isinstance(r, dict) else dict(zip(cols, r)) for r in cur.fetchall()]


def backoff_seconds(attempt: int, *, rng: random.Random | None = None) -> float:
    base = min(BACKOFF_CAP_S, BACKOFF_BASE_S * (2 ** max(0, attempt - 1)))
    return base * (rng or random).uniform(0.8, 1.2)


def enqueue(conn: psycopg.Connection, kind: str, payload: dict | None = None, *,
            idempotency_key: str | None = None, priority: int = 100, max_attempts: int = 5,
            delay_s: float = 0.0, created_by: str | None = None) -> tuple[Job, bool]:
    """(job, created). With an idempotency key already in the table, returns the
    EXISTING job and created=False -- whatever its status -- so a retried API
    call reports the job it started the first time."""
    json.dumps(payload or {})                       # fail here, not inside the INSERT
    with conn.cursor() as cur:
        cur.execute(
            f"""INSERT INTO {TABLE} (kind, payload, idempotency_key, priority, max_attempts,
                                    run_after, created_by)
                VALUES (%s, %s, %s, %s, %s, now() + make_interval(secs => %s), %s)
                ON CONFLICT (idempotency_key) WHERE idempotency_key IS NOT NULL DO NOTHING
                RETURNING *""",
            [kind, Jsonb(payload or {}), idempotency_key, priority, max_attempts, delay_s,
             created_by])
        rows = _rows(cur)
        if rows:
            return Job.from_row(rows[0]), True
        cur.execute(f"SELECT * FROM {TABLE} WHERE idempotency_key = %s", [idempotency_key])
        return Job.from_row(_rows(cur)[0]), False


def get(conn: psycopg.Connection, job_id: str) -> Job | None:
    with conn.cursor() as cur:
        try:
            cur.execute(f"SELECT * FROM {TABLE} WHERE job_id = %s", [job_id])
        except psycopg.errors.InvalidTextRepresentation:
            conn.rollback()
            return None
        rows = _rows(cur)
    return Job.from_row(rows[0]) if rows else None


def claim(conn: psycopg.Connection, worker_id: str, kinds: Sequence[str], *,
          lease_s: int = DEFAULT_LEASE_S) -> Job | None:
    """Take one runnable job of the given kinds, or None. Commits."""
    with conn.cursor() as cur:
        cur.execute(
            f"""UPDATE {TABLE} j
                   SET status = 'running', locked_by = %(w)s,
                       locked_until = now() + make_interval(secs => %(lease)s),
                       attempts = j.attempts + 1,
                       started_at = coalesce(j.started_at, now()), updated_at = now()
                 WHERE j.job_id = (
                       SELECT job_id FROM {TABLE}
                        WHERE kind = ANY(%(kinds)s)
                          AND ((status = 'queued' AND run_after <= now())
                               OR (status = 'running' AND locked_until < now()
                                   AND attempts < max_attempts))
                        ORDER BY priority, run_after
                        LIMIT 1
                        FOR UPDATE SKIP LOCKED)
             RETURNING j.*""",
            {"w": worker_id, "lease": lease_s, "kinds": list(kinds)})
        rows = _rows(cur)
    conn.commit()
    return Job.from_row(rows[0]) if rows else None


def heartbeat(conn: psycopg.Connection, job: Job, worker_id: str, *,
              lease_s: int = DEFAULT_LEASE_S, progress: dict | None = None) -> bool:
    """Extend the lease (and optionally record progress). False = lease lost:
    the caller must stop work and record nothing. Commits."""
    with conn.cursor() as cur:
        cur.execute(
            f"""UPDATE {TABLE}
                   SET locked_until = now() + make_interval(secs => %s),
                       progress = coalesce(%s, progress), updated_at = now()
                 WHERE job_id = %s AND locked_by = %s AND status = 'running'""",
            [lease_s, Jsonb(progress) if progress is not None else None, job.job_id, worker_id])
        held = cur.rowcount == 1
    conn.commit()
    return held


def complete(conn: psycopg.Connection, job: Job, worker_id: str,
             result: dict | None = None) -> bool:
    """Record success. Does NOT commit: a handler that wrote rows on `conn`
    commits them in the same transaction as the outcome."""
    with conn.cursor() as cur:
        cur.execute(
            f"""UPDATE {TABLE}
                   SET status = 'succeeded', result = %s, locked_by = NULL, locked_until = NULL,
                       finished_at = now(), updated_at = now(), last_error = NULL
                 WHERE job_id = %s AND locked_by = %s AND status = 'running'""",
            [Jsonb(result or {}), job.job_id, worker_id])
        return cur.rowcount == 1


def fail(conn: psycopg.Connection, job: Job, worker_id: str, error: str, *,
         retryable: bool = True) -> str | None:
    """Record a failure: back to `queued` after a backoff, or `dead` when the
    error is permanent or attempts are spent. Returns the new status, or None if
    the lease was lost. Commits."""
    dead = (not retryable) or job.attempts >= job.max_attempts
    delay = 0.0 if dead else backoff_seconds(job.attempts)
    with conn.cursor() as cur:
        cur.execute(
            f"""UPDATE {TABLE}
                   SET status = %s, last_error = %s, locked_by = NULL, locked_until = NULL,
                       run_after = now() + make_interval(secs => %s),
                       finished_at = CASE WHEN %s THEN now() ELSE NULL END, updated_at = now()
                 WHERE job_id = %s AND locked_by = %s AND status = 'running'""",
            ["dead" if dead else "queued", error[:_ERROR_MAX], delay, dead, job.job_id, worker_id])
        held = cur.rowcount == 1
    conn.commit()
    return ("dead" if dead else "queued") if held else None


def cancel(conn: psycopg.Connection, job_id: str) -> bool:
    """Cancel a job that has not started. A running job is not interrupted. Commits."""
    with conn.cursor() as cur:
        cur.execute(f"""UPDATE {TABLE} SET status = 'cancelled', finished_at = now(),
                               updated_at = now()
                         WHERE job_id = %s AND status = 'queued'""", [job_id])
        done = cur.rowcount == 1
    conn.commit()
    return done


def reap(conn: psycopg.Connection) -> int:
    """Expired leases with no attempts left become dead (the claim will not hand
    them out again). Safe to run from every worker. Commits."""
    with conn.cursor() as cur:
        cur.execute(
            f"""UPDATE {TABLE}
                   SET status = 'dead', locked_by = NULL, locked_until = NULL,
                       finished_at = now(), updated_at = now(),
                       last_error = coalesce(last_error, '') ||
                                    CASE WHEN last_error IS NULL THEN '' ELSE ' | ' END ||
                                    'lease expired on the final attempt (worker lost)'
                 WHERE status = 'running' AND locked_until < now()
                   AND attempts >= max_attempts""")
        n = cur.rowcount
    conn.commit()
    return n


def stats(conn: psycopg.Connection) -> dict[str, Any]:
    """Queue depth and oldest-runnable age per kind: the autoscaling and alerting
    signal."""
    with conn.cursor() as cur:
        cur.execute(
            f"""SELECT kind,
                       count(*) FILTER (WHERE status = 'queued' AND run_after <= now()) AS ready,
                       count(*) FILTER (WHERE status = 'queued' AND run_after > now()) AS delayed,
                       count(*) FILTER (WHERE status = 'running') AS running,
                       count(*) FILTER (WHERE status = 'dead') AS dead,
                       extract(epoch FROM now() - min(run_after)
                               FILTER (WHERE status = 'queued' AND run_after <= now()))
                         AS oldest_ready_s
                  FROM {TABLE} GROUP BY kind ORDER BY kind""")
        rows = _rows(cur)
    conn.commit()
    return {r["kind"]: {k: (float(v) if k == "oldest_ready_s" and v is not None else v)
                        for k, v in r.items() if k != "kind"} for r in rows}
