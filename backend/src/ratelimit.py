"""Rate limits for expensive (model-backed) endpoints, shared across replicas.

Two ceilings per bucket, both per one-minute window:

  * per identity -- one user cannot spend the deployment's model budget;
  * per deployment -- all users together cannot exceed what the provider
    contract, the cost budget or the provider's own quota allows.

Counted with one UPSERT per request in `ztpa.rate_limits` (migration 0011),
so every API replica sees the same count. Without a database (local dev), an
in-process counter with the same semantics is used.

FAILS OPEN, LOUDLY
------------------
If the counter cannot be written, the request is allowed and the failure is
logged. A rate limiter that takes the product down with the database is worse
than one briefly not limiting; the endpoints behind it need the database
anyway, and the edge WAF still applies a coarse per-IP limit.
"""

from __future__ import annotations

import logging
import random
import threading
import time
from collections import defaultdict
from dataclasses import dataclass

import psycopg

from . import settings

log = logging.getLogger("npr.api.ratelimit")

_WINDOW_S = 60
_GLOBAL = "*"
_PRUNE_PROBABILITY = 0.01


@dataclass(frozen=True)
class Decision:
    allowed: bool
    limit: int
    remaining: int
    retry_after_s: int
    scope: str            # "identity" | "deployment" -- which ceiling was hit


def _window(now: float) -> int:
    return int(now // _WINDOW_S) * _WINDOW_S


# --- in-process fallback ------------------------------------------------------
_LOCAL: dict[tuple[str, str, int], int] = defaultdict(int)
_LOCAL_LOCK = threading.Lock()


def _local_hit(bucket: str, subjects: tuple[str, ...], window: int) -> list[int]:
    with _LOCAL_LOCK:
        for k in [k for k in _LOCAL if k[2] < window]:
            del _LOCAL[k]
        counts = []
        for s in subjects:
            _LOCAL[(bucket, s, window)] += 1
            counts.append(_LOCAL[(bucket, s, window)])
        return counts


def reset_local() -> None:
    with _LOCAL_LOCK:
        _LOCAL.clear()


# --- shared counter -----------------------------------------------------------
def _db_hit(bucket: str, subjects: tuple[str, ...], window: int) -> list[int]:
    from .db import get_conn

    with get_conn() as conn, conn.cursor() as cur:
        counts = []
        for s in subjects:
            cur.execute(
                """INSERT INTO ztpa.rate_limits (bucket, subject, window_start, hits)
                   VALUES (%s, %s, to_timestamp(%s), 1)
                   ON CONFLICT (bucket, subject, window_start)
                   DO UPDATE SET hits = ztpa.rate_limits.hits + 1
                   RETURNING hits""", [bucket, s, window])
            row = cur.fetchone()
            counts.append(int(row["hits"] if isinstance(row, dict) else row[0]))
        if random.random() < _PRUNE_PROBABILITY:
            cur.execute("DELETE FROM ztpa.rate_limits WHERE window_start < now() - interval '1 hour'")
        return counts


def hit(bucket: str, subject: str | None, *, per_identity: int, per_deployment: int,
        now: float | None = None) -> Decision:
    """Count one request against both ceilings and say whether it may proceed.
    A request over either ceiling is still counted, so hammering a limit does
    not reset it."""
    now = time.time() if now is None else now
    window = _window(now)
    retry = max(1, window + _WINDOW_S - int(now))
    subjects = (subject or "anonymous", _GLOBAL)
    try:
        counts = _db_hit(bucket, subjects, window) if settings.DATABASE_URL else \
            _local_hit(bucket, subjects, window)
    except (psycopg.Error, OSError, RuntimeError) as e:
        log.warning("rate limit counter unavailable; allowing the request",
                    exc_info=True, extra={"event": "ratelimit_unavailable", "bucket": bucket,
                                          "error": str(e)})
        return Decision(True, per_identity, per_identity, 0, "identity")
    mine, everyone = counts
    if mine > per_identity:
        return Decision(False, per_identity, 0, retry, "identity")
    if everyone > per_deployment:
        return Decision(False, per_deployment, 0, retry, "deployment")
    return Decision(True, per_identity, per_identity - mine, 0, "identity")
