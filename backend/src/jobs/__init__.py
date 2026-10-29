"""Background jobs: a Postgres queue (`queue`), a handler registry (here) and a
worker process (`worker`).

A handler is a function of one `JobContext` that returns a JSON-serialisable
result. Register it with `@handler("kind")`. Handlers MUST be idempotent: a
job whose worker dies mid-run is reclaimed and run again from the start, so a
handler writes its outputs keyed by deterministic ids (UPSERT), never appends.

Raise `PermanentError` for input that will never succeed (a malformed export):
the job goes straight to `dead` instead of burning its retries. Any other
exception is retried with backoff.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass, field
from typing import Any, Callable

import psycopg

from .queue import Job

Handler = Callable[["JobContext"], dict | None]
_HANDLERS: dict[str, Handler] = {}
_HEAVY: set[str] = set()
_LOCK = threading.Lock()


class PermanentError(Exception):
    """The job cannot succeed on retry. Its message is shown to the user."""


class LeaseLost(Exception):
    """Raised by `JobContext.check()` once another worker owns the job."""


@dataclass
class JobContext:
    job: Job
    conn: psycopg.Connection          # the handler's transaction; committed with the outcome
    worker_id: str
    _lost: threading.Event = field(default_factory=threading.Event)
    _progress: dict | None = None
    _progress_lock: threading.Lock = field(default_factory=threading.Lock)

    @property
    def payload(self) -> dict:
        return self.job.payload

    def progress(self, **fields: Any) -> None:
        """Record progress; the heartbeat publishes it. Cheap to call often."""
        with self._progress_lock:
            self._progress = {**(self._progress or {}), **fields}

    def take_progress(self) -> dict | None:
        with self._progress_lock:
            p, self._progress = self._progress, None
            return p

    def check(self) -> None:
        """Call between steps of a long handler: stops work promptly once the
        lease is lost, instead of computing a result nobody can record."""
        if self._lost.is_set():
            raise LeaseLost(self.job.job_id)


def handler(kind: str, *, heavy: bool = False) -> Callable[[Handler], Handler]:
    """Register `fn` for `kind`. `heavy` marks a kind that holds a whole rulebase
    in memory (gigabytes at the size limit): a worker process runs at most
    NPR_WORKER_HEAVY_CONCURRENCY of those at once, whatever its slot count."""
    def register(fn: Handler) -> Handler:
        with _LOCK:
            if kind in _HANDLERS and _HANDLERS[kind] is not fn:
                raise ValueError(f"a handler for job kind {kind!r} is already registered")
            _HANDLERS[kind] = fn
            if heavy:
                _HEAVY.add(kind)
        return fn
    return register


def heavy_kinds() -> frozenset[str]:
    with _LOCK:
        return frozenset(_HEAVY)


def handlers() -> dict[str, Handler]:
    with _LOCK:
        return dict(_HANDLERS)


def unregister(kind: str) -> None:
    with _LOCK:
        _HANDLERS.pop(kind, None)
        _HEAVY.discard(kind)
