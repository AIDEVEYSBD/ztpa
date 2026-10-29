"""The worker process: `python -m src.jobs.worker [--concurrency N] [--kinds a,b]`.

Each slot is a thread with two connections of its own: one for the handler's
transaction and one for heartbeats, so a long handler transaction never blocks
its own lease renewal. Slots poll with an idle backoff (0.2s up to
`poll_max_s`), which keeps an idle fleet's query rate low and a busy one's
pickup latency near zero.

SHUTDOWN
--------
SIGTERM (what Cloud Run and Container Apps send) stops claiming. Running jobs
get `grace_s` to finish; anything still running when the process exits keeps
its lease until it expires and is then reclaimed by another worker -- which is
why handlers must be idempotent (see src/jobs/__init__.py).

The same `Worker` runs in-process inside the API when NPR_JOBS_INLINE is true
(local development), so dev and production execute jobs through one code path.
"""

from __future__ import annotations

import argparse
import logging
import os
import signal
import socket
import threading
import time
import traceback
import uuid
from typing import Callable, Sequence

import psycopg
from psycopg.rows import dict_row

from .. import settings
from . import JobContext, LeaseLost, PermanentError, handlers, heavy_kinds, queue

log = logging.getLogger("npr.api.jobs")

ConnFactory = Callable[[], psycopg.Connection]


def _default_connect() -> psycopg.Connection:
    if not settings.DATABASE_URL:
        raise RuntimeError("DATABASE_URL is not set: the worker has no queue to read")
    conn = psycopg.connect(settings.DATABASE_URL, row_factory=dict_row, autocommit=False,
                           connect_timeout=10, application_name="npr-worker")
    conn.execute("SET search_path TO ztpa, public")
    conn.commit()
    return conn


def _close(*conns: psycopg.Connection | None) -> None:
    """Close connections that may already be dead. Closing a broken socket can
    raise; nothing useful can be done about it beyond noting it."""
    for c in conns:
        if c is None:
            continue
        try:
            c.close()
        except (psycopg.Error, OSError) as e:
            log.debug("closing a dead connection raised", extra={"event": "worker_close_failed",
                                                                 "error": str(e)})


class Worker:
    def __init__(self, *, kinds: Sequence[str] | None = None, concurrency: int = 2,
                 lease_s: int = queue.DEFAULT_LEASE_S, poll_max_s: float = 2.0,
                 grace_s: float = 25.0, connect: ConnFactory = _default_connect,
                 worker_id: str | None = None, heavy_concurrency: int | None = None) -> None:
        self.kinds = list(kinds) if kinds else None      # None = every registered kind
        self.concurrency = max(1, concurrency)
        # Memory, not CPU, bounds heavy jobs: one rulebase at the grant limit
        # peaks near 2.4 GiB, so two at once would OOM a 4 GiB worker. Slots
        # beyond this keep taking light jobs.
        self.heavy_concurrency = max(1, heavy_concurrency if heavy_concurrency is not None else
                                     int(os.environ.get("NPR_WORKER_HEAVY_CONCURRENCY", "1")))
        self._heavy_running = 0
        self._claim_lock = threading.Lock()
        self.lease_s = lease_s
        self.poll_max_s = poll_max_s
        self.grace_s = grace_s
        self.connect = connect
        self.worker_id = worker_id or f"{socket.gethostname()}:{os.getpid()}:{uuid.uuid4().hex[:6]}"
        self._stop = threading.Event()
        self._threads: list[threading.Thread] = []
        self.processed = 0
        self._count_lock = threading.Lock()

    # -- lifecycle -----------------------------------------------------------
    def start(self) -> "Worker":
        for i in range(self.concurrency):
            t = threading.Thread(target=self._slot, args=(i,), name=f"job-slot-{i}", daemon=True)
            t.start()
            self._threads.append(t)
        log.info("worker started", extra={"event": "worker_started", "worker": self.worker_id,
                                          "concurrency": self.concurrency,
                                          "kinds": self.kinds or sorted(handlers())})
        return self

    def stop(self, timeout: float | None = None) -> None:
        self._stop.set()
        deadline = time.monotonic() + (self.grace_s if timeout is None else timeout)
        for t in self._threads:
            t.join(max(0.0, deadline - time.monotonic()))
        log.info("worker stopped", extra={"event": "worker_stopped", "worker": self.worker_id,
                                          "processed": self.processed})

    @property
    def stopping(self) -> bool:
        return self._stop.is_set()

    # -- one slot --------------------------------------------------------------
    def _slot(self, index: int) -> None:
        conn = hb = None
        idle = 0.2
        last_reap = 0.0
        while not self._stop.is_set():
            try:
                if conn is None or conn.closed:
                    conn = self.connect()
                if hb is None or hb.closed:
                    hb = self.connect()
                if index == 0 and time.monotonic() - last_reap > self.lease_s:
                    queue.reap(conn)
                    last_reap = time.monotonic()
                job, heavy = self._claim(conn)
                if job is None:
                    self._stop.wait(idle)
                    idle = min(self.poll_max_s, idle * 2)
                    continue
                idle = 0.2
                try:
                    self._run(conn, hb, job)
                finally:
                    if heavy:
                        with self._claim_lock:
                            self._heavy_running -= 1
            except psycopg.OperationalError:
                # Database away (failover, network). Drop both connections and
                # back off; the lease protects any job we were holding.
                log.warning("worker lost its database connection; retrying", exc_info=True,
                            extra={"event": "worker_db_lost", "worker": self.worker_id})
                _close(conn, hb)
                conn = hb = None
                self._stop.wait(min(self.poll_max_s * 2, 5.0))
        _close(conn, hb)

    def _claim(self, conn: psycopg.Connection) -> tuple[queue.Job | None, bool]:
        """Claim under a process-wide lock, leaving heavy kinds out while this
        process already runs its share of them, so two slots cannot both take one."""
        with self._claim_lock:
            kinds = self.kinds or sorted(handlers())
            heavy = heavy_kinds()
            if self._heavy_running >= self.heavy_concurrency:
                kinds = [k for k in kinds if k not in heavy]
            job = queue.claim(conn, self.worker_id, kinds, lease_s=self.lease_s) if kinds else None
            is_heavy = job is not None and job.kind in heavy
            if is_heavy:
                self._heavy_running += 1
            return job, is_heavy

    def _run(self, conn: psycopg.Connection, hb: psycopg.Connection, job: queue.Job) -> None:
        fn = handlers().get(job.kind)
        ctx = JobContext(job=job, conn=conn, worker_id=self.worker_id)
        extra = {"job_id": job.job_id, "kind": job.kind, "attempt": job.attempts,
                 "worker": self.worker_id}
        if fn is None:
            queue.fail(conn, job, self.worker_id, f"no handler registered for kind {job.kind!r}",
                       retryable=True)
            return
        beating = threading.Event()
        beater = threading.Thread(target=self._heartbeat, args=(hb, ctx, beating),
                                  name=f"hb-{job.job_id[:8]}", daemon=True)
        beater.start()
        t0 = time.perf_counter()
        try:
            result = fn(ctx)
            ctx.check()
            if queue.complete(conn, job, self.worker_id, result or {}):
                conn.commit()
                log.info("job succeeded", extra={**extra, "event": "job_succeeded",
                                                 "ms": round((time.perf_counter() - t0) * 1000)})
            else:
                conn.rollback()
                log.warning("job finished after its lease was lost; outcome discarded",
                            extra={**extra, "event": "job_lease_lost"})
        except LeaseLost:
            conn.rollback()
            log.warning("job stopped: lease lost", extra={**extra, "event": "job_lease_lost"})
        except PermanentError as e:
            conn.rollback()
            queue.fail(conn, job, self.worker_id, str(e), retryable=False)
            log.warning("job rejected permanently", extra={**extra, "event": "job_dead",
                                                           "error": str(e)})
        except Exception as e:  # noqa: BLE001 — any handler failure is a retry, recorded
            conn.rollback()
            err = f"{type(e).__name__}: {e}"
            status = queue.fail(conn, job, self.worker_id,
                                err + "\n" + traceback.format_exc(limit=8), retryable=True)
            log.error("job failed", exc_info=True,
                      extra={**extra, "event": "job_failed", "error": err, "next": status})
        finally:
            beating.set()
            beater.join(5)
            with self._count_lock:
                self.processed += 1

    def _heartbeat(self, hb: psycopg.Connection, ctx: JobContext, done: threading.Event) -> None:
        interval = max(1.0, self.lease_s / 3)
        while not done.wait(interval):
            try:
                if not queue.heartbeat(hb, ctx.job, self.worker_id, lease_s=self.lease_s,
                                       progress=ctx.take_progress()):
                    ctx._lost.set()
                    return
            except psycopg.Error:
                # One missed beat is survivable (the lease is 3 intervals long);
                # a database that stays away will expire the lease, which is the
                # correct outcome.
                log.warning("heartbeat failed", exc_info=True,
                            extra={"event": "job_heartbeat_failed", "job_id": ctx.job.job_id})
                try:
                    hb.rollback()
                except psycopg.Error:
                    pass


def _serve_health(port: int, worker: "Worker"):
    """A minimal liveness endpoint for platforms that require a listening port
    (Cloud Run services). 200 while the worker runs, 503 once it is stopping.
    Not readiness: a worker has nothing to be ready FOR beyond running."""
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

    class _Health(BaseHTTPRequestHandler):
        def do_GET(self):  # noqa: N802 — http.server's naming
            ok = not worker.stopping
            body = b'{"status":"ok"}' if ok else b'{"status":"stopping"}'
            self.send_response(200 if ok else 503)
            self.send_header("content-type", "application/json")
            self.send_header("content-length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *_a):                # probes every few seconds; not news
            return

    srv = ThreadingHTTPServer(("0.0.0.0", port), _Health)
    threading.Thread(target=srv.serve_forever, name="worker-health", daemon=True).start()
    return srv


def _register_builtin_handlers() -> None:
    """Import the modules that declare handlers, so a bare worker knows them."""
    from . import builtin  # noqa: F401


def main(argv: Sequence[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Run background jobs from ztpa.jobs.")
    p.add_argument("--concurrency", type=int, default=int(os.environ.get("NPR_WORKER_CONCURRENCY", "2")))
    p.add_argument("--kinds", default=os.environ.get("NPR_WORKER_KINDS", ""),
                   help="comma-separated job kinds (default: all registered)")
    p.add_argument("--lease", type=int, default=int(os.environ.get("NPR_JOB_LEASE_S", "60")))
    p.add_argument("--health-port", type=int,
                   default=int(os.environ.get("NPR_WORKER_HEALTH_PORT", "0") or 0),
                   help="serve GET liveness on this port (Cloud Run needs one); 0 = off")
    args = p.parse_args(argv)
    from ..logjson import configure
    configure()                                    # same JSON lines as the API
    from .. import telemetry
    telemetry.configure()                          # database spans from jobs, same backend
    _register_builtin_handlers()
    w = Worker(kinds=[k for k in args.kinds.split(",") if k] or None,
               concurrency=args.concurrency, lease_s=args.lease).start()
    if args.health_port:
        _serve_health(args.health_port, w)
    stop = threading.Event()
    for sig in (signal.SIGTERM, signal.SIGINT):
        signal.signal(sig, lambda *_: stop.set())
    stop.wait()
    w.stop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
