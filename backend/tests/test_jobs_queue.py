"""The Postgres job queue, against a REAL database.

Concurrency properties (SKIP LOCKED, leases, exactly-one outcome) cannot be
proved against a fake, so this file needs NPR_TEST_DATABASE_URL with migration
0009 applied, and skips without it (fails loudly if it was asked for and is
unreachable, like the other real-DB suites).

Unlike test_db_governance.py these tests COMMIT -- the queue's protocol is
commits -- so every test uses its own random job kinds and deletes them after.
"""

from __future__ import annotations

import os
import threading
import time
import uuid
from typing import Any, Iterator

import pytest

from tests.dbharness import FAIL, SKIP, TEST_DB_ENV, collection_decision


def _probe(url: str) -> str | None:
    try:
        import psycopg
        with psycopg.connect(url, connect_timeout=2) as c:
            c.execute("SELECT 1 FROM ztpa.jobs LIMIT 0")
        return None
    except Exception as exc:  # noqa: BLE001
        return f"{type(exc).__name__}: {exc}"


_URL = os.environ.get(TEST_DB_ENV, "").strip()
_DECISION, _REASON = collection_decision(_URL, _probe(_URL) if _URL else None)
if _DECISION == FAIL:
    raise RuntimeError(_REASON)
pytestmark = pytest.mark.skipif(_DECISION == SKIP, reason=_REASON)

from src import jobs  # noqa: E402
from src.jobs import JobContext, PermanentError, queue  # noqa: E402
from src.jobs.worker import Worker  # noqa: E402


def connect():
    import psycopg
    from psycopg.rows import dict_row
    c = psycopg.connect(_URL, row_factory=dict_row, autocommit=False)
    c.execute("SET search_path TO ztpa, public")
    c.commit()
    return c


@pytest.fixture()
def conn() -> Iterator[Any]:
    c = connect()
    yield c
    c.close()


@pytest.fixture()
def kind(conn) -> Iterator[str]:
    """A job kind unique to this test, cleaned up after."""
    k = f"t{uuid.uuid4().hex[:12]}"
    yield k
    conn.rollback()
    with conn.cursor() as cur:
        cur.execute("DELETE FROM ztpa.jobs WHERE kind LIKE %s", [k + "%"])
    conn.commit()
    for name in list(jobs.handlers()):
        if name.startswith(k):
            jobs.unregister(name)


def _enqueue(conn, kind: str, **kw) -> queue.Job:
    job, _ = queue.enqueue(conn, kind, **kw)
    conn.commit()
    return job


def test_enqueue_claim_complete(conn, kind) -> None:
    job = _enqueue(conn, kind, payload={"n": 1}, created_by="ada@example.com")
    claimed = queue.claim(conn, "w1", [kind])
    assert claimed and claimed.job_id == job.job_id and claimed.attempts == 1
    assert claimed.status == "running" and claimed.locked_by == "w1"
    assert queue.claim(conn, "w2", [kind]) is None            # nothing else runnable
    assert queue.complete(conn, claimed, "w1", {"ok": True})
    conn.commit()
    done = queue.get(conn, job.job_id)
    assert done.status == "succeeded" and done.result == {"ok": True} and done.finished_at
    assert done.public()["created_by"] == "ada@example.com"


def test_an_idempotency_key_enqueues_once(conn, kind) -> None:
    a, created_a = queue.enqueue(conn, kind, idempotency_key=f"{kind}:sha")
    b, created_b = queue.enqueue(conn, kind, idempotency_key=f"{kind}:sha")
    conn.commit()
    assert created_a and not created_b and a.job_id == b.job_id


def test_a_delayed_job_is_not_claimed_early(conn, kind) -> None:
    _enqueue(conn, kind, delay_s=3600)
    assert queue.claim(conn, "w", [kind]) is None


def test_priority_orders_the_claim(conn, kind) -> None:
    low = _enqueue(conn, kind, priority=200)
    high = _enqueue(conn, kind, priority=10)
    assert queue.claim(conn, "w", [kind]).job_id == high.job_id
    assert queue.claim(conn, "w", [kind]).job_id == low.job_id


def test_concurrent_claimers_never_take_the_same_job(kind) -> None:
    n_jobs, n_workers = 120, 8
    c = connect()
    for i in range(n_jobs):
        queue.enqueue(c, kind, {"i": i})
    c.commit()
    taken: list[str] = []
    lock = threading.Lock()

    def drain(wid: str) -> None:
        wc = connect()
        while (job := queue.claim(wc, wid, [kind])) is not None:
            with lock:
                taken.append(job.job_id)
            queue.complete(wc, job, wid, {})
            wc.commit()
        wc.close()

    threads = [threading.Thread(target=drain, args=(f"w{i}",)) for i in range(n_workers)]
    [t.start() for t in threads]
    [t.join(60) for t in threads]
    assert len(taken) == n_jobs and len(set(taken)) == n_jobs
    with c.cursor() as cur:
        cur.execute("SELECT count(*) AS n FROM ztpa.jobs WHERE kind=%s AND status='succeeded'", [kind])
        assert cur.fetchone()["n"] == n_jobs
    c.close()


def test_an_expired_lease_is_reclaimed_and_the_old_owner_cannot_record(conn, kind) -> None:
    _enqueue(conn, kind)
    first = queue.claim(conn, "dead-worker", [kind], lease_s=1)
    time.sleep(1.3)
    second = queue.claim(conn, "live-worker", [kind], lease_s=60)
    assert second and second.job_id == first.job_id and second.attempts == 2
    assert queue.complete(conn, first, "dead-worker", {"late": True}) is False
    conn.rollback()
    assert queue.heartbeat(conn, first, "dead-worker") is False
    assert queue.complete(conn, second, "live-worker", {"ok": True})
    conn.commit()
    assert queue.get(conn, first.job_id).result == {"ok": True}


def test_heartbeat_extends_the_lease_and_records_progress(conn, kind) -> None:
    _enqueue(conn, kind)
    job = queue.claim(conn, "w", [kind], lease_s=1)
    assert queue.heartbeat(conn, job, "w", lease_s=60, progress={"rules": 500})
    time.sleep(1.2)
    assert queue.claim(conn, "thief", [kind]) is None          # lease was extended
    assert queue.get(conn, job.job_id).progress == {"rules": 500}


def test_failures_back_off_then_die_at_max_attempts(conn, kind) -> None:
    job = _enqueue(conn, kind, max_attempts=2)
    a1 = queue.claim(conn, "w", [kind])
    assert queue.fail(conn, a1, "w", "boom 1") == "queued"
    row = queue.get(conn, job.job_id)
    assert row.status == "queued" and row.last_error == "boom 1"
    assert queue.claim(conn, "w", [kind]) is None              # still backing off
    with conn.cursor() as cur:
        cur.execute("UPDATE ztpa.jobs SET run_after = now() WHERE job_id = %s", [job.job_id])
    conn.commit()
    a2 = queue.claim(conn, "w", [kind])
    assert a2.attempts == 2
    assert queue.fail(conn, a2, "w", "boom 2") == "dead"
    assert queue.get(conn, job.job_id).status == "dead"


def test_a_permanent_failure_skips_the_retries(conn, kind) -> None:
    job = _enqueue(conn, kind, max_attempts=5)
    assert queue.fail(conn, queue.claim(conn, "w", [kind]), "w", "bad export",
                      retryable=False) == "dead"
    assert queue.get(conn, job.job_id).attempts == 1


def test_reap_kills_a_lost_job_on_its_last_attempt(conn, kind) -> None:
    job = _enqueue(conn, kind, max_attempts=1)
    queue.claim(conn, "w", [kind], lease_s=1)
    time.sleep(1.3)
    assert queue.claim(conn, "other", [kind]) is None          # no attempts left to give
    assert queue.reap(conn) >= 1
    row = queue.get(conn, job.job_id)
    assert row.status == "dead" and "lease expired" in row.last_error


def test_cancel_only_touches_queued_jobs(conn, kind) -> None:
    q = _enqueue(conn, kind)
    assert queue.cancel(conn, q.job_id)
    r = _enqueue(conn, kind)
    queue.claim(conn, "w", [kind])
    assert queue.cancel(conn, r.job_id) is False


def test_get_with_a_malformed_id_is_none(conn) -> None:
    assert queue.get(conn, "not-a-uuid") is None


def test_stats_report_depth_per_kind(conn, kind) -> None:
    _enqueue(conn, kind)
    _enqueue(conn, kind, delay_s=600)
    s = queue.stats(conn)[kind]
    assert s["ready"] == 1 and s["delayed"] == 1 and s["oldest_ready_s"] >= 0


def _wait(conn, kind: str, n: int, statuses=("succeeded", "dead"), timeout: float = 30) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        with conn.cursor() as cur:
            cur.execute("SELECT count(*) AS n FROM ztpa.jobs WHERE kind=%s AND status = ANY(%s)",
                        [kind, list(statuses)])
            got = cur.fetchone()["n"]
        conn.commit()
        if got >= n:
            return
        time.sleep(0.1)
    raise AssertionError(f"only {got}/{n} {kind} jobs finished")


def test_the_worker_runs_handlers_and_records_outcomes(conn, kind) -> None:
    seen: list[int] = []
    lock = threading.Lock()

    @jobs.handler(kind)
    def work(ctx: JobContext) -> dict:
        ctx.progress(step="half")
        with lock:
            seen.append(ctx.payload["i"])
        if ctx.payload["i"] == 3:
            raise PermanentError("input 3 is malformed")
        return {"double": ctx.payload["i"] * 2}

    for i in range(40):
        queue.enqueue(conn, kind, {"i": i})
    conn.commit()
    w = Worker(kinds=[kind], concurrency=4, connect=connect, lease_s=30).start()
    try:
        _wait(conn, kind, 40)
    finally:
        w.stop(timeout=10)
    assert sorted(seen) == list(range(40))                     # each ran exactly once
    with conn.cursor() as cur:
        cur.execute("SELECT payload->>'i' AS i, status, result, last_error FROM ztpa.jobs "
                    "WHERE kind=%s", [kind])
        rows = {int(r["i"]): r for r in cur.fetchall()}
    assert rows[3]["status"] == "dead" and "malformed" in rows[3]["last_error"]
    assert rows[7]["status"] == "succeeded" and rows[7]["result"] == {"double": 14}


def test_a_handler_exception_is_retried_by_the_worker(conn, kind) -> None:
    calls = []

    @jobs.handler(kind)
    def flaky(ctx: JobContext) -> dict:
        calls.append(ctx.job.attempts)
        if ctx.job.attempts == 1:
            raise ConnectionError("downstream blip")
        return {"ok": True}

    job = _enqueue(conn, kind)
    w = Worker(kinds=[kind], concurrency=1, connect=connect, lease_s=30).start()
    try:
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline and queue.get(conn, job.job_id).status != "queued":
            conn.commit(); time.sleep(0.05)
        with conn.cursor() as cur:                              # skip the backoff wait
            cur.execute("UPDATE ztpa.jobs SET run_after = now() WHERE job_id=%s", [job.job_id])
        conn.commit()
        _wait(conn, kind, 1)
    finally:
        w.stop(timeout=10)
    assert calls == [1, 2] and queue.get(conn, job.job_id).status == "succeeded"


def test_the_builtin_ping_handler_is_registered() -> None:
    from src.jobs import builtin  # noqa: F401
    assert "system.ping" in jobs.handlers()


# --------------------------------------------------------------------------
# HTTP surface
# --------------------------------------------------------------------------

@pytest.fixture()
def api(monkeypatch: pytest.MonkeyPatch):
    """The real app against the test database. No `with TestClient(...)`, so the
    lifespan (engine warm-up, inline worker) does not run."""
    from fastapi.testclient import TestClient

    from app.main import app
    from src import db, settings

    monkeypatch.setattr(settings, "DATABASE_URL", _URL)
    monkeypatch.setattr(db, "DATABASE_URL", _URL)       # db binds it at import
    db.close_pool()
    yield TestClient(app)
    db.close_pool()


ADA = {"x-npr-role": "analyst", "x-npr-email": "ada@example.com", "x-npr-sub": "sub-ada"}
BOB = {"x-npr-role": "analyst", "x-npr-email": "bob@example.com", "x-npr-sub": "sub-bob"}
ADMIN = {"x-npr-role": "admin", "x-npr-email": "root@example.com", "x-npr-sub": "sub-root"}


def test_a_job_is_visible_to_its_creator_and_admins_only(api, conn, kind) -> None:
    job = _enqueue(conn, kind, created_by="sub-ada")
    assert api.get(f"/api/jobs/{job.job_id}", headers=ADA).json()["status"] == "queued"
    assert api.get(f"/api/jobs/{job.job_id}", headers=ADMIN).status_code == 200
    assert api.get(f"/api/jobs/{job.job_id}", headers=BOB).status_code == 404
    assert api.get("/api/jobs/not-a-uuid", headers=ADA).status_code == 404
    body = api.get(f"/api/jobs/{job.job_id}", headers=ADA).json()
    assert "locked_by" not in body and "payload" not in body


def test_cancel_through_the_api(api, conn, kind) -> None:
    job = _enqueue(conn, kind, created_by="sub-ada")
    assert api.post(f"/api/jobs/{job.job_id}/cancel", headers=BOB).status_code == 404
    assert api.post(f"/api/jobs/{job.job_id}/cancel", headers=ADA).json()["status"] == "cancelled"
    assert api.post(f"/api/jobs/{job.job_id}/cancel", headers=ADA).status_code == 409


def test_stats_and_ping_are_admin_only(api, conn) -> None:
    assert api.get("/api/admin/jobs/stats", headers=ADA).status_code == 403
    assert api.post("/api/admin/jobs/ping", headers=ADA).status_code == 403
    r = api.post("/api/admin/jobs/ping", headers=ADMIN)
    assert r.status_code == 202 and r.json()["kind"] == "system.ping"
    job_id = r.json()["job_id"]
    assert "system.ping" in api.get("/api/admin/jobs/stats", headers=ADMIN).json()["kinds"]
    with conn.cursor() as cur:
        cur.execute("DELETE FROM ztpa.jobs WHERE job_id = %s", [job_id])
    conn.commit()


def test_worker_health_endpoint_reflects_stopping() -> None:
    import socket
    import urllib.error
    import urllib.request

    from src.jobs.worker import _serve_health

    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
    w = Worker(kinds=["unused"], connect=connect)
    srv = _serve_health(port, w)
    try:
        with urllib.request.urlopen(f"http://127.0.0.1:{port}/", timeout=3) as r:
            assert r.status == 200
        w._stop.set()
        with pytest.raises(urllib.error.HTTPError) as e:
            urllib.request.urlopen(f"http://127.0.0.1:{port}/", timeout=3)
        e.value.close()
        assert e.value.code == 503
    finally:
        srv.shutdown()
        srv.server_close()


def test_smoke_passes_against_a_live_api_and_worker(monkeypatch, capsys) -> None:
    """The post-deploy smoke test, end to end: a real HTTP liveness endpoint,
    the migration check and a worker completing the ping."""
    import socket
    import urllib.error

    from src import smoke
    from src.jobs import builtin  # noqa: F401
    from src.jobs.worker import _serve_health

    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
    w = Worker(kinds=["system.ping"], concurrency=1, connect=connect)
    srv = _serve_health(port, w)            # stands in for the API's /api/live
    import http.server

    class Live(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200 if self.path == "/api/live" else 404)
            self.end_headers()

        def log_message(self, *_a):
            return

    srv.RequestHandlerClass = Live
    monkeypatch.setenv("DATABASE_URL", _URL)
    w.start()
    try:
        assert smoke.main(["--api-url", f"http://127.0.0.1:{port}", "--worker-timeout", "20"]) == 0
    finally:
        w.stop(timeout=10)
        srv.shutdown()
        srv.server_close()
    out = capsys.readouterr().out
    assert out.count('"ok": true') == 3


def test_smoke_fails_when_no_worker_is_running(monkeypatch) -> None:
    from src import smoke
    monkeypatch.setenv("DATABASE_URL", _URL)
    assert smoke.check_worker(timeout_s=2) is False
    with connect() as c, c.cursor() as cur:            # leave no orphan ping behind
        cur.execute("DELETE FROM ztpa.jobs WHERE created_by = 'smoke' AND status = 'queued'")
        c.commit()
