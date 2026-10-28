"""Post-deploy smoke test: `python -m src.smoke --api-url https://<internal-api>`.

Runs INSIDE the private network (as a one-off execution of the migrate job's
image, with its command overridden) because the API has no public ingress.
Exit 0 only if all of these hold:

  1. the API answers /api/live over the private network;
  2. the database is reachable and fully migrated (`migrate.py --check`);
  3. a `system.ping` job enqueued now is completed by a worker within the
     timeout -- so at least one worker is running the new image's handlers
     against the same database.

Each check prints one JSON line, so a failed deploy says which link broke.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

import psycopg
from psycopg.rows import dict_row


def _say(check: str, ok: bool, **detail) -> bool:
    print(json.dumps({"event": "smoke", "check": check, "ok": ok, **detail}), flush=True)
    return ok


def _id_token_headers(api_url: str) -> dict:
    """A Google ID token for a Cloud Run API with invoker IAM on, minted as this
    job's service account. Nothing elsewhere (local runs, Container Apps)."""
    if ".run.app" not in api_url:
        return {}
    from google.auth.transport.requests import Request
    from google.oauth2 import id_token
    return {"X-Serverless-Authorization": f"Bearer {id_token.fetch_id_token(Request(), api_url.rstrip('/'))}"}


def check_api(api_url: str) -> bool:
    try:
        req = urllib.request.Request(f"{api_url.rstrip('/')}/api/live", headers=_id_token_headers(api_url))
        with urllib.request.urlopen(req, timeout=10) as r:
            return _say("api_live", r.status == 200, status=r.status)
    except Exception as e:  # noqa: BLE001 — any failure is a failed check, reported as one
        return _say("api_live", False, error=f"{type(e).__name__}: {e}")


def check_migrations() -> bool:
    migrate = Path(__file__).resolve().parents[2] / "db" / "migrate.py"
    r = subprocess.run([sys.executable, str(migrate), "--check"], capture_output=True, text=True,
                       timeout=60)
    return _say("migrations_current", r.returncode == 0, output=r.stdout.strip()[-400:])


def check_worker(timeout_s: float) -> bool:
    from .jobs import queue

    url = os.environ.get("DATABASE_URL", "")
    if not url:
        return _say("worker_roundtrip", False, error="DATABASE_URL is not set")
    with psycopg.connect(url, row_factory=dict_row, connect_timeout=10) as conn:
        job, _ = queue.enqueue(conn, "system.ping", {"echo": "smoke"}, priority=0,
                               max_attempts=1, created_by="smoke")
        conn.commit()
        deadline = time.monotonic() + timeout_s
        while time.monotonic() < deadline:
            current = queue.get(conn, job.job_id)
            conn.commit()
            if current and current.status in ("succeeded", "dead"):
                return _say("worker_roundtrip", current.status == "succeeded",
                            job_id=job.job_id, status=current.status,
                            worker=(current.result or {}).get("worker"))
            time.sleep(1)
        return _say("worker_roundtrip", False, job_id=job.job_id,
                    error=f"no worker completed the job within {timeout_s:.0f}s")


def main(argv=None) -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--api-url", required=True)
    p.add_argument("--worker-timeout", type=float, default=120.0)
    a = p.parse_args(argv)
    results = [check_api(a.api_url), check_migrations(), check_worker(a.worker_timeout)]
    return 0 if all(results) else 1


if __name__ == "__main__":
    raise SystemExit(main())
