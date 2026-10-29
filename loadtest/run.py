"""Load test for the API and the intake pipeline.

    python loadtest/run.py --base http://127.0.0.1:8000 --duration 60 --concurrency 64
    python loadtest/run.py --base https://<internal-api> --proxy-secret "$NPR_PROXY_SECRET" ...

Two phases:
  1. INGEST BURST -- uploads --exports distinct Check Point exports at once and
     waits until every one is accepted: worker throughput and end-to-end latency.
  2. READ MIX -- --concurrency virtual users for --duration seconds over the
     screens people actually load (register pages, export list, change package,
     console findings, health): requests/s and p50/p95/p99 per endpoint.

Exit 1 if a threshold fails (p95 per endpoint, error rate, ingest time), so the
same script gates a release in CI against a staging environment.
Uses only httpx (already a backend dependency) and the backend's own fixture.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import random
import statistics
import sys
import time
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

import httpx

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "backend"))
from tests import cp_fixture as fx  # noqa: E402

ANALYST = {"x-npr-role": "analyst", "x-npr-email": "load@example.com", "x-npr-sub": "sub-load"}


def headers(secret: str | None, cookie: str | None = None) -> dict:
    """Direct-to-API identity headers, or -- through the frontend -- a signed-in
    session cookie (the frontend strips x-npr-* and sets its own)."""
    if cookie:
        return {"cookie": cookie}
    return {**ANALYST, **({"x-npr-proxy-secret": secret} if secret else {})}


def pct(xs: list[float], p: float) -> float:
    if not xs:
        return 0.0
    xs = sorted(xs)
    return xs[min(len(xs) - 1, int(round(p / 100 * (len(xs) - 1))))]


async def ingest_burst(client: httpx.AsyncClient, n: int, h: dict, timeout: float) -> dict:
    async def one(i: int) -> tuple[str, float]:
        doc = fx.export(exported_at=datetime.now(timezone.utc).isoformat())
        doc["nonce"] = f"{time.time_ns()}-{i}-{random.random()}"
        t0 = time.perf_counter()
        r = await client.post("/api/exports", params={"source": "checkpoint", "filename": f"load-{i}.json"},
                              content=json.dumps(doc).encode(), headers={**h, "content-type": "application/json"})
        r.raise_for_status()
        return r.json()["export"]["export_id"], t0

    t0 = time.perf_counter()
    started = await asyncio.gather(*(one(i) for i in range(n)))
    upload_s = time.perf_counter() - t0
    pending = {eid: ts for eid, ts in started}
    done: dict[str, float] = {}
    statuses: dict[str, int] = defaultdict(int)
    deadline = time.perf_counter() + timeout
    while pending and time.perf_counter() < deadline:
        for eid in list(pending):
            r = await client.get(f"/api/exports/{eid}", headers=h)
            st = r.json().get("status")
            if st in ("accepted", "rejected"):
                done[eid] = time.perf_counter() - pending.pop(eid)
                statuses[st] += 1
        await asyncio.sleep(0.25)
    total = time.perf_counter() - t0
    return {"exports": n, "upload_seconds": round(upload_s, 2), "all_done_seconds": round(total, 2),
            "per_export_p50_s": round(statistics.median(done.values()), 2) if done else None,
            "per_export_max_s": round(max(done.values()), 2) if done else None,
            "throughput_per_min": round(len(done) / total * 60, 1) if total else 0,
            "statuses": dict(statuses), "timed_out": len(pending), "export_ids": list(done)}


async def read_mix(client: httpx.AsyncClient, export_ids: list[str], package_id: str | None,
                   h: dict, concurrency: int, duration: float, raw: bool = False) -> dict:
    lat: dict[str, list[float]] = defaultdict(list)
    errors: dict[str, int] = defaultdict(int)
    stop = time.perf_counter() + duration

    def pick() -> tuple[str, str]:
        eid = random.choice(export_ids)
        roll = random.random()
        if roll < 0.40:
            return "review", f"/api/exports/{eid}/review?limit=100&offset={random.choice([0, 100])}"
        if roll < 0.55:
            return "export", f"/api/exports/{eid}"
        if roll < 0.70:
            return "exports_list", "/api/exports?limit=50"
        if roll < 0.80 and package_id:
            return "package", f"/api/change-packages/{package_id}"
        if roll < 0.92:
            return "findings", "/api/findings?limit=50"
        return "live", "/api/live"

    async def user() -> None:
        while time.perf_counter() < stop:
            name, path = pick()
            t0 = time.perf_counter()
            try:
                r = await client.get(path, headers=h)
                ok = r.status_code < 500 and r.status_code != 429
            except httpx.HTTPError:
                ok = False
            lat[name].append((time.perf_counter() - t0) * 1000)
            if not ok:
                errors[name] += 1

    t0 = time.perf_counter()
    await asyncio.gather(*(user() for _ in range(concurrency)))
    wall = time.perf_counter() - t0
    if raw:
        return {"lat": dict(lat), "errors": dict(errors), "wall": wall}
    return summarise(lat, errors, wall, concurrency)


def summarise(lat: dict, errors: dict, wall: float, concurrency: int) -> dict:
    total = sum(len(v) for v in lat.values())
    return {"concurrency": concurrency, "seconds": round(wall, 1), "requests": total,
            "rps": round(total / wall, 1), "errors": dict(errors),
            "error_rate": round(sum(errors.values()) / max(1, total), 4),
            "endpoints": {k: {"n": len(v), "p50_ms": round(pct(v, 50), 1), "p95_ms": round(pct(v, 95), 1),
                              "p99_ms": round(pct(v, 99), 1)} for k, v in sorted(lat.items())}}


def _worker_proc(args: tuple) -> dict:
    """One load-generator process: its own event loop and connection pool, so
    the generator is not the bottleneck it is measuring."""
    base, ids, pkg, h, conc, duration = args

    async def go():
        limits = httpx.Limits(max_connections=conc + 4, max_keepalive_connections=conc + 4)
        async with httpx.AsyncClient(base_url=base, timeout=30, limits=limits) as c:
            return await read_mix(c, ids, pkg, h, conc, duration, raw=True)
    return asyncio.run(go())


def read_mix_parallel(base, ids, pkg, h, concurrency, duration, processes) -> dict:
    from concurrent.futures import ProcessPoolExecutor
    per = max(1, concurrency // processes)
    with ProcessPoolExecutor(processes) as ex:
        parts = list(ex.map(_worker_proc, [(base, ids, pkg, h, per, duration)] * processes))
    lat: dict[str, list[float]] = defaultdict(list)
    errors: dict[str, int] = defaultdict(int)
    for p in parts:
        for k, v in p["lat"].items():
            lat[k] += v
        for k, v in p["errors"].items():
            errors[k] += v
    return summarise(lat, errors, max(p["wall"] for p in parts), per * processes)


async def main_async(a) -> int:
    h = headers(a.proxy_secret, a.cookie)
    limits = httpx.Limits(max_connections=a.concurrency + 16, max_keepalive_connections=a.concurrency + 16)
    async with httpx.AsyncClient(base_url=a.base, timeout=30, limits=limits) as client:
        ingest = await ingest_burst(client, a.exports, h, a.ingest_timeout)
        ids = ingest.pop("export_ids")
        pkg = None
        if ids:
            r = await client.post(f"/api/exports/{ids[0]}/change-package", params={"supersede": "true"}, headers=h)
            pkg = r.json().get("package_id") if r.status_code == 201 else None
    if not ids:
        reads = {}
    elif a.processes > 1:
        reads = read_mix_parallel(a.base, ids, pkg, h, a.concurrency, a.duration, a.processes)
    else:
        async with httpx.AsyncClient(base_url=a.base, timeout=30, limits=limits) as client:
            reads = await read_mix(client, ids, pkg, h, a.concurrency, a.duration)
    fails = []
    if ingest["timed_out"]:
        fails.append(f"{ingest['timed_out']} exports not processed within {a.ingest_timeout}s")
    if reads:
        if reads["error_rate"] > a.max_error_rate:
            fails.append(f"error rate {reads['error_rate']} > {a.max_error_rate}")
        for k, v in reads["endpoints"].items():
            if v["p95_ms"] > a.max_p95_ms:
                fails.append(f"{k} p95 {v['p95_ms']} ms > {a.max_p95_ms}")
    print(json.dumps({"ingest": ingest, "reads": reads, "thresholds": {
        "max_p95_ms": a.max_p95_ms, "max_error_rate": a.max_error_rate,
        "ingest_timeout_s": a.ingest_timeout}, "failures": fails}, indent=2))
    return 1 if fails else 0


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", default="http://127.0.0.1:8000")
    ap.add_argument("--proxy-secret", default=os.environ.get("NPR_PROXY_SECRET"))
    ap.add_argument("--cookie", default=os.environ.get("NPR_LOADTEST_COOKIE"),
                    help="session cookie header, to test through the frontend as a signed-in user")
    ap.add_argument("--exports", type=int, default=20)
    ap.add_argument("--concurrency", type=int, default=64)
    ap.add_argument("--duration", type=float, default=60)
    ap.add_argument("--processes", type=int, default=4,
                    help="load-generator processes (one event loop each)")
    ap.add_argument("--ingest-timeout", type=float, default=180)
    ap.add_argument("--max-p95-ms", type=float, default=500)
    ap.add_argument("--max-error-rate", type=float, default=0.005)
    return asyncio.run(main_async(ap.parse_args()))


if __name__ == "__main__":
    raise SystemExit(main())
