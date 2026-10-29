"""Multipart export uploads end to end on a real database: parts through the
API, assembled in storage, finalized and ingested by workers."""

from __future__ import annotations

import json
import time

import pytest

from tests.test_frr_intake import (  # noqa: F401  (env is a fixture)
    ANALYST, VIEWER, _fresh, _settle, connect, env, pytestmark,
)

OTHER = {"x-npr-role": "analyst", "x-npr-email": "bob@example.com", "x-npr-sub": "sub-bob"}


@pytest.fixture()
def up(env):
    from src.jobs.worker import Worker
    w = Worker(kinds=["export.finalize"], concurrency=1, connect=connect, lease_s=30).start()
    yield env
    w.stop(timeout=10)
    c = connect()
    with c.cursor() as cur:
        cur.execute("DELETE FROM ztpa.export_uploads WHERE uploaded_by IN ('sub-ada', 'sub-bob')")
        cur.execute("DELETE FROM ztpa.jobs WHERE kind = 'export.finalize'")
    c.commit()
    c.close()


def _upload_in_parts(c, body: bytes, part: int = 7000, headers=ANALYST) -> dict:
    s = c.post("/api/exports/uploads", json={"source": "checkpoint", "filename": "big.json"}, headers=headers)
    assert s.status_code == 201, s.text
    uid = s.json()["upload_id"]
    chunks = [body[i:i + part] for i in range(0, len(body), part)]
    for n in reversed(range(1, len(chunks) + 1)):                   # any order
        r = c.put(f"/api/exports/uploads/{uid}/parts/{n}", content=chunks[n - 1], headers=headers)
        assert r.status_code == 200, r.text
    r = c.post(f"/api/exports/uploads/{uid}/complete", json={"parts": len(chunks)}, headers=headers)
    assert r.status_code == 202, r.text
    for _ in range(200):
        st = c.get(f"/api/exports/uploads/{uid}", headers=headers).json()
        if st["status"] in ("done", "failed"):
            return st
        time.sleep(0.1)
    raise AssertionError("upload not finalized")


def test_a_multipart_upload_becomes_a_reviewed_export(up) -> None:
    body = json.dumps(_fresh()).encode()
    st = _upload_in_parts(up, body)
    assert st["status"] == "done" and st["duplicate"] is False and st["bytes"] == len(body)
    exp = _settle(up, st["export_id"])
    assert exp["status"] == "accepted" and exp["summary"]["rules"] == 10


def test_the_same_bytes_twice_resolve_to_one_export(up) -> None:
    body = json.dumps(_fresh()).encode()
    first = _upload_in_parts(up, body)
    _settle(up, first["export_id"])
    again = _upload_in_parts(up, body, part=9000)
    assert again["duplicate"] is True and again["export_id"] == first["export_id"]


def test_missing_parts_and_oversized_parts_are_refused(up, monkeypatch) -> None:
    c = up
    uid = c.post("/api/exports/uploads", json={"source": "checkpoint"}, headers=ANALYST).json()["upload_id"]
    c.put(f"/api/exports/uploads/{uid}/parts/1", content=b"a" * 10, headers=ANALYST)
    c.put(f"/api/exports/uploads/{uid}/parts/3", content=b"c" * 10, headers=ANALYST)
    r = c.post(f"/api/exports/uploads/{uid}/complete", json={"parts": 3}, headers=ANALYST)
    assert r.status_code == 409 and "missing [2]" in r.text
    from app import uploads_api
    monkeypatch.setattr(uploads_api, "PART_MAX", 5)
    assert c.put(f"/api/exports/uploads/{uid}/parts/2", content=b"b" * 10, headers=ANALYST).status_code == 413


def test_sessions_are_private_and_viewers_cannot_upload(up) -> None:
    c = up
    uid = c.post("/api/exports/uploads", json={"source": "checkpoint"}, headers=ANALYST).json()["upload_id"]
    assert c.get(f"/api/exports/uploads/{uid}", headers=OTHER).status_code == 404
    assert c.put(f"/api/exports/uploads/{uid}/parts/1", content=b"x", headers=OTHER).status_code == 404
    assert c.post("/api/exports/uploads", json={"source": "checkpoint"}, headers=VIEWER).status_code == 403
    assert c.post("/api/exports/uploads", json={"source": "paloalto"}, headers=ANALYST).status_code == 422


def test_a_completed_upload_takes_no_more_parts(up) -> None:
    st = _upload_in_parts(up, json.dumps(_fresh()).encode())
    r = up.put(f"/api/exports/uploads/{st['upload_id']}/parts/1", content=b"x", headers=ANALYST)
    assert r.status_code == 409


def test_an_export_too_large_to_parse_is_rejected_with_advice(up, monkeypatch) -> None:
    from src.frr import intake
    monkeypatch.setattr(intake, "MAX_PARSE_BYTES", 1000)
    st = _upload_in_parts(up, json.dumps(_fresh()).encode())
    exp = _settle(up, st["export_id"])
    assert exp["status"] == "rejected" and "access layer separately" in exp["rejection_reason"]
