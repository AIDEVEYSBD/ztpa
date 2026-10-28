"""Export intake end to end against a REAL database: upload through the API, a
worker ingests it, the register is served. Plus every rejection path."""

from __future__ import annotations

import json
import os
import time
from typing import Any, Iterator

import pytest

from tests import cp_fixture as fx
from tests.dbharness import FAIL, SKIP, TEST_DB_ENV, collection_decision


def _probe(url: str) -> str | None:
    try:
        import psycopg
        with psycopg.connect(url, connect_timeout=2) as c:
            c.execute("SELECT 1 FROM ztpa.exports LIMIT 0")
        return None
    except Exception as exc:  # noqa: BLE001
        return f"{type(exc).__name__}: {exc}"


_URL = os.environ.get(TEST_DB_ENV, "").strip()
_DECISION, _REASON = collection_decision(_URL, _probe(_URL) if _URL else None)
if _DECISION == FAIL:
    raise RuntimeError(_REASON)
pytestmark = pytest.mark.skipif(_DECISION == SKIP, reason=_REASON)

ANALYST = {"x-npr-role": "analyst", "x-npr-email": "ada@example.com", "x-npr-sub": "sub-ada"}
VIEWER = {"x-npr-role": "viewer", "x-npr-email": "vic@example.com", "x-npr-sub": "sub-vic"}


def connect():
    import psycopg
    from psycopg.rows import dict_row
    c = psycopg.connect(_URL, row_factory=dict_row, autocommit=False)
    c.execute("SET search_path TO ztpa, public")
    c.commit()
    return c


@pytest.fixture()
def env(monkeypatch: pytest.MonkeyPatch) -> Iterator[Any]:
    """App + one in-process worker against the test database. Every export and
    job the test created is deleted afterwards."""
    from fastapi.testclient import TestClient

    from app.main import app
    from src import db, settings
    from src.jobs import builtin  # noqa: F401
    from src.jobs.worker import Worker

    monkeypatch.setattr(settings, "DATABASE_URL", _URL)
    monkeypatch.setattr(db, "DATABASE_URL", _URL)
    db.close_pool()
    c = connect()
    with c.cursor() as cur:
        cur.execute("SELECT now() AS t")
        started = cur.fetchone()["t"]
    c.commit()
    w = Worker(kinds=["export.ingest"], concurrency=2, connect=connect, lease_s=30).start()
    yield TestClient(app)
    w.stop(timeout=10)
    with c.cursor() as cur:
        cur.execute("DELETE FROM ztpa.exports WHERE uploaded_at >= %s", [started])
        cur.execute("DELETE FROM ztpa.jobs WHERE kind = 'export.ingest' AND created_at >= %s", [started])
    c.commit()
    c.close()
    db.close_pool()


def _upload(client, doc, *, headers=ANALYST, **params) -> Any:
    body = doc if isinstance(doc, (bytes, bytearray)) else json.dumps(doc).encode()
    q = {"source": "checkpoint", "filename": "network-layer.json", **params}
    return client.post("/api/exports", params=q, content=body,
                       headers={**headers, "content-type": "application/json"})


def _settle(client, export_id: str, timeout: float = 20) -> dict:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        row = client.get(f"/api/exports/{export_id}", headers=ANALYST).json()
        if row["status"] != "received":
            return row
        time.sleep(0.1)
    raise AssertionError(f"export {export_id} still received after {timeout}s")


def _fresh(**overrides) -> dict:
    """The fixture, re-dated to now so the age check passes, plus a nonce so
    each test's bytes (and therefore sha256) are distinct."""
    from datetime import datetime, timezone
    e = fx.export(exported_at=datetime.now(timezone.utc).isoformat())
    e["nonce"] = os.urandom(8).hex()
    e.update(overrides)
    return e


def test_upload_ingest_and_review(env) -> None:
    r = _upload(env, _fresh())
    assert r.status_code == 202, r.text
    body = r.json()
    assert body["export"]["status"] == "received" and body["job"]["kind"] == "export.ingest"
    row = _settle(env, body["export"]["export_id"])
    assert row["status"] == "accepted", row
    assert row["summary"]["rules"] == 10 and row["summary"]["nat_rules"] == 2
    assert row["summary"]["review"]["by_check"]["any_any"] == 1
    assert row["uploaded_by"] == "sub-ada"

    rev = env.get(f"/api/exports/{row['export_id']}/review", headers=VIEWER).json()
    assert rev["items"][0]["band"] == "critical"
    crit = env.get(f"/api/exports/{row['export_id']}/review", params={"band": "critical"},
                   headers=VIEWER).json()
    assert {e["number"] for e in crit["items"]} == {1, 5}
    expired = env.get(f"/api/exports/{row['export_id']}/review", params={"check": "expired"},
                      headers=VIEWER).json()
    assert [e["number"] for e in expired["items"]] == [7]


def test_the_same_bytes_are_one_export(env) -> None:
    doc = _fresh()
    first = _upload(env, doc).json()
    second = _upload(env, doc)
    assert second.status_code == 200 and second.json()["duplicate"] is True
    assert second.json()["export"]["export_id"] == first["export"]["export_id"]


@pytest.mark.parametrize("doc, params, reason", [
    (lambda: _fresh(exported_at="2025-01-01T00:00:00Z"), {}, "more than 30 days ago"),
    (lambda: _fresh(exported_at="2099-01-01T00:00:00Z"), {}, "in the future"),
    (lambda: {k: v for k, v in _fresh().items() if k != "exported_at"}, {}, "does not say when"),
    (lambda: b"{not json", {}, "not valid JSON"),
    (lambda: {**_fresh(), "access_layers": [{"name": "x", "objects-dictionary": []}]}, {}, "no 'rulebase'"),
])
def test_rejections_say_why(env, doc, params, reason) -> None:
    r = _upload(env, doc(), **params)
    assert r.status_code == 202
    row = _settle(env, r.json()["export"]["export_id"])
    assert row["status"] == "rejected" and reason in row["rejection_reason"]
    assert env.get(f"/api/exports/{row['export_id']}/review", headers=ANALYST).status_code == 409


def test_a_declared_export_time_is_used_when_the_file_has_none(env) -> None:
    from datetime import datetime, timezone
    doc = {k: v for k, v in _fresh().items() if k != "exported_at"}
    r = _upload(env, doc, exported_at=datetime.now(timezone.utc).isoformat())
    assert _settle(env, r.json()["export"]["export_id"])["status"] == "accepted"


def test_a_tampered_stored_object_is_rejected(env, monkeypatch) -> None:
    from src import storage
    from src.frr import intake

    real_get = storage.LocalStore.get_bytes

    def tampered(self, key):
        data = real_get(self, key)
        return data + b" " if key.endswith("/original") else data

    monkeypatch.setattr(storage.LocalStore, "get_bytes", tampered)
    r = _upload(env, _fresh())
    row = _settle(env, r.json()["export"]["export_id"])
    assert row["status"] == "rejected" and "checksum" in row["rejection_reason"]
    assert intake  # imported for the monkeypatch target's module


def test_roles_and_input_validation(env, monkeypatch) -> None:
    assert _upload(env, _fresh(), headers=VIEWER).status_code == 403
    assert _upload(env, _fresh(), source="paloalto").status_code == 422
    assert _upload(env, _fresh(), filename="../../etc/passwd").status_code == 422
    assert _upload(env, _fresh(), exported_at="yesterday").status_code == 422
    assert _upload(env, b"").status_code == 422
    from app import exports_api
    monkeypatch.setattr(exports_api, "MAX_EXPORT_BYTES", 100)
    assert _upload(env, _fresh()).status_code == 413
    assert env.get("/api/exports/not-a-uuid", headers=ANALYST).status_code == 404


def test_listing_is_newest_first(env) -> None:
    a = _upload(env, _fresh()).json()["export"]["export_id"]
    b = _upload(env, _fresh()).json()["export"]["export_id"]
    items = env.get("/api/exports", params={"limit": 2}, headers=VIEWER).json()["items"]
    assert [i["export_id"] for i in items] == [b, a]
