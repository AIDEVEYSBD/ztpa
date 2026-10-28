"""Request-size caps, field caps and the model-endpoint rate limit (offline:
the in-process counter; the shared counter is covered with a real database
below when NPR_TEST_DATABASE_URL is set)."""

from __future__ import annotations

import os

import pytest
from fastapi.testclient import TestClient

from src import ratelimit, settings

ADMIN = {"x-npr-role": "admin", "x-npr-email": "root@example.com", "x-npr-sub": "sub-root"}


@pytest.fixture()
def client():
    from app.main import app
    ratelimit.reset_local()
    yield TestClient(app)
    ratelimit.reset_local()


def test_an_oversized_body_is_refused_with_413(client, monkeypatch) -> None:
    monkeypatch.setattr(settings, "NPR_MAX_BODY_BYTES", 1000)
    r = client.post("/api/intake", headers=ADMIN, content=b'{"text": "' + b"x" * 2000 + b'"}',
                    )
    assert r.status_code == 413 and r.json()["request_id"]


def test_a_chunked_body_without_content_length_is_still_capped(client, monkeypatch) -> None:
    monkeypatch.setattr(settings, "NPR_MAX_BODY_BYTES", 1000)

    def chunks():
        yield b'{"text": "'
        for _ in range(10):
            yield b"x" * 500
        yield b'"}'

    r = client.post("/api/intake", headers={**ADMIN, "content-type": "application/json"},
                    content=chunks())
    assert r.status_code == 413


def test_field_caps(client) -> None:
    assert client.post("/api/agent/ask", headers=ADMIN, json={"question": "q" * 4001}).status_code == 422
    assert client.post("/api/intake", headers=ADMIN, json={"text": ""}).status_code == 422
    big = {"rows": ["x" * 1000] * 70}
    r = client.post("/api/connectors/propose", headers=ADMIN, json={"sample": big})
    assert r.status_code == 422 and "64 KB" in r.text


def test_model_endpoints_are_rate_limited_per_identity(client, monkeypatch) -> None:
    monkeypatch.setattr(settings, "NPR_RATE_LLM_PER_IDENTITY", 2)
    codes = [client.post("/api/intake", headers=ADMIN, json={"text": "open 443 to web"}).status_code
             for _ in range(3)]
    assert codes[:2] != [429, 429] and codes[2] == 429
    r = client.post("/api/intake", headers=ADMIN, json={"text": "again"})
    assert r.status_code == 429 and int(r.headers["retry-after"]) >= 1
    other = {**ADMIN, "x-npr-sub": "sub-other", "x-npr-email": "other@example.com"}
    assert client.post("/api/intake", headers=other, json={"text": "x"}).status_code != 429


def test_the_deployment_ceiling_applies_across_identities() -> None:
    ratelimit.reset_local()
    now = 1_000_000.0
    a = [ratelimit.hit("b", f"u{i}", per_identity=10, per_deployment=3, now=now).allowed
         for i in range(4)]
    assert a == [True, True, True, False]
    d = ratelimit.hit("b", "u9", per_identity=10, per_deployment=3, now=now)
    assert d.scope == "deployment" and not d.allowed
    assert ratelimit.hit("b", "u9", per_identity=10, per_deployment=3, now=now + 60).allowed


_URL = os.environ.get("NPR_TEST_DATABASE_URL", "").strip()


@pytest.mark.skipif(not _URL, reason="NPR_TEST_DATABASE_URL is not set")
def test_the_shared_counter_is_one_count_for_every_replica(monkeypatch) -> None:
    import uuid

    import psycopg

    from src import db
    monkeypatch.setattr(settings, "DATABASE_URL", _URL)
    monkeypatch.setattr(db, "DATABASE_URL", _URL)
    db.close_pool()
    bucket = f"t{uuid.uuid4().hex[:10]}"
    try:
        now = 2_000_000.0
        results = [ratelimit.hit(bucket, "ada", per_identity=3, per_deployment=100, now=now).allowed
                   for _ in range(4)]
        assert results == [True, True, True, False]
        with psycopg.connect(_URL) as c:
            n = c.execute("SELECT hits FROM ztpa.rate_limits WHERE bucket=%s AND subject='ada'",
                          [bucket]).fetchone()[0]
        assert n == 4
    finally:
        with psycopg.connect(_URL) as c:
            c.execute("DELETE FROM ztpa.rate_limits WHERE bucket=%s", [bucket])
        db.close_pool()
