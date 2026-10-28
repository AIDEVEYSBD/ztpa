"""Published snapshots: signed artifacts, the active pointer, and replicas
converging on it. Real Postgres (NPR_TEST_DATABASE_URL, migration 0010);
storage is the per-test temp directory conftest installs.
"""

from __future__ import annotations

import os
from typing import Any, Iterator

import pytest

from tests.dbharness import FAIL, SKIP, TEST_DB_ENV, collection_decision


def _probe(url: str) -> str | None:
    try:
        import psycopg
        with psycopg.connect(url, connect_timeout=2) as c:
            c.execute("SELECT 1 FROM ztpa.active_snapshot LIMIT 0")
        return None
    except Exception as exc:  # noqa: BLE001
        return f"{type(exc).__name__}: {exc}"


_URL = os.environ.get(TEST_DB_ENV, "").strip()
_DECISION, _REASON = collection_decision(_URL, _probe(_URL) if _URL else None)
if _DECISION == FAIL:
    raise RuntimeError(_REASON)
pytestmark = pytest.mark.skipif(_DECISION == SKIP, reason=_REASON)

from src import snapshot_artifacts as sa, storage  # noqa: E402
from src.analyzers.run_all import run  # noqa: E402


@pytest.fixture(scope="module")
def result():
    return run()


@pytest.fixture()
def conn() -> Iterator[Any]:
    """Rolled back: the pointer table is a singleton, so nothing may survive."""
    import psycopg
    from psycopg.rows import dict_row
    c = psycopg.connect(_URL, row_factory=dict_row, autocommit=False)
    c.execute("SET search_path TO ztpa, public")
    yield c
    c.rollback()
    c.close()


def test_publish_then_load_round_trips(conn, result) -> None:
    with conn.cursor() as cur:
        p1 = sa.publish(cur, result, "demo", published_by="ada@example.com")
        p2 = sa.publish(cur, result, "demo")
        assert p2["generation"] == p1["generation"] + 1
        assert sa.read_pointer(cur)["artifact_key"] == p1["artifact_key"]   # content-addressed
    loaded = sa.load(p2)
    assert loaded.snapshot_id == result.snapshot_id
    assert len(loaded.findings) == len(result.findings)
    assert loaded.graph.number_of_edges() == result.graph.number_of_edges()


def test_a_tampered_artifact_is_never_unpickled(conn, result, monkeypatch) -> None:
    with conn.cursor() as cur:
        p = sa.publish(cur, result, "demo")
    forged = sa._FORMAT + b"anything an attacker with bucket access writes"
    storage.store().put_bytes(p["artifact_key"], forged, "application/octet-stream")
    import hashlib
    p = {**p, "artifact_sha256": hashlib.sha256(forged).hexdigest()}   # attacker fixes the checksum too
    import pickle
    monkeypatch.setattr(pickle, "loads", lambda *_a, **_k: pytest.fail("unpickled an unverified artifact"))
    with pytest.raises(sa.ArtifactError, match="signature"):
        sa.load(p)


def test_a_truncated_download_is_an_error(conn, result) -> None:
    with conn.cursor() as cur:
        p = sa.publish(cur, result, "demo")
    data = storage.store().get_bytes(p["artifact_key"])
    storage.store().put_bytes(p["artifact_key"], data[:-10], "application/octet-stream")
    with pytest.raises(sa.ArtifactError, match="checksum"):
        sa.load(p)


def test_a_different_key_cannot_verify(conn, result, monkeypatch) -> None:
    from src import settings
    with conn.cursor() as cur:
        p = sa.publish(cur, result, "demo")
    monkeypatch.setattr(settings, "NPR_ARTIFACT_KEY", "x" * 40)
    with pytest.raises(sa.ArtifactError, match="signature"):
        sa.load(p)


# --------------------------------------------------------------------------
# replicas converge on the pointer
# --------------------------------------------------------------------------

@pytest.fixture()
def replica(monkeypatch: pytest.MonkeyPatch, conn):
    """`app.main` as one API replica against the test database. The pointer
    write is committed (another replica's publish is a committed fact), so the
    fixture restores whatever pointer was there before."""
    import app.main as m
    from src import db, settings

    with conn.cursor() as cur:
        before = sa.read_pointer(cur)
    monkeypatch.setattr(settings, "DATABASE_URL", _URL)
    monkeypatch.setattr(db, "DATABASE_URL", _URL)
    monkeypatch.setattr(settings, "NPR_SNAPSHOT_POLL_S", 0.0)
    db.close_pool()
    monkeypatch.setattr(m, "_SYNC", {"generation": None, "checked": float("-inf")})
    monkeypatch.setattr(m, "_ENGINE", None)
    monkeypatch.setattr(m, "_ACTIVE_SCENARIO", "demo")
    monkeypatch.setattr(m, "_preload_explanations", lambda *_a: None)
    yield m
    db.close_pool()
    import psycopg
    with psycopg.connect(_URL) as c:
        if before is None:
            c.execute("DELETE FROM ztpa.active_snapshot")
        else:
            c.execute("""UPDATE ztpa.active_snapshot SET snapshot_id=%s, scenario=%s, artifact_key=%s,
                         artifact_sha256=%s, artifact_hmac=%s, artifact_bytes=%s, generation=%s""",
                      [before["snapshot_id"], before["scenario"], before["artifact_key"],
                       before["artifact_sha256"], before["artifact_hmac"],
                       before["artifact_bytes"], before["generation"]])


def _publish_committed(result, scenario: str) -> dict:
    import psycopg
    from psycopg.rows import dict_row
    with psycopg.connect(_URL, row_factory=dict_row) as c, c.cursor() as cur:
        return sa.publish(cur, result, scenario)


def test_a_cold_replica_loads_the_published_snapshot_without_building(replica, result, monkeypatch) -> None:
    _publish_committed(result, "at_scale")
    monkeypatch.setattr(replica, "_run_engine",
                        lambda *_a, **_k: pytest.fail("a replica rebuilt instead of loading"))
    served = replica.engine()
    assert served.snapshot_id == result.snapshot_id
    assert replica._ACTIVE_SCENARIO == "at_scale"


def test_a_running_replica_adopts_a_snapshot_another_replica_published(replica, result) -> None:
    import dataclasses
    stale = dataclasses.replace(result, snapshot_id="snap-stale")
    replica._ENGINE = stale
    pointer = _publish_committed(result, "demo")
    assert replica.engine().snapshot_id == result.snapshot_id
    assert replica._SYNC["generation"] == pointer["generation"]


def test_an_unloadable_artifact_keeps_the_current_snapshot_serving(replica, result) -> None:
    import dataclasses
    current = dataclasses.replace(result, snapshot_id="snap-current")
    replica._ENGINE = current
    p = _publish_committed(result, "demo")
    storage.store().delete(p["artifact_key"])
    assert replica.engine().snapshot_id == "snap-current"
