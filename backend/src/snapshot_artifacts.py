"""Published engine artifacts: how every API replica serves the same snapshot
without rebuilding it.

`publish()` serialises an `EngineResult`, signs it, stores it under
`snapshots/<snapshot_id>/<sha256>.engine`, and points `ztpa.active_snapshot`
at it -- on the caller's cursor, so the pointer moves in the same transaction
as the snapshot's rows. `load()` fetches, verifies and deserialises.

WHY PICKLE, AND WHY IT IS SAFE HERE
-----------------------------------
The result holds dataclasses and a networkx graph; pickle round-trips them
exactly, and at 2,000 assets loads in ~0.1s against a ~2s rebuild (measured).
Pickle executes code on load, so an artifact is only ever loaded after its
HMAC-SHA256 verifies under `NPR_ARTIFACT_KEY`, a secret the bucket does not
hold. Write access to storage alone therefore cannot make a replica run code.
The sha256 is checked too, so a truncated download is an error, not a crash.
"""

from __future__ import annotations

import hashlib
import hmac
import logging
import pickle
import zlib
from typing import Any

import psycopg

from . import settings, storage

log = logging.getLogger("npr.api.snapshots")

_PREFIX = "snapshots"
_FORMAT = b"NPRENG1\n"                    # bump on an incompatible layout change


class ArtifactError(RuntimeError):
    pass


def _key() -> bytes:
    return settings.artifact_key().encode()


def serialise(result: Any) -> bytes:
    return _FORMAT + zlib.compress(pickle.dumps(result, protocol=5), 6)


def sign(data: bytes) -> str:
    return hmac.new(_key(), data, hashlib.sha256).hexdigest()


def publish(cur: psycopg.Cursor, result: Any, scenario: str, *,
            published_by: str | None = None) -> dict[str, Any]:
    """Store the artifact, then move the pointer on `cur` (uncommitted). A
    storage failure raises, so the caller's transaction -- the snapshot rows --
    rolls back with it and no replica is pointed at an artifact that is missing."""
    data = serialise(result)
    digest = hashlib.sha256(data).hexdigest()
    key = f"{_PREFIX}/{result.snapshot_id}/{digest}.engine"
    # Always written, even though the key is content-addressed: an `exists`
    # shortcut would leave a corrupted or half-written object at this key in
    # place forever, and every replica would then fail to load it.
    storage.store().put_bytes(key, data, "application/octet-stream")
    cur.execute(
        """INSERT INTO ztpa.active_snapshot
               (id, snapshot_id, scenario, artifact_key, artifact_sha256, artifact_hmac,
                artifact_bytes, generation, published_at, published_by)
           VALUES (true, %s, %s, %s, %s, %s, %s, 1, now(), %s)
           ON CONFLICT (id) DO UPDATE SET
               snapshot_id = EXCLUDED.snapshot_id, scenario = EXCLUDED.scenario,
               artifact_key = EXCLUDED.artifact_key, artifact_sha256 = EXCLUDED.artifact_sha256,
               artifact_hmac = EXCLUDED.artifact_hmac, artifact_bytes = EXCLUDED.artifact_bytes,
               generation = ztpa.active_snapshot.generation + 1,
               published_at = now(), published_by = EXCLUDED.published_by
           RETURNING snapshot_id, scenario, artifact_key, artifact_sha256, artifact_hmac,
                     artifact_bytes, generation""",
        [result.snapshot_id, scenario, key, digest, sign(data), len(data), published_by])
    pointer = dict(cur.fetchone() or {})           # dict rows everywhere (src/db.py)
    log.info("snapshot artifact published", extra={
        "event": "snapshot_published", "snapshot_id": result.snapshot_id, "scenario": scenario,
        "bytes": len(data), "generation": pointer.get("generation")})
    return pointer


def read_pointer(cur: psycopg.Cursor) -> dict[str, Any] | None:
    try:
        cur.execute("""SELECT snapshot_id, scenario, artifact_key, artifact_sha256, artifact_hmac,
                              artifact_bytes, generation FROM ztpa.active_snapshot""")
    except psycopg.errors.UndefinedTable:
        # Migration 0010 not applied yet: behave as before it existed.
        cur.connection.rollback()
        return None
    row = cur.fetchone()
    return dict(row) if row else None


def load(pointer: dict[str, Any]) -> Any:
    data = storage.store().get_bytes(pointer["artifact_key"])
    if hashlib.sha256(data).hexdigest() != pointer["artifact_sha256"]:
        raise ArtifactError(f"artifact {pointer['artifact_key']} does not match its checksum")
    if not hmac.compare_digest(sign(data), pointer["artifact_hmac"]):
        raise ArtifactError(f"artifact {pointer['artifact_key']} failed signature verification; "
                            "refusing to load it")
    if not data.startswith(_FORMAT):
        raise ArtifactError(f"artifact {pointer['artifact_key']} has an unknown format")
    return pickle.loads(zlib.decompress(data[len(_FORMAT):]))  # noqa: S301 — HMAC-verified above
