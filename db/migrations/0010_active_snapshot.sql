-- 0010 — the active-snapshot pointer
--
-- Which analysis every API replica should be serving. Before this, "the active
-- snapshot" was a variable in one process's memory, so two replicas could serve
-- two different estates and a restart forgot an operator's dataset switch.
--
-- One row. Publishing a snapshot writes its engine artifact to object storage
-- (backend/src/snapshot_artifacts.py) and then bumps `generation` here in the
-- same transaction as the snapshot's rows. Replicas poll this row and load the
-- artifact when the generation moves, instead of rebuilding the engine.

SET search_path TO ztpa, public;

CREATE TABLE IF NOT EXISTS ztpa.active_snapshot (
    id              boolean PRIMARY KEY DEFAULT true CHECK (id),
    snapshot_id     text NOT NULL,
    scenario        text NOT NULL,
    artifact_key    text NOT NULL,
    artifact_sha256 text NOT NULL CHECK (artifact_sha256 ~ '^[0-9a-f]{64}$'),
    -- HMAC-SHA256 of the artifact bytes under NPR_ARTIFACT_KEY. The artifact is
    -- a pickle; it is loaded only after this verifies, so write access to the
    -- bucket alone cannot make a replica execute code.
    artifact_hmac   text NOT NULL CHECK (artifact_hmac ~ '^[0-9a-f]{64}$'),
    artifact_bytes  bigint NOT NULL CHECK (artifact_bytes > 0),
    generation      bigint NOT NULL DEFAULT 1 CHECK (generation > 0),
    published_at    timestamptz NOT NULL DEFAULT now(),
    published_by    text
);

COMMENT ON TABLE ztpa.active_snapshot IS
    'Single-row pointer to the snapshot every API replica serves, and the signed '
    'engine artifact to load it from. See backend/src/snapshot_artifacts.py.';
