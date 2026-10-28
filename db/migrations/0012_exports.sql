-- 0012 — uploaded policy exports and their review outcome
--
-- One row per distinct export (by sha256): who uploaded it, when it was taken,
-- where the original bytes live in object storage, and what intake decided.
-- A rejected export keeps its reason; it is never silently an empty estate.

SET search_path TO ztpa, public;

CREATE TABLE IF NOT EXISTS ztpa.exports (
    export_id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    sha256               text NOT NULL UNIQUE CHECK (sha256 ~ '^[0-9a-f]{64}$'),
    source_type          text NOT NULL CHECK (source_type ~ '^[a-z][a-z0-9_]{0,31}$'),
    filename             text,
    size_bytes           bigint NOT NULL CHECK (size_bytes > 0),
    storage_key          text NOT NULL,
    -- As declared by the uploader; the export's own timestamp wins when present.
    declared_exported_at timestamptz,
    exported_at          timestamptz,
    uploaded_by          text,
    uploaded_at          timestamptz NOT NULL DEFAULT now(),
    status               text NOT NULL DEFAULT 'received'
                         CHECK (status IN ('received', 'accepted', 'rejected')),
    rejection_reason     text,
    summary              jsonb,
    parsed_key           text,
    review_key           text,
    job_id               uuid,
    updated_at           timestamptz NOT NULL DEFAULT now(),
    CHECK ((status = 'rejected') = (rejection_reason IS NOT NULL)),
    CHECK (status <> 'accepted' OR (review_key IS NOT NULL AND parsed_key IS NOT NULL))
);

CREATE INDEX IF NOT EXISTS idx_exports_uploaded ON ztpa.exports (uploaded_at DESC);

COMMENT ON TABLE ztpa.exports IS
    'Uploaded policy exports (content-addressed by sha256) and the intake outcome. '
    'See backend/src/frr/intake.py.';
