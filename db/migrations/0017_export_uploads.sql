-- 0017 — multipart export uploads
--
-- Cloud Run caps a request body at 32 MiB; large policy exports arrive as
-- numbered parts through the API (never via a public storage URL: on Azure the
-- storage account has no public network access at all). An upload is a session:
-- open -> completing (parts assembled, a job hashes and registers the export)
-- -> done (export_id set; possibly an existing export the bytes duplicate) |
-- failed (reason). Sessions left open expire.

SET search_path TO ztpa, public;

CREATE TABLE IF NOT EXISTS ztpa.export_uploads (
    upload_id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    source_type          text NOT NULL CHECK (source_type ~ '^[a-z][a-z0-9_]{0,31}$'),
    filename             text,
    declared_exported_at timestamptz,
    uploaded_by          text,
    status               text NOT NULL DEFAULT 'open'
                         CHECK (status IN ('open', 'completing', 'done', 'failed')),
    parts                integer NOT NULL DEFAULT 0 CHECK (parts >= 0),
    bytes                bigint NOT NULL DEFAULT 0 CHECK (bytes >= 0),
    storage_key          text NOT NULL,
    export_id            uuid REFERENCES ztpa.exports (export_id) ON DELETE SET NULL,
    duplicate            boolean NOT NULL DEFAULT false,
    failure_reason       text,
    created_at           timestamptz NOT NULL DEFAULT now(),
    expires_at           timestamptz NOT NULL DEFAULT now() + interval '24 hours',
    CHECK ((status = 'failed') = (failure_reason IS NOT NULL))
);

CREATE TABLE IF NOT EXISTS ztpa.export_upload_parts (
    upload_id  uuid NOT NULL REFERENCES ztpa.export_uploads (upload_id) ON DELETE CASCADE,
    part       integer NOT NULL CHECK (part BETWEEN 1 AND 2000),
    bytes      integer NOT NULL CHECK (bytes > 0),
    received_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (upload_id, part)
);
