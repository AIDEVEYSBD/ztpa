-- 0016 — context datasets: CMDB/IPAM ownership and observed flows
--
-- CMDB/IPAM rows say who owns an address range and what runs there; flow rows
-- (e.g. a Stealthwatch flow export) say which sources actually reached which
-- destination port. Flows are stored AGGREGATED per (src, dst, proto, port), so
-- a multi-million-row export becomes the distinct conversations it describes.
-- The newest accepted dataset of each kind is the active one.

SET search_path TO ztpa, public;

CREATE TABLE IF NOT EXISTS ztpa.context_datasets (
    dataset_id       uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    kind             text NOT NULL CHECK (kind IN ('cmdb', 'flows')),
    filename         text,
    sha256           text NOT NULL CHECK (sha256 ~ '^[0-9a-f]{64}$'),
    size_bytes       bigint NOT NULL CHECK (size_bytes > 0),
    storage_key      text NOT NULL,
    status           text NOT NULL DEFAULT 'received' CHECK (status IN ('received', 'accepted', 'rejected')),
    rejection_reason text,
    summary          jsonb,
    uploaded_by      text,
    uploaded_at      timestamptz NOT NULL DEFAULT now(),
    job_id           uuid,
    UNIQUE (kind, sha256),
    CHECK ((status = 'rejected') = (rejection_reason IS NOT NULL))
);
CREATE INDEX IF NOT EXISTS idx_context_active ON ztpa.context_datasets (kind, uploaded_at DESC)
    WHERE status = 'accepted';

CREATE TABLE IF NOT EXISTS ztpa.cmdb_assets (
    dataset_id   uuid NOT NULL REFERENCES ztpa.context_datasets (dataset_id) ON DELETE CASCADE,
    net          cidr NOT NULL,
    owner        text,
    application  text,
    environment  text,
    zone         text,
    criticality  text
);
CREATE INDEX IF NOT EXISTS idx_cmdb_net ON ztpa.cmdb_assets USING gist (net inet_ops);
CREATE INDEX IF NOT EXISTS idx_cmdb_dataset ON ztpa.cmdb_assets (dataset_id);

CREATE TABLE IF NOT EXISTS ztpa.flows (
    dataset_id  uuid NOT NULL REFERENCES ztpa.context_datasets (dataset_id) ON DELETE CASCADE,
    src         inet NOT NULL,
    dst         inet NOT NULL,
    proto       text NOT NULL,
    port        integer CHECK (port BETWEEN 0 AND 65535),
    first_seen  timestamptz,
    last_seen   timestamptz NOT NULL,
    flows       bigint NOT NULL DEFAULT 1 CHECK (flows > 0)
);
CREATE INDEX IF NOT EXISTS idx_flows_lookup ON ztpa.flows (dataset_id, proto, port, last_seen);
CREATE INDEX IF NOT EXISTS idx_flows_dst ON ztpa.flows USING gist (dst inet_ops);
