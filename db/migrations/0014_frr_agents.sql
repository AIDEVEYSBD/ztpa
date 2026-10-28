-- 0014 — FRR agent runs, narratives and the knowledge base (RAG sources)
--
-- frr_runs records one orchestrated review run: each agent's step, its inputs'
-- identity, its outputs' summary, the prompt version and model it used, so a
-- run is auditable and resumable. Narratives are stored beside the
-- deterministic items they describe and never replace them.
--
-- knowledge_docs / knowledge_chunks hold the client's network standards,
-- exception register and change/rollback runbooks. Retrieval is Postgres full
-- text search (identical on Cloud SQL and Flexible Server, no embedding
-- service); the chunk table is shaped so a pgvector column can be added later.

SET search_path TO ztpa, public;

CREATE TABLE IF NOT EXISTS ztpa.frr_runs (
    run_id       uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    export_id    uuid NOT NULL REFERENCES ztpa.exports (export_id) ON DELETE CASCADE,
    package_id   uuid REFERENCES ztpa.change_packages (package_id) ON DELETE SET NULL,
    job_id       uuid,
    status       text NOT NULL DEFAULT 'queued'
                 CHECK (status IN ('queued', 'running', 'succeeded', 'failed')),
    steps        jsonb NOT NULL DEFAULT '[]'::jsonb,
    created_by   text,
    created_at   timestamptz NOT NULL DEFAULT now(),
    finished_at  timestamptz
);
CREATE INDEX IF NOT EXISTS idx_frr_runs_export ON ztpa.frr_runs (export_id, created_at DESC);

ALTER TABLE ztpa.change_package_items ADD COLUMN IF NOT EXISTS narrative jsonb;
ALTER TABLE ztpa.change_packages ADD COLUMN IF NOT EXISTS narrative jsonb;

CREATE TABLE IF NOT EXISTS ztpa.knowledge_docs (
    doc_id       uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    kind         text NOT NULL CHECK (kind IN ('standard', 'exception', 'runbook')),
    title        text NOT NULL CHECK (length(title) BETWEEN 1 AND 300),
    sha256       text NOT NULL UNIQUE CHECK (sha256 ~ '^[0-9a-f]{64}$'),
    uploaded_by  text,
    uploaded_at  timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS ztpa.knowledge_chunks (
    doc_id   uuid NOT NULL REFERENCES ztpa.knowledge_docs (doc_id) ON DELETE CASCADE,
    ord      integer NOT NULL,
    heading  text,
    body     text NOT NULL,
    tsv      tsvector GENERATED ALWAYS AS
             (to_tsvector('english', coalesce(heading, '') || ' ' || body)) STORED,
    PRIMARY KEY (doc_id, ord)
);
CREATE INDEX IF NOT EXISTS idx_knowledge_chunks_tsv ON ztpa.knowledge_chunks USING gin (tsv);
