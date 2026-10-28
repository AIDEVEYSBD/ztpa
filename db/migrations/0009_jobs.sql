-- 0009 — durable job queue
--
-- Heavy work (export intake, engine builds, review pipelines, LLM narrative)
-- leaves the request path and runs in workers. The queue lives in Postgres
-- rather than Pub/Sub or Service Bus so it is identical on both clouds and
-- transactional with the rows the jobs produce. Workers claim with
-- `FOR UPDATE SKIP LOCKED`; see backend/src/jobs/queue.py for the protocol.

SET search_path TO ztpa, public;

CREATE TABLE IF NOT EXISTS ztpa.jobs (
    job_id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    kind            text NOT NULL CHECK (kind ~ '^[a-z][a-z0-9_.]{0,63}$'),
    payload         jsonb NOT NULL DEFAULT '{}'::jsonb,
    status          text NOT NULL DEFAULT 'queued'
                    CHECK (status IN ('queued', 'running', 'succeeded', 'dead', 'cancelled')),
    -- Lower runs first. 100 is normal; interactive work uses less.
    priority        smallint NOT NULL DEFAULT 100,
    attempts        integer NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    max_attempts    integer NOT NULL DEFAULT 5 CHECK (max_attempts BETWEEN 1 AND 50),
    run_after       timestamptz NOT NULL DEFAULT now(),
    -- The lease. A worker that dies stops heartbeating; once `locked_until`
    -- passes, another worker may reclaim the job.
    locked_by       text,
    locked_until    timestamptz,
    -- Same key = same job: a double upload or a retried API call enqueues once.
    idempotency_key text,
    progress        jsonb,
    result          jsonb,
    last_error      text,
    created_by      text,
    created_at      timestamptz NOT NULL DEFAULT now(),
    started_at      timestamptz,
    finished_at     timestamptz,
    updated_at      timestamptz NOT NULL DEFAULT now(),
    CHECK ((status = 'running') = (locked_by IS NOT NULL AND locked_until IS NOT NULL))
);

CREATE UNIQUE INDEX IF NOT EXISTS uq_jobs_idempotency
    ON ztpa.jobs (idempotency_key) WHERE idempotency_key IS NOT NULL;

-- The claim query's two arms: runnable queued work, and expired leases.
CREATE INDEX IF NOT EXISTS idx_jobs_runnable
    ON ztpa.jobs (priority, run_after) WHERE status = 'queued';
CREATE INDEX IF NOT EXISTS idx_jobs_leases
    ON ztpa.jobs (locked_until) WHERE status = 'running';
CREATE INDEX IF NOT EXISTS idx_jobs_kind_created
    ON ztpa.jobs (kind, created_at DESC);

COMMENT ON TABLE ztpa.jobs IS
    'Durable job queue. Claimed with FOR UPDATE SKIP LOCKED under a heartbeat '
    'lease; retried with backoff to max_attempts, then dead. See '
    'backend/src/jobs/queue.py.';
