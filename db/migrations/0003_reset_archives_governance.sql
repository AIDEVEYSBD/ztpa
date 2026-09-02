-- 0003_reset_archives_governance -- make the demo reset RETIRE the change trail
-- instead of destroying it.
--
-- WHY. The Phase 2 exit criterion is stated in
-- docs/PROD-READINESS-AUDIT.md:230 as
--
--     "A recompute, a dataset switch, an asset merge and a reset each leave
--      change_requests, change_decisions and audit_log intact"
--
-- and three of those four were made true by 0001 (the snapshot FK stopped
-- cascading) and by src/db.delete_snapshot_children (it stopped deleting the
-- parent row). The fourth was not: `POST /api/admin/reset-demo` ran
-- `DELETE FROM change_requests` and `DELETE FROM change_decisions`
-- unconditionally, so on a real database a reset still took the approval trail
-- to zero. It was deliberate -- a demo reset is supposed to clear the working
-- set -- but "clear the working set" and "destroy the compliance record" are
-- two different acts that happened to share one implementation, and the second
-- one is the thing this whole phase exists to stop. A system of record does not
-- get to erase rows because a screen wants to look empty.
--
-- WHAT. `archived_at` splits them. A reset STAMPS the live rows instead of
-- deleting them; every read path that feeds a screen filters
-- `archived_at IS NULL`, so the console still resets to a clean slate, while the
-- rows -- who asked for what, how the gate ruled, when -- stay in the table,
-- queryable, and countable by the tests that assert the criterion.
--
-- NULL means live. That is deliberately the DEFAULT for a column added to an
-- existing table, so every row already in the database stays visible: a
-- migration that hid history would be the same mistake wearing a different hat.
--
-- Re-writing a request UNARCHIVES it (src/persist.persist_change_request_row
-- passes archived_at=NULL in the upsert), because request ids are deterministic
-- content hashes: re-running the demo re-submits the identical id, and the
-- record of the new submission has to be visible.
--
-- Forward-only, one transaction, applied and recorded exactly once by
-- db/migrate.py. Every statement is IF NOT EXISTS, so re-running by hand is
-- harmless.

SET search_path TO ztpa, public;

-- ---------------------------------------------------------------------------
-- 1. The retirement stamp itself, on the two governance tables the criterion
-- names. `staged_changes` / `remediation_revisions` / `campaign_plans` keep
-- being DELETEd by a reset: the push queue, the comment thread and the cached
-- plan are the working set and the cache, not the record of a decision.
-- ---------------------------------------------------------------------------
ALTER TABLE change_requests  ADD COLUMN IF NOT EXISTS archived_at timestamptz;
ALTER TABLE change_decisions ADD COLUMN IF NOT EXISTS archived_at timestamptz;

-- ---------------------------------------------------------------------------
-- 2. The read side. GET /api/change-decisions joins the two tables, filters the
-- archived rows out and orders by decided_at DESC -- so a partial index on
-- exactly the live rows keeps that page an index scan as the archive grows,
-- which is the point of archiving rather than deleting: the table only gets
-- bigger from here.
-- ---------------------------------------------------------------------------
CREATE INDEX IF NOT EXISTS idx_decisions_live
    ON change_decisions (decided_at DESC) WHERE archived_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_requests_live
    ON change_requests (created_at DESC) WHERE archived_at IS NULL;
