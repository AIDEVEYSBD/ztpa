-- 0001_governance_fk -- governance rows must outlive the snapshot they cite.
--
-- WHY. `change_requests.snapshot_id` was declared
-- `REFERENCES snapshots(snapshot_id) ON DELETE CASCADE`, and the persist layer
-- cleared a snapshot's derived rows by deleting the PARENT `snapshots` row.
-- The engine is deterministic, so a recompute of UNCHANGED data resolves to the
-- SAME snapshot_id -- meaning one press of Recompute (or confirming an asset
-- merge, or switching dataset back) deleted the live row and cascaded away every
-- change_request and, through it, every change_decision: the entire approval
-- trail, silently, with staged_changes left dangling on a request_id that no
-- longer resolved. The FK is a "baseline evaluated against" pointer, not
-- ownership; it is now nullable with ON DELETE SET NULL, matching the treatment
-- audit_log.snapshot_id already had.
--
-- Also folds in the two pieces of known drift between db/schema.sql and the DDL
-- the application was executing at runtime (persist._ensure_merges /
-- ensure_campaign_plans), so the file and the database finally agree.
--
-- Forward-only. Re-runnable by hand: every statement is IF NOT EXISTS, or a
-- DROP ... IF EXISTS paired with the ADD that follows it. Applied and recorded
-- exactly once by db/migrate.py, in a single transaction.

SET search_path TO ztpa, public;

-- ---------------------------------------------------------------------------
-- 1. change_requests.snapshot_id: ownership -> pointer.
-- SET NULL requires the column to be nullable; DROP NOT NULL is a no-op when it
-- already is (a database created from the current schema.sql).
-- ---------------------------------------------------------------------------
ALTER TABLE change_requests ALTER COLUMN snapshot_id DROP NOT NULL;

ALTER TABLE change_requests DROP CONSTRAINT IF EXISTS change_requests_snapshot_id_fkey;
ALTER TABLE change_requests ADD CONSTRAINT change_requests_snapshot_id_fkey
    FOREIGN KEY (snapshot_id) REFERENCES snapshots(snapshot_id) ON DELETE SET NULL;

-- change_decisions.request_id keeps ON DELETE CASCADE on purpose: a decision IS
-- a child of its request (it is meaningless without one), and now that a
-- recompute can no longer delete a change_request, nothing routine cascades
-- through it. staged_changes deliberately keeps its soft link -- adding a real
-- FK would fail against the dangling request_ids the old cascade already left
-- behind, and repairing those is a data question, not a schema one.

-- ---------------------------------------------------------------------------
-- 2. asset_merges -- was only ever created by persist._ensure_merges at runtime
-- and was missing from schema.sql. Same definition, so this is a no-op on any
-- database that has run the app.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS asset_merges (
    merge_id      text PRIMARY KEY,
    name_a        text NOT NULL,
    name_b        text NOT NULL,
    confirmed_by  text,
    created_at    timestamptz DEFAULT now()
);

-- ---------------------------------------------------------------------------
-- 3. asset_correlations.match_key -- widen to admit 'manual_review', the value
-- identity.py:136 emits for a human-confirmed merge. The new set is a strict
-- superset of the old, so no existing row can violate it.
-- ---------------------------------------------------------------------------
ALTER TABLE asset_correlations DROP CONSTRAINT IF EXISTS asset_correlations_match_key_check;
ALTER TABLE asset_correlations ADD CONSTRAINT asset_correlations_match_key_check
    CHECK (match_key IN ('cloud_id', 'hostname', 'mac', 'context_ip', 'manual_review'));

-- ---------------------------------------------------------------------------
-- 4. campaign_plans -- created at runtime by persist.ensure_campaign_plans on
-- databases older than schema.sql:campaign_plans. delete_snapshot_children now
-- clears it per snapshot (it is an LLM cache over findings that are being
-- regenerated), so it has to exist before the next recompute runs.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS campaign_plans (
    snapshot_id  text PRIMARY KEY,
    plan         jsonb NOT NULL DEFAULT '{}'::jsonb,
    created_at   timestamptz NOT NULL DEFAULT now()
);
