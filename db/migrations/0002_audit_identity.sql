-- 0002_audit_identity -- give the audit trail a WHO, and retire the last of the
-- runtime DDL.
--
-- WHY (part 1: identity). `audit_log` recorded `actor`, a KIND -- one of
-- 'agent' / 'user' / 'system' -- and nothing else about who acted. Every one of
-- the fifteen call sites passed the literal `'user'`, so the compliance artifact
-- answered "who deleted this snapshot?" with "a user", which is not an answer.
-- `src/db.audit()` now reads `request_ctx.current()` itself and fills the three
-- columns added here; no call site can forget an argument it does not have.
--
-- WHY (part 2: the snapshot pointer). `audit_log.snapshot_id` was
-- `REFERENCES snapshots(snapshot_id) ON DELETE SET NULL`. Deleting a snapshot
-- therefore ERASED the one field tying each audit row to the posture it was
-- recorded against -- silently, and precisely when the trail matters most. The
-- id is a deterministic content hash of the inputs, so it stays meaningful (and
-- re-derivable) after the row it named is gone: it becomes a plain text column,
-- the same treatment `change_requests.snapshot_id` got in 0001 for the same
-- reason, one step further because nothing about an append-only log should be
-- rewritten by a DELETE elsewhere.
--
-- WHY (part 3: the last ensure_* helpers). `persist.ensure_finding_types` and
-- `persist.ensure_change_request_status` executed ALTER TABLE at REQUEST time
-- behind module-level READY latches. Their end state was already in
-- db/schema.sql, so a fresh install was correct -- but schema.sql only ever ADDs
-- (every statement is IF NOT EXISTS), so an EXISTING database predating those
-- edits depended on the helpers having run. Both are restated here, which is
-- what lets the helpers be deleted: `db/migrate.py --migrations-only` is now
-- sufficient to converge any database this application has ever created.
-- (0001 did the same for asset_merges, the match_key CHECK and campaign_plans.)
--
-- Forward-only, one transaction, applied and recorded exactly once by
-- db/migrate.py. Every statement is IF NOT EXISTS or a DROP ... IF EXISTS paired
-- with the ADD that follows, so re-running by hand is harmless.

SET search_path TO ztpa, public;

-- ---------------------------------------------------------------------------
-- 1. audit_log: the acting identity.
-- Nullable on purpose. NULL means "no identified actor" -- a CLI script, the
-- warm-engine thread at boot, a dev instance with no proxy in front of it -- and
-- is written as NULL rather than as request_ctx's least-privilege 'viewer'
-- default, because inventing a subject is the exact failure this column exists
-- to end. Text, not a FK to app_users: the trail must outlive the account, and
-- `actor_sub` (the AutoX subject) is the stable key when an email is reused.
-- ---------------------------------------------------------------------------
ALTER TABLE audit_log ADD COLUMN IF NOT EXISTS actor_email text;
ALTER TABLE audit_log ADD COLUMN IF NOT EXISTS actor_sub   text;
ALTER TABLE audit_log ADD COLUMN IF NOT EXISTS actor_role  text;

-- ---------------------------------------------------------------------------
-- 2. audit_log.snapshot_id: foreign key -> plain column.
-- Dropping the constraint keeps every existing value; it only stops a future
-- DELETE on snapshots from nulling them.
-- ---------------------------------------------------------------------------
ALTER TABLE audit_log DROP CONSTRAINT IF EXISTS audit_log_snapshot_id_fkey;

-- ---------------------------------------------------------------------------
-- 3. Indexes for the read side (GET /api/audit is admin-only, newest first,
-- paginated). ts DESC matches the ORDER BY exactly, so the page is an index
-- scan rather than a sort of the whole table; actor_email answers "everything
-- this person did", which is the second question anyone asks of an audit trail.
-- ---------------------------------------------------------------------------
CREATE INDEX IF NOT EXISTS idx_audit_ts     ON audit_log (ts DESC);
CREATE INDEX IF NOT EXISTS idx_audit_actor  ON audit_log (actor_email);

-- ---------------------------------------------------------------------------
-- 4. findings.type -- was widened by persist.ensure_finding_types at runtime.
-- The new set is a strict superset of the old, so no existing row can violate
-- it. 'transport_exposure' is emitted by src/analyzers/transport_exposure.py.
-- ---------------------------------------------------------------------------
ALTER TABLE findings DROP CONSTRAINT IF EXISTS findings_type_check;
ALTER TABLE findings ADD CONSTRAINT findings_type_check
    CHECK (type IN ('over_permissive', 'cidr_overlap', 'shadowed_rule',
                    'cross_tool_path', 'transport_exposure'));

-- ---------------------------------------------------------------------------
-- 5. change_requests lifecycle -- was added by
-- persist.ensure_change_request_status at runtime. 'open' (awaiting action) or
-- 'rejected'; approved/staged requests are tracked through staged_changes.
-- ---------------------------------------------------------------------------
ALTER TABLE change_requests ADD COLUMN IF NOT EXISTS status        text NOT NULL DEFAULT 'open';
ALTER TABLE change_requests ADD COLUMN IF NOT EXISTS rejected_by   text;
ALTER TABLE change_requests ADD COLUMN IF NOT EXISTS reject_reason text;

-- ---------------------------------------------------------------------------
-- 6. staged_changes.created_by -- declared since the first schema and never
-- written by anything, on the table that lists the changes about to be pushed
-- into a production firewall. persist.persist_staged_change now stamps it from
-- the request context. Restated here for a database old enough to predate the
-- column's declaration.
-- ---------------------------------------------------------------------------
ALTER TABLE staged_changes ADD COLUMN IF NOT EXISTS created_by text;
