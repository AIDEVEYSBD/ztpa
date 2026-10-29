-- 0020 — find partly covered rules in the register
--
-- A rule some of whose grants are already matched by rules above it is not
-- flagged (it still carries traffic), so the default flagged-only view never
-- shows it. A boolean with a partial index makes "partly covered" an indexed
-- filter like the others. Adding a column with a constant default rewrites
-- nothing on PostgreSQL 11+.

SET search_path TO ztpa, public;

ALTER TABLE ztpa.review_entries ADD COLUMN IF NOT EXISTS partly_covered boolean NOT NULL DEFAULT false;
CREATE INDEX IF NOT EXISTS idx_review_partly_covered ON ztpa.review_entries (export_id, ord) WHERE partly_covered;
