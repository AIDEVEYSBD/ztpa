-- 0018 — the rule-risk register as rows
--
-- The register was one stored JSON document per export; at 70,000 rules every
-- API process had to download and parse ~100 MB before serving a page (1.5-2.5 s
-- per cold process in staging). One row per entry, in register order, makes
-- filtering and pagination indexed queries. The small review head (stats,
-- limitations, effective policy, NAT findings) lives on the export row.

SET search_path TO ztpa, public;

ALTER TABLE ztpa.exports ADD COLUMN IF NOT EXISTS review_head jsonb;

CREATE TABLE IF NOT EXISTS ztpa.review_entries (
    export_id  uuid NOT NULL REFERENCES ztpa.exports (export_id) ON DELETE CASCADE,
    ord        integer NOT NULL,                 -- register order (worst first)
    rule_uid   text NOT NULL,
    flagged    boolean NOT NULL,
    band       text CHECK (band IN ('critical', 'high', 'medium', 'low')),
    severity   integer NOT NULL DEFAULT 0,
    checks     text[] NOT NULL DEFAULT '{}',
    entry      jsonb NOT NULL,
    PRIMARY KEY (export_id, ord)
);
CREATE INDEX IF NOT EXISTS idx_review_flagged ON ztpa.review_entries (export_id, ord) WHERE flagged;
CREATE INDEX IF NOT EXISTS idx_review_band ON ztpa.review_entries (export_id, band, ord) WHERE flagged;
CREATE INDEX IF NOT EXISTS idx_review_checks ON ztpa.review_entries USING gin (checks);
CREATE INDEX IF NOT EXISTS idx_review_rule ON ztpa.review_entries (export_id, rule_uid);
