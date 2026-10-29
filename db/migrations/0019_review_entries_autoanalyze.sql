-- 0019 — keep planner statistics current on bulk-loaded tables
--
-- Ingest COPYs tens of thousands of rows into review_entries (and context data
-- into flows / cmdb_assets) at once. Until autovacuum's default threshold
-- (10% + 50 rows) triggers an ANALYZE, the planner believes these tables are
-- tiny and picks nested loops: a review comparison took 357 s on a freshly
-- loaded 70,000-rule pair and 0.5 s once analysed. The runtime role cannot
-- ANALYZE (owner only on PostgreSQL 16), so autovacuum is told to re-analyse
-- after ~1% change.

SET search_path TO ztpa, public;

ALTER TABLE ztpa.review_entries SET (autovacuum_analyze_scale_factor = 0.01, autovacuum_analyze_threshold = 1000);
ALTER TABLE ztpa.flows          SET (autovacuum_analyze_scale_factor = 0.01, autovacuum_analyze_threshold = 1000);
ALTER TABLE ztpa.cmdb_assets    SET (autovacuum_analyze_scale_factor = 0.01, autovacuum_analyze_threshold = 1000);
