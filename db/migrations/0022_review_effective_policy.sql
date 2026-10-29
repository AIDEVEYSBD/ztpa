-- 0022 — keep the per-gateway rule lists out of the review head
--
-- The head on each export carried the full effective policy: the rule numbers
-- in every class for every gateway, 771 KB of JSON (375 KB stored) at 110,000
-- rules. Every register page read, decompressed and parsed it to show four
-- counts per gateway; under a staging load test that made the database the
-- bottleneck. The lists move to their own column, read only when a gateway is
-- opened; the head keeps the counts.

SET search_path TO ztpa, public;

ALTER TABLE ztpa.exports ADD COLUMN IF NOT EXISTS review_effective jsonb;

UPDATE ztpa.exports e
   SET review_effective = e.review_head->'effective_policy',
       review_head = (e.review_head - 'effective_policy') || jsonb_build_object(
         'effective_policy_summary',
         (SELECT coalesce(jsonb_agg(jsonb_build_object(
                    'layer', g->'layer', 'gateway', g->'gateway', 'rules_installed', g->'rules_installed',
                    'effective_allow_count', jsonb_array_length(coalesce(g->'effective_allow', '[]')),
                    'shadowed_count', jsonb_array_length(coalesce(g->'shadowed', '[]')),
                    'deny_count', jsonb_array_length(coalesce(g->'deny', '[]')),
                    'inactive_count', jsonb_array_length(coalesce(g->'inactive', '[]')),
                    'partly_covered_count', jsonb_array_length(coalesce(g->'partly_covered', '[]'))
                  ) ORDER BY ord), '[]'::jsonb)
            FROM jsonb_array_elements(e.review_head->'effective_policy') WITH ORDINALITY AS t(g, ord)))
 WHERE e.review_head ? 'effective_policy';
