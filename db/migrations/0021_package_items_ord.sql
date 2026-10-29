-- 0021 — page change-package items from an index
--
-- Items were paged with ORDER BY CASE band ... END, rule_number: an expression no
-- index serves, so every page of a 55,000-item package sorted all of it (262 ms
-- and a 70 MB on-disk sort locally; seconds on a small database under load,
-- which starved connection pools in the staging load test). Items now carry
-- their position, assigned at drafting; existing packages are numbered in the
-- order they were shown. The index carries the filter columns so a page's keys
-- come from an index-only scan.

SET search_path TO ztpa, public;

ALTER TABLE ztpa.change_package_items ADD COLUMN IF NOT EXISTS ord integer;

UPDATE ztpa.change_package_items i SET ord = o.n
  FROM (SELECT package_id, item_id,
               row_number() OVER (PARTITION BY package_id
                                  ORDER BY CASE band WHEN 'critical' THEN 0 WHEN 'high' THEN 1
                                                     WHEN 'medium' THEN 2 ELSE 3 END,
                                           rule_number NULLS LAST, item_id) - 1 AS n
          FROM ztpa.change_package_items WHERE ord IS NULL) o
 WHERE i.package_id = o.package_id AND i.item_id = o.item_id;

CREATE INDEX IF NOT EXISTS idx_package_items_ord ON ztpa.change_package_items
    (package_id, ord) INCLUDE (item_id, band, proposal, availability_impact, layer, owner_decision);
