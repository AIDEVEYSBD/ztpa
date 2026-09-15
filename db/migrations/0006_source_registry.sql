-- 0006 — open the ingestible-tool vocabulary, and record which rung it sits on
--
-- `sources.tool` was CHECKed against the five tools that existed when the table
-- was written. That looks like the right kind of guard, and it was not, because
-- of what it made the layer above it do.
--
-- `models.SourceTool` was the matching closed Literal, and `normalizers/profile.py`
-- knew it. So a record from any tool outside the list was relabelled
-- `source_tool = 'algosec'` to make it satisfy both. Bringing your own connector
-- -- which is a shipped feature of this product, with its own screen -- therefore
-- did not fail. It ingested cleanly, the counts looked right, and every
-- provenance claim downstream pointed at a different vendor's product: the
-- source badge on a finding, the "seen by" column on an asset, the rule
-- reference an operator would click to go verify something in their own
-- console, and the audit trail.
--
-- A constraint that a shipped feature has to falsify in order to pass is a bug
-- in the constraint. The vocabulary opens, the relabel is deleted in the same
-- commit, and what a source IS becomes something we record (`tier`,
-- `registered`) rather than something we assert by omission.

BEGIN;

-- The vocabulary becomes OPEN. `tool` was CHECKed against the five tools that
-- existed when the table was written, and the constraint was satisfied by
-- lying: `normalizers/profile.py` relabelled any record from an unlisted tool
-- as 'algosec' so the insert would succeed. A CHECK that a shipped feature has
-- to falsify to pass is a bug in the CHECK, not a guard.
--
-- Non-empty is the real constraint. An empty tool attributes every record,
-- object and finding it produced to the empty string, which no screen can
-- render and no operator can act on.
ALTER TABLE sources DROP CONSTRAINT IF EXISTS sources_tool_check;
ALTER TABLE sources ADD CONSTRAINT sources_tool_check CHECK (btrim(tool) <> '');

-- Which rung of the collection ladder this source sits on. Not decoration: a
-- fact from a cross-vendor aggregator and a fact read off the box itself are
-- different qualities of evidence, and "this device was read from AlgoSec, not
-- from its own console" is the sentence that tells an operator how much of
-- their estate is actually accounted for.
--
-- Defaulted rather than back-filled per row: every source that exists at
-- migration time predates the distinction, and 'aggregator' is what all five of
-- them are.
ALTER TABLE sources ADD COLUMN IF NOT EXISTS tier text NOT NULL DEFAULT 'aggregator'
    CHECK (tier IN ('aggregator', 'management_console', 'device'));

-- Whether this tool is one the build ships a normalizer for, or an operator's
-- own profile. Stored rather than derived at read time, because the catalogue
-- changes between releases and a row must keep meaning what it meant when it
-- was written: a source that was custom in this snapshot did not retroactively
-- become a shipped integration because a later release added it.
ALTER TABLE sources ADD COLUMN IF NOT EXISTS registered boolean NOT NULL DEFAULT true;

COMMENT ON COLUMN sources.tier IS
    'Collection rung: aggregator (cross-vendor console, second-hand), '
    'management_console (one vendor, deep), device (read off the box). '
    'Decides how much a fact from this source is worth, and which lanes of the '
    'topology it can be expected to populate at all.';
COMMENT ON COLUMN sources.registered IS
    'False for a bring-your-own SourceProfile: the tool name is the operator''s, '
    'not one this build ships a normalizer for. The UI says so rather than '
    'presenting it as a shipped integration.';

COMMIT;
