-- 0004_ai_config -- the stored AI-provider configuration the Configuration page
-- writes, as ONE row that an operator can be held to.
--
-- WHY. Provider routing has been environment-only since the first commit:
-- `ADVISORY_PROVIDER`, `OPENAI_API_KEY`, `OLLAMA_HOST` (backend/src/settings.py).
-- That is the right shape for a secret and the wrong shape for a CHOICE. On
-- Azure Container Apps changing an environment variable is a revision -- a
-- deploy -- so "point the advisory layer at our own Foundry deployment" is a
-- pipeline change rather than an admin action, it is invisible to the product's
-- own audit trail, and nothing records who made it or when. The AI residency
-- chip in the header (frontend/components/Topbar.tsx) tells a user their
-- topology is leaving the box; until now nothing could tell them who decided
-- that.
--
-- So the choice moves into the system of record, next to every other decision
-- this product keeps: `configured_by` + `updated_at` give it the same human
-- identity the audit trail grew in 0002, and `GET /api/admin/ai/config` can
-- answer "what is this deployment pointed at, and who pointed it there".
--
-- ⚠ NO API KEY COLUMN. NOT NOW, NOT LATER, NOT "JUST FOR THE MANUAL PATH".
-- A key is a secret and this table is not a secret store: it is read by the
-- routing path on every model call, dumped by `pg_dump` into every backup,
-- replicated to every read replica, and returned (minus whatever the API layer
-- remembers to strip) by an admin endpoint. `azure_auth_mode = 'identity'` is
-- the intended posture and needs no secret at all -- the Container App's managed
-- identity is the credential. `azure_auth_mode = 'key'` exists for a custom
-- endpoint that has no identity story, and that key lives in a Container Apps
-- secret surfaced as an environment variable (`AZURE_AI_API_KEY`), the same
-- place `OPENAI_API_KEY` already lives. The resolution order in
-- backend/src/ai_config.py states this as a rule: STORED ROW WINS FOR CHOICES,
-- ENVIRONMENT IS THE ONLY SOURCE OF SECRETS. A column added here "for
-- convenience" silently breaks it, and backend/tests/test_ai_config.py fails if
-- one ever appears.
--
-- WHY A SINGLE ROW, AND HOW IT IS ENFORCED. There is exactly one advisory
-- provider per deployment -- `settings.active_provider()` returns one string --
-- so a table that can hold two configurations can hold a disagreement the code
-- has no way to resolve, and "which row is live" becomes an unwritten
-- convention (`ORDER BY updated_at DESC LIMIT 1`) that every future reader has
-- to rediscover. The constraint chosen is a CONSTANT PRIMARY KEY:
--
--     id boolean PRIMARY KEY DEFAULT true CHECK (id)
--
-- A primary key is NOT NULL, so `id` can only ever be `true`: the second insert
-- collides on the key (or is rejected by the CHECK if it tries `false`), and the
-- database refuses it rather than the application remembering to. It is
-- preferred over a partial unique index on a constant expression for two
-- reasons: it gives the UPSERT a real conflict target
-- (`INSERT ... ON CONFLICT (id) DO UPDATE`), which is how `ai_config.save()`
-- writes without a read-modify-write race between two admins; and it is visible
-- as a column in `\d ztpa.ai_config`, where a partial index on `((true))` is
-- the kind of cleverness that gets dropped by someone tidying up.
--
-- Forward-only, one transaction, applied and recorded exactly once by
-- db/migrate.py. Every statement is IF NOT EXISTS, so re-running by hand is
-- harmless. The identical definition is in db/schema.sql for a fresh install;
-- the two must agree, and backend/tests/test_ai_config.py asserts they do.

SET search_path TO ztpa, public;

CREATE TABLE IF NOT EXISTS ai_config (
    -- The singleton key. See the note above: the type is boolean and the CHECK
    -- pins it to true, so "there is at most one configuration" is a database
    -- fact rather than an application habit.
    id                 boolean PRIMARY KEY DEFAULT true CHECK (id),

    -- Which advisory provider this deployment uses. Same vocabulary as
    -- ADVISORY_PROVIDER (backend/src/settings.py) so a stored value and an
    -- environment value are directly comparable -- including 'auto', which is
    -- how an operator says "go back to letting the environment decide" without
    -- deleting the row and losing the record that they said it.
    provider           text NOT NULL DEFAULT 'auto'
                       CHECK (provider IN ('auto', 'azure', 'openai', 'anthropic', 'ollama')),

    -- Azure AI Foundry target. The endpoint is the account's data-plane host,
    -- e.g. https://<account>.cognitiveservices.azure.com/ (what
    -- `az cognitiveservices account show` returns as properties.endpoint), or a
    -- custom host from the manual escape hatch. `azure_deployment` is the
    -- DEPLOYMENT name on that account, not the model name -- they differ often
    -- enough that using one for the other is a 404 at request time.
    azure_endpoint     text,
    azure_deployment   text,

    -- Data-plane API version. Nullable so the application default
    -- (ai_config.DEFAULT_AZURE_API_VERSION) can move without a migration to
    -- rewrite every row; a stored value pins a deployment that needs one.
    azure_api_version  text,

    -- 'identity' -> the Container App's managed identity (no secret anywhere);
    -- 'key'      -> an API key read from the environment. Never from here.
    azure_auth_mode    text NOT NULL DEFAULT 'identity'
                       CHECK (azure_auth_mode IN ('identity', 'key')),

    -- Optional USER-ASSIGNED managed identity client id. NULL means
    -- DefaultAzureCredential picks the credential itself, which is what works
    -- both in the deployed app (the attached identity) and on a developer
    -- machine (`az login`). Set it when more than one identity is attached and
    -- the ambiguity has to be resolved explicitly.
    azure_client_id    text,

    -- Attribution, exactly as 0002 gave the audit trail: the actor email from
    -- request_ctx at the moment of the save. Nullable because a configuration
    -- written by a script or a migration has no human behind it, and inventing
    -- one is the failure 0002 exists to end.
    configured_by      text,
    updated_at         timestamptz NOT NULL DEFAULT now(),

    -- An 'azure' configuration without a target is not a configuration: it
    -- routes every model call at nothing and degrades to the deterministic
    -- fallback, which the product reports as "the model said nothing useful"
    -- rather than "you never finished configuring this". Refused here so a
    -- half-saved form cannot become the live routing decision.
    -- `ai_config.save()` raises AiConfigError on the same condition first, so
    -- the API layer answers 400 instead of leaking a constraint violation.
    CONSTRAINT ai_config_azure_target_complete CHECK (
        provider <> 'azure'
        OR (nullif(btrim(azure_endpoint), '') IS NOT NULL
            AND nullif(btrim(azure_deployment), '') IS NOT NULL)
    )
);

-- Documented in the database itself, so `\d+` and every schema browser carry
-- the constraint that matters most about this table.
COMMENT ON TABLE ztpa.ai_config IS
    'Single-row advisory-provider configuration written by the Configuration '
    'page. NEVER stores an API key: secrets come from the environment '
    '(Container Apps secrets) only. See db/migrations/0004_ai_config.sql.';
