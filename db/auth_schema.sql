-- Network Policy Reviewer -- identity schema (in the project's `ztpa` schema).
--
-- NB: this lives in `ztpa`, NOT `public`, because the target database may be
-- shared with other projects that already own a public.app_users table.
--
-- Apply:  psql "$DATABASE_URL" --single-transaction -v ON_ERROR_STOP=1 -f db/auth_schema.sql
--    or:  python db/migrate.py db/auth_schema.sql
--
-- THIS IS NOT A USER DIRECTORY. The application authenticates against AutoX SSO
-- and takes every role from the `autox:app_roles` claim on the current token.
-- Nothing here grants access, and nothing here is read to decide a request:
--   * there is no password column -- password sign-in is gone;
--   * there is no token table -- magic links, invites and resets are gone
--     (`ztpa.auth_tokens` was dropped by db/migrations/0005_drop_local_auth.sql
--     and is not recreated here, so re-running this baseline cannot resurrect it);
--   * rows are created as a SIDE EFFECT of a successful sign-in, never by an
--     admin inviting someone -- there is no invite UI and no bootstrap script.
--
-- What it IS: the projection that gives the audit trail a WHO.
-- db/migrations/0002_audit_identity.sql added `audit_log.actor_email`,
-- `actor_sub` and `actor_role` as plain text so the trail outlives the account;
-- this table is what turns a historical `actor_sub` back into a person, with
-- when they were first and last seen and which roles their token carried.
-- frontend/lib/users.ts:provisionSsoUser writes it on every authentication.
--
-- Order: this baseline, then db/sso_schema.sql (which adds the sso_* columns and
-- relaxes `role` to allow NULL), then db/migrate.py for the numbered migrations.

CREATE SCHEMA IF NOT EXISTS ztpa;

-- `gen_random_uuid()` is BUILT IN from Postgres 13 -- db/schema.sql:26 says the
-- same thing and never asks for the extension. This file did, and that is the
-- only thing it ever wanted pgcrypto for.
--
-- On a managed Postgres that is not a harmless extra: Azure Database for
-- PostgreSQL Flexible Server REFUSES `CREATE EXTENSION` for anything absent from
-- its `azure.extensions` server parameter, which is empty by default. The
-- statement therefore aborted the whole file, ztpa.app_users was never created,
-- and the deploy produced a database nobody could log into -- with no error
-- until someone tried to sign in.
--
-- So it is attempted, not required: on <13 with pgcrypto available it still
-- installs, and everywhere else the failure is swallowed and the built-in is
-- used. The DO block is needed because plain `IF NOT EXISTS` does not help --
-- the extension genuinely is not installed, the server simply will not allow it.
DO $$
BEGIN
    CREATE EXTENSION IF NOT EXISTS pgcrypto;
EXCEPTION WHEN insufficient_privilege OR feature_not_supported OR OTHERS THEN
    RAISE NOTICE 'pgcrypto unavailable (%), continuing: gen_random_uuid() is built in on PG13+', SQLERRM;
END
$$;

CREATE TABLE IF NOT EXISTS ztpa.app_users (
    id             text PRIMARY KEY DEFAULT gen_random_uuid()::text,
    email          text NOT NULL UNIQUE,                 -- stored lowercased
    name           text,
    -- Mirrors the role resolved from autox:app_roles at the last sign-in.
    -- Reporting only. sso_schema.sql drops the NOT NULL, because an
    -- authenticated user holding no application role is a real state.
    role           text NOT NULL DEFAULT 'analyst'
                     CHECK (role IN ('admin', 'analyst', 'viewer')),
    -- Stamped from the AutoX `email_verified` claim, forward-only.
    email_verified timestamptz,
    -- Always 'active' for a mirrored sign-in. 'invited' and 'disabled' are
    -- vestigial: nobody can be invited (AutoX grants membership) and disabling
    -- someone here would not stop them signing in, because this table is not
    -- consulted. Kept so existing rows stay valid.
    status         text NOT NULL DEFAULT 'invited'
                     CHECK (status IN ('invited', 'active', 'disabled')),
    created_at     timestamptz NOT NULL DEFAULT now(),
    -- 'autox-sso' for a normal sign-in, 'breakglass' for the emergency path
    -- (docs/BREAKGLASS.md).
    created_by     text
);

CREATE INDEX IF NOT EXISTS idx_ztpa_app_users_email ON ztpa.app_users (lower(email));

-- The same two comments migration 0005 writes on an EXISTING database. They live
-- here too because 0005 runs BEFORE this baseline on a fresh install (see the
-- long note in that file), so without this a new environment would end up with
-- the table and none of the explanation attached to it.
COMMENT ON TABLE ztpa.app_users IS
    'Read-only mirror of who has authenticated (AutoX SSO, keyed on sso_sub; '
    'break-glass sign-ins carry sso_sub = breakglass:<email>). Written as a '
    'side effect of sign-in by frontend/lib/users.ts. NOT an authorization '
    'input: roles come from the autox:app_roles claim on the current token. '
    'Exists so audit_log.actor_sub/actor_email can be resolved to a person.';

COMMENT ON COLUMN ztpa.app_users.role IS
    'Role resolved from autox:app_roles at last sign-in. Audit/reporting only '
    '-- never read to allow or deny anything.';
