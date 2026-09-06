-- Network Policy Reviewer -- auth schema (in the project's `ztpa` schema).
-- NB: these live in `ztpa`, NOT `public`, because the target database may be
-- shared with other projects that already own a public.app_users table.
-- Apply:  psql "$DATABASE_URL" --single-transaction -v ON_ERROR_STOP=1 -f db/auth_schema.sql
-- Invite-only: users are created by an admin; passwords/magic links are set via tokens.

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
    role           text NOT NULL DEFAULT 'analyst'
                     CHECK (role IN ('admin', 'analyst', 'viewer')),
    password_hash  text,                                 -- null until the user sets one
    email_verified timestamptz,
    status         text NOT NULL DEFAULT 'invited'
                     CHECK (status IN ('invited', 'active', 'disabled')),
    created_at     timestamptz NOT NULL DEFAULT now(),
    created_by     text
);

CREATE TABLE IF NOT EXISTS ztpa.auth_tokens (
    token       text PRIMARY KEY,                        -- random, single-use
    email       text NOT NULL,
    purpose     text NOT NULL CHECK (purpose IN ('magic', 'reset', 'invite')),
    expires     timestamptz NOT NULL,
    used        boolean NOT NULL DEFAULT false,
    created_at  timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_ztpa_app_users_email   ON ztpa.app_users (lower(email));
CREATE INDEX IF NOT EXISTS idx_ztpa_auth_tokens_email ON ztpa.auth_tokens (email);
CREATE INDEX IF NOT EXISTS idx_ztpa_auth_tokens_exp   ON ztpa.auth_tokens (expires);
