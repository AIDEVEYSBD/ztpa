-- 0005_drop_local_auth -- retire local authentication. SSO becomes the only door.
--
-- WHAT THIS REMOVES, AND WHY IT IS SAFE TO REMOVE IT.
--
-- The application authenticates against AutoX SSO (OIDC) and resolves every
-- authorization decision from the `autox:app_roles` claim on the current token.
-- Three things in this schema existed only to support the password / magic-link
-- login that has now been deleted from the frontend:
--
--   * `ztpa.auth_tokens`            -- single-use magic-link, invite and reset
--                                      tokens. Every reader is gone:
--                                      frontend/lib/tokens.ts, the "magic"
--                                      credential provider in frontend/auth.ts,
--                                      frontend/app/actions.ts, and the two
--                                      bootstrap scripts (create-admin.mjs,
--                                      send-reset.mjs). The table is a store of
--                                      LIVE CREDENTIALS -- leaving it behind
--                                      leaves unexpired sign-in tokens sitting
--                                      in the database with no code left to
--                                      expire or invalidate them, which is
--                                      strictly worse than dropping it.
--   * `ztpa.app_users.password_hash` -- bcrypt hashes. Read by
--                                      users.verifyUserPassword and written by
--                                      users.setPassword and create-admin.mjs;
--                                      all three are deleted. A dormant hash is
--                                      a credential nobody rotates.
--   * the two auth_tokens indexes    -- go with the table.
--
-- WHAT THIS DELIBERATELY DOES NOT REMOVE.
--
-- `ztpa.app_users` STAYS. It is not the user directory any more -- it grants
-- nothing, denies nothing and is never consulted to authorize anything -- but
-- 0002_audit_identity added `audit_log.actor_email` / `actor_sub` / `actor_role`
-- as TEXT columns, on purpose, so the trail outlives the account. This table is
-- the projection that turns a historical `actor_sub` back into a person, and
-- frontend/lib/users.ts:provisionSsoUser writes a row on every authentication to
-- keep it current. Dropping it would break SSO sign-in (the provisioning INSERT
-- fails) and destroy the compliance record at the same time. Step 2 below says
-- so in a NOTICE anywhere that table turns out to be missing.
--
-- `status`, `email_verified`, `created_by`, `name` and `role` all stay: each is
-- still written by provisioning, and `email_verified` is now stamped from the
-- AutoX `email_verified` claim rather than by a consumed magic link.
--
-- IDEMPOTENT AND ORDER-INDEPENDENT. Every statement is IF EXISTS, so this
-- applies unchanged to a database that already ran the old auth_schema.sql and
-- to a fresh one built from the rewritten baseline (which never creates either
-- object). Forward-only: recorded once in ztpa.schema_migrations by db/migrate.py.
--
-- RECOVERY. Removing local login means a broken SSO configuration locks
-- everyone out. The recovery path is NOT in this schema by design -- see
-- docs/BREAKGLASS.md. The break-glass credential lives in the platform's secret
-- store, never in this database, which is why nothing here needs to survive for
-- an operator to get back in.

SET search_path TO ztpa, public;

-- ---------------------------------------------------------------------------
-- 1. The magic-link / invite / reset token store, and its indexes with it.
-- Unconditional: DROP ... IF EXISTS is happy whether or not the object is there.
-- ---------------------------------------------------------------------------
DROP INDEX IF EXISTS ztpa.idx_ztpa_auth_tokens_email;
DROP INDEX IF EXISTS ztpa.idx_ztpa_auth_tokens_exp;
DROP TABLE IF EXISTS ztpa.auth_tokens;

-- ---------------------------------------------------------------------------
-- 2. The password column, and the table comments that say what app_users is now.
--
-- WHY THIS IS CONDITIONAL, AND NOT A TRIPWIRE THAT RAISES.
--
-- `ztpa.app_users` is created by db/auth_schema.sql, which is a SEPARATE
-- baseline: `db/migrate.py` takes one baseline at a time, and the deploy runs
-- them in this order (scripts/azure/deploy.sh, MIGRATE_SCRIPT):
--
--     python db/migrate.py                     <- engine schema + ALL migrations
--     python db/migrate.py db/auth_schema.sql   <- app_users
--     python db/migrate.py db/sso_schema.sql    <- the sso_* columns
--
-- So on a FRESH database this migration runs BEFORE the table it edits exists.
-- `ALTER TABLE ... DROP COLUMN IF EXISTS` does not forgive a missing TABLE
-- (42P01), and an earlier draft of this file raised an explicit exception here
-- -- both of which abort step 1 and take the whole deploy job with them, on
-- every new environment. Verified against a real fresh database.
--
-- The absence of the table is therefore NOT an error: it means there is nothing
-- to clean up yet, and the rewritten db/auth_schema.sql never creates a
-- password column or a token table, so the end state is identical either way.
-- On an EXISTING database (the ordering that matters for this migration) the
-- table is present and the drops happen.
--
-- What is worth being loud about is the opposite mistake -- someone deciding
-- that app_users is obsolete under SSO and dropping it. It is not: 0002 made
-- audit_log.actor_email / actor_sub / actor_role plain text so the trail
-- outlives the account, and this table is the projection that resolves those
-- back to a person. The NOTICE below says so wherever it is seen.
-- ---------------------------------------------------------------------------
DO $$
BEGIN
    IF to_regclass('ztpa.app_users') IS NULL THEN
        RAISE NOTICE
            'ztpa.app_users does not exist yet -- nothing to clean up. This is the '
            'normal fresh-install ordering (db/migrate.py runs migrations before '
            'db/auth_schema.sql creates the table, and that baseline no longer '
            'declares password_hash). If you are looking at an EXISTING database, '
            'this table is missing and must be restored: it is the mirror that '
            'audit_log.actor_sub/actor_email resolve against, and '
            'frontend/lib/users.ts:provisionSsoUser writes it on every sign-in.';
        RETURN;
    END IF;

    ALTER TABLE ztpa.app_users DROP COLUMN IF EXISTS password_hash;

    -- Say what the table is now, in the database itself, so the next person to
    -- read it with \d+ does not have to find this file first.
    COMMENT ON TABLE ztpa.app_users IS
        'Read-only mirror of who has authenticated (AutoX SSO, keyed on sso_sub; '
        'break-glass sign-ins carry sso_sub = breakglass:<email>). Written as a '
        'side effect of sign-in by frontend/lib/users.ts. NOT an authorization '
        'input: roles come from the autox:app_roles claim on the current token. '
        'Exists so audit_log.actor_sub/actor_email can be resolved to a person.';

    COMMENT ON COLUMN ztpa.app_users.role IS
        'Role resolved from autox:app_roles at last sign-in. Audit/reporting only '
        '-- never read to allow or deny anything.';
END
$$;
