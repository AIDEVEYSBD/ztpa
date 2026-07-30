-- AutoX SSO (OIDC) support for ztpa.app_users.
-- Apply:  psql "$DATABASE_URL" --single-transaction -v ON_ERROR_STOP=1 -f db/sso_schema.sql
--    or:  python db/migrate.py db/sso_schema.sql
-- (No dollar-quoting anywhere below — migrate.py splits statements on ';'.)
--
-- The identity key becomes `sso_sub` (the AutoX `sub` claim), NOT email: a
-- deleted-and-recreated AutoX account keeps the email but gets a new `sub`, and
-- re-linking it to the old row would hand one person another's history.
--
-- `role` here mirrors the role resolved from the token at last sign-in. It is
-- audit/reporting state only — authorization always reads the current token, so
-- this column must never be treated as a cached allow/deny verdict.

ALTER TABLE ztpa.app_users ADD COLUMN IF NOT EXISTS sso_sub        text;
ALTER TABLE ztpa.app_users ADD COLUMN IF NOT EXISTS sso_app_roles  text[] NOT NULL DEFAULT '{}';
ALTER TABLE ztpa.app_users ADD COLUMN IF NOT EXISTS sso_org_type   text;
ALTER TABLE ztpa.app_users ADD COLUMN IF NOT EXISTS is_ey_employee boolean;
ALTER TABLE ztpa.app_users ADD COLUMN IF NOT EXISTS last_login_at  timestamptz;

-- One local row per AutoX subject. Partial index so legacy local-only users
-- (sso_sub IS NULL) are unaffected.
CREATE UNIQUE INDEX IF NOT EXISTS uq_ztpa_app_users_sso_sub
    ON ztpa.app_users (sso_sub) WHERE sso_sub IS NOT NULL;

-- SSO users never have a local password; the column is already nullable.
-- A user with no app role can still exist locally with role NULL, so drop the
-- NOT NULL and let the CHECK allow NULL.
ALTER TABLE ztpa.app_users ALTER COLUMN role DROP NOT NULL;

ALTER TABLE ztpa.app_users DROP CONSTRAINT IF EXISTS app_users_role_check;

ALTER TABLE ztpa.app_users
    ADD CONSTRAINT app_users_role_check
    CHECK (role IS NULL OR role IN ('admin', 'analyst', 'viewer'));
