/**
 * `ztpa.app_users` — the READ-ONLY MIRROR of who has signed in.
 *
 * WHAT THIS TABLE IS NOW, AND WHY IT SURVIVED SSO-ONLY.
 *
 * Authorization does not read it. Membership does not read it. Roles come from
 * the `autox:app_roles` claim on every request's token and from nowhere else,
 * so this table cannot grant, deny or cache access — `db/sso_schema.sql` says
 * the same thing about its `role` column.
 *
 * It is kept because the AUDIT TRAIL depends on the projection existing.
 * `db/migrations/0002_audit_identity.sql` added `audit_log.actor_email` /
 * `actor_sub` / `actor_role` to turn an event log into a compliance record;
 * those columns are deliberately text and not a foreign key ("the trail must
 * outlive the account"), and this table is what turns a bare AutoX subject in
 * the trail back into a person — first seen, last seen, what roles their token
 * carried at the time. Drop it and sign-in still writes nothing, but every
 * historical `actor_sub` becomes an opaque uuid nobody can resolve.
 *
 * So: written on every successful authentication, read by humans and reports,
 * never consulted to decide anything. The write is a SIDE EFFECT and is allowed
 * to fail — see `provisionSsoUser`, and `auth.ts`, which treats a throw here as
 * non-fatal so a database problem can never lock out a valid user.
 *
 * What used to be here and is gone with local login: `verifyUserPassword`,
 * `setPassword`, `createUser`, `listUsers`, `setStatus`, `countUsers`,
 * `getUserByEmail`. Their table columns went with them
 * (`db/migrations/0005_drop_local_auth.sql` drops `password_hash`).
 */

import { q } from "./db";
import type { AppRole } from "./roles";
import { breakGlassSub } from "./sso";

export interface SsoProvisionInput {
  /** AutoX `sub` — the primary key of the mirror. Never email. */
  sub: string;
  email: string | null;
  emailVerified: boolean;
  name: string | null;
  /** Role resolved from autox:app_roles; null when the user holds none. */
  role: AppRole | null;
  appRoles: string[];
  isEyEmployee: boolean | null;
  orgType: string | null;
}

/**
 * Mirror an authenticated AutoX user into ztpa.app_users, keyed on `sub`.
 *
 * Never gates sign-in — the caller treats a throw as non-fatal. Three paths:
 *   1. row already linked to this `sub`  -> refresh its attributes
 *   2. a pre-existing UNLINKED local row with the same (verified) email
 *      -> adopt it, so users who predate SSO keep their history
 *   3. otherwise -> insert
 *
 * Email adoption is deliberately narrow: it requires email_verified and only
 * ever claims rows that have no sso_sub yet. It survives the removal of local
 * login because the rows it adopts do — `0005_drop_local_auth.sql` drops the
 * password column, not the people.
 *
 * `email_verified` is stamped from the AutoX `email_verified` claim and only
 * ever forward: it used to be written by the magic-link/reset flow, and when
 * that went the column would have become write-never. COALESCE, not an
 * overwrite — a claim that arrives false must not erase a verification that
 * already happened.
 */
export async function provisionSsoUser(input: SsoProvisionInput): Promise<void> {
  const email = input.email?.toLowerCase().trim() || null;
  const roles = input.appRoles ?? [];
  const verifiedAt = input.emailVerified ? new Date() : null;

  const linked = await q<{ id: string }>("SELECT id FROM ztpa.app_users WHERE sso_sub = $1", [input.sub]);
  if (linked[0]) {
    await q(
      `UPDATE ztpa.app_users
          SET email = COALESCE($2, email), name = COALESCE($3, name), role = $4,
              sso_app_roles = $5, is_ey_employee = $6, sso_org_type = $7,
              email_verified = COALESCE(email_verified, $8),
              status = 'active', last_login_at = now()
        WHERE id = $1`,
      [linked[0].id, email, input.name, input.role, roles, input.isEyEmployee, input.orgType, verifiedAt],
    );
    return;
  }

  if (email && input.emailVerified) {
    const adopted = await q<{ id: string }>(
      `UPDATE ztpa.app_users
          SET sso_sub = $1, name = COALESCE($3, name), role = $4, sso_app_roles = $5,
              is_ey_employee = $6, sso_org_type = $7, status = 'active',
              email_verified = COALESCE(email_verified, now()), last_login_at = now()
        WHERE lower(email) = $2 AND sso_sub IS NULL
        RETURNING id`,
      [input.sub, email, input.name, input.role, roles, input.isEyEmployee, input.orgType],
    );
    if (adopted[0]) return;
  }

  await q(
    `INSERT INTO ztpa.app_users
        (email, name, role, status, sso_sub, sso_app_roles, is_ey_employee, sso_org_type,
         email_verified, last_login_at, created_by)
     VALUES ($1, $2, $3, 'active', $4, $5, $6, $7, $8, now(), 'autox-sso')
     ON CONFLICT (email) DO UPDATE
        SET sso_sub = EXCLUDED.sso_sub, name = COALESCE(EXCLUDED.name, ztpa.app_users.name),
            role = EXCLUDED.role, sso_app_roles = EXCLUDED.sso_app_roles,
            is_ey_employee = EXCLUDED.is_ey_employee, sso_org_type = EXCLUDED.sso_org_type,
            email_verified = COALESCE(ztpa.app_users.email_verified, EXCLUDED.email_verified),
            status = 'active', last_login_at = now()
        -- never re-point a row that already belongs to a DIFFERENT AutoX subject
        WHERE ztpa.app_users.sso_sub IS NULL OR ztpa.app_users.sso_sub = EXCLUDED.sso_sub`,
    [email ?? `${input.sub}@sso.local`, input.name, input.role, input.sub, roles,
     input.isEyEmployee, input.orgType, verifiedAt],
  );
}

/**
 * Mirror a BREAK-GLASS sign-in (docs/BREAKGLASS.md).
 *
 * Same table, same side-effect contract — but it must be visible at a glance
 * that this row was not an AutoX authentication. `sso_sub` is
 * `breakglass:<email>`, `sso_app_roles` is `{breakglass}` and `created_by` is
 * `breakglass`, so "did anyone use the emergency door, and when" is one query:
 *
 *     SELECT email, last_login_at FROM ztpa.app_users WHERE sso_sub LIKE 'breakglass:%';
 *
 * The row is a record, never a permission: the admin role on a break-glass
 * session comes from `auth.ts` having verified the configured credential, and
 * writing this row is allowed to fail without affecting the sign-in.
 */
export async function provisionBreakGlassUser(email: string): Promise<void> {
  const addr = email.toLowerCase().trim();
  await q(
    `INSERT INTO ztpa.app_users
        (email, name, role, status, sso_sub, sso_app_roles, last_login_at, created_by)
     VALUES ($1, 'Break-glass operator', 'admin', 'active', $2, '{breakglass}', now(), 'breakglass')
     ON CONFLICT (email) DO UPDATE
        SET role = 'admin', status = 'active', last_login_at = now()
        WHERE ztpa.app_users.sso_sub IS NULL OR ztpa.app_users.sso_sub = EXCLUDED.sso_sub`,
    [addr, breakGlassSub(addr)],
  );
}
