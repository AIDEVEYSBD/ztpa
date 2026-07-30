import bcrypt from "bcryptjs";
import { q } from "./db";
import type { AppRole } from "./roles";

export type Role = AppRole;

export interface AppUser {
  id: string;
  email: string;
  name: string | null;
  role: Role | null;
  status: "invited" | "active" | "disabled";
  password_hash?: string | null;
  created_at?: string;
  sso_sub?: string | null;
  sso_app_roles?: string[] | null;
  last_login_at?: string | null;
}

export async function getUserByEmail(email: string): Promise<AppUser | null> {
  const rows = await q<AppUser>("SELECT * FROM ztpa.app_users WHERE email = $1", [email.toLowerCase().trim()]);
  return rows[0] ?? null;
}

export async function verifyUserPassword(email: string, password: string): Promise<AppUser | null> {
  const u = await getUserByEmail(email);
  if (!u || u.status === "disabled" || !u.password_hash) return null;
  return (await bcrypt.compare(password, u.password_hash)) ? u : null;
}

export async function setPassword(email: string, password: string): Promise<void> {
  const hash = await bcrypt.hash(password, 10);
  await q(
    "UPDATE ztpa.app_users SET password_hash = $1, status = 'active', email_verified = now() WHERE email = $2",
    [hash, email.toLowerCase().trim()],
  );
}

export async function createUser(email: string, name: string | null, role: Role, createdBy: string | null): Promise<AppUser | null> {
  await q(
    `INSERT INTO ztpa.app_users (email, name, role, created_by) VALUES ($1, $2, $3, $4)
     ON CONFLICT (email) DO UPDATE SET name = EXCLUDED.name, role = EXCLUDED.role`,
    [email.toLowerCase().trim(), name, role, createdBy],
  );
  return getUserByEmail(email);
}

export async function listUsers(): Promise<AppUser[]> {
  return q<AppUser>("SELECT id, email, name, role, status, created_at FROM ztpa.app_users ORDER BY created_at");
}

export async function setStatus(email: string, status: AppUser["status"]): Promise<void> {
  await q("UPDATE ztpa.app_users SET status = $1 WHERE email = $2", [status, email.toLowerCase().trim()]);
}

export async function countUsers(): Promise<number> {
  const rows = await q<{ n: string }>("SELECT count(*)::int AS n FROM ztpa.app_users");
  return Number(rows[0]?.n ?? 0);
}

// --- AutoX SSO provisioning -------------------------------------------------

export interface SsoProvisionInput {
  sub: string;
  email: string | null;
  emailVerified: boolean;
  name: string | null;
  /** Role resolved from autox:app_roles; null when the user holds none. */
  role: Role | null;
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
 *      -> adopt it, so migrating users keep their history
 *   3. otherwise -> insert
 *
 * Email adoption is deliberately narrow: it requires email_verified and only
 * ever claims rows that have no sso_sub yet.
 */
export async function provisionSsoUser(input: SsoProvisionInput): Promise<void> {
  const email = input.email?.toLowerCase().trim() || null;
  const roles = input.appRoles ?? [];

  const linked = await q<{ id: string }>("SELECT id FROM ztpa.app_users WHERE sso_sub = $1", [input.sub]);
  if (linked[0]) {
    await q(
      `UPDATE ztpa.app_users
          SET email = COALESCE($2, email), name = COALESCE($3, name), role = $4,
              sso_app_roles = $5, is_ey_employee = $6, sso_org_type = $7,
              status = 'active', last_login_at = now()
        WHERE id = $1`,
      [linked[0].id, email, input.name, input.role, roles, input.isEyEmployee, input.orgType],
    );
    return;
  }

  if (email && input.emailVerified) {
    const adopted = await q<{ id: string }>(
      `UPDATE ztpa.app_users
          SET sso_sub = $1, name = COALESCE($3, name), role = $4, sso_app_roles = $5,
              is_ey_employee = $6, sso_org_type = $7, status = 'active',
              password_hash = NULL, last_login_at = now()
        WHERE lower(email) = $2 AND sso_sub IS NULL
        RETURNING id`,
      [input.sub, email, input.name, input.role, roles, input.isEyEmployee, input.orgType],
    );
    if (adopted[0]) return;
  }

  await q(
    `INSERT INTO ztpa.app_users
        (email, name, role, status, sso_sub, sso_app_roles, is_ey_employee, sso_org_type, last_login_at, created_by)
     VALUES ($1, $2, $3, 'active', $4, $5, $6, $7, now(), 'autox-sso')
     ON CONFLICT (email) DO UPDATE
        SET sso_sub = EXCLUDED.sso_sub, name = COALESCE(EXCLUDED.name, ztpa.app_users.name),
            role = EXCLUDED.role, sso_app_roles = EXCLUDED.sso_app_roles,
            is_ey_employee = EXCLUDED.is_ey_employee, sso_org_type = EXCLUDED.sso_org_type,
            status = 'active', last_login_at = now()
        -- never re-point a row that already belongs to a DIFFERENT AutoX subject
        WHERE ztpa.app_users.sso_sub IS NULL OR ztpa.app_users.sso_sub = EXCLUDED.sso_sub`,
    [email ?? `${input.sub}@sso.local`, input.name, input.role, input.sub, roles, input.isEyEmployee, input.orgType],
  );
}
