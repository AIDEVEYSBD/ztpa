import bcrypt from "bcryptjs";
import { q } from "./db";

export type Role = "admin" | "analyst" | "viewer";

export interface AppUser {
  id: string;
  email: string;
  name: string | null;
  role: Role;
  status: "invited" | "active" | "disabled";
  password_hash?: string | null;
  created_at?: string;
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
