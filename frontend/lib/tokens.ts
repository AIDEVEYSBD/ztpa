import crypto from "crypto";
import { q } from "./db";

export type Purpose = "magic" | "reset" | "invite";

export async function createToken(email: string, purpose: Purpose, ttlMinutes = 30): Promise<string> {
  const token = crypto.randomBytes(32).toString("base64url");
  const expires = new Date(Date.now() + ttlMinutes * 60_000).toISOString();
  await q("INSERT INTO ztpa.auth_tokens (token, email, purpose, expires) VALUES ($1, $2, $3, $4)",
    [token, email.toLowerCase().trim(), purpose, expires]);
  return token;
}

interface TokenRow { email: string; purpose: string; expires: string; used: boolean }

/** Validate + single-use consume. Activates an invited user on success. Returns email or null. */
export async function consumeToken(token: string, purposes: Purpose | Purpose[]): Promise<string | null> {
  const allow = Array.isArray(purposes) ? purposes : [purposes];
  const rows = await q<TokenRow>("SELECT email, purpose, expires, used FROM ztpa.auth_tokens WHERE token = $1", [token]);
  const t = rows[0];
  if (!t || t.used || !allow.includes(t.purpose as Purpose) || new Date(t.expires) < new Date()) return null;
  await q("UPDATE ztpa.auth_tokens SET used = true WHERE token = $1", [token]);
  await q("UPDATE ztpa.app_users SET status = 'active', email_verified = now() WHERE email = $1 AND status = 'invited'", [t.email]);
  return t.email;
}
