"use server";

import { auth } from "@/auth";
import { getBaseUrl } from "@/lib/baseurl";
import { emails } from "@/lib/email";
import { consumeToken, createToken } from "@/lib/tokens";
import { createUser, getUserByEmail, listUsers, setPassword, type Role } from "@/lib/users";

export async function requestMagic(email: string) {
  const u = await getUserByEmail(email);
  // Always return ok (don't leak which emails exist); only send if the user can sign in.
  if (u && u.status !== "disabled") {
    const token = await createToken(email, "magic");
    const r = await emails.magic(u.email, `${getBaseUrl()}/login/magic?token=${token}`);
    return { ok: true, devLink: (r as any).devLink as string | undefined };
  }
  return { ok: true };
}

export async function requestReset(email: string) {
  const u = await getUserByEmail(email);
  if (u && u.status !== "disabled") {
    const token = await createToken(email, "reset");
    const r = await emails.reset(u.email, `${getBaseUrl()}/reset?token=${token}`);
    return { ok: true, devLink: (r as any).devLink as string | undefined };
  }
  return { ok: true };
}

export async function doReset(token: string, password: string) {
  if (!password || password.length < 8) return { ok: false, error: "Password must be at least 8 characters." };
  const email = await consumeToken(token, "reset");
  if (!email) return { ok: false, error: "This link is invalid or has expired." };
  await setPassword(email, password);
  return { ok: true };
}

async function requireAdmin() {
  const session = await auth();
  const role = (session?.user as any)?.role;
  return role === "admin" ? session : null;
}

export async function adminCreateUser(email: string, name: string, role: Role) {
  const session = await requireAdmin();
  if (!session) return { ok: false, error: "Not authorized." };
  if (!email) return { ok: false, error: "Email is required." };
  await createUser(email, name || null, role, (session.user as any).email);
  const token = await createToken(email, "invite", 60 * 24); // 24h
  const r = await emails.invite(email.toLowerCase().trim(), `${getBaseUrl()}/login/magic?token=${token}`, role);
  return { ok: true, devLink: (r as any).devLink as string | undefined };
}

export async function adminListUsers() {
  const session = await requireAdmin();
  if (!session) return [];
  return listUsers();
}
