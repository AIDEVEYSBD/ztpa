"use server";

import { auth } from "@/auth";
import { getBaseUrl } from "@/lib/baseurl";
import { emails } from "@/lib/email";
import { consumeToken, createToken } from "@/lib/tokens";
import { isAdmin } from "@/lib/roles";
import { localLoginEnabled } from "@/lib/sso";
import { createUser, getUserByEmail, listUsers, setPassword, type AppUser, type Role } from "@/lib/users";

/**
 * The result shape every auth action returns.
 *
 * `devLink` is declared and permanently absent. A server action's return value
 * is serialized to the BROWSER, and on any pre-SSO or cutover deployment the
 * magic-link form is reachable unauthenticated — so returning a live sign-in
 * token there was a ten-second account takeover of any address an attacker can
 * name, the admin's included. The link is printed to the server console in
 * development instead (`logDevLink`). The optional-never keeps existing readers
 * compiling, and makes it a type error to ever put a token back in.
 */
export interface AuthActionResult {
  ok: boolean;
  error?: string;
  devLink?: never;
}

/** Every path through the sign-in actions answers with THIS value. Identical
 *  shape for a known address, an unknown one, a disabled account and an
 *  SSO-only deployment, so the response cannot be used to enumerate users. */
const ACCEPTED: AuthActionResult = { ok: true };

/** Print a one-time link to the SERVER console, in development only. It never
 *  crosses the network boundary to the browser. */
function logDevLink(kind: string, email: string, sent: unknown): void {
  if (process.env.NODE_ENV === "production") return;
  const link = (sent as { devLink?: string } | null)?.devLink;
  if (link) console.log(`[dev ${kind} link] ${email}: ${link}`);
}

export async function requestMagic(email: string): Promise<AuthActionResult> {
  if (!localLoginEnabled()) return ACCEPTED; // SSO owns sign-in; don't mint bypass links
  const u = await getUserByEmail(email);
  // Only send if the user can sign in — but answer identically either way.
  if (u && u.status !== "disabled") {
    const token = await createToken(email, "magic");
    logDevLink("magic", u.email, await emails.magic(u.email, `${getBaseUrl()}/login/magic?token=${token}`));
  }
  return ACCEPTED;
}

export async function requestReset(email: string): Promise<AuthActionResult> {
  if (!localLoginEnabled()) return ACCEPTED;
  const u = await getUserByEmail(email);
  if (u && u.status !== "disabled") {
    const token = await createToken(email, "reset");
    logDevLink("reset", u.email, await emails.reset(u.email, `${getBaseUrl()}/reset?token=${token}`));
  }
  return ACCEPTED;
}

export async function doReset(token: string, password: string): Promise<AuthActionResult> {
  if (!localLoginEnabled()) return { ok: false, error: "Passwords are managed in AutoX SSO." };
  if (!password || password.length < 8) return { ok: false, error: "Password must be at least 8 characters." };
  const email = await consumeToken(token, "reset");
  if (!email) return { ok: false, error: "This link is invalid or has expired." };
  await setPassword(email, password);
  return { ok: true };
}

async function requireAdmin() {
  const session = await auth();
  return isAdmin((session?.user as any)?.role) ? session : null;
}

export async function adminCreateUser(email: string, name: string, role: Role): Promise<AuthActionResult> {
  const session = await requireAdmin();
  if (!session) return { ok: false, error: "Not authorized." };
  // Under SSO, membership and roles are granted in the AutoX admin, not here —
  // an invite would create a local row nobody can sign into.
  if (!localLoginEnabled()) {
    return { ok: false, error: "Users and roles are managed in AutoX SSO. Assign an application role there." };
  }
  if (!email) return { ok: false, error: "Email is required." };
  const invitee = email.toLowerCase().trim();
  await createUser(email, name || null, role, (session.user as any).email);
  const token = await createToken(email, "invite", 60 * 24); // 24h
  // Same rule as the sign-in links: an invite token is a credential. It goes to
  // the invitee's inbox, or to the dev console — never back over the wire.
  logDevLink("invite", invitee, await emails.invite(invitee, `${getBaseUrl()}/login/magic?token=${token}`, role));
  return { ok: true };
}

/**
 * The user list, or the reason there isn't one.
 *
 * Why a result object rather than `AppUser[]`: this used to answer `[]` for a
 * caller holding no admin role, and the console rendered that as "Users (0)"
 * and "No users yet" — a claim about the tenant manufactured out of an
 * authorization failure. Throwing is no better here: a server action's
 * exception reaches the browser as an opaque `digest` in a production build,
 * so the reason has to travel in the RETURN value to survive. `status` carries
 * the HTTP-shaped fact the client's error panel needs to tell "you may not"
 * (403, amber) apart from "it broke" (500, red).
 */
export type AdminUsersResult =
  | { ok: true; users: AppUser[] }
  | { ok: false; status: number; error: string };

export async function adminListUsers(): Promise<AdminUsersResult> {
  const session = await requireAdmin();
  if (!session) return { ok: false, status: 403, error: "Your role may not list users." };
  try {
    return { ok: true, users: await listUsers() };
  } catch (e) {
    // A dead database must not be reported as an empty directory.
    return { ok: false, status: 500, error: e instanceof Error && e.message ? e.message : "The user directory could not be read." };
  }
}
