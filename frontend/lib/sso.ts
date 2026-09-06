/** AutoX SSO (OIDC) wiring — https://sso.autogrc.cloud/integration.md
 *
 * Edge-safe: imported by `auth.config.ts`, which the middleware loads. No DB, no
 * node built-ins.
 *
 * The one non-obvious requirement: the access token is OPAQUE by default. To get
 * a JWT carrying `autox:app_roles`, `resource=<SSO_RESOURCE>` must be sent on
 * BOTH the /auth request and the /token exchange. Sending it only at /auth
 * silently yields an opaque token — which reads as "user has no roles". See
 * `auth.autox.ts` for the token-leg injection.
 */

import type { AppRole } from "./roles";

export const SSO_ISSUER = (process.env.SSO_ISSUER || "https://sso.autogrc.cloud").replace(/\/+$/, "");
export const SSO_DISCOVERY = `${SSO_ISSUER}/.well-known/openid-configuration`;

/** Audience that turns the access token into a JWT. Must reach /auth AND /token. */
export const SSO_RESOURCE = process.env.SSO_RESOURCE || `${SSO_ISSUER}/api`;

/** `orgs` + `roles` are what populate autox:orgs / autox:roles. We do not request
 *  `offline_access`: no refresh tokens means no rotation/reuse-detection races,
 *  and role changes are picked up by re-authorizing (see SSO_SESSION_MAX_AGE). */
export const SSO_SCOPE = process.env.SSO_SCOPE || "openid profile email orgs roles";

export const SSO_CLIENT_ID = process.env.SSO_CLIENT_ID || "";
export const SSO_CLIENT_SECRET = process.env.SSO_CLIENT_SECRET || "";

/** SSO is live once a client_id is registered. */
export const ssoEnabled = (): boolean => !!SSO_CLIENT_ID;

// --- break-glass -----------------------------------------------------------
//
// THIS IS THE ONLY WAY IN THAT DOES NOT GO THROUGH AUTOX, AND IT IS OFF.
//
// Password sign-in and magic links are gone; AutoX is the sole identity
// provider. That is the decision, and it has a consequence nobody can wish
// away: a broken SSO client registration, a rotated secret, an AutoX outage or
// a mistyped `SSO_ISSUER` locks every operator out of a running deployment with
// no way back in. `docs/BREAKGLASS.md` is the recovery, and this is the code it
// drives.
//
// Three properties it must have, and each one is a deliberate choice below:
//
//  1. **Off unless someone armed it.** The predecessor (`localLoginEnabled`)
//     returned TRUE whenever SSO was not configured, so the shipped default of
//     a fresh clone -- and of the live deployment, which has no `SSO_*` var set
//     -- was "password login is on". Under SSO-only that default would silently
//     preserve the very bypass this workstream removes. It is now the literal
//     string "true" in `AUTH_LOCAL_LOGIN` and nothing else. Never derive it from
//     the absence of another setting.
//
//  2. **No credential in the database.** The old path compared bcrypt hashes in
//     `ztpa.app_users.password_hash`; migration 0005 drops that column. The
//     break-glass credential lives ONLY in the platform's secret store (a
//     Container Apps secret), so a database compromise yields no login and there
//     is no dormant password sitting in a table waiting to be found. It also
//     means break-glass works when the database is down -- the session is minted
//     from configuration alone, and mirroring the sign-in into `app_users` is a
//     best-effort side effect exactly as it is for AutoX.
//
//  3. **Distinguishable in the audit trail.** A break-glass session carries
//     `sub = breakglass:<email>`, never an AutoX subject, so `audit_log
//     .actor_sub` says which door was used.
//
// The name `AUTH_LOCAL_LOGIN` is reused rather than invented because
// `scripts/azure/deploy.sh` already plumbs it to the Container App, so the
// recovery in docs/BREAKGLASS.md needs no deploy-script change to work today.
// Its MEANING changed -- it no longer means "keep the old login for everyone".

/** The single identity break-glass can authenticate. Lowercased, since it is
 *  compared against operator-typed input and stamped into the audit trail. */
export const BREAKGLASS_EMAIL = (process.env.BREAKGLASS_EMAIL || "").trim().toLowerCase();

/** bcrypt hash of the break-glass password (preferred: the plaintext then never
 *  appears in shell history, a deployment template or `az` output). */
export const BREAKGLASS_PASSWORD_HASH = (process.env.BREAKGLASS_PASSWORD_HASH || "").trim();

/** Plaintext fallback. Accepted on purpose: a recovery that fails because the
 *  operator could not produce a bcrypt hash at 3am is not a recovery. It is
 *  logged as a warning on every use so it cannot become the normal state. */
export const BREAKGLASS_PASSWORD = process.env.BREAKGLASS_PASSWORD || "";

/** Absolute lifetime of a break-glass session. Deliberately short and NOT
 *  extended by activity: if an operator forgets to disarm the flag, the sessions
 *  it minted still die. Default 15 minutes. */
export const BREAKGLASS_SESSION_MAX_AGE = Number(process.env.BREAKGLASS_SESSION_MAX_AGE || 900);

/** The `sub` a break-glass session carries. Prefixed so no AutoX subject can
 *  ever collide with it and so the audit trail is greppable. */
export const breakGlassSub = (email: string): string => `breakglass:${email}`;

/** Is `sub` a break-glass identity? Used by anything reading the audit trail. */
export const isBreakGlassSub = (sub: string | null | undefined): boolean =>
  typeof sub === "string" && sub.startsWith("breakglass:");

/**
 * Why the login screen shows what it shows.
 *
 * `armed but not usable` is a state in its own right, and it must be visible:
 * an operator who flipped the flag and forgot the credential would otherwise
 * see a sign-in page with nothing on it and no idea why.
 */
export type BreakGlassState =
  | { armed: false }
  | { armed: true; usable: false; reason: string }
  | { armed: true; usable: true; email: string };

export function breakGlassState(): BreakGlassState {
  if (process.env.AUTH_LOCAL_LOGIN !== "true") return { armed: false };
  if (!BREAKGLASS_EMAIL) {
    return { armed: true, usable: false, reason: "BREAKGLASS_EMAIL is not set." };
  }
  if (!BREAKGLASS_PASSWORD_HASH && !BREAKGLASS_PASSWORD) {
    return {
      armed: true,
      usable: false,
      reason: "Neither BREAKGLASS_PASSWORD_HASH nor BREAKGLASS_PASSWORD is set.",
    };
  }
  return { armed: true, usable: true, email: BREAKGLASS_EMAIL };
}

/** Break-glass can actually authenticate someone right now. */
export const breakGlassEnabled = (): boolean => {
  const s = breakGlassState();
  return s.armed && s.usable;
};

/** Absolute lifetime of a signed-in session, in seconds. This is the role-freshness
 *  knob: AutoX role grants/revocations only appear in NEWLY minted tokens, so the
 *  session is capped and the user is bounced through /auth again (silently, while
 *  their SSO session is alive) to pick up changes. Default 1h. */
export const SSO_SESSION_MAX_AGE = Number(process.env.SSO_SESSION_MAX_AGE || 3600);

// --- token helpers ---------------------------------------------------------

function b64urlDecode(part: string): string {
  const b64 = part.replace(/-/g, "+").replace(/_/g, "/").padEnd(Math.ceil(part.length / 4) * 4, "=");
  const bin = atob(b64);
  const bytes = Uint8Array.from(bin, (c) => c.charCodeAt(0));
  return new TextDecoder().decode(bytes);
}

/** Decode (NOT verify) a JWT payload. Only ever used on tokens we received
 *  straight from the SSO token endpoint over TLS — the ID token's signature is
 *  verified by Auth.js/oauth4webapi against the JWKS before we get here. */
export function decodeJwtPayload(token: string | undefined | null): Record<string, any> | null {
  if (!token) return null;
  const parts = token.split(".");
  if (parts.length !== 3) return null; // opaque token
  try {
    const claims = JSON.parse(b64urlDecode(parts[1]));
    return claims && typeof claims === "object" ? claims : null;
  } catch {
    return null;
  }
}

export interface SsoIdentity {
  sub: string | null;
  email: string | null;
  emailVerified: boolean;
  name: string | null;
  isEyEmployee: boolean | null;
  orgType: string | null;
  /** Global directory roles (autox:roles) — kept for display/audit only. */
  directoryRoles: string[];
}

export function identityFromIdToken(claims: Record<string, any> | null | undefined): SsoIdentity {
  const c = claims ?? {};
  return {
    sub: typeof c.sub === "string" ? c.sub : null,
    email: typeof c.email === "string" ? c.email.toLowerCase() : null,
    emailVerified: c.email_verified === true,
    name: c.name || c.preferred_username || null,
    isEyEmployee: typeof c["autox:is_ey_employee"] === "boolean" ? c["autox:is_ey_employee"] : null,
    orgType: typeof c["autox:org_type"] === "string" ? c["autox:org_type"] : null,
    directoryRoles: Array.isArray(c["autox:roles"]) ? c["autox:roles"].map(String) : [],
  };
}

export type AppRolesRead =
  | { kind: "jwt"; roles: string[] }
  /** Access token came back opaque -> `resource` did not reach both legs. This is
   *  a configuration fault, NOT "the user has no roles". */
  | { kind: "opaque" };

/** Read `autox:app_roles` out of the JWT access token. */
export function readAppRoles(accessToken: string | undefined | null): AppRolesRead {
  const claims = decodeJwtPayload(accessToken);
  if (!claims) return { kind: "opaque" };
  const raw = claims["autox:app_roles"];
  // The claim is absent (not empty) when no roles are assigned.
  return { kind: "jwt", roles: Array.isArray(raw) ? raw.map(String) : [] };
}

// --- logout ----------------------------------------------------------------

/** RP-initiated logout. Without `id_token_hint` the SSO cannot identify the
 *  client, cannot validate `post_logout_redirect_uri`, and will not return. */
export function endSessionUrl(opts: { idToken?: string | null; postLogoutRedirectUri?: string; state?: string }): string {
  const url = new URL(`${SSO_ISSUER}/session/end`);
  if (opts.idToken) url.searchParams.set("id_token_hint", opts.idToken);
  if (opts.postLogoutRedirectUri) url.searchParams.set("post_logout_redirect_uri", opts.postLogoutRedirectUri);
  if (opts.state) url.searchParams.set("state", opts.state);
  return url.toString();
}

// --- cold start ------------------------------------------------------------

export type SsoHealth = "live" | "waking";

/** Probe before redirecting a user into a scale-to-zero SSO. "Live" requires the
 *  app's OWN JSON body: Render's cold-start page is an HTML 503, and Cloud Run
 *  queues the request and answers slowly with a 200, so status alone lies. */
export async function ssoHealth(timeoutMs = 4000): Promise<SsoHealth> {
  try {
    const r = await fetch(`${SSO_ISSUER}/health`, {
      cache: "no-store",
      redirect: "manual",
      signal: AbortSignal.timeout(timeoutMs),
    });
    if (!r.ok) return "waking";
    if (!(r.headers.get("content-type") || "").includes("application/json")) return "waking";
    const body = (await r.json()) as { status?: string };
    return body?.status === "ok" ? "live" : "waking";
  } catch {
    return "waking"; // timeout, hang, connection error
  }
}

// --- session shape ---------------------------------------------------------

/** Non-secret SSO context we expose on the session (never the ID/access token). */
export interface SsoSessionInfo {
  sub: string;
  appRoles: string[];
  unmapped: string[];
  isEyEmployee: boolean | null;
  orgType: string | null;
  /** true => the access token was opaque; `resource` is missing on a leg. */
  misconfigured: boolean;
  /** epoch seconds at which this session stops being trusted and must re-authorize */
  reauthAt: number;
}

export interface SsoSessionUser {
  id: string;
  email: string | null;
  name: string | null;
  role: AppRole | null;
}
