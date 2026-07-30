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

/** Local password/magic-link login. Off automatically once SSO is configured;
 *  `AUTH_LOCAL_LOGIN=true` keeps it on (useful during cutover). */
export const localLoginEnabled = (): boolean =>
  process.env.AUTH_LOCAL_LOGIN === "true" || !ssoEnabled();

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
