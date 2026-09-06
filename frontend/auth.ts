import NextAuth, { type NextAuthConfig } from "next-auth";
import Credentials from "next-auth/providers/credentials";
import bcrypt from "bcryptjs";
import authConfig from "./auth.config";
import { autox } from "./auth.autox";
import { provisionBreakGlassUser, provisionSsoUser } from "@/lib/users";
import {
  BREAKGLASS_EMAIL, BREAKGLASS_PASSWORD, BREAKGLASS_PASSWORD_HASH,
  breakGlassEnabled, breakGlassSub, identityFromIdToken, readAppRoles, ssoEnabled,
} from "@/lib/sso";
import { resolveRole } from "@/lib/roles";

/**
 * SSO-ONLY. AutoX is the identity provider; there is no password directory, no
 * magic link, no invite and no reset. The only other provider that can ever be
 * registered is the break-glass credential below, and it is off unless an
 * operator armed it.
 *
 * What was removed and why it cannot come back by accident:
 *   - `Credentials({ id: "password" })` verified `app_users.password_hash`.
 *     Migration 0005 drops the column, so the query has nothing to read.
 *   - `Credentials({ id: "magic" })` consumed a row in `ztpa.auth_tokens`.
 *     Migration 0005 drops the table, and `lib/tokens.ts` is deleted.
 *   Both providers were registered by `localLoginEnabled()`, which returned TRUE
 *   whenever SSO was unconfigured — i.e. by default. See lib/sso.ts.
 */

// --- break-glass credential -------------------------------------------------

/**
 * Failed-attempt brake. bcrypt at cost 10 already caps an online guesser at
 * roughly ten tries a second per instance, but a break-glass window is exactly
 * when nobody is watching the logs, so the door also shuts itself.
 *
 * In-process and per-instance ON PURPOSE, and its limits are stated rather than
 * papered over: a multi-replica frontend multiplies the budget by the replica
 * count, and a restart clears it. It is defence in depth on top of a strong
 * configured password, not the reason the password may be weak. A shared
 * counter would need the database, and break-glass must work when the database
 * is the thing that is broken.
 */
const MAX_ATTEMPTS = 5;
// Five minutes, not fifteen: the person most likely to trip this is the operator
// mistyping under pressure, and locking the recovery path for a quarter of an
// hour during an incident costs more than it buys. 5 tries / 5 minutes is 1440
// guesses a day against a credential the operator generated minutes earlier. A
// restart of the revision clears it (docs/BREAKGLASS.md says so).
const LOCKOUT_MS = 5 * 60_000;
let failures = 0;
let lockedUntil = 0;

/** Length-independent equality for the plaintext branch. `bcrypt.compare` is
 *  already constant-time for the hash branch. */
function timingSafeEqual(a: string, b: string): boolean {
  // Compare the same number of bytes regardless of input length: XOR-accumulate
  // over the longer of the two, so an early mismatch costs the same as a late one.
  const n = Math.max(a.length, b.length);
  let diff = a.length ^ b.length;
  for (let i = 0; i < n; i++) diff |= (a.charCodeAt(i) || 0) ^ (b.charCodeAt(i) || 0);
  return diff === 0;
}

/**
 * The emergency door. Registered ONLY when `AUTH_LOCAL_LOGIN=true` and a
 * credential is configured (`lib/sso.breakGlassState`), so on a normal
 * deployment this provider does not exist and `/api/auth/callback/breakglass`
 * is not a route.
 *
 * Every outcome is logged at error level, successes included: the point of a
 * break-glass path is that using it is loud.
 */
const breakGlass = Credentials({
  id: "breakglass",
  name: "Break-glass",
  credentials: { email: {}, password: {} },
  authorize: async (c) => {
    const email = String(c?.email || "").trim().toLowerCase();
    const password = String(c?.password || "");

    if (Date.now() < lockedUntil) {
      console.error(
        `[breakglass] REFUSED (locked out for another ${Math.ceil((lockedUntil - Date.now()) / 1000)}s ` +
        `after ${MAX_ATTEMPTS} failed attempts) email=${email || "(blank)"}`,
      );
      return null;
    }

    // Both halves must match, and the email is checked in constant time too so
    // the response cannot be used to confirm the configured address.
    const emailOk = timingSafeEqual(email, BREAKGLASS_EMAIL);
    const passwordOk = BREAKGLASS_PASSWORD_HASH
      ? await bcrypt.compare(password, BREAKGLASS_PASSWORD_HASH).catch(() => false)
      : timingSafeEqual(password, BREAKGLASS_PASSWORD);

    if (!emailOk || !passwordOk) {
      failures += 1;
      if (failures >= MAX_ATTEMPTS) {
        lockedUntil = Date.now() + LOCKOUT_MS;
        failures = 0;
        console.error(`[breakglass] FAILED sign-in; locking this instance out for ${LOCKOUT_MS / 60000} minutes (restart the revision to clear it)`);
      } else {
        console.error(`[breakglass] FAILED sign-in attempt ${failures}/${MAX_ATTEMPTS} email=${email || "(blank)"}`);
      }
      return null;
    }

    failures = 0;
    if (!BREAKGLASS_PASSWORD_HASH) {
      console.error(
        "[breakglass] the credential is configured as PLAINTEXT (BREAKGLASS_PASSWORD). " +
        "Set BREAKGLASS_PASSWORD_HASH instead — see docs/BREAKGLASS.md.",
      );
    }
    console.error(
      `[breakglass] SUCCESSFUL sign-in as ${email} with role=admin. ` +
      "This bypassed AutoX SSO. Disarm AUTH_LOCAL_LOGIN as soon as SSO is working again.",
    );
    // `id` becomes the session `sub`, which the middleware forwards as
    // x-npr-sub and db.audit() writes to audit_log.actor_sub.
    return { id: breakGlassSub(email), email, name: "Break-glass operator", role: "admin" } as any;
  },
});

const providers: NextAuthConfig["providers"] = [
  ...(ssoEnabled() ? [autox] : []),
  ...(breakGlassEnabled() ? [breakGlass] : []),
];

// A deployment with no way in is a deployment nobody can fix from the browser.
// It is a legitimate state (SSO not yet registered), but it must not be a quiet
// one — the login page says the same thing to whoever opens it.
if (providers.length === 0) {
  console.error(
    "[auth] NO SIGN-IN METHOD IS CONFIGURED. Set SSO_CLIENT_ID (docs/SSO.md) to enable AutoX SSO, " +
    "or arm the emergency path with AUTH_LOCAL_LOGIN=true + BREAKGLASS_EMAIL + BREAKGLASS_PASSWORD_HASH " +
    "(docs/BREAKGLASS.md). Until then nobody can sign in.",
  );
}

export const { handlers, signIn, signOut, auth } = NextAuth({
  ...authConfig,
  providers,
  callbacks: {
    ...authConfig.callbacks,
    /**
     * Local provisioning is a SIDE EFFECT of a successful authentication, never
     * a gate on it: we do not deny sign-in based on local state, and a failed
     * upsert must not lock a valid user out. Users with no app role still sign
     * in — the role gate then routes them to /no-access.
     */
    async signIn({ account, profile, user }) {
      if (account?.provider === "breakglass") {
        try {
          // Best effort, and deliberately after the credential check: the
          // emergency path must still work with the database unreachable.
          await provisionBreakGlassUser(String(user?.email || BREAKGLASS_EMAIL));
        } catch (e) {
          console.error("[breakglass] could not mirror the sign-in into app_users (sign-in still allowed):", e);
        }
        return true;
      }
      if (account?.provider !== "autox") return true;
      try {
        const id = identityFromIdToken(profile ?? null);
        const read = readAppRoles(account.access_token as string | undefined);
        const appRoles = read.kind === "jwt" ? read.roles : [];

        // The opaque-access-token failure is silent by design in the protocol and
        // is indistinguishable from "user has no roles" unless we say so. Log it
        // loudly: it means `resource` did not reach both /auth and /token.
        if (read.kind === "opaque") {
          console.error(
            "[sso] access token is OPAQUE — autox:app_roles cannot be read. " +
            "`resource` must be sent on BOTH the /auth request and the /token exchange " +
            "(see auth.autox.ts: authorization.params.resource + fetchWithResource).",
          );
        } else {
          console.info(`[sso] sign-in ${id.sub} app_roles=[${appRoles.join(", ")}] -> role=${resolveRole(appRoles) ?? "none"}`);
        }

        if (id.sub) {
          await provisionSsoUser({
            sub: id.sub,
            email: id.email ?? (user?.email ? user.email.toLowerCase() : null),
            emailVerified: id.emailVerified,
            name: id.name,
            role: resolveRole(appRoles),
            appRoles,
            isEyEmployee: id.isEyEmployee,
            orgType: id.orgType,
          });
        }
      } catch (e) {
        console.error("[sso] provisioning failed (sign-in still allowed):", e);
      }
      return true;
    },
  },
});
