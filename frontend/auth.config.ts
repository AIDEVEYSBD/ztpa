import type { NextAuthConfig } from "next-auth";
import { resolveRole, unmappedRoles, type AppRole } from "@/lib/roles";
import {
  BREAKGLASS_SESSION_MAX_AGE, identityFromIdToken, readAppRoles, SSO_SESSION_MAX_AGE,
} from "@/lib/sso";

// Edge-safe config (no DB imports) — used by middleware AND spread into the full
// config in auth.ts. Public routes need no session; everything else (including
// the /api proxy to the backend) requires one.
//
// `/forgot` and `/reset` are gone from this list because the routes are gone:
// SSO-only has no password to reset. They are NOT left here "just in case" —
// a public path is an unauthenticated entry point, and one that maps to no page
// is surface with no purpose.
const PUBLIC = ["/login", "/sso"];

/** Signed in, but the role gate does not apply (otherwise /no-access would loop). */
export const ROLE_EXEMPT = ["/no-access"];

export function isPublicPath(pathname: string): boolean {
  if (pathname === "/") return true; // public marketing landing page
  if (pathname.startsWith("/api/auth")) return true; // Auth.js endpoints
  return PUBLIC.some((x) => pathname === x || pathname.startsWith(x + "/"));
}

export function isRoleExempt(pathname: string): boolean {
  return ROLE_EXEMPT.some((x) => pathname === x || pathname.startsWith(x + "/"));
}

const nowSec = () => Math.floor(Date.now() / 1000);

export const authConfig = {
  trustHost: true,
  // Absolute cap, not a rolling window: an AutoX role change only shows up in a
  // newly minted token, so the session must expire and re-authorize. See
  // SSO_SESSION_MAX_AGE in lib/sso.ts.
  session: { strategy: "jwt", maxAge: SSO_SESSION_MAX_AGE },
  pages: { signIn: "/login" },
  providers: [],
  callbacks: {
    authorized({ request, auth }) {
      const p = request.nextUrl.pathname;
      if (isPublicPath(p)) return true;
      if (!auth?.user) return false;
      if (isRoleExempt(p)) return true;
      return !!(auth.user as { role?: AppRole | null }).role;
    },

    jwt({ token, user, account, profile }) {
      if (account?.provider === "autox") {
        // --- app roles ---------------------------------------------------
        // autox:app_roles lives ONLY in the JWT access token (needs `resource`
        // on both legs). autox:roles is the global directory role and is NOT
        // used for authorization here.
        const read = readAppRoles(account.access_token as string | undefined);
        const appRoles = read.kind === "jwt" ? read.roles : [];
        const id = identityFromIdToken(profile ?? null);

        token.provider = "autox";
        token.sub = id.sub ?? token.sub;
        token.uid = id.sub ?? token.sub;
        token.email = id.email ?? token.email;
        token.name = id.name ?? token.name;
        token.emailVerified = id.emailVerified;
        token.appRoles = appRoles;
        token.unmapped = unmappedRoles(appRoles);
        token.role = resolveRole(appRoles);
        token.misconfigured = read.kind === "opaque";
        token.isEyEmployee = id.isEyEmployee;
        token.orgType = id.orgType;
        token.directoryRoles = id.directoryRoles;
        // Held for RP-initiated logout (id_token_hint). Stays inside the
        // encrypted session cookie — the `session` callback never exposes it.
        token.idToken = account.id_token;
        token.authAt = nowSec();
        token.reauthAt = nowSec() + SSO_SESSION_MAX_AGE;
      } else if (account?.provider === "breakglass" && user) {
        // The emergency door (docs/BREAKGLASS.md). `role` is admin because
        // auth.ts verified the configured credential — it is NOT read from any
        // table, and there is no other credential provider left that could
        // reach this branch. `appRoles` names the door so /no-access, the
        // sidebar and anything reading the session can tell the two apart.
        token.provider = "breakglass";
        token.role = (user as { role?: AppRole }).role ?? null;
        token.uid = (user as { id?: string }).id;
        token.sub = (user as { id?: string }).id ?? token.sub;
        token.email = (user as { email?: string | null }).email ?? token.email;
        token.appRoles = ["breakglass"];
        token.unmapped = [];
        token.misconfigured = false;
        token.isEyEmployee = null;
        token.orgType = null;
        token.directoryRoles = [];
        token.authAt = nowSec();
        // Deliberately shorter than an SSO session, and on the same absolute
        // (never rolling) clock: if the operator forgets to disarm the flag,
        // the sessions it minted still expire on their own.
        token.reauthAt = nowSec() + BREAKGLASS_SESSION_MAX_AGE;
      }

      // Hard stop at the absolute deadline: clears the session cookie, so the
      // next navigation runs a fresh authorization request and picks up any
      // role change. Never extend this on activity.
      //
      // Provider-agnostic on purpose. It used to test `provider === "autox"`,
      // which was correct while the alternative was a local password session
      // that had no deadline to enforce; a break-glass session is the opposite
      // case — the one session that most needs to die by itself.
      if (typeof token.reauthAt === "number" && nowSec() >= token.reauthAt) {
        return null;
      }
      return token;
    },

    session({ session, token }) {
      if (session.user) {
        (session.user as any).id = token.uid ?? token.sub;
        (session.user as any).role = (token.role as AppRole | null) ?? null;
      }
      (session as any).sso = {
        provider: token.provider ?? "none",
        sub: (token.uid ?? token.sub) as string,
        appRoles: (token.appRoles as string[]) ?? [],
        unmapped: (token.unmapped as string[]) ?? [],
        isEyEmployee: (token.isEyEmployee as boolean | null) ?? null,
        orgType: (token.orgType as string | null) ?? null,
        misconfigured: token.misconfigured === true,
        reauthAt: (token.reauthAt as number) ?? null,
      };
      return session;
    },
  },
} satisfies NextAuthConfig;

export default authConfig;
