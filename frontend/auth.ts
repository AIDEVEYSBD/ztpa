import NextAuth, { type NextAuthConfig } from "next-auth";
import Credentials from "next-auth/providers/credentials";
import authConfig from "./auth.config";
import { autox } from "./auth.autox";
import { getUserByEmail, verifyUserPassword, provisionSsoUser } from "@/lib/users";
import { consumeToken } from "@/lib/tokens";
import { identityFromIdToken, localLoginEnabled, readAppRoles, ssoEnabled } from "@/lib/sso";
import { resolveRole } from "@/lib/roles";

// Local password / magic-link providers. Registered only while local login is
// enabled — once SSO_CLIENT_ID is set these disappear, so the legacy credential
// paths cannot be used as an SSO bypass.
const legacyProviders: NextAuthConfig["providers"] = [
  Credentials({
    id: "password",
    name: "Password",
    credentials: { email: {}, password: {} },
    authorize: async (c) => {
      const u = await verifyUserPassword(String(c?.email || ""), String(c?.password || ""));
      return u ? ({ id: u.id, email: u.email, name: u.name ?? u.email, role: u.role } as any) : null;
    },
  }),
  Credentials({
    id: "magic",
    name: "Magic link",
    credentials: { token: {} },
    authorize: async (c) => {
      const email = await consumeToken(String(c?.token || ""), ["magic", "invite"]);
      if (!email) return null;
      const u = await getUserByEmail(email);
      return u && u.status !== "disabled"
        ? ({ id: u.id, email: u.email, name: u.name ?? u.email, role: u.role } as any) : null;
    },
  }),
];

export const { handlers, signIn, signOut, auth } = NextAuth({
  ...authConfig,
  providers: [
    ...(ssoEnabled() ? [autox] : []),
    ...(localLoginEnabled() ? legacyProviders : []),
  ],
  callbacks: {
    ...authConfig.callbacks,
    /**
     * Local provisioning is a SIDE EFFECT of a successful AutoX authentication,
     * never a gate on it: we do not deny sign-in based on local state, and a
     * failed upsert must not lock a valid user out. Users with no app role still
     * sign in — the role gate then routes them to /no-access.
     */
    async signIn({ account, profile, user }) {
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
