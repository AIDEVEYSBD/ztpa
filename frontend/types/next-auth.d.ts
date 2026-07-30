import type { AppRole } from "@/lib/roles";
import type { SsoSessionInfo } from "@/lib/sso";

declare module "next-auth" {
  interface Session {
    /** Non-secret AutoX context. Never carries the ID or access token. */
    sso?: SsoSessionInfo & { provider: string };
    user: {
      id?: string;
      email?: string | null;
      name?: string | null;
      image?: string | null;
      /** Resolved from `autox:app_roles`. `null` = authenticated but not entitled. */
      role?: AppRole | null;
    };
  }
}

declare module "next-auth/jwt" {
  interface JWT {
    provider?: string;
    uid?: string;
    role?: AppRole | null;
    /** Raw `autox:app_roles` from the JWT access token. */
    appRoles?: string[];
    unmapped?: string[];
    /** Access token came back opaque -> `resource` missing on a leg. */
    misconfigured?: boolean;
    isEyEmployee?: boolean | null;
    orgType?: string | null;
    directoryRoles?: string[];
    emailVerified?: boolean;
    /** Held only for RP-initiated logout (`id_token_hint`). */
    idToken?: string;
    authAt?: number;
    /** Absolute epoch-second deadline; past it the session is dropped. */
    reauthAt?: number;
  }
}
