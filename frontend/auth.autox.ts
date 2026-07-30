import { customFetch } from "next-auth";
import type { OIDCConfig } from "next-auth/providers";
import {
  SSO_CLIENT_ID, SSO_CLIENT_SECRET, SSO_ISSUER, SSO_RESOURCE, SSO_SCOPE,
} from "@/lib/sso";

/** AutoX SSO ID-token claims we care about. */
export interface AutoxProfile extends Record<string, any> {
  sub: string;
  email?: string;
  email_verified?: boolean;
  name?: string;
  preferred_username?: string;
  "autox:is_ey_employee"?: boolean;
  "autox:org_type"?: "EY" | "client";
  "autox:orgs"?: Array<{ id: string; name: string; type: string; team?: string; role?: string }>;
  "autox:roles"?: string[];
}

/**
 * `resource` must be present on BOTH legs of the code flow or the access token
 * comes back opaque — silently, with no error — and `autox:app_roles` is
 * unreadable.
 *
 * Auth.js puts `authorization.params` on the /auth URL for us, but it has no
 * config hook for extra /token body params. It does hand the provider's
 * `customFetch` the token request with its body still a live `URLSearchParams`
 * (that is how Auth.js itself strips `code_verifier`), so we append `resource`
 * there. Discovery and userinfo requests carry no such body and pass through.
 */
const fetchWithResource: typeof fetch = (input, init) => {
  const body = init?.body;
  if (body instanceof URLSearchParams && !body.has("resource")) {
    const grant = body.get("grant_type");
    if (grant === "authorization_code" || grant === "refresh_token") {
      body.set("resource", SSO_RESOURCE);
    }
  }
  return fetch(input as any, init);
};

const authMethod =
  process.env.SSO_TOKEN_AUTH_METHOD || (SSO_CLIENT_SECRET ? "client_secret_basic" : "none");

/**
 * AutoX SSO: OIDC, authorization code + PKCE (S256) only, ES256 id_token.
 * Endpoints come from `${SSO_ISSUER}/.well-known/openid-configuration` — we set
 * `issuer` and let Auth.js discover, so a moved endpoint needs no code change.
 */
export const autox: OIDCConfig<AutoxProfile> = {
  id: "autox",
  name: "AutoX SSO",
  type: "oidc",
  issuer: SSO_ISSUER,
  clientId: SSO_CLIENT_ID,
  // Public clients omit the secret; `token_endpoint_auth_method: none` then applies.
  clientSecret: SSO_CLIENT_SECRET || undefined,
  checks: ["pkce", "state", "nonce"],
  client: {
    id_token_signed_response_alg: "ES256",
    token_endpoint_auth_method: authMethod,
  },
  authorization: {
    params: {
      scope: SSO_SCOPE,
      // leg 1 of 2 — see fetchWithResource for leg 2
      resource: SSO_RESOURCE,
    },
  },
  // Identity comes from the (signature-verified) id_token; no extra /me round trip.
  idToken: true,
  profile: (p) => ({
    // `sub` is the primary key everywhere downstream. A deleted+recreated AutoX
    // account gets a NEW sub, so never key on email.
    id: p.sub,
    email: p.email?.toLowerCase() ?? null,
    name: p.name ?? p.preferred_username ?? p.email ?? p.sub,
  }),
  [customFetch]: fetchWithResource,
};
