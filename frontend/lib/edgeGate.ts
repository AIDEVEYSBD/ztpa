import { NextResponse, type NextRequest } from "next/server";
import { isPublicPath, isRoleExempt } from "../auth.config";

// The middleware's decisions, apart from NextAuth so they can be tested: what
// happens to a request given the session user (or none) and the environment.
// middleware.ts wraps this in `auth(...)`; read it there for the why of each step.

export type SessionUser = { id?: string; role?: string | null; email?: string | null };
type Env = Record<string, string | undefined>;
type Mint = (audience: string) => Promise<string>;

// Cloud Run invoker IAM on the API (orgs commonly enforce it): the request must
// carry a Google ID token for the API's URL. Minted from the metadata server as
// the frontend's service account, cached until five minutes before expiry, and
// sent as X-Serverless-Authorization, which Cloud Run checks and strips without
// touching the app's own headers. Only when NPR_BACKEND_AUDIENCE is set.
let idToken: { value: string; audience: string; exp: number } | null = null;

export async function backendIdToken(audience: string, fetchImpl: typeof fetch = fetch): Promise<string> {
  const now = Date.now() / 1000;
  if (idToken && idToken.audience === audience && idToken.exp - 300 > now) return idToken.value;
  const url = "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/identity"
    + `?audience=${encodeURIComponent(audience)}&format=full`;
  const r = await fetchImpl(url, { headers: { "Metadata-Flavor": "Google" }, cache: "no-store" });
  if (!r.ok) throw new Error(`metadata server answered ${r.status} for an identity token`);
  const value = (await r.text()).trim();
  const payload = JSON.parse(atob(value.split(".")[1].replace(/-/g, "+").replace(/_/g, "/"))) as { exp?: number };
  idToken = { value, audience, exp: payload.exp ?? now + 600 };
  return value;
}

/** Test hook: forget the cached ID token. */
export function resetIdTokenCache(): void {
  idToken = null;
}

export async function gate(req: NextRequest, user: SessionUser | null | undefined,
                           env: Env = process.env, mint: Mint = backendIdToken): Promise<NextResponse> {
  const { pathname, search } = req.nextUrl;

  // Edge lock. Behind a WAF edge that cannot be enforced at the network layer
  // (Front Door before Container Apps, whose ingress cannot filter by service
  // tag), only requests carrying THIS edge's id are served; a direct hit on the
  // app's own hostname bypasses the WAF and gets a 404. Unset = no check.
  const edgeId = env.NPR_EDGE_ID?.trim();
  if (edgeId && req.headers.get(env.NPR_EDGE_HEADER?.trim() || "x-azure-fdid") !== edgeId) {
    return new NextResponse("Not found", { status: 404 });
  }

  // Public paths pass through unmodified, headers and all. Safe only because no
  // public path proxies to FastAPI (auth.config's PUBLIC list is Auth.js and the
  // sign-in pages). Anything added there that DOES reach /api must strip x-npr-*.
  if (isPublicPath(pathname)) return NextResponse.next();

  if (!user) {
    const url = new URL("/login", req.nextUrl.origin);
    url.searchParams.set("callbackUrl", pathname + search);
    return NextResponse.redirect(url);
  }

  // Authenticated but holding no app role: fail closed, no implicit viewer.
  if (!user.role && !isRoleExempt(pathname)) {
    return NextResponse.redirect(new URL("/no-access", req.nextUrl.origin));
  }

  // Strip EVERY client-supplied x-npr-* header (the proxy secret included)
  // before setting ours.
  const headers = new Headers(req.headers);
  for (const key of Array.from(headers.keys())) {
    if (key.toLowerCase().startsWith("x-npr-")) headers.delete(key);
  }
  if (user.role) headers.set("x-npr-role", String(user.role));
  if (user.email) headers.set("x-npr-email", String(user.email));
  if (user.id) headers.set("x-npr-sub", String(user.id)); // AutoX `sub` — the stable key
  // Read per request and trimmed, to match the backend's compare_digest.
  const proxySecret = env.NPR_PROXY_SECRET?.trim();
  if (proxySecret) headers.set("x-npr-proxy-secret", proxySecret);
  const audience = env.NPR_BACKEND_AUDIENCE?.trim();
  if (audience && pathname.startsWith("/api/")) {
    try {
      headers.set("x-serverless-authorization", `Bearer ${await mint(audience)}`);
    } catch (e) {
      // Fail closed and say why: without the token Cloud Run answers a bare 403.
      console.error(JSON.stringify({ event: "backend_id_token_failed", error: String(e) }));
      return NextResponse.json({ detail: "the frontend could not obtain a credential for the API; retry shortly",
                                 error: "backend credential unavailable" }, { status: 503 });
    }
  }
  return NextResponse.next({ request: { headers } });
}
