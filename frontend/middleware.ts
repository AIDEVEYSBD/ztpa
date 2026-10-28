import NextAuth from "next-auth";
import { NextResponse } from "next/server";
import authConfig, { isPublicPath, isRoleExempt } from "./auth.config";

// Edge middleware. IMPORTANT: when `auth` wraps a custom function, NextAuth does
// NOT auto-enforce the `authorized` callback — the function fully controls the
// response. So we gate explicitly here:
//   1. no session          -> /login (which starts the AutoX authorization request)
//   2. session, no role    -> /no-access (a real retry page, not a dead end)
//   3. otherwise           -> forward sub/role/email to the FastAPI backend,
//                             signed with the shared x-npr-proxy-secret
// The forwarded headers are what the backend's request_ctx reads for per-role
// tool access and usage attribution — which is exactly why they must be
// unforgeable: anything a client sent under x-npr-* is dropped, and the secret
// is what lets the backend tell our headers from a direct call to its own URL.
const { auth } = NextAuth(authConfig);

type SessionUser = { id?: string; role?: string | null; email?: string | null };

export default auth((req) => {
  const { pathname, search } = req.nextUrl;

  // Edge lock. When the app sits behind a WAF edge that cannot be enforced at
  // the network layer (Azure Front Door in front of Container Apps, whose
  // ingress cannot filter by service tag), only requests carrying THIS edge's id
  // are served; a direct hit on the app's own hostname bypasses the WAF and gets
  // a 404. Unset (local, GCP behind its own load balancer) = no check.
  const edgeId = process.env.NPR_EDGE_ID?.trim();
  if (edgeId && req.headers.get(process.env.NPR_EDGE_HEADER?.trim() || "x-azure-fdid") !== edgeId) {
    return new NextResponse("Not found", { status: 404 });
  }
  const user = (req.auth as { user?: SessionUser } | null)?.user;

  // Public paths pass through unmodified, headers and all. That is safe only
  // because no public path proxies to FastAPI (auth.config's PUBLIC list is
  // /login, /forgot, /reset, /sso, "/" and /api/auth — Auth.js, not the backend).
  // Anything added to that list that DOES reach /api must strip x-npr-* here too.
  if (isPublicPath(pathname)) return NextResponse.next();

  if (!user) {
    const url = new URL("/login", req.nextUrl.origin);
    url.searchParams.set("callbackUrl", pathname + search);
    return NextResponse.redirect(url);
  }

  // Authenticated by AutoX but holding no app role we recognise. Fail closed —
  // there is no implicit `viewer`.
  if (!user.role && !isRoleExempt(pathname)) {
    return NextResponse.redirect(new URL("/no-access", req.nextUrl.origin));
  }

  const headers = new Headers(req.headers);
  // Defence in depth: strip EVERY client-supplied x-npr-* header before we set
  // ours. Deleting only the three known names would leave x-npr-proxy-secret —
  // the header that proves a request came through this middleware — forgeable by
  // anyone who can reach this app, which is the whole point of the check.
  for (const key of Array.from(headers.keys())) {
    if (key.toLowerCase().startsWith("x-npr-")) headers.delete(key);
  }
  if (user.role) headers.set("x-npr-role", String(user.role));
  if (user.email) headers.set("x-npr-email", String(user.email));
  if (user.id) headers.set("x-npr-sub", String(user.id)); // AutoX `sub` — the stable key
  // Shared secret proving the actor headers above were set here and not by a
  // client talking to the API directly (the FastAPI side compares it with
  // hmac.compare_digest). Read per-request rather than at module scope so a
  // rotated value takes effect on restart of the app only, not on rebuild. The
  // backend enforces only when its own NPR_PROXY_SECRET is set, so leaving this
  // unset keeps local dev working exactly as before.
  // Trimmed to match the backend, which reads `(os.environ.get(...) or "").strip()`
  // — an untrimmed copy of the same value would fail compare_digest and 401 the
  // whole app over a trailing newline in a dashboard secret.
  const proxySecret = process.env.NPR_PROXY_SECRET?.trim();
  if (proxySecret) headers.set("x-npr-proxy-secret", proxySecret);
  return NextResponse.next({ request: { headers } });
});

export const config = {
  // Metadata/static routes must be excluded, not just public: the favicon is
  // requested on the /login page itself, and a gated `/icon.svg` would answer an
  // image request with a redirect to /login — which is why the tab icon rendered
  // from a stale localhost cache in dev but was missing on a fresh origin.
  matcher: ["/((?!api/auth|_next/static|_next/image|favicon.ico|icon.svg|apple-icon.png|robots.txt|sitemap.xml).*)"],
};
