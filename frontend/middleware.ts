import NextAuth from "next-auth";
import authConfig from "./auth.config";
import { gate, type SessionUser } from "./lib/edgeGate";

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
//
// The decisions themselves live in lib/edgeGate.ts (tested in edgeGate.test.ts).
const { auth } = NextAuth(authConfig);

export default auth(async (req) => gate(req, (req.auth as { user?: SessionUser } | null)?.user));

export const config = {
  // Metadata/static routes must be excluded, not just public: the favicon is
  // requested on the /login page itself, and a gated `/icon.svg` would answer an
  // image request with a redirect to /login — which is why the tab icon rendered
  // from a stale localhost cache in dev but was missing on a fresh origin.
  matcher: ["/((?!api/auth|_next/static|_next/image|favicon.ico|icon.svg|apple-icon.png|robots.txt|sitemap.xml).*)"],
};
