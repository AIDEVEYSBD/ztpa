import NextAuth from "next-auth";
import { NextResponse } from "next/server";
import authConfig, { isPublicPath, isRoleExempt } from "./auth.config";

// Edge middleware. IMPORTANT: when `auth` wraps a custom function, NextAuth does
// NOT auto-enforce the `authorized` callback — the function fully controls the
// response. So we gate explicitly here:
//   1. no session          -> /login (which starts the AutoX authorization request)
//   2. session, no role    -> /no-access (a real retry page, not a dead end)
//   3. otherwise           -> forward sub/role/email to the FastAPI backend
// The forwarded headers are what the backend's request_ctx reads for per-role
// tool access and usage attribution.
const { auth } = NextAuth(authConfig);

type SessionUser = { id?: string; role?: string | null; email?: string | null };

export default auth((req) => {
  const { pathname, search } = req.nextUrl;
  const user = (req.auth as { user?: SessionUser } | null)?.user;

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
  // Defence in depth: strip any client-supplied actor headers before we set ours.
  headers.delete("x-npr-role");
  headers.delete("x-npr-email");
  headers.delete("x-npr-sub");
  if (user.role) headers.set("x-npr-role", String(user.role));
  if (user.email) headers.set("x-npr-email", String(user.email));
  if (user.id) headers.set("x-npr-sub", String(user.id)); // AutoX `sub` — the stable key
  return NextResponse.next({ request: { headers } });
});

export const config = {
  // Metadata/static routes must be excluded, not just public: the favicon is
  // requested on the /login page itself, and a gated `/icon.svg` would answer an
  // image request with a redirect to /login — which is why the tab icon rendered
  // from a stale localhost cache in dev but was missing on a fresh origin.
  matcher: ["/((?!api/auth|_next/static|_next/image|favicon.ico|icon.svg|apple-icon.png|robots.txt|sitemap.xml).*)"],
};
