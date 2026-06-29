import NextAuth from "next-auth";
import { NextResponse } from "next/server";
import authConfig from "./auth.config";

// Edge middleware. IMPORTANT: when `auth` wraps a custom function, NextAuth does
// NOT auto-enforce the `authorized` callback — the function fully controls the
// response. So we gate explicitly here: any unauthenticated request to a route
// that isn't public is redirected to /login. For authorized requests we forward
// the signed-in user's role + email as headers so the FastAPI backend behind the
// /api proxy can attribute usage and enforce per-role tool access (see backend
// request_ctx + the _ActorMiddleware).
const { auth } = NextAuth(authConfig);

const PUBLIC = ["/login", "/forgot", "/reset"];
function isPublic(pathname: string): boolean {
  if (pathname === "/") return true; // public marketing landing
  if (pathname.startsWith("/api/auth")) return true; // auth endpoints
  return PUBLIC.some((x) => pathname === x || pathname.startsWith(x + "/"));
}

export default auth((req) => {
  const { pathname } = req.nextUrl;
  const user = (req.auth as { user?: { role?: string; email?: string } } | null)?.user;

  if (!user && !isPublic(pathname)) {
    const url = new URL("/login", req.nextUrl.origin);
    url.searchParams.set("callbackUrl", pathname);
    return NextResponse.redirect(url);
  }

  const headers = new Headers(req.headers);
  if (user?.role) headers.set("x-ztpa-role", String(user.role));
  if (user?.email) headers.set("x-ztpa-email", String(user.email));
  return NextResponse.next({ request: { headers } });
});

export const config = {
  matcher: ["/((?!api/auth|_next/static|_next/image|favicon.ico).*)"],
};
