import NextAuth from "next-auth";
import { NextResponse } from "next/server";
import authConfig from "./auth.config";

// Edge middleware: the `authorized` callback in authConfig gates every route
// (incl. the /api proxy). For authorized requests we additionally forward the
// signed-in user's role + email as request headers, so the FastAPI backend
// behind the proxy can attribute usage and enforce per-role tool access
// (see backend request_ctx + the _ActorMiddleware).
const { auth } = NextAuth(authConfig);

export default auth((req) => {
  const user = (req.auth as any)?.user;
  const headers = new Headers(req.headers);
  if (user?.role) headers.set("x-ztpa-role", String(user.role));
  if (user?.email) headers.set("x-ztpa-email", String(user.email));
  return NextResponse.next({ request: { headers } });
});

export const config = {
  matcher: ["/((?!api/auth|_next/static|_next/image|favicon.ico).*)"],
};
