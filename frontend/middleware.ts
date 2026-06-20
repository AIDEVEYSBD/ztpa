import NextAuth from "next-auth";
import authConfig from "./auth.config";

// Edge middleware: gates every route (incl. the /api proxy) via the `authorized`
// callback. /api/auth/* and static assets are excluded by the matcher.
export default NextAuth(authConfig).auth;

export const config = {
  matcher: ["/((?!api/auth|_next/static|_next/image|favicon.ico).*)"],
};
