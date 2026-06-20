import type { NextAuthConfig } from "next-auth";

// Edge-safe config (no DB imports) — used by middleware AND spread into the full
// config in auth.ts. Public routes need no session; everything else (including
// the /api proxy to the backend) requires one.
const PUBLIC = ["/login", "/forgot", "/reset"];

export const authConfig = {
  trustHost: true,
  session: { strategy: "jwt" },
  pages: { signIn: "/login" },
  providers: [],
  callbacks: {
    authorized({ request, auth }) {
      const p = request.nextUrl.pathname;
      if (p.startsWith("/api/auth")) return true;
      if (PUBLIC.some((x) => p === x || p.startsWith(x + "/"))) return true;
      return !!auth?.user;
    },
    jwt({ token, user }) {
      if (user) {
        (token as any).role = (user as any).role;
        (token as any).uid = (user as any).id;
      }
      return token;
    },
    session({ session, token }) {
      if (session.user) {
        (session.user as any).role = (token as any).role;
        (session.user as any).id = (token as any).uid;
      }
      return session;
    },
  },
} satisfies NextAuthConfig;

export default authConfig;
