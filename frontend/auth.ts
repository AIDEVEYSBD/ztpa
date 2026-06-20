import NextAuth from "next-auth";
import Credentials from "next-auth/providers/credentials";
import authConfig from "./auth.config";
import { getUserByEmail, verifyUserPassword } from "@/lib/users";
import { consumeToken } from "@/lib/tokens";

export const { handlers, signIn, signOut, auth } = NextAuth({
  ...authConfig,
  providers: [
    Credentials({
      id: "password",
      name: "Password",
      credentials: { email: {}, password: {} },
      authorize: async (c) => {
        const u = await verifyUserPassword(String(c?.email || ""), String(c?.password || ""));
        return u ? ({ id: u.id, email: u.email, name: u.name ?? u.email, role: u.role } as any) : null;
      },
    }),
    Credentials({
      id: "magic",
      name: "Magic link",
      credentials: { token: {} },
      authorize: async (c) => {
        const email = await consumeToken(String(c?.token || ""), ["magic", "invite"]);
        if (!email) return null;
        const u = await getUserByEmail(email);
        return u && u.status !== "disabled"
          ? ({ id: u.id, email: u.email, name: u.name ?? u.email, role: u.role } as any) : null;
      },
    }),
  ],
});
