import { NextResponse, type NextRequest } from "next/server";
import { getToken } from "next-auth/jwt";
import { signOut } from "@/auth";
import { endSessionUrl, ssoEnabled } from "@/lib/sso";

/**
 * Single sign-out. Clears the local session, then hands off to the AutoX
 * end-session endpoint so the SSO session goes too (otherwise "sign out" only
 * drops our cookie and the next sign-in is instant and silent).
 *
 * `id_token_hint` is required: without it the SSO cannot identify the client,
 * cannot validate `post_logout_redirect_uri`, and will not redirect back. The
 * ID token is read straight out of the encrypted session cookie — it is never
 * exposed through the session payload.
 */
export const dynamic = "force-dynamic";

async function handle(req: NextRequest) {
  const secure = (req.headers.get("x-forwarded-proto") || req.nextUrl.protocol.replace(":", "")) === "https";
  const cookieName = `${secure ? "__Secure-" : ""}authjs.session-token`;

  let idToken: string | undefined;
  let provider: string | undefined;
  try {
    const token = await getToken({
      req,
      secret: process.env.AUTH_SECRET!,
      salt: cookieName,
      secureCookie: secure,
      cookieName,
    });
    idToken = token?.idToken as string | undefined;
    provider = token?.provider as string | undefined;
  } catch {
    /* no / unreadable session — still clear cookies and bounce to /login */
  }

  // Clears the (possibly chunked) session cookies via the cookie jar; those
  // mutations are applied to the response we return below.
  await signOut({ redirect: false });

  const origin = req.nextUrl.origin;
  const postLogout = process.env.SSO_POST_LOGOUT_REDIRECT_URI || `${origin}/login`;

  const target =
    ssoEnabled() && provider === "autox" && idToken
      ? endSessionUrl({ idToken, postLogoutRedirectUri: postLogout, state: "npr" })
      : `${origin}/login`;

  return NextResponse.redirect(target);
}

export const GET = handle;
export const POST = handle;
