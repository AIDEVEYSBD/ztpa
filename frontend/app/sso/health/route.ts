import { NextResponse } from "next/server";
import { ssoEnabled, ssoHealth } from "@/lib/sso";

/**
 * Cold-start probe, called from the sign-in screen before we hand the browser to
 * the SSO. AutoX can scale to zero; redirecting into a waking instance drops the
 * user on a Render 503 page or a very slow first byte. Proxied through the server
 * so the browser never has to deal with cross-origin on /health.
 */
export const dynamic = "force-dynamic";

export async function GET() {
  if (!ssoEnabled()) return NextResponse.json({ status: "disabled" }, { headers: { "cache-control": "no-store" } });
  const status = await ssoHealth();
  return NextResponse.json({ status }, { headers: { "cache-control": "no-store" } });
}
