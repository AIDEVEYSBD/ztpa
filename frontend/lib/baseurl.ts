import { headers } from "next/headers";

/**
 * The app's base URL for building absolute links in emails (magic/reset/invite).
 * Derived from the actual request host so links are correct on localhost, preview
 * URLs, or production behind a proxy. Falls back to APP_URL/AUTH_URL (used by CLI
 * scripts that have no request context), then localhost.
 *
 * Security note: a trusted reverse proxy should set x-forwarded-host. If you need
 * to pin a canonical origin (host-header-injection hardening), set APP_URL and
 * this still prefers the request host only when APP_URL is unset.
 */
export function getBaseUrl(): string {
  try {
    const h = headers();
    const host = h.get("x-forwarded-host") || h.get("host");
    if (host) {
      const proto = h.get("x-forwarded-proto") || (host.startsWith("localhost") || host.startsWith("127.") ? "http" : "https");
      return `${proto}://${host}`;
    }
  } catch {
    /* not in a request scope */
  }
  return process.env.APP_URL || process.env.AUTH_URL || "http://localhost:3000";
}
