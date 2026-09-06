import { LoginForm } from "@/components/auth/LoginForm";
import { breakGlassState, ssoEnabled } from "@/lib/sso";

/**
 * The only sign-in surface. AutoX SSO, or — when an operator has armed it —
 * the break-glass credential from docs/BREAKGLASS.md.
 *
 * Rendered per request (never statically): what this page may offer is a
 * function of the environment the container was started with, and a build-time
 * snapshot of that would keep offering a door after the operator closed it.
 */
export const dynamic = "force-dynamic";

export default function LoginPage({ searchParams }: {
  searchParams: { callbackUrl?: string; error?: string };
}) {
  return (
    <LoginForm
      sso={ssoEnabled()}
      breakGlass={breakGlassState()}
      callbackUrl={searchParams?.callbackUrl}
      error={searchParams?.error}
    />
  );
}
