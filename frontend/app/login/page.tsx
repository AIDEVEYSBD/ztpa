import { LoginForm } from "@/components/auth/LoginForm";
import { localLoginEnabled, ssoEnabled } from "@/lib/sso";

export default function LoginPage({ searchParams }: {
  searchParams: { reset?: string; callbackUrl?: string; error?: string };
}) {
  return (
    <LoginForm
      reset={searchParams?.reset === "1"}
      sso={ssoEnabled()}
      local={localLoginEnabled()}
      callbackUrl={searchParams?.callbackUrl}
      error={searchParams?.error}
    />
  );
}
