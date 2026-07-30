import { redirect } from "next/navigation";
import { auth } from "@/auth";
import { NoAccess } from "@/components/auth/NoAccess";
import { SSO_APP_ROLE_NAMES } from "@/lib/roles";

/** Never cached: the verdict is only valid for the current token. */
export const dynamic = "force-dynamic";

export default async function NoAccessPage() {
  const session = await auth();
  if (!session?.user) redirect("/login");
  // A role arrived (fresh token) — nothing to see here.
  if ((session.user as { role?: string | null }).role) redirect("/console");

  const sso = (session as any).sso as
    | { appRoles?: string[]; unmapped?: string[]; misconfigured?: boolean }
    | undefined;

  return (
    <NoAccess
      email={session.user.email}
      appRoles={sso?.appRoles ?? []}
      unmapped={sso?.unmapped ?? []}
      misconfigured={sso?.misconfigured === true}
      requiredRoles={Object.values(SSO_APP_ROLE_NAMES)}
    />
  );
}
