"use client";

import { useState } from "react";
import { signIn } from "next-auth/react";
import { Spinner } from "../ui";
import { AuthShell, AuthBanner } from "./AuthShell";

/**
 * Shown when AutoX authenticated the user but granted them no role in THIS app.
 *
 * The retry button starts a brand-new authorization request. That is the whole
 * point of this page: an AutoX role grant only appears in a newly minted token,
 * so re-rendering the cached session would keep saying "no access" forever. We
 * also never store this verdict anywhere that outlives the token.
 */
export function NoAccess({ email, appRoles, unmapped, misconfigured, requiredRoles }: {
  email?: string | null;
  appRoles: string[];
  unmapped: string[];
  misconfigured: boolean;
  requiredRoles: string[];
}) {
  const [busy, setBusy] = useState(false);

  const retry = async () => {
    setBusy(true);
    await signIn("autox", { callbackUrl: "/console" });
  };

  return (
    <AuthShell title="No access to this application" subtitle="Signed in, but not entitled">
      {misconfigured ? (
        <AuthBanner kind="error">
          <b>SSO misconfiguration.</b> The access token came back opaque, so this app cannot read
          <code className="mono mx-1">autox:app_roles</code>. The <code className="mono">resource</code> parameter
          must reach both the authorization request and the token exchange.
        </AuthBanner>
      ) : (
        <AuthBanner kind="error">
          {email ? <><b>{email}</b> has</> : "You have"} no role assigned in this application.
        </AuthBanner>
      )}

      <div className="space-y-3 text-sm text-text2">
        <p>
          Ask an AutoX administrator to assign you one of these application roles, then use the button
          below — access changes only take effect in a new sign-in.
        </p>
        <ul className="space-y-1 border border-border bg-sunk p-3 text-xs">
          {requiredRoles.map((r) => (
            <li key={r} className="mono text-text">{r}</li>
          ))}
        </ul>

        {appRoles.length > 0 && (
          <p className="text-xs text-text3">
            Roles currently on your token: <span className="mono">{appRoles.join(", ")}</span>
            {unmapped.length > 0 && (
              <>
                {" "}— unrecognised by this app: <span className="mono text-sev-high">{unmapped.join(", ")}</span>
              </>
            )}
          </p>
        )}

        <button type="button" onClick={retry} disabled={busy} className="btn-primary w-full">
          {busy ? <Spinner label="Re-checking with AutoX…" /> : "I've been granted access — retry"}
        </button>
        <div className="text-center text-xs text-muted">
          <a href="/sso/logout" className="underline">Sign out</a>
        </div>
      </div>
    </AuthShell>
  );
}
