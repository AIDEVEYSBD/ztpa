"use client";

import { useState } from "react";
import { signIn } from "next-auth/react";
import { ShieldAlert, KeyRound } from "lucide-react";
import type { BreakGlassState } from "@/lib/sso";
import { Spinner } from "../ui";
import { AuthShell, AuthInput, AuthBanner } from "./AuthShell";
import { SsoSignIn } from "./SsoSignIn";

/** Auth.js surfaces OAuth/OIDC failures as ?error= on the sign-in page. */
const SSO_ERRORS: Record<string, string> = {
  OAuthSignin: "Could not start sign-in with AutoX SSO. Please try again.",
  OAuthCallback: "AutoX SSO returned an error completing sign-in. Please try again.",
  OAuthCallbackError: "AutoX SSO rejected the sign-in request. Check that this app's redirect URI is registered.",
  Configuration: "SSO is not configured correctly. Contact your administrator.",
  AccessDenied: "AutoX SSO denied this sign-in.",
  Verification: "That sign-in link is no longer valid.",
};

/**
 * SSO-only sign-in.
 *
 * Three states, and the third is the one that used to be a bug rather than a
 * screen. The password and magic-link tabs are gone, and `ssoEnabled()` is
 * still just "is SSO_CLIENT_ID set" — so on a deployment with no `SSO_*`
 * variables (which is what the live one looks like today) this component would
 * otherwise render an empty box: a sign-in page with no way to sign in and no
 * statement of why. An operator staring at that has no idea whether the app is
 * broken, whether they are meant to wait, or what to change.
 *
 * So "nothing is configured" is rendered explicitly, names the two variables
 * that fix it, and points at the emergency path — because the person who most
 * needs that text is the one who has just locked themselves out.
 */
export function LoginForm({ sso = false, breakGlass, callbackUrl, error }: {
  sso?: boolean;
  breakGlass: BreakGlassState;
  callbackUrl?: string;
  error?: string;
}) {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [loading, setLoading] = useState(false);
  const [localError, setLocalError] = useState<string>();
  const [showBreakGlass, setShowBreakGlass] = useState(false);

  const target = callbackUrl && callbackUrl.startsWith("/") ? callbackUrl : "/console";
  const ssoError = error ? SSO_ERRORS[error] ?? "Sign-in failed. Please try again." : undefined;

  const armed = breakGlass.armed;
  const usable = breakGlass.armed && breakGlass.usable;

  const onBreakGlass = async (e: React.FormEvent) => {
    e.preventDefault(); setLoading(true); setLocalError(undefined);
    const r = await signIn("breakglass", { email, password, redirect: false });
    // Keep the spinner up through the redirect so the button never flickers
    // back to its idle label before the page changes.
    if (r?.error) { setLocalError("That break-glass credential was not accepted."); setLoading(false); }
    else window.location.href = target;
  };

  // Nothing is configured. Do not render a login box: say so.
  if (!sso && !armed) {
    return (
      <AuthShell title="Sign-in is not configured" subtitle="Nobody can sign in to this deployment">
        <AuthBanner kind="error">
          <b>No identity provider is configured.</b> This application authenticates through AutoX SSO
          and has no local accounts, so with <code className="mono">SSO_CLIENT_ID</code> unset there is
          no way in.
        </AuthBanner>
        <div className="space-y-3 text-sm text-text2">
          <p>An operator with access to this deployment&apos;s configuration can fix it two ways:</p>
          <ul className="space-y-2 border border-border bg-sunk p-3 text-xs">
            <li>
              <div className="font-bold text-text">Configure SSO (the normal fix)</div>
              <div className="mono mt-1 text-text3">SSO_CLIENT_ID=&hellip;<br />SSO_CLIENT_SECRET=&hellip;</div>
              <div className="mt-1 text-text3">Registration steps: <span className="mono">docs/SSO.md</span></div>
            </li>
            <li>
              <div className="font-bold text-text">Open the emergency door (temporary)</div>
              <div className="mono mt-1 text-text3">
                AUTH_LOCAL_LOGIN=true<br />BREAKGLASS_EMAIL=&hellip;<br />BREAKGLASS_PASSWORD_HASH=&hellip;
              </div>
              <div className="mt-1 text-text3">Full procedure: <span className="mono">docs/BREAKGLASS.md</span></div>
            </li>
          </ul>
          <p className="text-xs text-text3">
            Both take effect on the next revision of the container app; neither needs a rebuild.
          </p>
        </div>
      </AuthShell>
    );
  }

  return (
    <AuthShell title="Sign in">
      {ssoError && <AuthBanner kind="error">{ssoError}</AuthBanner>}

      {sso && (
        // `auto` when SSO is the only method: nothing to choose, so don't make
        // the user click through a one-option screen. A previous error stops the
        // auto-start so they aren't caught in a redirect loop, and so does an
        // armed break-glass door — during an incident the operator needs to
        // reach the form, not be bounced into the SSO that is failing.
        <SsoSignIn callbackUrl={target} auto={!armed && !ssoError} />
      )}

      {armed && !usable && (
        <AuthBanner kind="error">
          <b>Break-glass is armed but unusable.</b> {breakGlass.reason} See{" "}
          <code className="mono">docs/BREAKGLASS.md</code>.
        </AuthBanner>
      )}

      {usable && (
        <div className={sso ? "mt-4 border-t border-border pt-4" : ""}>
          {!showBreakGlass ? (
            <button type="button" onClick={() => setShowBreakGlass(true)}
              className="btn-ghost flex w-full items-center justify-center gap-2 text-xs">
              <KeyRound size={13} /> Break-glass sign-in
            </button>
          ) : (
            <form onSubmit={onBreakGlass} className="space-y-3">
              <div className="flex items-start gap-2 border border-sev-high-line bg-sev-high-bg p-2.5 text-[11.5px] text-sev-high">
                <ShieldAlert size={14} className="mt-px shrink-0" />
                <span>
                  This bypasses AutoX SSO with a credential held in this deployment&apos;s configuration.
                  The sign-in is written to the audit trail as <span className="mono">breakglass:&lt;email&gt;</span>,
                  the session is short-lived, and every attempt is logged. Disarm{" "}
                  <span className="mono">AUTH_LOCAL_LOGIN</span> when SSO works again.
                </span>
              </div>
              <AuthInput label="Break-glass email" type="email" required autoComplete="off"
                value={email} onChange={(e) => setEmail(e.target.value)} placeholder="the configured BREAKGLASS_EMAIL" />
              <AuthInput label="Break-glass password" type="password" required autoComplete="off"
                value={password} onChange={(e) => setPassword(e.target.value)} placeholder="••••••••" />
              {localError && <p className="text-xs text-sev-critical">{localError}</p>}
              <button className="btn-primary w-full" disabled={loading}>
                {loading ? <Spinner label="Signing in…" /> : "Break the glass"}
              </button>
            </form>
          )}
        </div>
      )}

      {sso && (
        <p className="mt-3 text-center text-[11px] text-text3">
          Access is managed in AutoX SSO. Ask your administrator for a role in this application.
        </p>
      )}
    </AuthShell>
  );
}
