"use client";

import { useState } from "react";
import Link from "next/link";
import { signIn } from "next-auth/react";
import { requestMagic } from "@/app/actions";
import { cn, Spinner } from "../ui";
import { AuthShell, AuthInput, AuthBanner, DevLink } from "./AuthShell";
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

export function LoginForm({ reset, sso = false, local = true, callbackUrl, error }: {
  reset?: boolean;
  sso?: boolean;
  local?: boolean;
  callbackUrl?: string;
  error?: string;
}) {
  const [mode, setMode] = useState<"password" | "magic">("password");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [loading, setLoading] = useState(false);
  const [localError, setLocalError] = useState<string>();
  const [sent, setSent] = useState<{ devLink?: string }>();

  const target = callbackUrl && callbackUrl.startsWith("/") ? callbackUrl : "/console";
  const ssoError = error ? SSO_ERRORS[error] ?? "Sign-in failed. Please try again." : undefined;

  const onPassword = async (e: React.FormEvent) => {
    e.preventDefault(); setLoading(true); setLocalError(undefined);
    const r = await signIn("password", { email, password, redirect: false });
    // Keep the spinner up through the redirect so the button never flickers
    // back to its idle label before the page changes.
    if (r?.error) { setLocalError("Invalid email or password."); setLoading(false); }
    else window.location.href = target;
  };
  const onMagic = async (e: React.FormEvent) => {
    e.preventDefault(); setLoading(true); setLocalError(undefined);
    const r = await requestMagic(email); setLoading(false); setSent({ devLink: r.devLink });
  };

  const tab = (active: boolean) => cn("flex-1 px-3 py-1.5 transition-colors", active ? "bg-accent-soft font-bold text-accent-fg" : "text-text2 hover:bg-surfaceHover");

  return (
    <AuthShell title="Sign in">
      {reset && <AuthBanner>Password updated. Sign in with your new password.</AuthBanner>}
      {ssoError && <AuthBanner kind="error">{ssoError}</AuthBanner>}

      {sso && (
        // `auto` when SSO is the only method: nothing to choose, so don't make
        // the user click through a one-option screen. A previous error stops the
        // auto-start so they aren't caught in a redirect loop.
        <SsoSignIn callbackUrl={target} auto={!local && !ssoError} />
      )}

      {sso && local && (
        <div className="my-4 flex items-center gap-3 text-[11px] uppercase tracking-wide text-text3">
          <span className="h-px flex-1 bg-border" />or<span className="h-px flex-1 bg-border" />
        </div>
      )}

      {local && (
        <>
          <div className="mb-4 flex gap-1 rounded-lg border p-1 text-sm">
            <button type="button" onClick={() => setMode("password")} className={tab(mode === "password")}>Password</button>
            <button type="button" onClick={() => setMode("magic")} className={tab(mode === "magic")}>Magic link</button>
          </div>

          {mode === "password" ? (
            <form onSubmit={onPassword} className="space-y-3">
              <AuthInput label="Email" type="email" required value={email} onChange={(e) => setEmail(e.target.value)} placeholder="you@example.com" />
              <AuthInput label="Password" type="password" required value={password} onChange={(e) => setPassword(e.target.value)} placeholder="••••••••" />
              {localError && <p className="text-xs text-sev-critical">{localError}</p>}
              <button className="btn-primary w-full" disabled={loading}>{loading ? <Spinner label="Signing in…" /> : "Sign in"}</button>
              <div className="text-center text-xs text-muted"><Link href="/forgot" className="underline">Forgot password?</Link></div>
            </form>
          ) : sent ? (
            <div className="text-sm">
              <p>If <b>{email}</b> has an account, a sign-in link is on its way.</p>
              {sent.devLink && <DevLink href={sent.devLink} />}
            </div>
          ) : (
            <form onSubmit={onMagic} className="space-y-3">
              <AuthInput label="Email" type="email" required value={email} onChange={(e) => setEmail(e.target.value)} placeholder="you@example.com" />
              <button className="btn-primary w-full" disabled={loading}>{loading ? <Spinner label="Sending link…" /> : "Email me a sign-in link"}</button>
            </form>
          )}
        </>
      )}

      {!local && sso && (
        <p className="mt-3 text-center text-[11px] text-text3">
          Access is managed in AutoX SSO. Ask your administrator for a role in this application.
        </p>
      )}
    </AuthShell>
  );
}
