"use client";

import { useState } from "react";
import Link from "next/link";
import { signIn } from "next-auth/react";
import { requestMagic } from "@/app/actions";
import { cn, Spinner } from "../ui";
import { AuthShell, AuthInput, AuthBanner, DevLink } from "./AuthShell";

export function LoginForm({ reset }: { reset?: boolean }) {
  const [mode, setMode] = useState<"password" | "magic">("password");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string>();
  const [sent, setSent] = useState<{ devLink?: string }>();

  const onPassword = async (e: React.FormEvent) => {
    e.preventDefault(); setLoading(true); setError(undefined);
    const r = await signIn("password", { email, password, redirect: false });
    // Keep the spinner up through the redirect so the button never flickers
    // back to its idle label before the page changes.
    if (r?.error) { setError("Invalid email or password."); setLoading(false); }
    else window.location.href = "/console";
  };
  const onMagic = async (e: React.FormEvent) => {
    e.preventDefault(); setLoading(true); setError(undefined);
    const r = await requestMagic(email); setLoading(false); setSent({ devLink: r.devLink });
  };

  const tab = (active: boolean) => cn("flex-1 px-3 py-1.5 transition-colors", active ? "bg-accent-soft font-bold text-accent-fg" : "text-text2 hover:bg-surfaceHover");

  return (
    <AuthShell title="Sign in">
      {reset && <AuthBanner>Password updated. Sign in with your new password.</AuthBanner>}
      <div className="mb-4 flex gap-1 rounded-lg border p-1 text-sm">
        <button type="button" onClick={() => setMode("password")} className={tab(mode === "password")}>Password</button>
        <button type="button" onClick={() => setMode("magic")} className={tab(mode === "magic")}>Magic link</button>
      </div>

      {mode === "password" ? (
        <form onSubmit={onPassword} className="space-y-3">
          <AuthInput label="Email" type="email" required value={email} onChange={(e) => setEmail(e.target.value)} placeholder="you@example.com" />
          <AuthInput label="Password" type="password" required value={password} onChange={(e) => setPassword(e.target.value)} placeholder="••••••••" />
          {error && <p className="text-xs text-sev-critical">{error}</p>}
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
    </AuthShell>
  );
}
