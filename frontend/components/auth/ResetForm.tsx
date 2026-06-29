"use client";

import { useState } from "react";
import Link from "next/link";
import { doReset } from "@/app/actions";
import { Spinner } from "../ui";
import { AuthShell, AuthInput, AuthBanner } from "./AuthShell";

export function ResetForm({ token }: { token: string }) {
  const [password, setPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string>();

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (password !== confirm) { setError("Passwords do not match."); return; }
    setLoading(true); setError(undefined);
    const r = await doReset(token, password);
    if (r.ok) window.location.href = "/login?reset=1";
    else { setError(r.error); setLoading(false); }
  };

  if (!token) {
    return (
      <AuthShell title="Reset your password">
        <AuthBanner kind="error">Missing reset token.</AuthBanner>
        <Link href="/forgot" className="btn-primary w-full">Request a new link</Link>
      </AuthShell>
    );
  }

  return (
    <AuthShell title="Set a new password">
      <form onSubmit={submit} className="space-y-3">
        <AuthInput label="New password" type="password" required minLength={8} value={password} onChange={(e) => setPassword(e.target.value)} placeholder="at least 8 characters" />
        <AuthInput label="Confirm password" type="password" required value={confirm} onChange={(e) => setConfirm(e.target.value)} />
        {error && <p className="text-xs text-sev-critical">{error}</p>}
        <button className="btn-primary w-full" disabled={loading}>{loading ? <Spinner label="Updating…" /> : "Update password"}</button>
      </form>
    </AuthShell>
  );
}
