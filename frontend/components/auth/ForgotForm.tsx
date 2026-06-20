"use client";

import { useState } from "react";
import Link from "next/link";
import { requestReset } from "@/app/actions";
import { Spinner } from "../ui";
import { AuthShell, AuthInput, DevLink } from "./AuthShell";

export function ForgotForm() {
  const [email, setEmail] = useState("");
  const [loading, setLoading] = useState(false);
  const [sent, setSent] = useState<{ devLink?: string }>();

  const submit = async (e: React.FormEvent) => {
    e.preventDefault(); setLoading(true);
    const r = await requestReset(email); setLoading(false); setSent({ devLink: r.devLink });
  };

  return (
    <AuthShell title="Reset your password">
      {sent ? (
        <div className="text-sm">
          <p>If <b>{email}</b> has an account, a reset link is on its way.</p>
          {sent.devLink && <DevLink href={sent.devLink} />}
          <Link href="/login" className="mt-4 block text-center text-xs text-muted underline">Back to sign in</Link>
        </div>
      ) : (
        <form onSubmit={submit} className="space-y-3">
          <AuthInput label="Email" type="email" required value={email} onChange={(e) => setEmail(e.target.value)} placeholder="you@example.com" />
          <button className="btn-primary w-full" disabled={loading}>{loading ? <Spinner /> : "Send reset link"}</button>
          <Link href="/login" className="block text-center text-xs text-muted underline">Back to sign in</Link>
        </form>
      )}
    </AuthShell>
  );
}
