"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { signIn } from "next-auth/react";
import { Spinner } from "../ui";
import { AuthShell, AuthBanner } from "./AuthShell";

export function MagicSignIn({ token }: { token: string }) {
  const [error, setError] = useState<string>();

  useEffect(() => {
    if (!token) { setError("Missing link token."); return; }
    signIn("magic", { token, redirect: false }).then((r) => {
      if (r?.error) setError("This link is invalid or has expired.");
      else window.location.href = "/";
    });
  }, [token]);

  return (
    <AuthShell title="Signing you in…">
      {error ? (
        <>
          <AuthBanner kind="error">{error}</AuthBanner>
          <Link href="/login" className="btn-primary w-full">Back to sign in</Link>
        </>
      ) : (
        <Spinner label="Verifying your secure link…" />
      )}
    </AuthShell>
  );
}
