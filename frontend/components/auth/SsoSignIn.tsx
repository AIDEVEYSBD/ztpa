"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import { signIn } from "next-auth/react";
import { Spinner } from "../ui";

type Phase = "idle" | "probing" | "waking" | "redirecting";

const POLL_MS = 2500;
const MAX_WAIT_MS = 60_000;

/**
 * Starts an AutoX authorization request, but probes the SSO's /health first.
 * AutoX can scale to zero; sending the browser into a cold instance shows the
 * host's 503 page instead of a login screen. We poll until the SSO answers with
 * its own JSON, then redirect.
 *
 * `auto` is used when SSO is the only sign-in method — there is nothing to
 * choose, so we start immediately.
 */
export function SsoSignIn({ callbackUrl = "/console", auto = false, label = "Continue with AutoX SSO" }: {
  callbackUrl?: string;
  auto?: boolean;
  label?: string;
}) {
  const [phase, setPhase] = useState<Phase>("idle");
  const started = useRef(false);

  const go = useCallback(async () => {
    if (started.current) return;
    started.current = true;
    setPhase("probing");
    const deadline = Date.now() + MAX_WAIT_MS;
    for (;;) {
      let status = "waking";
      try {
        const r = await fetch("/sso/health", { cache: "no-store" });
        status = ((await r.json()) as { status?: string }).status ?? "waking";
      } catch {
        /* treat as waking */
      }
      if (status === "live" || status === "disabled" || Date.now() > deadline) break;
      setPhase("waking");
      await new Promise((res) => setTimeout(res, POLL_MS));
    }
    setPhase("redirecting");
    // A real authorization request — never a re-render of a cached session.
    await signIn("autox", { callbackUrl });
  }, [callbackUrl]);

  useEffect(() => {
    if (auto) void go();
  }, [auto, go]);

  const busy = phase !== "idle";
  return (
    <div className="space-y-2">
      <button type="button" onClick={go} disabled={busy} className="btn-primary w-full">
        {phase === "idle" && label}
        {phase === "probing" && <Spinner label="Contacting AutoX SSO…" />}
        {phase === "waking" && <Spinner label="Waking AutoX SSO…" />}
        {phase === "redirecting" && <Spinner label="Redirecting…" />}
      </button>
      {phase === "waking" && (
        <p className="text-center text-[11px] text-text3">
          The identity service is starting up. This can take up to a minute on first use.
        </p>
      )}
    </div>
  );
}
