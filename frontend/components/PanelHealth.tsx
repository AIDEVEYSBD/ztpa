"use client";

/**
 * A screen-aware failure signal for the console shell.
 *
 * WHY THIS EXISTS. The degraded banner at the top of `app/console/page.tsx`
 * asserted, whenever its own six feeds happened to be clean, that "Every panel
 * below loaded." The banner could not know that. It measures six console-level
 * fetches; the panel a user is actually looking at belongs to a child screen
 * that fetches its own data. On the Change Gate with no database, the banner
 * rendered that sentence with two HTTP 500 error panels visible directly
 * underneath it — a false claim, in the exact state the banner exists to
 * describe, and the third time this codebase has been caught asserting a fact
 * about a fetch it never looked at.
 *
 * HOW IT WORKS, AND WHY IT IS WIRED HERE RATHER THAN IN EVERY SCREEN. The
 * registration happens inside `ErrorState` / `InlineError` themselves (see
 * `components/ui/Feedback.tsx`) — the two components every screen already uses
 * to render a failure, an invariant pinned by
 * `backend/tests/test_frontend_error_surfacing.py`. So a screen cannot fail
 * "quietly" as far as the banner is concerned: rendering the failure IS the
 * report. A new screen added tomorrow is covered the moment it renders an error
 * panel, with no line of code to remember. The alternative — a hook each screen
 * must call — is one more thing to forget, and forgetting is precisely the
 * failure mode being fixed.
 *
 * The provider therefore counts MOUNTED failure panels, not fetch outcomes. It
 * answers one question and no more: "is anything below this banner currently
 * telling the user it failed?" That is a claim the banner can support, at every
 * instant, including while panels are still loading.
 */

import {
  createContext, useCallback, useContext, useEffect, useId, useMemo, useState,
  type ReactNode,
} from "react";

type Registry = {
  /** Announce (or update) a failure panel. Idempotent per key. */
  report: (key: string, resource: string) => void;
  /** Withdraw it — the panel unmounted, i.e. the failure is no longer on screen. */
  release: (key: string) => void;
};

const RegistryCtx = createContext<Registry | null>(null);
/** The live set of resources whose failure panels are mounted, sorted by
 *  resource name so the order is stable across renders. */
const FailuresCtx = createContext<readonly string[]>([]);

/**
 * Wrap the subtree whose failures the banner should account for — in practice
 * the console's screen content, NOT the console-level error panels above it
 * (those are already counted from their own `Resource` state, and counting them
 * twice would overstate the damage).
 */
export function PanelHealthProvider({ children }: { children: ReactNode }) {
  const [panels, setPanels] = useState<Record<string, string>>({});

  // Both callbacks are stable and both bail out when nothing changes, so a
  // child's registration effect cannot drive a render loop: report -> setState
  // -> re-render -> report with the same arguments -> no state change -> stop.
  const report = useCallback((key: string, resource: string) => {
    setPanels((prev) => (prev[key] === resource ? prev : { ...prev, [key]: resource }));
  }, []);

  const release = useCallback((key: string) => {
    setPanels((prev) => {
      if (!(key in prev)) return prev;
      const next = { ...prev };
      delete next[key];
      return next;
    });
  }, []);

  const registry = useMemo<Registry>(() => ({ report, release }), [report, release]);
  const failures = useMemo(() => Object.values(panels).sort(), [panels]);

  return (
    <RegistryCtx.Provider value={registry}>
      <FailuresCtx.Provider value={failures}>{children}</FailuresCtx.Provider>
    </RegistryCtx.Provider>
  );
}

/**
 * Called by a failure panel to put itself on the record.
 *
 * `mounted` is a parameter rather than a condition around the call because
 * hooks cannot be conditional: a panel that renders nothing (no error) still
 * calls this, with `false`, and stays out of the registry.
 *
 * Outside a provider — the sign-in pages, `/no-access` — the context is null and
 * this is a no-op, so `ErrorState` remains usable anywhere.
 */
export function useReportedFailure(resource: string, mounted: boolean): void {
  const key = useId();
  const registry = useContext(RegistryCtx);
  useEffect(() => {
    if (!registry || !mounted) return;
    registry.report(key, resource);
    return () => registry.release(key);
  }, [registry, key, resource, mounted]);
}

/**
 * The resources whose failure panels are on screen right now, for the banner.
 * Empty means "nothing below has reported a failure" — which is all the banner
 * is entitled to say, and is true whether the panels finished loading or not.
 */
export function useScreenFailures(): readonly string[] {
  return useContext(FailuresCtx);
}
