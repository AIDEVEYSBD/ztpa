"use client";

import { useCallback, useEffect, useState } from "react";
import { AnimatePresence, motion } from "framer-motion";
import { History, ShieldAlert } from "lucide-react";
import {
  api, asApiError,
  type ApiError, type HealthReport, type Provenance, type SnapshotList, type SnapshotSummary,
} from "@/lib/api";
import type { ActionItem, Finding, GraphData } from "@/lib/types";
import { Sidebar, type ScreenId } from "@/components/Sidebar";
import { Topbar } from "@/components/Topbar";
import { RiskTodo } from "@/components/RiskTodo";
import { ChangeGate } from "@/components/ChangeGate";
import { Assistant } from "@/components/Assistant";
import { ReportPanel } from "@/components/ReportPanel";
import { Connectors } from "@/components/Connectors";
import { SourcesPanel } from "@/components/SourcesPanel";
import { InventoryPanel } from "@/components/InventoryPanel";
import { ExplorerPanel } from "@/components/ExplorerPanel";
import { Staging } from "@/components/Staging";
import { SnapshotsAdmin } from "@/components/admin/SnapshotsAdmin";
import { ToolsAdmin } from "@/components/admin/ToolsAdmin";
import { MetricsAdmin } from "@/components/admin/MetricsAdmin";
import { AuditAdmin } from "@/components/admin/AuditAdmin";
import { AiConfigAdmin } from "@/components/admin/AiConfigAdmin";
import { ErrorState } from "@/components/ui/Feedback";
import { Button } from "@/components/ui/Button";
import { PanelHealthProvider, useScreenFailures } from "@/components/PanelHealth";

const META: Record<ScreenId, { title: string; sub: string }> = {
  sources: { title: "Sources", sub: "What we read, from which rung of the ladder \u2014 and what each console cannot tell us" },
  inventory: { title: "Inventory", sub: "Every device, VLAN, subnet, circuit and asset, and where each one was found" },
  explorer: { title: "Explorer", sub: "The estate layer by layer, the policy paths across it, and every finding on the map" },
  risks: { title: "Risk To-Do", sub: "What is wrong, the rules behind it, a verified fix, and the ruling" },
  change: { title: "Change Gate", sub: "Every change request and how it was ruled on" },
  staging: { title: "Implementation Queue", sub: "Approved changes, waiting to be applied to the source system" },
  ask: { title: "Ask the Network", sub: "Plain-English questions, grounded in engine facts" },
  report: { title: "Posture Report", sub: "Executive and compliance summary" },
  connectors: { title: "Connectors", sub: "Bring your own source via a validated profile" },
  snapshots: { title: "Snapshots", sub: "Point-in-time runs, with delete (admin)" },
  tools: { title: "Tools & Usage", sub: "Available tools, per-role access, and usage metrics (admin)" },
  metrics: { title: "Metrics & Cost", sub: "Application-wide KPIs, token usage and estimated cost (admin)" },
  audit: { title: "Audit trail", sub: "Every recorded action, who performed it and when (admin)" },
  config: { title: "Configuration", sub: "Which AI provider this deployment uses, and whether it can actually call it (admin)" },
};

/**
 * Per-resource load state. `status` is the whole truth about a panel:
 *   loading — nothing may be asserted yet;
 *   ok      — `data` is real and may be counted, summed and rendered;
 *   error   — `data` is absent and NOTHING derived from it may be shown as a
 *             value. A "0 critical findings" computed from a failed fetch is
 *             indistinguishable from a clean estate, and that lie is the whole
 *             reason this screen could not be trusted.
 */
type Resource<T> = { status: "loading" | "ok" | "error"; data?: T; error?: ApiError };

const LOADING: Resource<never> = { status: "loading" };

/** Drive one resource to `ok` or `error` — there is deliberately no third path
 *  where a rejection leaves the slot looking merely empty. */
function settle<T>(p: Promise<T>, set: (r: Resource<T>) => void, alive: () => boolean): void {
  p.then((data) => { if (alive()) set({ status: "ok", data }); })
   .catch((e) => { if (alive()) set({ status: "error", error: asApiError(e) }); });
}

export default function Dashboard() {
  // OPENS ON THE EXPLORER.
  //
  // It opened on Sources, on the reasoning that a review starts at "what are we
  // reading". That is true of a review and false of a product: nobody opens a
  // tool to read its bibliography. You open it to see your network, and the
  // first screen should be the one that shows it — with everything else one
  // click away from the thing you are looking at.
  const [screen, setScreen] = useState<ScreenId>("explorer");
  const [health, setHealth] = useState<Resource<HealthReport>>(LOADING);
  // Each feed keeps the WHOLE payload rather than the array inside it, because
  // the backend attaches `served_from`/`degraded_reason` to the envelope: with
  // no database it recomputes findings, the graph and the counts in memory and
  // says so, and a screen that unwrapped straight to `.findings` threw that
  // disclosure away and presented live numbers as persisted ones.
  const [counts, setCounts] = useState<Resource<SnapshotSummary>>(LOADING);
  const [findings, setFindings] = useState<Resource<{ findings: Finding[] } & Provenance>>(LOADING);
  const [graph, setGraph] = useState<Resource<GraphData & Provenance>>(LOADING);
  const [actions, setActions] = useState<Resource<{ actions: ActionItem[] } & Provenance>>(LOADING);
  const [snaps, setSnaps] = useState<Resource<SnapshotList>>(LOADING);       // prefetched on load
  const [viewSnap, setViewSnap] = useState<string | undefined>(undefined);   // undefined = live/latest
  const [attempt, setAttempt] = useState(0);                                 // bumped by Retry

  const retry = useCallback(() => setAttempt((n) => n + 1), []);

  useEffect(() => {
    let live = true;
    const alive = () => live;
    setHealth(LOADING);
    setSnaps(LOADING);
    settle(api.health(), setHealth, alive);
    // Prefetch the snapshot timeline once so the switcher opens instantly.
    settle(api.snapshots(), setSnaps, alive);
    return () => { live = false; };
  }, [attempt]);

  useEffect(() => {
    let live = true;
    const alive = () => live;
    setCounts(LOADING);
    setFindings(LOADING);
    setGraph(LOADING);
    setActions(LOADING);
    settle(api.snapshot(viewSnap), setCounts, alive);
    settle(api.findings(viewSnap), setFindings, alive);
    settle(api.graph(viewSnap), setGraph, alive);
    settle(api.actions(viewSnap), setActions, alive);
    return () => { live = false; };
  }, [viewSnap, attempt]);

  const findingList = findings.data?.findings ?? [];
  const actionList = actions.data?.actions ?? [];
  const critical = findingList.filter((f) => f.severity_band === "critical").length;
  const m = META[screen];
  const historical = !!viewSnap && !!health.data && viewSnap !== health.data.snapshot_id;

  // A nav badge is only allowed to show a number when the fetch behind it
  // succeeded. Sidebar renders nothing for a 0, which is the honest state here:
  // "we don't know" must never look like "we checked, and it's none".
  const navCounts = findings.status === "ok"
    ? { findings: counts.data?.counts?.findings ?? findingList.length, critical }
    : { findings: 0, critical: 0 };

  // DEGRADED IS NOT BROKEN. /api/health answers 503 while it is running perfectly
  // well but cannot do its whole job — no database is the common one, and it is
  // the state this repo ships in. That used to reach here as a rejected fetch,
  // so every screen carried a red "Could not load service health" panel and the
  // product looked dead. It resolves now (see lib/api.readHealth), and the
  // backend's own reasons are rendered as a warning: something IS wrong, the app
  // is still answering, and the difference is stated rather than guessed at.
  const degraded = health.status === "ok" && health.data?.status !== "ok"
    ? health.data?.degraded_reasons ?? []
    : [];

  // Every console feed, named the way the user thinks of it. The failed ones are
  // reported at the top of EVERY screen, because a failed findings fetch still
  // invalidates the counts the Map is drawing. `health` is in here for the case
  // it really did fail — a 503 with a payload is the `degraded` state above, not
  // a failure.
  const feeds = [
    ["service health", health],
    ["the snapshot summary", counts],
    ["findings", findings],
    ["the reachability graph", graph],
    ["prioritized actions", actions],
    ["the snapshot timeline", snaps],
  ] as [string, Resource<Provenance>][];
  const failures = feeds.filter(([, r]) => r.status === "error");
  // ...and the ones that have not answered yet. "Nothing has failed" is not the
  // same statement as "everything loaded", and while a feed is still in flight
  // only the first of the two is true.
  const pending = feeds.filter(([, r]) => r.status === "loading");

  // Which of them the backend recomputed in memory because it could not read
  // the persisted snapshot. Real numbers, from the same engine that produced the
  // snapshot — but not read back from the system of record, and the banner has
  // no business implying otherwise. Only the backend knows which claim it made,
  // so this is read off the payload, never inferred from the health status.
  const fromMemory = feeds
    .filter(([, r]) => r.status === "ok" && r.data?.served_from === "engine_memory")
    .map(([label]) => label);

  // ...and which ones answered but could not be read at all. The snapshot
  // timeline is the honest case: it is a history of PERSISTED runs, so with no
  // store it comes back `[]` plus a reason. That is a 200 whose payload is empty
  // ON PURPOSE, and it has to be named here or "every panel loaded" would be
  // covering for a panel that knows nothing.
  const unread = feeds
    .filter(([, r]) => r.status === "ok" && r.data?.served_from === "unavailable")
    .map(([label]) => label);

  return (
    <div id="app-shell" className="flex h-screen w-full overflow-hidden bg-canvas text-fg">
      <Sidebar active={screen} onSelect={setScreen} counts={navCounts} />
      <div id="app-col" className="flex min-w-0 flex-1 flex-col">
        <Topbar title={m.title} sub={m.sub} viewSnap={viewSnap} onViewSnap={setViewSnap}
          snaps={snaps.data?.snapshots ?? []} snapsUnknown={snaps.data?.degraded_reason} />
        {/* Everything the banner is entitled to talk about lives inside this
            provider: the console's own failure panels AND the child screen's.
            A failure panel registers itself by being rendered (see
            components/PanelHealth.tsx), which is what makes it impossible for
            the banner to assert that the panels below it are fine while one of
            them is on screen saying otherwise. */}
        <PanelHealthProvider>
        <main id="app-main" className="zt-scroll relative min-h-0 grow overflow-x-hidden overflow-y-auto overscroll-contain">
          {degraded.length > 0 && (
            <DegradedBanner degraded={degraded} feedCount={feeds.length} failed={failures.length}
              pending={pending.length} fromMemory={fromMemory} unread={unread} onRetry={retry} />
          )}
          {failures.length > 0 && (
            <div className="m-4 space-y-2">
              {failures.map(([label, r]) => (
                <ErrorState key={label} resource={label} error={r.error} onRetry={retry} />
              ))}
              {failures.length > 1 && (
                <p className="text-[11.5px] text-faint">
                  {failures.length} of {feeds.length} console feeds failed. Treat every number on this screen as unknown until they load.
                </p>
              )}
            </div>
          )}
          <AnimatePresence>
            {historical && (
              <motion.div key="hist-banner" initial={{ opacity: 0, height: 0 }} animate={{ opacity: 1, height: "auto" }} exit={{ opacity: 0, height: 0 }}
                className="flex flex-wrap items-center gap-2 overflow-hidden border-b border-line bg-raise/55 px-5 py-2 text-[12.5px] text-dim">
                <History size={13} className="shrink-0 text-run" />
                <span className="min-w-0">Viewing a past snapshot <span className="tnum font-mono text-[11px] text-fg">@{viewSnap!.replace(/^snap_/, "").slice(0, 7)}</span> (read-only). Live actions use the latest snapshot.</span>
                <button onClick={() => setViewSnap(undefined)} className="focusable ml-auto shrink-0 cursor-pointer font-medium text-fg underline">Back to live</button>
              </motion.div>
            )}
          </AnimatePresence>
          <div id="app-content" className="mx-auto w-full max-w-[1520px] px-5 py-7 3xl:max-w-[1800px] 4xl:max-w-[2160px]">
            <AnimatePresence mode="wait">
              <motion.div key={`${screen}:${viewSnap ?? "live"}`}
                initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}
                transition={{ duration: 0.15, ease: "easeOut" }}>
                {screen === "sources" && <SourcesPanel snapshot={viewSnap} />}
                {screen === "inventory" && <InventoryPanel snapshot={viewSnap} />}
                {screen === "explorer" && (
                  <ExplorerPanel snapshot={viewSnap} findings={findingList}
                    findingsError={findings.error} />
                )}
                {screen === "risks" && (
                  <RiskTodo actions={actionList} findings={findingList} readOnly={historical}
                    loading={actions.status === "loading" || findings.status === "loading"}
                    actionsError={actions.error} findingsError={findings.error} onRetry={retry}
                    onNavigate={setScreen} />
                )}
                {screen === "change" && <ChangeGate onNavigate={setScreen} />}
                {screen === "staging" && <Staging />}
                {screen === "ask" && <Assistant />}
                {screen === "report" && <ReportPanel />}
                {screen === "connectors" && <Connectors />}
                {/* "Identity & merges" was absorbed into Inventory. Kept as a
                    redirect so an old nav entry or a bookmark lands on the
                    merged screen rather than on a blank panel; remove with the
                    nav entry itself. */}
                {screen === "snapshots" && <SnapshotsAdmin onView={(id) => { setViewSnap(id); setScreen("explorer"); }} />}
                {screen === "tools" && <ToolsAdmin />}
                {screen === "metrics" && <MetricsAdmin />}
                {screen === "audit" && <AuditAdmin />}
                {screen === "config" && <AiConfigAdmin />}
              </motion.div>
            </AnimatePresence>
          </div>
        </main>
        </PanelHealthProvider>
      </div>
    </div>
  );
}

/**
 * The degraded-state notice — and the paragraph that used to lie.
 *
 * "It answered, and reported N problems with itself. Every panel below loaded."
 * The second sentence was unconditional on anything the component had measured.
 * `failures` covers the six CONSOLE feeds this page fetches; the panels a user
 * is looking at belong to the child screen, which fetches its own data. On the
 * Change Gate with no database, that sentence rendered directly above two HTTP
 * 500 panels — the exact state the banner exists to describe.
 *
 * It is now split into four mutually exclusive claims, each one restricted to
 * something actually observed:
 *   - a console feed failed        -> say how many, of how many
 *   - a panel on this screen failed -> say so, and name it (`useScreenFailures`,
 *     fed by every ErrorState/InlineError mounted underneath this banner)
 *   - a console feed is still in flight -> claim nothing yet
 *   - none of the above            -> the only branch allowed to reassure, and
 *     even then it says "no panel is reporting a failure", which is true at the
 *     instant it renders, rather than "every panel loaded", which is a claim
 *     about panels that may still be loading.
 */
function DegradedBanner({ degraded, feedCount, failed, pending, fromMemory, unread, onRetry }: {
  /** The backend's own `degraded_reasons`, rendered verbatim. */
  degraded: string[];
  /** How many console-level feeds exist, so "N of M" is a real fraction. */
  feedCount: number;
  /** How many of them errored. */
  failed: number;
  /** How many have not answered yet. */
  pending: number;
  /** Feeds the backend said it recomputed in memory instead of reading back. */
  fromMemory: string[];
  /** Feeds it answered for but could not read at all. */
  unread: string[];
  onRetry: () => void;
}) {
  const screenFailures = useScreenFailures();

  const panelClaim =
    failed > 0
      ? ` ${failed} of the ${feedCount} console feeds below did not load — see the errors under this notice.`
      : screenFailures.length > 0
        ? ` The ${feedCount} console feeds below loaded, but ${screenFailures.length === 1 ? "a panel" : `${screenFailures.length} panels`} on this screen could not: ${screenFailures.join(", ")}. See the errors under this notice.`
        : pending > 0
          ? " The panels below have not finished loading, so nothing under this notice has been checked yet."
          : ` All ${feedCount} console feeds below loaded, and no panel on this screen is reporting a failure.`;

  return (
    <div role="status" className="relative m-4 flex gap-3 overflow-hidden rounded-lg border border-line bg-surface p-3.5 pl-4 elev-1">
      <span aria-hidden className="absolute inset-y-0 left-0 w-[3px] bg-run" />
      <ShieldAlert size={15} className="mt-0.5 shrink-0 text-run" />
      <div className="min-w-0 flex-1">
        <div className="text-[13px] font-medium text-fg">
          The backend is running in a degraded state
        </div>
        <p className="mt-1 text-[12.5px] leading-[1.55] text-dim">
          It answered, and reported
          {degraded.length === 1 ? " this problem" : ` these ${degraded.length} problems`} with
          itself.{panelClaim}
          {fromMemory.length > 0 &&
            ` ${fromMemory.join(", ")} came from the running engine rather than from the persisted snapshot: the numbers are real, but they were not read back from the system of record.`}
          {unread.length > 0 &&
            ` ${unread.join(", ")} could not be read at all — treat it as unknown, not as empty.`}
          {" "}Anything durable (snapshots, decisions, the audit trail) may not be being written.
        </p>
        <ul className="mt-1.5 space-y-0.5 font-mono text-[10.5px] text-faint">
          {degraded.map((reason) => <li key={reason}>· {reason}</li>)}
        </ul>
      </div>
      <Button size="sm" variant="solid" tone="ink" className="shrink-0" onClick={onRetry}>Re-check</Button>
    </div>
  );
}
