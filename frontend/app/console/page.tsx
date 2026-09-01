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
import { NetworkMap } from "@/components/NetworkMap";
import { RiskTodo } from "@/components/RiskTodo";
import { ChangeGate } from "@/components/ChangeGate";
import { Assistant } from "@/components/Assistant";
import { ReportPanel } from "@/components/ReportPanel";
import { Connectors } from "@/components/Connectors";
import { AssetsPanel } from "@/components/AssetsPanel";
import { IngestInspector } from "@/components/IngestInspector";
import { Staging } from "@/components/Staging";
import { UsersAdmin } from "@/components/admin/UsersAdmin";
import { SnapshotsAdmin } from "@/components/admin/SnapshotsAdmin";
import { ToolsAdmin } from "@/components/admin/ToolsAdmin";
import { MetricsAdmin } from "@/components/admin/MetricsAdmin";
import { ErrorState } from "@/components/ui/Feedback";

const META: Record<ScreenId, { title: string; sub: string }> = {
  map: { title: "Network Map", sub: "Unified reachability across AlgoSec, Guardicore and Wiz" },
  risks: { title: "Risk To-Do", sub: "Prioritized actions — iterate a fix, then send it to the Change Gate" },
  change: { title: "Change Gate", sub: "Simulated delta, then auto-approve or escalate — then send to staging" },
  staging: { title: "Staging Area", sub: "Approved changes, ready to push to the source system" },
  ask: { title: "Ask the Network", sub: "Plain-English questions, grounded in engine facts" },
  report: { title: "Posture Report", sub: "Executive and compliance summary" },
  connectors: { title: "Connectors", sub: "Bring your own source via a validated profile" },
  assets: { title: "Assets & Identity", sub: "One identity per asset, IP is an attribute" },
  ingest: { title: "Ingested data", sub: "What the connectors produced for this snapshot (admin)" },
  users: { title: "Manage users", sub: "Invite users and assign roles (admin)" },
  snapshots: { title: "Snapshots", sub: "Point-in-time runs, with delete (admin)" },
  tools: { title: "Tools & Usage", sub: "Available tools, per-role access, and usage metrics (admin)" },
  metrics: { title: "Metrics & Cost", sub: "Application-wide KPIs, token usage and estimated cost (admin)" },
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
  const [screen, setScreen] = useState<ScreenId>("map");
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
    <div id="app-shell" className="flex h-screen w-full overflow-hidden bg-aurora text-text">
      <Sidebar active={screen} onSelect={setScreen} counts={navCounts} />
      <div id="app-col" className="flex min-w-0 flex-1 flex-col">
        <Topbar title={m.title} sub={m.sub} viewSnap={viewSnap} onViewSnap={setViewSnap}
          snaps={snaps.data?.snapshots ?? []} snapsUnknown={snaps.data?.degraded_reason} />
        <main id="app-main" className="zt-scroll relative flex-1 overflow-x-hidden overflow-y-auto">
          {degraded.length > 0 && (
            <div role="status" className="m-4 border border-sev-medium-line bg-sev-medium-bg p-3.5">
              <div className="flex items-start gap-2.5">
                <ShieldAlert size={16} className="mt-0.5 shrink-0 text-sev-medium" />
                <div className="min-w-0 flex-1">
                  <div className="text-[13px] font-bold text-sev-medium">
                    The backend is running in a degraded state
                  </div>
                  {/* This paragraph used to assert, unconditionally, that every panel */}
                  {/* under it held real computed data — a claim about fetches this */}
                  {/* component had not looked at, and false in the exact state the */}
                  {/* banner exists to describe: with no database every data feed below */}
                  {/* it answered 500, and the banner said otherwise anyway. It may only */}
                  {/* state what `failures` and `fromMemory` measured, so every clause is */}
                  {/* now conditional on one of them. */}
                  <p className="mt-1 text-[12px] leading-relaxed text-text2">
                    It answered, and reported
                    {degraded.length === 1 ? " this problem" : ` these ${degraded.length} problems`} with
                    itself.{failures.length === 0
                      ? " Every panel below loaded."
                      : ` ${failures.length} of the ${feeds.length} panels below did not load — see the errors under this notice.`}
                    {fromMemory.length > 0 &&
                      ` ${fromMemory.join(", ")} came from the running engine rather than from the persisted snapshot: the numbers are real, but they were not read back from the system of record.`}
                    {unread.length > 0 &&
                      ` ${unread.join(", ")} could not be read at all — treat it as unknown, not as empty.`}
                    {" "}Anything durable (snapshots, decisions, the audit trail) may not be being written.
                  </p>
                  <ul className="mono mt-1.5 space-y-0.5 text-[11px] text-text3">
                    {degraded.map((reason) => <li key={reason}>· {reason}</li>)}
                  </ul>
                </div>
                <button onClick={retry} className="btn-ghost shrink-0 text-xs">Re-check</button>
              </div>
            </div>
          )}
          {failures.length > 0 && (
            <div className="m-4 space-y-2">
              {failures.map(([label, r]) => (
                <ErrorState key={label} resource={label} error={r.error} onRetry={retry} />
              ))}
              {failures.length > 1 && (
                <p className="text-[11.5px] text-text3">
                  {failures.length} of {feeds.length} console feeds failed. Treat every number on this screen as unknown until they load.
                </p>
              )}
            </div>
          )}
          <AnimatePresence>
            {historical && (
              <motion.div key="hist-banner" initial={{ opacity: 0, height: 0 }} animate={{ opacity: 1, height: "auto" }} exit={{ opacity: 0, height: 0 }}
                className="flex flex-wrap items-center gap-2 overflow-hidden border-b border-accent bg-accent-soft px-5 py-2 text-[12.5px]">
                <History size={14} className="shrink-0" />
                <span className="min-w-0">Viewing a past snapshot <span className="mono">@{viewSnap!.replace(/^snap_/, "").slice(0, 7)}</span> (read-only). Live actions use the latest snapshot.</span>
                <button onClick={() => setViewSnap(undefined)} className="ml-auto shrink-0 font-bold underline">Back to live</button>
              </motion.div>
            )}
          </AnimatePresence>
          <div id="app-content" className="mx-auto max-w-[1320px] p-5 lg:p-6 2xl:max-w-[1520px] 3xl:max-w-[1800px] 3xl:p-8 4xl:max-w-[2160px]">
            <AnimatePresence mode="wait">
              <motion.div key={`${screen}:${viewSnap ?? "live"}`}
                initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}
                transition={{ duration: 0.15, ease: "easeOut" }}>
                {screen === "map" && (
                  <NetworkMap graph={graph.data} findings={findingList} counts={counts.data?.counts ?? {}}
                    loading={graph.status === "loading"} graphError={graph.error}
                    findingsError={findings.error ?? counts.error} onRetry={retry} />
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
                {screen === "assets" && <AssetsPanel snapshot={viewSnap} />}
                {screen === "ingest" && <IngestInspector snapshot={viewSnap} />}
                {screen === "users" && <UsersAdmin />}
                {screen === "snapshots" && <SnapshotsAdmin onView={(id) => { setViewSnap(id); setScreen("map"); }} />}
                {screen === "tools" && <ToolsAdmin />}
                {screen === "metrics" && <MetricsAdmin />}
              </motion.div>
            </AnimatePresence>
          </div>
        </main>
      </div>
    </div>
  );
}
