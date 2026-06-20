"use client";

import { useEffect, useState } from "react";
import { AnimatePresence, motion } from "framer-motion";
import { History } from "lucide-react";
import { api } from "@/lib/api";
import type { ActionItem, Finding, GraphData, Health } from "@/lib/types";
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
import { UsersAdmin } from "@/components/admin/UsersAdmin";
import { SnapshotsAdmin } from "@/components/admin/SnapshotsAdmin";

const META: Record<ScreenId, { title: string; sub: string }> = {
  map: { title: "Network Map", sub: "Unified reachability across AlgoSec, Guardicore and Wiz" },
  risks: { title: "Risk To-Do", sub: "Prioritized, root-cause-grouped actions, worst first" },
  change: { title: "Change Gate", sub: "Simulated delta, then auto-approve or escalate" },
  ask: { title: "Ask the Network", sub: "Plain-English questions, grounded in engine facts" },
  report: { title: "Posture Report", sub: "Executive and compliance summary" },
  connectors: { title: "Connectors", sub: "Bring your own source via a validated profile" },
  assets: { title: "Assets & Identity", sub: "One identity per asset, IP is an attribute" },
  ingest: { title: "Ingested data", sub: "What the connectors produced for this snapshot (admin)" },
  users: { title: "Manage users", sub: "Invite users and assign roles (admin)" },
  snapshots: { title: "Snapshots", sub: "Point-in-time runs, with delete (admin)" },
};

export default function Dashboard() {
  const [screen, setScreen] = useState<ScreenId>("map");
  const [health, setHealth] = useState<Health>();
  const [counts, setCounts] = useState<Record<string, number>>({});
  const [findings, setFindings] = useState<Finding[]>([]);
  const [graph, setGraph] = useState<GraphData>();
  const [actions, setActions] = useState<ActionItem[]>([]);
  const [err, setErr] = useState<string>();
  const [viewSnap, setViewSnap] = useState<string | undefined>(undefined);  // undefined = live/latest
  const [snaps, setSnaps] = useState<any[]>([]);                            // prefetched on load
  const [loading, setLoading] = useState({ findings: true, graph: true, actions: true });

  useEffect(() => { api.health().then(setHealth).catch((e) => setErr(String(e))); }, []);
  // Prefetch the snapshot timeline once so the switcher opens instantly.
  useEffect(() => { api.snapshots().then((s) => setSnaps(s.snapshots)).catch(() => {}); }, []);

  useEffect(() => {
    let live = true;
    setLoading({ findings: true, graph: true, actions: true });
    api.snapshot(viewSnap).then((s) => { if (live) setCounts(s.counts); }).catch(() => {});
    api.findings(viewSnap).then((f) => { if (live) setFindings(f.findings); }).catch(() => {}).finally(() => { if (live) setLoading((l) => ({ ...l, findings: false })); });
    api.graph(viewSnap).then((g) => { if (live) setGraph(g); }).catch(() => {}).finally(() => { if (live) setLoading((l) => ({ ...l, graph: false })); });
    api.actions(viewSnap).then((a) => { if (live) setActions(a.actions); }).catch(() => {}).finally(() => { if (live) setLoading((l) => ({ ...l, actions: false })); });
    return () => { live = false; };
  }, [viewSnap]);

  const critical = findings.filter((f) => f.severity_band === "critical").length;
  const m = META[screen];
  const historical = !!viewSnap && !!health && viewSnap !== health.snapshot_id;

  return (
    <div id="app-shell" className="flex h-screen w-full overflow-hidden bg-bg text-text">
      <Sidebar active={screen} onSelect={setScreen} counts={{ findings: counts.findings ?? findings.length, critical }} />
      <div id="app-col" className="flex min-w-0 flex-1 flex-col">
        <Topbar title={m.title} sub={m.sub} viewSnap={viewSnap} onViewSnap={setViewSnap} snaps={snaps} />
        <main id="app-main" className="zt-scroll relative flex-1 overflow-x-hidden overflow-y-auto">
          {err && (
            <div className="sunk m-4 border-sev-critical-line bg-sev-critical-bg p-3 text-[13px] text-sev-critical">
              Backend unreachable: {err}. Is the API running on :8000?
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
          <div id="app-content" className="mx-auto max-w-[1320px] p-5 lg:p-6">
            <AnimatePresence mode="wait">
              <motion.div key={`${screen}:${viewSnap ?? "live"}`}
                initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0, y: -6 }}
                transition={{ duration: 0.22, ease: "easeOut" }}>
                {screen === "map" && <NetworkMap graph={graph} findings={findings} counts={counts} loading={loading.graph} />}
                {screen === "risks" && <RiskTodo actions={actions} findings={findings} readOnly={historical} loading={loading.actions || loading.findings} />}
                {screen === "change" && <ChangeGate />}
                {screen === "ask" && <Assistant />}
                {screen === "report" && <ReportPanel />}
                {screen === "connectors" && <Connectors />}
                {screen === "assets" && <AssetsPanel snapshot={viewSnap} />}
                {screen === "ingest" && <IngestInspector snapshot={viewSnap} />}
                {screen === "users" && <UsersAdmin />}
                {screen === "snapshots" && <SnapshotsAdmin onView={(id) => { setViewSnap(id); setScreen("map"); }} />}
              </motion.div>
            </AnimatePresence>
          </div>
        </main>
      </div>
    </div>
  );
}
