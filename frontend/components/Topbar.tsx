"use client";

import { useEffect, useState } from "react";
import { useSession } from "next-auth/react";
import { RefreshCw, ChevronDown, FlaskConical, Check, History } from "lucide-react";
import { api } from "@/lib/api";
import { cn } from "./ui";

const STAGES = [
  "Reading simulated exports",
  "Resolving asset identities",
  "Building reachability graph",
  "Running the 4 analyzers",
  "Scoring + guardrail floor",
  "Persisting snapshot to Neon",
];

type Scenario = { id: string; label: string; description: string };
const short = (id: string) => id.replace(/^snap_/, "").slice(0, 7);

export function Topbar({ title, sub, viewSnap, onViewSnap, snaps = [] }:
  { title: string; sub: string; viewSnap?: string; onViewSnap: (id?: string) => void; snaps?: any[] }) {
  const { data } = useSession();
  const isAdmin = (data?.user as any)?.role === "admin";
  const [scenarios, setScenarios] = useState<Scenario[]>([]);
  const [activeScenario, setActiveScenario] = useState<string>("");
  const [dsOpen, setDsOpen] = useState(false);
  const [snapOpen, setSnapOpen] = useState(false);
  const [busy, setBusy] = useState<{ label: string; stage: number; result?: any } | null>(null);

  useEffect(() => { api.scenarios().then((s) => { setScenarios(s.scenarios); setActiveScenario(s.active); }).catch(() => {}); }, []);

  const runWithOverlay = async (label: string, fn: () => Promise<any>) => {
    setDsOpen(false); setSnapOpen(false);
    setBusy({ label, stage: 0 });
    const timer = setInterval(() => setBusy((b) => (b && !b.result ? { ...b, stage: Math.min(b.stage + 1, STAGES.length - 1) } : b)), 300);
    let result: any = {};
    try { result = (await fn())?.summary ?? {}; } catch { result = { error: true }; }
    clearInterval(timer);
    setBusy((b) => (b ? { ...b, stage: STAGES.length, result } : b));
    await new Promise((r) => setTimeout(r, 2400));
    window.location.reload();
  };

  return (
    <>
      <header className="flex h-14 shrink-0 items-center gap-2.5 border-b border-border bg-surface px-5">
        <div className="flex min-w-0 flex-col justify-center gap-0.5">
          <h1 className="m-0 truncate text-[15px] font-bold leading-tight tracking-[-0.01em]">{title}</h1>
          <span className="truncate text-[11px] leading-tight text-text3">{sub}</span>
        </div>
        <div className="flex-1" />

        {/* snapshot timeline (permanent, all users) */}
        <div className="relative">
          <button onClick={() => setSnapOpen((o) => !o)}
            className={cn("btn-ghost !h-8", viewSnap && "!border-accent")} title="Browse point-in-time snapshots">
            <History size={14} />
            <span className="hidden sm:inline">{viewSnap ? `Viewing @${short(viewSnap)}` : "Live"}</span>
            <ChevronDown size={13} />
          </button>
          {snapOpen && (
            <>
              <div className="fixed inset-0 z-40" onClick={() => setSnapOpen(false)} />
              <div className="panel absolute right-0 z-50 mt-1 max-h-[460px] w-[340px] overflow-y-auto p-1 shadow-[0_8px_28px_rgba(0,0,0,0.25)]">
                <div className="label px-2 py-1.5">Snapshot timeline</div>
                <button onClick={() => { onViewSnap(undefined); setSnapOpen(false); }} className="row block w-full px-2 py-2 text-left">
                  <div className="flex items-center gap-2 text-[13px] font-bold"><span className="h-2 w-2 bg-ok" /> Live (latest)</div>
                </button>
                <div className="relative ml-3 mt-1 border-l border-border">
                  {snaps.map((s) => (
                    <button key={s.snapshot_id} onClick={() => { onViewSnap(s.snapshot_id); setSnapOpen(false); }}
                      className="row block w-full py-2 pl-4 pr-2 text-left">
                      <span className={cn("absolute -ml-[21px] mt-1 h-2 w-2 border", viewSnap === s.snapshot_id ? "border-accent bg-accent" : "border-borderStrong bg-surface")} />
                      <div className="flex items-center gap-2">
                        <span className="mono text-[12px] font-bold">@{short(s.snapshot_id)}</span>
                        {s.label && <span className="text-[10px] text-text3">{s.label}</span>}
                      </div>
                      <div className="mono mt-0.5 text-[10px] text-text3">{s.findings} findings · {s.critical} critical · {new Date(s.created_at).toLocaleString()}</div>
                    </button>
                  ))}
                  {!snaps.length && <div className="py-3 pl-4 text-[11px] text-text3">no snapshots yet</div>}
                </div>
              </div>
            </>
          )}
        </div>

        {/* demo dataset switcher (admin only, visually marked as demo) */}
        {isAdmin && scenarios.length > 0 && (
          <div className="relative">
            <button onClick={() => setDsOpen((o) => !o)}
              className="btn-ghost !h-8 !border-dashed" title="Demo only: swaps the simulated dataset">
              <FlaskConical size={14} className="text-text3" />
              <span className="hidden md:inline">Demo: {scenarios.find((s) => s.id === activeScenario)?.label ?? "data"}</span>
              <ChevronDown size={13} />
            </button>
            {dsOpen && (
              <>
                <div className="fixed inset-0 z-40" onClick={() => setDsOpen(false)} />
                <div className="panel absolute right-0 z-50 mt-1 w-[320px] p-1 shadow-[0_8px_28px_rgba(0,0,0,0.25)]">
                  <div className="label px-2 py-1.5">Demo dataset · simulated</div>
                  {scenarios.map((s) => (
                    <button key={s.id} onClick={() => runWithOverlay(`Switching to ${s.label}`, () => api.switchDataset(s.id))}
                      className="row block w-full px-2 py-2 text-left">
                      <div className="flex items-center gap-2 text-[13px] font-bold">
                        {s.label}
                        {s.id === activeScenario && <span className="mono bg-accent px-1 text-[9px] text-accent-ink">CURRENT</span>}
                      </div>
                      <div className="text-[11px] text-text3">{s.description}</div>
                    </button>
                  ))}
                </div>
              </>
            )}
          </div>
        )}

        <button onClick={() => runWithOverlay("Recomputing snapshot", () => api.recompute())} disabled={!!busy}
          className="btn-ghost !h-8" title="Re-run the deterministic engine live">
          <RefreshCw size={13} className={busy ? "animate-spin" : ""} /> <span className="hidden sm:inline">Recompute</span>
        </button>
      </header>

      {busy && (
        <div className="fixed inset-0 z-[200] grid place-items-center bg-[rgba(10,10,16,0.62)] backdrop-blur-sm">
          <div className="panel w-[440px] p-6">
            <div className="flex items-center gap-2 text-[14px] font-bold">
              {busy.result ? <Check size={16} className="text-ok" /> : <RefreshCw size={16} className="animate-spin text-accent" />}
              {busy.result ? "Snapshot recomputed" : busy.label}
            </div>
            {!busy.result ? (
              <div className="mt-4 space-y-2.5">
                {STAGES.map((s, i) => (
                  <div key={i} className="flex items-center gap-2.5 text-[12.5px]">
                    <span className={`grid h-4 w-4 shrink-0 place-items-center border ${i < busy.stage ? "border-ok-line bg-ok" : i === busy.stage ? "border-accent" : "border-border"}`}>
                      {i < busy.stage && <Check size={10} className="text-white" />}
                      {i === busy.stage && <span className="h-1.5 w-1.5 animate-pulse bg-accent" />}
                    </span>
                    <span className={i <= busy.stage ? "text-text" : "text-text3"}>{s}</span>
                  </div>
                ))}
              </div>
            ) : (
              <div className="mt-4">
                <div className="mb-3 text-[12.5px] text-text2">Deterministic engine ran in <b className="mono text-text">{busy.result.timings?.total ?? "?"} ms</b></div>
                <div className="mb-3 space-y-1.5">
                  {([["Read + normalize exports", "normalize"], ["Resolve asset identities", "identity"], ["Build reachability graph", "graph"], ["Analyze + score + guardrails", "analyze"]] as const).map(([lab, k]) => (
                    <div key={k} className="flex items-center gap-2 text-[12px]">
                      <Check size={12} className="shrink-0 text-ok" />
                      <span className="flex-1 text-text2">{lab}</span>
                      <span className="mono text-text3">{busy.result.timings?.[k] ?? 0} ms</span>
                    </div>
                  ))}
                </div>
                <div className="grid grid-cols-4 gap-2 border-t border-hair pt-3 text-center">
                  {([["assets", "assets"], ["rules", "records"], ["findings", "findings"], ["paths", "paths"]] as const).map(([lab, k]) => (
                    <div key={k}><div className="mono text-[18px] font-bold tabular-nums">{busy.result[k] ?? "-"}</div><div className="text-[10px] text-text3">{lab}</div></div>
                  ))}
                </div>
                <div className="mt-3 text-[11px] text-text3">refreshing the view…</div>
              </div>
            )}
          </div>
        </div>
      )}
    </>
  );
}
