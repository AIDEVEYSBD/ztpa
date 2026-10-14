"use client";

import { useEffect, useRef, useState } from "react";
import { useSession } from "next-auth/react";
import {
  RefreshCw, ChevronDown, FlaskConical, Check, History, RotateCcw, AlertTriangle, X,
} from "lucide-react";
import { api, asApiError, type ApiError } from "@/lib/api";
import type { ProviderStatus } from "@/lib/types";
import { cn, Button } from "./ui";
import { SurfaceGrain } from "./ui/Material";

const STAGES = [
  "Reading simulated exports",
  "Resolving asset identities",
  "Building reachability graph",
  "Running the 4 analyzers",
  "Scoring + guardrail floor",
  "Persisting snapshot to Neon",
];

type Scenario = { id: string; label: string; description: string };

/** `/api/health`'s `ai` block, plus the shape it takes when the backend could not
 *  read its own provider status (`{"error": "..."}`, health.py never 500s over
 *  it). Carried explicitly so the chip can say WHY it does not know, instead of
 *  reading `active_provider: undefined` as "not ollama" and claiming "Hosted". */

const short = (id: string) => id.replace(/^snap_/, "").slice(0, 7);

/** The outcome of an overlay-run job. Discriminated on `ok` so the overlay
 *  CANNOT render the success panel for a failed call — the previous shape
 *  (`{error: true}` on a bare `any`) let a 500 draw a green tick, "? ms" and
 *  "-" for every count, then reload the page to unchanged data. */
type OverlayResult =
  | { ok: true; summary: Record<string, any> }
  | { ok: false; error: ApiError };

type Busy = { label: string; stage: number; result?: OverlayResult };

export function Topbar({ title, sub, viewSnap, onViewSnap, snaps = [], snapsUnknown }:
  { title: string; sub: string; viewSnap?: string; onViewSnap: (id?: string) => void; snaps?: any[];
    /** The backend's reason the timeline could not be read, when it could not be.
     *  Set = the empty list means UNKNOWN; unset = it really is empty. */
    snapsUnknown?: string }) {
  const { data } = useSession();
  const isAdmin = (data?.user as any)?.role === "admin";
  const [scenarios, setScenarios] = useState<Scenario[]>([]);
  const [activeScenario, setActiveScenario] = useState<string>("");
  const [dsOpen, setDsOpen] = useState(false);
  const [snapOpen, setSnapOpen] = useState(false);
  const [busy, setBusy] = useState<Busy | null>(null);
  const snapRef = useRef<HTMLDivElement>(null);
  const dsRef = useRef<HTMLDivElement>(null);

  // The dataset switcher is a demo affordance, but its failure is still not
  // swallowed: an absent switcher is indistinguishable from a broken one, so a
  // failed list renders a marked chip carrying the reason instead of nothing.
  const [scenarioError, setScenarioError] = useState<ApiError>();
  useEffect(() => {
    api.scenarios()
      .then((s) => { setScenarios(s.scenarios); setActiveScenario(s.active); })
      .catch((e) => setScenarioError(asApiError(e)));
  }, []);


  // Click-away + Escape for the popovers. A document listener is used (rather than
  // a `fixed inset-0` catcher) because the glass header sets `backdrop-filter`,
  // which would confine a fixed catcher to the header strip.
  useEffect(() => {
    if (!snapOpen && !dsOpen) return;
    const onDown = (e: MouseEvent) => {
      const t = e.target as Node;
      if (snapOpen && snapRef.current && !snapRef.current.contains(t)) setSnapOpen(false);
      if (dsOpen && dsRef.current && !dsRef.current.contains(t)) setDsOpen(false);
    };
    const onEsc = (e: KeyboardEvent) => { if (e.key === "Escape") { setSnapOpen(false); setDsOpen(false); } };
    document.addEventListener("mousedown", onDown);
    document.addEventListener("keydown", onEsc);
    return () => { document.removeEventListener("mousedown", onDown); document.removeEventListener("keydown", onEsc); };
  }, [snapOpen, dsOpen]);

  const [lastRun, setLastRun] = useState<{ label: string; fn: () => Promise<any> } | null>(null);

  const runWithOverlay = async (label: string, fn: () => Promise<any>) => {
    setDsOpen(false); setSnapOpen(false);
    setLastRun({ label, fn });
    setBusy({ label, stage: 0 });
    const timer = setInterval(() => setBusy((b) => (b && !b.result ? { ...b, stage: Math.min(b.stage + 1, STAGES.length - 1) } : b)), 300);
    let result: OverlayResult;
    try {
      result = { ok: true, summary: (await fn())?.summary ?? {} };
    } catch (e) {
      result = { ok: false, error: asApiError(e) };
    }
    clearInterval(timer);
    setBusy((b) => (b ? { ...b, stage: STAGES.length, result } : b));
    // A failed run must NOT reload: the reload was what replaced the failure with
    // the unchanged, stale view and made a 500 look like a successful recompute.
    // The overlay stays up until the operator dismisses it.
    if (!result.ok) return;
    await new Promise((r) => setTimeout(r, 2400));
    window.location.reload();
  };

  // Discriminate the overlay result ONCE, here, so no branch of the JSX below can
  // render the success panel for a failed call.
  const failure = busy?.result && !busy.result.ok ? busy.result.error : undefined;
  const overlayFailed = !!failure;
  const summary = busy?.result?.ok ? busy.result.summary : undefined;

  return (
    <>
      {/* z-30 lifts the whole header above the page content so its popovers
          render on top. */}
      <header className="relative z-30 flex h-12 shrink-0 items-center gap-2.5 border-b border-line bg-surface px-4">
        <SurfaceGrain />
        <div className="relative z-10 flex min-w-0 flex-col justify-center gap-0.5">
          <h1 className="m-0 truncate text-[13px] leading-tight font-semibold tracking-[-0.01em] text-on-grain">{title}</h1>
          <span className="truncate text-[10.5px] leading-tight text-faint">{sub}</span>
        </div>
        <div className="relative z-10 flex-1" />

        {/* where prompt content goes (permanent, all users) */}

        {/* snapshot timeline (permanent, all users) */}
        <div ref={snapRef} className="relative z-10">
          <Button
            size="sm"
            variant={viewSnap ? "solid" : "quiet"}
            tone={viewSnap ? "run" : "ink"}
            onClick={() => { setSnapOpen((o) => !o); setDsOpen(false); }}
            title="Browse point-in-time snapshots"
          >
            <History size={13} />
            <span className="hidden sm:inline">{viewSnap ? `Viewing @${short(viewSnap)}` : "Live"}</span>
            <ChevronDown size={11} className={cn("transition-transform duration-150", snapOpen && "rotate-180")} />
          </Button>
          {snapOpen && (
            <div className="af-pop absolute right-0 z-50 mt-1 max-h-[460px] w-[340px] overflow-y-auto rounded-md border border-line bg-surface p-1 elev-3">
              <div className="px-2 py-1.5 text-[11px] font-medium tracking-[0.06em] text-faint uppercase">Snapshot timeline</div>
              <button onClick={() => { onViewSnap(undefined); setSnapOpen(false); }} className="focusable block w-full rounded-sm px-2 py-2 text-left hover:bg-raise/50">
                <div className="flex items-center gap-2 text-[12px] font-medium"><span className="size-1.5 rounded-[2px] bg-ok" /> Live (latest)</div>
              </button>
              <div className="relative mt-1 ml-3 border-l border-line">
                {snaps.map((s) => (
                  <button key={s.snapshot_id} onClick={() => { onViewSnap(s.snapshot_id); setSnapOpen(false); }}
                    className="focusable block w-full rounded-sm py-2 pr-2 pl-4 text-left hover:bg-raise/50">
                    <span className={cn("absolute -ml-[21px] mt-1 size-1.5 rounded-[2px] border", viewSnap === s.snapshot_id ? "border-ink bg-ink" : "border-line-strong bg-surface")} />
                    <div className="flex items-center gap-2">
                      <span className="tnum font-mono text-[11px] font-medium">@{short(s.snapshot_id)}</span>
                      {s.label && <span className="text-[10px] text-faint">{s.label}</span>}
                    </div>
                    <div className="tnum mt-0.5 font-mono text-[10px] text-faint">{s.findings} findings · {s.critical} critical · {new Date(s.created_at).toLocaleString("en-GB")}</div>
                  </button>
                ))}
                {/* "no snapshots yet" is a claim about the database, so it may only be
                    made when the database was actually read. With the store
                    unreachable the API answers `[]` plus its reason, and the
                    dropdown reports that instead of inventing a clean history. */}
                {!snaps.length && (snapsUnknown
                  ? <div role="status" className="py-3 pr-2 pl-4 text-[11px] text-warn">
                      the snapshot timeline could not be read
                      <div className="mt-1 font-mono text-[10px] leading-relaxed text-faint">{snapsUnknown}</div>
                    </div>
                  : <div className="py-3 pl-4 text-[11px] text-faint">no snapshots yet</div>)}
              </div>
            </div>
          )}
        </div>

        {/* demo dataset switcher (admin only, visually marked as demo) */}
        {isAdmin && scenarios.length > 0 && (
          <div ref={dsRef} className="relative z-10">
            <Button
              size="sm"
              variant="quiet"
              tone="neutral"
              onClick={() => { setDsOpen((o) => !o); setSnapOpen(false); }}
              title="Demo only: swaps the simulated dataset"
            >
              <FlaskConical size={13} className="text-faint" />
              <span className="hidden md:inline">Demo: {scenarios.find((s) => s.id === activeScenario)?.label ?? "data"}</span>
              <ChevronDown size={11} className={cn("transition-transform duration-150", dsOpen && "rotate-180")} />
            </Button>
            {dsOpen && (
              <div className="af-pop absolute right-0 z-50 mt-1 w-[320px] rounded-md border border-line bg-surface p-1 elev-3">
                <div className="px-2 py-1.5 text-[11px] font-medium tracking-[0.06em] text-faint uppercase">Demo dataset · simulated</div>
                {scenarios.map((s) => (
                  <button key={s.id} onClick={() => runWithOverlay(`Switching to ${s.label}`, () => api.switchDataset(s.id))}
                    className="focusable block w-full rounded-sm px-2 py-2 text-left hover:bg-raise/50">
                    <div className="flex items-center gap-2 text-[12px] font-medium">
                      {s.label}
                      {s.id === activeScenario && <span className="rounded-[3px] border border-line-strong px-1 py-px font-mono text-[9px] font-semibold text-dim">CURRENT</span>}
                    </div>
                    <div className="text-[11px] text-faint">{s.description}</div>
                  </button>
                ))}
              </div>
            )}
          </div>
        )}

        {/* the switcher could not be built — say so rather than silently omitting it */}
        {isAdmin && scenarioError && scenarios.length === 0 && (
          <span className="relative z-10 inline-flex items-center gap-1.5 rounded-sm border border-dashed border-warn-line bg-raise px-1.5 py-0.5 text-[10.5px] font-medium text-warn"
            title={`Demo dataset list unavailable — ${scenarioError.status ? `HTTP ${scenarioError.status}: ` : ""}${scenarioError.detail}`}>
            <FlaskConical size={13} /> <span className="hidden md:inline">Datasets unavailable</span>
          </span>
        )}

        {/* reset the change-gate demo (admin only, marked as a demo tool) */}
        {isAdmin && (
          <Button
            size="sm"
            variant="quiet"
            tone="neutral"
            className="relative z-10"
            onClick={() => {
              if (window.confirm("Reset the change-gate demo?\n\nThis clears every change request, decision, and staged change, then recomputes a clean baseline — any pushed fix is undone and its finding reappears.")) {
                runWithOverlay("Resetting demo", () => api.resetDemo());
              }
            }}
            disabled={!!busy}
            title="Demo only: clear all change requests / decisions / staged changes and recompute a clean baseline"
          >
            <RotateCcw size={13} /> <span className="hidden md:inline">Reset demo</span>
          </Button>
        )}

        <Button
          size="sm"
          variant="solid"
          tone="ink"
          className="relative z-10"
          onClick={() => runWithOverlay("Recomputing snapshot", () => api.recompute())}
          disabled={!!busy}
          title="Re-run the deterministic engine live"
        >
          <RefreshCw size={13} className={busy ? "af-spin" : ""} /> <span className="hidden sm:inline">Recompute</span>
        </Button>
      </header>

      {busy && (
        <div className="fixed inset-0 z-[200] grid place-items-center bg-canvas/75 p-4">
          <div className="af-pop relative w-[440px] rounded-lg border border-line bg-surface p-6 elev-3">
            <div className="flex items-center gap-2 text-[14px] font-semibold tracking-[-0.005em]">
              {!busy.result ? <RefreshCw size={15} className="af-spin text-run" />
                : overlayFailed ? <AlertTriangle size={15} className="text-err" />
                : <Check size={15} className="text-ok" />}
              {!busy.result ? busy.label
                : overlayFailed ? `${busy.label} failed`
                : "Snapshot recomputed"}
            </div>
            {overlayFailed ? (
              // Failure. No tick, no fabricated timings, no zeroed counts, and no
              // reload: the snapshot on screen is the one from before this run.
              <div className="mt-4">
                <div className="relative overflow-hidden rounded-lg border border-line bg-surface p-3 pl-4">
                  <span aria-hidden className="absolute inset-y-0 left-0 w-[3px] bg-err" />
                  <div className="font-mono text-[11px] font-medium text-err">
                    {failure?.isNetwork ? "NO RESPONSE FROM THE API" : `HTTP ${failure?.status}`}
                  </div>
                  <div className="mt-1 text-[12.5px] text-fg">{failure?.detail}</div>
                </div>
                <div className="mt-3 text-[12px] leading-[1.55] text-dim">
                  Nothing was changed. The engine did not produce a new snapshot, and the view behind this
                  dialog is the previous one — not a refreshed result.
                </div>
                <div className="mt-4 flex items-center gap-2">
                  <Button size="sm" variant="solid" tone="ink" onClick={() => { if (lastRun) runWithOverlay(lastRun.label, lastRun.fn); }}>
                    <RefreshCw size={13} /> Try again
                  </Button>
                  <Button size="sm" variant="solid" tone="err" onClick={() => setBusy(null)}>
                    <X size={13} /> Dismiss
                  </Button>
                </div>
              </div>
            ) : !busy.result ? (
              <div className="mt-4 space-y-2.5">
                {STAGES.map((s, i) => (
                  <div key={i} className="flex items-center gap-2.5 text-[12.5px]">
                    <span className={cn("grid size-4 shrink-0 place-items-center rounded-xs border",
                      i < busy.stage ? "border-ok bg-ok" : i === busy.stage ? "border-line-strong" : "border-line")}>
                      {i < busy.stage && <Check size={10} className="text-on-solid" />}
                      {i === busy.stage && <span className="af-pulse size-1.5 rounded-[2px] bg-run" />}
                    </span>
                    <span className={i <= busy.stage ? "text-fg" : "text-ghost"}>{s}</span>
                  </div>
                ))}
              </div>
            ) : (
              <div className="mt-4">
                <div className="mb-3 text-[12.5px] text-dim">Deterministic engine ran in <b className="tnum font-mono text-fg">{summary?.timings?.total ?? "unknown"} ms</b></div>
                <div className="mb-3 space-y-1.5">
                  {([["Read + normalize exports", "normalize"], ["Resolve asset identities", "identity"], ["Build reachability graph", "graph"], ["Analyze + score + guardrails", "analyze"]] as const).map(([lab, k]) => (
                    <div key={k} className="flex items-center gap-2 text-[12px]">
                      <Check size={12} className="shrink-0 text-ok" />
                      <span className="flex-1 text-dim">{lab}</span>
                      <span className="tnum font-mono text-[11px] text-faint">{summary?.timings?.[k] ?? 0} ms</span>
                    </div>
                  ))}
                </div>
                <div className="grid grid-cols-4 gap-2 border-t border-line pt-3 text-center">
                  {([["assets", "assets"], ["rules", "records"], ["findings", "findings"], ["paths", "paths"]] as const).map(([lab, k]) => (
                    <div key={k}>
                      <div className="tnum text-[22px] leading-none font-semibold tracking-[-0.02em]">{summary?.[k] ?? "unknown"}</div>
                      <div className="mt-1 text-[10px] text-ghost">{lab}</div>
                    </div>
                  ))}
                </div>
                <div className="mt-3 text-[10.5px] text-ghost">refreshing the view…</div>
              </div>
            )}
          </div>
        </div>
      )}
    </>
  );
}

