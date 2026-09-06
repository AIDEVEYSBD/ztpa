"use client";

import { useEffect, useRef, useState } from "react";
import { useSession } from "next-auth/react";
import {
  RefreshCw, ChevronDown, FlaskConical, Check, History, RotateCcw, AlertTriangle, X, Cloud, HardDrive,
  HelpCircle,
} from "lucide-react";
import { api, asApiError, type ApiError } from "@/lib/api";
import type { ProviderStatus } from "@/lib/types";
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

/** `/api/health`'s `ai` block, plus the shape it takes when the backend could not
 *  read its own provider status (`{"error": "..."}`, health.py never 500s over
 *  it). Carried explicitly so the chip can say WHY it does not know, instead of
 *  reading `active_provider: undefined` as "not ollama" and claiming "Hosted". */
type Residency = ProviderStatus & { error?: string };

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
  const [ai, setAi] = useState<Residency>();
  const [aiError, setAiError] = useState<ApiError>();
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

  // Residency signal. The backend already computes this on every /api/health;
  // until now nothing on screen read it, so a hosted fallback (render.yaml pins
  // ADVISORY_PROVIDER=openai) was completely undisclosed.
  //
  // A DEGRADED backend still knows its own provider. /api/health returns 503 with
  // a full payload when it cannot reach the database, and `api.health` resolves
  // on that (lib/api.readHealth) rather than discarding it — so this chip now
  // reads "Hosted — data leaves this host" in exactly the deployment where that
  // warning matters most, instead of "AI residency unknown" out of a body that
  // was sitting right there. Only a real failure to read health lands in catch.
  useEffect(() => {
    api.health()
      .then((h) => { setAi(h.ai); setAiError(undefined); })
      .catch((e) => { setAi(undefined); setAiError(asApiError(e)); });
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
      {/* z-30 lifts the whole header (a glass/backdrop-filter stacking context)
          above the page content so its popovers render on top. */}
      <header className="glass-chrome relative z-30 flex h-14 shrink-0 items-center gap-2.5 border-b border-border px-5">
        <span aria-hidden className="spectrum-line thin absolute inset-x-0 top-0" />
        <div className="flex min-w-0 flex-col justify-center gap-0.5">
          <h1 className="m-0 truncate text-[15px] font-bold leading-tight tracking-[-0.01em]">{title}</h1>
          <span className="truncate text-[11px] leading-tight text-text3">{sub}</span>
        </div>
        <div className="flex-1" />

        {/* where prompt content goes (permanent, all users) */}
        <ResidencyChip ai={ai} error={aiError} />

        {/* snapshot timeline (permanent, all users) */}
        <div ref={snapRef} className="relative">
          <button onClick={() => { setSnapOpen((o) => !o); setDsOpen(false); }}
            className={cn("btn-ghost !h-8", viewSnap && "!border-accent !text-accent-fg")} title="Browse point-in-time snapshots">
            <History size={14} />
            <span className="hidden sm:inline">{viewSnap ? `Viewing @${short(viewSnap)}` : "Live"}</span>
            <ChevronDown size={13} className={cn("transition-transform", snapOpen && "rotate-180")} />
          </button>
          {snapOpen && (
            <div className="popover absolute right-0 z-50 mt-1 max-h-[460px] w-[340px] overflow-y-auto p-1">
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
                {/* "no snapshots yet" is a claim about the database, so it may only be
                    made when the database was actually read. With the store
                    unreachable the API answers `[]` plus its reason, and the
                    dropdown reports that instead of inventing a clean history. */}
                {!snaps.length && (snapsUnknown
                  ? <div role="status" className="py-3 pl-4 pr-2 text-[11px] text-sev-medium">
                      the snapshot timeline could not be read
                      <div className="mono mt-1 text-[10px] leading-relaxed text-text3">{snapsUnknown}</div>
                    </div>
                  : <div className="py-3 pl-4 text-[11px] text-text3">no snapshots yet</div>)}
              </div>
            </div>
          )}
        </div>

        {/* demo dataset switcher (admin only, visually marked as demo) */}
        {isAdmin && scenarios.length > 0 && (
          <div ref={dsRef} className="relative">
            <button onClick={() => { setDsOpen((o) => !o); setSnapOpen(false); }}
              className="btn-ghost !h-8 !border-dashed" title="Demo only: swaps the simulated dataset">
              <FlaskConical size={14} className="text-text3" />
              <span className="hidden md:inline">Demo: {scenarios.find((s) => s.id === activeScenario)?.label ?? "data"}</span>
              <ChevronDown size={13} className={cn("transition-transform", dsOpen && "rotate-180")} />
            </button>
            {dsOpen && (
              <div className="popover absolute right-0 z-50 mt-1 w-[320px] p-1">
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
            )}
          </div>
        )}

        {/* the switcher could not be built — say so rather than silently omitting it */}
        {isAdmin && scenarioError && scenarios.length === 0 && (
          <span className="chip !h-8 border-dashed border-sev-high-line text-[10.5px] text-sev-high"
            title={`Demo dataset list unavailable — ${scenarioError.status ? `HTTP ${scenarioError.status}: ` : ""}${scenarioError.detail}`}>
            <FlaskConical size={13} /> <span className="hidden md:inline">Datasets unavailable</span>
          </span>
        )}

        {/* reset the change-gate demo (admin only, marked as a demo tool) */}
        {isAdmin && (
          <button
            onClick={() => {
              if (window.confirm("Reset the change-gate demo?\n\nThis clears every change request, decision, and staged change, then recomputes a clean baseline — any pushed fix is undone and its finding reappears.")) {
                runWithOverlay("Resetting demo", () => api.resetDemo());
              }
            }}
            disabled={!!busy} className="btn-ghost !h-8 !border-dashed"
            title="Demo only: clear all change requests / decisions / staged changes and recompute a clean baseline">
            <RotateCcw size={13} /> <span className="hidden md:inline">Reset demo</span>
          </button>
        )}

        <button onClick={() => runWithOverlay("Recomputing snapshot", () => api.recompute())} disabled={!!busy}
          className="btn-ghost !h-8" title="Re-run the deterministic engine live">
          <RefreshCw size={13} className={busy ? "animate-spin" : ""} /> <span className="hidden sm:inline">Recompute</span>
        </button>
      </header>

      {busy && (
        <div className="fixed inset-0 z-[200] grid place-items-center bg-black/70 backdrop-blur-sm">
          <div className={cn("panel relative w-[440px] p-6",
            overlayFailed ? "!border-sev-critical-line" : "glow-accent")}>
            <span aria-hidden className="spectrum-line thin absolute inset-x-0 top-0" />
            <div className="flex items-center gap-2 text-[14px] font-bold">
              {!busy.result ? <RefreshCw size={16} className="animate-spin text-accent-fg" />
                : overlayFailed ? <AlertTriangle size={16} className="text-sev-critical" />
                : <Check size={16} className="text-ok" />}
              {!busy.result ? busy.label
                : overlayFailed ? `${busy.label} failed`
                : "Snapshot recomputed"}
            </div>
            {overlayFailed ? (
              // Failure. No tick, no fabricated timings, no zeroed counts, and no
              // reload: the snapshot on screen is the one from before this run.
              <div className="mt-4">
                <div className="border border-sev-critical-line bg-sev-critical-bg p-3">
                  <div className="mono text-[11px] font-bold text-sev-critical">
                    {failure?.isNetwork ? "NO RESPONSE FROM THE API" : `HTTP ${failure?.status}`}
                  </div>
                  <div className="mt-1 text-[12.5px] text-text">{failure?.detail}</div>
                </div>
                <div className="mt-3 text-[12px] text-text2">
                  Nothing was changed. The engine did not produce a new snapshot, and the view behind this
                  dialog is the previous one — not a refreshed result.
                </div>
                <div className="mt-4 flex items-center gap-2">
                  <button onClick={() => { if (lastRun) runWithOverlay(lastRun.label, lastRun.fn); }}
                    className="btn-primary !py-1.5 text-xs"><RefreshCw size={13} /> Try again</button>
                  <button onClick={() => setBusy(null)} className="btn-ghost text-xs"><X size={13} /> Dismiss</button>
                </div>
              </div>
            ) : !busy.result ? (
              <div className="mt-4 space-y-2.5">
                {STAGES.map((s, i) => (
                  <div key={i} className="flex items-center gap-2.5 text-[12.5px]">
                    <span className={cn("grid h-4 w-4 shrink-0 place-items-center border",
                      i < busy.stage ? "border-ok-line bg-ok" : i === busy.stage ? "border-accent" : "border-border")}>
                      {i < busy.stage && <Check size={10} className="text-white" />}
                      {i === busy.stage && <span className="h-1.5 w-1.5 animate-pulse bg-accent" />}
                    </span>
                    <span className={i <= busy.stage ? "text-text" : "text-text3"}>{s}</span>
                  </div>
                ))}
              </div>
            ) : (
              <div className="mt-4">
                <div className="mb-3 text-[12.5px] text-text2">Deterministic engine ran in <b className="mono text-text">{summary?.timings?.total ?? "?"} ms</b></div>
                <div className="mb-3 space-y-1.5">
                  {([["Read + normalize exports", "normalize"], ["Resolve asset identities", "identity"], ["Build reachability graph", "graph"], ["Analyze + score + guardrails", "analyze"]] as const).map(([lab, k]) => (
                    <div key={k} className="flex items-center gap-2 text-[12px]">
                      <Check size={12} className="shrink-0 text-ok" />
                      <span className="flex-1 text-text2">{lab}</span>
                      <span className="mono text-text3">{summary?.timings?.[k] ?? 0} ms</span>
                    </div>
                  ))}
                </div>
                <div className="grid grid-cols-4 gap-2 border-t border-hair pt-3 text-center">
                  {([["assets", "assets"], ["rules", "records"], ["findings", "findings"], ["paths", "paths"]] as const).map(([lab, k]) => (
                    <div key={k}><div className="mono text-[18px] font-bold tabular-nums">{summary?.[k] ?? "-"}</div><div className="text-[10px] text-text3">{lab}</div></div>
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

/**
 * Where the prompt content goes — the one thing a "local-first" product must not
 * leave to a README. `/api/health` has always returned `ai.active_provider` and
 * `ai.data_residency`; no component read them, so a hosted fallback was silent.
 *
 * The rule is deliberately blunt: anything other than ollama means the finding
 * text, rule text and asset names of this estate are sent off this host, so the
 * chip says exactly that. render.yaml pins ADVISORY_PROVIDER=openai, so on the
 * only documented deployment this reads "Hosted" — which is the point.
 */
function ResidencyChip({ ai, error }: { ai?: Residency; error?: ApiError }) {
  // Unknown is its own state: never fall back to claiming "Local", and never let
  // a payload the backend could not fill in (`{"error": ...}`, so no
  // `active_provider`) fall through to the `!== "ollama"` test below and read as
  // a confident "Hosted".
  if (!ai?.active_provider) {
    const why = ai?.error
      ? `The API could not read its model provider status — ${ai.error}`
      : error
        ? `Could not read /api/health — ${error.status ? `HTTP ${error.status}: ` : ""}${error.detail}`
        : "Reading the model provider from /api/health…";
    return (
      <span className="chip !h-8 border-dashed border-borderStrong text-[10.5px] text-text3" title={why}>
        <HelpCircle size={13} />
        <span className="hidden lg:inline">AI residency unknown</span>
      </span>
    );
  }

  // Azure AI Foundry is hosted, but it is hosted IN THE CUSTOMER'S OWN TENANT --
  // their subscription, their resource group, their region. Labelling that
  // "data leaves this host" the same way as a third-party API is true but
  // useless: it collapses the one distinction a compliance reader cares about.
  const isAzure = ai.active_provider === "azure";
  const hosted = ai.active_provider !== "ollama" && !isAzure;
  // "Local — model unreachable" described the CONFIGURATION rather than the
  // consequence, and read as a fault on a deployment that simply has no local
  // model and never will. What matters to the reader is that no model is
  // answering, so every capability is serving its deterministic fallback.
  const degraded = !hosted && !isAzure && !ai.ollama_reachable;
  const label = isAzure ? "Azure AI Foundry — your tenant"
    : hosted ? "Hosted — data leaves this host"
    : degraded ? "No model — deterministic fallback"
    : "Local — stays on this host";
  const title = isAzure
    ? `Provider: azure · judge ${ai.judge_model} · prose ${ai.prose_model} · residency: ${ai.data_residency}. `
      + "Prompts go to an Azure AI Foundry deployment in your own subscription — they leave this "
      + "container, but not your tenant."
    : hosted
    ? `Provider: ${ai.active_provider} · judge ${ai.judge_model} · prose ${ai.prose_model} · residency: ${ai.data_residency}. `
      + "Finding text, rule text and asset names are sent to this hosted provider."
    : degraded
      ? `Provider: ollama · judge ${ai.judge_model} · residency: ${ai.data_residency}. Ollama is not reachable, `
        + "so no model is answering and every AI capability is serving its deterministic engine "
        + "fallback. Nothing leaves this host. Configure a provider on the Configuration screen."
      : `Provider: ollama · judge ${ai.judge_model} · prose ${ai.prose_model} · embed ${ai.embed_model} · `
        + `residency: ${ai.data_residency}. Nothing leaves this host.`;

  return (
    <span title={title}
      className={cn("chip !h-8 text-[10.5px]",
        hosted ? "border-sev-high-line bg-sev-high-bg text-sev-high"
          : degraded ? "border-sev-medium-line bg-sev-medium-bg text-sev-medium"
          : "border-ok-line bg-ok-bg text-ok")}>
      {hosted ? <Cloud size={13} /> : <HardDrive size={13} />}
      <span className="hidden lg:inline">{label}</span>
    </span>
  );
}
