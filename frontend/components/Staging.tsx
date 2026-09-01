"use client";

import { useEffect, useMemo, useRef, useState } from "react";
import { AnimatePresence, motion } from "framer-motion";
import {
  Rocket, Check, X, AlertTriangle, Trash2, ArrowRight, Server, FlaskConical, Loader2, RefreshCw, SkipForward,
} from "lucide-react";
import { api, asApiError, type ApiError } from "@/lib/api";
import type { PushPlan, PushStep, StagedChange, StagedStatus } from "@/lib/types";
import { cn, Spinner, Skeleton } from "./ui";

const TOOL_LABEL: Record<string, string> = { algosec: "AlgoSec", guardicore: "Guardicore", wiz: "Wiz" };
const STATUS_STYLE: Record<string, string> = {
  staged: "border-border bg-sunk text-text2",
  pushing: "border-accent bg-accent-soft text-text",
  pushed: "border-ok-line bg-ok-bg text-ok",
  no_op: "border-border bg-sunk text-text3",
  conflict: "border-sev-high-line bg-sev-high-bg text-sev-high",
  failed: "border-sev-critical-line bg-sev-critical-bg text-sev-critical",
};
// `pushed` deliberately does not read "pushed" on screen: nothing was pushed
// anywhere. The label says what actually happened to the change.
const STATUS_LABEL: Record<string, string> = {
  staged: "staged",
  pushing: "staging",
  pushed: "staged (simulated)",
  no_op: "skipped — no-op",
  conflict: "held for review",
  failed: "failed",
};

export function Staging() {
  const [items, setItems] = useState<StagedChange[]>();
  const [error, setError] = useState<ApiError>();
  // An empty list and a failed fetch used to render identically ("Nothing staged
  // yet"), which is the same class of lie as the push copy: the screen asserting
  // a state it does not know it is in. Failure is now its own state.
  const load = () => {
    setError(undefined);
    return api.staging()
      .then((r) => setItems(r.staged))
      .catch((e) => { setItems(undefined); setError(asApiError(e)); });
  };
  useEffect(() => { load(); }, []);

  const groups = useMemo(() => {
    const g: Record<string, StagedChange[]> = {};
    (items ?? []).forEach((s) => { (g[s.target_tool] ??= []).push(s); });
    return g;
  }, [items]);

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-end gap-2">
        <p className="max-w-3xl text-[13px] text-text2">
          Changes approved in the Change Gate are staged here, grouped by the source system they target.
          <b> Stage</b> runs a stepped, deterministic dry run: the conflict detection is genuine engine
          math against the current snapshot, but the push itself is <b>simulated</b> — no connector to
          AlgoSec, Guardicore or Wiz is configured, so nothing is written to the source system. A staged
          change is folded into the engine&apos;s own record set on the next recompute.
        </p>
        <button onClick={load} className="btn-ghost ml-auto text-xs"><RefreshCw size={13} /> Refresh</button>
      </div>

      {/* Said once, at the top, so the per-card wording is never the only place
          the operator can learn that no source system was contacted. */}
      <div className="chip border-dashed border-borderStrong text-[11px] text-text3">
        <FlaskConical size={12} /> Simulated push — no live connector configured
      </div>

      {error ? (
        <div className="panel grid min-h-[260px] place-items-center gap-2 p-6 text-center">
          <AlertTriangle size={18} className="mx-auto text-sev-critical" />
          <div className="text-[13px] font-bold text-sev-critical">
            Could not load the staging area{error.status ? ` — HTTP ${error.status}` : ""}
          </div>
          <div className="max-w-md text-[12px] text-text2">{error.detail}</div>
          <div className="text-[11px] text-text3">This is not an empty staging area — the list is unknown.</div>
          <button onClick={load} className="btn-ghost mx-auto text-xs"><RefreshCw size={13} /> Try again</button>
        </div>
      ) : items === undefined ? (
        <div className="space-y-3">{Array.from({ length: 3 }).map((_, i) => (
          <div key={i} className="panel space-y-2 p-3"><Skeleton className="h-4 w-1/2" /><Skeleton className="h-3 w-2/3" /></div>
        ))}</div>
      ) : items.length === 0 ? (
        <div className="panel grid min-h-[260px] place-items-center p-6 text-center text-[13px] text-text3">
          Nothing staged yet. Approve a change in the Change Gate and send it here.
        </div>
      ) : (
        Object.entries(groups).map(([tool, list]) => (
          <div key={tool} className="space-y-2.5">
            <div className="flex items-center gap-2 text-[13px] font-bold">
              <Server size={15} className="text-text2" /> {TOOL_LABEL[tool] ?? tool}
              <span className="chip border-border text-[10px] text-text3">{list.length}</span>
            </div>
            {list.map((s) => <StagedCard key={s.staged_id} item={s} onChanged={load} />)}
          </div>
        ))
      )}
    </div>
  );
}

function StagedCard({ item, onChanged }: { item: StagedChange; onChanged: () => void }) {
  const [status, setStatus] = useState<StagedStatus>(item.status);
  const [steps, setSteps] = useState<PushStep[]>(item.push_steps ?? []);
  const [revealed, setRevealed] = useState(item.push_steps?.length ?? 0);
  const [pushing, setPushing] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<ApiError>();
  // Rendered wording comes off this flag, not off a hardcoded sentence. It is not
  // a stored column, so a row loaded from the DB arrives without it — and absent
  // means simulated, because no build of this product has a connector yet.
  const [simulated, setSimulated] = useState(item.simulated ?? true);
  const timers = useRef<ReturnType<typeof setTimeout>[]>([]);

  useEffect(() => () => { timers.current.forEach(clearTimeout); }, []);

  const p = item.payload ?? {};
  const isRem = item.kind === "remediation";
  const tool = TOOL_LABEL[item.target_tool] ?? item.target_tool;

  const push = async () => {
    setPushing(true); setStatus("pushing"); setSteps([]); setRevealed(0); setError(undefined);
    try {
      // api.stagingPush' declared return type is narrower than what the route
      // sends (lib/api.ts is owned elsewhere); PushPlan is the real payload.
      const res = (await api.stagingPush(item.staged_id)) as PushPlan;
      const plan = (res.push_steps ?? []) as PushStep[];
      setSteps(plan);
      setSimulated(res.simulated ?? true);
      // Reveal steps one at a time so the conflict resolution reads as real-time.
      plan.forEach((_, i) => {
        timers.current.push(setTimeout(() => {
          setRevealed(i + 1);
          if (i === plan.length - 1) { setStatus(res.status); setPushing(false); onChanged(); }
        }, 650 * (i + 1)));
      });
      if (plan.length === 0) { setStatus(res.status); setPushing(false); onChanged(); }
    } catch (e) {
      setStatus("failed"); setPushing(false); setError(asApiError(e));
    }
  };

  const discard = async () => {
    setBusy(true); setError(undefined);
    try { await api.stagingDiscard(item.staged_id); onChanged(); }
    catch (e) { setError(asApiError(e)); }
    finally { setBusy(false); }
  };

  const conflicts = item.conflicts ?? [];

  return (
    <div className="panel p-3">
      <div className="flex flex-wrap items-center gap-2">
        <span className={cn("chip text-[10px]", STATUS_STYLE[status] ?? STATUS_STYLE.staged)}>
          {status === "pushed" ? <Check size={11} />
            : status === "no_op" ? <SkipForward size={11} />
            : status === "conflict" ? <AlertTriangle size={11} />
            : status === "failed" ? <X size={11} />
            : status === "pushing" ? <Loader2 size={11} className="animate-spin" />
            : <Rocket size={11} />}
          {STATUS_LABEL[status] ?? status}
        </span>
        {isRem && <span className="chip border-accent text-[10px]">remediation</span>}
        <span className="chip border-border text-[10px] text-text3 capitalize">{item.decision?.replace("_", " ")}</span>
        <span className="ml-auto text-[10px] text-text3">{item.created_at ? new Date(item.created_at).toLocaleString() : ""}</span>
      </div>

      <div className="mono mt-1.5 flex flex-wrap items-center gap-1.5 text-[12px] text-text2">
        {isRem ? (
          <span className="break-all">{p.summary || `${p.op ?? ""} ${p.target_ref ?? ""}`.trim()}</span>
        ) : (
          <>
            <span className="break-all">{p.source}</span><ArrowRight size={11} className="shrink-0" />
            <span className="break-all">{p.destination}</span><span className="text-text3">· {p.service}</span>
          </>
        )}
      </div>

      {(status === "pushing" || steps.length > 0) && (
        <div className="mt-2.5 space-y-1.5 rounded-lg bg-surfaceHover p-2.5">
          <AnimatePresence>
            {steps.slice(0, revealed).map((st) => (
              <motion.div key={st.key} initial={{ opacity: 0, x: -6 }} animate={{ opacity: 1, x: 0 }}
                className="flex items-start gap-2 text-[12px]">
                <span className="mt-0.5 shrink-0">
                  {st.status === "ok" ? <Check size={13} className="text-ok" />
                    : st.status === "warn" ? <AlertTriangle size={13} className="text-sev-high" />
                    : <X size={13} className="text-sev-critical" />}
                </span>
                <span className="min-w-0">
                  <span className="font-semibold">{st.label}</span>
                  <span className="ml-1.5 text-text3">{st.detail}</span>
                </span>
              </motion.div>
            ))}
          </AnimatePresence>
          {pushing && revealed < steps.length && (
            <div className="flex items-center gap-1.5 text-[11px] text-text3">
              <Loader2 size={12} className="animate-spin" /> resolving…
            </div>
          )}
        </div>
      )}

      {conflicts.length > 0 && status !== "pushing" && (
        <div className="mt-2 text-[11px] text-text3">
          {conflicts.length} conflict{conflicts.length !== 1 ? "s" : ""} detected · {(item.resolution?.unresolved ?? []).length} need human review
        </div>
      )}

      {error && (
        <div className="mt-2 flex items-start gap-1.5 text-[11.5px] text-sev-critical">
          <X size={13} className="mt-0.5 shrink-0" />
          <span><b>{error.status ? `HTTP ${error.status}` : "No response from the API"}</b> — {error.detail} Nothing was staged.</span>
        </div>
      )}

      <div className="mt-2 flex flex-wrap items-center gap-2 border-t border-hair pt-2">
        {status === "pushed" ? (
          <span className={cn("flex items-center gap-1.5 text-[12px]", simulated ? "text-text2" : "text-ok")}>
            {simulated ? <FlaskConical size={13} className="text-text3" /> : <Check size={13} />}
            {simulated
              ? <>Staged for {tool} (simulated push — no live connector). Folded into the next recompute.</>
              : <>Applied to {tool} — data source updated.</>}
          </span>
        ) : status === "no_op" ? (
          <span className="flex items-center gap-1.5 text-[12px] text-text2">
            <SkipForward size={13} className="text-text3" /> Skipped — the flow is already covered, so nothing was staged and the next recompute is unchanged.
          </span>
        ) : status === "conflict" ? (
          <span className="flex items-center gap-1.5 text-[12px] text-sev-high"><AlertTriangle size={13} /> Held for human review — nothing was staged.</span>
        ) : (
          <button onClick={push} disabled={pushing} className="btn-primary !py-1.5 text-xs">
            {pushing ? <Spinner label="Staging…" /> : <><Rocket size={13} /> Stage for {tool} (simulated)</>}
          </button>
        )}
        {(status === "conflict" || status === "no_op") && (
          <button onClick={push} disabled={pushing} className="btn-ghost text-xs"><RefreshCw size={12} /> Re-run</button>
        )}
        <button onClick={discard} disabled={busy || pushing} className="btn-ghost ml-auto text-xs text-text3">
          <Trash2 size={12} /> Discard
        </button>
      </div>
    </div>
  );
}
