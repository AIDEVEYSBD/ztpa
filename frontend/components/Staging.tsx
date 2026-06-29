"use client";

import { useEffect, useMemo, useRef, useState } from "react";
import { AnimatePresence, motion } from "framer-motion";
import {
  Rocket, Check, X, AlertTriangle, Trash2, ArrowRight, Server, ShieldCheck, Loader2, RefreshCw,
} from "lucide-react";
import { api } from "@/lib/api";
import type { PushStep, StagedChange } from "@/lib/types";
import { cn, Spinner, Skeleton } from "./ui";

const TOOL_LABEL: Record<string, string> = { algosec: "AlgoSec", guardicore: "Guardicore", wiz: "Wiz" };
const STATUS_STYLE: Record<string, string> = {
  staged: "border-border bg-sunk text-text2",
  pushing: "border-accent bg-accent-soft text-text",
  pushed: "border-ok-line bg-ok-bg text-ok",
  conflict: "border-sev-high-line bg-sev-high-bg text-sev-high",
  failed: "border-sev-critical-line bg-sev-critical-bg text-sev-critical",
};

export function Staging() {
  const [items, setItems] = useState<StagedChange[]>();
  const load = () => api.staging().then((r) => setItems(r.staged)).catch(() => setItems([]));
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
          <b>Push</b> runs a stepped, deterministic deployment that detects and resolves real rule conflicts
          (computed by the engine), then writes the change to the data source — reflected on the next recompute.
        </p>
        <button onClick={load} className="btn-ghost ml-auto text-xs"><RefreshCw size={13} /> Refresh</button>
      </div>

      {items === undefined ? (
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
  const [status, setStatus] = useState<StagedChange["status"]>(item.status);
  const [steps, setSteps] = useState<PushStep[]>(item.push_steps ?? []);
  const [revealed, setRevealed] = useState(item.push_steps?.length ?? 0);
  const [pushing, setPushing] = useState(false);
  const [busy, setBusy] = useState(false);
  const timers = useRef<ReturnType<typeof setTimeout>[]>([]);

  useEffect(() => () => { timers.current.forEach(clearTimeout); }, []);

  const p = item.payload ?? {};
  const isRem = item.kind === "remediation";

  const push = async () => {
    setPushing(true); setStatus("pushing"); setSteps([]); setRevealed(0);
    try {
      const res = await api.stagingPush(item.staged_id);
      const plan = (res.push_steps ?? []) as PushStep[];
      setSteps(plan);
      // Reveal steps one at a time so the conflict resolution reads as real-time.
      plan.forEach((_, i) => {
        timers.current.push(setTimeout(() => {
          setRevealed(i + 1);
          if (i === plan.length - 1) { setStatus(res.status as StagedChange["status"]); setPushing(false); onChanged(); }
        }, 650 * (i + 1)));
      });
      if (plan.length === 0) { setStatus(res.status as StagedChange["status"]); setPushing(false); onChanged(); }
    } catch {
      setStatus("failed"); setPushing(false);
    }
  };

  const discard = async () => {
    setBusy(true);
    try { await api.stagingDiscard(item.staged_id); onChanged(); } finally { setBusy(false); }
  };

  const conflicts = item.conflicts ?? [];

  return (
    <div className="panel p-3">
      <div className="flex flex-wrap items-center gap-2">
        <span className={cn("chip text-[10px] capitalize", STATUS_STYLE[status] ?? STATUS_STYLE.staged)}>
          {status === "pushed" ? <Check size={11} /> : status === "conflict" ? <AlertTriangle size={11} /> : status === "pushing" ? <Loader2 size={11} className="animate-spin" /> : <Rocket size={11} />}
          {status}
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

      <div className="mt-2 flex flex-wrap items-center gap-2 border-t border-hair pt-2">
        {status === "pushed" ? (
          <span className="flex items-center gap-1.5 text-[12px] text-ok"><ShieldCheck size={13} /> Applied to {TOOL_LABEL[item.target_tool] ?? item.target_tool} — data source updated</span>
        ) : status === "conflict" ? (
          <span className="flex items-center gap-1.5 text-[12px] text-sev-high"><AlertTriangle size={13} /> Held for human review</span>
        ) : (
          <button onClick={push} disabled={pushing} className="btn-primary !py-1.5 text-xs">
            {pushing ? <Spinner label="Pushing…" /> : <><Rocket size={13} /> Push to {TOOL_LABEL[item.target_tool] ?? item.target_tool}</>}
          </button>
        )}
        {status === "conflict" && (
          <button onClick={push} disabled={pushing} className="btn-ghost text-xs"><RefreshCw size={12} /> Retry push</button>
        )}
        <button onClick={discard} disabled={busy || pushing} className="btn-ghost ml-auto text-xs text-text3">
          <Trash2 size={12} /> Discard
        </button>
      </div>
    </div>
  );
}
