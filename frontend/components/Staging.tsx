"use client";

/**
 * THE IMPLEMENTATION QUEUE.
 *
 * Renamed from "staging area", which named a holding pen and told the operator
 * nothing about what happens next. This is the list of approved changes on their
 * way into the estate, and the screen is split by what has actually happened to
 * each one:
 *
 *   QUEUED   approved, nothing applied yet.
 *   APPLIED  in the engine's applied overlay — and with a way back out of it.
 *
 * WHAT "APPLIED" HONESTLY MEANS. `load_applied_changes` re-applies every pushed
 * row to the record set on each engine build, so these changes really do change
 * what this product reports. Nothing was written to AlgoSec, Guardicore or Wiz:
 * no connector exists in this build. Both halves are said, every time, and the
 * wording is driven by the `simulated` flag rather than hardcoded — so the day a
 * connector lands, the copy tells the truth without an edit.
 */

import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { useSession } from "next-auth/react";
import { AnimatePresence, motion } from "framer-motion";
import {
  AlertTriangle, Check, FlaskConical, Loader2, RefreshCw, Rocket, Server, SkipForward, Trash2, X,
} from "lucide-react";
import { api, asApiError, type ApiError } from "@/lib/api";
import type { PushPlan, PushStep } from "@/lib/types";
import { canApprove as canApproveChanges, type AppRole } from "@/lib/roles";
import { cn, Skeleton, Spinner } from "./ui";
import { ErrorState } from "./ui/Feedback";
import { Readout, type FigureSpec } from "./risk/bits";
import { ProposedLine } from "./risk/gate";
import {
  AppliedChanges, DecisionOrigin, QUEUE_STATUS, StatusChip, toolLabel, type QueueRow, type QueueStatus,
} from "./risk/implementation";

/** Statuses that are still waiting on someone. `pushed` / `rolled_back` are the
 *  applied history and are rendered by `AppliedChanges` instead. */
const WAITING: QueueStatus[] = ["staged", "pushing", "conflict", "failed", "no_op"];

export function Staging() {
  const { data: session } = useSession();
  const role = ((session?.user as any)?.role ?? null) as AppRole | null;
  const canApprove = canApproveChanges(role);

  const [items, setItems] = useState<QueueRow[]>();
  const [error, setError] = useState<ApiError>();

  // An empty list and a failed fetch used to render identically ("Nothing staged
  // yet"), which is the same class of lie as an invented zero: the screen
  // asserting a state it does not know it is in. Failure is its own state.
  const load = useCallback(() => {
    setError(undefined);
    return api.staging()
      .then((r) => setItems(r.staged as QueueRow[]))
      .catch((e) => { setItems(undefined); setError(asApiError(e)); });
  }, []);
  useEffect(() => { load(); }, [load]);

  const waiting = useMemo(() => (items ?? []).filter((s) => WAITING.includes(s.status)), [items]);
  const groups = useMemo(() => {
    const g: Record<string, QueueRow[]> = {};
    waiting.forEach((s) => { (g[s.target_tool] ??= []).push(s); });
    return g;
  }, [waiting]);

  const known = items !== undefined;
  const n = (pred: (s: QueueRow) => boolean) => (known ? (items ?? []).filter(pred).length : null);
  const unknown = "The implementation queue did not load, so this is unknown — not zero.";
  const figures: FigureSpec[] = [
    { key: "queued", label: "queued", value: n((s) => s.status === "staged"), unknown },
    { key: "held", label: "held for review", value: n((s) => s.status === "conflict"), unknown, tone: "text-sev-high" },
    { key: "applied", label: "applied", value: n((s) => s.status === "pushed"), unknown, tone: "text-ok" },
    { key: "rolled", label: "rolled back", value: n((s) => s.status === "rolled_back"), unknown, tone: "text-sev-medium" },
    { key: "skipped", label: "skipped", value: n((s) => s.status === "no_op"), unknown },
  ];

  return (
    <div className="space-y-2.5">
      <Readout
        title="The implementation queue"
        note={<span className="inline-flex items-center gap-1.5"><FlaskConical size={11} /> simulated run — no live connector is configured</span>}
        figures={figures}
      />

      {error ? (
        <ErrorState resource="the implementation queue" error={error} onRetry={load} />
      ) : (
        <>
          <div className="border border-border bg-surface2">
            <div className="flex flex-wrap items-center gap-2 border-b border-hair px-3.5 py-2">
              <span className="eyebrow">Waiting to be implemented</span>
              <span className="text-[10.5px] text-text3">approved in the Change Gate, grouped by the system they target</span>
              <button onClick={load} className="btn-ghost ml-auto !h-[24px] !px-2 text-[11px]"><RefreshCw size={11} /> Refresh</button>
            </div>
            <div className="space-y-2.5 p-3">
              {items === undefined ? (
                Array.from({ length: 2 }).map((_, i) => (
                  <div key={i} className="space-y-2 border border-border bg-surface2 p-3"><Skeleton className="h-4 w-1/2" /><Skeleton className="h-3 w-2/3" /></div>
                ))
              ) : waiting.length === 0 ? (
                <div className="p-4 text-center text-[12px] text-text3">
                  Nothing is waiting. Approve a change in the Risk To-Do side panel or the Change Gate and it lands here.
                </div>
              ) : (
                Object.entries(groups).map(([tool, list]) => (
                  <div key={tool} className="space-y-2">
                    <div className="flex items-center gap-2 text-[11px] font-bold uppercase tracking-[0.12em]">
                      <Server size={12} className="text-text3" /> {toolLabel(tool)}
                      <span className="mono font-normal tabular-nums text-text3">{list.length}</span>
                    </div>
                    {list.map((s) => <QueueCard key={s.staged_id} item={s} canApprove={canApprove} onChanged={load} />)}
                  </div>
                ))
              )}
            </div>
          </div>

          <div className="border border-border bg-surface2">
            <div className="flex flex-wrap items-center gap-2 border-b border-hair px-3.5 py-2">
              <span className="eyebrow">Applied</span>
              <span className="text-[10.5px] text-text3">
                in the engine&apos;s applied overlay — every build folds these into the record set
              </span>
            </div>
            <div className="p-3">
              <AppliedChanges rows={items} loading={items === undefined} canApprove={canApprove}
                onChanged={load} onRetry={load}
                emptyNote="No change has been applied yet. The engine's applied overlay is empty." />
            </div>
          </div>
        </>
      )}
    </div>
  );
}

/** One change waiting to be implemented. */
function QueueCard({ item, canApprove, onChanged }: { item: QueueRow; canApprove: boolean; onChanged: () => void }) {
  const [status, setStatus] = useState<QueueStatus>(item.status);
  const [steps, setSteps] = useState<PushStep[]>(item.push_steps ?? []);
  const [revealed, setRevealed] = useState(item.push_steps?.length ?? 0);
  const [running, setRunning] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<ApiError>();
  // Rendered wording comes off this flag, not off a hardcoded sentence. It is
  // not a stored column, so a row loaded from the DB arrives without it — and
  // absent means simulated, because no build of this product has a connector.
  const [simulated, setSimulated] = useState(item.simulated ?? true);
  const timers = useRef<ReturnType<typeof setTimeout>[]>([]);
  useEffect(() => () => { timers.current.forEach(clearTimeout); }, []);

  const tool = toolLabel(item.target_tool);

  const run = async () => {
    setRunning(true); setStatus("pushing"); setSteps([]); setRevealed(0); setError(undefined);
    try {
      // `api.stagingPush`'s declared return type is narrower than what the route
      // sends (lib/api.ts is owned elsewhere); PushPlan is the real payload.
      const res = (await api.stagingPush(item.staged_id)) as PushPlan;
      const plan = (res.push_steps ?? []) as PushStep[];
      setSteps(plan);
      setSimulated(res.simulated ?? true);
      // Reveal one step at a time so the conflict resolution reads as real work.
      plan.forEach((_, i) => {
        timers.current.push(setTimeout(() => {
          setRevealed(i + 1);
          if (i === plan.length - 1) { setStatus(res.status as QueueStatus); setRunning(false); onChanged(); }
        }, 550 * (i + 1)));
      });
      if (plan.length === 0) { setStatus(res.status as QueueStatus); setRunning(false); onChanged(); }
    } catch (e) {
      setStatus("failed"); setRunning(false); setError(asApiError(e));
    }
  };

  const discard = async () => {
    setBusy(true); setError(undefined);
    try { await api.stagingDiscard(item.staged_id); onChanged(); }
    catch (e) { setError(asApiError(e)); }
    finally { setBusy(false); }
  };

  const conflicts = item.conflicts ?? [];
  const meta = QUEUE_STATUS[status];

  return (
    <div className="border border-border bg-surface2">
      <div className="flex flex-wrap items-center gap-2 border-b border-hair px-2.5 py-1.5">
        <StatusChip status={status} />
        {item.kind === "remediation" && (
          <span className="inline-flex h-[20px] items-center border border-accent bg-accent-soft px-1.5 text-[9.5px] font-bold uppercase tracking-[0.08em] text-accent-fg">
            remediation
          </span>
        )}
        <DecisionOrigin decision={item.decision} />
        <span className="mono ml-auto text-[10px] text-text3">
          {item.created_at ? new Date(item.created_at).toLocaleString() : ""}
        </span>
      </div>

      <div className="space-y-1 px-2.5 py-2">
        <ProposedLine proposed={item.payload} kind={item.kind} />
        <div className="text-[10.5px] text-text3">
          target {tool} · requested by <span className="mono text-text2">{item.requested_by ?? "unknown"}</span>
        </div>
        {meta && <div className="text-[10.5px] text-text3">{meta.meaning}</div>}
      </div>

      {(status === "pushing" || steps.length > 0) && (
        <div className="space-y-1 border-t border-hair bg-sunk px-2.5 py-2">
          <AnimatePresence>
            {steps.slice(0, revealed).map((st) => (
              <motion.div key={st.key} initial={{ opacity: 0, x: -5 }} animate={{ opacity: 1, x: 0 }}
                className="flex items-start gap-1.5 text-[11.5px]">
                <span className="mt-0.5 shrink-0">
                  {st.status === "ok" ? <Check size={12} className="text-ok" />
                    : st.status === "warn" ? <AlertTriangle size={12} className="text-sev-high" />
                    : <X size={12} className="text-sev-critical" />}
                </span>
                <span className="min-w-0"><b>{st.label}</b> <span className="text-text3">{st.detail}</span></span>
              </motion.div>
            ))}
          </AnimatePresence>
          {running && revealed < steps.length && (
            <div className="flex items-center gap-1.5 text-[10.5px] text-text3"><Loader2 size={11} className="animate-spin" /> resolving…</div>
          )}
        </div>
      )}

      {conflicts.length > 0 && status !== "pushing" && (
        <div className="border-t border-hair px-2.5 py-1.5 text-[10.5px] text-text3">
          {conflicts.length} conflict{conflicts.length !== 1 ? "s" : ""} detected · {(item.resolution?.unresolved ?? []).length} need human review
        </div>
      )}

      {error && (
        <div role="alert" className="flex items-start gap-1.5 border-t border-hair px-2.5 py-2 text-[11px] text-sev-critical">
          <X size={12} className="mt-0.5 shrink-0" />
          <span>
            <b>{error.status ? `HTTP ${error.status}` : "No response from the API"}</b> — {error.detail} Nothing was applied.
          </span>
        </div>
      )}

      <div className="flex flex-wrap items-center gap-2 border-t border-hair px-2.5 py-1.5">
        {status === "no_op" ? (
          <span className="flex items-center gap-1.5 text-[11px] text-text2">
            <SkipForward size={12} className="text-text3" /> The flow is already covered, so nothing was recorded.
          </span>
        ) : status === "conflict" ? (
          <span className="flex items-center gap-1.5 text-[11px] text-sev-high"><AlertTriangle size={12} /> Held for a human — nothing was applied.</span>
        ) : !canApprove ? (
          // A viewer sees the state and not a control the API would refuse.
          <span className="text-[11px] text-text3">Implementing a queued change is an approver action.</span>
        ) : (
          <button onClick={run} disabled={running} className="btn-primary !h-[26px] !px-2 text-[11px]">
            {running ? <Spinner label="Running…" /> : <><Rocket size={12} /> Implement on {tool}{simulated ? " (simulated)" : ""}</>}
          </button>
        )}
        {canApprove && (status === "conflict" || status === "no_op") && (
          <button onClick={run} disabled={running} className="btn-ghost !h-[26px] !px-2 text-[11px]"><RefreshCw size={11} /> Re-run</button>
        )}
        {canApprove && (
          <button onClick={discard} disabled={busy || running} className="btn-ghost ml-auto !h-[26px] !px-2 text-[11px] text-text3">
            <Trash2 size={11} /> Discard
          </button>
        )}
      </div>
    </div>
  );
}
