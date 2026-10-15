"use client";

/**
 * THE IMPLEMENTATION VOCABULARY, IN ONE PLACE.
 *
 * "Staging area" was renamed because it told the user nothing about what
 * happens next; the screen is a queue of approved changes on their way to being
 * implemented. The words for each state are shared with the Risk To-Do side
 * panel, which now shows the same states inline — two screens spelling the same
 * status differently is how an operator learns to distrust both.
 *
 * WHAT "APPLIED" HONESTLY MEANS HERE. `status='pushed'` rows are re-applied to
 * the record set by the engine on every build (`load_applied_changes`), so they
 * really are applied — to OUR model of the estate. Nothing was written to
 * AlgoSec, Guardicore or Wiz: no connector exists in this build. Both halves are
 * said, every time, and `simulated` drives the wording rather than a hardcoded
 * sentence.
 */

import { useState } from "react";
import { AlertTriangle, Check, History, Loader2, Rocket, SkipForward, Undo2, X } from "lucide-react";
import { asApiError, riskApi, type ApiError, type RollbackResult } from "@/lib/api";
import type { StagedChange } from "@/lib/types";
import { cn } from "@/lib/cn";
import { Spinner } from "@/components/ui";
import { ErrorState, InlineError } from "@/components/ui/Feedback";
import { ProposedLine } from "./gate";

/** `rolled_back` is a real status the API sets and `lib/types.ts` (owned
 *  elsewhere) does not yet spell, so it is widened here rather than cast away. */
export type QueueStatus = StagedChange["status"] | "rolled_back";
export type QueueRow = Omit<StagedChange, "status"> & { status: QueueStatus };

export const TOOL_LABEL: Record<string, string> = { algosec: "AlgoSec", guardicore: "Guardicore", wiz: "Wiz" };
export const toolLabel = (t: string) => TOOL_LABEL[t] ?? t;

type StatusMeta = { label: string; cls: string; Icon: typeof Check; meaning: string };

export const QUEUE_STATUS: Record<string, StatusMeta> = {
  staged: {
    label: "queued", cls: "border-queue-line bg-queue-bg text-queue", Icon: Rocket,
    meaning: "Approved and waiting. Nothing has been applied.",
  },
  pushing: {
    label: "implementing", cls: "border-run-line bg-run-bg text-run", Icon: Loader2,
    meaning: "The stepped dry run is executing.",
  },
  pushed: {
    label: "applied", cls: "border-ok-line bg-ok-bg text-ok", Icon: Check,
    meaning: "In the applied overlay — the engine folds it into the record set on every build. No source system was written to.",
  },
  no_op: {
    label: "skipped — no-op", cls: "border-line bg-raise text-faint", Icon: SkipForward,
    meaning: "Every conflict resolved to 'skip', so nothing was recorded and the next recompute is unchanged.",
  },
  conflict: {
    label: "held for review", cls: "border-warn-line bg-warn-bg text-warn", Icon: AlertTriangle,
    meaning: "A conflict needs a human. Nothing was applied.",
  },
  failed: {
    label: "failed", cls: "border-err-line bg-err-bg text-err", Icon: X,
    meaning: "The run did not complete. Nothing was applied.",
  },
  rolled_back: {
    label: "rolled back", cls: "border-run-line bg-run-bg text-run", Icon: Undo2,
    meaning: "Was applied, then withdrawn. The row is kept: somebody approved it, it was live, somebody reversed it.",
  },
};

export function StatusChip({ status, size = "md", className }: { status: string; size?: "sm" | "md"; className?: string }) {
  const m = QUEUE_STATUS[status];
  if (!m) {
    return (
      <span className={cn("inline-flex items-center rounded-sm border border-line-strong bg-raise px-1.5 py-0.5 font-mono font-medium text-dim",
        size === "sm" ? "text-[9.5px]" : "text-[10.5px]", className)}
        title={`The API reported status "${status}", which this build does not know.`}>
        {status}
      </span>
    );
  }
  const { Icon } = m;
  return (
    <span title={m.meaning}
      className={cn("inline-flex items-center gap-1.5 rounded-sm border px-1.5 py-0.5 font-medium", m.cls,
        size === "sm" ? "text-[10px]" : "text-[11px]", className)}>
      <Icon size={size === "sm" ? 10 : 12} className={cn("shrink-0", status === "pushing" && "af-spin")} />
      {m.label}
    </span>
  );
}

/** How a change came to be approved. The queue row carries the DECISION, not
 *  the approver's name — that lives on the ruling — so this says exactly what
 *  the row knows and no more. */
export function DecisionOrigin({ decision }: { decision?: string }) {
  const manual = decision === "manual_approved";
  return (
    <span className="text-[10.5px] text-text3" title={manual
      ? "An escalated change an approver explicitly cleared."
      : "The gate auto-approved this from the computed delta."}>
      {manual ? "manually approved by an approver" : "auto-approved by the gate"}
    </span>
  );
}

const when = (v?: string | null) => (v ? new Date(v).toLocaleString() : null);

/**
 * ONE APPLIED CHANGE, WITH THE WAY BACK OUT.
 *
 * Asked for directly: "if a change is approved, have a place where we had made
 * changes and have a way to rollback those."
 *
 * A rollback is a status transition, not a reverse edit — the applied overlay is
 * derived, so dropping the row out of `pushed` means the next build simply never
 * applies it. Which is why the confirmation says `recompute_required` out loud:
 * the RUNNING engine still holds the change. Reporting "rolled back" alone would
 * claim the estate had already moved.
 */
export function AppliedChangeCard({ row, canApprove, snapshot, onChanged, findingSlot }: {
  row: QueueRow;
  canApprove: boolean;
  snapshot?: string;
  onChanged?: () => void;
  /** The finding this change came from, rendered by the caller as a link back
   *  into the Risk To-Do list. */
  findingSlot?: React.ReactNode;
}) {
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<ApiError>();
  const [result, setResult] = useState<RollbackResult>();
  const [reason, setReason] = useState("");
  const [asking, setAsking] = useState(false);

  const rolledBack = row.status === "rolled_back";

  const rollback = async () => {
    setBusy(true); setErr(undefined);
    try {
      const r = await riskApi.rollback(row.staged_id, reason.trim() || undefined);
      setResult(r); setAsking(false); setReason("");
      onChanged?.();
    } catch (e) {
      setErr(asApiError(e));
    } finally { setBusy(false); }
  };

  return (
    <div className="border border-border bg-surface2">
      <div className="flex flex-wrap items-center gap-2 border-b border-hair px-2.5 py-1.5">
        <StatusChip status={row.status} />
        <span className="text-[11px] text-text2">{toolLabel(row.target_tool)}</span>
        {findingSlot}
        <span className="mono ml-auto text-[10px] text-text3">
          {when(row.pushed_at) ?? when(row.created_at) ?? ""}
        </span>
      </div>

      <div className="space-y-1.5 px-2.5 py-2">
        <ProposedLine proposed={row.payload} kind={row.kind} snapshot={snapshot} />
        <div className="flex flex-wrap items-center gap-x-3 gap-y-1 text-[10.5px] text-text3">
          <DecisionOrigin decision={row.decision} />
          <span>requested by <span className="mono text-text2">{row.requested_by ?? "unknown"}</span></span>
          {when(row.created_at) && <span>approved {when(row.created_at)}</span>}
          {when(row.pushed_at) && <span>applied {when(row.pushed_at)}</span>}
        </div>
        {row.justification && <div className="text-[10.5px] italic text-text3">“{row.justification}”</div>}
      </div>

      {result && (
        // The honest half of a successful rollback. `recompute_required` is not
        // a footnote: until the engine is rebuilt it still reports the estate
        // WITH this change in it.
        <div role="status" className="flex items-start gap-2 border-t border-sev-medium-line bg-sev-medium-bg px-2.5 py-2 text-[11px]">
          <Undo2 size={13} className="mt-0.5 shrink-0 text-sev-medium" />
          <span>
            <b className="text-sev-medium">Rolled back.</b> {result.detail}
            {result.recompute_required && (
              <span className="mt-0.5 block text-text2">
                The running engine still holds this change until it is rebuilt — recompute before quoting the estate&apos;s posture.
              </span>
            )}
          </span>
        </div>
      )}

      {err && <div className="border-t border-hair px-2.5 py-2"><InlineError resource="the rollback" error={err} onRetry={rollback} /></div>}

      <div className="flex flex-wrap items-center gap-2 border-t border-hair px-2.5 py-1.5">
        {rolledBack ? (
          // The recompute caveat is stated on EVERY withdrawn row, not only on
          // the one just actioned: the engine reads the applied overlay at build
          // time, so a row can sit here withdrawn while the running result still
          // reports the estate with the change in it. A banner that vanished on
          // the next render would let that gap go unsaid.
          <span className="text-[11px] text-text3">
            Withdrawn from the applied overlay; the record is kept as compliance history. The engine re-reads the
            overlay only when it is rebuilt — <b className="text-text2">Recompute</b> before quoting the estate&apos;s posture.
          </span>
        ) : !canApprove ? (
          // A viewer must see the STATE and not a control they cannot use.
          <span className="text-[11px] text-text3">
            Applied. Rolling a change back is an approver action.
          </span>
        ) : asking ? (
          <>
            <input
              value={reason} onChange={(e) => setReason(e.target.value)} placeholder="Reason (optional, recorded in the audit trail)"
              className="field !h-[26px] min-w-[200px] flex-1 !text-[11px]"
            />
            <button onClick={rollback} disabled={busy} className="btn-danger !h-[26px] !px-2 text-[11px]">
              {busy ? <Spinner label="Rolling back…" /> : <><Undo2 size={12} /> Confirm rollback</>}
            </button>
            <button onClick={() => { setAsking(false); setReason(""); }} disabled={busy} className="btn-ghost !h-[26px] !px-2 text-[11px]">Cancel</button>
          </>
        ) : (
          <>
            <button onClick={() => setAsking(true)} className="btn-ghost !h-[26px] !px-2 text-[11px]">
              <Undo2 size={12} /> Roll back
            </button>
            <span className="text-[10.5px] text-text3">Takes it out of the applied overlay; the record stays.</span>
          </>
        )}
      </div>
    </div>
  );
}

/**
 * THE PLACE WHERE CHANGES WE MADE ARE LISTED.
 *
 * Presentational on purpose: both callers already load `/api/staging` for their
 * own reasons, and a second fetch would let the two lists disagree about what is
 * applied.
 */
export function AppliedChanges({ rows, error, loading, canApprove, snapshot, onChanged, onRetry, findingSlot, emptyNote }: {
  /** Every staged row; this component selects the applied + withdrawn ones. */
  rows?: QueueRow[];
  error?: ApiError;
  loading?: boolean;
  canApprove: boolean;
  snapshot?: string;
  onChanged?: () => void;
  onRetry?: () => void;
  findingSlot?: (row: QueueRow) => React.ReactNode;
  emptyNote?: string;
}) {
  if (error) {
    return (
      <ErrorState
        resource="the applied-change history"
        error={error}
        onRetry={onRetry}
        className=""
      />
    );
  }
  if (loading && !rows) {
    return <div className="border border-border bg-surface2 p-3 text-[11.5px] text-text3">Reading the applied overlay…</div>;
  }
  const applied = (rows ?? []).filter((r) => r.status === "pushed");
  const withdrawn = (rows ?? []).filter((r) => r.status === "rolled_back");
  if (!applied.length && !withdrawn.length) {
    return (
      <div className="border border-border bg-surface2 p-3 text-[11.5px] text-text3">
        {emptyNote ?? "No change has been applied yet. Nothing is in the engine's applied overlay."}
      </div>
    );
  }
  return (
    <div className="space-y-2">
      {applied.map((r) => (
        <AppliedChangeCard key={r.staged_id} row={r} canApprove={canApprove} snapshot={snapshot}
          onChanged={onChanged} findingSlot={findingSlot?.(r)} />
      ))}
      {withdrawn.length > 0 && (
        <>
          <div className="flex items-center gap-1.5 pt-1 text-[9.5px] font-bold uppercase tracking-[0.14em] text-text3">
            <History size={11} /> withdrawn ({withdrawn.length})
          </div>
          {withdrawn.map((r) => (
            <AppliedChangeCard key={r.staged_id} row={r} canApprove={canApprove} snapshot={snapshot}
              onChanged={onChanged} findingSlot={findingSlot?.(r)} />
          ))}
        </>
      )}
    </div>
  );
}
