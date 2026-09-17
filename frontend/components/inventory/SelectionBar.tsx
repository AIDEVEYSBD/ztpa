"use client";

/**
 * The bulk action bar.
 *
 * IT ONLY OFFERS WHAT ACTUALLY EXISTS. There is no "delete", no "tag", no
 * "assign owner" — this console reads an estate it does not own, and a greyed
 * button for an endpoint that was never built is a promise the product cannot
 * keep. Two actions are real, and they are the only two here:
 *
 *   EXPORT SELECTED — client-side, from rows already loaded.
 *   CONFIRM MERGE   — `POST /api/assets/merge`, and only for the selected rows
 *                     an unconfirmed proposal actually names. It is hidden
 *                     outright when the selection contains no such row, rather
 *                     than sitting there disabled implying the estate has
 *                     duplicates it does not have.
 *
 * The selection is cleared by the panel whenever the filter or the page moves,
 * so "selected" can never mean rows that are no longer on screen — which is how
 * a bulk action ends up applied to something the operator cannot see.
 */

import { useState } from "react";
import { Check, Download, GitMerge, X } from "lucide-react";
import { asApiError, type ApiError } from "@/lib/api";
import { Spinner } from "@/components/ui";
import { InlineError } from "@/components/ui/Feedback";
import type { MergeSuggestionDetail } from "./identity";

export function SelectionBar({
  count,
  onClear,
  onExport,
  pendingMerges,
  isLive,
  onConfirmMerge,
  onMerged,
}: {
  count: number;
  onClear: () => void;
  onExport: () => void;
  /** The distinct proposals the selected rows resolve to. Empty = no merge
   *  action is offered at all. */
  pendingMerges: MergeSuggestionDetail[];
  isLive: boolean;
  onConfirmMerge: (a: string, b: string) => Promise<void>;
  onMerged: () => void;
}) {
  const [busy, setBusy] = useState(false);
  const [done, setDone] = useState(0);
  const [error, setError] = useState<ApiError>();

  if (count === 0) return null;

  const runMerges = async () => {
    setBusy(true);
    setError(undefined);
    setDone(0);
    // Sequential on purpose: each merge re-resolves identity and recomputes, so
    // firing them together would have later ones decided against a snapshot the
    // earlier ones have already moved.
    for (let i = 0; i < pendingMerges.length; i += 1) {
      const s = pendingMerges[i];
      try {
        await onConfirmMerge(s.a, s.b);
        setDone(i + 1);
      } catch (e) {
        // Stop at the first failure and say how far it got. Carrying on would
        // leave the operator unable to tell which pairs were applied.
        setError(asApiError(e));
        break;
      }
    }
    setBusy(false);
    onMerged();
  };

  return (
    <div className="border border-accent bg-accent-soft">
      <div className="flex flex-wrap items-center gap-x-3 gap-y-2 px-3 py-2">
        <span className="text-[12px] font-bold text-accent-fg">
          <span className="mono tabular-nums">{count.toLocaleString()}</span> {count === 1 ? "row" : "rows"} selected
        </span>

        <button type="button" onClick={onExport} className="btn-ghost !h-7 !px-2 text-[11.5px]" disabled={busy}>
          <Download size={12} /> Export selected
        </button>

        {pendingMerges.length > 0 ? (
          <button
            type="button"
            onClick={runMerges}
            disabled={busy || !isLive}
            className="btn-primary !h-7 !px-2 text-[11.5px]"
            title={
              isLive
                ? `Confirm ${pendingMerges.length} duplicate ${pendingMerges.length === 1 ? "proposal" : "proposals"} the selected rows are named in: ${pendingMerges
                    .map((s) => `${s.a} ~ ${s.b}`)
                    .join("; ")}. Each one re-resolves identities and recomputes.`
                : "A merge rewrites the live snapshot — switch to Live to confirm."
            }
          >
            {busy ? (
              <Spinner label={`Merging ${done + 1} of ${pendingMerges.length}…`} />
            ) : (
              <>
                <GitMerge size={12} /> Confirm {pendingMerges.length}{" "}
                {pendingMerges.length === 1 ? "merge" : "merges"}
              </>
            )}
          </button>
        ) : null}

        <span className="text-[10.5px] text-text2">
          {pendingMerges.length === 0
            ? "No unconfirmed duplicate proposal names any selected row, so there is nothing to merge."
            : "The engine never merges on its own — this confirms proposals a human has read."}
        </span>

        <button
          type="button"
          onClick={onClear}
          disabled={busy}
          className="ml-auto inline-flex items-center gap-1 text-[11.5px] font-bold text-text2 underline underline-offset-2 transition-colors hover:text-accent-fg"
        >
          <X size={11} /> Clear
        </button>
      </div>

      {done > 0 && !busy && !error ? (
        <p className="flex items-center gap-1.5 border-t border-accent px-3 py-1.5 text-[11.5px] font-bold text-ok">
          <Check size={12} /> {done} {done === 1 ? "merge" : "merges"} confirmed. Identities were re-resolved and the
          estate recomputed.
        </p>
      ) : null}

      {error ? (
        <div className="border-t border-accent px-3 py-1.5">
          <InlineError resource={`the merge after ${done} of ${pendingMerges.length} had been applied`} error={error} />
        </div>
      ) : null}
    </div>
  );
}

export default SelectionBar;
