"use client";

/**
 * IDENTITY & MERGES — absorbed from the duplicate screen that used to sit next
 * to this one in the nav.
 *
 * That screen's table restated the inventory with fewer columns and fewer
 * entity types, so it is gone. THIS is what was unique about it, and every
 * behaviour it had is carried over deliberately:
 *
 *   · the confidence score, as a percentage;
 *   · the sensitive tags the two records share, which is why a wrong merge here
 *     is expensive;
 *   · the engine's reason, as prose, verbatim;
 *   · a per-pair Confirm control, because THE ENGINE NEVER AUTO-MERGES — a
 *     wrong merge corrupts a fact permanently, and a human owns that decision;
 *   · that control disabled on a historical snapshot, with the reason;
 *   · and the failure distinction below, which is the load-bearing one.
 *
 * THE FAILURE DISTINCTION. The old fallback for a failed suggestions fetch was
 * `[]`, and `[]` rendered "All identities resolved deterministically" — the
 * product inventing a clean bill of health out of a dead endpoint, on the one
 * screen whose entire job is to flag unresolved identity. So:
 *
 *      undefined  =  not answered (loading), or not answered at all (failed)
 *      []         =  the API answered, and proposed nothing
 *
 * They render as a skeleton, an ErrorState, and an empty state respectively,
 * and they are never allowed to collapse into each other.
 */

import { useState } from "react";
import { Check, GitMerge, Link2, ShieldQuestion } from "lucide-react";
import { asApiError, type ApiError } from "@/lib/api";
import { cn } from "@/lib/cn";
import { toolColour } from "@/lib/toolColour";
import { Chip, EmptyState, Panel, Skeleton, SkeletonText, Spinner, Tag } from "@/components/ui";
import { ErrorState, InlineError } from "@/components/ui/Feedback";
import { Prose } from "@/components/Markdown";
import type { IdentityState, MergeSuggestionDetail } from "./identity";

export function IdentityReview({
  identity,
  snapshot,
  /** Jump the table to the rows a proposal names. */
  onShowDuplicates,
}: {
  identity: IdentityState;
  snapshot?: string;
  onShowDuplicates?: () => void;
}) {
  const [merging, setMerging] = useState<string>();
  const [mergeErr, setMergeErr] = useState<ApiError>();
  const [merged, setMerged] = useState<string>();
  // A merge rewrites the live snapshot. It is not an operation on a past one.
  const isLive = !snapshot;

  const { suggestions, suggestionsError, correlatedAssets, assetsError } = identity;

  const confirm = async (s: MergeSuggestionDetail) => {
    const pair = `${s.a}~${s.b}`;
    setMerging(pair);
    setMergeErr(undefined);
    setMerged(undefined);
    try {
      await identity.confirmMerge(s.a, s.b);
      setMerged(pair);
    } catch (e) {
      setMergeErr(asApiError(e));
    } finally {
      setMerging(undefined);
    }
  };

  return (
    <Panel
      title="Identity & merges"
      actions={
        suggestions && suggestions.length > 0 ? (
          <Chip variant="warn" mono>
            {suggestions.length} awaiting review
          </Chip>
        ) : null
      }
      noPadding
    >
      <div className="space-y-3 p-3 sm:p-4">
        <p className="text-[12px] leading-relaxed text-text2">
          One identity per asset; an IP is an attribute of it, not its key. Matches the engine could prove &mdash; the
          same hostname, or the same address inside the same context &mdash; are already settled and are marked on the
          inventory rows above. What is left here is what it could NOT prove, and{" "}
          <span className="font-bold text-text">the engine never merges those on its own</span>: a wrong merge corrupts
          a fact permanently, so a human confirms each one.
        </p>

        <SettledSummary
          correlatedAssets={correlatedAssets}
          assetsError={assetsError}
          onShowDuplicates={onShowDuplicates}
          onRetry={() => identity.reload(false)}
        />

        <div>
          <div className="mb-2 flex flex-wrap items-center gap-2">
            <span className="flex items-center gap-1.5 text-[10px] font-bold uppercase tracking-[0.12em] text-text3">
              <GitMerge size={11} /> Possible duplicates &mdash; review
            </span>
            {!isLive ? (
              <Chip variant="warn">read-only: past snapshot</Chip>
            ) : null}
          </div>

          {suggestionsError ? (
            /* NOT an empty state. A failed fetch here used to print "all
               identities resolved deterministically", which is the product
               inventing a clean result out of a dead endpoint. */
            <ErrorState
              resource="the duplicate-identity suggestions"
              error={suggestionsError}
              onRetry={() => identity.reload(false)}
            />
          ) : suggestions === undefined ? (
            <div className="grid gap-2 md:grid-cols-2">
              {Array.from({ length: 2 }).map((_, i) => (
                <div key={i} className="space-y-2 border border-border bg-surface2 p-3">
                  <Skeleton className="h-4 w-3/4" />
                  <Skeleton className="h-3 w-1/2" />
                  <SkeletonText lines={2} />
                </div>
              ))}
            </div>
          ) : suggestions.length === 0 ? (
            <div className="border border-border bg-surface2">
              <EmptyState
                icon={GitMerge}
                title="No candidates"
                sub="The API answered and proposed nothing: every identity in this snapshot resolved deterministically."
              />
            </div>
          ) : (
            <ul className="grid gap-2 md:grid-cols-2">
              {suggestions.map((s) => (
                <SuggestionCard
                  key={`${s.a}~${s.b}`}
                  s={s}
                  busy={merging === `${s.a}~${s.b}`}
                  anyBusy={!!merging}
                  isLive={isLive}
                  done={merged === `${s.a}~${s.b}`}
                  onConfirm={() => confirm(s)}
                />
              ))}
            </ul>
          )}

          {mergeErr ? <InlineError resource="the confirmed merge" error={mergeErr} className="mt-2" /> : null}

          {suggestions && suggestions.length > 0 && !isLive ? (
            <p className="mt-2 text-[11px] text-text3">
              You are viewing a past snapshot. A merge rewrites identity in the <b className="text-text2">live</b> one,
              so it cannot be confirmed from here &mdash; switch to Live above.
            </p>
          ) : null}
        </div>
      </div>
    </Panel>
  );
}

// ── The settled half ───────────────────────────────────────────────────────

function SettledSummary({
  correlatedAssets,
  assetsError,
  onShowDuplicates,
  onRetry,
}: {
  correlatedAssets?: number;
  assetsError?: ApiError;
  onShowDuplicates?: () => void;
  onRetry: () => void;
}) {
  if (assetsError) {
    return <InlineError resource="the settled identity correlations" error={assetsError} onRetry={onRetry} />;
  }
  return (
    <div className="flex flex-wrap items-center gap-x-3 gap-y-1.5 border border-border bg-sunk px-3 py-2 text-[11.5px]">
      <span className="flex items-center gap-1.5 font-bold text-accent-fg">
        <Link2 size={12} />
        {correlatedAssets === undefined ? (
          <span
            className="cursor-help underline decoration-dotted underline-offset-2"
            title="The asset layer has not answered yet, so how many identities were correlated is unknown. It is not zero."
          >
            &mdash;
          </span>
        ) : (
          <span className="mono tabular-nums">{correlatedAssets.toLocaleString()}</span>
        )}{" "}
        settled {correlatedAssets === 1 ? "identity" : "identities"}
      </span>
      <span className="text-text2">
        proved to be the same thing another console called something else. Each one is marked{" "}
        <span className="mono text-[10.5px] font-bold text-accent-fg">merged</span> on its inventory row.
      </span>
      {onShowDuplicates ? (
        <button
          type="button"
          onClick={onShowDuplicates}
          className="ml-auto shrink-0 font-bold text-text3 underline underline-offset-2 transition-colors hover:text-accent-fg"
        >
          show them in the table
        </button>
      ) : null}
    </div>
  );
}

// ── One proposal ───────────────────────────────────────────────────────────

function SuggestionCard({
  s,
  busy,
  anyBusy,
  isLive,
  done,
  onConfirm,
}: {
  s: MergeSuggestionDetail;
  busy: boolean;
  anyBusy: boolean;
  isLive: boolean;
  done: boolean;
  onConfirm: () => void;
}) {
  const pct = Math.round(s.confidence * 100);
  // `similarity_available: false` means the embedding model could not be
  // reached, so this score is NOT embedding-backed. Rendering the number
  // without that fact is the same class of lie as rendering a failed count.
  const degraded = s.similarity_available === false;

  return (
    <li className="flex flex-col border border-border bg-surface2">
      <div className="flex flex-wrap items-start gap-2 border-b border-hair px-3 py-2">
        <div className="min-w-0 flex-1">
          <Side name={s.a} tools={s.a_tools} ips={s.a_ips} />
          <div className="my-1 flex items-center gap-2 text-[10px] font-bold uppercase tracking-[0.12em] text-text3">
            <span className="h-px flex-1 bg-hair" />
            same thing?
            <span className="h-px flex-1 bg-hair" />
          </div>
          <Side name={s.b} tools={s.b_tools} ips={s.b_ips} />
        </div>
        <Chip variant={degraded ? "warn" : pct >= 90 ? "accent" : "neutral"} mono className="shrink-0">
          {pct}%
        </Chip>
      </div>

      <div className="space-y-2 px-3 py-2">
        {s.shared_sensitive_tags.length > 0 ? (
          <div
            className="flex flex-wrap items-center gap-1"
            title="Both records carry these tags. It is why this pair matters: merging two different machines that both hold regulated data moves a control onto the wrong box."
          >
            <span className="text-[10px] font-bold uppercase tracking-[0.1em] text-text3">shared</span>
            {s.shared_sensitive_tags.map((t) => (
              <Tag key={t}>{t}</Tag>
            ))}
          </div>
        ) : (
          <p className="text-[11px] text-text3">The two records share no sensitive tag.</p>
        )}

        <Prose className="!text-[11.5px]">{s.reason}</Prose>

        <div className="flex flex-wrap items-center gap-x-3 gap-y-1 text-[10.5px] text-text3">
          {s.name_similarity !== undefined ? (
            <span className="mono" title="String similarity between the two names, before any tag evidence.">
              name {Math.round(s.name_similarity * 100)}%
            </span>
          ) : null}
          {s.confidence_basis ? (
            <span className="mono" title="How the engine arrived at the score above.">
              basis: {s.confidence_basis}
            </span>
          ) : null}
          {s.recommended_action ? (
            <span className="mono" title="What the engine recommends a human do with this pair.">
              action: {s.recommended_action}
            </span>
          ) : null}
        </div>

        {degraded ? (
          <p className="flex items-start gap-1.5 border border-sev-medium-line bg-sev-medium-bg px-2 py-1.5 text-[11px] leading-relaxed text-sev-medium">
            <ShieldQuestion size={12} className="mt-[2px] shrink-0" />
            <span>
              <span className="font-bold">The embedding model was not available for this pair</span>, so the score above
              is not embedding-backed &mdash; it rests on the string and tag evidence alone.
              {s.similarity_unavailable_reason ? (
                <span className="mono mt-0.5 block break-words text-[10.5px] opacity-80">
                  {s.similarity_unavailable_reason}
                </span>
              ) : null}
            </span>
          </p>
        ) : null}
      </div>

      <div className="mt-auto border-t border-hair p-2">
        {done ? (
          <p className="flex items-center justify-center gap-1.5 py-1 text-[11.5px] font-bold text-ok">
            <Check size={13} /> Merged &mdash; identities re-resolved and the estate recomputed.
          </p>
        ) : (
          <button
            type="button"
            onClick={onConfirm}
            disabled={!isLive || anyBusy}
            className={cn("btn-primary !h-8 w-full text-[11.5px]")}
            title={
              isLive
                ? "Unify these into one asset. This re-resolves identities and recomputes the snapshot, and it cannot be undone from here."
                : "Switch to the live snapshot to confirm merges."
            }
          >
            {busy ? <Spinner label="Merging + recomputing…" /> : <><Check size={13} /> Confirm merge</>}
          </button>
        )}
      </div>
    </li>
  );
}

function Side({ name, tools, ips }: { name: string; tools?: string[]; ips?: string[] }) {
  return (
    <div className="min-w-0">
      <div className="mono break-all text-[12.5px] font-bold">{name}</div>
      <div className="mt-0.5 flex flex-wrap items-center gap-x-2 gap-y-0.5">
        {tools?.length ? (
          tools.map((t) => (
            <span key={t} className="inline-flex items-center gap-1 text-[10.5px] text-text2">
              <span aria-hidden className="h-2 w-2 shrink-0" style={{ background: toolColour(t) }} />
              <span className="mono">{t}</span>
            </span>
          ))
        ) : (
          <span className="text-[10.5px] text-text3">no source named with this record</span>
        )}
        {ips?.length ? <span className="mono text-[10.5px] text-text3">{ips.join(", ")}</span> : null}
      </div>
    </div>
  );
}

export default IdentityReview;
