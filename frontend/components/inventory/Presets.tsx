"use client";

/**
 * The one-click chips.
 *
 * Two rows, kept visibly apart, because they answer at two different scopes —
 * see views.ts. The second row's caveat line is not decoration: it is the only
 * thing stopping "Conflicts 3" off a 50-row page from being quoted as the
 * estate's conflict count.
 */

import { Bookmark, Eye, Loader2 } from "lucide-react";
import { cn } from "@/lib/cn";
import { InlineError } from "@/components/ui/Feedback";
import {
  EMPTY_FILTER,
  PAGE_VIEWS,
  filterEquals,
  type PageView,
  type PageViewCtx,
  type PageViewId,
  type QueryFilter,
  type QueryPreset,
  type UnlinkedState,
} from "./views";

export function Presets({
  presets,
  current,
  onApply,
  views,
  activeView,
  onView,
  viewCtx,
  unlinked,
  loadedRows,
  filtered,
}: {
  presets: QueryPreset[];
  current: QueryFilter;
  onApply: (f: QueryFilter) => void;
  /** Row counts per view, over the LOADED page. `undefined` = the read behind
   *  it has not landed or has failed. */
  views: Partial<Record<PageViewId, number | undefined>>;
  activeView?: PageViewId;
  onView: (id?: PageViewId) => void;
  viewCtx: PageViewCtx;
  unlinked: UnlinkedState;
  loadedRows: number;
  filtered: boolean;
}) {
  return (
    <div className="border border-border bg-surface2">
      <div className="flex flex-wrap items-center gap-x-2 gap-y-1.5 border-b border-hair px-3 py-2">
        <span
          className="flex items-center gap-1.5 text-[10px] font-bold uppercase tracking-[0.12em] text-text3"
          title="These re-ask the API. The result describes the whole snapshot, not this page."
        >
          <Bookmark size={11} /> Saved queries
        </span>
        {presets.length === 0 ? (
          <span className="text-[11px] text-text3">
            No saved query can be built from this snapshot&apos;s facets.
          </span>
        ) : (
          presets.map((p) => {
            const on = filterEquals(current, p.filter);
            return (
              <button
                key={p.id}
                type="button"
                aria-pressed={on}
                onClick={() => onApply(on ? EMPTY_FILTER : p.filter)}
                title={`${p.asks}${on ? "\n\nApplied. Click to clear every filter." : ""}`}
                className={cn(
                  "inline-flex min-h-[22px] items-center gap-1.5 border px-2 py-[3px] text-[11px] font-bold leading-tight transition-colors",
                  on
                    ? "border-accent bg-accent-soft text-accent-fg"
                    : "border-border bg-sunk text-text2 hover:border-accent hover:text-accent-fg",
                )}
              >
                {p.label}
                {p.count !== undefined ? (
                  <span className="mono text-[10px] tabular-nums opacity-70">{p.count}</span>
                ) : null}
              </button>
            );
          })
        )}
        <span className="ml-auto text-[10.5px] text-text3">server-side &middot; describes the snapshot</span>
      </div>

      <div className="flex flex-wrap items-center gap-x-2 gap-y-1.5 px-3 py-2">
        <span
          className="flex items-center gap-1.5 text-[10px] font-bold uppercase tracking-[0.12em] text-text3"
          title="These narrow the rows already loaded. They are not server-side filters."
        >
          <Eye size={11} /> Page views
        </span>
        {PAGE_VIEWS.map((v) => (
          <ViewChip
            key={v.id}
            view={v}
            count={views[v.id]}
            active={activeView === v.id}
            ctx={viewCtx}
            unlinked={unlinked}
            onClick={() => onView(activeView === v.id ? undefined : v.id)}
          />
        ))}
        {activeView ? (
          <button
            type="button"
            onClick={() => onView(undefined)}
            className="text-[11px] font-bold text-text3 underline underline-offset-2 transition-colors hover:text-accent-fg"
          >
            show all rows
          </button>
        ) : null}
        <span className="ml-auto text-[10.5px] text-text3">
          {loadedRows.toLocaleString()} {loadedRows === 1 ? "row" : "rows"} loaded
        </span>
      </div>

      {activeView ? (
        <ViewCaveat
          view={PAGE_VIEWS.find((v) => v.id === activeView)!}
          count={views[activeView]}
          loadedRows={loadedRows}
          unlinked={unlinked}
          filtered={filtered}
        />
      ) : null}

      {unlinked.error ? (
        <div className="border-t border-hair px-3 py-2">
          <InlineError resource="the topology read behind unlinked devices" error={unlinked.error} />
        </div>
      ) : null}
    </div>
  );
}

function ViewChip({
  view,
  count,
  active,
  ctx,
  unlinked,
  onClick,
}: {
  view: PageView;
  count?: number;
  active: boolean;
  ctx: PageViewCtx;
  unlinked: UnlinkedState;
  onClick: () => void;
}) {
  const identityDown = view.needs === "identity" && ctx.identityUnknown;
  const topoDown = view.needs === "topology" && !!unlinked.error;
  const topoPending = view.needs === "topology" && !unlinked.requested;
  const busy = view.needs === "topology" && unlinked.loading;
  const blocked = identityDown || topoDown;

  const title = identityDown
    ? `${view.hint}\n\nUNAVAILABLE: the asset layer could not be read, so this cannot be answered. It is not zero.`
    : topoDown
      ? `${view.hint}\n\nUNAVAILABLE: the topology read failed, so this cannot be answered. It is not zero.`
      : topoPending
        ? `${view.hint}\n\nClick to run the topology read this needs.`
        : `${view.hint}\n\n${count ?? 0} of the rows loaded on this page.`;

  return (
    <button
      type="button"
      aria-pressed={active}
      disabled={blocked}
      onClick={onClick}
      title={title}
      className={cn(
        "inline-flex min-h-[22px] items-center gap-1.5 border px-2 py-[3px] text-[11px] font-bold leading-tight transition-colors",
        blocked
          ? "cursor-not-allowed border-sev-medium-line bg-sev-medium-bg text-sev-medium"
          : active
            ? "border-accent bg-accent-soft text-accent-fg"
            : "border-border bg-sunk text-text2 hover:border-accent hover:text-accent-fg",
      )}
    >
      {view.label}
      {busy ? (
        <Loader2 size={10} className="animate-spin" />
      ) : blocked ? (
        <span className="text-[10px]">unavailable</span>
      ) : topoPending ? (
        <span className="mono text-[10px] opacity-70">&mdash;</span>
      ) : (
        <span className="mono text-[10px] tabular-nums opacity-70">{count ?? 0}</span>
      )}
    </button>
  );
}

/** The sentence that keeps a page figure from being read as an estate figure. */
function ViewCaveat({
  view,
  count,
  loadedRows,
  unlinked,
  filtered,
}: {
  view: PageView;
  count?: number;
  loadedRows: number;
  unlinked: UnlinkedState;
  filtered: boolean;
}) {
  const n = count ?? 0;
  const estate =
    view.id === "unlinked" && unlinked.total !== undefined
      ? `The topology engine reports ${unlinked.total.toLocaleString()} unlinked ${unlinked.total === 1 ? "device" : "devices"} in this snapshot.`
      : undefined;

  return (
    <div className="border-t border-hair bg-sunk px-3 py-2 text-[11px] leading-relaxed text-text2">
      <span className="font-bold text-text">
        Page view: {view.label} &mdash; {n.toLocaleString()} of the {loadedRows.toLocaleString()}{" "}
        {loadedRows === 1 ? "row" : "rows"} on this page.
      </span>{" "}
      This narrows what is already loaded; it is not a server-side filter, so it says nothing about the rows on other
      pages{filtered ? " or about matches this filter excluded" : ""}.
      {estate ? <span className="text-text"> {estate}</span> : null}
      {view.id === "unlinked" && unlinked.total !== undefined && n < unlinked.total ? (
        <span className="text-sev-medium">
          {" "}
          {n === 0
            ? "None of them is on this page — page on, raise the page size, or clear the filter."
            : `${(unlinked.total - n).toLocaleString()} of them are not on this page.`}
        </span>
      ) : null}
    </div>
  );
}

export default Presets;
