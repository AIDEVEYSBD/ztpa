"use client";

/**
 * STEP 2 OF THE REVIEW - THE INVENTORY.
 *
 * Every entity we found, what KIND it is, and the explicit ask: WHERE WE FOUND
 * IT - which source, which subnet, which VLAN. The header reads the estate's
 * figures out loud ("I have these many subnets, I have these many VLANs"), the
 * table carries the provenance, and the drawer carries the evidence behind a
 * row.
 *
 * THIS SCREEN ALSO ABSORBED "IDENTITY & MERGES", which used to sit next to it
 * in the nav and show a second, smaller table of the same estate. The table is
 * gone; what was genuinely unique about that screen - the embedding-based
 * duplicate proposals a human confirms - is a clearly-separated section at the
 * bottom of this one, and the SETTLED half of the same fact is now on the rows
 * it affects: an asset the engine correlated across tools carries that on its
 * inventory row, which is where somebody would look for it.
 *
 * WHAT THIS SCREEN REFUSES TO DO, and why each refusal is load-bearing:
 *
 *   - A failed fetch renders NOTHING derived from it. No figure row, no facet
 *     counts, no "0 entities" - one ErrorState, which also puts itself on the
 *     console's health record so the degraded banner above cannot claim the
 *     panels below it are fine.
 *   - A `null` count is an em-dash with its reason, never a 0. "No source
 *     declares an interface count" and "there are no interfaces" are different
 *     statements about a client's network.
 *   - `has_more` is said out loud. A silently truncated table reads as a
 *     complete one, and the number a reviewer quotes off it would be wrong. The
 *     CSV export says the same thing on the way out of the product.
 *   - Filtering and paging are the SERVER's, so `total` and the rows on screen
 *     answer the same question. Sorting and the PAGE VIEWS are local, and both
 *     say so rather than letting a narrowed page imply a narrowed estate.
 *   - Whether a source is a live connector or a seeded export comes from the
 *     source register; when that register cannot be read, this screen says the
 *     origin is unknown rather than letting the badges imply "live".
 *   - A failed asset read makes "was this correlated across tools?" UNKNOWN on
 *     every row, not "no".
 */

import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { PackageSearch, RotateCw, ScanSearch } from "lucide-react";
import { api, asApiError, type ApiError } from "@/lib/api";
import type { InventoryItem, InventoryResponse, SourceCard } from "@/lib/types";
import { Chip, EmptyState, Panel } from "./ui";
import { ErrorState, InlineError } from "./ui/Feedback";
import { CountsReadout } from "./inventory/CountsReadout";
import { InventoryFilters, type FacetGroup } from "./inventory/InventoryFilters";
import { InventoryTable } from "./inventory/InventoryTable";
import { InventoryDrawer } from "./inventory/InventoryDrawer";
import { IdentityReview } from "./inventory/IdentityReview";
import { Presets } from "./inventory/Presets";
import { SelectionBar } from "./inventory/SelectionBar";
import { TIER_MEANING, TIER_SHORT } from "./inventory/bits";
import {
  ColumnMenu,
  DensityToggle,
  ExportButton,
  ExportReceiptNote,
  type ExportReceipt,
} from "./inventory/TableTools";
import {
  DEFAULT_COLUMN_IDS,
  INVENTORY_COLUMNS,
  resolveColumns,
  type CellCtx,
  type DrawerFocus,
} from "./inventory/columns";
import { csvFilename, downloadCsv, toCsv } from "./inventory/csv";
import { useIdentity, type MergeSuggestionDetail } from "./inventory/identity";
import { isDensity, isStringArray, PREF_KEYS, usePersistentState, type Density } from "./inventory/prefs";
import {
  buildPresets,
  EMPTY_FILTER,
  PAGE_VIEWS,
  PAGE_VIEW_BY_ID,
  useUnlinkedDevices,
  type PageViewCtx,
  type PageViewId,
  type QueryFilter,
} from "./inventory/views";

const PAGE_SIZES = [25, 50, 100, 200];

export function InventoryPanel({ snapshot }: { snapshot?: string }) {
  // -- filter state ---------------------------------------------------------
  // Held as ONE object so a saved query can replace the whole filter in a
  // single click. A preset that merged into whatever was already applied would
  // produce a result nobody could explain.
  const [filter, setFilter] = useState<QueryFilter>(EMPTY_FILTER);
  const { q, ip, ipMode, source, kind, vlan, zone } = filter;
  const dq = useDebounced(q, 300);
  const [limit, setLimit] = useState(50);
  const [offset, setOffset] = useState(0);
  const [tick, setTick] = useState(0);

  const patch = useCallback((p: Partial<QueryFilter>) => setFilter((f) => ({ ...f, ...p })), []);

  // -- payload state --------------------------------------------------------
  const [res, setRes] = useState<InventoryResponse>();
  const [err, setErr] = useState<ApiError>();
  const [loading, setLoading] = useState(true);
  const [cards, setCards] = useState<Record<string, SourceCard>>();
  const [cardsErr, setCardsErr] = useState<ApiError>();

  // The number of entities in the snapshot with NO filter applied, captured the
  // only time it can honestly be known: from a response to an unfiltered
  // request. It is what "filtered from N" is measured against, and it is simply
  // absent - rather than guessed at - if no unfiltered read has succeeded.
  const [estateTotal, setEstateTotal] = useState<number>();

  const kindKey = kind.join(" "), vlanKey = vlan.join(" "), zoneKey = zone.join(" ");
  const filtered = !!(dq.trim() || ip.trim() || source || kind.length || vlan.length || zone.length);

  // Any change to the filter invalidates the window into the result set: page 4
  // of the old query is not page 4 of the new one.
  useEffect(() => { setOffset(0); }, [dq, ip, ipMode, source, kindKey, vlanKey, zoneKey, limit]);

  useEffect(() => {
    let alive = true;
    setLoading(true);
    setErr(undefined);
    const unfiltered = !filtered;
    api
      .inventory({ snapshot, q: dq, ip, ip_mode: ipMode, source, kind, vlan, zone, limit, offset })
      .then((data) => {
        if (!alive) return;
        setRes(data);
        if (unfiltered && offset === 0) setEstateTotal(data.total);
      })
      .catch((e) => {
        if (!alive) return;
        // The previous page is NOT kept on screen under a failure: a stale table
        // beside a fresh-looking filter is the same lie as an invented zero.
        setRes(undefined);
        setErr(asApiError(e));
      })
      .finally(() => { if (alive) setLoading(false); });
    return () => { alive = false; };
    // `kind`/`vlan`/`zone` are compared by their joined keys so a new array with
    // the same contents does not re-fetch.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [snapshot, dq, ip, ipMode, source, kindKey, vlanKey, zoneKey, limit, offset, tick]);

  useEffect(() => {
    let alive = true;
    setCardsErr(undefined);
    api
      .sources(snapshot)
      .then((s) => { if (alive) setCards(Object.fromEntries(s.sources.map((c) => [c.tool, c]))); })
      .catch((e) => {
        // Not fatal to the screen - tier is on every observation regardless -
        // but it IS rendered, because an unread register must not degrade into
        // badges that quietly read as live connectors.
        if (alive) { setCards(undefined); setCardsErr(asApiError(e)); }
      });
    return () => { alive = false; };
  }, [snapshot, tick]);

  const reload = useCallback(() => setTick((t) => t + 1), []);
  const clearAll = useCallback(() => { setFilter(EMPTY_FILTER); setOffset(0); }, []);
  const toggleFacet = useCallback((group: FacetGroup, value: string) => {
    setFilter((f) => {
      const prev = f[group];
      return { ...f, [group]: prev.includes(value) ? prev.filter((v) => v !== value) : [...prev, value] };
    });
  }, []);

  // -- the asset layer, joined onto the rows --------------------------------
  const identity = useIdentity(snapshot, reload);
  const identityUnknown = !!identity.assetsError;

  // -- table preferences ----------------------------------------------------
  const [columnIds, setColumnIds, resetColumns] = usePersistentState<string[]>(
    PREF_KEYS.columns,
    DEFAULT_COLUMN_IDS,
    isStringArray,
  );
  const [density, setDensity] = usePersistentState<Density>(PREF_KEYS.density, "comfortable", isDensity);
  const columns = useMemo(() => resolveColumns(columnIds), [columnIds]);

  // -- drawer ---------------------------------------------------------------
  const [open, setOpen] = useState<{ item: InventoryItem; focus: DrawerFocus }>();
  const openRow = useCallback((item: InventoryItem, focus: DrawerFocus) => setOpen({ item, focus }), []);

  const ctx: CellCtx = useMemo(
    () => ({ cards, identity: identity.lookup, identityUnknown, onOpen: openRow }),
    [cards, identity.lookup, identityUnknown, openRow],
  );

  const items = useMemo(() => res?.items ?? [], [res]);

  // -- page views (client-side, over the loaded page) -----------------------
  const [view, setView] = useState<PageViewId>();
  const unlinked = useUnlinkedDevices(view === "unlinked", snapshot);
  const viewCtx: PageViewCtx = useMemo(
    () => ({ identity: identity.lookup, identityUnknown, unlinked: unlinked.keys }),
    [identity.lookup, identityUnknown, unlinked.keys],
  );

  const viewCounts = useMemo(() => {
    const out: Partial<Record<PageViewId, number | undefined>> = {};
    for (const v of PAGE_VIEWS) {
      if (v.needs === "identity" && identityUnknown) { out[v.id] = undefined; continue; }
      if (v.needs === "topology" && unlinked.keys === undefined) { out[v.id] = undefined; continue; }
      out[v.id] = items.filter((i) => v.test(i, viewCtx)).length;
    }
    return out;
  }, [items, viewCtx, identityUnknown, unlinked.keys]);

  const viewedItems = useMemo(() => {
    if (!view) return items;
    const spec = PAGE_VIEW_BY_ID[view];
    if (!spec) return items;
    return items.filter((i) => spec.test(i, viewCtx));
  }, [items, view, viewCtx]);

  // -- selection ------------------------------------------------------------
  // Cleared whenever the window into the result set moves. "Selected" must never
  // mean rows that are no longer loaded: a bulk action applied to something the
  // operator cannot see is the worst kind of surprise.
  const [selected, setSelected] = useState<Set<string>>(new Set());
  useEffect(() => { setSelected(new Set()); }, [snapshot, dq, ip, ipMode, source, kindKey, vlanKey, zoneKey, limit, offset, tick]);

  const toggleRow = useCallback((key: string) => {
    setSelected((prev) => {
      const next = new Set(prev);
      if (next.has(key)) next.delete(key);
      else next.add(key);
      return next;
    });
  }, []);
  const toggleAll = useCallback((keys: string[], on: boolean) => {
    setSelected((prev) => {
      const next = new Set(prev);
      for (const k of keys) { if (on) next.add(k); else next.delete(k); }
      return next;
    });
  }, []);

  // -- export ---------------------------------------------------------------
  // The order the table is actually showing, published up from it so the file
  // matches the screen rather than a re-derived order that could differ.
  const [ordered, setOrdered] = useState<InventoryItem[]>([]);
  const [receipt, setReceipt] = useState<ExportReceipt>();

  const runExport = useCallback(
    (rows: InventoryItem[], scope: string, stem: string) => {
      const header = columns.map((c) => c.label);
      const body = rows.map((item) => columns.map((c) => c.csv(item, ctx)));
      const filename = csvFilename(stem, snapshot);
      const ok = downloadCsv(filename, toCsv([header, ...body]));
      setReceipt({
        ok,
        rows: rows.length,
        loaded: items.length,
        total: res?.total,
        columns: columns.length,
        registerColumns: INVENTORY_COLUMNS.length,
        scope,
        filename: ok ? filename : undefined,
      });
    },
    [columns, ctx, items.length, res?.total, snapshot],
  );

  const exportView = useCallback(() => {
    const rows = ordered.length ? ordered : viewedItems;
    runExport(
      rows,
      view ? `the ${rows.length} rows the "${PAGE_VIEW_BY_ID[view]?.label ?? view}" page view shows` : "the rows loaded on this page",
      "inventory",
    );
  }, [ordered, viewedItems, view, runExport]);

  const exportSelected = useCallback(() => {
    const rows = (ordered.length ? ordered : viewedItems).filter((i) => selected.has(i.key));
    runExport(rows, "the current selection", "inventory-selected");
  }, [ordered, viewedItems, selected, runExport]);

  // The distinct proposals the selection resolves to. An action with nothing
  // behind it is never offered, so this list being empty hides the button.
  const pendingMerges: MergeSuggestionDetail[] = useMemo(() => {
    if (identityUnknown) return [];
    const seen = new Set<string>();
    const out: MergeSuggestionDetail[] = [];
    for (const item of items) {
      if (!selected.has(item.key)) continue;
      for (const s of identity.lookup(item)?.suggestions ?? []) {
        const pair = `${s.a}~${s.b}`;
        if (seen.has(pair)) continue;
        seen.add(pair);
        out.push(s);
      }
    }
    return out;
  }, [items, selected, identity, identityUnknown]);

  // -- readouts -------------------------------------------------------------
  const shownFrom = items.length ? offset + 1 : 0;
  const shownTo = offset + items.length;
  const remaining = res ? Math.max(0, res.total - shownTo) : 0;

  const summary = useMemo(() => {
    if (!res) return null;
    const noun = filtered ? (res.total === 1 ? "match" : "matches") : res.total === 1 ? "entity" : "entities";
    const head = items.length
      ? `showing ${shownFrom.toLocaleString()}-${shownTo.toLocaleString()} of ${res.total.toLocaleString()} ${noun}`
      : `showing 0 of ${res.total.toLocaleString()} ${noun}`;
    return (
      <span className="mono tabular-nums">
        {head}
        {filtered && estateTotal !== undefined ? (
          <span className="text-text3"> &middot; filtered from {estateTotal.toLocaleString()}</span>
        ) : null}
      </span>
    );
  }, [res, filtered, items.length, shownFrom, shownTo, estateTotal]);

  const presets = useMemo(() => buildPresets(res?.facets), [res?.facets]);

  return (
    <div className="min-w-0 space-y-4">
      {/* The figure row is rendered ONLY from a payload that arrived. A readout
          computed from a failure is the one thing this screen must never do. */}
      {err ? null : <CountsReadout counts={res?.counts} loading={loading && !res} />}

      <Panel
        title="Inventory"
        actions={
          <>
            {loading && res ? <Chip variant="neutral" pulse>updating</Chip> : null}
            <button type="button" onClick={reload} className="btn-ghost !h-7 !px-2 text-[11.5px]" title="Re-read the inventory">
              <RotateCw size={12} /> Refresh
            </button>
          </>
        }
        noPadding
      >
        <div className="min-w-0 space-y-3 p-3 sm:p-4">
          <p className="text-[12px] leading-relaxed text-text2">
            Every device, VLAN, subnet, circuit and asset the onboarded consoles reported.
            <span className="font-bold text-text"> Source(s)</span> lists every console that saw a row, with its tier.
          </p>

          {cardsErr ? (
            <InlineError resource="the source register (live vs seeded)" error={cardsErr} onRetry={reload} />
          ) : null}

          {identity.assetsError ? (
            <InlineError
              resource="the asset layer (cross-tool identity)"
              error={identity.assetsError}
              onRetry={() => identity.reload(false)}
            />
          ) : null}

          {err ? (
            <>
              <ErrorState resource="the estate inventory" error={err} onRetry={reload} />
              {filtered ? (
                <p className="text-[11.5px] text-text2">
                  A filter was applied to this request.{" "}
                  <button type="button" onClick={clearAll} className="font-bold underline underline-offset-2">
                    Clear every filter
                  </button>{" "}
                  and retry &mdash; the unfiltered read is the simplest one for the API to answer.
                </p>
              ) : null}
            </>
          ) : (
            <>
              <Presets
                presets={presets}
                current={filter}
                onApply={(f) => { setFilter(f); setOffset(0); setView(undefined); }}
                views={viewCounts}
                activeView={view}
                onView={setView}
                viewCtx={viewCtx}
                unlinked={unlinked}
                loadedRows={items.length}
                filtered={filtered}
              />

              <InventoryFilters
                facets={res?.facets}
                cards={cards}
                q={q}
                onQ={(v) => patch({ q: v })}
                ip={ip}
                ipMode={ipMode}
                onIp={(nextIp, nextMode) => patch({ ip: nextIp, ipMode: nextMode })}
                source={source}
                onSource={(v) => patch({ source: v })}
                selected={{ kind, vlan, zone }}
                onToggleFacet={toggleFacet}
                onClearAll={clearAll}
                summary={summary}
              />

              <div className="flex flex-wrap items-center gap-2">
                {/* Deliberately the PAGE's arithmetic, not the estate's — the
                    estate figure is on the filter bar above, and repeating it
                    here beside a local control is how the two get confused. */}
                <span className="text-[11.5px] text-faint">
                  <span className="tnum font-mono">{items.length.toLocaleString("en-GB")}</span>{" "}
                  {items.length === 1 ? "row" : "rows"} loaded
                  {view ? (
                    <>
                      {" "}&middot; <span className="tnum font-mono">{viewedItems.length.toLocaleString("en-GB")}</span> shown
                      by the page view
                    </>
                  ) : null}
                  {selected.size ? (
                    <>
                      {" "}&middot; <span className="tnum font-mono text-fg">{selected.size.toLocaleString("en-GB")}</span>{" "}
                      selected
                    </>
                  ) : null}
                </span>
                <div className="ml-auto flex flex-wrap items-center gap-2">
                  <DensityToggle value={density} onChange={setDensity} />
                  <ColumnMenu visible={columnIds} onChange={setColumnIds} onReset={resetColumns} />
                  <ExportButton
                    label="Export CSV"
                    disabled={viewedItems.length === 0}
                    onExport={exportView}
                    title="Write the rows this table is showing, in the columns it is showing, to a CSV. Client-side, from the rows already loaded — the receipt says how many matched but were not."
                  />
                </div>
              </div>

              {receipt ? <ExportReceiptNote receipt={receipt} onDismiss={() => setReceipt(undefined)} /> : null}

              <SelectionBar
                count={selected.size}
                onClear={() => setSelected(new Set())}
                onExport={exportSelected}
                pendingMerges={pendingMerges}
                isLive={!snapshot}
                onConfirmMerge={identity.confirmMerge}
                onMerged={() => setSelected(new Set())}
              />

              {!loading && res && items.length === 0 ? (
                <div className="border border-border">
                  {filtered ? (
                    <EmptyState
                      icon={ScanSearch}
                      title="No entity matches this filter"
                      sub="The read succeeded and returned nothing for these terms. Widen the address mode, or clear a facet."
                    />
                  ) : (
                    <EmptyState
                      icon={PackageSearch}
                      title="No entities in this snapshot"
                      sub="The read succeeded and no onboarded source contributed an entity. This is an empty inventory, not a failed one."
                    />
                  )}
                  {filtered ? (
                    <div className="border-t border-hair px-3 py-2 text-center">
                      <button type="button" onClick={clearAll} className="btn-ghost !h-7 text-[11.5px]">Clear every filter</button>
                    </div>
                  ) : null}
                </div>
              ) : !loading && view && viewedItems.length === 0 ? (
                /* The page view emptied the table, and that is a statement about
                   THIS PAGE only — never about the snapshot. */
                <div className="border border-border">
                  <EmptyState
                    icon={ScanSearch}
                    title={`No row on this page matches the "${PAGE_VIEW_BY_ID[view]?.label ?? view}" view`}
                    sub={`${items.length.toLocaleString()} rows are loaded and none of them matches. This narrows the loaded page, not the snapshot — page on, raise the page size, or clear the view.`}
                  />
                  <div className="border-t border-hair px-3 py-2 text-center">
                    <button type="button" onClick={() => setView(undefined)} className="btn-ghost !h-7 text-[11.5px]">
                      Show all loaded rows
                    </button>
                  </div>
                </div>
              ) : (
                <InventoryTable
                  items={viewedItems}
                  columns={columns}
                  ctx={ctx}
                  density={density}
                  loading={loading}
                  hasMore={!!res?.has_more}
                  selected={selected}
                  onToggleRow={toggleRow}
                  onToggleAll={toggleAll}
                  onOrderChange={setOrdered}
                />
              )}

              {res?.has_more ? (
                <div className="flex flex-wrap items-center gap-x-2 gap-y-1 border border-sev-medium-line bg-sev-medium-bg px-3 py-2 text-[11.5px] text-sev-medium">
                  <span className="font-bold">This table is one page, not the whole result.</span>
                  <span className="text-text2">
                    {remaining.toLocaleString()} more {remaining === 1 ? "entity matches" : "entities match"} and{" "}
                    {remaining === 1 ? "is" : "are"} not loaded. Page on, raise the page size, or narrow the filter.
                  </span>
                </div>
              ) : null}

              <Pager
                offset={offset}
                limit={limit}
                count={items.length}
                total={res?.total}
                hasMore={!!res?.has_more}
                loading={loading}
                onLimit={setLimit}
                onOffset={setOffset}
              />

              <TierLegend />
            </>
          )}
        </div>
      </Panel>

      {/* The absorbed screen. A section of the inventory, not a sibling of it -
          it is the same estate, and the settled half of it is already on the
          rows above. */}
      <IdentityReview
        identity={identity}
        snapshot={snapshot}
        onShowDuplicates={() => setView("merged")}
      />

      <InventoryDrawer
        item={open?.item}
        focus={open?.focus ?? "top"}
        cards={cards}
        cardsUnknown={!!cardsErr}
        identity={open ? identity.lookup(open.item) : undefined}
        identityUnknown={identityUnknown}
        snapshot={snapshot}
        onClose={() => setOpen(undefined)}
      />
    </div>
  );
}

// -- Paging -----------------------------------------------------------------

function Pager({ offset, limit, count, total, hasMore, loading, onLimit, onOffset }: {
  offset: number;
  limit: number;
  count: number;
  total?: number;
  hasMore: boolean;
  loading: boolean;
  onLimit: (n: number) => void;
  onOffset: (n: number) => void;
}) {
  const page = Math.floor(offset / limit) + 1;
  const pages = total !== undefined && limit > 0 ? Math.max(1, Math.ceil(total / limit)) : undefined;
  return (
    <div className="flex flex-wrap items-center gap-2 text-[11.5px] text-text2">
      <button
        type="button"
        className="btn-ghost !h-7 !px-2.5 text-[11.5px]"
        disabled={offset === 0 || loading}
        onClick={() => onOffset(Math.max(0, offset - limit))}
      >
        Previous
      </button>
      <button
        type="button"
        className="btn-ghost !h-7 !px-2.5 text-[11.5px]"
        disabled={!hasMore || loading}
        onClick={() => onOffset(offset + limit)}
      >
        Next
      </button>
      <span className="mono tabular-nums text-text3">
        page {page}{pages !== undefined ? ` of ${pages}` : ""}
        {total === undefined ? "" : ` (${count.toLocaleString()} rows loaded)`}
      </span>
      <label className="ml-auto flex items-center gap-1.5 text-text3">
        rows per page
        <select
          value={limit}
          onChange={(e) => onLimit(Number(e.target.value))}
          className="field !h-7 w-auto text-[11.5px]"
          aria-label="Rows per page"
        >
          {PAGE_SIZES.map((n) => <option key={n} value={n}>{n}</option>)}
        </select>
      </label>
    </div>
  );
}

// -- Legend -----------------------------------------------------------------

/** The tier codes on every source badge, spelled out once. A three-letter code
 *  nobody can expand is decoration; this is the ladder the whole provenance
 *  claim rests on. */
function TierLegend() {
  return (
    <div className="flex flex-wrap items-center gap-x-4 gap-y-1 border-t border-hair pt-2 text-[11px] text-text3">
      <span className="font-bold uppercase tracking-[0.12em]">Source tiers</span>
      {(Object.keys(TIER_SHORT) as (keyof typeof TIER_SHORT)[]).map((t) => (
        <span key={t} className="inline-flex cursor-help items-center gap-1.5" title={TIER_MEANING[t]}>
          <span className="chip mono !h-[17px] text-[9.5px]">{TIER_SHORT[t]}</span>
          <span>{t.replace("_", " ")}</span>
        </span>
      ))}
      <span>Higher on the ladder is further from the box.</span>
    </div>
  );
}

// -- Utilities --------------------------------------------------------------

/** Hold a value still until it stops changing. The free-text box is a real
 *  server query, not a local filter, so it is not fired per keystroke. */
function useDebounced<T>(value: T, ms: number): T {
  const [held, setHeld] = useState(value);
  const timer = useRef<ReturnType<typeof setTimeout>>();
  useEffect(() => {
    timer.current = setTimeout(() => setHeld(value), ms);
    return () => clearTimeout(timer.current);
  }, [value, ms]);
  return held;
}

export default InventoryPanel;
