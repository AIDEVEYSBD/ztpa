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
 *     complete one, and the number a reviewer quotes off it would be wrong.
 *   - Filtering and paging are the SERVER's, so `total` and the rows on screen
 *     answer the same question. Only sorting is local, and the table says so.
 *   - Whether a source is a live connector or a seeded export comes from the
 *     source register; when that register cannot be read, this screen says the
 *     origin is unknown rather than letting the badges imply "live".
 */

import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { PackageSearch, RotateCw, ScanSearch } from "lucide-react";
import { api, asApiError, type ApiError, type IpFilterMode } from "@/lib/api";
import type { InventoryItem, InventoryResponse, SourceCard } from "@/lib/types";
import { Chip, EmptyState, Panel } from "./ui";
import { ErrorState, InlineError } from "./ui/Feedback";
import { CountsReadout } from "./inventory/CountsReadout";
import { InventoryFilters, type FacetGroup } from "./inventory/InventoryFilters";
import { InventoryTable, type DrawerFocus } from "./inventory/InventoryTable";
import { InventoryDrawer } from "./inventory/InventoryDrawer";
import { TIER_MEANING, TIER_SHORT } from "./inventory/bits";

const PAGE_SIZES = [25, 50, 100, 200];

export function InventoryPanel({ snapshot }: { snapshot?: string }) {
  // -- filter state ---------------------------------------------------------
  const [q, setQ] = useState("");
  const dq = useDebounced(q, 300);
  const [ip, setIp] = useState("");
  const [ipMode, setIpMode] = useState<IpFilterMode>("intersects");
  const [source, setSource] = useState("");
  const [kind, setKind] = useState<string[]>([]);
  const [vlan, setVlan] = useState<string[]>([]);
  const [zone, setZone] = useState<string[]>([]);
  const [limit, setLimit] = useState(50);
  const [offset, setOffset] = useState(0);
  const [tick, setTick] = useState(0);

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
  const clearAll = useCallback(() => {
    setQ(""); setIp(""); setSource(""); setKind([]); setVlan([]); setZone([]); setOffset(0);
  }, []);
  const toggleFacet = useCallback((group: FacetGroup, value: string) => {
    const set = group === "kind" ? setKind : group === "vlan" ? setVlan : setZone;
    set((prev) => (prev.includes(value) ? prev.filter((v) => v !== value) : [...prev, value]));
  }, []);

  // -- drawer ---------------------------------------------------------------
  const [open, setOpen] = useState<{ item: InventoryItem; focus: DrawerFocus }>();
  const openRow = useCallback((item: InventoryItem, focus: DrawerFocus) => setOpen({ item, focus }), []);

  const items = res?.items ?? [];
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

  return (
    <div className="space-y-4">
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
        <div className="space-y-3 p-4">
          <p className="text-[12px] leading-relaxed text-text2">
            Every entity the onboarded sources reported, what kind it is, and where we found it. The
            <span className="font-bold text-text"> Source(s)</span> column lists every console that saw a row &mdash; not the
            one that won &mdash; each with the tier its claim came from.
          </p>

          {cardsErr ? (
            <InlineError resource="the source register (live vs seeded)" error={cardsErr} onRetry={reload} />
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
              <InventoryFilters
                facets={res?.facets}
                cards={cards}
                q={q}
                onQ={setQ}
                ip={ip}
                ipMode={ipMode}
                onIp={(nextIp, nextMode) => { setIp(nextIp); setIpMode(nextMode); }}
                source={source}
                onSource={setSource}
                selected={{ kind, vlan, zone }}
                onToggleFacet={toggleFacet}
                onClearAll={clearAll}
                summary={summary}
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
              ) : (
                <InventoryTable
                  items={items}
                  cards={cards}
                  loading={loading}
                  hasMore={!!res?.has_more}
                  onOpen={openRow}
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

      <InventoryDrawer
        item={open?.item}
        focus={open?.focus ?? "top"}
        cards={cards}
        cardsUnknown={!!cardsErr}
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
