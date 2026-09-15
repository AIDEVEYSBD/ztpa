"use client";

import { useCallback, useEffect, useMemo, useState } from "react";
import { CircleSlash, Info, Layers3, Plug, Radio, Unplug } from "lucide-react";
import { api, asApiError, ApiError } from "@/lib/api";
import type { SourceCard, SourceTier } from "@/lib/types";
import { toolColour } from "@/lib/toolColour";
import { useFilterSort, SearchBox } from "@/lib/tableTools";
import { Chip, Eyebrow, EmptyState, Skeleton, cn } from "./ui";
import { ErrorState } from "./ui/Feedback";
import { Prose } from "./Markdown";
import { SourceCardView } from "./sources/SourceCardView";
import { TIER_ORDER, UNKNOWN_TIER, tierMeta, tierRank } from "./sources/tiers";

type StatusFilter = "all" | "connected" | "available";
type TierFilter = SourceTier | "all";

/**
 * SOURCES — step one of the review: the inventory of intelligence.
 *
 * Four questions, in this order, because that is the order a reviewer asks
 * them: what are we reading, from which rung of the collection ladder, what did
 * it actually contribute to this snapshot — and what can it NOT tell us.
 *
 * The fourth is the one nobody builds, and it is the whole point. Every card
 * carries `blind_to` at the same weight as `yields`, because an empty access
 * lane on the topology screen means one of two completely different things
 * depending on whether anything connected here can see an access switch at all.
 *
 * Two structural rules this screen exists to keep:
 *
 *   The GROUPING is a claim. Connected sources are grouped by tier in ladder
 *   order — aggregator, then management console, then device — because the ask
 *   describes a fallback sequence, and a flat list of cards would say an estate
 *   read through three boxes directly is the same as one with an aggregator.
 *
 *   A CATALOGUE ENTRY IS NOT AN INTEGRATION. Catalogue cards carry no
 *   contribution figures at all — not zeroed ones. A "0 devices" under a source
 *   nobody connected reads as "connected, and it found nothing", which is the
 *   exact lie the rest of this product is built to refuse.
 */
export function SourcesPanel({ snapshot }: { snapshot?: string }) {
  const [cards, setCards] = useState<SourceCard[]>();
  const [loading, setLoading] = useState(true);
  const [err, setErr] = useState<ApiError>();
  const [tier, setTier] = useState<TierFilter>("all");
  const [status, setStatus] = useState<StatusFilter>("all");
  const [open, setOpen] = useState<Record<string, boolean>>({});

  const load = useCallback((withSpinner = true) => {
    let live = true;
    if (withSpinner) setLoading(true);
    setErr(undefined);
    api.sources(snapshot)
      .then((r) => {
        if (!live) return;
        // `api.sources` declares the shape; it does not verify it. A 200 that
        // is not a source list would arrive here as `undefined` and render as
        // "nothing is onboarded yet" — a confident claim about the deployment
        // made out of a response that said no such thing.
        if (!Array.isArray(r?.sources)) {
          setCards(undefined);
          setErr(new ApiError(
            200,
            "The API answered without a source list (`sources: [...]`). The frontend and backend are " +
              "probably different builds. Nothing is shown, because an empty screen here would read as " +
              "'nothing is connected', which is not what this response says.",
            "/api/sources",
          ));
          return;
        }
        setCards(r.sources);
      })
      // An empty source list out of a failed fetch would render as a product
      // with no connectors and an empty catalogue. Unknown is not none.
      .catch((e) => { if (live) { setCards(undefined); setErr(asApiError(e)); } })
      .finally(() => { if (live) setLoading(false); });
    return () => { live = false; };
  }, [snapshot]);

  useEffect(() => load(), [load]);

  const all = useMemo(() => cards ?? [], [cards]);
  const connectedAll = useMemo(() => all.filter((c) => c.connected), [all]);
  const availableAll = useMemo(() => all.filter((c) => !c.connected), [all]);

  // Search covers vendor and tool, plus the product label — "catalyst" and
  // "Cisco" have to find the same card.
  const t = useFilterSort(all, {
    search: (s) => `${s.tool} ${s.label} ${s.vendor}`,
    sorts: { label: (s) => s.label },
    initialSort: "label",
  });

  const filtered = useMemo(
    () => t.rows.filter(
      (c) => (tier === "all" || c.tier === tier) && (status === "all" || (status === "connected") === !!c.connected),
    ),
    [t.rows, tier, status],
  );
  const filtering = t.q.trim() !== "" || tier !== "all" || status !== "all";
  const clearFilters = () => { t.setQ(""); setTier("all"); setStatus("all"); };

  const connectedShown = useMemo(() => filtered.filter((c) => c.connected), [filtered]);
  const availableShown = useMemo(
    () => [...filtered.filter((c) => !c.connected)].sort(
      (a, b) => tierRank(a.tier) - tierRank(b.tier) || String(a.label ?? "").localeCompare(String(b.label ?? "")),
    ),
    [filtered],
  );
  const oddTierConnected = useMemo(
    () => connectedShown.filter((c) => !TIER_ORDER.includes(c.tier)),
    [connectedShown],
  );
  // Filtering to one rung shows that rung. The other two are not absences —
  // they were not asked about — so their headings do not appear at all.
  const rungs = useMemo(() => (tier === "all" ? TIER_ORDER : TIER_ORDER.filter((x) => x === tier)), [tier]);

  /** The registry note worth reading BEFORE the inventory: the aggregator at
   *  the top of the ladder models enforcement points and policy, not network
   *  inventory. Read off `notes` rather than written here, so it cannot drift
   *  from what the backend actually says. */
  const ladderNote = useMemo(
    () => all.find((c) => c.tool === "algosec" && c.notes) ?? all.find((c) => c.tier === "aggregator" && c.notes),
    [all],
  );

  const toggle = (tool: string) => setOpen((o) => ({ ...o, [tool]: !o[tool] }));

  // ── failure ────────────────────────────────────────────────────────────
  if (err) {
    return (
      <div className="space-y-4">
        <Header />
        <ErrorState resource="the source inventory" error={err} onRetry={() => load()} />
        <p className="text-[11.5px] text-text3">
          No source list means no catalogue either. Nothing is being shown rather than an empty screen:
          &ldquo;we could not ask&rdquo; and &ldquo;nothing is connected&rdquo; are different answers.
        </p>
      </div>
    );
  }

  // ── loading ────────────────────────────────────────────────────────────
  if (loading && !cards) {
    return (
      <div className="space-y-4">
        <div className="panel space-y-3 p-4">
          <Skeleton className="h-3 w-52" />
          <Skeleton className="h-6 w-80" />
          <Skeleton className="h-3 w-full max-w-2xl" />
        </div>
        <Skeleton className="h-3 w-40" />
        <div className="grid gap-3 md:grid-cols-2 3xl:grid-cols-3">
          {Array.from({ length: 4 }).map((_, i) => (
            <div key={i} className="panel space-y-2.5 p-4">
              <Skeleton className="h-4 w-2/3" />
              <Skeleton className="h-3 w-24" />
              <Skeleton className="h-8 w-full" />
              <div className="grid gap-2 sm:grid-cols-2">
                <Skeleton className="h-20 w-full" />
                <Skeleton className="h-20 w-full" />
              </div>
            </div>
          ))}
        </div>
      </div>
    );
  }

  // ── the API answered, with nothing in it ───────────────────────────────
  if (all.length === 0) {
    return (
      <div className="space-y-4">
        <Header />
        <div className="panel">
          <EmptyState
            icon={Plug}
            title="This build's API returned no sources at all"
            sub="Not a connected source, and not a catalogue entry either. There is nothing to read from here — which is a statement about this API build, not about the estate."
          />
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-4">
      {/* ── header strip ──────────────────────────────────────────────────── */}
      <div className="panel p-4">
        <div className="flex flex-wrap items-center gap-3">
          <Eyebrow><Radio size={13} /> Sources — inventory of intelligence</Eyebrow>
          <SearchBox value={t.q} onChange={t.setQ} placeholder="Search vendor or tool…" className="sm:ml-auto" />
        </div>

        <div className="mt-3 flex flex-wrap items-baseline gap-x-2 gap-y-1">
          <span className="mono text-[26px] font-bold leading-none tabular-nums text-text">{connectedAll.length}</span>
          <span className="text-[12.5px] font-bold text-text2">connected</span>
          <span className="text-text3">·</span>
          <span className="mono text-[26px] font-bold leading-none tabular-nums text-text2">{availableAll.length}</span>
          <span className="text-[12.5px] font-bold text-text2">available in the catalogue</span>
        </div>

        <p className="mt-2 max-w-3xl text-[12px] leading-relaxed text-text2">
          What we are reading, which rung of the collection ladder it came from, what it put into this
          snapshot — and what it cannot tell us.{" "}
          <b className="text-text">A catalogue entry is not an integration.</b>{" "}
          Catalogue sources are ones this product knows how to read: the API family, the auth model and the
          yields are described, nothing is connected, and nothing has been collected from them.
        </p>

        <div className="mt-3 flex flex-wrap items-center gap-x-4 gap-y-2 border-t border-hair pt-3">
          <Seg
            label="Rung"
            value={tier}
            onChange={setTier}
            options={[
              { key: "all", label: "All" },
              ...TIER_ORDER.map((x) => ({ key: x, label: tierMeta(x).label })),
            ]}
          />
          <Seg
            label="State"
            value={status}
            onChange={setStatus}
            options={[
              { key: "all", label: "All" },
              { key: "connected", label: "Connected" },
              { key: "available", label: "Catalogue" },
            ]}
          />
          {filtering && (
            <button type="button" onClick={clearFilters} className="btn-ghost !h-7 !px-2 text-[11px]">
              Clear filters
            </button>
          )}
        </div>
      </div>

      {/* ── connected, grouped by rung of the ladder ───────────────────────── */}
      {status !== "available" && (
        <section className="space-y-3">
          <div>
            <Eyebrow><Plug size={13} /> Connected sources</Eyebrow>
            <p className="mt-1.5 max-w-3xl text-[12px] leading-relaxed text-text2">
              Read top-down. An aggregator covers everything that was added to it; where one does not reach,
              a vendor&apos;s management console does; where that does not reach either, the device itself is
              read in its own scope. A rung with nothing on it is a coverage gap, and it is named as one.
            </p>
          </div>

          {connectedAll.length === 0 ? (
            <div className="sunk flex items-start gap-3 p-5">
              <Unplug size={18} className="mt-0.5 shrink-0 text-text3" />
              <div className="min-w-0">
                <div className="text-[13px] font-bold text-text2">Nothing is onboarded yet</div>
                <p className="mt-1 max-w-2xl text-[12px] leading-relaxed text-text3">
                  No source is connected to this deployment, so nothing has contributed anything to this
                  snapshot. That is a real state, not a failure — the catalogue below is what this product
                  knows how to read, not what it is reading. A connected source appears here on its rung of
                  the ladder: aggregator, then management console, then device.
                </p>
              </div>
            </div>
          ) : (
            <div className="space-y-4">
              {rungs.map((x) => (
                <Rung
                  key={x}
                  tier={x}
                  cards={connectedShown.filter((c) => c.tier === x)}
                  connectedHere={connectedAll.some((c) => c.tier === x)}
                  open={open}
                  onToggle={toggle}
                />
              ))}
              {tier === "all" && oddTierConnected.length > 0 && (
                <Rung
                  tier="__unknown__"
                  cards={oddTierConnected}
                  connectedHere
                  open={open}
                  onToggle={toggle}
                />
              )}
            </div>
          )}
        </section>
      )}

      {/* ── the note that has to be read before the inventory is ──────────── */}
      {ladderNote?.notes && (
        <section className="panel p-4" style={{ borderLeft: `3px solid ${toolColour(ladderNote.tool)}` }}>
          <Eyebrow><Info size={13} /> What {ladderNote.label} is, and is not</Eyebrow>
          <div className="mt-2 max-w-3xl">
            <Prose className="!text-[12.5px]">{ladderNote.notes}</Prose>
          </div>
          {(ladderNote.blind_to ?? []).length > 0 && (
            <div className="mt-2 flex flex-wrap items-center gap-1.5">
              <span className="label text-[9px]">It will not give you</span>
              {(ladderNote.blind_to ?? []).map((b) => (
                <Chip key={b} variant="neutral">{b}</Chip>
              ))}
            </div>
          )}
          <p className="mt-2 text-[11px] text-text3">
            From the source registry, verbatim — this is the expectation to set before reading the inventory,
            not after.
          </p>
        </section>
      )}

      {/* ── catalogue ──────────────────────────────────────────────────────── */}
      {status !== "connected" && (
        <section className="space-y-3">
          <div>
            <Eyebrow><Layers3 size={13} /> Available in the catalogue</Eyebrow>
            <p className="mt-1.5 max-w-3xl text-[12px] leading-relaxed text-text2">
              Sources this product knows how to read and is <b className="text-text">not</b> reading. Each card
              carries the real API family a connector would speak and the yields it would add — and no figures,
              because nothing has been collected from it.
            </p>
          </div>

          {availableAll.length === 0 ? (
            <div className="sunk p-4 text-[12px] text-text2">
              Every source in this build&apos;s registry is connected. The catalogue is empty because there is
              nothing left in it — not because there is nothing else worth reading.
            </div>
          ) : availableShown.length === 0 ? (
            <NoMatch onClear={clearFilters} what="catalogue entry" />
          ) : (
            <div className="grid gap-3 md:grid-cols-2 3xl:grid-cols-3">
              {availableShown.map((c) => (
                <SourceCardView key={c.tool} card={c} expanded={!!open[c.tool]} onToggle={() => toggle(c.tool)} />
              ))}
            </div>
          )}
        </section>
      )}
    </div>
  );
}

/** The screen's identity, kept renderable when there is no data to describe —
 *  a failure panel with no heading above it is a panel with no subject. */
function Header() {
  return (
    <div className="panel p-4">
      <Eyebrow><Radio size={13} /> Sources — inventory of intelligence</Eyebrow>
      <p className="mt-2 max-w-3xl text-[12px] leading-relaxed text-text2">
        What we are reading, which rung of the collection ladder it came from, what it put into this snapshot —
        and what it cannot tell us.
      </p>
    </div>
  );
}

/**
 * One rung of the ladder: its heading, what a fact from it is worth, and either
 * the sources connected at it or a NAMED ABSENCE saying what an empty rung
 * costs. An empty heading with nothing under it would be read as a rendering
 * bug; it is a coverage gap.
 */
function Rung({
  tier, cards, connectedHere, open, onToggle,
}: {
  tier: string;
  cards: SourceCard[];
  /** Is anything connected at this rung AT ALL, before filters? An empty rung
   *  and a filtered-out rung are different sentences. */
  connectedHere: boolean;
  open: Record<string, boolean>;
  onToggle: (tool: string) => void;
}) {
  const meta = tier === "__unknown__" ? UNKNOWN_TIER : tierMeta(tier);
  return (
    <div>
      <div className="flex flex-wrap items-baseline gap-x-3 gap-y-1 border-b border-hair pb-1.5">
        <span className="flex items-center gap-2">
          <span aria-hidden className="flex items-center gap-[2px]">
            {[1, 2, 3].map((n) => (
              <span key={n} className={cn("h-2.5 w-[3px]", n === meta.rung ? "bg-accent" : "bg-borderStrong opacity-50")} />
            ))}
          </span>
          <span className="text-[12px] font-bold uppercase tracking-[0.1em] text-text">{meta.label}</span>
          {meta.rung > 0 && <span className="mono text-[10px] text-text3">rung {meta.rung}/3</span>}
        </span>
        <span className="min-w-0 flex-1 text-[11.5px] leading-snug text-text3">{meta.blurb}</span>
      </div>

      {cards.length > 0 ? (
        <div className="mt-3 grid gap-3 md:grid-cols-2 3xl:grid-cols-3">
          {cards.map((c) => (
            <SourceCardView key={c.tool} card={c} expanded={!!open[c.tool]} onToggle={() => onToggle(c.tool)} />
          ))}
        </div>
      ) : connectedHere ? (
        // Hidden by a filter is NOT an absence, and must not be dressed as one.
        <p className="mt-3 text-[11.5px] text-text3">
          Sources are connected at this rung, and the current filter is hiding them.
        </p>
      ) : (
        <div className="mt-3 flex items-start gap-2.5 border border-dashed border-border bg-sunk p-3">
          <CircleSlash size={14} className="mt-0.5 shrink-0 text-text3" />
          <div className="min-w-0">
            <div className="text-[11.5px] font-bold text-text2">No source connected at this rung</div>
            <p className="mt-0.5 max-w-2xl text-[11.5px] leading-snug text-text3">{meta.absence}</p>
          </div>
        </div>
      )}
    </div>
  );
}

function NoMatch({ what, onClear }: { what: string; onClear: () => void }) {
  return (
    <div className="sunk flex flex-wrap items-center gap-2 p-4 text-[12px] text-text2">
      <span>No {what} matches this search or filter. The others are still there — they are filtered out, not missing.</span>
      <button type="button" onClick={onClear} className="btn-ghost !h-7 !px-2 text-[11px]">Clear filters</button>
    </div>
  );
}

/** Squared segmented control — the filter idiom for a card screen (the table
 *  screens use SortTh; there is no table here to hang a header off). */
function Seg<T extends string>({
  label, value, onChange, options,
}: {
  label: string;
  value: T;
  onChange: (v: T) => void;
  options: { key: T; label: string }[];
}) {
  return (
    <div className="flex items-center gap-2">
      <span className="label text-[9px]">{label}</span>
      <div className="flex border border-border">
        {options.map((o) => (
          <button
            key={o.key}
            type="button"
            onClick={() => onChange(o.key)}
            data-active={value === o.key}
            className={cn(
              "border-r border-border px-2 py-1 text-[11px] font-bold leading-none last:border-r-0",
              "text-text3 transition-colors hover:text-text",
              "data-[active=true]:bg-accent data-[active=true]:text-accent-ink",
            )}
          >
            {o.label}
          </button>
        ))}
      </div>
    </div>
  );
}

export default SourcesPanel;
