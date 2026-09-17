"use client";

import type { ReactNode } from "react";
import {
  Boxes, Cable, ChevronDown, ChevronRight, Clock, Cpu, EyeOff, FileStack, FlaskConical,
  KeyRound, Link2, ScanSearch, Server, Unplug,
} from "lucide-react";
import type { SourceCard } from "@/lib/types";
import { toolColour } from "@/lib/toolColour";
import { NetIcon } from "@/components/net/icons";
import { Chip, cn } from "@/components/ui";
import { Prose } from "@/components/Markdown";
import { tierMeta } from "./tiers";

/** Local timestamp rendering, matching admin/AuditAdmin: an unparseable value is
 *  printed verbatim rather than turned into "Invalid Date". */
function when(ts: string): string {
  const d = new Date(ts);
  return Number.isNaN(d.getTime()) ? ts : d.toLocaleString(undefined, { hour12: false });
}

type Contributed = NonNullable<SourceCard["contributed"]>;
type FigureSpec = { key: keyof Contributed; label: string; icon: ReactNode };

/** The compact row, in the order the ask reads them out. `records` is what the
 *  source handed us; the rest is what came out of it. */
const COMPACT_FIGURES: FigureSpec[] = [
  { key: "records", label: "records", icon: <FileStack size={11} /> },
  { key: "devices", label: "devices", icon: <Cpu size={11} /> },
  { key: "interfaces", label: "interfaces", icon: <Cable size={11} /> },
  { key: "vlans", label: "VLANs", icon: <NetIcon kind="vlan" size={12} /> },
  { key: "circuits", label: "circuits", icon: <NetIcon kind="circuit" size={12} /> },
];

/** The rest of the contribution, shown once a card is opened. */
const DETAIL_FIGURES: FigureSpec[] = [
  { key: "entities", label: "entities", icon: <Boxes size={11} /> },
  { key: "links", label: "links", icon: <Link2 size={11} /> },
  { key: "subnets", label: "subnets", icon: <NetIcon kind="subnet" size={12} /> },
];

/**
 * One contribution figure.
 *
 * Three states, deliberately distinguishable: a number, a zero (dimmed, and
 * labelled as a real observation — this source is connected and put none of
 * this kind into the snapshot), and an em-dash for a figure the payload does
 * not carry. The third must never render as the second; see `InventoryCounts`
 * in lib/types.ts.
 */
function Figure({ label, icon, value }: { label: string; icon: ReactNode; value: unknown }) {
  const known = typeof value === "number" && Number.isFinite(value);
  const zero = known && value === 0;
  const title = !known
    ? `This source declared no ${label} figure for this snapshot. Unknown — not zero.`
    : zero
      ? `This source contributed no ${label} to this snapshot.`
      : undefined;
  return (
    <span className="inline-flex items-center gap-1.5" title={title}>
      <span className={cn("shrink-0", zero || !known ? "text-text3" : "text-text2")}>{icon}</span>
      <span className={cn("mono text-[15px] font-bold leading-none tabular-nums", known && !zero ? "text-text" : "text-text3")}>
        {known ? String(value) : "—"}
      </span>
      {/* 11px at 0.05em, not 10px at 0.1em. Wide tracking on small uppercase is
          the thing that made this row scan as texture rather than as words. The
          dim/em-dash semantics above are untouched: `text3` still means "this
          figure is zero or unknown", it is just legible now. */}
      <span className="text-[11px] uppercase tracking-[0.05em] text-text2">{label}</span>
    </span>
  );
}

/** Where this source sits on the collection ladder: the rung, drawn, plus its
 *  name. Three squares with one filled reads at a glance in a grid of cards. */
export function TierChip({ tier }: { tier: string }) {
  const meta = tierMeta(tier);
  return (
    <span
      className="inline-flex items-center gap-1.5 whitespace-nowrap border border-border bg-sunk px-1.5 py-0.5 text-[10px] font-bold uppercase tracking-[0.08em] text-text2"
      title={`${meta.label} — rung ${meta.rung || "?"} of ${3}. ${meta.blurb}`}
    >
      <span aria-hidden className="flex items-center gap-[2px]">
        {[1, 2, 3].map((n) => (
          <span key={n} className={cn("h-[7px] w-[3px]", n === meta.rung ? "bg-accent" : "bg-borderStrong opacity-50")} />
        ))}
      </span>
      {meta.label}
    </span>
  );
}

/**
 * The yields / blind-to pair.
 *
 * Rendered as two equal columns because they are two halves of one claim. The
 * blind-to half is the reason this screen exists: it is what stops an operator
 * reading an empty access lane as an empty access layer, and it is not a
 * footnote under the capabilities.
 */
function CapabilityList({
  items, tone, expanded, countHidden,
}: { items: string[]; tone: "yields" | "blind"; expanded: boolean; countHidden: boolean }) {
  const blind = tone === "blind";
  const shown = expanded ? items : items.slice(0, 4);
  const hidden = items.length - shown.length;
  return (
    <div className="min-w-0 border border-border bg-sunk p-2.5">
      <div className="flex items-center gap-1.5">
        {blind ? <EyeOff size={11} className="text-sev-medium" /> : <ScanSearch size={11} className="text-text3" />}
        <span className={cn("text-[11px] font-bold uppercase tracking-[0.06em]", blind ? "text-sev-medium" : "text-text2")}>
          {blind ? "Blind to" : "Yields"}
        </span>
      </div>
      {items.length === 0 ? (
        <p className="mt-1.5 text-[11px] leading-snug text-text3">
          {blind
            ? "Not stated. An empty list here is a gap in the registry — it is not a source that sees everything."
            : "Not stated. This build's registry declares nothing for this source."}
        </p>
      ) : (
        <ul className="mt-1.5 space-y-1">
          {shown.map((y) => (
            <li key={y} className="flex items-start gap-1.5 text-[12px] leading-snug text-text2">
              <span
                aria-hidden
                className={cn("mt-[5px] h-[5px] w-[5px] shrink-0", blind ? "border border-sev-medium" : "bg-text3")}
              />
              <span className="min-w-0 break-words">{y}</span>
            </li>
          ))}
          {hidden > 0 && (
            <li className="text-[11px] text-text3">{countHidden ? `+${hidden} more` : "… more"}</li>
          )}
        </ul>
      )}
    </div>
  );
}

export interface SourceCardViewProps {
  card: SourceCard;
  expanded: boolean;
  onToggle: () => void;
}

/**
 * One source, connected or catalogued.
 *
 * The SAME card in both cases, at two emphases — a catalogue entry is a
 * description of a source we know how to read, not a dimmed integration. What
 * it never carries is a contribution figure: a `0 devices` under an
 * unconnected source reads as "connected, and it found nothing", which is the
 * exact lie this screen is built to refuse. So the figures are not dimmed for
 * the catalogue, they are absent.
 */
export function SourceCardView({ card, expanded, onToggle }: SourceCardViewProps) {
  const colour = toolColour(card.tool);
  const connected = !!card.connected;
  const contributed = card.contributed;

  return (
    <div
      className={cn(
        "card relative flex min-w-0 flex-col",
        connected ? "p-3.5" : "p-3",
        expanded && "border-accent",
      )}
      style={{ borderLeftWidth: connected ? 3 : 2, borderLeftColor: colour, borderLeftStyle: "solid" }}
      onClick={onToggle}
    >
      {/* ── identity ─────────────────────────────────────────────────────── */}
      <div className="flex min-w-0 items-start gap-2">
        <span aria-hidden className="mt-[3px] h-2.5 w-2.5 shrink-0" style={{ background: colour }} />
        <div className="min-w-0 flex-1">
          <div className="flex flex-wrap items-center gap-x-2 gap-y-1">
            <span className={cn("min-w-0 break-words font-bold", connected ? "text-[15px]" : "text-[14px]")}>{card.label}</span>
            <span className="text-[12.5px] text-text2">{card.vendor}</span>
          </div>
          <div className="mono mt-0.5 text-[11px] text-text3">{card.tool}</div>
        </div>
        <div className="flex shrink-0 flex-col items-end gap-1">
          <TierChip tier={card.tier} />
          <button
            type="button"
            onClick={(e) => { e.stopPropagation(); onToggle(); }}
            aria-expanded={expanded}
            className="inline-flex items-center gap-1 text-[10.5px] font-bold uppercase tracking-[0.08em] text-text3 hover:text-accent-fg"
          >
            {expanded ? <ChevronDown size={12} /> : <ChevronRight size={12} />}
            {expanded ? "less" : "detail"}
          </button>
        </div>
      </div>

      {/* ── state: connected / catalogue, and simulated either way ────────── */}
      <div className="mt-2 flex flex-wrap items-center gap-1.5">
        {connected ? (
          <Chip variant="ok" dot>connected</Chip>
        ) : (
          <Chip variant="neutral"><Unplug size={10} /> not connected</Chip>
        )}
        {connected && (
          <span className="inline-flex items-center gap-1.5 text-[11px] text-text3">
            <Clock size={11} className="shrink-0" />
            {card.last_sync ? <span className="mono">{when(card.last_sync)}</span> : <span>last sync not reported</span>}
          </span>
        )}
        {card.device && (
          <span className="mono inline-flex items-center gap-1.5 text-[10.5px] text-text3" title="The console or device a record from this source is attributed to">
            <Server size={10} className="shrink-0" />
            {card.device}
          </span>
        )}
      </div>

      {/* A seeded export is a seeded export whether or not it is wired up: the
          flag is rendered wherever it is true, at full weight, because the
          audience for this screen is the client whose estate it describes. */}
      {card.simulated && (
        <span
          className="mt-2 inline-flex w-fit items-center gap-1.5 border border-sev-high-line bg-sev-high-bg px-1.5 py-0.5 text-[11px] font-bold text-sev-high"
          title="Seeded export. Nothing contacted this vendor."
        >
          <FlaskConical size={12} className="shrink-0" />
          simulated export
        </span>
      )}

      {/* ── what it put into this snapshot (connected only) ───────────────── */}
      {connected && (
        contributed ? (
          <div className="mt-2.5 border-t border-hair pt-2.5">
            <div className="label mb-1.5 !text-text2">Contributed to this snapshot</div>
            <div className="flex flex-wrap items-center gap-x-4 gap-y-2">
              {COMPACT_FIGURES.map((f) => (
                <Figure key={f.key} label={f.label} icon={f.icon} value={contributed[f.key]} />
              ))}
              {expanded && DETAIL_FIGURES.map((f) => (
                <Figure key={f.key} label={f.label} icon={f.icon} value={contributed[f.key]} />
              ))}
            </div>
          </div>
        ) : (
          <div className="mt-2.5 border-t border-hair pt-2.5 text-[11px] leading-snug text-text3">
            This source is connected, and the API reported no contribution figures for this snapshot.
            Unknown — not zero: nothing here says it contributed nothing.
          </div>
        )
      )}

      {/* ── yields / blind to, equal weight ───────────────────────────────── */}
      <div className="mt-2.5 grid gap-2 sm:grid-cols-2">
        <CapabilityList items={card.yields ?? []} tone="yields" expanded={expanded} countHidden={connected} />
        <CapabilityList items={card.blind_to ?? []} tone="blind" expanded={expanded} countHidden={connected} />
      </div>

      {/* ── full detail ───────────────────────────────────────────────────── */}
      {expanded && (
        <div className="mt-2.5 space-y-2 border-t border-hair pt-2.5">
          <div className="sunk px-2.5 py-2">
            <div className="label !text-text2">API family</div>
            <div className="mono mt-1 break-words text-[11.5px] leading-relaxed text-text2">{card.api}</div>
          </div>
          <div className="flex flex-wrap items-start gap-x-2 gap-y-1 text-[12px] text-text2">
            <KeyRound size={12} className="mt-0.5 shrink-0 text-text3" />
            <span className="label leading-[1.6] !text-text2">Auth</span>
            <span className="mono min-w-0 break-words text-[11px]">{card.auth || "not stated"}</span>
          </div>
          {card.notes ? (
            <div>
              <div className="label mb-0.5 !text-text2">Notes</div>
              <Prose className="!text-[11.5px]">{card.notes}</Prose>
            </div>
          ) : (
            <div className="text-[11px] text-text3">No notes recorded for this source.</div>
          )}
        </div>
      )}
    </div>
  );
}

export default SourceCardView;
