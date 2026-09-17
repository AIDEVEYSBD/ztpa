"use client";

/**
 * The small, shared pieces of the inventory screen.
 *
 * Everything in here exists to keep ONE rule from being re-decided per cell:
 * a value the estate never reported and a value that is genuinely empty are
 * different facts, and the screen has to render them differently. `Unreported`
 * is that rule's picture, and it is used everywhere a field is optional.
 */

import { useState, type ReactNode } from "react";
import type { Observation, SourceCard, SourceTier } from "@/lib/types";
import { cn } from "@/lib/cn";
import { ToolBadge } from "@/components/ui";

// ── The collection ladder ──────────────────────────────────────────────────
//
// `tier` is on every observation because a fact read off the box and a fact a
// cross-vendor aggregator was told are not the same quality of fact. The short
// codes are what fits in a dense table; the meanings are on every hover and in
// the legend, so the code is never the only place the distinction exists.

export const TIER_SHORT: Record<SourceTier, string> = {
  aggregator: "AGG",
  management_console: "MGMT",
  device: "DEV",
};

export const TIER_MEANING: Record<SourceTier, string> = {
  aggregator: "Aggregator — a cross-vendor tool that was TOLD about this. The weakest claim on the ladder: it can be stale without anything looking wrong.",
  management_console: "Management console — the vendor's own manager for this box.",
  device: "Device — read off the box itself. The strongest claim on the ladder.",
};

/** The short code for a tier, or the raw string when the API sends one this
 *  build does not know (which must show as itself, not as a guess). */
export function tierShort(tier: string): string {
  return TIER_SHORT[tier as SourceTier] ?? tier;
}

export function tierMeaning(tier: string): string {
  return TIER_MEANING[tier as SourceTier] ?? `Tier "${tier}" — not a tier this build of the console knows.`;
}

/**
 * A field no source reported.
 *
 * An em-dash with the reason on hover, and deliberately not an empty cell: a
 * blank reads as "nothing there", which is a claim about the estate. This is
 * "we were not told", which is a claim about our coverage.
 */
export function Unreported({ what, className }: { what: string; className?: string }) {
  return (
    <span
      className={cn("cursor-help text-text3 underline decoration-dotted decoration-from-font underline-offset-2", className)}
      title={`No onboarded source reported ${what} for this entity. Unknown, not absent.`}
      aria-label={`${what}: not reported by any source`}
    >
      —
    </span>
  );
}

/** A plain value, or `Unreported` when it is null / blank. */
export function Value({ value, what, mono, className }: { value?: string | number | null; what: string; mono?: boolean; className?: string }) {
  const empty = value === null || value === undefined || String(value).trim() === "";
  if (empty) return <Unreported what={what} />;
  return <span className={cn(mono && "mono text-[11.5px]", className)}>{String(value)}</span>;
}

// ── Provenance ─────────────────────────────────────────────────────────────

/**
 * One console that saw this row: its colour, its name, its TIER — and, when the
 * source register could be read, whether it is a live connector or a seeded
 * export.
 *
 * `card` being undefined is NOT rendered as "live". The screen says once, out
 * loud, that the register could not be read (see `ProvenanceNotice`); a badge
 * that quietly omitted the marker would be picking the flattering reading of a
 * failure, which is the one thing this product does not do.
 */
export function SourceBadge({ obs, card }: { obs: Observation; card?: SourceCard }) {
  const lines = [
    `${obs.tool} — ${tierMeaning(obs.tier)}`,
    card ? (card.simulated ? "SEEDED EXPORT: this source is a captured export, not a live connector." : "Live connector.") : "Whether this source is live or a seeded export could not be read.",
    obs.raw_ref ? `raw record: ${obs.raw_ref}` : "No raw record reference on this observation.",
  ];
  return (
    <span className="inline-flex items-center align-middle" title={lines.join("\n")}>
      <ToolBadge tool={obs.tool} detail={tierShort(obs.tier)} />
      {card?.simulated ? (
        <span className="-ml-px inline-flex h-[22px] items-center border border-sev-medium-line bg-sev-medium-bg px-1 text-[9.5px] font-bold uppercase tracking-[0.06em] text-sev-medium">
          sim
        </span>
      ) : null}
    </span>
  );
}

/** Every console that saw a row, not just the winning one — "where did we find
 *  it" has three answers for a firewall FortiManager, the FortiGate and AlgoSec
 *  all describe, and all three are shown. */
export function SourceBadges({ observed, cards, className }: {
  observed: Observation[];
  cards?: Record<string, SourceCard>;
  className?: string;
}) {
  if (!observed.length) {
    return <Unreported what="a source" className={className} />;
  }
  return (
    <span className={cn("inline-flex flex-wrap items-center gap-1", className)}>
      {observed.map((o, i) => <SourceBadge key={`${o.tool}-${o.raw_ref ?? i}`} obs={o} card={cards?.[o.tool]} />)}
    </span>
  );
}

// ── Addresses ──────────────────────────────────────────────────────────────

/**
 * The address list, truncated to `max` with a `+N` that opens in place.
 *
 * The hidden one is routinely the one that matters — a management interface on
 * a flat VLAN, a second leg into a DMZ — so `+N` is a real control, carries the
 * hidden addresses in its tooltip, and never silently drops them.
 */
export function AddressList({ addresses, max = 2, className }: { addresses: string[]; max?: number; className?: string }) {
  const [open, setOpen] = useState(false);
  if (!addresses.length) return <Unreported what="an address" className={className} />;
  const shown = open ? addresses : addresses.slice(0, max);
  const hidden = addresses.length - shown.length;
  return (
    <span className={cn("mono inline-flex flex-wrap items-center gap-x-2 gap-y-1 text-[11.5px] tabular-nums", className)}>
      {shown.map((a, i) => <span key={`${a}-${i}`} className="whitespace-nowrap">{a}</span>)}
      {hidden > 0 && (
        <button
          type="button"
          onClick={(e) => { e.stopPropagation(); setOpen(true); }}
          title={`${hidden} more on this entity: ${addresses.slice(max).join(", ")}`}
          className="border border-border bg-sunk px-1 text-[10px] font-bold leading-[15px] text-text2 transition-colors hover:border-accent hover:text-accent-fg"
        >
          +{hidden}
        </button>
      )}
      {open && addresses.length > max && (
        <button
          type="button"
          onClick={(e) => { e.stopPropagation(); setOpen(false); }}
          className="text-[10px] font-bold uppercase tracking-[0.08em] text-text3 transition-colors hover:text-accent-fg"
        >
          less
        </button>
      )}
    </span>
  );
}

// ── Drawer scaffolding ─────────────────────────────────────────────────────

/** A labelled row in the detail drawer. */
export function Field({ label, children, className }: { label: string; children: ReactNode; className?: string }) {
  return (
    <div className={cn("grid grid-cols-[112px_1fr] items-start gap-3 border-b border-hair py-1.5 last:border-0", className)}>
      <span className="text-[10px] font-bold uppercase tracking-[0.1em] text-text3">{label}</span>
      <span className="min-w-0 break-words text-[12.5px]">{children}</span>
    </div>
  );
}

/** A section heading inside the drawer. */
export function DrawerSection({ title, note, children }: { title: string; note?: string; children: ReactNode }) {
  return (
    <section className="border border-border bg-surface2">
      <header className="border-b border-hair px-3 py-2">
        <div className="text-[10px] font-bold uppercase tracking-[0.12em] text-text3">{title}</div>
        {note ? <p className="mt-1 text-[11px] leading-relaxed text-text2">{note}</p> : null}
      </header>
      <div className="px-3 py-2">{children}</div>
    </section>
  );
}

/** A claim's value, as the API sent it. Objects are printed rather than
 *  summarised — a conflict is a verbatim disagreement and paraphrasing one
 *  loses the thing the reviewer is there to compare. */
export function claimValue(v: unknown): string {
  if (v === null) return "null";
  if (v === undefined) return "(absent)";
  if (typeof v === "string") return v || '""';
  if (typeof v === "number" || typeof v === "boolean") return String(v);
  try {
    return JSON.stringify(v);
  } catch {
    return String(v);
  }
}
