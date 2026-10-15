"use client";

/**
 * DIRECTION, IN COLOUR — and never in colour alone.
 *
 * "0.0.0.0/0 reaches the PCI database" and "the PCI database reaches the
 * internet" are different problems with different fixes, and a source/
 * destination column pair makes a reader work that out for themselves. The
 * engine already decided (`direction.flow`), so the screen states it.
 *
 * THREE CHANNELS, ALWAYS: a severity token for colour, a distinct glyph, and
 * the word itself. The console is theme-aware and read by people who may not
 * separate orange from red, so the word is not optional decoration — it is the
 * channel that always works. Colours come from globals.css severity tokens; no
 * hex is written here.
 *
 * BIDIRECTIONAL IS NOT A FIFTH COLOUR. It is an orthogonal fact about the same
 * grant, so it gets an orthogonal treatment: a dashed hairline chip carrying the
 * REVERSE RULE'S REFERENCE. A fix that removes one direction and leaves the
 * other is the exact mistake this is here to prevent, so the thing the reviewer
 * must also act on is named rather than implied by a boolean.
 */

import { ArrowLeftRight, ArrowRight, ArrowRightFromLine, ArrowRightToLine, Globe } from "lucide-react";
import type { RuleDirection, RuleFlow } from "@/lib/api";
import { cn } from "@/lib/cn";

type FlowStyle = {
  label: string;
  /** Static class strings: Tailwind cannot see a `sev-${flow}` built at runtime. */
  chip: string;
  swatch: string;
  text: string;
  Icon: typeof ArrowRight;
  /** Said on hover, and in the panel as running text. */
  meaning: string;
  /** The legend line — the same fact, short enough to sit on one row. */
  short: string;
};

export const FLOW: Record<RuleFlow, FlowStyle> = {
  inbound: {
    label: "inbound",
    short: "public space → inside the estate",
    chip: "border-err-line bg-err-bg text-err",
    swatch: "bg-err",
    text: "text-err",
    Icon: ArrowRightToLine,
    meaning: "Ingress — public space reaches an asset inside the estate.",
  },
  outbound: {
    label: "outbound",
    short: "inside the estate → public space",
    chip: "border-warn-line bg-warn-bg text-warn",
    swatch: "bg-warn",
    text: "text-warn",
    Icon: ArrowRightFromLine,
    meaning: "Egress — an asset inside the estate reaches public space.",
  },
  transit: {
    label: "transit",
    short: "public on both sides",
    chip: "border-run-line bg-run-bg text-run",
    swatch: "bg-run",
    text: "text-run",
    Icon: Globe,
    meaning: "Public space on both sides — the grant never enters the estate.",
  },
  internal: {
    label: "internal",
    short: "east-west, both ends inside",
    chip: "border-queue-line bg-queue-bg text-queue",
    swatch: "bg-queue",
    text: "text-queue",
    Icon: ArrowRight,
    meaning: "East-west — both ends are inside the estate.",
  },
};

/** An API that grew a fifth flow must not render as one of the four we know. */
export function flowStyle(flow: string): FlowStyle | undefined {
  return FLOW[flow as RuleFlow];
}

export function DirectionChip({ direction, size = "md", refId, className }: {
  direction: RuleDirection;
  size?: "sm" | "md";
  /** The rule this chip speaks for. Named in the tooltip because a finding
   *  cites several references and the chip can only describe one of them. */
  refId?: string;
  className?: string;
}) {
  const s = flowStyle(direction.flow);
  if (!s) {
    return (
      <span
        title={`The API reported flow "${direction.flow}", which this build does not know. Shown as itself rather than mapped onto a colour it may not mean.`}
        className={cn("mono inline-flex items-center gap-1.5 border border-borderStrong bg-sunk px-1.5 font-bold text-text2",
          size === "sm" ? "h-[18px] text-[9.5px]" : "h-[22px] text-[10.5px]", className)}
      >
        {direction.flow}
      </span>
    );
  }
  const { Icon } = s;
  return (
    <span
      title={`${refId ? `${refId}: ` : ""}${s.label} — ${direction.detail}. ${s.meaning}`}
      className={cn("inline-flex items-center gap-1.5 border px-1.5 font-bold uppercase tracking-[0.08em]",
        s.chip, size === "sm" ? "h-[18px] text-[9.5px]" : "h-[22px] text-[10.5px]", className)}
    >
      <Icon size={size === "sm" ? 10 : 12} className="shrink-0" />
      {s.label}
    </span>
  );
}

/**
 * The two-way marker. Deliberately styled unlike the flow chips — dashed,
 * neutral — so it reads as a second fact about the grant rather than as a fifth
 * direction. `reverse_ref` is rendered by the caller (it needs the expandable
 * token, which would be a circular import from here).
 */
export function TwoWayChip({ size = "md", className }: { size?: "sm" | "md"; className?: string }) {
  return (
    <span
      title="A reverse grant of the same service exists, so this pair is two-way. Removing only this rule leaves the other direction open."
      className={cn("inline-flex items-center gap-1.5 border border-dashed border-borderStrong bg-sunk px-1.5 font-bold uppercase tracking-[0.08em] text-text2",
        size === "sm" ? "h-[18px] text-[9.5px]" : "h-[22px] text-[10.5px]", className)}
    >
      <ArrowLeftRight size={size === "sm" ? 10 : 12} className="shrink-0" />
      two-way
    </span>
  );
}

/** One-way is stated too, not left as the absence of the two-way chip: a
 *  reviewer scanning for "which of these is reversible" needs both answers to
 *  be present, or a missing chip reads as a field that failed to render. */
export function OneWayChip({ size = "md", className }: { size?: "sm" | "md"; className?: string }) {
  return (
    <span
      title="No reverse grant of this service exists in the snapshot, so traffic is permitted in one direction only."
      className={cn("inline-flex items-center gap-1.5 border border-border bg-sunk px-1.5 font-bold uppercase tracking-[0.08em] text-text3",
        size === "sm" ? "h-[18px] text-[9.5px]" : "h-[22px] text-[10.5px]", className)}
    >
      <ArrowRight size={size === "sm" ? 10 : 12} className="shrink-0" />
      one-way
    </span>
  );
}

/** The arrow between the two endpoints of a flow line. Carries the direction's
 *  colour so the line itself reads without reaching the chip, and becomes a
 *  double-headed arrow when the pair is two-way. */
export function FlowArrow({ direction, className }: { direction: RuleDirection; className?: string }) {
  const s = flowStyle(direction.flow);
  const Icon = direction.bidirectional ? ArrowLeftRight : (s?.Icon ?? ArrowRight);
  return (
    <span className={cn("inline-flex shrink-0 items-center", className)}
      title={direction.bidirectional ? "Two-way: a reverse grant of the same service exists." : direction.detail}>
      <span aria-hidden className={cn("h-px w-7", s ? s.swatch : "bg-borderStrong")} />
      <Icon size={13} className={cn("-ml-px shrink-0", s ? s.text : "text-text3")} />
    </span>
  );
}

/** The screen's colour key. Shown once, near the rules it explains, so a reader
 *  never has to infer what orange meant. */
export function DirectionLegend({ className }: { className?: string }) {
  return (
    <div className={cn("flex flex-wrap items-center gap-x-3 gap-y-1.5", className)}>
      {(Object.keys(FLOW) as RuleFlow[]).map((f) => (
        <span key={f} className="inline-flex items-center gap-1.5 text-[10.5px] text-text3">
          <DirectionChip size="sm" direction={{ flow: f, detail: FLOW[f].meaning, bidirectional: false, reverse_ref: null }} />
          {FLOW[f].short}
        </span>
      ))}
      <span className="inline-flex items-center gap-1.5 text-[10.5px] text-text3">
        <TwoWayChip size="sm" /> a reverse grant exists
      </span>
    </div>
  );
}
