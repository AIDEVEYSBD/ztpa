"use client";

/**
 * The small marks the drawer repeats, kept in one place so the vocabulary
 * cannot drift between the four sections that use it.
 *
 * Two of them carry rules rather than styling:
 *
 *   <Unknown>  is the em-dash. It is what a field renders when the payload did
 *              not carry it. It is NEVER a zero, never "none", and never blank:
 *              a blank cell reads as "nothing there", which is a claim.
 *   <SourceToolBadge> renders `simulated` whenever it KNOWS a source is a seeded
 *              export, and renders nothing at all when it does not know. There is
 *              deliberately no "live" marker — the absence of the source cards
 *              must not be able to decorate a seeded export as a real connector.
 */

import type { ReactNode } from "react";
import { ArrowRight, HelpCircle } from "lucide-react";
import type { LinkEvidence, Observation, SourceTier } from "@/lib/types";
import { Chip, ToolBadge, cn } from "@/components/ui";
import type { SourceIndex } from "./data";

/** A value the payload did not carry. The reason is on hover AND announced. */
export function Unknown({ reason }: { reason: string }) {
  return (
    <span className="mono inline-flex items-center gap-1 text-text3" title={reason}>
      <span aria-hidden>—</span>
      <span className="sr-only">not stated: {reason}</span>
      <HelpCircle size={11} aria-hidden />
    </span>
  );
}

/** A field label + value in the identity grid. */
export function Field({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="border-b border-hair py-2 last:border-0 sm:border-0 sm:py-0">
      <div className="label mb-1 !text-[9.5px]">{label}</div>
      <div className="text-[12.5px]">{children}</div>
    </div>
  );
}

/** Identifier / address / set-arithmetic mark. Mono, squared, hairline. */
export function MonoChip({
  children,
  tone = "neutral",
  title,
  className,
}: {
  children: ReactNode;
  tone?: "neutral" | "accent" | "warn" | "danger" | "ok" | "info";
  title?: string;
  className?: string;
}) {
  // The className lands on the OUTER span, because that is the flex item a
  // caller is positioning (`ml-auto` on the inner chip would do nothing).
  return (
    <span title={title} className={cn("inline-flex", className)}>
      <Chip variant={tone} mono className="!text-[10px]">
        {children}
      </Chip>
    </span>
  );
}

const TIER_LABEL: Record<SourceTier, string> = {
  aggregator: "aggregator",
  management_console: "console",
  device: "device",
};

/**
 * A source tool, with its collection tier and its simulated flag when we know
 * them. `sources` undefined means the source cards did not load — the badge then
 * says nothing about provenance rather than implying a live connector.
 */
export function SourceToolBadge({
  tool,
  detail,
  sources,
  showTier = false,
}: {
  tool: string;
  detail?: string;
  sources?: SourceIndex;
  showTier?: boolean;
}) {
  const card = sources?.byTool.get(tool);
  return (
    <span className="inline-flex flex-wrap items-center gap-1">
      <ToolBadge tool={tool} detail={detail} />
      {showTier && card ? (
        <MonoChip tone="neutral" title={`Collection tier: ${card.tier}. A fact read off the box and one read from a cross-vendor aggregator are not the same quality of fact.`}>
          {TIER_LABEL[card.tier] ?? card.tier}
        </MonoChip>
      ) : null}
      {card?.simulated ? (
        <MonoChip tone="warn" title="This source is a seeded export, not a live connector. Everything attributed to it is demonstration data.">
          simulated
        </MonoChip>
      ) : null}
      {sources && !card ? (
        /* The cards loaded and this tool is not among them, so whether it is a
           live connector or a seeded export is UNKNOWN. Silence would read as
           "live", which is the one reading that must not be available. */
        <span
          title={`No source card was returned for "${tool}", so its collection tier and whether it is a seeded export are unknown. Silence here is not a claim that it is a live connector.`}
          className="mono inline-flex h-[18px] items-center border border-dashed border-borderStrong px-1 text-[10px] font-bold leading-none text-text3"
          aria-label={`provenance unknown for ${tool}`}
        >
          ?
        </span>
      ) : null}
    </span>
  );
}

const EVIDENCE_NOTE: Record<LinkEvidence, string> = {
  lldp: "Neighbour discovery reported by the device itself.",
  cdp: "Neighbour discovery reported by the device itself.",
  api_topology: "A vendor console's own topology API stated this.",
  config: "Read out of the device configuration.",
  routing: "Derived from the routing table.",
  declared: "Declared in the source data rather than observed on the wire.",
  containment:
    "WEAKER than a cable: two interfaces provably inside one address block. That is a real layer-3 observation, and it is not evidence of a physical link.",
};

/** How a thing was observed. `containment` is drawn dashed, everywhere, because
 *  it is a different and weaker kind of fact than a reported adjacency. */
export function EvidenceChip({ evidence }: { evidence: LinkEvidence }) {
  const weak = evidence === "containment";
  return (
    <span
      title={EVIDENCE_NOTE[evidence] ?? evidence}
      className={cn(
        "mono inline-flex h-[18px] items-center border px-1.5 text-[10px] font-bold leading-none",
        weak ? "border-dashed border-sev-medium-line bg-sev-medium-bg text-sev-medium" : "border-border bg-sunk text-text2",
      )}
    >
      {evidence}
    </span>
  );
}

/** The consoles that saw a row — all of them, not just the winning one. */
export function ObservedBy({ observations, sources }: { observations: Observation[]; sources?: SourceIndex }) {
  if (observations.length === 0) {
    return <Unknown reason="this record carries no observation list, so which console saw it is not stated" />;
  }
  return (
    <span className="inline-flex flex-wrap items-center gap-1.5">
      {observations.map((o, i) => (
        <span key={`${o.tool}-${i}`} className="inline-flex flex-wrap items-center gap-1">
          <SourceToolBadge tool={o.tool} sources={sources} showTier />
          {o.evidence ? <EvidenceChip evidence={o.evidence} /> : null}
        </span>
      ))}
    </span>
  );
}

/** `source → destination`, mono, wrapping rather than truncating: a rule's ends
 *  are the reason the row is on screen and must not be elided. */
export function Flow({ from, to }: { from: string; to: string }) {
  return (
    <span className="mono inline-flex flex-wrap items-center gap-1.5 text-[11.5px]">
      <span className="break-all">{from || "—"}</span>
      <ArrowRight size={11} className="shrink-0 text-text3" aria-label="to" />
      <span className="break-all">{to || "—"}</span>
    </span>
  );
}

/** allow / deny, coloured the same way the rule popover colours it. */
export function ActionChip({ action }: { action: string }) {
  const allow = action.toLowerCase() === "allow";
  const deny = action.toLowerCase() === "deny" || action.toLowerCase() === "drop" || action.toLowerCase() === "reject";
  return (
    <span
      className={cn(
        "mono inline-flex h-[18px] shrink-0 items-center border px-1.5 text-[10px] font-bold uppercase leading-none",
        allow && "border-ok-line bg-ok-bg text-ok",
        deny && "border-sev-critical-line bg-sev-critical-bg text-sev-critical",
        !allow && !deny && "border-border bg-sunk text-text2",
      )}
    >
      {action || "?"}
    </span>
  );
}
