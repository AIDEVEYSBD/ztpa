"use client";

/**
 * The key to the diagram, inside the diagram.
 *
 * It used to be a page section under the canvas (ExplorerPanel's `Legend`
 * block), which had two problems. The small one: a reader looking at a mark had
 * to leave the picture to find out what it meant. The large one: fullscreen
 * renders the canvas into a `z-[70]` portal and marks the inline tree
 * `inert` + `aria-hidden`, so the key VANISHED in the one mode the file itself
 * calls "where this canvas is actually read". A legend that disappears when you
 * go fullscreen is not a legend.
 *
 * So it lives in the canvas's own flex cell, as a sibling of <Canvas> rather
 * than inside it -- everything absolute inside Canvas sits in the
 * `transform: scale(zoom)` content layer and would zoom and scroll with the
 * diagram. The cell is exactly the viewport, and `workbench` renders exactly
 * once at a time, so this follows the canvas into the portal with no duplicated
 * tab stops.
 *
 * EVERY MARK IS CONDITIONAL. A mark is drawn only when that mark is on THIS
 * canvas, which is the rule the structural layer already states for itself. A
 * key listing a dashed containment line over an estate with no containment
 * links teaches a distinction the reader cannot then find, and on the
 * partial-onboarding scenarios that is most of the key.
 */

import { ChevronDown, ChevronUp, EyeOff, Minus, Unlink } from "lucide-react";
import { cn } from "@/lib/cn";
import { EVIDENCE_COPY, RELATION_COPY, type EvidenceTier, type RelationLayer } from "./layout";
import type { RedundancyBand, VlanBand } from "./palette";
import { LineSample, PairSample, RelationSample } from "./Legend";

/**
 * How much of the key is showing.
 *
 *   min    a "Key" chip and nothing else, for a reader who wants the bottom-left
 *          corner of the diagram back
 *   strip  the marks, one row -- the default, because a key one click away is
 *          not embedded in the viewer
 *   open   the marks with their sentences, plus the VLAN bands
 */
export type KeyMode = "min" | "strip" | "open";

export interface CanvasKeyProps {
  mode: KeyMode;
  onMode: (m: KeyMode) => void;
  /** Evidence tiers actually drawn on this canvas. */
  tiers: EvidenceTier[];
  redundancy: RedundancyBand[];
  relations: RelationLayer | null;
  relationsVisible: boolean;
  vlanBands: VlanBand[];
  hasAggregated: boolean;
  hasHa: boolean;
  simulatedCount: number;
  unlinkedCount: number;
  /** Lanes the topology response reported as unobserved. */
  darkLanes: number;
  /** True while the reachability overlay has hops on screen. */
  showingHops: boolean;
}

function Mark({ mark, label, title }: { mark: React.ReactNode; label: string; title: string }) {
  return (
    <span className="inline-flex shrink-0 items-center gap-1.5" title={title}>
      <span className="flex items-center">{mark}</span>
      <span className="whitespace-nowrap text-[10.5px] text-text2">{label}</span>
    </span>
  );
}

function Row({ mark, label, title }: { mark: React.ReactNode; label: string; title: string }) {
  return (
    <div className="flex items-start gap-2 py-1">
      <span className="mt-[3px] flex w-10 shrink-0 justify-center">{mark}</span>
      <span className="min-w-0">
        <span className="text-[11.5px] font-bold text-text2">{label}</span>
        <span className="block text-[11px] leading-snug text-text3">{title}</span>
      </span>
    </div>
  );
}

const SIM_CHIP = (
  <span className="border border-sev-high-line bg-sev-high-bg px-1 text-[9px] font-bold uppercase text-sev-high">
    sim
  </span>
);

export function CanvasKey(props: CanvasKeyProps) {
  const {
    mode, onMode, tiers, redundancy, relations, relationsVisible, vlanBands,
    hasAggregated, hasHa, simulatedCount, unlinkedCount, darkLanes, showingHops,
  } = props;
  const open = mode === "open";

  const structural = relationsVisible && !!relations && relations.lines.length > 0;
  // One swatch per distinct tint, not per group. The canvas cycles three tints
  // across N groups, and showing a single group's tint left a reader with a
  // green pair and an amber pair no way to know the colour means "a pair"
  // rather than something about the pair.
  const tints = [...new Set(redundancy.map((r) => r.tint))];

  const marks: { key: string; mark: React.ReactNode; label: string; title: string }[] = [];
  for (const t of tiers) {
    marks.push({
      key: `tier-${t}`,
      mark: <LineSample tier={t} />,
      label: EVIDENCE_COPY[t]?.label ?? t,
      title: EVIDENCE_COPY[t]?.detail ?? t,
    });
  }
  if (structural) {
    marks.push({
      key: "structural",
      mark: <RelationSample />,
      label: "structure",
      // Deliberately the FAMILY's sentence, not any one relation's: the strip
      // shows one hairline for every structural relation on the canvas, and
      // RELATION_COPY is keyed per relation kind.
      title: "A structural fact the topology states — a circuit reaching the internet, a VLAN carried on a port. Not an adjacency, and never a cable.",
    });
  }
  if (tints.length > 0) {
    // ONE mark carrying every tint, not one mark per tint. Three entries all
    // labelled "redundant" reads as a rendering bug; the tints side by side
    // under a single label is the actual statement -- these are interchangeable
    // group colours, and the colour itself means nothing.
    marks.push({
      key: "pair",
      mark: (
        <span className="flex flex-col gap-[3px]">
          {tints.map((tint) => <PairSample key={tint} tint={tint} />)}
        </span>
      ),
      label: tints.length > 1 ? `redundant (${tints.length} groups)` : "redundant",
      title: "Two or more links between the same pair of devices. The tint separates one group from the next and means nothing on its own.",
    });
  }
  if (hasAggregated) {
    marks.push({
      key: "agg",
      mark: <span className="mono text-[10px] font-bold text-text2">&times;N</span>,
      label: "aggregated",
      title: "One line standing for N parallel links between the same pair.",
    });
  }
  if (hasHa) {
    marks.push({
      key: "ha",
      mark: <span aria-hidden className="h-3 w-5 border border-dashed border-borderStrong" />,
      label: "HA pair",
      title: "Two devices a console reported as one high-availability unit.",
    });
  }
  if (showingHops) {
    marks.push({
      key: "hop",
      mark: (
        <svg width={34} height={10} aria-hidden className="shrink-0">
          <path d="M1 5H27" fill="none" stroke="var(--accent)" strokeWidth={2.2} strokeLinecap="round" />
          <path d="M27 1.5 L33 5 L27 8.5 z" fill="var(--accent)" />
        </svg>
      ),
      label: "policy hop",
      title: "One allow rule permitting traffic from one node to the next. A grant, not a cable.",
    });
  }
  if (simulatedCount > 0) {
    marks.push({
      key: "sim",
      mark: SIM_CHIP,
      label: `${simulatedCount} simulated`,
      title: "Reported by a seeded export rather than a live connector. Nothing contacted this vendor.",
    });
  }
  if (unlinkedCount > 0) {
    marks.push({
      key: "unlinked",
      mark: <Unlink size={12} className="text-text3" />,
      label: `${unlinkedCount} unlinked`,
      title: "Inventoried, with no adjacency any onboarded source reported. A gap in what the consoles say, not in the estate.",
    });
  }
  if (darkLanes > 0) {
    marks.push({
      key: "dark",
      mark: <EyeOff size={12} className="text-text3" />,
      label: `${darkLanes} dark`,
      title: "No onboarded source reported a device at this layer. The lane names the API that would fill it.",
    });
  }

  if (marks.length === 0) return null;

  // Minimised: a chip, and nothing over the diagram. Still the same landmark
  // region, so a reader who minimised it can find it again the same way.
  if (mode === "min") {
    return (
      <aside role="region" aria-label="Canvas key" className="absolute bottom-2 left-2 z-[12]">
        <button
          type="button"
          onClick={() => onMode("strip")}
          title="Show the key to this diagram"
          className="popover flex items-center gap-1.5 px-2 py-1 text-[9px] font-bold uppercase tracking-[0.08em] text-text3 hover:text-accent-fg"
        >
          <ChevronUp size={12} /> Key
        </button>
      </aside>
    );
  }

  return (
    <aside
      role="region"
      aria-label="Canvas key"
      className={cn(
        "popover absolute bottom-2 left-2 z-[12] flex flex-col overflow-hidden",
        // z-[12] clears the canvas's own chrome (link tags z-5, hop svg z-6, hop
        // tags z-7, cards z-10) and stays UNDER the narrow-screen scrim (z-20)
        // and the node drawer (z-30), so it can never cover the drawer.
        open ? "max-h-[min(72%,420px)] w-[min(92%,330px)]" : "max-w-[min(94%,760px)]",
      )}
    >
      {/* Two buttons, not one nested in another: expand and minimise are
          different actions and a button inside a button is invalid markup. */}
      <div className="flex min-w-0 items-center">
        <button
          type="button"
          onClick={() => onMode(open ? "strip" : "open")}
          aria-expanded={open}
          className="flex min-w-0 flex-1 items-center gap-2 px-2 py-1 text-left hover:bg-surface-hover"
        >
          <span className="text-[9px] font-bold uppercase tracking-[0.08em] text-text3">Key</span>
          {!open && (
            <span className="flex min-w-0 flex-wrap items-center gap-x-2.5 gap-y-1">
              {marks.map((m) => <Mark key={m.key} mark={m.mark} label={m.label} title={m.title} />)}
            </span>
          )}
          <span className="ml-auto shrink-0 pl-1 text-text3">
            {open ? <ChevronDown size={12} /> : <ChevronUp size={12} />}
          </span>
        </button>
        <button
          type="button"
          onClick={() => onMode("min")}
          title="Minimise the key"
          aria-label="Minimise the key"
          className="shrink-0 border-l border-hair px-1.5 py-1 text-text3 hover:bg-surface-hover hover:text-accent-fg"
        >
          <Minus size={12} />
        </button>
      </div>

      {open && (
        <div className="zt-scroll min-h-0 overflow-y-auto border-t border-hair px-2 py-1">
          {marks.map((m) => <Row key={m.key} mark={m.mark} label={m.label} title={m.title} />)}
          {vlanBands.length > 0 && (
            <div className="mt-1 border-t border-hair pt-1.5">
              <div className="label mb-1 !text-text2">VLAN bands</div>
              <div className="flex flex-wrap items-center gap-x-2 gap-y-1">
                {vlanBands.map((b) => (
                  <span key={b.vlan_id} className="inline-flex items-center gap-1"
                    title={b.name ?? undefined}>
                    {/* A hatched band past the eighth is NOT given a colour here.
                        `palette.ts` stops at eight deliberately -- nine
                        indistinguishable colours is a lie about how much a
                        reader can tell apart -- and those bands are identified
                        by their label alone on the canvas. Inventing a swatch
                        for one would contradict the drawing. */}
                    <span aria-hidden
                      className={cn("h-2.5 w-2.5 shrink-0", !b.colour && "border border-borderStrong")}
                      style={b.colour ? { background: b.colour } : undefined} />
                    <span className="mono text-[10.5px] text-text2">{b.vlan_id}</span>
                  </span>
                ))}
              </div>
              {vlanBands.some((b) => !b.colour) && (
                <p className="mt-1 text-[10.5px] leading-snug text-text3">
                  Past the eighth VLAN the band is drawn unfilled and identified by its number.
                </p>
              )}
            </div>
          )}
        </div>
      )}
    </aside>
  );
}

export default CanvasKey;
