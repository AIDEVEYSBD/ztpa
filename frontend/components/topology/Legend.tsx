"use client";

/**
 * The legend — and, specifically, the one sentence that keeps this canvas
 * honest: what a dashed line means.
 *
 * `containment` links are drawn differently because they ARE different. Every
 * other line on the canvas says "a protocol or a console reported these two
 * devices as adjacent". A containment link says "two interfaces provably sit in
 * one address block" — a real L3 observation, and not a cable. Blending the two
 * would let a screen assert a physical topology built partly out of subnet
 * arithmetic, which is exactly the kind of confident-looking wrong answer this
 * product exists to stop.
 */

import { EyeOff, Unlink } from "lucide-react";
import { cn } from "@/lib/cn";
import { EVIDENCE_COPY, type EvidenceTier } from "./layout";
import { VLAN_PALETTE, type RedundancyBand, type VlanBand } from "./palette";

function LineSample({ tier, tint }: { tier: EvidenceTier; tint?: string }) {
  return (
    <svg width={40} height={10} aria-hidden className="shrink-0">
      <path
        d="M1 5H39"
        fill="none"
        stroke={tint ?? (tier === "containment" ? "var(--text-3)" : "var(--border-strong)")}
        strokeWidth={tier === "wire" ? 1.7 : 1.3}
        strokeDasharray={tier === "containment" ? "5 4" : undefined}
        strokeLinecap="round"
      />
    </svg>
  );
}

function Row({ mark, title, children }: { mark: React.ReactNode; title: string; children?: React.ReactNode }) {
  return (
    <div className="flex items-start gap-2 py-1">
      <span className="mt-0.5 flex w-10 shrink-0 justify-center">{mark}</span>
      <div className="min-w-0">
        <div className="text-[11.5px] font-bold text-text2">{title}</div>
        {children ? <div className="text-[11px] leading-snug text-text3">{children}</div> : null}
      </div>
    </div>
  );
}

function Group({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div className="min-w-0">
      <div className="label mb-1">{title}</div>
      {children}
    </div>
  );
}

export interface LegendProps {
  redundancy: RedundancyBand[];
  vlanBands: VlanBand[];
  /** True when the payload actually contains a containment link. The tier is
   *  explained either way — a reader has to know what a dashed line WOULD mean
   *  before they meet one. */
  hasContainment: boolean;
  hasAggregated: boolean;
  hasHa: boolean;
  className?: string;
}

export function Legend({ redundancy, vlanBands, hasContainment, hasAggregated, hasHa, className }: LegendProps) {
  const hatched = vlanBands.filter((b) => b.hatched);
  return (
    <div className={cn("grid gap-x-6 gap-y-4 sm:grid-cols-2 xl:grid-cols-4", className)}>
      <Group title="How we know a link exists">
        {(["wire", "stated", "containment"] as EvidenceTier[]).map((t) => (
          <Row key={t} mark={<LineSample tier={t} />} title={EVIDENCE_COPY[t].label}>
            {EVIDENCE_COPY[t].detail}
          </Row>
        ))}
        {!hasContainment ? (
          <div className="mt-1 text-[10.5px] text-text3">No containment link is on this canvas; nothing here is dashed.</div>
        ) : null}
      </Group>

      <Group title="Redundancy">
        {redundancy.length === 0 ? (
          <div className="text-[11px] text-text3">
            No link in this snapshot declares a <span className="mono">redundant_group</span>. That is the payload&rsquo;s
            claim, not a judgement about the estate: a pair of links that nothing grouped is drawn as two ordinary lines.
          </div>
        ) : (
          redundancy.map((r) => (
            <Row
              key={r.group}
              mark={<LineSample tier="wire" tint={r.tint} />}
              title={`${r.tag} · ${r.group}`}
            >
              Every line tagged {r.tag} belongs to this group. Two of them side by side is the criss-cross; one of them
              alone is a single point of failure wearing the same colour.
            </Row>
          ))
        )}
        {hasAggregated ? (
          <Row mark={<span className="mono text-[10px] font-bold text-text2">×N</span>} title="Aggregated link">
            One line, N member cables (a LAG). One failure domain, several cables — the count is on the line because a
            photograph of the rack shows the cables and not the domain.
          </Row>
        ) : null}
        {hasHa ? (
          <Row
            mark={<span className="block h-3.5 w-8 border border-borderStrong" />}
            title="HA pair, bracketed"
          >
            Two devices sharing an <span className="mono">ha_group</span>, drawn as one unit because they fail as one.
          </Row>
        ) : null}
      </Group>

      <Group title="What is not drawn">
        <Row mark={<EyeOff size={13} className="text-text3" />} title="Unobserved lane">
          A dotted strip carries the reason and the console API that would fill it. No faded device is ever drawn for a
          layer nobody observed — that would put hardware on screen that no source reported.
        </Row>
        <Row mark={<Unlink size={13} className="text-sev-high" />} title="Unlinked device">
          Inventoried, with no cable reported by anything. Drawn with a dashed border and listed on its own rail, so a box
          with no line reads as a coverage gap rather than a rendering bug.
        </Row>
        <Row mark={<span className="mono text-[9px] font-bold text-info">sim</span>} title="Seeded source">
          At least one console behind this device is a seeded export, not a live connector.
        </Row>
      </Group>

      <Group title="VLAN bands (segment lane)">
        {vlanBands.length === 0 ? (
          <div className="text-[11px] text-text3">No VLAN is declared in this snapshot.</div>
        ) : (
          <div className="flex flex-wrap gap-1">
            {vlanBands.map((b) => (
              <span
                key={b.vlan_id}
                className="inline-flex items-center gap-1 border border-border bg-sunk px-1.5 py-0.5 text-[10px] font-bold text-text2"
              >
                <span
                  className="h-2.5 w-2.5 shrink-0 border border-border"
                  style={
                    b.colour
                      ? { background: b.colour }
                      : { background: "repeating-linear-gradient(135deg, var(--text-3) 0 2px, transparent 2px 4px)" }
                  }
                />
                {b.label}
              </span>
            ))}
          </div>
        )}
        <div className="mt-1.5 text-[11px] leading-snug text-text3">
          Colour is never the only carrier: every banded card prints its VLAN and name as text.
          {hatched.length > 0
            ? ` The palette holds ${VLAN_PALETTE.length}; ${hatched.length} further VLAN${hatched.length === 1 ? " is" : "s are"} hatched and identified by label alone, because nine indistinguishable colours are not a palette.`
            : ""}
        </div>
      </Group>
    </div>
  );
}
