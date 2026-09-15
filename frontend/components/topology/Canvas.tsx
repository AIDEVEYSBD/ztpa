"use client";

/**
 * The canvas itself: lane bands, links as SVG, cards as positioned elements.
 *
 * Three things here are the picture rather than decoration.
 *
 * REDUNDANCY. Links sharing a `redundant_group` are drawn in one tint with one
 * tag, so the criss-cross — two edge routers each reaching both firewalls —
 * reads as a single fact instead of four unrelated lines, and the access switch
 * with one line up reads as the exception it is. `aggregated` links carry ×N for
 * their member count, because a LAG is one failure domain and four cables, and
 * only one of those two numbers is visible in a photograph of the rack.
 *
 * EVIDENCE. `containment` is dashed and everything else is solid, because
 * containment is not a cable (see EVIDENCE_COPY in layout.ts). A weaker fact
 * that looks identical to a stronger one is the same defect as a failed fetch
 * that looks identical to an empty result.
 *
 * THE WALKTHROUGH. `focus` drives the dimming, the staged travelling dash and
 * the resilience blast. Every number behind it comes off the payload; this file
 * only decides what is lit at hop N.
 */

import { useCallback, useEffect, useRef } from "react";
import type { TopoNode } from "@/lib/types";
import { cn } from "@/lib/cn";
import { Lane } from "./Lane";
import { NodeCard, type NodeState } from "./NodeCard";
import { evidenceTier, type Layout, type PlacedLink } from "./layout";
import type { RedundancyBand, VlanBand } from "./palette";

export interface FocusView {
  /** Cards the selected finding names. */
  nodes: ReadonlySet<string>;
  /** Links already reached by the staged trace (includes the active one). */
  lit: ReadonlySet<string>;
  /** The hop currently travelling. */
  activeLink?: string;
  /** Resilience only: the device whose failure is being shown. */
  failed?: string;
  /** Resilience only: the cards revealed as isolated so far. */
  isolated: ReadonlySet<string>;
  mode: "path" | "blast";
}

export interface CanvasProps {
  layout: Layout;
  bandsFor: (node: TopoNode) => VlanBand[];
  redundancy: Map<string, RedundancyBand>;
  simulatedTools: ReadonlySet<string> | null;
  unlinked: Map<string, string>;
  focus?: FocusView | null;
  onToggleLane: (layer: string) => void;
  zoom: number;
  reduced: boolean;
  /** Reports the scroll viewport width so the caller can compute a fit zoom. */
  onViewport?: (width: number) => void;
  className?: string;
}

const HALO_W = 7;

function linkStroke(l: PlacedLink, redundancy: Map<string, RedundancyBand>): string {
  const band = l.redundantGroup ? redundancy.get(l.redundantGroup) : undefined;
  if (band) return band.tint;
  return evidenceTier(l.evidence) === "containment" ? "var(--text-3)" : "var(--border-strong)";
}

function linkTip(l: PlacedLink): string {
  const tiers = [...new Set(l.merged.map((m) => `${m.evidence}: ${m.evidence_detail}`))];
  const tools = [...new Set(l.merged.flatMap((m) => m.observed_by.map((o) => `${o.tool} (${o.tier})`)))];
  return [
    `${l.a} ↔ ${l.b}`,
    l.merged.length > 1 ? `${l.merged.length} links drawn as one line` : null,
    l.aggregated ? `aggregated: ${l.memberCount} members` : null,
    l.redundantGroup ? `redundant group: ${l.redundantGroup}` : null,
    ...tiers,
    tools.length ? `observed by: ${tools.join(", ")}` : "observed by: nothing recorded",
  ]
    .filter(Boolean)
    .join("\n");
}

export function Canvas({
  layout, bandsFor, redundancy, simulatedTools, unlinked, focus,
  onToggleLane, zoom, reduced, onViewport, className,
}: CanvasProps) {
  const scrollRef = useRef<HTMLDivElement | null>(null);
  const drag = useRef<{ x: number; y: number; sl: number; st: number } | null>(null);

  useEffect(() => {
    const el = scrollRef.current;
    if (!el || !onViewport) return;
    const report = () => onViewport(el.clientWidth);
    report();
    if (typeof ResizeObserver === "undefined") return;
    const ro = new ResizeObserver(report);
    ro.observe(el);
    return () => ro.disconnect();
  }, [onViewport]);

  // Drag-to-pan. Cheap: no state, no re-render, and it defers to the native
  // scrollbars rather than replacing them.
  const onPointerDown = useCallback((e: React.PointerEvent) => {
    const el = scrollRef.current;
    if (!el || e.button !== 0) return;
    if ((e.target as HTMLElement).closest("button, a, input")) return;
    // Mouse only. A touch drag is already a scroll gesture, and capturing it
    // here would replace the platform's kinetic scrolling with a worse one.
    if (e.pointerType !== "mouse") return;
    drag.current = { x: e.clientX, y: e.clientY, sl: el.scrollLeft, st: el.scrollTop };
    el.setPointerCapture(e.pointerId);
  }, []);
  const onPointerMove = useCallback((e: React.PointerEvent) => {
    const el = scrollRef.current;
    const d = drag.current;
    if (!el || !d) return;
    el.scrollLeft = d.sl - (e.clientX - d.x);
    el.scrollTop = d.st - (e.clientY - d.y);
  }, []);
  const endDrag = useCallback((e: React.PointerEvent) => {
    const el = scrollRef.current;
    if (el && el.hasPointerCapture(e.pointerId)) el.releasePointerCapture(e.pointerId);
    drag.current = null;
  }, []);

  const nodeState = (id: string): NodeState => {
    if (!focus) return "normal";
    if (focus.mode === "blast") {
      if (focus.failed === id) return "failed";
      if (focus.isolated.has(id)) return "isolated";
      return focus.nodes.has(id) ? "focus" : "normal";
    }
    return focus.nodes.has(id) ? "focus" : "dim";
  };

  const linkOpacity = (l: PlacedLink): number => {
    if (!focus) return 1;
    if (focus.mode === "blast") {
      const touched =
        (focus.failed && (l.a === focus.failed || l.b === focus.failed)) ||
        focus.isolated.has(l.a) || focus.isolated.has(l.b);
      return touched ? 0.12 : 1;
    }
    return focus.lit.has(l.id) ? 1 : 0.1;
  };

  return (
    <div
      ref={scrollRef}
      onPointerDown={onPointerDown}
      onPointerMove={onPointerMove}
      onPointerUp={endDrag}
      onPointerCancel={endDrag}
      className={cn("zt-scroll relative h-full w-full overflow-auto bg-sunk", className)}
    >
      <div style={{ width: layout.width * zoom, height: layout.height * zoom }} className="relative">
        <div
          style={{ width: layout.width, height: layout.height, transform: `scale(${zoom})`, transformOrigin: "top left" }}
          className="relative"
        >
          {layout.lanes.map((lane, i) => (
            <Lane
              key={`${lane.layer}:${i}`}
              lane={lane}
              width={layout.width}
              first={i === 0}
              onToggle={lane.collapsible ? () => onToggleLane(String(lane.layer)) : undefined}
            />
          ))}

          <svg
            width={layout.width}
            height={layout.height}
            className="pointer-events-none absolute left-0 top-0"
            style={{ overflow: "visible" }}
            aria-hidden
          >
            {/* HA pairs, bracketed as one unit — behind the cards they enclose. */}
            {layout.units.map((u) => (
              <rect
                key={u.key}
                x={u.x} y={u.y} width={u.w} height={u.h}
                fill="none" stroke="var(--border-strong)" strokeWidth={1}
                vectorEffect="non-scaling-stroke"
              />
            ))}

            {layout.links.map((l) => {
              const stroke = linkStroke(l, redundancy);
              const tier = evidenceTier(l.evidence);
              const lit = !!focus && focus.mode === "path" && focus.lit.has(l.id);
              const active = focus?.activeLink === l.id;
              return (
                <g key={l.id} opacity={linkOpacity(l)} className={cn(!reduced && "transition-opacity duration-300")}>
                  <title>{linkTip(l)}</title>
                  {l.redundantGroup ? (
                    <path d={l.d} fill="none" stroke={stroke} strokeWidth={HALO_W} strokeOpacity={0.16} strokeLinecap="round" />
                  ) : null}
                  <path
                    d={l.d}
                    fill="none"
                    stroke={lit ? "var(--accent)" : stroke}
                    strokeWidth={lit ? 2.4 : tier === "wire" ? 1.7 : 1.3}
                    strokeDasharray={tier === "containment" ? "5 4" : undefined}
                    strokeLinecap="round"
                    vectorEffect="non-scaling-stroke"
                  />
                  {/* The travelling dash: one hop at a time, so the path can be
                      followed rather than read all at once. Suppressed entirely
                      under prefers-reduced-motion — the hop is still staged, it
                      just arrives as a static highlight. */}
                  {active && !reduced ? (
                    <path
                      d={l.d}
                      fill="none"
                      stroke="var(--accent)"
                      strokeWidth={3}
                      strokeDasharray="10 6"
                      strokeLinecap="butt"
                      className="zt-trace-line"
                      vectorEffect="non-scaling-stroke"
                    />
                  ) : null}
                </g>
              );
            })}
          </svg>

          {/* Link tags. Positioned elements rather than SVG text so they get the
              same hairline chip treatment as everything else on the screen. */}
          {layout.links.map((l) => {
            const band = l.redundantGroup ? redundancy.get(l.redundantGroup) : undefined;
            const count = l.aggregated && l.memberCount > 1 ? `×${l.memberCount}` : l.merged.length > 1 ? `×${l.merged.length}` : "";
            if (!band && !count) return null;
            return (
              <div
                key={`tag:${l.id}`}
                className="pointer-events-none absolute z-[5] flex -translate-x-1/2 -translate-y-1/2 items-center gap-0.5 border border-border bg-surface px-1 text-[9px] font-bold leading-[13px]"
                style={{ left: l.mid.x, top: l.mid.y, opacity: linkOpacity(l) }}
              >
                {band ? <span style={{ color: band.tint }}>{band.tag}</span> : null}
                {count ? <span className="mono text-text3">{count}</span> : null}
              </div>
            );
          })}

          {/* HA bracket labels. */}
          {layout.units.map((u) => (
            <div
              key={`ha:${u.key}`}
              className="pointer-events-none absolute z-[5] border border-borderStrong bg-surface px-1 text-[9px] font-bold uppercase tracking-[0.08em] text-text3"
              style={{ left: u.x + 4, top: u.y - 7 }}
              title={`HA group ${u.group} — drawn as one unit because it fails as one.`}
            >
              HA {u.group}
            </div>
          ))}

          {layout.nodes.map((p) => (
            <NodeCard
              key={p.id}
              placed={p}
              state={nodeState(p.id)}
              bands={p.node ? bandsFor(p.node) : []}
              simulatedTools={simulatedTools}
              unlinkedReason={p.node ? unlinked.get(p.node.key) ?? p.node.unlinked_reason ?? null : null}
              onExpand={p.kind === "group" ? () => onToggleLane(String(p.layer)) : undefined}
              reduced={reduced}
            />
          ))}
        </div>
      </div>
    </div>
  );
}
