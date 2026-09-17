"use client";

/**
 * The canvas itself: lane bands, links as SVG, cards as positioned elements —
 * and the overlays drawn on top of them.
 *
 * Four things here are the picture rather than decoration.
 *
 * REDUNDANCY. Links sharing a `redundant_group` are drawn in one tint and each
 * one says how many paths the group holds (`2 paths`), so the criss-cross — two
 * edge routers each reaching both firewalls — reads as a single fact instead of
 * four unrelated lines, and the access switch whose single line up wears no
 * badge at all reads as the exception it is. `aggregated` links carry ×N for
 * their member count instead, because a LAG is one failure domain and four
 * cables, and only one of those two numbers is visible in a photograph of the
 * rack. The two counts are never spelled the same way: "two cables to one box"
 * and "two paths to two boxes" is the distinction this whole screen is for.
 *
 * STRUCTURE. `relations` are the facts that are not cables — a circuit
 * terminating on a CPE, the switch routing a VLAN, a host's address inside a
 * subnet. Without them the internet, circuit, segment and endpoint lanes had no
 * line to anything and the estate read as four disconnected islands. They are
 * drawn UNDER the links, as straight dotted hairlines: a third geometry, so a
 * structural fact is never mistaken for an observed adjacency even in greyscale.
 *
 * EVIDENCE. `containment` is dashed and everything else is solid, because
 * containment is not a cable (see EVIDENCE_COPY in layout.ts). A weaker fact
 * that looks identical to a stronger one is the same defect as a failed fetch
 * that looks identical to an empty result.
 *
 * THE WALKTHROUGH. `focus` drives the dimming, the staged travelling dash and
 * the resilience blast. Every number behind it comes off the payload; this file
 * only decides what is lit at hop N.
 *
 * THE CROSS-TOOL CHAIN. `path` traces a reachability path ACROSS these lanes —
 * the computation no single console can produce, drawn on the estate it runs
 * through rather than on a second graph with its own positions. Its lines are
 * deliberately unlike the cables: they bow the other way, they carry the
 * service and the tool that permits the hop, and they are numbered. A reader
 * must never be able to mistake a policy hop for a wire.
 */

import { useCallback, useEffect, useLayoutEffect, useRef } from "react";
import type { TopoNode } from "@/lib/types";
import { cn } from "@/lib/cn";
import { toolColour } from "@/lib/toolColour";
import { Lane } from "./Lane";
import { NodeCard, type NodeState } from "./NodeCard";
import { evidenceTier, type Layout, type PlacedLink, type PlacedRelation, type RelationLayer } from "./layout";
import type { PlacedPath } from "./paths";
import type { RedundancyBand, VlanBand } from "./palette";

export interface FocusView {
  /** Cards the selected finding — or the selected path — names. */
  nodes: ReadonlySet<string>;
  /** Links already reached by the staged trace (includes the active one). */
  lit: ReadonlySet<string>;
  /** The hop currently travelling. */
  activeLink?: string;
  /** Resilience only: the device(s) whose failure is being shown. A set, not
   *  one id, because a shared-carrier finding fails two CPEs at once and
   *  turning only one of them critical would draw a different failure from the
   *  one the severity was measured over. */
  failed: ReadonlySet<string>;
  /** Resilience only: the cards revealed as isolated so far. */
  isolated: ReadonlySet<string>;
  /** `path` traces this topology's own links; `reach` traces a policy chain
   *  drawn over them (so every cable is uniformly quiet); `blast` plays a
   *  failure. */
  mode: "path" | "blast" | "reach";
}

export interface CanvasProps {
  layout: Layout;
  bandsFor: (node: TopoNode) => VlanBand[];
  redundancy: Map<string, RedundancyBand>;
  /** The structural layer, already placed. Null when the reader has switched it
   *  off — never an empty layer standing in for one that failed to load. */
  relations?: RelationLayer | null;
  simulatedTools: ReadonlySet<string> | null;
  unlinked: Map<string, string>;
  focus?: FocusView | null;
  /** The cross-tool chain to trace over the lanes, already resolved to cards. */
  path?: PlacedPath | null;
  /** How many of the chain's hops are revealed. Equal to `path.hops.length`
   *  when the reveal has finished or motion is reduced. */
  pathStage?: number;
  onToggleLane: (layer: string) => void;
  /** Open a device's detail drawer. */
  onSelectNode?: (key: string) => void;
  selectedNode?: string | null;
  /** Cards matching the current search, and the one the canvas is centred on. */
  matches?: ReadonlySet<string>;
  activeMatch?: string | null;
  /** Bump `nonce` to scroll a card into view. */
  focusRequest?: { id: string; nonce: number } | null;
  /** A click on empty canvas. The way back to "nothing selected" that needs no
   *  panel to be open. */
  onBackgroundClick?: () => void;
  zoom: number;
  reduced: boolean;
  /** Reports the scroll viewport width so the caller can compute a fit zoom. */
  onViewport?: (width: number) => void;
  /**
   * Where the canvas was looking, kept by the CALLER so that going fullscreen —
   * which remounts this component into a portal — does not throw the reader
   * back to the top-left of a diagram they had just panned across.
   *
   * Held as the CENTRE OF THE VIEWPORT IN LAYOUT COORDINATES, not as scroll
   * pixels. Fullscreen changes both the zoom (it refits) and the lane wrapping
   * (a wider viewport re-flows `maxRowW`), so a pixel offset taken before the
   * transition points somewhere else entirely after it. A layout-space point
   * survives both.
   */
  scrollMemo?: React.MutableRefObject<{ cx: number; cy: number }>;
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

/** Eight is as many lines as a native tooltip renders before it stops being
 *  read; the rest are counted rather than dropped, so a collapsed lane's forty
 *  memberships never quietly become "eight". */
const TIP_ITEMS = 8;

function relationTip(r: PlacedRelation): string {
  const shown = r.items.slice(0, TIP_ITEMS);
  return [
    `${r.a} — ${r.b}`,
    r.items.length > 1 ? `${r.items.length} structural relations drawn as one line` : null,
    ...shown.map((i) => `${i.kind}: ${i.detail || `${i.a} → ${i.b}`}`),
    r.items.length > shown.length ? `…and ${r.items.length - shown.length} more` : null,
    "structure, not a cable: nothing observed this as an adjacency",
  ]
    .filter(Boolean)
    .join("\n");
}

export function Canvas({
  layout, bandsFor, redundancy, relations, simulatedTools, unlinked, focus, path, pathStage = 0,
  onToggleLane, onSelectNode, selectedNode, matches, activeMatch, focusRequest,
  onBackgroundClick, zoom, reduced, onViewport, scrollMemo, className,
}: CanvasProps) {
  const scrollRef = useRef<HTMLDivElement | null>(null);
  const drag = useRef<{ x: number; y: number; sl: number; st: number; moved: boolean } | null>(null);
  const suppressClick = useRef(false);

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

  const centreOn = useCallback((cx: number, cy: number, z: number) => {
    const el = scrollRef.current;
    if (!el || el.clientWidth === 0) return;
    el.scrollLeft = Math.max(0, cx * z - el.clientWidth / 2);
    el.scrollTop = Math.max(0, cy * z - el.clientHeight / 2);
  }, []);

  // Restore the caller's remembered view on mount. This is what makes "go
  // fullscreen" non-destructive: the reader keeps the part of the estate they
  // were looking at. (Switching overlays never remounts, so it keeps it for
  // free.) Mount only — deliberately not re-run, or a later re-layout would
  // yank the view back.
  const mountZoom = useRef(zoom);
  useLayoutEffect(() => {
    const memo = scrollMemo?.current;
    if (!memo || (memo.cx === 0 && memo.cy === 0)) return;
    centreOn(memo.cx, memo.cy, mountZoom.current);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // Zooming keeps the CENTRE of the view fixed rather than its top-left corner.
  // Corner-anchored zoom walks the diagram off screen a little on every step,
  // and it is also what breaks the fullscreen restore above: fullscreen refits
  // the zoom immediately after mounting, and without this the restored centre
  // would be recomputed against the old scale.
  const lastZoom = useRef(zoom);
  useLayoutEffect(() => {
    const el = scrollRef.current;
    const prev = lastZoom.current;
    if (!el || prev === zoom || el.clientWidth === 0) { lastZoom.current = zoom; return; }
    const cx = (el.scrollLeft + el.clientWidth / 2) / prev;
    const cy = (el.scrollTop + el.clientHeight / 2) / prev;
    lastZoom.current = zoom;
    centreOn(cx, cy, zoom);
  }, [zoom, centreOn]);

  const onScroll = useCallback(() => {
    const el = scrollRef.current;
    if (!el || !scrollMemo || el.clientWidth === 0) return;
    scrollMemo.current = {
      cx: (el.scrollLeft + el.clientWidth / 2) / zoom,
      cy: (el.scrollTop + el.clientHeight / 2) / zoom,
    };
  }, [scrollMemo, zoom]);

  // Bring a card into view — the landing half of search, and of "focus this
  // node". Centred rather than merely scrolled-into-view, because a match that
  // lands one pixel inside the bottom edge has not been found.
  //
  // Guarded on the NONCE rather than on the effect's dependencies: expanding a
  // lane changes `layout`, and without the guard every re-layout would yank the
  // reader back to whatever was last searched for.
  const handledFocus = useRef(-1);
  useEffect(() => {
    const el = scrollRef.current;
    if (!el || !focusRequest || handledFocus.current === focusRequest.nonce) return;
    const p = layout.byId.get(focusRequest.id);
    if (!p) return;
    handledFocus.current = focusRequest.nonce;
    const cx = (p.x + p.w / 2) * zoom;
    const cy = (p.y + p.h / 2) * zoom;
    el.scrollTo({
      left: Math.max(0, cx - el.clientWidth / 2),
      top: Math.max(0, cy - el.clientHeight / 2),
      behavior: reduced ? "auto" : "smooth",
    });
    // Intentionally keyed on the nonce: asking for the same card twice must
    // scroll to it twice.
  }, [focusRequest, layout, zoom, reduced]);

  // Drag-to-pan. Cheap: no state, no re-render, and it defers to the native
  // scrollbars rather than replacing them.
  const onPointerDown = useCallback((e: React.PointerEvent) => {
    const el = scrollRef.current;
    if (!el || e.button !== 0) return;
    if ((e.target as HTMLElement).closest("button, a, input, [role='button']")) return;
    // Mouse only. A touch drag is already a scroll gesture, and capturing it
    // here would replace the platform's kinetic scrolling with a worse one.
    if (e.pointerType !== "mouse") return;
    drag.current = { x: e.clientX, y: e.clientY, sl: el.scrollLeft, st: el.scrollTop, moved: false };
    el.setPointerCapture(e.pointerId);
  }, []);
  const onPointerMove = useCallback((e: React.PointerEvent) => {
    const el = scrollRef.current;
    const d = drag.current;
    if (!el || !d) return;
    if (Math.abs(e.clientX - d.x) > 3 || Math.abs(e.clientY - d.y) > 3) d.moved = true;
    el.scrollLeft = d.sl - (e.clientX - d.x);
    el.scrollTop = d.st - (e.clientY - d.y);
  }, []);
  const endDrag = useCallback((e: React.PointerEvent) => {
    const el = scrollRef.current;
    if (el && el.hasPointerCapture(e.pointerId)) el.releasePointerCapture(e.pointerId);
    // A pan must not read as a click on empty canvas, or panning would clear
    // the reader's selection every time.
    suppressClick.current = !!drag.current?.moved;
    drag.current = null;
  }, []);

  const onClick = useCallback((e: React.MouseEvent) => {
    if (suppressClick.current) { suppressClick.current = false; return; }
    if ((e.target as HTMLElement).closest("button, a, input, [role='button']")) return;
    onBackgroundClick?.();
  }, [onBackgroundClick]);

  const nodeState = (id: string): NodeState => {
    if (!focus) return "normal";
    if (focus.mode === "blast") {
      if (focus.failed.has(id)) return "failed";
      if (focus.isolated.has(id)) return "isolated";
      return focus.nodes.has(id) ? "focus" : "normal";
    }
    return focus.nodes.has(id) ? "focus" : "dim";
  };

  const linkOpacity = (l: PlacedLink): number => {
    if (!focus) return 1;
    if (focus.mode === "blast") {
      const touched =
        focus.failed.has(l.a) || focus.failed.has(l.b) ||
        focus.isolated.has(l.a) || focus.isolated.has(l.b);
      return touched ? 0.12 : 1;
    }
    // Under the reachability overlay every cable is quiet: the chain is a
    // policy fact drawn over the estate, and lighting a cable because the chain
    // happens to run past it would assert the traffic takes that wire.
    if (focus.mode === "reach") return 0.14;
    return focus.lit.has(l.id) ? 1 : 0.1;
  };

  // ── Tags ────────────────────────────────────────────────────────────────
  //
  // ONE TAG PER REDUNDANT GROUP, not one per link. The badge answers "how many
  // separate paths does this device have up to that tier", which is a fact
  // about the GROUP — printing it on both members said the same number twice
  // and, where the two members cross, printed it twice in the same place. The
  // tint is what ties a line to its group; the badge only has to be readable.
  //
  // That halves the chips on the criss-cross rows from four to two, which is
  // what makes them fit: `2 paths` needs about 58px and four of them wanted
  // 232px of a 170px span. It was survivable while the tag was `R5` only
  // because a two-character chip mostly hid under the one on top of it.
  //
  // The ×N / N-links counts stay per LINE, because a LAG's member count is a
  // fact about one cable bundle and belongs on that cable.
  interface CanvasTag {
    key: string;
    x: number; y: number;
    tint?: string;
    label?: string;
    count?: string;
    opacity: number;
    title?: string;
  }

  const tags: CanvasTag[] = [];
  {
    const byGroup = new Map<string, PlacedLink[]>();
    for (const l of layout.links) {
      if (!l.redundantGroup) continue;
      const bucket = byGroup.get(l.redundantGroup);
      if (bucket) bucket.push(l);
      else byGroup.set(l.redundantGroup, [l]);
    }
    for (const [group, members] of byGroup) {
      const band = redundancy.get(group);
      if (!band) continue;
      // The centroid of the group's drawn lines: between the pair, which is
      // where a reader looking at a criss-cross is already looking.
      const x = members.reduce((sc, m) => sc + m.mid.x, 0) / members.length;
      const y = members.reduce((sc, m) => sc + m.mid.y, 0) / members.length;
      tags.push({
        key: `grp:${group}`,
        x, y,
        tint: band.tint,
        label: band.tag,
        // Lit if ANY member is lit: a group half-dimmed by a walkthrough still
        // has to say how many paths it holds, or the trace reads as "one path".
        opacity: Math.max(...members.map(linkOpacity)),
        title: `${group}: ${band.tag} between the same device and the tier above it. ${
          members.length === 1
            ? "Only one of them resolved to a line on this canvas."
            : "Every line in this tint is one of them."
        }`,
      });
    }
    for (const l of layout.links) {
      const count = l.aggregated && l.memberCount > 1
        ? `×${l.memberCount}`
        : l.merged.length > 1
          ? `${l.merged.length} links`
          : "";
      if (!count) continue;
      tags.push({
        key: `cnt:${l.id}`,
        x: l.mid.x, y: l.mid.y,
        count,
        opacity: linkOpacity(l),
        title: l.aggregated
          ? `One aggregated link, ${l.memberCount} member cables — one failure domain.`
          : `${l.merged.length} distinct links between these two cards, drawn as one line.`,
      });
    }
  }

  // Nudged SIDEWAYS where two still collide, never down: the vertical gap
  // between two lanes is about twenty pixels and a tag pushed into it lands on
  // a card or on the HA bracket label. Offsets alternate right/left and are
  // tried in a fixed order over tags sorted by position, so one snapshot always
  // draws its tags in the same place — the same reason the layout is arithmetic.
  const tagAt = new Map<string, { x: number; y: number }>();
  {
    const TAG_W = 58;
    const taken: { x: number; y: number }[] = [];
    for (const t of [...tags].sort((a, b) => a.x - b.x || a.y - b.y || a.key.localeCompare(b.key))) {
      let x = t.x;
      for (let step = 0; step <= 6; step += 1) {
        const k = Math.ceil(step / 2) * (step % 2 === 1 ? 1 : -1);
        const cand = t.x + k * TAG_W;
        if (cand - TAG_W / 2 < 0 || cand + TAG_W / 2 > layout.width) continue;
        x = cand;
        if (!taken.some((o) => Math.abs(o.x - x) < TAG_W && Math.abs(o.y - t.y) < 14)) break;
      }
      taken.push({ x, y: t.y });
      tagAt.set(t.key, { x, y: t.y });
    }
  }

  const visibleHops = path ? path.hops.filter((h) => !h.selfLoop && h.index < pathStage) : [];
  const activeHopIndex = path ? Math.min(pathStage - 1, path.hops.length - 1) : -1;

  // Two hops between cards in the same lane land their tags on top of each
  // other, and a service/tool tag that cannot be read is the one fact the
  // overlay exists to carry. Colliding tags are nudged down in a deterministic
  // pass, so the same snapshot always draws them in the same place.
  const hopTag = new Map<number, { x: number; y: number }>();
  {
    const taken: { x: number; y: number }[] = [];
    for (const h of visibleHops) {
      let { x, y } = h.mid;
      for (let guard = 0; guard < 6; guard += 1) {
        // 120px is the widest a `tcp/8443 · guardicore` tag gets, and the tags
        // are centre-anchored, so two centres closer than that can still touch.
        if (!taken.some((t) => Math.abs(t.x - x) < 120 && Math.abs(t.y - y) < 15)) break;
        y += 17;
      }
      taken.push({ x, y });
      hopTag.set(h.index, { x, y });
    }
  }

  return (
    <div
      ref={scrollRef}
      onPointerDown={onPointerDown}
      onPointerMove={onPointerMove}
      onPointerUp={endDrag}
      onPointerCancel={endDrag}
      onClick={onClick}
      onScroll={onScroll}
      className={cn("zt-scroll relative h-full w-full overflow-auto bg-sunk", className)}
    >
      {/* `mx-auto` is not decoration: the lanes wrap to a readable ceiling, so
          on a 2560 display the diagram is narrower than the viewport. Left
          aligned it reads as a ribbon abandoned against one edge with a field
          of empty sunk canvas beside it. Centred it reads as a diagram. When it
          is WIDER than the viewport the auto margins collapse to zero and
          scrolling behaves exactly as before. */}
      <div style={{ width: layout.width * zoom, height: layout.height * zoom }} className="relative mx-auto">
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

          {/* ── Structure, beneath everything ───────────────────────────────
              Painted BEFORE the links so a cable always wins the pixel, and at
              a fraction of their weight: 1px, dotted, --text-3 at half alpha.
              The eye still goes to the criss-cross first, which is the point —
              these lines exist so the outer and inner lanes stop floating, not
              to be read one by one. Under any overlay they drop nearly out: a
              walkthrough dims the estate to what a finding names, and structure
              is never what a finding names. */}
          {relations && relations.lines.length > 0 ? (
            <svg
              width={layout.width}
              height={layout.height}
              className="pointer-events-none absolute left-0 top-0"
              style={{ overflow: "visible" }}
              aria-hidden
            >
              {relations.lines.map((r) => (
                <g
                  key={`rel:${r.id}`}
                  opacity={focus ? 0.06 : 1}
                  style={{ pointerEvents: "stroke" }}
                  className={cn(!reduced && "transition-opacity duration-300")}
                >
                  <title>{relationTip(r)}</title>
                  <path d={r.d} fill="none" stroke="transparent" strokeWidth={10} strokeLinecap="round" />
                  <path
                    d={r.d}
                    fill="none"
                    stroke="var(--text-3)"
                    strokeOpacity={0.55}
                    strokeWidth={1}
                    // "1 3" and not the links' "5 4": a dotted hairline reads as
                    // a relationship, a dashed line already means containment
                    // evidence on this canvas, and the two must not rhyme.
                    strokeDasharray="1 3"
                    strokeLinecap="round"
                    vectorEffect="non-scaling-stroke"
                  />
                </g>
              ))}
            </svg>
          ) : null}

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
                // `pointerEvents: stroke` re-enables hover on the line itself
                // inside an otherwise pointer-transparent svg, so the evidence
                // and provenance behind a link are one hover away. The wide
                // transparent path under it is the hit area — a 1.3px hairline
                // is not something anyone can reliably point at.
                <g
                  key={l.id}
                  opacity={linkOpacity(l)}
                  style={{ pointerEvents: "stroke" }}
                  className={cn(!reduced && "transition-opacity duration-300")}
                >
                  <title>{linkTip(l)}</title>
                  <path d={l.d} fill="none" stroke="transparent" strokeWidth={12} strokeLinecap="round" />
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

          {/* ── The cross-tool chain, over the lanes ────────────────────────── */}
          {path && visibleHops.length > 0 ? (
            <svg
              width={layout.width}
              height={layout.height}
              className="pointer-events-none absolute left-0 top-0 z-[6]"
              style={{ overflow: "visible" }}
              aria-hidden
            >
              <defs>
                <marker id="zt-hop-arrow" viewBox="0 0 8 8" refX="6.5" refY="4" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
                  <path d="M0 0 L8 4 L0 8 z" fill="var(--accent)" />
                </marker>
              </defs>
              {visibleHops.map((h) => {
                const tint = toolColour(h.hop.tool);
                const isActive = h.index === activeHopIndex;
                return (
                  <g key={`hop:${h.index}`}>
                    {/* A wide, low-alpha halo in the TOOL's colour under an
                        accent core: the chain reads as one thing, and each hop
                        still says which console permits it. */}
                    <path d={h.d} fill="none" stroke={tint} strokeWidth={8} strokeOpacity={0.3} strokeLinecap="round" />
                    <path
                      d={h.d}
                      fill="none"
                      stroke="var(--accent)"
                      strokeWidth={2.4}
                      strokeLinecap="round"
                      markerEnd="url(#zt-hop-arrow)"
                      vectorEffect="non-scaling-stroke"
                    />
                    {isActive && !reduced ? (
                      <path
                        d={h.d}
                        fill="none"
                        stroke="var(--accent)"
                        strokeWidth={3.4}
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
          ) : null}

          {/* What each hop permits, and which console permits it. */}
          {visibleHops.map((h) => (
            <div
              key={`hoptag:${h.index}`}
              className="pointer-events-none absolute z-[7] flex -translate-x-1/2 -translate-y-1/2 items-center gap-1 border bg-surface px-1 py-px text-[9px] font-bold leading-[13px]"
              style={{
                left: hopTag.get(h.index)?.x ?? h.mid.x,
                top: hopTag.get(h.index)?.y ?? h.mid.y,
                borderColor: toolColour(h.hop.tool),
              }}
              title={`${h.hop.src_display} → ${h.hop.dst_display} · ${h.hop.service} · ${h.hop.tool} rule ${h.hop.ref}`}
            >
              <span className="h-1.5 w-1.5 shrink-0" style={{ background: toolColour(h.hop.tool) }} />
              <span className="mono text-text">{h.hop.service || "service not stated"}</span>
              <span className="mono text-text3">{h.hop.tool}</span>
            </div>
          ))}

          {/* Link and group tags. Positioned elements rather than SVG text so
              they get the same hairline chip treatment as everything else. */}
          {tags.map((t) => (
            <div
              key={`tag:${t.key}`}
              className="pointer-events-none absolute z-[5] flex -translate-x-1/2 -translate-y-1/2 items-center gap-0.5 border border-border bg-surface px-1 text-[9px] font-bold leading-[13px]"
              style={{ left: tagAt.get(t.key)?.x ?? t.x, top: tagAt.get(t.key)?.y ?? t.y, opacity: t.opacity }}
              title={t.title}
            >
              {t.label ? <span style={{ color: t.tint }}>{t.label}</span> : null}
              {t.count ? <span className="mono text-text3">{t.count}</span> : null}
            </div>
          ))}

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

          {layout.nodes.map((p) => {
            const order = path?.order.get(p.id);
            const onChain = order != null && path != null
              // A card only wears its hop number once the reveal has reached it.
              && path.hops.some((h) => h.index < pathStage && (h.from.id === p.id || h.to.id === p.id));
            return (
              <NodeCard
                key={p.id}
                placed={p}
                state={nodeState(p.id)}
                bands={p.node ? bandsFor(p.node) : []}
                simulatedTools={simulatedTools}
                unlinkedReason={p.node ? unlinked.get(p.node.key) ?? p.node.unlinked_reason ?? null : null}
                onExpand={p.kind === "group" ? () => onToggleLane(String(p.layer)) : undefined}
                onSelect={p.kind === "device" && onSelectNode ? () => onSelectNode(p.id) : undefined}
                selected={selectedNode === p.id}
                matched={matches?.has(p.id)}
                activeMatch={activeMatch === p.id}
                pathIndex={onChain ? order : undefined}
                pathTerminal={onChain && path ? order === path.cards.length - 1 : false}
                reduced={reduced}
              />
            );
          })}
        </div>
      </div>
    </div>
  );
}
