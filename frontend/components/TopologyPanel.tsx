"use client";

/**
 * THE TOPOLOGY CANVAS — the estate drawn outside-in, one band per layer, from
 * what the consoles actually reported and nothing else.
 *
 * This screen answers a question a table cannot: where the shape of this
 * network is wrong. Two edge routers each reaching both firewalls is a picture;
 * one access switch reaching one core is the same picture with a line missing,
 * and the missing line is the finding. So the canvas is not decoration on top of
 * the inventory — it is the inventory arranged so that absence is visible.
 *
 * WHICH MAKES ABSENCE THE THING IT MUST GET RIGHT, and there are four kinds of
 * it, each rendered as itself:
 *
 *   an unobserved LANE      a named absence — the reason and the console API
 *                           that would fill it. Never a faded device: drawing
 *                           hardware nobody observed is the one thing this
 *                           screen must not do.
 *   an unlinked DEVICE      inventoried, no cable reported by anything. It gets
 *                           a dashed card and its own rail, so a box with no
 *                           line reads as a coverage gap and not a bug.
 *   a null COUNT            an em-dash with the reason on hover, never 0.
 *   a capped RESPONSE       said out loud, with the capped lanes named.
 *
 * And one kind of weakness: a `containment` link is dashed, because two
 * interfaces provably sharing an address block is a real L3 observation and is
 * not a cable. The legend carries that sentence.
 *
 * NetworkMap.tsx is the other half of this screen's job and is deliberately
 * untouched: that one draws REACHABILITY (who can talk to whom, from the policy
 * graph), this one draws TOPOLOGY (what is plugged into what). They are
 * different graphs built by different analyzers and holding them apart is a
 * guard the engine already maintains.
 */

import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { createPortal } from "react-dom";
import {
  AlertTriangle, Layers, Maximize2, Minimize2, Play, Scan, Unlink, ZoomIn, ZoomOut,
} from "lucide-react";
import { api, asApiError, type ApiError, type ResiliencePayload, type TopologyPayload } from "@/lib/api";
import type { Finding, SourceCard, TopoNode } from "@/lib/types";
import { cn } from "@/lib/cn";
import { Chip, Eyebrow, SeverityPill, StatPill } from "./ui";
import { ErrorState, InlineError } from "./ui/Feedback";
import { NetIcon } from "./net/icons";
import { Canvas, type FocusView } from "./topology/Canvas";
import { FindingSidebar } from "./topology/FindingSidebar";
import { Legend } from "./topology/Legend";
import { buildLayout, GEOM, orderHops, type Layout } from "./topology/layout";
import { buildRedundancyBands, buildVlanBands, unknownVlanBand, type VlanBand } from "./topology/palette";
import { fromPolicy, fromResilience, involvedCards, sortWalk, type WalkFinding } from "./topology/findings";

/** How long one hop of the trace, or one batch of a blast reveal, is on screen. */
const STAGE_MS = 520;
/** Never more than this many ticks in a blast replay, however wide the radius:
 *  a 200-device isolation should take four seconds, not a hundred. */
const MAX_BLAST_TICKS = 14;

const clamp = (v: number, lo: number, hi: number) => Math.min(hi, Math.max(lo, v));

/**
 * The lowest zoom "Fit" will choose.
 *
 * Fit fits the WIDTH, and it stops here rather than shrinking until everything
 * is on screen, because a diagram whose hostnames cannot be read is not a
 * diagram that fits — it is a picture of one. Below this the canvas scrolls
 * instead, and the lane layout has already narrowed itself to the space
 * available (see `maxRowW` below), so it rarely comes to that.
 */
const FIT_MIN = 0.72;

function useReducedMotion(): boolean {
  const [reduced, setReduced] = useState(false);
  useEffect(() => {
    if (typeof window === "undefined" || !window.matchMedia) return;
    const mq = window.matchMedia("(prefers-reduced-motion: reduce)");
    const sync = () => setReduced(mq.matches);
    sync();
    mq.addEventListener("change", sync);
    return () => mq.removeEventListener("change", sync);
  }, []);
  return reduced;
}

/** A count from `InventoryCounts`. `null` is not zero and never renders as one. */
function Count({ label, value }: { label: string; value: number | null | undefined }) {
  const unknown = value == null;
  return (
    <div
      title={
        unknown
          ? `No onboarded source declares a ${label.toLowerCase()} count for this snapshot. It is unknown, not zero.`
          : undefined
      }
    >
      <StatPill label={label} value={unknown ? <span className="text-text3">—</span> : value} tone="neutral" />
    </div>
  );
}

function ZoomBar({ zoom, setZoom, onFit }: { zoom: number; setZoom: (z: number) => void; onFit: () => void }) {
  return (
    <div className="flex items-center gap-1">
      <button type="button" onClick={() => setZoom(clamp(zoom - 0.1, 0.5, 1.6))} className="btn-ghost !h-7 !w-7 !px-0" aria-label="Zoom out">
        <ZoomOut size={13} />
      </button>
      <span className="mono w-9 text-center text-[11px] tabular-nums text-text3">{Math.round(zoom * 100)}%</span>
      <button type="button" onClick={() => setZoom(clamp(zoom + 0.1, 0.5, 1.6))} className="btn-ghost !h-7 !w-7 !px-0" aria-label="Zoom in">
        <ZoomIn size={13} />
      </button>
      <button
        type="button"
        onClick={onFit}
        className="btn-ghost !h-7 px-2 text-[11px]"
        title="Fit the canvas to the width available — stopping at 72%, below which the hostnames stop being readable"
      >
        <Scan size={12} /> Fit
      </button>
    </div>
  );
}

export interface TopologyPanelProps {
  snapshot?: string;
  /**
   * The console's policy findings. Optional, and filtered to the ones that name
   * a device on this canvas — a finding about two cloud workloads has nothing
   * to light up here, and a walkthrough where a third of the steps highlight
   * nothing is a walkthrough nobody finishes.
   */
  findings?: Finding[];
  /** Set when the findings feed itself failed, so the walkthrough's "N findings"
   *  is never read as a complete set. */
  findingsError?: ApiError;
}

export function TopologyPanel({ snapshot, findings, findingsError }: TopologyPanelProps) {
  const reduced = useReducedMotion();

  const [topo, setTopo] = useState<TopologyPayload>();
  const [topoErr, setTopoErr] = useState<ApiError>();
  const [loading, setLoading] = useState(true);
  const [res, setRes] = useState<ResiliencePayload>();
  const [resErr, setResErr] = useState<ApiError>();
  const [resLoading, setResLoading] = useState(true);
  const [src, setSrc] = useState<SourceCard[]>();
  const [srcErr, setSrcErr] = useState<ApiError>();

  const [expanded, setExpanded] = useState<ReadonlySet<string>>(new Set<string>());
  const [zoom, setZoom] = useState(1);
  /** Width of the scroll viewport, as the canvas last measured it. */
  const [viewW, setViewW] = useState(0);
  const [fullscreen, setFullscreen] = useState(false);
  const [sidebarCollapsed, setSidebarCollapsed] = useState(false);
  const [selIndexState, setSelIndex] = useState<number | null>(null);
  const [stage, setStage] = useState(0);
  const [replayNonce, setReplayNonce] = useState(0);
  const [explainingId, setExplainingId] = useState<string>();
  const [explainErr, setExplainErr] = useState<ApiError>();
  const [explained, setExplained] = useState<Record<string, string>>({});
  const [mounted, setMounted] = useState(false);

  useEffect(() => setMounted(true), []);

  const load = useCallback(() => {
    let live = true;
    setLoading(true); setResLoading(true);
    setTopoErr(undefined); setResErr(undefined); setSrcErr(undefined);
    api.topology(snapshot)
      // A failed topology read must not leave the last good lanes on screen: a
      // stale picture with a fresh header is the worst of both.
      .then((t) => { if (live) setTopo(t); })
      .catch((e) => { if (live) { setTopo(undefined); setTopoErr(asApiError(e)); } })
      .finally(() => { if (live) setLoading(false); });
    api.resilience(snapshot)
      .then((r) => { if (live) setRes(r); })
      .catch((e) => { if (live) { setRes(undefined); setResErr(asApiError(e)); } })
      .finally(() => { if (live) setResLoading(false); });
    api.sources(snapshot)
      .then((s) => { if (live) setSrc(s.sources); })
      // Undefined, not []: an empty source list would render as "no source is a
      // seeded export", which is the flattering reading of a failed fetch.
      .catch((e) => { if (live) { setSrc(undefined); setSrcErr(asApiError(e)); } });
    return () => { live = false; };
  }, [snapshot]);

  useEffect(() => load(), [load]);

  // ── Derived model ───────────────────────────────────────────────────────
  const lanes = useMemo(() => topo?.lanes ?? [], [topo]);
  const links = useMemo(() => topo?.links ?? [], [topo]);

  // The lanes wrap to the width actually available rather than to a constant,
  // so a 1024px projector — or a fullscreen canvas with the sidebar open beside
  // it — gets a narrower, taller picture at full zoom instead of a wide one
  // shrunk until the hostnames stop being readable.
  const maxRowW = viewW > 0
    ? clamp(viewW - GEOM.labelW - GEOM.padRight, GEOM.minContentW, GEOM.maxRowW)
    : GEOM.maxRowW;

  const layout: Layout = useMemo(
    () => buildLayout(lanes, links, { expanded, maxRowW }),
    [lanes, links, expanded, maxRowW],
  );

  const allNodes = useMemo(() => lanes.flatMap((l) => l.nodes), [lanes]);
  const nodeByKey = useMemo(() => new Map(allNodes.map((n) => [n.key, n])), [allNodes]);
  const nameFor = useCallback((key: string) => nodeByKey.get(key)?.name || key, [nodeByKey]);

  const vlanBands = useMemo(() => buildVlanBands(topo?.vlans ?? []), [topo]);
  const segmentKeys = useMemo(
    () => new Set(lanes.filter((l) => l.layer === "segment").flatMap((l) => l.nodes.map((n) => n.key))),
    [lanes],
  );
  // Only the segment lane is banded. A trunk carrying nine VLANs is not a
  // segment, and painting it would make the band mean two different things.
  const bandsFor = useCallback(
    (n: TopoNode): VlanBand[] =>
      segmentKeys.has(n.key)
        ? (n.vlan_ids ?? []).map((id) => vlanBands.get(id) ?? unknownVlanBand(id))
        : [],
    [segmentKeys, vlanBands],
  );

  const redundancy = useMemo(
    () => buildRedundancyBands(links.map((l) => l.redundant_group).filter((g): g is string => !!g)),
    [links],
  );

  const simulatedTools = useMemo(
    () => (src ? new Set(src.filter((s) => s.simulated).map((s) => s.tool)) : null),
    [src],
  );

  const unlinked = useMemo(() => {
    const m = new Map<string, string>();
    for (const u of topo?.unlinked_devices ?? []) m.set(u.device_key, u.reason);
    for (const n of allNodes) if (n.unlinked_reason && !m.has(n.key)) m.set(n.key, n.unlinked_reason);
    return m;
  }, [topo, allNodes]);

  const unlinkedRows = useMemo(() => {
    const declared = topo?.unlinked_devices ?? [];
    const extra = allNodes
      .filter((n) => n.unlinked_reason && !declared.some((d) => d.device_key === n.key))
      .map((n) => ({ device_key: n.key, reason: n.unlinked_reason!, would_be_filled_by: n.would_be_filled_by ?? "" }));
    return [...declared, ...extra];
  }, [topo, allNodes]);

  const policy = useMemo(() => fromPolicy(findings ?? [], allNodes), [findings, allNodes]);
  const walk = useMemo(() => {
    const fromRes = res ? fromResilience(res.findings, res.blast_radius) : [];
    const items = sortWalk([...fromRes, ...policy.items]);
    // An explanation fetched in this session replaces the empty detail it was
    // fetched for, and nothing else about the item.
    return items.map((i) => (explained[i.id] ? { ...i, detail: explained[i.id] } : i));
  }, [res, policy.items, explained]);

  // Clamped against the CURRENT list: a reload that shrinks the findings must
  // not leave a selection pointing past the end, which would put "4 of 2" in
  // the sidebar and dim the canvas for a finding that is no longer there.
  const selIndex = selIndexState != null && selIndexState >= 0 && selIndexState < walk.length ? selIndexState : null;
  const sel: WalkFinding | undefined = selIndex == null ? undefined : walk[selIndex];

  // ── The staged animation ────────────────────────────────────────────────
  const anim = useMemo(() => {
    if (!sel) return null;
    const nodes = involvedCards(sel, layout.cardFor);
    // The adjacencies the finding names outright, resolved to drawn lines.
    const named = new Set(
      sel.involved.map((k) => layout.linkByRawId.get(k)).filter((id): id is string => !!id),
    );
    // A named link's two ends are part of the finding whether or not the
    // payload also listed them as devices.
    for (const id of named) {
      const l = layout.linkById.get(id);
      if (l) { nodes.add(l.a); nodes.add(l.b); }
    }
    const hops = orderHops(layout, nodes, named);
    // What the cut costs, straight off `blast_radius`: the stranded circuits
    // and the isolated devices, in that order, resolved to cards. Nothing here
    // is derived from the lanes on screen — a browser-side recount would
    // disagree with the report for a reason nobody could find.
    const lost = [...new Set(sel.lost.map((k) => layout.cardFor.get(k)).filter((k): k is string => !!k))];
    const failedKeys = sel.failing.length > 0 ? sel.failing : sel.blast ? [sel.blast.device_key] : [];
    const failed = new Set(failedKeys.map((k) => layout.cardFor.get(k)).filter((k): k is string => !!k));
    // A resilience finding shows the FAILURE; anything else traces the path.
    const mode: FocusView["mode"] = sel.kind === "resilience" && failed.size > 0 ? "blast" : "path";
    const batch = lost.length > 0 ? Math.max(1, Math.ceil(lost.length / MAX_BLAST_TICKS)) : 1;
    const ticks = lost.length > 0 ? Math.ceil(lost.length / batch) : 0;
    const total = mode === "blast" ? 1 + ticks : Math.max(1, hops.length);
    return { nodes, hops, lost, failed, mode, batch, total };
  }, [sel, layout]);

  const totalStages = anim?.total ?? 0;
  // Keyed on the finding's ID rather than on `sel` itself: the parent re-renders
  // with a fresh `findings` array on every console tick, which gives every item
  // a new object identity, and an effect that depended on the object would
  // restart the trace from hop one several times a second.
  const selId = sel?.id;

  useEffect(() => {
    if (!selId || totalStages <= 0) { setStage(0); return; }
    // Reduced motion: no travelling dash and no staged fade — the same end
    // state, arrived at immediately, with the sidebar text unchanged.
    if (reduced || totalStages <= 1) { setStage(totalStages); return; }
    setStage(0);
    let i = 0;
    const id = window.setInterval(() => {
      i += 1;
      setStage(i);
      if (i >= totalStages) window.clearInterval(id);
    }, STAGE_MS);
    return () => window.clearInterval(id);
    // `replayNonce` restarts the same finding's animation on demand.
  }, [selId, totalStages, reduced, replayNonce]);

  const lostShown = anim && anim.mode === "blast"
    ? (stage === 0 ? 0 : Math.min(anim.lost.length, stage * anim.batch))
    : 0;

  const focus: FocusView | null = useMemo(() => {
    if (!anim) return null;
    // A finding whose devices are all off this canvas must dim NOTHING. The
    // alternative — an empty involved set fed to the dimmer — blanks the whole
    // picture and reads as a rendering failure; the sidebar says so in words
    // instead.
    if (anim.nodes.size === 0 && anim.failed.size === 0) return null;
    if (anim.mode === "blast") {
      return {
        nodes: anim.nodes,
        lit: new Set<string>(),
        failed: anim.failed,
        isolated: new Set(anim.lost.slice(0, lostShown)),
        mode: "blast",
      };
    }
    const activeIndex = Math.min(stage, anim.hops.length - 1);
    const lit = new Set(anim.hops.slice(0, activeIndex + 1).map((h) => h.id));
    return {
      nodes: anim.nodes,
      lit,
      activeLink: stage < anim.hops.length ? anim.hops[stage]?.id : undefined,
      failed: new Set<string>(),
      isolated: new Set<string>(),
      mode: "path",
    };
  }, [anim, stage, lostShown]);

  // ── Viewport, zoom, fullscreen ──────────────────────────────────────────
  const viewportW = useRef(0);
  const layoutW = useRef<number>(GEOM.maxRowW);
  layoutW.current = layout.width;
  const fitPending = useRef(false);
  const fsRef = useRef<HTMLDivElement | null>(null);
  const toggleRef = useRef<HTMLButtonElement | null>(null);

  const onViewport = useCallback((w: number) => {
    viewportW.current = w;
    // A few px of jitter (a scrollbar appearing) must not re-flow the lanes.
    setViewW((prev) => (Math.abs(prev - w) > 8 ? w : prev));
  }, []);

  // A pending fit is applied HERE rather than inside `onViewport`, because a new
  // viewport width re-flows the lanes and therefore changes `layout.width`. Run
  // in the callback, the fit would divide by the width the canvas had a moment
  // ago and land on the wrong zoom.
  useEffect(() => {
    if (!fitPending.current || viewW <= 0) return;
    fitPending.current = false;
    setZoom(clamp(viewW / layout.width, FIT_MIN, 1));
  }, [viewW, layout.width]);

  const fit = useCallback(() => {
    const w = viewportW.current;
    if (w > 0) setZoom(clamp(w / layoutW.current, FIT_MIN, 1));
    else fitPending.current = true;
  }, []);

  const openFullscreen = useCallback((index?: number) => {
    fitPending.current = true;
    if (index != null) setSelIndex(index);
    setFullscreen(true);
  }, []);

  const closeFullscreen = useCallback(() => {
    setFullscreen(false);
    setZoom(1);
    toggleRef.current?.focus();
  }, []);

  const step = useCallback((delta: number) => {
    setSelIndex((cur) => {
      if (walk.length === 0) return null;
      const base = cur == null || cur >= walk.length ? -1 : cur;
      return clamp(base + delta, 0, walk.length - 1);
    });
  }, [walk.length]);

  // ESC exits; the arrows walk the findings. Both are scoped to the fullscreen
  // layer, and both stand down inside a text field.
  useEffect(() => {
    if (!fullscreen) return;
    const onKey = (e: KeyboardEvent) => {
      const el = e.target as HTMLElement | null;
      if (el && (el.tagName === "INPUT" || el.tagName === "TEXTAREA" || el.isContentEditable)) return;
      if (e.key === "Escape") { e.preventDefault(); closeFullscreen(); return; }
      if (walk.length === 0) return;
      if (e.key === "ArrowRight" || e.key === "ArrowDown") { e.preventDefault(); step(1); }
      if (e.key === "ArrowLeft" || e.key === "ArrowUp") { e.preventDefault(); step(-1); }
    };
    window.addEventListener("keydown", onKey);
    const prev = document.body.style.overflow;
    document.body.style.overflow = "hidden";
    return () => {
      window.removeEventListener("keydown", onKey);
      document.body.style.overflow = prev;
    };
  }, [fullscreen, closeFullscreen, step, walk.length]);

  // Selecting a finding that lives in a collapsed lane is pointless if the lane
  // stays collapsed, so the lanes holding it are opened. Reduced to a string so
  // the effect fires when the ANSWER changes, not when its inputs are rebuilt.
  const lanesToOpen = useMemo(() => {
    if (!sel) return "";
    const needed = new Set<string>();
    for (const key of sel.involved) {
      const card = layout.cardFor.get(key);
      if (card?.startsWith("grp:")) needed.add(card.split(":")[1]);
    }
    return [...needed].sort().join(",");
  }, [sel, layout]);

  useEffect(() => {
    if (!lanesToOpen) return;
    setExpanded((prev) => {
      const next = new Set(prev);
      let changed = false;
      for (const layer of lanesToOpen.split(",")) if (!next.has(layer)) { next.add(layer); changed = true; }
      return changed ? next : prev;
    });
  }, [lanesToOpen]);

  const toggleLane = useCallback((layer: string) => {
    setExpanded((prev) => {
      const next = new Set(prev);
      if (next.has(layer)) next.delete(layer);
      else next.add(layer);
      return next;
    });
  }, []);

  const askExplain = useCallback(async (item: WalkFinding) => {
    setExplainingId(item.id);
    setExplainErr(undefined);
    try {
      const r = await api.explain(item.id);
      if (r.explanation) setExplained((m) => ({ ...m, [item.id]: r.explanation }));
      else if (r.pending) setExplainErr(asApiError(new Error("The advisory layer is still writing this explanation. Try again in a moment.")));
    } catch (e) {
      setExplainErr(asApiError(e));
    } finally {
      setExplainingId(undefined);
    }
  }, []);

  // ── Pieces shared by the inline and fullscreen layouts ──────────────────
  const counts = topo?.counts;
  const caps = topo?.caps;
  const capped = !!caps && caps.nodes_shown < caps.nodes_total;
  const hasContainment = links.some((l) => l.evidence === "containment");
  const hasAggregated = links.some((l) => l.aggregated);
  const hasHa = layout.units.length > 0;
  const simulated = src?.filter((s) => s.simulated) ?? [];

  const canvas = (
    <Canvas
      layout={layout}
      bandsFor={bandsFor}
      redundancy={redundancy}
      simulatedTools={simulatedTools}
      unlinked={unlinked}
      focus={focus}
      onToggleLane={toggleLane}
      zoom={zoom}
      reduced={reduced}
      onViewport={onViewport}
    />
  );

  const sidebar = (
    <FindingSidebar
      items={walk}
      index={selIndex}
      onIndex={(i) => setSelIndex(clamp(i, 0, Math.max(0, walk.length - 1)))}
      collapsed={sidebarCollapsed}
      onToggleCollapsed={() => setSidebarCollapsed((c) => !c)}
      loading={resLoading}
      error={resErr}
      onRetry={load}
      analysed={res ? res.analysed : null}
      notAnalysedReason={res?.reason}
      blastBasis={res?.blast_basis}
      lostShown={lostShown}
      lostTotal={anim?.lost.length ?? 0}
      involvedOnCanvas={anim ? anim.nodes.size : 0}
      replayDone={stage >= totalStages}
      onReplay={() => setReplayNonce((n) => n + 1)}
      nameFor={nameFor}
      onExplain={askExplain}
      explainingId={explainingId}
      explainError={explainErr}
      skippedPolicy={policy.skipped}
      snapshot={snapshot}
    />
  );

  return (
    <div className="space-y-4">
      {/* ── Header: what this is, and the estate's own counts ─────────────── */}
      <div className="panel p-4">
        <div className="flex flex-wrap items-start gap-3">
          <div className="min-w-0 flex-1">
            <Eyebrow>Topology</Eyebrow>
            <p className="mt-1.5 max-w-3xl text-[12px] leading-relaxed text-text2">
              The estate drawn outside-in — internet to endpoint, one band per layer — from what the onboarded consoles
              reported. A lane nobody observed is named rather than drawn, a device nobody reported a cable for is
              listed on its own rail rather than left floating, and a link that rests on address containment is dashed
              rather than blended in with the cables.
            </p>
          </div>
          <div className="flex shrink-0 items-center gap-1.5">
            <button
              ref={toggleRef}
              type="button"
              onClick={() => (fullscreen ? closeFullscreen() : openFullscreen())}
              className="btn-ghost text-[12px]"
            >
              {fullscreen ? <Minimize2 size={13} /> : <Maximize2 size={13} />} Fullscreen
            </button>
            {/* No count while the resilience read is failed or in flight: "Walk
                3 findings" out of a half-loaded set is a claim about how many
                there are. */}
            {resErr ? null : resLoading ? null : walk.length > 0 ? (
              <button type="button" onClick={() => openFullscreen(0)} className="btn-primary text-[12px]">
                <Play size={12} /> Walk {walk.length} finding{walk.length === 1 ? "" : "s"}
              </button>
            ) : null}
          </div>
        </div>

        {topoErr ? null : (
          <div className="mt-3 grid grid-cols-2 gap-2 sm:grid-cols-3 lg:grid-cols-5">
            <Count label="Devices" value={counts?.devices} />
            <Count label="VLANs" value={counts?.vlans} />
            <Count label="Subnets" value={counts?.subnets} />
            <Count label="Public IPs" value={counts?.public_ips} />
            <Count label="Circuits" value={counts?.circuits} />
          </div>
        )}

        {/* Provenance. A seeded export is said out loud, always — and a source
            register we could not read says UNKNOWN rather than nothing. */}
        <div className="mt-3 text-[11.5px]">
          {srcErr ? (
            <InlineError resource="the source register" error={srcErr} onRetry={load} />
          ) : src === undefined ? (
            <span className="text-text3">Reading the source register…</span>
          ) : simulated.length > 0 ? (
            <span className="inline-flex flex-wrap items-center gap-1.5 text-text2">
              <Chip variant="info" dot>
                {simulated.length} of {src.length} sources are seeded exports
              </Chip>
              <span className="mono text-[11px] text-text3">{simulated.map((s) => s.tool).join(" · ")}</span>
              <span className="text-text3">— every device below that one of these reported is marked</span>
              <span className="mono text-info">sim</span>
            </span>
          ) : (
            <span className="text-text3">
              All {src.length} registered source{src.length === 1 ? "" : "s"} report as live connectors; none is a seeded
              export.
            </span>
          )}
        </div>

        {srcErr ? (
          <p className="mt-1.5 text-[11px] text-text3">
            Provenance below is drawn without a live/seeded marker rather than with the flattering one: this build cannot
            currently say which consoles are seeded exports.
          </p>
        ) : null}

        {/* What this response left out. */}
        {capped && caps ? (
          <div className="mt-3 flex items-start gap-2 border border-sev-medium-line bg-sev-medium-bg px-3 py-2 text-[11.5px]">
            <AlertTriangle size={13} className="mt-0.5 shrink-0 text-sev-medium" />
            <span className="text-text2">
              This response is capped: <span className="mono">{caps.nodes_shown}</span> of{" "}
              <span className="mono">{caps.nodes_total}</span> nodes are on the canvas.
              {caps.capped_lanes.length > 0 ? (
                <> Capped lane{caps.capped_lanes.length === 1 ? "" : "s"}: <span className="mono">{caps.capped_lanes.join(", ")}</span>.</>
              ) : null}{" "}
              What is missing is missing from the picture, not from the estate.
            </span>
          </div>
        ) : null}

        {topo?.degraded_analyzers && topo.degraded_analyzers.length > 0 ? (
          <div className="mt-2 flex items-start gap-2 border border-sev-high-line bg-sev-high-bg px-3 py-2 text-[11.5px]">
            <AlertTriangle size={13} className="mt-0.5 shrink-0 text-sev-high" />
            <span className="text-text2">
              {topo.degraded_analyzers.length} analyzer{topo.degraded_analyzers.length === 1 ? "" : "s"} did not finish
              (<span className="mono">{topo.degraded_analyzers.join(", ")}</span>), so findings on this canvas are
              incomplete rather than few.
            </span>
          </div>
        ) : null}

        {topo?.source_conflicts && topo.source_conflicts.length > 0 ? (
          <p
            className="mt-2 text-[11px] text-text3"
            title={topo.source_conflicts
              .map((c) => `${c.entity}.${c.field}: ${c.claims.map((k) => `${k.tool}=${String(k.value)}`).join(" vs ")}`)
              .join("\n")}
          >
            {topo.source_conflicts.length} field{topo.source_conflicts.length === 1 ? "" : "s"} two consoles state
            differently. Not an error — a stale entry, or a box replaced without the aggregator being told. The
            Inventory screen reconciles them claim by claim.
          </p>
        ) : null}

        {findingsError ? (
          <div className="mt-2">
            <InlineError resource="the findings feed" error={findingsError} />
          </div>
        ) : null}
      </div>

      {/* ── The canvas ────────────────────────────────────────────────────── */}
      {topoErr ? (
        <ErrorState resource="the network topology" error={topoErr} onRetry={load} />
      ) : loading && !topo ? (
        <div className="panel p-4">
          <div className="skeleton" style={{ height: 420 }} />
        </div>
      ) : (
        <>
          <section className="panel flex min-h-0 flex-col overflow-hidden">
            <header className="panel-head shrink-0">
              <div className="flex min-w-0 items-center gap-2">
                <Layers size={13} className="shrink-0 text-accent-fg" />
                <h2 className="eyebrow truncate">
                  {layout.lanes.length} lane{layout.lanes.length === 1 ? "" : "s"} · {layout.nodes.length} card
                  {layout.nodes.length === 1 ? "" : "s"} · {layout.links.length} link
                  {layout.links.length === 1 ? "" : "s"}
                </h2>
              </div>
              <div className="flex shrink-0 items-center gap-1.5">
                <ZoomBar zoom={zoom} setZoom={setZoom} onFit={fit} />
              </div>
            </header>
            <div style={{ height: "clamp(380px, 62vh, 660px)" }} className="min-h-0">
              {fullscreen ? (
                <div className="flex h-full items-center justify-center bg-sunk text-[12px] text-text3">
                  The canvas is open fullscreen. Press <span className="mono mx-1 text-text2">Esc</span> to bring it back
                  here.
                </div>
              ) : (
                canvas
              )}
            </div>
            {layout.unresolved.length > 0 || layout.hiddenInGroups > 0 ? (
              <footer className="shrink-0 border-t border-hair px-4 py-2 text-[11px] text-text3">
                {layout.unresolved.length > 0 ? (
                  <span title={layout.unresolved.map((l) => `${l.a} ↔ ${l.b}`).join("\n")}>
                    {layout.unresolved.length} link{layout.unresolved.length === 1 ? "" : "s"} name a device that is not
                    in any lane of this response and could not be drawn.{" "}
                  </span>
                ) : null}
                {layout.hiddenInGroups > 0 ? (
                  <span>
                    {layout.hiddenInGroups} link{layout.hiddenInGroups === 1 ? " runs" : "s run"} between members of a
                    collapsed group; expand the lane to see them.
                  </span>
                ) : null}
              </footer>
            ) : null}
          </section>

          {/* ── The unlinked rail ───────────────────────────────────────────── */}
          {unlinkedRows.length > 0 ? (
            <section className="border border-dashed border-sev-high-line bg-sev-high-bg p-3">
              <div className="flex flex-wrap items-center gap-2">
                <Unlink size={13} className="shrink-0 text-sev-high" />
                <span className="text-[12px] font-bold text-sev-high">
                  {unlinkedRows.length} inventoried device{unlinkedRows.length === 1 ? "" : "s"} with no cable reported
                </span>
                <span className="text-[11.5px] text-text2">
                  These are on the canvas with a dashed border and no line. That is a gap in what the consoles report,
                  not a gap in the estate.
                </span>
              </div>
              <ul className="mt-2 grid gap-1.5 sm:grid-cols-2 xl:grid-cols-3">
                {unlinkedRows.map((u) => {
                  const n = nodeByKey.get(u.device_key);
                  return (
                    <li key={u.device_key} className="flex items-start gap-2 border border-border bg-surface px-2 py-1.5">
                      <NetIcon kind={n?.role ?? n?.kind ?? "unknown"} size={15} className="mt-0.5 shrink-0 text-text3" />
                      <div className="min-w-0">
                        <div className="mono truncate text-[11.5px] font-bold">{n?.name || u.device_key}</div>
                        <div className="text-[11px] leading-snug text-text2">{u.reason}</div>
                        {u.would_be_filled_by ? (
                          <div className="mono text-[10.5px] text-text3">would be filled by {u.would_be_filled_by}</div>
                        ) : null}
                      </div>
                    </li>
                  );
                })}
              </ul>
            </section>
          ) : null}

          {/* ── Findings, inline ────────────────────────────────────────────── */}
          <section className="panel p-4">
            <div className="flex flex-wrap items-center gap-2">
              <Eyebrow>Findings on this topology</Eyebrow>
              {resErr ? null : (
                <span className="mono text-[11px] text-text3">
                  {walk.length} on the canvas
                  {policy.skipped > 0 ? ` · ${policy.skipped} elsewhere` : ""}
                </span>
              )}
              {walk.length > 0 && !resErr ? (
                <button type="button" onClick={() => openFullscreen(0)} className="btn-ghost ml-auto text-[11.5px]">
                  <Play size={12} /> Walk them fullscreen
                </button>
              ) : null}
            </div>
            {resErr ? (
              <div className="mt-2">
                <ErrorState resource="the resilience analysis" error={resErr} onRetry={load} />
              </div>
            ) : resLoading && !res ? (
              <div className="mt-2 space-y-2">
                {Array.from({ length: 3 }).map((_, i) => (
                  <div key={i} className="skeleton h-9" />
                ))}
              </div>
            ) : res && !res.analysed ? (
              <div className="mt-2 border border-sev-medium-line bg-sev-medium-bg p-3 text-[11.5px] text-text2">
                <span className="font-bold text-sev-medium">Nothing was analysed.</span>{" "}
                {res.reason ?? "The resilience analyzer reports it had nothing to work on."} An empty list here is not a
                statement that this estate has no single point of failure.
              </div>
            ) : walk.length === 0 ? (
              <p className="mt-2 text-[12px] text-text2">
                The analysis ran and returned no finding that names a device on this canvas.
              </p>
            ) : (
              <ul className="mt-2 grid gap-1.5 lg:grid-cols-2">
                {walk.map((f, i) => (
                  <li key={f.id}>
                    <button
                      type="button"
                      onClick={() => openFullscreen(i)}
                      className="row flex w-full items-start gap-2 border border-border bg-surface px-2.5 py-2 text-left hover:border-accent"
                    >
                      <span className="mono w-5 shrink-0 pt-0.5 text-[10px] tabular-nums text-text3">{i + 1}</span>
                      <span className="min-w-0 flex-1">
                        <span className="block truncate text-[12px] font-bold">{f.title}</span>
                        <span className="mono block truncate text-[10.5px] text-text3">{f.type}</span>
                      </span>
                      <SeverityPill band={f.band} severity={f.severity} forced={f.forcedCritical} />
                    </button>
                  </li>
                ))}
              </ul>
            )}

            {/* The analyzer's caveats. An empty findings list is only readable
                next to what the analysis could not see. */}
            {res && res.caveats && res.caveats.length > 0 ? (
              <div className="mt-3 border-t border-hair pt-2">
                <div className="label mb-1">What this analysis could not see</div>
                <ul className="space-y-1">
                  {res.caveats.map((c, i) => (
                    <li key={i} className="text-[11px] leading-snug text-text2">
                      {c}
                    </li>
                  ))}
                </ul>
              </div>
            ) : null}

            {res && (res.suppressed.length > 0 || res.excluded_adjacencies.length > 0) ? (
              <details className="mt-3 border-t border-hair pt-2">
                <summary className="cursor-pointer text-[11.5px] text-text2">
                  {res.suppressed.length} candidate finding{res.suppressed.length === 1 ? "" : "s"} suppressed
                  {res.excluded_adjacencies.length > 0
                    ? `, ${res.excluded_adjacencies.length} adjacenc${res.excluded_adjacencies.length === 1 ? "y" : "ies"} excluded`
                    : ""}{" "}
                  — every one of them with its reason
                </summary>
                <p className="mt-1.5 text-[11px] leading-snug text-text3">
                  The resilience analyzer publishes what it chose not to report. An estate cabled the right way nearly
                  everywhere would otherwise bury its four real findings in fourteen false ones, and a filter nobody can
                  audit is indistinguishable from a bug.
                </p>
                <ul className="mt-1.5 space-y-1">
                  {res.suppressed.map((x, i) => (
                    <li key={`s${i}`} className="text-[11px] text-text2">
                      <span className="mono text-text3">{x.kind}</span> · <span className="mono">{x.candidate}</span> —{" "}
                      {x.detail}
                    </li>
                  ))}
                  {res.excluded_adjacencies.map((x, i) => (
                    <li key={`e${i}`} className="text-[11px] text-text2">
                      <span className="mono text-text3">{x.reason}</span> — {x.detail}
                    </li>
                  ))}
                </ul>
              </details>
            ) : null}
          </section>

          {/* ── Legend ──────────────────────────────────────────────────────── */}
          <section className="panel p-4">
            <div className="mb-3 flex items-center gap-2">
              <Eyebrow>Legend</Eyebrow>
            </div>
            <Legend
              redundancy={[...redundancy.values()]}
              vlanBands={[...vlanBands.values()]}
              hasContainment={hasContainment}
              hasAggregated={hasAggregated}
              hasHa={hasHa}
            />
          </section>
        </>
      )}

      {/* ── Fullscreen ────────────────────────────────────────────────────── */}
      {mounted && fullscreen && !topoErr
        ? createPortal(
            <div
              ref={fsRef}
              tabIndex={-1}
              role="dialog"
              aria-modal="true"
              aria-label="Network topology, fullscreen"
              className="fixed inset-0 z-[70] flex flex-col bg-bg outline-none"
            >
              <header className="flex shrink-0 flex-wrap items-center gap-2 border-b border-border px-3 py-2">
                <Eyebrow>Topology</Eyebrow>
                <span className="mono hidden text-[11px] text-text3 sm:inline">
                  {layout.lanes.length} lanes · {layout.nodes.length} cards · {layout.links.length} links
                </span>
                {sel ? (
                  <span className="mono text-[11px] tabular-nums text-text2">
                    finding {(selIndex ?? 0) + 1} of {walk.length}
                  </span>
                ) : null}
                <div className="ml-auto flex items-center gap-1.5">
                  <ZoomBar zoom={zoom} setZoom={setZoom} onFit={fit} />
                  <button type="button" onClick={closeFullscreen} className="btn-ghost text-[12px]" autoFocus>
                    <Minimize2 size={13} /> Exit <span className="mono ml-1 text-text3">Esc</span>
                  </button>
                </div>
              </header>
              <div className="flex min-h-0 flex-1">
                <div className="min-w-0 flex-1">{canvas}</div>
                {sidebar}
              </div>
            </div>,
            document.body,
          )
        : null}
    </div>
  );
}

export default TopologyPanel;
