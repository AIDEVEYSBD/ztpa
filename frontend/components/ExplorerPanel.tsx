"use client";

/**
 * THE EXPLORER — one canvas for one network.
 *
 * There used to be two screens here and they were two pictures of the same
 * estate. "Topology" drew the physical layers outside-in from what the consoles
 * cabled together; "Reachability" drew the cross-tool policy chain on its own
 * force-laid graph with its own positions. A reader had to hold both in their
 * head to notice that the chain ends on a host sitting in VLAN 50 behind the
 * core pair — which is the entire point of computing the chain.
 *
 * They are one screen now because they can be: the chain's terminal has a VLAN,
 * a subnet and a place in the endpoint lane, so the policy path can be traced
 * ACROSS the layered canvas instead of beside it. The lanes are the permanent
 * base; everything else is an overlay over them:
 *
 *   off            just the network. Nothing dimmed, everything clickable.
 *   reachability   the cross-tool chain, hop by hop, with the panel that
 *                  explains it. The product's one differentiated computation,
 *                  drawn on the estate it runs through.
 *   findings       the walkthrough: dim to what a finding names, trace it, and
 *                  play a resilience failure as a blast radius.
 *
 * Switching between them never costs canvas state — the zoom, the pan and which
 * lanes are expanded survive, because they are the reader's place in the
 * diagram and not a property of the overlay.
 *
 * WHAT THE CANVAS STILL REFUSES TO DO, unchanged and load-bearing: an
 * `observed: false` lane is a NAMED ABSENCE and never a ghost device; an
 * inventoried device with no reported cable gets a dashed card and its own rail;
 * a null count is an em-dash with a reason and never a zero; a capped response
 * says so and names the capped lanes; and a `containment` link stays dashed,
 * because two interfaces provably sharing an address block is an L3 observation
 * and is not a cable.
 *
 * AND WHAT WAS BROKEN AND IS NOT ANY MORE. Selecting a finding and then closing
 * the panel used to leave the canvas dimmed on that finding with no way back:
 * there is now exactly ONE selection, and closing a panel, pressing Esc, or
 * clicking empty canvas all clear it.
 */

import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { createPortal } from "react-dom";
import {
  AlertTriangle,
  Keyboard,
  Layers,
  Maximize2,
  Minimize2,
  Play,
  Route,
  Scan,
  Unlink,
  X,
  ZoomIn,
  ZoomOut,
} from "lucide-react";
import {
  api,
  asApiError,
  type ApiError,
  type GraphPayload,
  type ResiliencePayload,
  type TopologyPayload,
} from "@/lib/api";
import type { BlastRadius, Finding, SourceCard, TopoNode } from "@/lib/types";
import { cn } from "@/lib/cn";
import { Chip, Eyebrow, SeverityPill, StatPill } from "./ui";
import { ErrorState, InlineError } from "./ui/Feedback";
import { NetIcon } from "./net/icons";
import { Canvas, type FocusView } from "./topology/Canvas";
import { FindingSidebar } from "./topology/FindingSidebar";
import { HopPanel } from "./topology/HopPanel";
import { Legend } from "./topology/Legend";
import { NodeDrawer } from "./topology/NodeDrawer";
import { SearchBox } from "./topology/SearchBox";
import { buildLayout, EVIDENCE_COPY, evidenceTier, GEOM, orderHops, type Layout } from "./topology/layout";
import { buildRedundancyBands, buildVlanBands, unknownVlanBand, type VlanBand } from "./topology/palette";
import { fromPolicy, fromResilience, involvedCards, sortWalk, type WalkFinding } from "./topology/findings";
import { normalisePaths, placePath, type CrossToolPath } from "./topology/paths";
import { searchableFrom, searchNodes, vlanIndex, type ExplorerNode } from "./topology/node";

/** How long one hop of a trace, or one batch of a blast reveal, is on screen. */
const STAGE_MS = 520;
/** Never more than this many ticks in a blast replay, however wide the radius:
 *  a 200-device isolation should take four seconds, not a hundred. */
const MAX_BLAST_TICKS = 14;
/**
 * Below this the side panel stops being a rail beside the canvas and becomes a
 * sheet over it — and it is measured against the EXPLORER'S OWN WIDTH, not the
 * window's.
 *
 * The distinction is the whole fix. On a 1280px laptop the console's nav rail
 * and page padding take ~250px before this screen gets any, so a breakpoint
 * read off the viewport docks a 400px panel into a 1030px column and leaves the
 * diagram 630px — the panel eating half the canvas it is describing, which is
 * exactly the complaint. Below this the panel slides over the canvas instead,
 * and the canvas keeps its full width underneath.
 */
const DOCK_AT = 860;

const clamp = (v: number, lo: number, hi: number) => Math.min(hi, Math.max(lo, v));

/**
 * The lowest zoom "Fit" will choose.
 *
 * Fit fits the WIDTH, and it stops here rather than shrinking until everything
 * is on screen, because a diagram whose hostnames cannot be read is not a
 * diagram that fits — it is a picture of one.
 */
const FIT_MIN = 0.72;

export type ExplorerOverlay = "off" | "reachability" | "findings";

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

/** True once the viewport is at least `px` wide. False during SSR and on the
 *  first client paint, which is the safe direction: the sheet layout works at
 *  every width, the docked rail does not. */
function useMinWidth(px: number): boolean {
  const [wide, setWide] = useState(false);
  useEffect(() => {
    if (typeof window === "undefined" || !window.matchMedia) return;
    const mq = window.matchMedia(`(min-width: ${px}px)`);
    const sync = () => setWide(mq.matches);
    sync();
    mq.addEventListener("change", sync);
    return () => mq.removeEventListener("change", sync);
  }, [px]);
  return wide;
}

/**
 * The measured width of one element, via ResizeObserver.
 *
 * Every layout decision on this screen that used to read `vw` now reads this
 * instead: `vw` is the window, and the window is not what this panel has.
 */
function useWidth<T extends HTMLElement>(): [(el: T | null) => void, number] {
  const [w, setW] = useState(0);
  const ro = useRef<ResizeObserver | null>(null);
  const ref = useCallback((el: T | null) => {
    ro.current?.disconnect();
    ro.current = null;
    if (!el) return;
    setW(el.clientWidth);
    if (typeof ResizeObserver === "undefined") return;
    ro.current = new ResizeObserver(() => setW(el.clientWidth));
    ro.current.observe(el);
  }, []);
  return [ref, w];
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
    <div className="flex shrink-0 items-center gap-1">
      <button
        type="button"
        onClick={() => setZoom(clamp(zoom - 0.1, 0.5, 1.6))}
        className="btn-ghost !h-7 !w-7 !px-0"
        aria-label="Zoom out"
      >
        <ZoomOut size={13} />
      </button>
      <span className="mono hidden w-9 text-center text-[11px] tabular-nums text-text3 sm:inline">
        {Math.round(zoom * 100)}%
      </span>
      <button
        type="button"
        onClick={() => setZoom(clamp(zoom + 0.1, 0.5, 1.6))}
        className="btn-ghost !h-7 !w-7 !px-0"
        aria-label="Zoom in"
      >
        <ZoomIn size={13} />
      </button>
      <button
        type="button"
        onClick={onFit}
        className="btn-ghost !h-7 px-2 text-[11px]"
        title="Fit the canvas to the width available — stopping at 72%, below which the hostnames stop being readable (f)"
      >
        <Scan size={12} /> <span className="hidden sm:inline">Fit</span>
      </button>
    </div>
  );
}

/** The overlay switch. Each option carries its own count, because "Findings"
 *  with nothing behind it and "Findings · 7" are different offers. */
function OverlaySwitch({
  value,
  onChange,
  pathCount,
  findingCount,
  pathsReady,
  findingsReady,
}: {
  value: ExplorerOverlay;
  onChange: (v: ExplorerOverlay) => void;
  pathCount: number;
  findingCount: number;
  pathsReady: boolean;
  findingsReady: boolean;
}) {
  const opts: {
    id: ExplorerOverlay;
    label: string;
    count: number | null;
    title: string;
  }[] = [
    {
      id: "off",
      label: "Network",
      count: null,
      title: "Just the estate: nothing dimmed, every card clickable.",
    },
    {
      id: "reachability",
      label: "Reachability",
      count: pathsReady ? pathCount : null,
      title: "Trace the cross-tool policy chain across these lanes — the path no single console can show you.",
    },
    {
      id: "findings",
      label: "Findings",
      count: findingsReady ? findingCount : null,
      title: "Walk the findings that name a device on this canvas, one at a time.",
    },
  ];
  return (
    <div className="flex shrink-0 border border-border text-[11px]" role="tablist" aria-label="Canvas overlay">
      {opts.map((o, i) => (
        <button
          key={o.id}
          type="button"
          role="tab"
          aria-selected={value === o.id}
          title={o.title}
          onClick={() => onChange(o.id)}
          className={cn(
            "flex items-center gap-1.5 px-2.5 py-1 transition-colors",
            i > 0 && "border-l border-border",
            value === o.id ? "bg-accent-soft font-bold text-accent-fg" : "text-text2 hover:bg-surfaceHover",
          )}
        >
          {o.label}
          {o.count != null ? <span className="mono text-[10px] tabular-nums opacity-70">{o.count}</span> : null}
        </button>
      ))}
    </div>
  );
}

function Shortcuts({ className }: { className?: string }) {
  const rows: [string, string][] = [
    ["/", "search"],
    ["Esc", "clear selection"],
    ["↑ ↓", "walk findings"],
    ["f", "fit"],
  ];
  return (
    <div className={cn("flex flex-wrap items-center gap-x-3 gap-y-1 text-[10.5px] text-text3", className)}>
      <Keyboard size={11} className="shrink-0" />
      {rows.map(([k, what]) => (
        <span key={k} className="flex items-center gap-1">
          <kbd className="mono border border-border bg-sunk px-1 text-[9.5px] not-italic text-text2">{k}</kbd>
          {what}
        </span>
      ))}
    </div>
  );
}

/** Exactly one thing can be selected at a time, and there is always a way out
 *  of it. Modelling this as a single value is the whole fix for the selection
 *  that used to get stuck behind a closed panel. */
type Selection = { kind: "finding"; index: number } | { kind: "node"; cardId: string } | null;

export interface ExplorerPanelProps {
  snapshot?: string;
  /**
   * The console's policy findings. Optional, and filtered to the ones that name
   * a device on this canvas — a finding about two cloud workloads has nothing
   * to light up here.
   */
  findings?: Finding[];
  /** Set when the findings feed itself failed, so the walkthrough's "N findings"
   *  is never read as a complete set. */
  findingsError?: ApiError;
  /** Which overlay the screen opens on. Defaults to `off`: the estate, with
   *  nothing dimmed and everything clickable. */
  initialOverlay?: ExplorerOverlay;
}

export function ExplorerPanel({ snapshot, findings, findingsError, initialOverlay = "off" }: ExplorerPanelProps) {
  const reduced = useReducedMotion();
  const [workbenchRef, workbenchW] = useWidth<HTMLDivElement>();
  // The viewport query is only the FIRST PAINT's guess, before the workbench
  // has been measured; every paint after that uses the measurement.
  const wideWindow = useMinWidth(DOCK_AT + 260);
  const docked = workbenchW > 0 ? workbenchW >= DOCK_AT : wideWindow;

  const [topo, setTopo] = useState<TopologyPayload>();
  const [topoErr, setTopoErr] = useState<ApiError>();
  const [loading, setLoading] = useState(true);
  const [res, setRes] = useState<ResiliencePayload>();
  const [resErr, setResErr] = useState<ApiError>();
  const [resLoading, setResLoading] = useState(true);
  const [src, setSrc] = useState<SourceCard[]>();
  const [srcErr, setSrcErr] = useState<ApiError>();
  const [graph, setGraph] = useState<GraphPayload>();
  const [graphErr, setGraphErr] = useState<ApiError>();
  const [graphLoading, setGraphLoading] = useState(true);

  const [overlay, setOverlay] = useState<ExplorerOverlay>(initialOverlay);
  const [expanded, setExpanded] = useState<ReadonlySet<string>>(new Set<string>());
  const [zoom, setZoom] = useState(1);
  /** Width of the scroll viewport, as the canvas last measured it. */
  const [viewW, setViewW] = useState(0);
  const [fullscreen, setFullscreen] = useState(false);
  const [sidebarCollapsed, setSidebarCollapsed] = useState(false);
  const [selection, setSelection] = useState<Selection>(null);
  const [blastKey, setBlastKey] = useState<string | null>(null);
  const [stage, setStage] = useState(0);
  const [replayNonce, setReplayNonce] = useState(0);
  const [explainingId, setExplainingId] = useState<string>();
  const [explainErr, setExplainErr] = useState<ApiError>();
  const [explained, setExplained] = useState<Record<string, string>>({});
  const [mounted, setMounted] = useState(false);
  const [pathIndex, setPathIndex] = useState(0);
  const [reachStage, setReachStage] = useState(0);
  const [reachNonce, setReachNonce] = useState(0);
  const [query, setQuery] = useState("");
  const [matchIndex, setMatchIndex] = useState(0);
  const [searchFocusNonce, setSearchFocusNonce] = useState(0);
  const [focusRequest, setFocusRequest] = useState<{
    id: string;
    nonce: number;
  } | null>(null);
  const focusNonce = useRef(0);

  useEffect(() => setMounted(true), []);

  const load = useCallback(() => {
    let live = true;
    setLoading(true);
    setResLoading(true);
    setGraphLoading(true);
    setTopoErr(undefined);
    setResErr(undefined);
    setSrcErr(undefined);
    setGraphErr(undefined);
    api
      .topology(snapshot)
      // A failed topology read must not leave the last good lanes on screen: a
      // stale picture with a fresh header is the worst of both.
      .then((t) => {
        if (live) setTopo(t);
      })
      .catch((e) => {
        if (live) {
          setTopo(undefined);
          setTopoErr(asApiError(e));
        }
      })
      .finally(() => {
        if (live) setLoading(false);
      });
    api
      .resilience(snapshot)
      .then((r) => {
        if (live) setRes(r);
      })
      .catch((e) => {
        if (live) {
          setRes(undefined);
          setResErr(asApiError(e));
        }
      })
      .finally(() => {
        if (live) setResLoading(false);
      });
    api
      .sources(snapshot)
      .then((s) => {
        if (live) setSrc(s.sources);
      })
      // Undefined, not []: an empty source list would render as "no source is a
      // seeded export", which is the flattering reading of a failed fetch.
      .catch((e) => {
        if (live) {
          setSrc(undefined);
          setSrcErr(asApiError(e));
        }
      });
    api
      .graph(snapshot)
      .then((g) => {
        if (live) setGraph(g);
      })
      .catch((e) => {
        if (live) {
          setGraph(undefined);
          setGraphErr(asApiError(e));
        }
      })
      .finally(() => {
        if (live) setGraphLoading(false);
      });
    return () => {
      live = false;
    };
  }, [snapshot]);

  useEffect(() => load(), [load]);

  // ── Derived model ───────────────────────────────────────────────────────
  const lanes = useMemo(() => topo?.lanes ?? [], [topo]);
  const links = useMemo(() => topo?.links ?? [], [topo]);

  // The lanes wrap to the width actually available rather than to a constant,
  // so a 1280px laptop — or a fullscreen canvas with a panel open beside it —
  // gets a narrower, taller picture at full zoom instead of a wide one shrunk
  // until the hostnames stop being readable.
  const maxRowW = viewW > 0 ? clamp(viewW - GEOM.labelW - GEOM.padRight, GEOM.minContentW, GEOM.maxRowW) : GEOM.maxRowW;

  const layout: Layout = useMemo(
    () => buildLayout(lanes, links, { expanded, maxRowW }),
    [lanes, links, expanded, maxRowW],
  );

  const allNodes = useMemo(() => lanes.flatMap((l) => l.nodes), [lanes]);
  const nodeByKey = useMemo(() => new Map(allNodes.map((n) => [n.key, n])), [allNodes]);
  const nameFor = useCallback((key: string) => nodeByKey.get(key)?.name || key, [nodeByKey]);
  const laneLabel = useMemo(() => new Map(layout.lanes.map((l) => [String(l.layer), l.label])), [layout.lanes]);

  const vlanBands = useMemo(() => buildVlanBands(topo?.vlans ?? []), [topo]);
  const vlanFacts = useMemo(() => vlanIndex(topo?.vlans), [topo]);
  const segmentKeys = useMemo(
    () => new Set(lanes.filter((l) => l.layer === "segment").flatMap((l) => l.nodes.map((n) => n.key))),
    [lanes],
  );
  // Only the segment lane is banded. A trunk carrying nine VLANs is not a
  // segment, and painting it would make the band mean two different things.
  const bandsFor = useCallback(
    (n: TopoNode): VlanBand[] =>
      segmentKeys.has(n.key) ? (n.vlan_ids ?? []).map((id) => vlanBands.get(id) ?? unknownVlanBand(id)) : [],
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
      .map((n) => ({
        device_key: n.key,
        reason: n.unlinked_reason!,
        would_be_filled_by: n.would_be_filled_by ?? "",
      }));
    return [...declared, ...extra];
  }, [topo, allNodes]);

  const policy = useMemo(() => fromPolicy(findings ?? [], allNodes), [findings, allNodes]);
  const walk = useMemo(() => {
    const fromRes = res ? fromResilience(res.findings, res.blast_radius) : [];
    const items = sortWalk([...fromRes, ...policy.items]);
    // Prose fetched in this session becomes the item's MODEL detail. It never
    // touches the engine's own explanation, which stays on screen beside it.
    return items.map((i) => (explained[i.id] ? { ...i, modelDetail: explained[i.id] } : i));
  }, [res, policy.items, explained]);

  const blastByDevice = useMemo(() => new Map((res?.blast_radius ?? []).map((b) => [b.device_key, b])), [res]);

  // ── The cross-tool chain ────────────────────────────────────────────────
  const paths: CrossToolPath[] = useMemo(() => normalisePaths(graph?.cross_tool_paths), [graph]);
  const pathIdx = paths.length > 0 ? Math.min(pathIndex, paths.length - 1) : 0;
  const selectedPath = paths[pathIdx];
  const placedPath = useMemo(() => placePath(selectedPath, layout), [selectedPath, layout]);
  const graphReady = !graphLoading && !graphErr;

  // Clamped against the CURRENT list: a reload that shrinks the findings must
  // not leave a selection pointing past the end, which would put "4 of 2" in
  // the panel and dim the canvas for a finding that is no longer there.
  const selIndex =
    selection?.kind === "finding" && selection.index >= 0 && selection.index < walk.length ? selection.index : null;
  const sel: WalkFinding | undefined = selIndex == null ? undefined : walk[selIndex];
  const selectedCard = selection?.kind === "node" ? selection.cardId : null;
  const selectedNode = selectedCard ? (layout.byId.get(selectedCard)?.node as ExplorerNode | undefined) : undefined;

  // ── Selection, and the one way out of it ────────────────────────────────
  const clearSelection = useCallback(() => {
    setSelection(null);
    setBlastKey(null);
  }, []);

  const selectNode = useCallback((cardId: string) => {
    setBlastKey(null);
    setSelection({ kind: "node", cardId });
  }, []);

  const selectFindingIndex = useCallback((i: number) => {
    setBlastKey(null);
    setOverlay("findings");
    setSidebarCollapsed(false);
    setSelection({ kind: "finding", index: i });
  }, []);

  const selectFindingById = useCallback(
    (id: string) => {
      const i = walk.findIndex((f) => f.id === id);
      if (i >= 0) selectFindingIndex(i);
    },
    [walk, selectFindingIndex],
  );

  // ── The staged animation for a finding ──────────────────────────────────
  const anim = useMemo(() => {
    if (!sel) return null;
    const nodes = involvedCards(sel, layout.cardFor);
    // The adjacencies the finding names outright, resolved to drawn lines.
    const named = new Set(sel.involved.map((k) => layout.linkByRawId.get(k)).filter((id): id is string => !!id));
    // A named link's two ends are part of the finding whether or not the
    // payload also listed them as devices.
    for (const id of named) {
      const l = layout.linkById.get(id);
      if (l) {
        nodes.add(l.a);
        nodes.add(l.b);
      }
    }
    const hops = orderHops(layout, nodes, named);
    // What the cut costs, straight off `blast_radius`: the stranded circuits
    // and the isolated devices, in that order, resolved to cards.
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

  // ── "Lose this device", from the node drawer ────────────────────────────
  const blastAnim = useMemo(() => {
    if (!blastKey) return null;
    const br: BlastRadius | undefined = blastByDevice.get(blastKey);
    if (!br) return null;
    const failedCard = layout.cardFor.get(blastKey);
    const failed = new Set(failedCard ? [failedCard] : []);
    const lost = [
      ...new Set(
        [...br.circuits_stranded, ...br.devices_isolated]
          .map((k) => layout.cardFor.get(k))
          .filter((k): k is string => !!k),
      ),
    ];
    const batch = lost.length > 0 ? Math.max(1, Math.ceil(lost.length / MAX_BLAST_TICKS)) : 1;
    const ticks = lost.length > 0 ? Math.ceil(lost.length / batch) : 0;
    return { radius: br, failed, lost, batch, total: 1 + ticks, nodes: failed };
  }, [blastKey, blastByDevice, layout]);

  const activeAnim = blastAnim ?? anim;
  const totalStages = blastAnim ? blastAnim.total : (anim?.total ?? 0);
  // Keyed on the finding's ID rather than on `sel` itself: the parent re-renders
  // with a fresh `findings` array on every console tick, which gives every item
  // a new object identity, and an effect that depended on the object would
  // restart the trace from hop one several times a second.
  const animKey = blastKey ? `blast:${blastKey}` : (sel?.id ?? "");

  useEffect(() => {
    if (!animKey || totalStages <= 0) {
      setStage(0);
      return;
    }
    // Reduced motion: no travelling dash and no staged fade — the same end
    // state, arrived at immediately, with the panel text unchanged.
    if (reduced || totalStages <= 1) {
      setStage(totalStages);
      return;
    }
    setStage(0);
    let i = 0;
    const id = window.setInterval(() => {
      i += 1;
      setStage(i);
      if (i >= totalStages) window.clearInterval(id);
    }, STAGE_MS);
    return () => window.clearInterval(id);
    // `replayNonce` restarts the same animation on demand.
  }, [animKey, totalStages, reduced, replayNonce]);

  const isBlastMode = !!blastAnim || anim?.mode === "blast";
  const lostShown =
    activeAnim && isBlastMode ? (stage === 0 ? 0 : Math.min(activeAnim.lost.length, stage * activeAnim.batch)) : 0;

  // ── The chain's own reveal ──────────────────────────────────────────────
  const hopCount = placedPath?.hops.length ?? 0;
  useEffect(() => {
    if (overlay !== "reachability" || hopCount === 0) {
      setReachStage(0);
      return;
    }
    if (reduced || hopCount <= 1) {
      setReachStage(hopCount);
      return;
    }
    setReachStage(0);
    let i = 0;
    const id = window.setInterval(() => {
      i += 1;
      setReachStage(i);
      if (i >= hopCount) window.clearInterval(id);
    }, STAGE_MS);
    return () => window.clearInterval(id);
  }, [overlay, hopCount, pathIdx, reduced, reachNonce]);

  // ── What the canvas dims, lights and fades ──────────────────────────────
  const focus: FocusView | null = useMemo(() => {
    // 1. A failure being played beats everything: it is the thing the reader
    //    asked to see.
    if (blastAnim) {
      return {
        nodes: blastAnim.nodes,
        lit: new Set<string>(),
        failed: blastAnim.failed,
        isolated: new Set(blastAnim.lost.slice(0, lostShown)),
        mode: "blast",
      };
    }
    // 2. A selected finding.
    if (anim) {
      // A finding whose devices are all off this canvas must dim NOTHING. The
      // alternative — an empty involved set fed to the dimmer — blanks the
      // whole picture and reads as a rendering failure; the panel says so in
      // words instead.
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
    }
    // 3. The chain, when its overlay is on and it actually landed on cards.
    if (overlay === "reachability" && placedPath && placedPath.cards.length > 0) {
      const reached = new Set<string>();
      for (const h of placedPath.hops) {
        if (h.index >= reachStage) continue;
        reached.add(h.from.id);
        reached.add(h.to.id);
      }
      if (reached.size === 0) return null;
      return {
        nodes: reached,
        lit: new Set<string>(),
        failed: new Set<string>(),
        isolated: new Set<string>(),
        mode: "reach",
      };
    }
    // 4. Nothing selected, no overlay: nothing dimmed, everything clickable.
    return null;
  }, [blastAnim, anim, stage, lostShown, overlay, placedPath, reachStage]);

  // ── Search ──────────────────────────────────────────────────────────────
  const corpus = useMemo(() => searchableFrom(layout.nodes), [layout.nodes]);
  const hits = useMemo(() => searchNodes(query, corpus), [query, corpus]);
  const activeHit = hits.length > 0 ? hits[Math.min(matchIndex, hits.length - 1)] : undefined;
  const matchCards = useMemo(() => new Set(hits.map((h) => h.cardId)), [hits]);

  useEffect(() => {
    setMatchIndex(0);
  }, [query]);

  const focusCard = useCallback((id: string) => {
    focusNonce.current += 1;
    setFocusRequest({ id, nonce: focusNonce.current });
  }, []);

  /**
   * Follow the trace.
   *
   * The chain runs from the internet lane to the endpoint lane, which is the
   * full height of a nine-lane canvas: at a zoom where the hostnames are
   * readable it does not fit on any screen at once, and a reveal the reader
   * cannot see is a reveal that did not happen. So the canvas walks the chain
   * with it, one hop at a time, landing on the terminal. Under reduced motion
   * the stage jumps straight to the end and this lands there in one move.
   */
  useEffect(() => {
    if (overlay !== "reachability" || !placedPath || reachStage <= 0) return;
    const hop = placedPath.hops.find((h) => h.index === reachStage - 1);
    if (hop) focusCard(hop.to.id);
  }, [overlay, placedPath, reachStage, focusCard]);

  // Landing on a hit: expand the lane if it is hiding inside a group card, then
  // centre it. A search that finds something it cannot show you is worse than
  // one that finds nothing.
  useEffect(() => {
    if (!activeHit) return;
    if (activeHit.viaGroup)
      setExpanded((prev) => (prev.has(activeHit.layer) ? prev : new Set([...prev, activeHit.layer])));
    focusCard(activeHit.cardId);
  }, [activeHit, focusCard]);

  // ── Viewport, zoom, fullscreen ──────────────────────────────────────────
  const viewportW = useRef(0);
  const layoutW = useRef<number>(GEOM.maxRowW);
  layoutW.current = layout.width;
  const fitPending = useRef(false);
  const toggleRef = useRef<HTMLButtonElement | null>(null);
  /** Where the canvas is looking, in LAYOUT coordinates, kept out here so going
   *  fullscreen — which remounts the canvas into a portal, refits the zoom and
   *  re-flows the lanes — keeps the reader's place. */
  const scrollMemo = useRef({ cx: 0, cy: 0 });

  const onViewport = useCallback((w: number) => {
    viewportW.current = w;
    // A few px of jitter (a scrollbar appearing) must not re-flow the lanes.
    setViewW((prev) => (Math.abs(prev - w) > 8 ? w : prev));
  }, []);

  // A pending fit is applied HERE rather than inside `onViewport`, because a new
  // viewport width re-flows the lanes and therefore changes `layout.width`.
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

  const openFullscreen = useCallback(() => {
    fitPending.current = true;
    setFullscreen(true);
  }, []);

  const closeFullscreen = useCallback(() => {
    setFullscreen(false);
    setZoom(1);
    toggleRef.current?.focus();
  }, []);

  const step = useCallback(
    (delta: number) => {
      if (walk.length === 0) return;
      setOverlay("findings");
      setSidebarCollapsed(false);
      setBlastKey(null);
      setSelection((cur) => {
        const base = cur?.kind === "finding" && cur.index < walk.length ? cur.index : -1;
        return {
          kind: "finding",
          index: clamp(base + delta, 0, walk.length - 1),
        };
      });
    },
    [walk.length],
  );

  // ── Keyboard ────────────────────────────────────────────────────────────
  const hasSelection = selection != null;
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      const el = e.target as HTMLElement | null;
      const typing = !!el && (el.tagName === "INPUT" || el.tagName === "TEXTAREA" || el.isContentEditable);

      if (e.key === "Escape") {
        // Esc unwinds ONE layer at a time, innermost first. It only leaves
        // fullscreen once there is nothing selected to clear, so a reader can
        // never be dropped out of the canvas while something is still dimmed.
        if (typing) return;
        if (hasSelection) {
          e.preventDefault();
          clearSelection();
          return;
        }
        if (query) {
          e.preventDefault();
          setQuery("");
          return;
        }
        if (fullscreen) {
          e.preventDefault();
          closeFullscreen();
        }
        return;
      }
      if (typing) return;

      if (e.key === "/") {
        e.preventDefault();
        setSearchFocusNonce((n) => n + 1);
        return;
      }
      if (e.key === "f" || e.key === "F") {
        e.preventDefault();
        fit();
        return;
      }
      if (walk.length === 0) return;
      if (e.key === "ArrowRight" || e.key === "ArrowDown") {
        e.preventDefault();
        step(1);
      }
      if (e.key === "ArrowLeft" || e.key === "ArrowUp") {
        e.preventDefault();
        step(-1);
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [hasSelection, clearSelection, query, fullscreen, closeFullscreen, fit, step, walk.length]);

  // Fullscreen locks the page behind it.
  useEffect(() => {
    if (!fullscreen) return;
    const prev = document.body.style.overflow;
    document.body.style.overflow = "hidden";
    return () => {
      document.body.style.overflow = prev;
    };
  }, [fullscreen]);

  /**
   * ...and takes it out of the tab order and off the accessibility tree while
   * it is up. `aria-modal` alone confines a screen reader but leaves the inline
   * toolbar Tab-reachable BEHIND the dialog, where the same "Findings" tab and
   * the same search field exist twice with the same names. Exactly one canvas
   * is operable at a time.
   *
   * Set imperatively because React 18 has no `inert` prop: passing one warns
   * about a non-boolean attribute and renders inconsistently across builds.
   */
  const inlineRef = useRef<HTMLDivElement | null>(null);
  useEffect(() => {
    const el = inlineRef.current;
    if (!el || !fullscreen) return;
    el.setAttribute("inert", "");
    el.setAttribute("aria-hidden", "true");
    return () => {
      el.removeAttribute("inert");
      el.removeAttribute("aria-hidden");
    };
  }, [fullscreen]);

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

  /**
   * The same rule for the chain, and it is the difference between the overlay
   * working and not: fourteen hosts in the endpoint lane collapse to group
   * cards by role, and all four of this estate's chain hops land INSIDE that
   * one card. The trace then draws a single line into a group and reports three
   * hops it could not draw — technically honest and completely useless. The
   * lanes the chain runs through are opened for it.
   */
  const pathLanesToOpen = useMemo(() => {
    if (overlay !== "reachability" || !selectedPath) return "";
    const needed = new Set<string>();
    for (const key of selectedPath.path) {
      const card = layout.cardFor.get(key);
      if (card?.startsWith("grp:")) needed.add(card.split(":")[1]);
    }
    return [...needed].sort().join(",");
  }, [overlay, selectedPath, layout]);

  const openLanes = useCallback((spec: string) => {
    if (!spec) return;
    setExpanded((prev) => {
      const next = new Set(prev);
      let changed = false;
      for (const layer of spec.split(","))
        if (!next.has(layer)) {
          next.add(layer);
          changed = true;
        }
      return changed ? next : prev;
    });
  }, []);

  useEffect(() => {
    openLanes(lanesToOpen);
  }, [lanesToOpen, openLanes]);
  useEffect(() => {
    openLanes(pathLanesToOpen);
  }, [pathLanesToOpen, openLanes]);

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
      if (r.explanation) setExplained((m) => ({ ...m, [item.id]: r.explanation as string }));
      // A model was asked and produced nothing. That is a FINISHED answer, and
      // telling the user to "try again in a moment" would send them round a
      // loop with no exit -- the engine's own explanation above is the whole of
      // what this deployment can say.
      else if (r.unavailable_reason)
        setExplainErr(asApiError(new Error(r.unavailable_reason)));
      else if (r.pending)
        setExplainErr(
          asApiError(new Error(
            `The advisory layer${r.provider ? ` (${r.provider})` : ""} is writing this now. `
            + "The engine's explanation above is complete and does not depend on it.",
          )),
        );
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

  const neighbours = useMemo(() => {
    if (!selectedCard) return [];
    return layout.links
      .filter((l) => l.a === selectedCard || l.b === selectedCard)
      .map((l) => {
        const other = l.a === selectedCard ? l.b : l.a;
        const p = layout.byId.get(other);
        return {
          id: other,
          name: p?.node?.name || p?.role || other,
          evidence: EVIDENCE_COPY[evidenceTier(l.evidence)].label,
        };
      });
  }, [selectedCard, layout]);

  const nodeConflicts = useMemo(() => {
    if (!selectedNode) return [];
    return (topo?.source_conflicts ?? []).filter((c) => c.entity === selectedNode.key);
  }, [topo, selectedNode]);

  const canvas = (
    <Canvas
      layout={layout}
      bandsFor={bandsFor}
      redundancy={redundancy}
      simulatedTools={simulatedTools}
      unlinked={unlinked}
      focus={focus}
      path={overlay === "reachability" ? placedPath : null}
      pathStage={overlay === "reachability" ? reachStage : 0}
      onToggleLane={toggleLane}
      onSelectNode={selectNode}
      selectedNode={selectedCard}
      matches={matchCards}
      activeMatch={activeHit?.cardId ?? null}
      focusRequest={focusRequest}
      onBackgroundClick={clearSelection}
      zoom={zoom}
      reduced={reduced}
      onViewport={onViewport}
      scrollMemo={scrollMemo}
    />
  );

  // Which side panel, if any. The node drawer wins: it is what the reader just
  // clicked on, and a click that opens nothing is the complaint this screen was
  // rebuilt to answer.
  const panelKind: "node" | "hops" | "findings" | null =
    selection?.kind === "node" && selectedNode
      ? "node"
      : overlay === "reachability"
        ? "hops"
        : overlay === "findings"
          ? "findings"
          : null;

  const panel =
    panelKind === "node" && selectedNode ? (
      <NodeDrawer
        node={selectedNode}
        layerLabel={
          laneLabel.get(String(layout.byId.get(selectedCard!)?.layer ?? "")) ??
          String(layout.byId.get(selectedCard!)?.layer ?? "")
        }
        vlans={vlanFacts}
        simulatedTools={simulatedTools}
        sourceConflicts={nodeConflicts}
        findings={walk}
        onSelectFinding={selectFindingById}
        neighbours={neighbours}
        onSelectNode={selectNode}
        blast={blastByDevice.get(selectedNode.key)}
        blastRead={!resLoading}
        blastError={resErr}
        blastBasis={res?.blast_basis}
        simulating={blastKey === selectedNode.key}
        onSimulateLoss={() => {
          setBlastKey(selectedNode.key);
          setReplayNonce((n) => n + 1);
        }}
        onStopSimulation={() => setBlastKey(null)}
        unlinkedReason={unlinked.get(selectedNode.key) ?? selectedNode.unlinked_reason ?? null}
        snapshot={snapshot}
        onClose={clearSelection}
        className="h-full w-full"
      />
    ) : panelKind === "hops" ? (
      <HopPanel
        paths={paths}
        index={pathIdx}
        onIndex={(i) => {
          setPathIndex(i);
          setReachNonce((n) => n + 1);
        }}
        placed={placedPath}
        stage={reachStage}
        onReplay={() => setReachNonce((n) => n + 1)}
        onFocusCard={focusCard}
        ready={graphReady}
        error={graphErr}
        onRetry={load}
        onDismiss={() => setOverlay("off")}
        snapshot={snapshot}
        className="h-full w-full"
      />
    ) : panelKind === "findings" ? (
      <FindingSidebar
        items={walk}
        index={selIndex}
        onIndex={(i) => selectFindingIndex(clamp(i, 0, Math.max(0, walk.length - 1)))}
        onClearSelection={clearSelection}
        onDismiss={() => {
          clearSelection();
          setOverlay("off");
        }}
        collapsed={docked && sidebarCollapsed}
        // Collapsing hides the reason the canvas is dimmed, so it clears the
        // selection too. This is BUG 1, at its source.
        onToggleCollapsed={() => {
          clearSelection();
          setSidebarCollapsed((c) => !c);
        }}
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
        className="h-full w-full"
      />
    ) : null;

  /** The docked rail's width, as a share of what this screen actually has.
   *  Never a fixed 380px: on a laptop that is a third of the diagram. */
  const railWidth =
    panelKind === "findings" && sidebarCollapsed
      ? 42
      : workbenchW > 0
        ? clamp(Math.round(workbenchW * (panelKind === "node" ? 0.34 : 0.3)), 290, panelKind === "node" ? 440 : 390)
        : 340;

  const workbench = (
    <div ref={workbenchRef} className="relative flex min-h-0 flex-1">
      <div className="min-w-0 flex-1">{canvas}</div>

      {/* Docked beside the canvas on a wide screen… */}
      {panel && docked ? (
        <div className="shrink-0" style={{ width: railWidth }}>
          {panel}
        </div>
      ) : null}

      {/* …and a sheet over it on a narrow one, so the panel never eats the
          diagram it is describing. */}
      {panel && !docked ? (
        <>
          {/* The scrim carries its opacity as a STYLE, not as `bg-bg/70`: the
              palette tokens are CSS custom properties, and Tailwind v3's slash
              opacity modifier cannot apply to a `var()` colour — it compiles to
              nothing, and the scrim silently becomes invisible. */}
          <button
            type="button"
            aria-label="Close the panel"
            onClick={() => {
              clearSelection();
              if (panelKind !== "node") setOverlay("off");
            }}
            style={{ background: "var(--bg)", opacity: 0.72 }}
            className="absolute inset-0 z-20 cursor-default"
          />
          <div className="absolute inset-y-0 right-0 z-30 w-[min(94vw,430px)] shadow-pop">{panel}</div>
        </>
      ) : null}
    </div>
  );

  const toolbar = (
    <div className="flex flex-wrap items-center gap-2 border-b border-border px-3 py-2">
      <OverlaySwitch
        value={overlay}
        onChange={(v) => {
          setOverlay(v);
          // Switching overlays must not carry a stale dim across with it, and
          // must not cost the reader their place in the diagram: zoom, pan and
          // expanded lanes are all untouched here on purpose.
          if (v !== "findings") clearSelection();
          if (v === "reachability") {
            setReachNonce((n) => n + 1);
            clearSelection();
          }
        }}
        pathCount={paths.length}
        findingCount={walk.length}
        pathsReady={graphReady}
        findingsReady={!resLoading && !resErr}
      />
      <div className="order-last w-full min-w-0 sm:order-none sm:w-auto sm:min-w-[210px] sm:flex-1 sm:max-w-[330px]">
        <SearchBox
          value={query}
          onChange={setQuery}
          hits={hits}
          active={Math.min(matchIndex, Math.max(0, hits.length - 1))}
          onActive={setMatchIndex}
          corpusSize={corpus.length}
          focusNonce={searchFocusNonce}
        />
      </div>
      <div className="ml-auto flex shrink-0 items-center gap-1.5">
        {hasSelection ? (
          <button
            type="button"
            onClick={clearSelection}
            className="btn-ghost !h-7 px-2 text-[11px]"
            title="Clear the selection — the canvas un-dims and every card is clickable again (Esc)"
          >
            <X size={12} /> Clear
          </button>
        ) : null}
        <ZoomBar zoom={zoom} setZoom={setZoom} onFit={fit} />
        <button
          ref={toggleRef}
          type="button"
          onClick={() => (fullscreen ? closeFullscreen() : openFullscreen())}
          className="btn-ghost !h-7 px-2 text-[11px]"
          title={fullscreen ? "Leave fullscreen (Esc)" : "Fullscreen"}
        >
          {fullscreen ? <Minimize2 size={13} /> : <Maximize2 size={13} />}
          <span className="hidden lg:inline">{fullscreen ? "Exit" : "Fullscreen"}</span>
        </button>
      </div>
    </div>
  );

  /** The one-line offer that keeps the headline computation discoverable
   *  without dimming the canvas the moment the screen opens. */
  const reachCallout =
    overlay !== "reachability" && graphReady && paths.length > 0 ? (
      <div className="flex flex-wrap items-center gap-x-2 gap-y-1 border-b border-hair bg-sunk px-3 py-1.5 text-[11.5px] text-text2">
        <Route size={12} className="shrink-0 text-accent-fg" />
        <span className="min-w-0">
          <b className="text-text">{paths.length}</b> cross-tool path
          {paths.length === 1 ? "" : "s"} in this snapshot
          {paths[0]?.tools.length ? (
            <>
              {" "}
              — one crosses <b className="text-text">{paths[0].tools.length}</b> consoles to reach{" "}
              <span className="mono text-text">{paths[0].terminal}</span>
            </>
          ) : null}
          . No single console can show it.
        </span>
        <button
          type="button"
          onClick={() => {
            setOverlay("reachability");
            clearSelection();
          }}
          className="btn-ghost !h-6 ml-auto shrink-0 px-2 text-[10.5px]"
        >
          Trace it
        </button>
      </div>
    ) : null;

  return (
    <>
      <div ref={inlineRef} className="space-y-4">
        {/* ── Header: what this is, and the estate's own counts ─────────────── */}
        <div className="panel p-4">
          <div className="flex flex-wrap items-start gap-3">
            <div className="min-w-0 flex-1">
              <Eyebrow>Explorer</Eyebrow>
              <p className="mt-1.5 max-w-3xl text-[12px] leading-relaxed text-text2">
                One network, one canvas. The estate is drawn outside-in — internet to endpoint, one band per layer —
                from what the onboarded consoles reported; the cross-tool policy chain is traced across those same lanes
                rather than on a second picture of its own. A lane nobody observed is named rather than drawn, a device
                nobody reported a cable for is listed on its own rail, and a link that rests on address containment is
                dashed rather than blended in with the cables. Click any card for everything one node is, down to the
                rules that reach it.
              </p>
            </div>
            <div className="flex shrink-0 flex-wrap items-center gap-1.5">
              {graphReady && paths.length > 0 ? (
                <button
                  type="button"
                  onClick={() => {
                    setOverlay("reachability");
                    clearSelection();
                  }}
                  className="btn-ghost text-[12px]"
                >
                  <Route size={12} /> Trace {paths.length} path
                  {paths.length === 1 ? "" : "s"}
                </button>
              ) : null}
              {/* No count while the resilience read is failed or in flight: "Walk
                3 findings" out of a half-loaded set is a claim about how many
                there are. */}
              {resErr || resLoading ? null : walk.length > 0 ? (
                <button type="button" onClick={() => selectFindingIndex(0)} className="btn-primary text-[12px]">
                  <Play size={12} /> Walk {walk.length} finding
                  {walk.length === 1 ? "" : "s"}
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
                All {src.length} registered source{src.length === 1 ? "" : "s"} report as live connectors; none is a
                seeded export.
              </span>
            )}
          </div>

          {srcErr ? (
            <p className="mt-1.5 text-[11px] text-text3">
              Provenance below is drawn without a live/seeded marker rather than with the flattering one: this build
              cannot currently say which consoles are seeded exports.
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
                  <>
                    {" "}
                    Capped lane{caps.capped_lanes.length === 1 ? "" : "s"}:{" "}
                    <span className="mono">{caps.capped_lanes.join(", ")}</span>.
                  </>
                ) : null}{" "}
                What is missing is missing from the picture, not from the estate.
              </span>
            </div>
          ) : null}

          {topo?.degraded_analyzers && topo.degraded_analyzers.length > 0 ? (
            <div className="mt-2 flex items-start gap-2 border border-sev-high-line bg-sev-high-bg px-3 py-2 text-[11.5px]">
              <AlertTriangle size={13} className="mt-0.5 shrink-0 text-sev-high" />
              <span className="text-text2">
                {topo.degraded_analyzers.length} analyzer
                {topo.degraded_analyzers.length === 1 ? "" : "s"} did not finish (
                <span className="mono">{topo.degraded_analyzers.join(", ")}</span>
                ), so findings on this canvas are incomplete rather than few.
              </span>
            </div>
          ) : null}

          {topo?.source_conflicts && topo.source_conflicts.length > 0 ? (
            <p
              className="mt-2 text-[11px] text-text3"
              title={topo.source_conflicts
                .map(
                  (c) => `${c.entity}.${c.field}: ${c.claims.map((k) => `${k.tool}=${String(k.value)}`).join(" vs ")}`,
                )
                .join("\n")}
            >
              {topo.source_conflicts.length} field
              {topo.source_conflicts.length === 1 ? "" : "s"} two consoles state differently. Not an error — a stale
              entry, or a box replaced without the aggregator being told. Open the device on the canvas to see the
              claims side by side.
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
              <header className="flex flex-wrap items-center gap-2 border-b border-hair px-3 py-2">
                <div className="flex min-w-0 items-center gap-2">
                  <Layers size={13} className="shrink-0 text-accent-fg" />
                  <h2 className="eyebrow truncate">
                    {layout.lanes.length} lane
                    {layout.lanes.length === 1 ? "" : "s"} · {layout.nodes.length} card
                    {layout.nodes.length === 1 ? "" : "s"} · {layout.links.length} link
                    {layout.links.length === 1 ? "" : "s"}
                  </h2>
                </div>
                <Shortcuts className="ml-auto hidden md:flex" />
              </header>
              {toolbar}
              {reachCallout}
              <div style={{ height: "clamp(420px, 64vh, 760px)" }} className="flex min-h-0 flex-col">
                {fullscreen ? (
                  <div className="flex h-full items-center justify-center bg-sunk px-4 text-center text-[12px] text-text3">
                    The canvas is open fullscreen. Press <span className="mono mx-1 text-text2">Esc</span> to bring it
                    back here.
                  </div>
                ) : (
                  workbench
                )}
              </div>
              {layout.unresolved.length > 0 || layout.hiddenInGroups > 0 ? (
                <footer className="shrink-0 border-t border-hair px-4 py-2 text-[11px] text-text3">
                  {layout.unresolved.length > 0 ? (
                    <span title={layout.unresolved.map((l) => `${l.a} ↔ ${l.b}`).join("\n")}>
                      {layout.unresolved.length} link
                      {layout.unresolved.length === 1 ? "" : "s"} name a device that is not in any lane of this response
                      and could not be drawn.{" "}
                    </span>
                  ) : null}
                  {layout.hiddenInGroups > 0 ? (
                    <span>
                      {layout.hiddenInGroups} link
                      {layout.hiddenInGroups === 1 ? " runs" : "s run"} between members of a collapsed group; expand the
                      lane to see them.
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
                    {unlinkedRows.length} inventoried device
                    {unlinkedRows.length === 1 ? "" : "s"} with no cable reported
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
                      <li key={u.device_key}>
                        <button
                          type="button"
                          onClick={() => {
                            const c = layout.cardFor.get(u.device_key);
                            if (c) {
                              selectNode(c);
                              focusCard(c);
                            }
                          }}
                          className="row flex w-full items-start gap-2 border border-border bg-surface px-2 py-1.5 text-left hover:border-accent"
                        >
                          <NetIcon
                            kind={n?.role ?? n?.kind ?? "unknown"}
                            size={18}
                            className="mt-0.5 shrink-0 text-text3"
                          />
                          <span className="min-w-0">
                            <span className="mono block truncate text-[11.5px] font-bold">
                              {n?.name || u.device_key}
                            </span>
                            <span className="block text-[11px] leading-snug text-text2">{u.reason}</span>
                            {u.would_be_filled_by ? (
                              <span className="mono block text-[10.5px] text-text3">
                                would be filled by {u.would_be_filled_by}
                              </span>
                            ) : null}
                          </span>
                        </button>
                      </li>
                    );
                  })}
                </ul>
              </section>
            ) : null}

            {/* ── Findings, inline ────────────────────────────────────────────── */}
            <section className="panel p-4">
              <div className="flex flex-wrap items-center gap-2">
                <Eyebrow>Findings on this canvas</Eyebrow>
                {resErr ? null : (
                  <span className="mono text-[11px] text-text3">
                    {walk.length} on the canvas
                    {policy.skipped > 0 ? ` · ${policy.skipped} elsewhere` : ""}
                  </span>
                )}
                {walk.length > 0 && !resErr ? (
                  <button
                    type="button"
                    onClick={() => {
                      selectFindingIndex(0);
                      openFullscreen();
                    }}
                    className="btn-ghost ml-auto text-[11.5px]"
                  >
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
                  {res.reason ?? "The resilience analyzer reports it had nothing to work on."} An empty list here is not
                  a statement that this estate has no single point of failure.
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
                        onClick={() => selectFindingIndex(i)}
                        className={cn(
                          "row flex w-full items-start gap-2 border bg-surface px-2.5 py-2 text-left hover:border-accent",
                          selIndex === i ? "border-accent" : "border-border",
                        )}
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
                    {res.suppressed.length} candidate finding
                    {res.suppressed.length === 1 ? "" : "s"} suppressed
                    {res.excluded_adjacencies.length > 0
                      ? `, ${res.excluded_adjacencies.length} adjacenc${res.excluded_adjacencies.length === 1 ? "y" : "ies"} excluded`
                      : ""}{" "}
                    — every one of them with its reason
                  </summary>
                  <p className="mt-1.5 text-[11px] leading-snug text-text3">
                    The resilience analyzer publishes what it chose not to report. An estate cabled the right way nearly
                    everywhere would otherwise bury its four real findings in fourteen false ones, and a filter nobody
                    can audit is indistinguishable from a bug.
                  </p>
                  <ul className="mt-1.5 space-y-1">
                    {res.suppressed.map((x, i) => (
                      <li key={`s${i}`} className="text-[11px] text-text2">
                        <span className="mono text-text3">{x.kind}</span> · <span className="mono">{x.candidate}</span>{" "}
                        — {x.detail}
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
              <div className="mb-3 flex flex-wrap items-center gap-2">
                <Eyebrow>Legend</Eyebrow>
                <Shortcuts className="ml-auto" />
              </div>
              <Legend
                redundancy={[...redundancy.values()]}
                vlanBands={[...vlanBands.values()]}
                hasContainment={hasContainment}
                hasAggregated={hasAggregated}
                hasHa={hasHa}
              />
              <div className="mt-3 border-t border-hair pt-2.5">
                <div className="label mb-1">The reachability overlay</div>
                <div className="flex flex-wrap items-start gap-x-5 gap-y-2">
                  <div className="flex items-start gap-2">
                    <svg width={40} height={12} aria-hidden className="mt-0.5 shrink-0">
                      <path d="M1 6H33" fill="none" stroke="var(--accent)" strokeWidth={2.4} strokeLinecap="round" />
                      <path d="M33 2 L39 6 L33 10 z" fill="var(--accent)" />
                    </svg>
                    <div className="min-w-0">
                      <div className="text-[11.5px] font-bold text-text2">A policy hop — not a cable</div>
                      <div className="text-[11px] leading-snug text-text3">
                        One allow rule permitting traffic from one node to the next. It bows the opposite way from a
                        link, carries an arrow, and is tagged with the service and the console that permits it. Nothing
                        on this overlay asserts a wire.
                      </div>
                    </div>
                  </div>
                  <div className="flex items-start gap-2">
                    <span className="mono mt-0.5 inline-flex h-[14px] min-w-[14px] shrink-0 items-center justify-center bg-accent px-0.5 text-[9px] font-bold leading-none text-accent-ink">
                      2
                    </span>
                    <div className="min-w-0">
                      <div className="text-[11.5px] font-bold text-text2">Position in the chain</div>
                      <div className="text-[11px] leading-snug text-text3">
                        The terminal wears a red marker: it is where the chain ends, and its tags are why that matters.
                      </div>
                    </div>
                  </div>
                </div>
              </div>
            </section>
          </>
        )}
      </div>

      {/* ── Fullscreen ────────────────────────────────────────────────────── */}
      {/* Outside the inert wrapper above: the dialog is the one operable
          canvas while it is open. */}
      {mounted && fullscreen && !topoErr
        ? createPortal(
            <div
              role="dialog"
              aria-modal="true"
              aria-label="Network explorer, fullscreen"
              className="fixed inset-0 z-[70] flex flex-col bg-bg p-0 outline-none sm:p-3 lg:p-4"
            >
              <div className="panel flex min-h-0 flex-1 flex-col overflow-hidden">
                <header className="flex flex-wrap items-center gap-2 border-b border-hair px-3 py-2">
                  <Eyebrow>Explorer</Eyebrow>
                  <span className="mono hidden text-[11px] text-text3 lg:inline">
                    {layout.lanes.length} lanes · {layout.nodes.length} cards · {layout.links.length} links
                  </span>
                  {sel ? (
                    <span className="mono text-[11px] tabular-nums text-text2">
                      finding {(selIndex ?? 0) + 1} of {walk.length}
                    </span>
                  ) : null}
                  <Shortcuts className="ml-auto hidden xl:flex" />
                  <button
                    type="button"
                    onClick={closeFullscreen}
                    className="btn-ghost ml-auto !h-7 shrink-0 px-2 text-[11px] xl:ml-0"
                  >
                    <Minimize2 size={13} /> Exit <span className="mono ml-1 text-text3">Esc</span>
                  </button>
                </header>
                {toolbar}
                {reachCallout}
                {workbench}
              </div>
            </div>,
            document.body,
          )
        : null}
    </>
  );
}

export default ExplorerPanel;
