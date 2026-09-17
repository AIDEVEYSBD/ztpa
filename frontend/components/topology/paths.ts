/**
 * The cross-tool path, drawn ON the layered canvas.
 *
 * This is the product's one differentiated computation: a chain of allow rules
 * that no single console can see, because each hop lives in a different vendor's
 * policy set. It used to be drawn on its own graph (NetworkMap.tsx) with its own
 * node positions, which meant the estate had two pictures that disagreed about
 * where anything was, and a reader had to hold both in their head to see that
 * the path ends on a host inside the db-tier VLAN.
 *
 * It can be drawn here now because the path's terminal is on this canvas: it has
 * a VLAN, a subnet and a place in the endpoint lane. So the path is an OVERLAY —
 * the same lanes, the same cards, with the chain traced across them — and the
 * two pictures became one.
 *
 * WHAT THIS MODULE REFUSES TO DO. A hop naming a node that is in no lane of this
 * topology response is NOT dropped and not drawn as a floating box: it is
 * collected in `missing` and named on screen. A path whose middle is invisible
 * would otherwise render as a shorter, tidier chain than the one the engine
 * found — the most dangerous kind of wrong, because it understates exposure.
 */

import type { Layout, PlacedNode } from "./layout";

export interface CrossToolHop {
  src: string;
  dst: string;
  /** What the engine wants a human to read; falls back to the raw id. */
  src_display: string;
  dst_display: string;
  service: string;
  tool: string;
  /** The rule reference — the receipt for this hop. */
  ref: string;
  l7_app?: string | null;
  l7_source?: string | null;
  services?: string[];
  apps?: string[];
}

export interface CrossToolPath {
  /** Node ids, in order, as the engine walked them. */
  path: string[];
  display_path: string[];
  hops: CrossToolHop[];
  entry: string;
  terminal: string;
  tools: string[];
  boundary: string;
  terminal_tags: string[];
  terminal_service?: string;
  port_class?: string;
  reaches_sensitive: boolean;
  title?: string;
}

const str = (v: unknown, fallback = ""): string => (typeof v === "string" ? v : fallback);
const arr = (v: unknown): string[] => (Array.isArray(v) ? v.filter((x): x is string => typeof x === "string") : []);

/**
 * `/api/graph.cross_tool_paths` is typed `Record<string, any>[]`, so every field
 * is read defensively and nothing is invented: a hop with no `service` renders
 * as a hop with no service, not as "any".
 */
export function normalisePaths(raw: Record<string, unknown>[] | undefined | null): CrossToolPath[] {
  if (!Array.isArray(raw)) return [];
  return raw.map((p) => {
    const hops = Array.isArray(p.hops) ? (p.hops as Record<string, unknown>[]) : [];
    return {
      path: arr(p.path),
      display_path: arr(p.display_path),
      hops: hops.map((h) => ({
        src: str(h.src),
        dst: str(h.dst),
        src_display: str(h.src_display) || str(h.src),
        dst_display: str(h.dst_display) || str(h.dst),
        service: str(h.service),
        tool: str(h.tool),
        ref: str(h.ref),
        l7_app: typeof h.l7_app === "string" ? h.l7_app : null,
        l7_source: typeof h.l7_source === "string" ? h.l7_source : null,
        services: arr(h.services),
        apps: arr(h.apps),
      })),
      entry: str(p.entry),
      terminal: str(p.terminal),
      tools: arr(p.tools),
      boundary: str(p.boundary),
      terminal_tags: arr(p.terminal_tags),
      terminal_service: str(p.terminal_service) || undefined,
      port_class: str(p.port_class) || undefined,
      reaches_sensitive: p.reaches_sensitive === true,
      title: str(p.title) || undefined,
    };
  });
}

/** One hop, resolved to two cards on the canvas. */
export interface PlacedHop {
  index: number;
  hop: CrossToolHop;
  from: PlacedNode;
  to: PlacedNode;
  /** SVG path data, routed to stay clear of the topology's own links. */
  d: string;
  mid: { x: number; y: number };
  /** True when the two ends landed on the SAME card — both devices are inside
   *  one collapsed group. The hop is real and is not drawn as a line, because a
   *  line from a card to itself is not a picture of anything. */
  selfLoop: boolean;
}

export interface PlacedPath {
  hops: PlacedHop[];
  /** Cards the path touches, in the order it touches them. */
  cards: string[];
  cardSet: Set<string>;
  /** Card id -> the position in the chain, for the numbered badge. */
  order: Map<string, number>;
  /** Path node ids with no card in this topology response. Named, never
   *  dropped: a hop the canvas cannot draw is still a hop that exists. */
  missing: string[];
  /** Hops whose ends collapsed into one card; the lane has to be expanded. */
  collapsed: number;
}

const r1 = (n: number) => Math.round(n * 10) / 10;

/**
 * Route one hop.
 *
 * Deliberately NOT the same curve `layout.pathBetween` draws for cables. A hop
 * between two cards in the same row bows ABOVE them (a cable bows below), and a
 * hop between lanes leaves and enters at the card's side rather than its centre
 * — so an overlay line is never mistaken for a link the consoles reported, even
 * before its colour is taken into account.
 */
function routeHop(a: PlacedNode, b: PlacedNode): { d: string; mid: { x: number; y: number } } {
  const ax = a.x + a.w / 2;
  const bx = b.x + b.w / 2;
  if (Math.abs(a.y - b.y) < 2) {
    const y = a.y;
    const lift = 30;
    const mx = (ax + bx) / 2;
    return {
      d: `M${r1(ax)} ${r1(y)} Q${r1(mx)} ${r1(y - lift)} ${r1(bx)} ${r1(y)}`,
      mid: { x: mx, y: y - lift * 0.55 },
    };
  }
  const down = a.y < b.y;
  const sy = down ? a.y + a.h : a.y;
  const ey = down ? b.y : b.y + b.h;
  const dy = Math.max(18, Math.abs(ey - sy) * 0.42) * (down ? 1 : -1);
  return {
    d: `M${r1(ax)} ${r1(sy)} C${r1(ax)} ${r1(sy + dy)} ${r1(bx)} ${r1(ey - dy)} ${r1(bx)} ${r1(ey)}`,
    mid: { x: (ax + bx) / 2, y: (sy + ey) / 2 },
  };
}

/** Resolve a path onto the lanes. Nothing here guesses a position: a node is
 *  where the layout put it, or it is missing and said to be missing. */
export function placePath(p: CrossToolPath | undefined, layout: Layout): PlacedPath | null {
  if (!p) return null;
  const hops: PlacedHop[] = [];
  const cards: string[] = [];
  const order = new Map<string, number>();
  const missing: string[] = [];
  let collapsed = 0;

  const cardOf = (id: string): PlacedNode | null => {
    const cardId = layout.cardFor.get(id);
    if (!cardId) return null;
    return layout.byId.get(cardId) ?? null;
  };

  const note = (n: PlacedNode) => {
    if (!order.has(n.id)) {
      order.set(n.id, cards.length);
      cards.push(n.id);
    }
  };

  p.hops.forEach((hop, index) => {
    const from = cardOf(hop.src);
    const to = cardOf(hop.dst);
    if (!from) missing.push(hop.src);
    if (!to) missing.push(hop.dst);
    if (!from || !to) return;
    note(from);
    note(to);
    if (from.id === to.id) {
      collapsed += 1;
      hops.push({ index, hop, from, to, d: "", mid: { x: from.x + from.w / 2, y: from.y }, selfLoop: true });
      return;
    }
    const { d, mid } = routeHop(from, to);
    hops.push({ index, hop, from, to, d, mid, selfLoop: false });
  });

  return {
    hops,
    cards,
    cardSet: new Set(cards),
    order,
    missing: [...new Set(missing)],
    collapsed,
  };
}
