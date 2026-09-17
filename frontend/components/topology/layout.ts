/**
 * Where every node and every line goes — arithmetic, in TypeScript, on purpose.
 *
 * WHY THERE IS NO LAYOUT LIBRARY HERE. A force-directed or hierarchical layout
 * engine decides positions from the shape of the graph, which is exactly the
 * wrong input for this picture: the lane a device is in is a FACT the engine
 * derived (`NetDevice.layer`, with `layer_source` and `layer_reason` beside it),
 * and a solver that nudges an edge router half a band toward the firewalls it
 * talks to has quietly overwritten that fact with an aesthetic preference. So
 * the y of a node is its lane, full stop, and the x of a node is its order
 * within that lane, full stop. Everything below is that rule plus packing.
 *
 * The second reason is legibility under a projector. A deterministic grid is
 * readable at 1024x768 and identical between two loads of the same snapshot; a
 * solver's output is neither, and "the diagram looked different in the meeting"
 * is not a thing a review tool gets to say.
 */

import type { LinkEvidence, TopoLane, TopoLink, TopoNode, TopologyLayer } from "@/lib/types";

/** Outside-in. The order the brief specifies, and the order a packet meets. */
export const LANE_ORDER: readonly TopologyLayer[] = [
  "internet", "circuit", "modem", "edge", "perimeter", "core", "access", "segment", "endpoint",
];

/**
 * Every dimension on the canvas, in one object.
 *
 * `maxRowW` is the load-bearing one: it is what keeps a wide lane from turning
 * the whole canvas into a 3000px strip that fits on a projector only at a zoom
 * where the hostnames are unreadable. A lane wider than this WRAPS — it never
 * shrinks its cards and never drops a node.
 *
 * It is a CEILING, not a target. The Explorer passes the width actually
 * available (`viewW - labelW - padRight`, floored at `minContentW`), so a
 * 1024x768 projector still gets a ~860px content column at full zoom — the
 * width this screen is demonstrated at — while a 2560 display gets a wider,
 * shorter picture instead of a 1020px ribbon marooned in the middle of it. The
 * ceiling exists because past about 1400px a lane stops being scannable left to
 * right: the eye loses the row before it reaches the end of it.
 */
export const GEOM = {
  labelW: 138,
  nodeW: 152,
  nodeH: 66,
  gapX: 24,
  haGap: 10,
  haPad: 7,
  rowGapY: 16,
  lanePadY: 20,
  maxRowW: 1400,
  minContentW: 560,
  padTop: 10,
  padBottom: 16,
  padRight: 26,
  /** An `observed: false` lane: the named absence, up to three lines of it. */
  absenceH: 98,
  /** An observed lane that genuinely holds nothing. Different claim, shorter strip. */
  emptyH: 54,
} as const;

/** Above this many nodes a lane collapses to group cards until asked to expand.
 *  Twelve cards across is already two wrapped rows; twenty is a wall. */
export const COLLAPSE_AT = 12;

/**
 * How strong the evidence for a line is — three tiers, not two.
 *
 * The brief asks for containment (dashed) versus cabled (solid), which is the
 * distinction that matters most. But `config` / `routing` / `declared` are not
 * cables either: they are a console stating an adjacency rather than a protocol
 * observing one. Drawing them identically to an LLDP neighbour would overstate
 * them, so they are solid (a device did assert this) and dimmer (nothing on the
 * wire confirmed it), and the legend names all three tiers.
 */
export type EvidenceTier = "wire" | "stated" | "containment";

export function evidenceTier(e: LinkEvidence | "mixed"): EvidenceTier {
  if (e === "containment") return "containment";
  if (e === "lldp" || e === "cdp" || e === "api_topology") return "wire";
  return "stated";
}

export const EVIDENCE_COPY: Record<EvidenceTier, { label: string; detail: string }> = {
  wire: {
    label: "Seen on the wire",
    detail: "LLDP, CDP or a controller's own topology API — a protocol observed this adjacency.",
  },
  stated: {
    label: "Stated by a console",
    detail: "Config, routing or a declared link. A source asserts these two are adjacent; nothing on the wire confirmed it.",
  },
  containment: {
    label: "Address containment",
    detail:
      "Two interfaces provably share an address block — a real L3 observation, and not a cable. It is the weakest line on this canvas and it is drawn dashed so it can never be mistaken for one of the others.",
  },
};

// ── Placed geometry ────────────────────────────────────────────────────────

export interface PlacedNode {
  /** Canvas id: the device key, or `grp:<layer>:<role>` for a collapsed group. */
  id: string;
  kind: "device" | "group";
  layer: TopologyLayer | string;
  laneIndex: number;
  x: number; y: number; w: number; h: number;
  /** The device, for `kind: "device"`. */
  node?: TopoNode;
  /** The devices behind a group card, for `kind: "group"`. */
  members?: TopoNode[];
  /** The role every member of a group card shares. */
  role?: string;
  haGroup?: string | null;
}

/** An HA pair drawn bracketed as one unit. */
export interface PlacedUnit {
  key: string;
  group: string;
  x: number; y: number; w: number; h: number;
  members: string[];
}

export interface PlacedLink {
  id: string;
  a: string;
  b: string;
  /** SVG path data. */
  d: string;
  mid: { x: number; y: number };
  /** The representative link; `merged` is every link drawn by this one path. */
  link: TopoLink;
  merged: TopoLink[];
  evidence: LinkEvidence | "mixed";
  redundantGroup: string | null;
  aggregated: boolean;
  /** Σ member_count across merged links — the ×N on an aggregated line. */
  memberCount: number;
  /** True when at least one end is a collapsed group card, so the line stands
   *  for several real links and must say so rather than imply one cable. */
  viaGroup: boolean;
}

export interface PlacedLane {
  layer: TopologyLayer | string;
  label: string;
  laneIndex: number;
  top: number;
  height: number;
  /** Nodes the payload put in this lane. */
  nodeCount: number;
  /** Cards actually drawn (group cards when collapsed). */
  cardCount: number;
  collapsed: boolean;
  collapsible: boolean;
  observed: boolean;
  reason?: string | null;
  wouldBeFilledBy?: string | null;
  rows: number;
}

export interface Layout {
  width: number;
  height: number;
  lanes: PlacedLane[];
  nodes: PlacedNode[];
  byId: Map<string, PlacedNode>;
  /** device key -> the card that represents it (itself, or its group card). */
  cardFor: Map<string, string>;
  units: PlacedUnit[];
  links: PlacedLink[];
  /** Placed link id -> the link. */
  linkById: Map<string, PlacedLink>;
  /**
   * A payload link id -> the placed line that draws it. Resilience findings
   * name the exact adjacency they are about (`cdp:asw-acc-03:Gi1/0/48~...`),
   * and this is what turns that string into the line to light: without it the
   * walkthrough can only guess at "every link between the involved devices",
   * which is a superset and sometimes a wrong one.
   */
  linkByRawId: Map<string, string>;
  /**
   * Links naming a device that is not on this canvas. Never silently dropped:
   * a missing line is indistinguishable from an absent one, so the count is
   * surfaced and the pairs are listed on hover.
   */
  unresolved: TopoLink[];
  /** Links whose two ends fell inside the same collapsed group card. */
  hiddenInGroups: number;
}

// ── Building it ────────────────────────────────────────────────────────────

interface Unit {
  members: TopoNode[];
  w: number;
  haGroup?: string | null;
  groupId?: string;
  role?: string;
}

export function laneRank(layer: string): number {
  const i = LANE_ORDER.indexOf(layer as TopologyLayer);
  return i === -1 ? LANE_ORDER.length : i;
}

/** Greedy packing, left to right, never splitting a unit (an HA pair stays one
 *  bracketed thing even when that pushes it to the next row). */
function packRows(units: Unit[], maxW: number, gap: number): Unit[][] {
  const rows: Unit[][] = [];
  let row: Unit[] = [];
  let w = 0;
  for (const u of units) {
    const add = row.length === 0 ? u.w : gap + u.w;
    if (row.length > 0 && w + add > maxW) {
      rows.push(row);
      row = [u];
      w = u.w;
    } else {
      row.push(u);
      w += add;
    }
  }
  if (row.length > 0) rows.push(row);
  return rows;
}

function rowWidth(row: Unit[], gap: number): number {
  return row.reduce((s, u) => s + u.w, 0) + Math.max(0, row.length - 1) * gap;
}

const r1 = (n: number) => Math.round(n * 10) / 10;

/** A cubic between two lanes, or a shallow bow for two cards on the same row. */
function pathBetween(a: PlacedNode, b: PlacedNode): { d: string; mid: { x: number; y: number } } {
  const acx = a.x + a.w / 2;
  const bcx = b.x + b.w / 2;
  if (Math.abs(a.y - b.y) < 2) {
    const y = a.y + a.h;
    const bow = 18;
    const mx = (acx + bcx) / 2;
    return { d: `M${r1(acx)} ${r1(y)} Q${r1(mx)} ${r1(y + bow)} ${r1(bcx)} ${r1(y)}`, mid: { x: mx, y: y + bow / 2 } };
  }
  const [u, l] = a.y < b.y ? [a, b] : [b, a];
  const ux = u.x + u.w / 2;
  const lx = l.x + l.w / 2;
  const uy = u.y + u.h;
  const ly = l.y;
  const dy = Math.max(14, (ly - uy) * 0.45);
  return {
    d: `M${r1(ux)} ${r1(uy)} C${r1(ux)} ${r1(uy + dy)} ${r1(lx)} ${r1(ly - dy)} ${r1(lx)} ${r1(ly)}`,
    mid: { x: (ux + lx) / 2, y: (uy + ly) / 2 },
  };
}

export interface LayoutOptions {
  /** Lanes the operator has explicitly expanded past `collapseAt`. */
  expanded?: ReadonlySet<string>;
  collapseAt?: number;
  /** Cap on row width before a lane wraps. Lower it for a narrow viewport. */
  maxRowW?: number;
}

export function buildLayout(lanes: TopoLane[], links: TopoLink[], opts: LayoutOptions = {}): Layout {
  const expanded = opts.expanded ?? new Set<string>();
  const collapseAt = opts.collapseAt ?? COLLAPSE_AT;
  const maxRowW = opts.maxRowW ?? GEOM.maxRowW;

  // Payload order is respected inside a lane; the lanes themselves are put in
  // the outside-in order the picture is defined by.
  const ordered = [...lanes].sort((a, b) => laneRank(a.layer) - laneRank(b.layer));

  interface Build { lane: TopoLane; rows: Unit[][]; collapsed: boolean; collapsible: boolean; cardCount: number }
  const builds: Build[] = ordered.map((lane) => {
    const collapsible = lane.observed && lane.nodes.length > collapseAt;
    const collapsed = collapsible && !expanded.has(lane.layer);
    let units: Unit[] = [];

    if (!lane.observed) {
      // Nothing to place. An unobserved lane draws a named absence, never a
      // faded device — see the Lane component.
      units = [];
    } else if (collapsed) {
      const groups = new Map<string, TopoNode[]>();
      for (const n of lane.nodes) {
        const role = n.role ?? n.kind ?? "unknown";
        const bucket = groups.get(role);
        if (bucket) bucket.push(n);
        else groups.set(role, [n]);
      }
      units = [...groups.entries()].map(([role, members]) => ({
        members,
        role,
        groupId: `grp:${lane.layer}:${role}`,
        w: GEOM.nodeW,
      }));
    } else {
      const seen = new Set<string>();
      for (const n of lane.nodes) {
        const ha = n.ha_group ?? null;
        if (ha) {
          if (seen.has(ha)) continue;
          seen.add(ha);
          const members = lane.nodes.filter((m) => m.ha_group === ha);
          units.push({
            members,
            haGroup: ha,
            w: members.length * GEOM.nodeW + (members.length - 1) * GEOM.haGap + (members.length > 1 ? GEOM.haPad * 2 : 0),
          });
        } else {
          units.push({ members: [n], w: GEOM.nodeW });
        }
      }
    }

    const rows = packRows(units, maxRowW, GEOM.gapX);
    return { lane, rows, collapsed, collapsible, cardCount: units.reduce((s, u) => s + (u.groupId ? 1 : u.members.length), 0) };
  });

  const widest = builds.reduce(
    (m, b) => Math.max(m, ...b.rows.map((r) => rowWidth(r, GEOM.gapX)), 0),
    0,
  );
  const contentW = Math.max(GEOM.minContentW, Math.min(maxRowW, widest));

  const placedLanes: PlacedLane[] = [];
  const nodes: PlacedNode[] = [];
  const units: PlacedUnit[] = [];
  const cardFor = new Map<string, string>();

  let y = GEOM.padTop;
  builds.forEach((b, laneIndex) => {
    const { lane } = b;
    const rows = b.rows.length;
    const height = !lane.observed
      ? GEOM.absenceH
      : rows === 0
        ? GEOM.emptyH
        : rows * GEOM.nodeH + (rows - 1) * GEOM.rowGapY + GEOM.lanePadY * 2;

    b.rows.forEach((row, rowIndex) => {
      const rw = rowWidth(row, GEOM.gapX);
      let x = GEOM.labelW + (contentW - rw) / 2;
      const rowY = y + GEOM.lanePadY + rowIndex * (GEOM.nodeH + GEOM.rowGapY);
      for (const u of row) {
        if (u.groupId) {
          const id = u.groupId;
          nodes.push({
            id, kind: "group", layer: lane.layer, laneIndex,
            x: r1(x), y: rowY, w: GEOM.nodeW, h: GEOM.nodeH,
            members: u.members, role: u.role,
          });
          for (const m of u.members) cardFor.set(m.key, id);
          x += u.w + GEOM.gapX;
          continue;
        }
        const pad = u.members.length > 1 ? GEOM.haPad : 0;
        if (u.members.length > 1 && u.haGroup) {
          units.push({
            key: `ha:${lane.layer}:${u.haGroup}`,
            group: u.haGroup,
            x: r1(x), y: rowY - GEOM.haPad, w: r1(u.w), h: GEOM.nodeH + GEOM.haPad * 2,
            members: u.members.map((m) => m.key),
          });
        }
        let mx = x + pad;
        for (const m of u.members) {
          nodes.push({
            id: m.key, kind: "device", layer: lane.layer, laneIndex,
            x: r1(mx), y: rowY, w: GEOM.nodeW, h: GEOM.nodeH,
            node: m, haGroup: m.ha_group ?? null,
          });
          cardFor.set(m.key, m.key);
          mx += GEOM.nodeW + GEOM.haGap;
        }
        x += u.w + GEOM.gapX;
      }
    });

    placedLanes.push({
      layer: lane.layer,
      label: lane.label,
      laneIndex,
      top: y,
      height,
      nodeCount: lane.nodes.length,
      cardCount: b.cardCount,
      collapsed: b.collapsed,
      collapsible: b.collapsible,
      observed: lane.observed,
      reason: lane.reason,
      wouldBeFilledBy: lane.would_be_filled_by,
      rows,
    });
    y += height;
  });

  const byId = new Map(nodes.map((n) => [n.id, n]));

  // ── Links ───────────────────────────────────────────────────────────────
  // Parallel lines between the same two cards are merged into one path (two
  // identical curves are one visible curve anyway, and the second would only
  // ever be a lie by overdraw). What they were is kept on `merged`, so the
  // count, the evidence tiers and the provenance are all still reportable.
  const unresolved: TopoLink[] = [];
  let hiddenInGroups = 0;
  const buckets = new Map<string, { a: string; b: string; items: TopoLink[] }>();

  for (const l of links) {
    const a = cardFor.get(l.a);
    const b = cardFor.get(l.b);
    if (!a || !b) { unresolved.push(l); continue; }
    if (a === b) { hiddenInGroups += 1; continue; }
    const key = a < b ? `${a}|${b}` : `${b}|${a}`;
    const bucket = buckets.get(key);
    if (bucket) bucket.items.push(l);
    else buckets.set(key, { a, b, items: [l] });
  }

  const placedLinks: PlacedLink[] = [];
  for (const [key, { a, b, items }] of buckets) {
    const na = byId.get(a);
    const nb = byId.get(b);
    if (!na || !nb) { unresolved.push(...items); continue; }
    const { d, mid } = pathBetween(na, nb);
    const evidences = new Set(items.map((i) => i.evidence));
    const groups = items.map((i) => i.redundant_group).filter((g): g is string => !!g);
    placedLinks.push({
      id: key,
      a, b, d, mid,
      link: items[0],
      merged: items,
      evidence: evidences.size === 1 ? items[0].evidence : "mixed",
      redundantGroup: groups[0] ?? null,
      aggregated: items.some((i) => i.aggregated),
      memberCount: items.reduce((s, i) => s + (i.member_count || 1), 0),
      viaGroup: na.kind === "group" || nb.kind === "group",
    });
  }

  const linkById = new Map(placedLinks.map((l) => [l.id, l]));
  const linkByRawId = new Map<string, string>();
  for (const l of placedLinks) for (const m of l.merged) linkByRawId.set(m.id, l.id);

  return {
    width: GEOM.labelW + contentW + GEOM.padRight,
    height: y + GEOM.padBottom,
    lanes: placedLanes,
    nodes,
    byId,
    cardFor,
    units,
    links: placedLinks,
    linkById,
    linkByRawId,
    unresolved,
    hiddenInGroups,
  };
}

/**
 * The lines a finding runs on: every link named outright, plus every link whose
 * two ends are both involved.
 *
 * Both halves are needed. A finding that names its adjacency (`single_homed_
 * device` does) should light exactly that cable and no other; a finding that
 * names only devices (`shared_circuit_handoff`) has to fall back to the links
 * between them, and lighting one too many there is better than lighting none.
 */
export function linksWithin(
  layout: Layout,
  keys: ReadonlySet<string>,
  named?: ReadonlySet<string>,
): PlacedLink[] {
  return layout.links.filter(
    (l) => (keys.has(l.a) && keys.has(l.b)) || (named?.has(l.id) ?? false),
  );
}

/**
 * Order a finding's links into hops a viewer can follow.
 *
 * Breadth-first from the OUTERMOST involved card (lowest lane index — the
 * internet end), so the trace runs the way the diagram is read: in from the
 * edge. Any links the walk does not reach — a second disconnected component
 * within one finding — are appended rather than dropped, because a hop that is
 * never animated is a hop the viewer never learns about.
 */
export function orderHops(
  layout: Layout,
  keys: ReadonlySet<string>,
  named?: ReadonlySet<string>,
): PlacedLink[] {
  const involved = linksWithin(layout, keys, named);
  if (involved.length < 2) return involved;

  const adjacency = new Map<string, PlacedLink[]>();
  for (const l of involved) {
    (adjacency.get(l.a) ?? adjacency.set(l.a, []).get(l.a)!).push(l);
    (adjacency.get(l.b) ?? adjacency.set(l.b, []).get(l.b)!).push(l);
  }

  const start = [...keys]
    .map((k) => layout.byId.get(k))
    .filter((n): n is PlacedNode => !!n)
    .sort((a, b) => a.laneIndex - b.laneIndex || a.x - b.x)[0];

  const out: PlacedLink[] = [];
  const takenLinks = new Set<string>();
  const seenNodes = new Set<string>();
  const queue: string[] = start ? [start.id] : [];
  if (start) seenNodes.add(start.id);

  while (queue.length > 0) {
    const cur = queue.shift()!;
    for (const l of adjacency.get(cur) ?? []) {
      if (takenLinks.has(l.id)) continue;
      takenLinks.add(l.id);
      out.push(l);
      const next = l.a === cur ? l.b : l.a;
      if (!seenNodes.has(next)) { seenNodes.add(next); queue.push(next); }
    }
  }
  for (const l of involved) if (!takenLinks.has(l.id)) out.push(l);
  return out;
}

// ── Structural relations, which are NOT cables ──────────────────────────────
//
// The canvas drew eighteen cables and nothing else, and a product owner looking
// at it asked why there were no edges for most of the devices. There were not:
// every link in `topology.links` runs DEVICE to DEVICE, so the internet, the WAN
// circuits, the segments and the hosts each floated in their own band with no
// line to anything, and the picture read as four disconnected islands.
//
// The relationships were in the payload all along, in `topology.relations`, and
// they are deliberately not links: a circuit terminating on a CPE, a VLAN a
// switch routes, a host's address sitting inside a subnet are CONTAINMENT,
// TERMINATION and MEMBERSHIP — structural facts — and none of them is an
// observed adjacency. The backend keeps them out of `links` because the
// resilience analyzer runs articulation points over that set and a broadcast
// domain in it would dissolve every cut vertex in the estate.
//
// So the same rule holds on this side of the wire: they are placed here, in
// their own layer, and drawn so that no reader can mistake one for a cable.

/** The four the backend emits today. Read as a plain string everywhere else, so
 *  a fifth kind from a newer backend still draws and still names itself rather
 *  than being silently dropped. */
export const RELATION_KINDS = ["reaches", "terminates", "carries", "contains"] as const;

export interface TopoRelation {
  a: string;
  b: string;
  kind: string;
  /** The sentence the backend wrote for this one fact — the hover text, and the
   *  reason a relation needs no label painted on the canvas. */
  detail: string;
}

export const RELATION_COPY: Record<string, { label: string; detail: string }> = {
  reaches: {
    label: "reaches",
    detail: "A WAN circuit is a path to the internet. That is what the word means, not an inference about this estate.",
  },
  terminates: {
    label: "terminates",
    detail: "The CPE on this site's end of that circuit — the box the carrier hands off to.",
  },
  carries: {
    label: "carries",
    detail:
      "The L3 device holding that VLAN's gateway: where the segment is routed. Switches that merely trunk the VLAN are counted under the canvas rather than drawn.",
  },
  contains: {
    label: "contains",
    detail: "That host's address provably sits inside the VLAN's subnet. Arithmetic on the addresses, and not a cable.",
  },
};

/**
 * `relations` is additive on the topology payload and is not in the shared
 * `TopologyResponse` type, so it is read defensively and nothing is invented: a
 * backend that predates the field yields an empty layer and a canvas that draws
 * exactly what it drew before, rather than a crash.
 */
export function normaliseRelations(raw: unknown): TopoRelation[] {
  if (!Array.isArray(raw)) return [];
  const out: TopoRelation[] = [];
  for (const r of raw) {
    if (!r || typeof r !== "object") continue;
    const o = r as Record<string, unknown>;
    if (typeof o.a !== "string" || typeof o.b !== "string" || typeof o.kind !== "string") continue;
    out.push({ a: o.a, b: o.b, kind: o.kind, detail: typeof o.detail === "string" ? o.detail : "" });
  }
  return out;
}

export interface PlacedRelation {
  id: string;
  /** The card in the OUTER lane, and the card in the inner one. Relations carry
   *  a direction in the payload, but nothing is drawn with an arrowhead — an
   *  arrow on a containment fact would assert a flow that does not exist — so
   *  the ends are ordered by lane instead, which is what the geometry needs. */
  a: string;
  b: string;
  d: string;
  mid: { x: number; y: number };
  kinds: string[];
  items: TopoRelation[];
}

export interface RelationLayer {
  lines: PlacedRelation[];
  /** The kinds actually on screen, in payload-sorted order, for the legend.
   *  Explaining a mark nobody can find is how a legend stops being read. */
  kinds: string[];
  /** `carries` facts held back because the device only trunks the VLAN. Counted
   *  and reported, never silently dropped: a suppressed edge and an absent one
   *  look identical, which is the defect this whole layer exists to fix. */
  trunkOnly: number;
  /** Relations naming something in no lane of this response. */
  unresolved: number;
  /** Relations whose two ends landed on one collapsed group card. */
  hiddenInGroups: number;
  /**
   * True when NO device in the payload could be matched to a VLAN gateway, so
   * the gateway filter would have deleted every `carries` line and left the
   * segment lane floating again — the exact symptom being fixed. In that case
   * every `carries` is drawn and the canvas says why, because a filter that
   * silently empties itself is worse than a busy picture.
   */
  gatewayUnknown: boolean;
}

export const EMPTY_RELATION_LAYER: RelationLayer = {
  lines: [], kinds: [], trunkOnly: 0, unresolved: 0, hiddenInGroups: 0, gatewayUnknown: false,
};

/**
 * Route one relation.
 *
 * Deliberately a STRAIGHT CHORD, where every cable on this canvas is a cubic
 * bow and every policy hop bows the other way. Three line families, three
 * geometries, before colour or weight is considered at all — so the distinction
 * survives greyscale, a projector and a reader who never opens the legend.
 *
 * The anchors are spread across the card's width rather than taken from its
 * centre, for two reasons: a cable already leaves the bottom centre, and the two
 * core switches each hold seven VLAN gateways — seven chords from one point is a
 * blot, seven from a comb is a fan you can count.
 */
function relationPath(
  a: PlacedNode, b: PlacedNode, aFrac: number, bFrac: number,
): { d: string; mid: { x: number; y: number } } {
  const ax = a.x + a.w * aFrac;
  const bx = b.x + b.w * bFrac;
  if (Math.abs(a.y - b.y) < 2) {
    // Same row. Bows ABOVE the cards — below is where a cable between two cards
    // in one lane already bows.
    const y = a.y;
    const lift = 22;
    const mx = (ax + bx) / 2;
    return {
      d: `M${r1(ax)} ${r1(y)} Q${r1(mx)} ${r1(y - lift)} ${r1(bx)} ${r1(y)}`,
      mid: { x: mx, y: y - lift * 0.55 },
    };
  }
  const [u, ux, l, lx] = a.y < b.y ? [a, ax, b, bx] : [b, bx, a, ax];
  const uy = u.y + u.h;
  const ly = l.y;
  return {
    d: `M${r1(ux)} ${r1(uy)} L${r1(lx)} ${r1(ly)}`,
    mid: { x: (ux + lx) / 2, y: (uy + ly) / 2 },
  };
}

/**
 * Resolve the payload's relations onto the cards this layout placed.
 *
 * `gatewayHolders` holds `<device key>|<vlan card key>` for every device an
 * interface address proves is a VLAN's gateway. It is how `carries` is thinned:
 * thirty-nine relations on twenty-five cards is a hairball, and twenty-six of
 * them are `carries` because every core and access switch trunks nearly every
 * VLAN. "Which switch has the VLAN in its allowed list" is not a fact worth a
 * line; "where the segment is routed" is, and it is the one the reader is
 * actually looking for.
 */
export function placeRelations(
  layout: Layout,
  relations: TopoRelation[],
  gatewayHolders: ReadonlySet<string>,
): RelationLayer {
  if (relations.length === 0) return EMPTY_RELATION_LAYER;

  // The pair is checked both ways round because the filter must not depend on
  // which end of a `carries` fact the backend happens to put first.
  const atGateway = (r: TopoRelation) =>
    gatewayHolders.has(`${r.a}|${r.b}`) || gatewayHolders.has(`${r.b}|${r.a}`);
  const carries = relations.filter((r) => r.kind === "carries");
  const gatewayUnknown = carries.length > 0 && !carries.some(atGateway);
  const kept = gatewayUnknown
    ? relations
    : relations.filter((r) => r.kind !== "carries" || atGateway(r));
  const trunkOnly = relations.length - kept.length;

  let unresolved = 0;
  let hiddenInGroups = 0;
  // Two facts between the same pair of CARDS are one line — the segment lane
  // collapses its fourteen hosts into one card, and four identical chords to it
  // are one visible chord plus three lies by overdraw. What they were is kept on
  // `items`, so the hover still lists every one.
  const buckets = new Map<string, { a: PlacedNode; b: PlacedNode; items: TopoRelation[] }>();
  for (const r of kept) {
    const ca = layout.cardFor.get(r.a);
    const cb = layout.cardFor.get(r.b);
    if (!ca || !cb) { unresolved += 1; continue; }
    if (ca === cb) { hiddenInGroups += 1; continue; }
    const na = layout.byId.get(ca);
    const nb = layout.byId.get(cb);
    if (!na || !nb) { unresolved += 1; continue; }
    // Ordered outer lane first, so the geometry below never has to ask twice.
    const [u, l] = na.laneIndex <= nb.laneIndex ? [na, nb] : [nb, na];
    const key = `${u.id}|${l.id}`;
    const bucket = buckets.get(key);
    if (bucket) bucket.items.push(r);
    else buckets.set(key, { a: u, b: l, items: [r] });
  }

  // Spread the anchors. Both ends are combed the same way — by the other end's
  // centre x — so the fan opens in the direction the eye is already travelling
  // and the order is identical between two renders of one snapshot.
  const byEnd = (pick: (e: { a: PlacedNode; b: PlacedNode }) => PlacedNode,
                 other: (e: { a: PlacedNode; b: PlacedNode }) => PlacedNode) => {
    const groups = new Map<string, string[]>();
    for (const [key, e] of buckets) {
      const id = pick(e).id;
      (groups.get(id) ?? groups.set(id, []).get(id)!).push(key);
    }
    const frac = new Map<string, number>();
    for (const keys of groups.values()) {
      keys.sort((k1, k2) => {
        const o1 = other(buckets.get(k1)!);
        const o2 = other(buckets.get(k2)!);
        return (o1.x + o1.w / 2) - (o2.x + o2.w / 2) || k1.localeCompare(k2);
      });
      // Inset to 15%–85% of the card: an anchor on the very corner reads as a
      // line that missed the card rather than one that leaves it.
      keys.forEach((k, i) => frac.set(k, keys.length === 1 ? 0.5 : 0.15 + 0.7 * (i / (keys.length - 1))));
    }
    return frac;
  };
  const aFrac = byEnd((e) => e.a, (e) => e.b);
  const bFrac = byEnd((e) => e.b, (e) => e.a);

  const lines: PlacedRelation[] = [];
  for (const [id, e] of buckets) {
    const { d, mid } = relationPath(e.a, e.b, aFrac.get(id) ?? 0.5, bFrac.get(id) ?? 0.5);
    lines.push({
      id, a: e.a.id, b: e.b.id, d, mid,
      kinds: [...new Set(e.items.map((i) => i.kind))],
      items: e.items,
    });
  }

  // From the lines actually PLACED, not from what survived the filter: a kind
  // whose every relation named a card off this canvas has no mark on screen, and
  // a legend that explains a mark nobody can find is a legend that stops being
  // read.
  const present = new Set(lines.flatMap((l) => l.kinds));
  const kinds = [
    ...RELATION_KINDS.filter((k) => present.has(k)),
    ...[...present].filter((k) => !(RELATION_KINDS as readonly string[]).includes(k)).sort(),
  ];

  return { lines, kinds, trunkOnly, unresolved, hiddenInGroups, gatewayUnknown };
}

/**
 * Which `<device key>|<vlan card key>` pairs are provable gateways.
 *
 * Provable, not assumed: a device holds a VLAN's gateway when one of its own
 * interface addresses IS the gateway address the payload declares for that VLAN.
 * Both members of an HSRP/VRRP pair legitimately report the same address, and
 * both get a line — dropping one would draw a single point of failure where the
 * estate has a pair.
 */
export function gatewayHolders(
  nodes: TopoNode[],
  vlans: { vlan_id: number; gateways: string[] }[],
): Set<string> {
  const vlanOfGateway = new Map<string, string>();
  for (const v of vlans) for (const g of v.gateways ?? []) vlanOfGateway.set(g, `vlan-${v.vlan_id}`);
  const out = new Set<string>();
  if (vlanOfGateway.size === 0) return out;
  for (const n of nodes) {
    for (const i of n.interfaces ?? []) {
      for (const a of i.addresses ?? []) {
        const card = vlanOfGateway.get(a.split("/")[0]);
        if (card) out.add(`${n.key}|${card}`);
      }
    }
  }
  return out;
}
