/**
 * What the Explorer knows about ONE node, and how a search finds it.
 *
 * `/api/topology` grew today: a node now carries its interfaces, its OS, its
 * serial, its management address, its tags, the reason its ROLE was assigned
 * (not only the reason its LANE was) and any field two consoles state
 * differently. `TopoNode` in lib/types.ts is owned elsewhere and declares the
 * older, narrower shape, so the extra fields are declared HERE as optional —
 * optional because they are genuinely absent on some nodes and their absence is
 * a fact worth rendering, not a gap to paper over.
 *
 * A host that the policy layer placed by address (`db-prod-01`) has no serial,
 * no interfaces and no model, because no console ever described it as hardware.
 * A drawer that printed "—" for those without saying why would read as a device
 * whose details we failed to fetch. The drawer therefore asks this module what
 * is KNOWN, and prints the unknowns as a named absence with the reason.
 */

import type { SourceConflict, TopoNode } from "@/lib/types";

/** One interface, as `/api/topology` now serves it under a device. */
export interface NodeInterface {
  name: string;
  addresses: string[];
  vlan_id?: number | null;
  zone?: string | null;
  admin_up?: boolean | null;
  oper_up?: boolean | null;
  speed_mbps?: number | null;
  lag_group?: string | null;
  description?: string | null;
  neighbor_device?: string | null;
  neighbor_interface?: string | null;
  networks_behind?: string[];
}

/**
 * A topology node with everything this build's API actually sends.
 *
 * Every added member is optional, so this stays assignable from `TopoNode` and
 * keeps compiling if lib/types.ts later declares the same fields itself.
 */
export type ExplorerNode = TopoNode & {
  interfaces?: NodeInterface[] | null;
  os_version?: string | null;
  serial?: string | null;
  site?: string | null;
  mgmt_ip?: string | null;
  tags?: string[] | null;
  role_source?: string | null;
  role_reason?: string | null;
  conflicts?: SourceConflict[] | null;
};

/**
 * The VLAN → subnet/gateway map the payload declares, as a lookup.
 *
 * A node's subnet is NOT on the node: it is on the VLAN the node's tag names.
 * Resolving it here is reading the payload's own claim, not inferring one — and
 * a VLAN id with no entry in `vlans` resolves to nothing rather than to a
 * plausible-looking block.
 */
export interface VlanFacts {
  vlan_id: number;
  name?: string | null;
  subnets: string[];
  gateways: string[];
}

export function vlanIndex(vlans: VlanFacts[] | undefined): Map<number, VlanFacts> {
  return new Map((vlans ?? []).map((v) => [v.vlan_id, v]));
}

/** Every address on the node itself plus every address on its interfaces,
 *  de-duplicated and stable. Interfaces are where a firewall's four legs live,
 *  and a drawer that showed only `addresses` would hide three of them. */
export function allAddresses(n: ExplorerNode): string[] {
  const out = new Set<string>(n.addresses ?? []);
  for (const i of n.interfaces ?? []) for (const a of i.addresses ?? []) out.add(a);
  // `mgmt_ip` is a bare host address and the interface list usually carries the
  // same address WITH its prefix. Listing both makes one interface look like
  // two, so the bare form is added only when nothing already covers it.
  if (n.mgmt_ip && ![...out].some((a) => a.split("/")[0] === n.mgmt_ip)) out.add(n.mgmt_ip);
  return [...out];
}

/**
 * The address to hand to `/api/ip`, or null when the node genuinely has none —
 * in which case the drawer says so rather than querying "".
 *
 * `0.0.0.0/0` is NOT excluded. It is the internet node's real address and the
 * source side of every rule that exposes this estate, so the most interesting
 * lookup on the whole canvas is the one an exclusion here would silently skip —
 * while leaving the drawer to claim the node "has no address in the payload",
 * which is false.
 */
export function primaryAddress(n: ExplorerNode): string | null {
  const own = (n.addresses ?? []).find((a) => !!a);
  if (own) return own;
  if (n.mgmt_ip) return n.mgmt_ip;
  for (const i of n.interfaces ?? []) {
    const a = (i.addresses ?? [])[0];
    if (a) return a;
  }
  return null;
}

/** The distinct consoles behind a node. A device seen three times by one
 *  aggregator is one console, and a sentence that lists it three times reads as
 *  three sources of corroboration that do not exist. */
export function distinctTools(n: ExplorerNode): string[] {
  return [...new Set((n.observed_by ?? []).map((o) => o.tool))];
}

// ── Search ────────────────────────────────────────────────────────────────

export interface SearchHit {
  /** The card on the canvas — the node itself, or the group card holding it. */
  cardId: string;
  key: string;
  name: string;
  /** Which field matched, in the user's words. Shown in the result list so a
   *  hit on a serial number does not look like a hit on a hostname. */
  why: string;
  /** True when the node is inside a collapsed group and its card is the group's
   *  — the Explorer expands that lane so the match is actually visible. */
  viaGroup: boolean;
  layer: string;
}

interface Searchable {
  node: ExplorerNode;
  cardId: string;
  viaGroup: boolean;
  layer: string;
}

/**
 * Find nodes by name, address, model or VLAN — the four the brief names — plus
 * the identifiers an operator actually has in hand: the key, the vendor, the
 * serial, the OS, the site, the management address and the role.
 *
 * Case-insensitive substring, and deliberately NOT fuzzy: on a console where a
 * hostname is evidence, a match has to be something the reader can see in the
 * string they typed.
 */
export function searchNodes(query: string, items: Searchable[]): SearchHit[] {
  const q = query.trim().toLowerCase();
  if (!q) return [];
  const hits: SearchHit[] = [];

  for (const { node: n, cardId, viaGroup, layer } of items) {
    const why = matchReason(n, q);
    if (!why) continue;
    hits.push({ cardId, key: n.key, name: n.name || n.key, why, viaGroup, layer });
  }
  return hits;
}

function hit(label: string, value: string, q: string): string | null {
  return value && value.toLowerCase().includes(q) ? `${label} ${value}` : null;
}

function matchReason(n: ExplorerNode, q: string): string | null {
  // Name first, so the common case reports as a name match rather than as
  // whichever field happens to be tested first.
  const name = hit("name", n.name || "", q);
  if (name) return name;
  if ((n.key || "").toLowerCase().includes(q)) return `key ${n.key}`;

  for (const a of allAddresses(n)) {
    const m = hit("address", a, q);
    if (m) return m;
  }
  const model = hit("model", [n.vendor, n.model].filter(Boolean).join(" "), q);
  if (model) return model;
  const os = hit("os", n.os_version || "", q);
  if (os) return os;
  const serial = hit("serial", n.serial || "", q);
  if (serial) return serial;
  const site = hit("site", n.site || "", q);
  if (site) return site;

  for (const v of n.vlan_ids ?? []) {
    if (String(v).includes(q) || `vlan ${v}`.includes(q) || `vlan-${v}`.includes(q)) return `VLAN ${v}`;
  }
  for (const t of n.tags ?? []) {
    const m = hit("tag", t, q);
    if (m) return m;
  }
  for (const i of n.interfaces ?? []) {
    const m = hit("interface", i.name || "", q);
    if (m) return m;
  }
  const role = hit("role", n.role || n.kind || "", q);
  if (role) return role;
  return null;
}

/** Build the search corpus from a placed layout. Group cards contribute their
 *  MEMBERS, so a device inside a collapsed lane is still findable — and the hit
 *  says the lane has to be expanded to see it. */
export function searchableFrom(
  placed: { id: string; kind: "device" | "group"; layer: string | number; node?: TopoNode; members?: TopoNode[] }[],
): Searchable[] {
  const out: Searchable[] = [];
  for (const p of placed) {
    if (p.kind === "group") {
      for (const m of p.members ?? []) {
        out.push({ node: m as ExplorerNode, cardId: p.id, viaGroup: true, layer: String(p.layer) });
      }
    } else if (p.node) {
      out.push({ node: p.node as ExplorerNode, cardId: p.id, viaGroup: false, layer: String(p.layer) });
    }
  }
  return out;
}
