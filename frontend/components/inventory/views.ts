"use client";

/**
 * TWO KINDS OF SHORTCUT, AND THEY ARE NOT THE SAME KIND OF ANSWER.
 *
 *   A SAVED QUERY re-asks the API. The filter is server-side, `total` comes
 *   back describing it, and the answer is about the whole snapshot. It is only
 *   offered when the facet it is built from exists in this snapshot, so the
 *   screen never shows a chip that cannot match anything.
 *
 *   A PAGE VIEW narrows THE ROWS ALREADY LOADED. It exists because the three
 *   most useful questions on this screen — which rows disagree with themselves,
 *   which identities are unresolved, which devices nobody reported a cable for
 *   — are not server-side filters, and building them client-side is the only
 *   way to have them at all.
 *
 * The distinction is load-bearing and is rendered, not just commented. A
 * client-side narrowing presented as a query is the paging lie in a new
 * costume: "3 conflicts" off a 50-row page reads as "3 conflicts in the
 * estate", and on a 4,000-row estate that is simply false. So every page view
 * states the population it ran over, and where a real estate-wide figure exists
 * (unlinked devices — the topology engine counts them) it is printed BESIDE the
 * page figure rather than instead of it.
 */

import { useEffect, useState } from "react";
import { api, asApiError, type ApiError, type IpFilterMode } from "@/lib/api";
import type { InventoryItem, InventoryResponse } from "@/lib/types";
import type { RowIdentity } from "./identity";

// ── Saved queries (server-side) ────────────────────────────────────────────

/** The complete filter state a preset installs. Every field is set, so applying
 *  a preset REPLACES the filter rather than merging into whatever was there —
 *  a one-click chip that silently ANDs with a forgotten facet is a chip whose
 *  result nobody can explain. */
export interface QueryFilter {
  q: string;
  ip: string;
  ipMode: IpFilterMode;
  source: string;
  kind: string[];
  vlan: string[];
  zone: string[];
}

export const EMPTY_FILTER: QueryFilter = {
  q: "",
  ip: "",
  ipMode: "intersects",
  source: "",
  kind: [],
  vlan: [],
  zone: [],
};

export interface QueryPreset {
  id: string;
  label: string;
  /** What the chip ACTUALLY asks, in the API's own vocabulary. Rendered on
   *  hover, because a friendly name over a technical filter is how a reviewer
   *  ends up quoting a number as an answer to a different question. */
  asks: string;
  filter: QueryFilter;
  /** Facet count behind it, when the preset was built from one. */
  count?: number;
}

type Facets = InventoryResponse["facets"] | undefined;

/** Zone names that mean "outside the trust boundary", most specific first. Only
 *  a zone this snapshot actually declares is ever used. */
const OUTSIDE_ZONES = ["untrust", "external", "internet", "public", "dmz", "wan"];

/**
 * Build the presets this snapshot can honestly offer.
 *
 * Facet-derived presets are gated on the facet existing. Text presets are not
 * gated, because a text query is a QUESTION rather than a claim: asking "which
 * entities are tagged pci" and getting none back is a real, useful answer, and
 * the empty state already says the read succeeded.
 */
export function buildPresets(facets: Facets): QueryPreset[] {
  const out: QueryPreset[] = [];
  const zones = facets?.zones ?? {};
  const kinds = facets?.kinds ?? {};

  const outside = OUTSIDE_ZONES.find((z) => z in zones);
  if (outside) {
    out.push({
      id: "internet-facing",
      label: "Internet-facing",
      asks: `zone = "${outside}" — everything a source placed outside the trust boundary. Server-side, so the count describes the whole snapshot.`,
      filter: { ...EMPTY_FILTER, zone: [outside] },
      count: zones[outside],
    });
  }

  if ("public_ip" in kinds) {
    out.push({
      id: "public-ips",
      label: "Public address space",
      asks: "kind = public_ip — the routable blocks this estate owns or was allocated.",
      filter: { ...EMPTY_FILTER, kind: ["public_ip"] },
      count: kinds.public_ip,
    });
  }

  if ("wan_circuit" in kinds) {
    out.push({
      id: "circuits",
      label: "WAN circuits",
      asks: "kind = wan_circuit — the carrier services the estate reaches the outside world on.",
      filter: { ...EMPTY_FILTER, kind: ["wan_circuit"] },
      count: kinds.wan_circuit,
    });
  }

  out.push({
    id: "pci",
    label: "PCI",
    asks: 'free text "pci" over name, address and tag. A tag-scope question, asked server-side over the whole snapshot.',
    filter: { ...EMPTY_FILTER, q: "pci" },
  });

  out.push({
    id: "customer-data",
    label: "Customer data",
    asks: 'free text "customer-data" over name, address and tag.',
    filter: { ...EMPTY_FILTER, q: "customer-data" },
  });

  return out;
}

/** Is this preset the filter currently applied? Compared on the whole state, so
 *  a preset plus one extra facet does NOT read as the preset. */
export function filterEquals(a: QueryFilter, b: QueryFilter): boolean {
  const same = (x: string[], y: string[]) => x.length === y.length && x.every((v, i) => v === y[i]);
  return (
    a.q.trim() === b.q.trim() &&
    a.ip.trim() === b.ip.trim() &&
    (a.ip.trim() ? a.ipMode === b.ipMode : true) &&
    a.source === b.source &&
    same([...a.kind].sort(), [...b.kind].sort()) &&
    same([...a.vlan].sort(), [...b.vlan].sort()) &&
    same([...a.zone].sort(), [...b.zone].sort())
  );
}

// ── Page views (client-side, over the loaded page) ─────────────────────────

export type PageViewId = "conflicts" | "duplicates" | "merged" | "unlinked" | "findings";

export interface PageViewCtx {
  identity: (item: InventoryItem) => RowIdentity | undefined;
  /** True when the asset read failed — every identity-derived view is UNKNOWN
   *  rather than empty. */
  identityUnknown: boolean;
  /** Device keys the topology engine could not find an adjacency for.
   *  `undefined` until the topology read lands, or if it failed. */
  unlinked?: Set<string>;
}

export interface PageView {
  id: PageViewId;
  label: string;
  hint: string;
  /** Which extra read this view depends on, so the chip can say when that read
   *  has not happened or has failed instead of rendering a confident 0. */
  needs?: "identity" | "topology";
  test: (item: InventoryItem, ctx: PageViewCtx) => boolean;
}

export const PAGE_VIEWS: PageView[] = [
  {
    id: "conflicts",
    label: "Conflicts",
    hint: "Rows where two consoles state the same field differently. Not an error — a fact about the estate's own record-keeping, and what a review is for.",
    test: (i) => i.conflicts.length > 0,
  },
  {
    id: "duplicates",
    label: "Duplicate candidates",
    // Counts ROWS, not proposals — one proposal names two rows, and a chip that
    // read "1" next to two highlighted rows would be the more confusing of the
    // two lies available here.
    hint: "Rows an unconfirmed merge proposal names. One proposal names two rows, so this counts rows. Nothing has been merged: a human confirms these in Identity & merges below.",
    needs: "identity",
    test: (i, ctx) => (ctx.identity(i)?.suggestions.length ?? 0) > 0,
  },
  {
    id: "merged",
    label: "Merged identities",
    hint: "Rows the engine proved were the same thing another console called something else.",
    needs: "identity",
    test: (i, ctx) => (ctx.identity(i)?.correlations.length ?? 0) > 0,
  },
  {
    id: "unlinked",
    label: "Unlinked devices",
    hint: "Devices that are inventoried but that no onboarded source reported an adjacency for — nobody told us what they are cabled to.",
    needs: "topology",
    test: (i, ctx) => !!ctx.unlinked?.has(i.key),
  },
  {
    id: "findings",
    label: "Named in a finding",
    hint: "Rows at least one finding in this snapshot names.",
    test: (i) => i.finding_ids.length > 0,
  },
];

export const PAGE_VIEW_BY_ID: Record<string, PageView> = Object.fromEntries(PAGE_VIEWS.map((v) => [v.id, v]));

/** Is this view's underlying read available? A view whose dependency failed is
 *  DISABLED with the reason on it, never rendered as a count of zero. */
export function viewAvailable(view: PageView, ctx: PageViewCtx, topologyLoaded: boolean): boolean {
  if (view.needs === "identity") return !ctx.identityUnknown;
  if (view.needs === "topology") return topologyLoaded && ctx.unlinked !== undefined;
  return true;
}

// ── The topology read behind "unlinked devices" ────────────────────────────

export interface UnlinkedState {
  keys?: Set<string>;
  /** The engine's own estate-wide count — a real server figure, printed beside
   *  the page figure so the page view never stands in for the estate. */
  total?: number;
  /** Why each one is unlinked, keyed by device. Carried into the drawer. */
  reasons?: Map<string, { reason: string; would_be_filled_by: string }>;
  error?: ApiError;
  loading: boolean;
  /** False until something has asked for it — the topology payload is large and
   *  is not fetched for a chip nobody clicked. */
  requested: boolean;
}

export function useUnlinkedDevices(enabled: boolean, snapshot?: string): UnlinkedState {
  const [state, setState] = useState<UnlinkedState>({ loading: false, requested: false });

  useEffect(() => {
    if (!enabled) return;
    let alive = true;
    setState((s) => ({ ...s, loading: true, requested: true, error: undefined }));
    api
      .topology(snapshot)
      .then((d) => {
        if (!alive) return;
        const list = d.unlinked_devices ?? [];
        setState({
          loading: false,
          requested: true,
          keys: new Set(list.map((u) => u.device_key)),
          total: list.length,
          reasons: new Map(list.map((u) => [u.device_key, { reason: u.reason, would_be_filled_by: u.would_be_filled_by }])),
        });
      })
      .catch((e) => {
        // No empty set on failure: "no unlinked devices" and "we could not ask"
        // are different answers, and only one of them is reassuring.
        if (alive) setState({ loading: false, requested: true, error: asApiError(e) });
      });
    return () => {
      alive = false;
    };
  }, [enabled, snapshot]);

  return state;
}
