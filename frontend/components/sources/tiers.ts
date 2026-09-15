import type { SourceTier } from "@/lib/types";

/**
 * The collection ladder, in the order a reviewer actually walks it.
 *
 * This is not a display preference. The ask describes a fallback sequence —
 * "AlgoSec will give you visibility of everything; any central management
 * consoles; if not anything then we look at individual devices in their scope"
 * — and `tier` (backend/src/sources.py) is that sequence made into data. The
 * Sources screen groups by it because the GROUPING is the claim: an estate with
 * an aggregator connected and an estate reading three boxes directly are not
 * the same estate, and a flat list of cards says they are.
 *
 * The order is aggregator → management_console → device, top rung first.
 */
export const TIER_ORDER: readonly SourceTier[] = ["aggregator", "management_console", "device"];

export interface TierMeta {
  /** Rung label, as prose rather than as the wire value. */
  label: string;
  /** Position on the ladder, 1 = top. `0` = a tier this build does not know. */
  rung: number;
  /** What a fact from this rung is worth, in one line. */
  blurb: string;
  /**
   * What it means when NOTHING is connected at this rung. Rendered as a named
   * absence, so an empty rung reads as a coverage gap with a consequence rather
   * than as a heading with nothing under it.
   */
  absence: string;
}

const AGGREGATOR: TierMeta = {
  label: "Aggregator",
  rung: 1,
  blurb:
    "Broad and second-hand: it reports what the devices it manages told it. One read covers " +
    "everything that was ever added to it — and nothing that was not.",
  absence:
    "Nothing at the top of the ladder. There is no cross-vendor view of this estate, so coverage " +
    "is only ever as wide as the consoles and devices connected below.",
};

const CONSOLE: TierMeta = {
  label: "Management console",
  rung: 2,
  blurb: "Deep on its own vendor, and blind to every other. Fills the lanes an aggregator does not manage.",
  absence:
    "No vendor console is connected. Any device an aggregator does not already manage has to be read " +
    "off the box itself, or it is not read at all.",
};

const DEVICE: TierMeta = {
  label: "Device",
  rung: 3,
  blurb:
    "Authoritative, and does not scale: read off the box, in its own scope. The bottom of the ladder " +
    "and the last thing standing between a gap and a guess.",
  absence:
    "Nothing is read directly off a device. Everything known about this estate is second-hand, and the " +
    "rungs above cannot see cabling, sub-interfaces or a demarc.",
};

/** A tier this frontend build has no vocabulary for. It is NOT dropped: a source
 *  the API returned and the screen silently omitted is worse than one shown
 *  under an honest "unrecognised" heading. */
export const UNKNOWN_TIER: TierMeta = {
  label: "Unrecognised rung",
  rung: 0,
  blurb:
    "The API placed this source at a tier this build of the console does not know. It is shown as-is " +
    "rather than hidden — the frontend and backend are probably different builds.",
  absence: "",
};

const TIER_META: Record<SourceTier, TierMeta> = {
  aggregator: AGGREGATOR,
  management_console: CONSOLE,
  device: DEVICE,
};

/** Metadata for a tier string off the wire — never `undefined`, so an unknown
 *  tier renders as itself instead of crashing a group header. */
export function tierMeta(tier: string): TierMeta {
  return Object.prototype.hasOwnProperty.call(TIER_META, tier)
    ? TIER_META[tier as SourceTier]
    : UNKNOWN_TIER;
}

/** Ladder position for sorting a mixed list (unknown tiers sort last). */
export function tierRank(tier: string): number {
  const r = tierMeta(tier).rung;
  return r === 0 ? TIER_ORDER.length + 1 : r;
}
