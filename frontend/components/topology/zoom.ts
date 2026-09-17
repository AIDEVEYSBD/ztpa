/**
 * The canvas zoom range, in one place.
 *
 * Three clamps used to disagree: the two ZoomBar buttons carried `0.5, 1.6` as
 * literals and `fit` carried its own floor. They are different rules and both
 * are wanted -- FIT.min is a bound on what the app may choose FOR you
 * (below it the hostnames stop being readable, so an automatic fit that went
 * there would be choosing an unreadable picture), while ZOOM.min is a bound on
 * what a reader may ASK for. A reader zooming out deliberately, to see shape
 * rather than names, is not making a mistake.
 *
 * `step` is multiplicative. The old `zoom ± 0.1` moved 20% per press at 0.5 and
 * 6% at 1.6, so the control got slower exactly as the diagram got bigger.
 */
export const ZOOM = { min: 0.4, max: 2, step: 1.15 } as const;

/** What `Fit` may choose. Narrower than ZOOM on purpose; see above. */
export const FIT = { min: 0.72, max: 1 } as const;

export const clampZoom = (z: number) => Math.min(ZOOM.max, Math.max(ZOOM.min, z));

/** Snap to exactly 1 near it, so stepping always has a true 100% rung. */
export const snap = (z: number) => (Math.abs(z - 1) < 0.02 ? 1 : z);

/**
 * The content tier a zoom level unlocks.
 *
 * SEMANTIC ZOOM: what a card SAYS changes with scale, never how big it is.
 * Card geometry is fixed (`layout.ts` GEOM) because lane height and row stride
 * read the constant rather than the placed node, so a taller card would overlap
 * its neighbour rather than push it.
 *
 *   far   below 0.72  -- text is sub-9px and unreadable, so stop drawing it
 *   mid   the default -- name, addresses, the badges
 *   near  0.0 and up  -- the fields that are otherwise a click away
 */
export type Tier = "far" | "mid" | "near";

export function tierFor(zoom: number): Tier {
  if (zoom < 0.72) return "far";
  if (zoom >= 1.3) return "near";
  return "mid";
}
