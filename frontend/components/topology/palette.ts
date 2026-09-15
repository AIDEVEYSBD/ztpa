/**
 * The topology canvas's two data palettes — VLAN bands and redundant groups.
 *
 * Everything that carries UI MEANING on this screen (severity, accent, surface,
 * hairline) comes from the CSS custom properties in app/globals.css, because
 * those flip wholesale between light and dark and a hardcoded hex is invisible
 * in one of the two themes. The two palettes below are the deliberate
 * exception, for the same reason lib/toolColour.ts is one: a VLAN id is DATA,
 * not a state, and there is no token vocabulary for "the fourth VLAN". Mapping
 * VLANs onto `--ok` / `--sev-medium` would be worse than a fixed palette — it
 * would assert that VLAN 20 is healthy and VLAN 40 is a warning.
 *
 * So these are fixed hues, chosen the way toolColour.ts chose its twelve: each
 * one has to clear BOTH grounds at once (`--surface-sunk` is #F6F6FA in light
 * and #101016 in dark), because a palette tuned for the dark console vanishes on
 * the printed report. They are used as a 1px keyline plus a low-alpha wash
 * behind a card, never as text colour, and — the rule that actually makes them
 * safe — COLOUR IS NEVER THE ONLY CARRIER. Every banded node prints its VLAN as
 * text (`VLAN 30 · app-tier`) and every redundant link carries a tag (`R1`)
 * that the legend spells out. Read the screen in greyscale and nothing is lost.
 */

import type { CSSProperties } from "react";

/**
 * Eight VLAN bands. Mid-tone, evenly spread around the wheel, and deliberately
 * clear of the two hues that already mean something here: the electric-yellow
 * accent (selection / the finding under walkthrough) and the critical red (a
 * failed device during a resilience replay).
 */
export const VLAN_PALETTE: readonly string[] = [
  "#D2492A", // vermilion
  "#A87A00", // ochre
  "#4E8F27", // green
  "#0E9488", // teal
  "#2D7FF9", // azure
  "#5B5BD6", // indigo
  "#9B4BC9", // violet
  "#C2407E", // magenta
];

export interface VlanBand {
  vlan_id: number;
  name?: string | null;
  /** The band colour, or null past the eighth VLAN (see `hatched`). */
  colour: string | null;
  /**
   * True for the ninth VLAN onward. The palette does not grow: nine
   * indistinguishable colours are not a palette, they are a lie about how much
   * the reader can tell apart. Past the eighth the band is drawn as a neutral
   * hatch and identified by its LABEL alone, and the legend says so out loud.
   */
  hatched: boolean;
  /** `VLAN 30 · app-tier` — the text that always accompanies the colour. */
  label: string;
}

/** The label a VLAN always carries, name included when a console reported one. */
export function vlanLabel(vlan_id: number, name?: string | null): string {
  return name ? `VLAN ${vlan_id} · ${name}` : `VLAN ${vlan_id}`;
}

/**
 * Assign bands to the VLANs in a payload.
 *
 * Indexed by ASCENDING VLAN ID rather than by order of appearance, so the same
 * estate re-renders with the same colours between loads, between snapshots and
 * between this screen and the legend beside it.
 */
export function buildVlanBands(
  vlans: { vlan_id: number; name?: string | null }[],
): Map<number, VlanBand> {
  const out = new Map<number, VlanBand>();
  const sorted = [...vlans].sort((a, b) => a.vlan_id - b.vlan_id);
  sorted.forEach((v, i) => {
    out.set(v.vlan_id, {
      vlan_id: v.vlan_id,
      name: v.name ?? null,
      colour: i < VLAN_PALETTE.length ? VLAN_PALETTE[i] : null,
      hatched: i >= VLAN_PALETTE.length,
      label: vlanLabel(v.vlan_id, v.name),
    });
  });
  return out;
}

/** A VLAN the `vlans` list never declared. Real (an interface reported the tag)
 *  and unnamed, so it gets the neutral hatch and its number, never a guess. */
export function unknownVlanBand(vlan_id: number): VlanBand {
  return { vlan_id, name: null, colour: null, hatched: true, label: `VLAN ${vlan_id}` };
}

/** The wash behind a banded card: the band hue at low alpha, or the neutral
 *  hatch for the ninth VLAN onward. Returned as inline style, not a class,
 *  because the hue is data. */
export function bandStyle(band: VlanBand): CSSProperties {
  if (band.colour) return { background: `${band.colour}1F`, borderLeft: `3px solid ${band.colour}` };
  return {
    background:
      "repeating-linear-gradient(135deg, var(--surface-hover) 0 4px, transparent 4px 8px)",
    borderLeft: "3px solid var(--text-3)",
  };
}

/**
 * Redundant-group tints.
 *
 * THREE, not eight, and they cycle. The number of redundant groups in a real
 * estate is small, and the thing that has to read at a glance is not "which
 * group is this" but "these two links are the pair" — so the tint ties members
 * together and the `R1` / `R2` tag on each member is what actually identifies
 * the group. Beyond three groups the tints repeat and the tags do not, which is
 * the right way round: an ambiguous colour with an unambiguous label is a
 * legible diagram, the reverse is a quiz.
 *
 * All three are CSS tokens, because unlike a VLAN id these sit on top of link
 * strokes that must stay visible in both themes, and the tokens are already
 * tuned for exactly that. `--accent` is deliberately NOT among them: on this
 * canvas yellow means "the finding you are currently walking through".
 */
export const REDUNDANCY_TINTS: readonly string[] = [
  "var(--info)",
  "var(--ok)",
  "var(--sev-medium)",
];

export interface RedundancyBand {
  group: string;
  /** `R1`, `R2`, … — the identity the legend maps back to the group name. */
  tag: string;
  tint: string;
}

/** Tag + tint per `redundant_group`, ordered by group name so the mapping is
 *  stable between renders. */
export function buildRedundancyBands(groups: string[]): Map<string, RedundancyBand> {
  const out = new Map<string, RedundancyBand>();
  [...new Set(groups)].sort().forEach((g, i) => {
    out.set(g, { group: g, tag: `R${i + 1}`, tint: REDUNDANCY_TINTS[i % REDUNDANCY_TINTS.length] });
  });
  return out;
}
