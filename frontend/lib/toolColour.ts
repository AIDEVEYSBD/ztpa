/**
 * The colour a source tool is drawn in — the ONE place the mapping lives.
 *
 * The five hexes below were spelled out three times: `TOOL_EDGE` in
 * NetworkMap.tsx, `TOOL_DOT` in ui/Badges.tsx (as Tailwind classes, so a
 * different spelling of the same intent) and `TOOL` in Landing.tsx. The
 * registry has since grown to TWELVE tools (backend/src/sources.py), and a
 * topology legend would have made it a fourth copy — at which point the same
 * tool renders in one colour on the map and another on the badge beside it, and
 * an edge colour stops being a fact about provenance and becomes a coincidence
 * of which file was edited last.
 *
 * WHY THESE VALUES. Edge strokes are 1.6px and land on `--surface-sunk`, which
 * is #F6F6FA in light and #101016 in dark, so every entry has to clear both
 * grounds at once — a palette tuned for the dark console vanished on the printed
 * report. Measured (WCAG contrast against both canvases, OKLab ΔE between
 * entries): every colour here is at least 2.25:1 on light and 3.67:1 on dark,
 * and no two are closer than ΔE 0.082 — against ΔE 0.054 for `sd_wan`/`sd_lan`,
 * which already shipped indistinguishable. None sits within ΔE 0.12 of the
 * accent yellow (which means "cross-tool path", not "a tool"), of any severity
 * colour, or of the unknown grey below.
 *
 * WHERE TWO TOOLS ARE CLOSE, THEY ARE CLOSE ON PURPOSE. Colour alone does not
 * separate twelve values at this stroke width, so the near-pairs are the ones a
 * reader is least harmed by confusing: the same vendor (`fortigate` /
 * `fortimanager`), the same job (`algosec` / `panorama`, both firewall-policy
 * aggregators), or the same layer (`sd_wan` / `carrier_portal`, both WAN). A
 * mistake inside a pair is still the right family; the legend and the edge
 * tooltip carry the tool's NAME, which is what the provenance claim actually
 * rests on.
 */
export const TOOL_COLOUR: Readonly<Record<string, string>> = {
  // firewall-policy aggregators
  algosec: "#3b82f6",          // blue 500
  panorama: "#2563eb",         // blue 600
  // east-west segmentation
  guardicore: "#8b5cf6",       // violet 500
  // cloud-hosted consoles
  wiz: "#06b6d4",              // cyan 500
  meraki: "#0891b2",           // cyan 600
  // WAN
  sd_wan: "#10b981",           // emerald 500
  carrier_portal: "#059669",   // emerald 600
  // LAN fabric
  sd_lan: "#14b8a6",           // teal 500
  // the Fortinet stack — manager and the device under it
  fortimanager: "#c026d3",     // fuchsia 600
  fortigate: "#e879f9",        // fuchsia 400
  // on-prem manager appliances
  catalyst_center: "#4d7c0f",  // lime 700
  junos_space: "#65a30d",      // lime 600
};

/**
 * What an unregistered tool is drawn in.
 *
 * Deliberately the neutral grey (`--sev-low`, theme-aware), and deliberately not
 * a sixth-nice-colour: a coloured edge is read as "this console said so", so
 * handing an unrecognised tool a plausible hue would make the map assert a
 * provenance it does not have. Grey reads as "not attributed", which is the
 * true statement, and no registered tool is within ΔE 0.12 of it.
 */
export const UNKNOWN_TOOL_COLOUR = "var(--sev-low)";

/** The colour for `tool`, or the neutral grey when it is not a registered one. */
export function toolColour(tool: string): string {
  return TOOL_COLOUR[tool] ?? UNKNOWN_TOOL_COLOUR;
}

// ── Display names ──────────────────────────────────────────────────────────
//
// A tool KEY and a tool NAME are different things, and the UI was showing the
// key. Badges read `junos_space` and `catalyst_center` while the Sources screen,
// which reads `label` off the API, said "Junos Space / Security Director" and
// "Cisco Catalyst Center" — so the same source had two names depending on which
// screen you were looking at, and one of them was a snake_case identifier.
//
// These are the SHORT forms, because the long ones are for a source card with
// room to breathe: a badge sitting inside a table row needs "Catalyst Center",
// not "Cisco Catalyst Center", and certainly not `catalyst_center`.
//
// Mirrors backend/src/sources.py REGISTRY. A key absent here falls back to a
// readable form of itself rather than to a guess — a bring-your-own connector
// names itself, and inventing a prettier name for one would be putting words in
// the operator's mouth.
const TOOL_LABEL: Record<string, string> = {
  algosec: "AlgoSec",
  guardicore: "Guardicore",
  wiz: "Wiz",
  fortimanager: "FortiManager",
  fortigate: "FortiGate",
  panorama: "Panorama",
  junos_space: "Junos Space",
  catalyst_center: "Catalyst Center",
  meraki: "Meraki",
  carrier_portal: "Carrier portal",
  sd_wan: "SD-WAN",
  sd_lan: "SD-LAN",
};

/** The display name for a source tool. Never render a raw key to a user.
 *
 *  An unregistered key (a bring-your-own SourceProfile) is de-snaked and
 *  title-cased rather than passed through raw or renamed: the operator chose
 *  that name, so it must stay recognisable as theirs. */
export function toolLabel(tool: string): string {
  const known = TOOL_LABEL[tool];
  if (known) return known;
  return tool
    .split(/[_-]/)
    .filter(Boolean)
    .map((w) => w.charAt(0).toUpperCase() + w.slice(1))
    .join(" ");
}
