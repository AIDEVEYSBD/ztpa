/**
 * The walkthrough's item type: one finding, in the shape the sidebar reads.
 *
 * Two different payloads feed this screen and they are NOT the same kind of
 * claim, so they are normalised rather than merged:
 *
 *   resilience  `/api/resilience` — single points of failure. Carries its own
 *               severity vector (R·L·S, see backend/src/analyzers/resilience.py),
 *               a remediation sentence, and — for the ones that name a device —
 *               a measured blast radius. These are the findings this canvas was
 *               built to animate.
 *   policy      the console's `Finding[]`, filtered to the ones that actually
 *               touch a device on this canvas. They carry rule refs and an
 *               explanation the advisory layer may or may not have written yet.
 *
 * `kind` stays on every item so the sidebar can never present a policy finding's
 * `signals` as a severity vector, or offer a remediation the payload does not
 * contain.
 */

import type { ResilienceFindingRow } from "@/lib/api";
import type { Band, BlastRadius, Finding, TopoNode } from "@/lib/types";

export type WalkKind = "resilience" | "policy";

export interface WalkFinding {
  id: string;
  kind: WalkKind;
  /** The engine's own type string (`shared_circuit_handoff`, `over_permissive`). */
  type: string;
  title: string;
  /** What the problem is, in the engine's words. Empty when nothing was written
   *  — the sidebar says so rather than inventing a sentence. */
  detail: string;
  severity: number;
  band: Band;
  forcedCritical: boolean;
  /** Keys the finding names — devices, circuits AND link ids. Not all of them
   *  are on the canvas. */
  involved: string[];
  /**
   * The element whose loss causes the damage, which is not always the element
   * the finding is named after: a single-homed modem is scored on its PARENT's
   * cut. The canvas turns this one critical, and the severity vector beside it
   * is the one measured from this device's failure. They have to be the same
   * device or the panel is showing two different failures at once.
   */
  failing: string[];
  /** Everything that loses its path when `failing` goes: stranded circuits
   *  first, then isolated devices. Off the payload; never recomputed. */
  lost: string[];
  /** The circuits the finding itself names as at risk. */
  circuits: string[];
  /**
   * True when `failing` names more than one element, i.e. the severity was
   * measured over their SIMULTANEOUS loss. No per-device blast radius explains
   * such a finding — the engine computed a combined cut that this payload does
   * not carry — so none is shown beside it. Putting one device's numbers under
   * a vector measured from several is the same defect as a count derived from a
   * failed fetch: a real number answering a different question.
   */
  combinedFailure: boolean;
  remediation?: string;
  ruleRefs: string[];
  /** Device keys / circuit ids a resilience finding cites. Not rule refs. */
  rawRefs: string[];
  sourceTools: string[];
  /** R·L·S for resilience; the raw signal bag for a policy finding. */
  vector: Record<string, unknown>;
  blast?: BlastRadius;
}

const TITLE_CASE = (s: string) =>
  s.replace(/[_:]+/g, " ").replace(/\b\w/g, (c) => c.toUpperCase());

/**
 * Resilience findings -> walkthrough items.
 *
 * The blast radius is attached by matching a finding's involved keys against
 * `blast_radius[].device_key`. It is looked up, never recomputed: the fraction,
 * the stranded circuits and the isolated set come out of a graph cut the engine
 * performed over the whole adjacency, and a browser recomputing any of it from
 * the lanes it happens to be drawing would produce a number that disagrees with
 * the report for a reason nobody could find.
 */
export function fromResilience(findings: ResilienceFindingRow[], blast: BlastRadius[]): WalkFinding[] {
  const byDevice = new Map(blast.map((b) => [b.device_key, b]));
  return findings.map((f) => {
    const failing = f.failing ?? [];
    const circuits = f.circuits ?? [];
    // A per-device radius is attached only when exactly one device fails. With
    // several, the engine scored the combined cut (`calc.of("carrier:X",
    // removed_nodes=cpes)`) and this payload carries only the per-device list —
    // so there is no row here whose fraction equals the vector's R, and the
    // honest thing is to show none rather than the closest-looking one.
    const single =
      failing.length === 1
        ? byDevice.get(failing[0])
        : failing.length === 0
          ? f.involved.map((k) => byDevice.get(k)).find((b): b is BlastRadius => !!b)
          : undefined;
    return {
      id: f.id,
      kind: "resilience" as const,
      type: f.kind,
      title: f.title,
      detail: f.detail,
      severity: f.severity,
      band: f.severity_band,
      forcedCritical: false,
      involved: f.involved,
      failing,
      circuits,
      combinedFailure: failing.length > 1,
      // Stranded circuits before isolated devices: the loss is drawn outside-in,
      // which is the direction the canvas is read in. With no measured radius
      // it is the circuits the finding itself names — its own claim, not a
      // browser-side inference.
      lost: single ? [...single.circuits_stranded, ...single.devices_isolated] : circuits,
      remediation: f.remediation,
      ruleRefs: [],
      rawRefs: f.raw_refs ?? [],
      sourceTools: f.source_tools ?? [],
      vector: f.severity_vector ?? {},
      blast: single,
    };
  });
}

/**
 * Policy findings -> walkthrough items, filtered to what this canvas can show.
 *
 * A finding about a rule between two cloud workloads has nothing to highlight
 * here, and listing it would put "12 of 40" on a walkthrough where 28 of the
 * steps light nothing up. So the filter is: the finding names a device on the
 * canvas, OR a device on the canvas names the finding (`TopoNode.finding_ids`,
 * which is the join the backend maintains). Anything else belongs on the Risk
 * To-Do screen, and the panel says how many were left there.
 */
export function fromPolicy(findings: Finding[], nodes: TopoNode[]): { items: WalkFinding[]; skipped: number } {
  const keys = new Set(nodes.map((n) => n.key));
  const byFinding = new Map<string, string[]>();
  for (const n of nodes) {
    for (const fid of n.finding_ids ?? []) {
      const bucket = byFinding.get(fid);
      if (bucket) bucket.push(n.key);
      else byFinding.set(fid, [n.key]);
    }
  }

  const items: WalkFinding[] = [];
  let skipped = 0;
  for (const f of findings) {
    const named = (f.involved ?? []).filter((k) => keys.has(k));
    const back = byFinding.get(f.finding_id) ?? [];
    const involved = [...new Set([...named, ...back])];
    if (involved.length === 0) { skipped += 1; continue; }
    items.push({
      id: f.finding_id,
      kind: "policy",
      type: f.type,
      title: TITLE_CASE(f.type),
      detail: f.explanation ?? "",
      severity: f.severity,
      band: f.severity_band,
      forcedCritical: f.forced_critical,
      involved,
      failing: [],
      lost: [],
      circuits: [],
      combinedFailure: false,
      ruleRefs: f.raw_refs ?? [],
      rawRefs: [],
      sourceTools: f.source_tools ?? [],
      vector: f.signals ?? {},
    });
  }
  return { items, skipped };
}

/** Critical first, then severity, then id — deterministic between renders. */
export function sortWalk(items: WalkFinding[]): WalkFinding[] {
  const rank: Record<Band, number> = { critical: 0, high: 1, medium: 2, low: 3 };
  return [...items].sort(
    (a, b) => rank[a.band] - rank[b.band] || b.severity - a.severity || a.id.localeCompare(b.id),
  );
}

/**
 * The cards a finding lights up.
 *
 * Involved keys are resolved THROUGH `cardFor`, so a device inside a collapsed
 * group lights its group card instead of silently lighting nothing — the whole
 * point of the walkthrough is that the viewer sees where the problem is, and a
 * collapsed lane must not be able to swallow it.
 */
export function involvedCards(item: WalkFinding, cardFor: Map<string, string>): Set<string> {
  const out = new Set<string>();
  for (const k of item.involved) {
    const card = cardFor.get(k);
    if (card) out.add(card);
  }
  return out;
}

/** The blast-radius readout, as sentences, straight off the payload. */
export function blastLines(b: BlastRadius): { label: string; value: string }[] {
  return [
    { label: "Paths to a circuit lost", value: `${b.paths_lost} of ${b.paths_before}` },
    { label: "Share of reachability destroyed", value: `${Math.round(b.fraction * 1000) / 10}%` },
    { label: "Circuits stranded", value: b.circuits_stranded.length ? b.circuits_stranded.join(", ") : "none" },
    { label: "Devices isolated (no path at all)", value: String(b.devices_isolated.length) },
    { label: "Devices degraded (fewer paths)", value: String(b.devices_degraded) },
    { label: "Components after the cut", value: String(b.components_after) },
  ];
}
