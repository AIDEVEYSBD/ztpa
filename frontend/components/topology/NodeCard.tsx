"use client";

/**
 * One card on the canvas: a device, or the group card a collapsed lane draws in
 * place of a dozen of them.
 *
 * Compact by design — glyph, name, model, source count — because the thing this
 * screen has to communicate is the SHAPE of the estate, and a card carrying six
 * lines of detail turns nine lanes into a wall of text.
 *
 * WHAT CHANGED. The card used to be an inert `<div>` with a tooltip, which is
 * why the owner said "i cant use it or click on something to see details about
 * it": everything a card knew was on a hover the mouse had to hold still for,
 * and nothing at all was on a click. It is now an activatable control — click
 * or Enter opens the detail drawer, a group card opens its lane instead —
 * keeping the tooltip as the quick read rather than as the only read.
 */

import { ChevronsUpDown, Unlink } from "lucide-react";
import { NetIcon } from "@/components/net/icons";
import { cn } from "@/lib/cn";
import type { PlacedNode } from "./layout";
import { bandStyle, type VlanBand } from "./palette";

export type NodeState = "normal" | "dim" | "focus" | "failed" | "isolated";

export interface NodeCardProps {
  placed: PlacedNode;
  state: NodeState;
  /** VLAN bands this device carries, already resolved to colours + labels. */
  bands: VlanBand[];
  /**
   * The tools this deployment knows to be seeded exports rather than live
   * connectors, or `null` when the source register could not be read. Null is
   * NOT "none": a card whose provenance we could not check says nothing about
   * it rather than implying the data is live.
   */
  simulatedTools: ReadonlySet<string> | null;
  unlinkedReason?: string | null;
  /** Open this card's lane (group cards only). */
  onExpand?: () => void;
  /** Open the detail drawer for this device. */
  onSelect?: () => void;
  /** This card is the drawer's current subject. */
  selected?: boolean;
  /** This card matches the current search. */
  matched?: boolean;
  /** …and it is the match the canvas has scrolled to. */
  activeMatch?: boolean;
  /** Position in the cross-tool chain, when the reachability overlay is on.
   *  0 is the entry point; the last index is the terminal. */
  pathIndex?: number;
  pathTerminal?: boolean;
  reduced: boolean;
}

function Micro({ children, tone = "neutral", title }: { children: React.ReactNode; tone?: "neutral" | "warn" | "accent" | "sim"; title?: string }) {
  return (
    <span
      title={title}
      className={cn(
        "inline-flex h-[13px] shrink-0 items-center gap-0.5 border px-1 text-[9px] font-bold leading-none",
        tone === "neutral" && "border-border bg-sunk text-text3",
        tone === "warn" && "border-sev-high-line bg-sev-high-bg text-sev-high",
        tone === "accent" && "border-accent bg-accent-soft text-accent-fg",
        tone === "sim" && "border-info-line bg-info-bg text-info",
      )}
    >
      {children}
    </span>
  );
}

export function NodeCard({
  placed, state, bands, simulatedTools, unlinkedReason, onExpand, onSelect,
  selected, matched, activeMatch, pathIndex, pathTerminal, reduced,
}: NodeCardProps) {
  const box = { left: placed.x, top: placed.y, width: placed.w, height: placed.h } as const;
  const band = bands[0];
  const wash = band ? bandStyle(band) : undefined;
  const onPath = pathIndex != null;

  const shell = cn(
    "absolute z-10 flex flex-col justify-between overflow-hidden border p-1.5 text-left",
    !reduced && "transition-[opacity,border-color,box-shadow] duration-300",
    // A dimmed card is still a card: it stays above the threshold where it can
    // be read and pointed at, because "everything else is unclickable" was the
    // exact complaint that started this rework.
    state === "dim" && "opacity-[0.26]",
    state === "isolated" && "opacity-[0.28]",
    state === "focus" && "border-accent shadow-[0_0_0_2px_var(--accent-glow)]",
    state === "failed" && "border-sev-critical bg-sev-critical-bg",
    (state === "normal" || state === "dim") && "border-border",
    state === "isolated" && "border-sev-critical-line",
    onPath && "border-accent shadow-[0_0_0_2px_var(--accent-glow)]",
    matched && !selected && "border-info shadow-[0_0_0_2px_var(--info-bg)]",
    activeMatch && "border-info shadow-[0_0_0_3px_var(--info-line)]",
    selected && "border-accent shadow-[0_0_0_3px_var(--accent-glow)]",
    !band && (state === "failed" ? "" : "bg-surface"),
    (onSelect || onExpand) && "cursor-pointer hover:border-accent focus-visible:outline focus-visible:outline-2 focus-visible:outline-accent",
  );

  if (placed.kind === "group") {
    const members = placed.members ?? [];
    const role = placed.role ?? "unknown";
    return (
      <div
        style={box}
        role="button"
        tabIndex={0}
        aria-label={`${members.length} ${role} devices, collapsed. Activate to expand the ${placed.layer} lane.`}
        onClick={onExpand}
        onKeyDown={(e) => {
          if (e.key === "Enter" || e.key === " ") { e.preventDefault(); onExpand?.(); }
        }}
        className={cn(shell, "border-dotted")}
        title={`${members.length} devices in the ${placed.layer} lane with role ${role}:\n${members.map((m) => m.name || m.key).join("\n")}`}
      >
        <div className="flex items-center gap-1.5">
          <NetIcon kind={role} size={18} className="shrink-0 text-text2" />
          <span className="mono truncate text-[11.5px] font-bold">
            {members.length} × {role}
          </span>
        </div>
        <div className="truncate text-[10px] text-text3">collapsed — nothing dropped</div>
        <span className="inline-flex h-[15px] w-full items-center justify-center gap-1 border border-border bg-sunk text-[9px] font-bold text-text2">
          <ChevronsUpDown size={9} /> Expand
        </span>
      </div>
    );
  }

  const n = placed.node!;
  const tools = n.observed_by ?? [];
  const sim = simulatedTools ? tools.some((o) => simulatedTools.has(o.tool)) : false;
  const findings = n.finding_ids?.length ?? 0;
  const secondary = band
    ? band.label
    : n.model || n.vendor || n.addresses?.[0] || n.kind;

  const tip = [
    n.name || n.key,
    `key: ${n.key}`,
    n.role ? `role: ${n.role}` : null,
    [n.vendor, n.model].filter(Boolean).join(" ") || null,
    n.addresses?.length ? `addresses: ${n.addresses.join(", ")}` : null,
    n.vlan_ids?.length ? `vlans: ${n.vlan_ids.join(", ")}` : null,
    n.ha_group ? `HA ${n.ha_group}${n.ha_role ? ` (${n.ha_role})` : ""}` : null,
    n.layer_reason ? `lane: ${n.layer_reason}` : null,
    tools.length ? `observed by: ${tools.map((o) => `${o.tool} (${o.tier})`).join(", ")}` : "observed by: nothing recorded",
    unlinkedReason ? `unlinked: ${unlinkedReason}` : null,
    onSelect ? "— click for every address, interface, source and policy that touches it" : null,
  ]
    .filter(Boolean)
    .join("\n");

  return (
    <div
      style={{ ...box, ...wash }}
      role="button"
      tabIndex={0}
      aria-pressed={selected}
      aria-label={`${n.name || n.key}${n.role ? `, ${n.role}` : ""}. Open details.`}
      onClick={onSelect}
      onKeyDown={(e) => {
        if (e.key === "Enter" || e.key === " ") { e.preventDefault(); onSelect?.(); }
      }}
      className={cn(shell, unlinkedReason && "border-dashed")}
      title={tip}
    >
      <div className="flex items-center gap-1.5">
        <NetIcon
          kind={n.role ?? n.kind}
          size={18}
          className={cn("shrink-0", state === "failed" ? "text-sev-critical" : "text-text2")}
        />
        <span className="mono min-w-0 flex-1 truncate text-[11.5px] font-bold">{n.name || n.key}</span>
        {/* The hop number, when the reachability chain runs through this card.
            A number, not just a glow: which hop it is, is the fact. */}
        {onPath ? (
          <span
            className={cn(
              "mono inline-flex h-[14px] min-w-[14px] shrink-0 items-center justify-center px-0.5 text-[9px] font-bold leading-none",
              pathTerminal ? "bg-sev-critical text-surface" : "bg-accent text-accent-ink",
            )}
            title={pathTerminal ? "The chain ends here." : `Step ${pathIndex + 1} of the cross-tool chain.`}
          >
            {pathIndex + 1}
          </span>
        ) : n.ha_role ? (
          <Micro title={`HA ${n.ha_group}`}>{n.ha_role}</Micro>
        ) : null}
      </div>

      <div className="mono truncate text-[10px] text-text3">
        {secondary}
        {bands.length > 1 ? <span className="ml-1 text-text2">+{bands.length - 1}</span> : null}
      </div>

      <div className="flex items-center gap-1 overflow-hidden">
        <Micro
          title={
            tools.length
              ? tools.map((o) => `${o.tool} (${o.tier})${o.evidence ? ` · ${o.evidence}` : ""}`).join("\n")
              : "No console is recorded as having observed this device."
          }
        >
          {tools.length} src
        </Micro>
        {sim ? <Micro tone="sim" title="At least one console that reported this device is a seeded export, not a live connector.">sim</Micro> : null}
        {findings > 0 ? <Micro tone="warn" title={n.finding_ids.join("\n")}>{findings} finding{findings === 1 ? "" : "s"}</Micro> : null}
        {unlinkedReason ? (
          <Micro tone="warn" title={unlinkedReason}>
            <Unlink size={8} /> unlinked
          </Micro>
        ) : null}
      </div>
    </div>
  );
}
