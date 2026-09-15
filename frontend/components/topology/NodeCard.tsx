"use client";

/**
 * One card on the canvas: a device, or the group card a collapsed lane draws in
 * place of a dozen of them.
 *
 * Compact by design — glyph, name, model, source count — because the thing this
 * screen has to communicate is the SHAPE of the estate, and a card carrying six
 * lines of detail turns nine lanes into a wall of text. Everything trimmed off
 * the face of the card is on its tooltip, which is the one place a dense
 * instrument is allowed to put detail.
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
  onExpand?: () => void;
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

export function NodeCard({ placed, state, bands, simulatedTools, unlinkedReason, onExpand, reduced }: NodeCardProps) {
  const box = { left: placed.x, top: placed.y, width: placed.w, height: placed.h } as const;
  const band = bands[0];
  const wash = band ? bandStyle(band) : undefined;

  const shell = cn(
    "absolute z-10 flex flex-col justify-between overflow-hidden border p-1.5",
    !reduced && "transition-[opacity,border-color,box-shadow] duration-300",
    state === "dim" && "opacity-[0.18]",
    state === "isolated" && "opacity-[0.22]",
    state === "focus" && "border-accent shadow-[0_0_0_2px_var(--accent-glow)]",
    state === "failed" && "border-sev-critical bg-sev-critical-bg",
    (state === "normal" || state === "dim") && "border-border",
    state === "isolated" && "border-sev-critical-line",
    !band && (state === "failed" ? "" : "bg-surface"),
  );

  if (placed.kind === "group") {
    const members = placed.members ?? [];
    const role = placed.role ?? "unknown";
    return (
      <div
        style={box}
        className={cn(shell, "border-dotted")}
        title={`${members.length} devices in the ${placed.layer} lane with role ${role}:\n${members.map((m) => m.name || m.key).join("\n")}`}
      >
        <div className="flex items-center gap-1.5">
          <NetIcon kind={role} size={15} className="shrink-0 text-text2" />
          <span className="mono truncate text-[11.5px] font-bold">
            {members.length} × {role}
          </span>
        </div>
        <div className="truncate text-[10px] text-text3">collapsed — nothing dropped</div>
        <button
          type="button"
          onClick={onExpand}
          className="inline-flex h-[15px] w-full items-center justify-center gap-1 border border-border bg-sunk text-[9px] font-bold text-text2 hover:border-accent hover:text-accent-fg"
        >
          <ChevronsUpDown size={9} /> Expand
        </button>
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
  ]
    .filter(Boolean)
    .join("\n");

  return (
    <div style={{ ...box, ...wash }} className={cn(shell, unlinkedReason && "border-dashed")} title={tip}>
      <div className="flex items-center gap-1.5">
        <NetIcon
          kind={n.role ?? n.kind}
          size={15}
          className={cn("shrink-0", state === "failed" ? "text-sev-critical" : "text-text2")}
        />
        <span className="mono min-w-0 flex-1 truncate text-[11.5px] font-bold">{n.name || n.key}</span>
        {n.ha_role ? <Micro title={`HA ${n.ha_group}`}>{n.ha_role}</Micro> : null}
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
