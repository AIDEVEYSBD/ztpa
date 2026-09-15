"use client";

/**
 * THE FIGURE ROW — "I have these many subnets, I have these many VLANs".
 *
 * This is the single most-quoted line on the screen, so it is built as an
 * instrument readout rather than a grid of stat cards: one continuous hairline
 * block, seven gauges, big mono tabular figures, no shadows and no gaps between
 * cells. It reads as one panel making one statement.
 *
 * THE NULL RULE IS THE WHOLE POINT. `InventoryCounts` members are
 * `number | null`, and `null` means NO ONBOARDED SOURCE DECLARES THIS FIGURE.
 * It renders as an em-dash carrying that reason, never as 0 — "we don't know"
 * and "we checked, and there are none" are different claims about a client's
 * estate, and only one of them is safe to put in front of them.
 */

import { Boxes, Cable, Server } from "lucide-react";
import type { InventoryCounts } from "@/lib/types";
import { NetIcon } from "@/components/net/icons";
import { Skeleton } from "@/components/ui";

type Figure = {
  key: keyof InventoryCounts;
  /** The word the readout is quoted with ("7 VLANs"). */
  label: string;
  /** Singular form, for the not-declared tooltip. */
  noun: string;
  icon: React.ReactNode;
};

const FIGURES: Figure[] = [
  { key: "devices", label: "devices", noun: "a device count", icon: <Server size={11} /> },
  { key: "interfaces", label: "interfaces", noun: "an interface count", icon: <Cable size={11} /> },
  { key: "vlans", label: "VLANs", noun: "a VLAN count", icon: <NetIcon kind="vlan" size={11} /> },
  { key: "subnets", label: "subnets", noun: "a subnet count", icon: <NetIcon kind="subnet" size={11} /> },
  { key: "public_ips", label: "public IPs", noun: "a public-IP count", icon: <NetIcon kind="public_ip" size={11} /> },
  { key: "circuits", label: "WAN circuits", noun: "a WAN-circuit count", icon: <NetIcon kind="wan_circuit" size={11} /> },
  { key: "assets", label: "assets", noun: "an asset count", icon: <Boxes size={11} /> },
];

export function CountsReadout({ counts, loading }: { counts?: InventoryCounts; loading?: boolean }) {
  return (
    <div className="border border-border bg-surface2" style={{ borderTopWidth: 2, borderTopColor: "var(--accent)" }}>
      <div className="flex flex-wrap items-center justify-between gap-x-4 gap-y-1 border-b border-hair px-3.5 py-2">
        <span className="eyebrow">What the onboarded sources declare</span>
        <span className="text-[10.5px] text-text3">
          A figure nothing declares reads <span className="text-text2">—</span>, never 0.
        </span>
      </div>
      <div className="grid grid-cols-2 gap-px bg-border sm:grid-cols-4 xl:grid-cols-7">
        {FIGURES.map((f) => (
          <div key={f.key} className="flex flex-col gap-2 bg-surface2 px-3.5 py-3">
            <span className="flex items-center gap-1.5 text-[9.5px] font-bold uppercase tracking-[0.16em] text-text3">
              <span className="shrink-0 text-text3">{f.icon}</span>
              {f.label}
            </span>
            {loading || !counts ? (
              <Skeleton className="h-[26px] w-16" />
            ) : (
              <Figure value={counts[f.key]} label={f.label} noun={f.noun} />
            )}
          </div>
        ))}
      </div>
    </div>
  );
}

function Figure({ value, label, noun }: { value: number | null; label: string; noun: string }) {
  if (value === null || value === undefined) {
    return (
      <span
        className="mono cursor-help text-[28px] font-bold leading-none tracking-[-0.02em] text-text3 underline decoration-dotted decoration-1 underline-offset-[6px]"
        title={`No onboarded source declares ${noun}. This is UNKNOWN, not zero — the Sources screen lists what each console is blind to.`}
        aria-label={`${label}: not declared by any onboarded source`}
      >
        —
      </span>
    );
  }
  return (
    <span className="mono text-[28px] font-bold leading-none tracking-[-0.02em] tabular-nums" aria-label={`${value} ${label}`}>
      {value.toLocaleString()}
    </span>
  );
}

export default CountsReadout;
