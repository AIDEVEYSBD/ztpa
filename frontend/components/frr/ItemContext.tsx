"use client";

/**
 * What the context datasets say about one package item: who owns what the rule
 * reaches (CMDB/IPAM), and which sources were seen using it (flows). Shown
 * up front, because it is what a network owner validates the change against.
 */

import { Users, Waypoints } from "lucide-react";
import type { PackageItem } from "@/lib/frrTypes";

type Owner = { net: string; owner?: string | null; application?: string | null; environment?: string | null;
               zone?: string | null; criticality?: string | null };
type Observed = { window_days: number; groups: { cidr: string; sources: number; flows: number }[]; truncated: boolean };

export function ItemContext({ item }: { item: PackageItem }) {
  const ev = (item.evidence ?? {}) as Record<string, unknown>;
  const owners = (ev.dest_owners as Owner[] | undefined) ?? [];
  const observed = ev.observed_sources as Observed | undefined;
  if (!owners.length && !observed) return null;
  return (
    <div className="grid gap-2 md:grid-cols-2">
      {owners.length > 0 && (
        <div className="rounded-md border border-line p-2.5 text-[11.5px]">
          <div className="mb-1 flex items-center gap-1.5 font-medium text-fg"><Users size={13} className="text-dim" /> Destination owners (CMDB)</div>
          <ul className="space-y-0.5">
            {owners.slice(0, 5).map((o) => (
              <li key={o.net} className="min-w-0 break-words">
                <span className="font-mono text-dim">{o.net}</span>{" "}
                <span className="text-fg">{o.owner ?? "no owner recorded"}</span>
                {o.application && <span className="text-dim"> · {o.application}</span>}
                {o.criticality && <span className="text-faint"> · {o.criticality}</span>}
              </li>
            ))}
          </ul>
        </div>
      )}
      {observed && (
        <div className="rounded-md border border-line p-2.5 text-[11.5px]">
          <div className="mb-1 flex items-center gap-1.5 font-medium text-fg">
            <Waypoints size={13} className="text-dim" /> Observed sources, last {observed.window_days} days
          </div>
          {observed.groups.length === 0 ? (
            <p className="text-dim">No flows matched this rule in the window.</p>
          ) : (
            <ul className="space-y-0.5 font-mono">
              {observed.groups.slice(0, 8).map((g) => (
                <li key={g.cidr} className="flex gap-3">
                  <span className="text-fg">{g.cidr}</span>
                  <span className="tnum text-dim">{g.sources} src · {g.flows.toLocaleString()} flows</span>
                </li>
              ))}
              {(observed.groups.length > 8 || observed.truncated) && (
                <li className="text-faint">+ more in the evidence</li>
              )}
            </ul>
          )}
        </div>
      )}
    </div>
  );
}
