"use client";

/**
 * NAT-rule hygiene for the export: NAT rules that can never be used, disabled
 * ones still present, static NAT no live rule reaches, and internal hosts the
 * internet reaches through static NAT. Access rules are evaluated on addresses
 * as written; NAT is context and hygiene, which the limitations box states.
 */

import { ArrowRightLeft } from "lucide-react";
import type { NatFinding } from "@/lib/frrTypes";
import { Chip, SeverityPill } from "../ui";

const LABEL: Record<string, string> = {
  nat_internet_exposure: "Internet exposure via NAT",
  nat_shadowed: "Shadowed NAT rule",
  nat_orphan: "Orphan static NAT",
  nat_disabled: "Disabled NAT rule",
};

export function NatFindings({ findings }: { findings: NatFinding[] }) {
  if (!findings.length) return null;
  const order = ["critical", "high", "medium", "low"];
  const sorted = [...findings].sort((a, b) => order.indexOf(a.band) - order.indexOf(b.band) || (a.nat_number ?? 0) - (b.nat_number ?? 0));
  return (
    <section aria-labelledby="frr-nat" className="rounded-lg border border-line bg-surface p-3.5 elev-1">
      <h3 id="frr-nat" className="flex items-center gap-1.5 text-[13px] font-medium text-fg">
        <ArrowRightLeft size={14} className="text-dim" /> NAT findings ({findings.length})
      </h3>
      <ul className="mt-2 space-y-1.5">
        {sorted.map((f) => (
          <li key={`${f.check}-${f.nat_uid}`} className="flex flex-wrap items-center gap-2 text-[12px]">
            <SeverityPill band={f.band} severity={f.severity} />
            <Chip variant="neutral">{LABEL[f.check] ?? f.check}</Chip>
            <span className="min-w-0 break-words text-fg">{f.title}</span>
            <span className="text-[11px] text-faint">· {f.package}</span>
          </li>
        ))}
      </ul>
    </section>
  );
}
