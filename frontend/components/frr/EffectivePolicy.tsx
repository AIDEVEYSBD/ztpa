"use client";

/**
 * The effective policy per (layer, gateway): which installed rules actually take
 * effect, which never match there, which deny, and which are switched off or
 * expired. Shadowing in the register is reported only when a rule is shadowed on
 * EVERY gateway it is installed on; this view shows where that is not the case.
 */

import { useState } from "react";
import { ChevronDown, ChevronRight, Network } from "lucide-react";
import type { EffectivePolicyGateway } from "@/lib/frrTypes";
import { Chip } from "../ui";

const SHOW = 40;

function Rules({ label, xs, variant }: { label: string; xs: (number | null)[]; variant: "ok" | "warn" | "neutral" | "danger" }) {
  const [all, setAll] = useState(false);
  const nums = xs.filter((x): x is number => x != null);
  const shown = all ? nums : nums.slice(0, SHOW);
  return (
    <div className="space-y-1">
      <div className="flex items-center gap-2 text-[11.5px]">
        <Chip variant={variant}>{label}</Chip>
        <span className="tnum text-dim">{nums.length}</span>
      </div>
      {nums.length > 0 && (
        <div className="font-mono text-[11px] leading-[1.6] text-fg break-words">
          {shown.join(", ")}
          {nums.length > SHOW && (
            <button type="button" className="focusable ml-2 text-accent underline-offset-2 hover:underline"
              onClick={() => setAll(!all)}>
              {all ? "show fewer" : `+${nums.length - SHOW} more`}
            </button>
          )}
        </div>
      )}
    </div>
  );
}

export function EffectivePolicy({ gateways }: { gateways: EffectivePolicyGateway[] }) {
  const [open, setOpen] = useState<string | null>(null);
  if (!gateways.length) return null;
  return (
    <section aria-labelledby="frr-effective" className="rounded-lg border border-line bg-surface p-3.5 elev-1">
      <h3 id="frr-effective" className="flex items-center gap-1.5 text-[13px] font-medium text-fg">
        <Network size={14} className="text-dim" /> Effective policy by gateway ({gateways.length})
      </h3>
      <p className="mt-0.5 text-[11.5px] text-dim">
        Rules installed on each gateway, in order. A rule listed as shadowed on one gateway but effective on another is
        not reported as shadowed in the register.
      </p>
      <div className="mt-2 divide-y divide-line">
        {gateways.map((g) => {
          const key = `${g.layer}|${g.gateway}`;
          const isOpen = open === key;
          return (
            <div key={key} className="py-1.5">
              <button type="button" aria-expanded={isOpen} onClick={() => setOpen(isOpen ? null : key)}
                className="focusable flex w-full cursor-pointer items-center gap-2 text-left text-[12px]">
                {isOpen ? <ChevronDown size={13} className="text-faint" /> : <ChevronRight size={13} className="text-faint" />}
                <span className="font-medium text-fg">{g.gateway}</span>
                <span className="text-faint">· {g.layer}</span>
                <span className="ml-auto flex gap-3 text-[11px] text-dim tnum">
                  <span>{g.rules_installed} installed</span>
                  <span>{g.effective_allow.length} effective allow</span>
                  <span>{g.shadowed.length} shadowed</span>
                  <span>{g.inactive.length} inactive</span>
                </span>
              </button>
              {isOpen && (
                <div className="mt-2 grid gap-3 pl-5 md:grid-cols-2">
                  <Rules label="effective allow" xs={g.effective_allow} variant="ok" />
                  <Rules label="deny" xs={g.deny} variant="neutral" />
                  <Rules label="shadowed here" xs={g.shadowed} variant="warn" />
                  <Rules label="inactive (disabled / expired)" xs={g.inactive} variant="neutral" />
                </div>
              )}
            </div>
          );
        })}
      </div>
    </section>
  );
}
