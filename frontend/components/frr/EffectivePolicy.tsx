"use client";

/**
 * The effective policy per (layer, gateway): which installed rules actually take
 * effect, which never match there, which deny, and which are switched off or
 * expired. Pages carry the counts; a gateway's rule lists load when it is opened
 * (they are large on big rulebases). Shadowing in the register is reported only
 * when a rule is shadowed on EVERY gateway it is installed on; this view shows
 * where that is not the case.
 */

import { useEffect, useState } from "react";
import { ChevronDown, ChevronRight, Network } from "lucide-react";
import { asApiError, type ApiError } from "@/lib/api";
import { frr } from "@/lib/frr";
import type { EffectivePolicyGateway, EffectivePolicySummary } from "@/lib/frrTypes";
import { Chip, Skeleton } from "../ui";
import { InlineError } from "../ui/Feedback";

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

function GatewayDetail({ exportId, g }: { exportId: string; g: EffectivePolicySummary }) {
  const [data, setData] = useState<EffectivePolicyGateway>();
  const [err, setErr] = useState<ApiError>();
  const [attempt, setAttempt] = useState(0);
  useEffect(() => {
    let live = true;
    setErr(undefined);
    frr.effectivePolicy(exportId, g.layer, g.gateway)
      .then((d) => { if (live) setData(d); })
      .catch((e) => { if (live) setErr(asApiError(e)); });
    return () => { live = false; };
  }, [exportId, g.layer, g.gateway, attempt]);
  if (err) return <InlineError resource={`the effective policy of ${g.gateway}`} error={err} onRetry={() => setAttempt((n) => n + 1)} />;
  if (!data) return <Skeleton className="h-16 w-full" />;
  return (
    <div className="mt-2 grid gap-3 pl-5 md:grid-cols-2">
      <Rules label="effective allow" xs={data.effective_allow} variant="ok" />
      <Rules label="deny" xs={data.deny} variant="neutral" />
      <Rules label="shadowed here" xs={data.shadowed} variant="warn" />
      <Rules label="inactive (disabled / expired)" xs={data.inactive} variant="neutral" />
      {data.partly_covered && data.partly_covered.length > 0 && (
        <Rules label="partly covered above (some grants never match)" xs={data.partly_covered} variant="warn" />
      )}
    </div>
  );
}

export function EffectivePolicy({ exportId, gateways }: { exportId: string; gateways: EffectivePolicySummary[] }) {
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
                  <span>{g.effective_allow_count} effective allow</span>
                  <span>{g.shadowed_count} shadowed</span>
                  <span>{g.inactive_count} inactive</span>
                  {g.partly_covered_count ? <span>{g.partly_covered_count} partly covered</span> : null}
                </span>
              </button>
              {isOpen && <GatewayDetail exportId={exportId} g={g} />}
            </div>
          );
        })}
      </div>
    </section>
  );
}
