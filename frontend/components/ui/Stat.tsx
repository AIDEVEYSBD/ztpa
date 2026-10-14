"use client";

import type { ReactNode } from "react";
import type { Band } from "@/lib/types";
import { cn } from "@/lib/cn";
import { SEV } from "./severity";

/** Severity stat card: a hairline card with a tone rule on the left edge. */
export function Stat({ band, value, label, sub }: { band: Band; value: number | string; label: string; sub?: string }) {
  const { Icon, varName } = SEV[band];
  return (
    <div className="relative flex flex-col overflow-hidden rounded-lg border border-line bg-surface p-4 elev-1">
      <span aria-hidden className="absolute inset-y-0 left-0 w-[3px]" style={{ background: `var(${varName})` }} />
      <div className="flex items-center gap-1.5">
        <Icon size={13} style={{ color: `var(${varName})` }} />
        <span className="text-[11px] font-medium text-faint">{label}</span>
      </div>
      <div className="tnum mt-2 text-[30px] leading-none font-semibold tracking-[-0.025em]">{value}</div>
      {sub && <div className="mt-1 text-[11.5px] text-faint">{sub}</div>}
    </div>
  );
}

export type StatTone = "neutral" | "accent" | "ok" | "warn" | "danger" | "info";

const TONE_VALUE: Record<StatTone, string> = {
  neutral: "text-fg", accent: "text-fg", ok: "text-ok", warn: "text-warn", danger: "text-err", info: "text-queue",
};
const TONE_BAR: Record<StatTone, string> = {
  neutral: "bg-line-strong", accent: "bg-line-strong", ok: "bg-ok", warn: "bg-warn", danger: "bg-err", info: "bg-queue",
};

export interface StatPillProps {
  label: string;
  value: ReactNode;
  suffix?: string;
  tone?: StatTone;
  icon?: ReactNode;
  className?: string;
}

/** Compact KPI cell — a labelled value with a tone keyline down the left edge. */
export function StatPill({ label, value, suffix, tone = "neutral", icon, className }: StatPillProps) {
  return (
    <div className={cn("relative flex flex-col gap-0.5 overflow-hidden rounded-md border border-line bg-surface px-3 py-2", className)}>
      <span aria-hidden className={cn("absolute top-2 bottom-2 left-0 w-0.5 rounded-[2px]", TONE_BAR[tone])} />
      <span className="flex items-center gap-1 pl-1.5 text-[10.5px] text-faint">
        {icon}
        {label}
      </span>
      <span className="flex items-baseline gap-1 pl-1.5">
        <span className={cn("tnum text-[19px] leading-none font-semibold tracking-[-0.02em]", TONE_VALUE[tone])}>{value}</span>
        {suffix ? <span className="text-[10px] text-ghost">{suffix}</span> : null}
      </span>
    </div>
  );
}
