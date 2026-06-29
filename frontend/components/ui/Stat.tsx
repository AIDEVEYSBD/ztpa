"use client";

import type { ReactNode } from "react";
import type { Band } from "@/lib/types";
import { cn } from "@/lib/cn";
import { SEV } from "./severity";

/** Severity stat card with a top accent rule + big tabular number. */
export function Stat({ band, value, label, sub }: { band: Band; value: number | string; label: string; sub?: string }) {
  const { Icon, varName } = SEV[band];
  return (
    <div className="panel px-4 py-3.5" style={{ borderTop: `2px solid var(${varName})` }}>
      <div className="flex items-center gap-1.5">
        <Icon size={15} style={{ color: `var(${varName})` }} />
        <span className="text-[12px] font-bold text-text2">{label}</span>
      </div>
      <div className="mono mt-2 text-[30px] font-bold leading-none tracking-[-0.02em] tabular-nums">{value}</div>
      {sub && <div className="mt-1 text-[11.5px] text-text3">{sub}</div>}
    </div>
  );
}

export type StatTone = "neutral" | "accent" | "ok" | "warn" | "danger" | "info";

const TONE_VALUE: Record<StatTone, string> = {
  neutral: "text-text", accent: "text-accent-fg", ok: "text-ok", warn: "text-sev-high", danger: "text-sev-critical", info: "text-info",
};
const TONE_BAR: Record<StatTone, string> = {
  neutral: "bg-borderStrong", accent: "bg-accent", ok: "bg-ok", warn: "bg-sev-high", danger: "bg-sev-critical", info: "bg-info",
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
    <div className={cn("relative flex flex-col gap-0.5 overflow-hidden border border-border bg-surface2 px-3 py-1.5", className)}>
      <span aria-hidden className={cn("absolute bottom-1.5 left-0 top-1.5 w-0.5", TONE_BAR[tone])} />
      <span className="flex items-center gap-1 pl-1.5 text-[9px] font-bold uppercase tracking-[0.16em] text-text3">
        {icon}
        {label}
      </span>
      <span className="flex items-baseline gap-1 pl-1.5">
        <span className={cn("text-[17px] font-bold leading-none tabular-nums", TONE_VALUE[tone])}>{value}</span>
        {suffix ? <span className="text-[10px] font-medium text-text3">{suffix}</span> : null}
      </span>
    </div>
  );
}
