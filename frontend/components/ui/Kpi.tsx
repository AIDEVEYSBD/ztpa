"use client";

import type { ReactNode } from "react";
import { cn } from "@/lib/cn";
import type { Tone } from "./Button";

const FIGURE: Partial<Record<Tone, string>> = {
  run: "var(--color-run)",
  ok: "var(--color-ok)",
  warn: "var(--color-warn)",
  err: "var(--color-err)",
};

/**
 * One cell of a KPI band. The whole tile is a button: every figure opens its
 * records. Tone is applied to the figure only, and only when the state
 * warrants it (active, pending, denials, exceeded).
 */
export function KpiTile({
  label,
  value,
  sub,
  tone,
  chip,
  active,
  onOpen,
  children,
}: {
  label: ReactNode;
  value: ReactNode;
  sub?: ReactNode;
  tone?: Tone;
  /** Mono window chip beside the label. */
  chip?: ReactNode;
  active?: boolean;
  onOpen?: () => void;
  /** Sparkline or other trailing visual. */
  children?: ReactNode;
}) {
  return (
    <div
      role="button"
      tabIndex={0}
      onClick={onOpen}
      onKeyDown={(e) => {
        if (e.key === "Enter" || e.key === " ") {
          e.preventDefault();
          onOpen?.();
        }
      }}
      className={cn(
        "focusable -mr-px -mb-px flex cursor-pointer flex-col gap-1 border-r border-b border-line px-3 py-2.5 text-left",
        active ? "bg-raise/80" : "hover:bg-raise/50",
      )}
    >
      <span className="flex items-center gap-1.5">
        <span className="truncate text-[10.5px] text-faint">{label}</span>
        {chip ? (
          <span className="rounded-[3px] border border-line bg-canvas px-1 font-mono text-[9px] leading-[14px] text-dim">
            {chip}
          </span>
        ) : null}
      </span>
      <span className="flex items-end justify-between gap-2">
        <span
          className="tnum text-[22px] leading-none font-semibold tracking-[-0.02em]"
          style={tone && FIGURE[tone] ? { color: FIGURE[tone] } : undefined}
        >
          {value}
        </span>
        {children}
      </span>
      {sub ? <span className="truncate text-[10px] text-ghost">{sub}</span> : null}
    </div>
  );
}

/** The bordered band a row of KpiTile sits in. */
export function KpiBand({ children, className }: { children: ReactNode; className?: string }) {
  return (
    <div
      className={cn(
        "grid grid-cols-2 overflow-hidden rounded-md border border-line bg-surface sm:grid-cols-4 xl:grid-cols-8",
        className,
      )}
    >
      {children}
    </div>
  );
}

/** A standalone KPI card, for when a figure deserves its own surface. */
export function Kpi({
  label,
  value,
  unit,
  sub,
  onOpen,
  className,
}: {
  label: ReactNode;
  value: ReactNode;
  unit?: ReactNode;
  sub?: ReactNode;
  onOpen?: () => void;
  className?: string;
}) {
  return (
    <div
      role={onOpen ? "button" : undefined}
      tabIndex={onOpen ? 0 : undefined}
      onClick={onOpen}
      className={cn(
        "flex flex-col gap-3 rounded-lg border border-line bg-surface p-4 elev-1",
        onOpen && "focusable cursor-pointer hover:border-line-strong",
        className,
      )}
    >
      <span className="text-[11px] font-medium text-faint">{label}</span>
      <span className="flex items-end gap-1.5">
        <span className="tnum text-[28px] leading-none font-semibold tracking-[-0.025em]">{value}</span>
        {unit ? <span className="text-[15px] text-dim">{unit}</span> : null}
      </span>
      {sub ? <span className="text-[11.5px] text-faint">{sub}</span> : null}
    </div>
  );
}

/** Key/value row used inside a drill-down. */
export function Fact({ label, children }: { label: ReactNode; children: ReactNode }) {
  return (
    <div className="flex items-baseline justify-between gap-4 border-b border-line py-2 last:border-0">
      <span className="text-[11.5px] text-faint">{label}</span>
      <span className="tnum text-[12.5px] font-medium text-fg">{children}</span>
    </div>
  );
}

export function PageHeader({
  title,
  lede,
  children,
}: {
  title: ReactNode;
  lede?: ReactNode;
  children?: ReactNode;
}) {
  return (
    <div className="flex flex-wrap items-end gap-4">
      <div className="flex flex-col gap-1.5">
        <h1 className="text-[22px] font-semibold tracking-[-0.02em] text-fg">{title}</h1>
        {lede ? <p className="max-w-[64ch] text-[12.5px] leading-[1.55] text-dim">{lede}</p> : null}
      </div>
      <span className="grow" />
      {children}
    </div>
  );
}

/** Standard page frame: every console page uses this width and rhythm. */
export function PageFrame({
  hue,
  className,
  children,
}: {
  hue?: string;
  className?: string;
  children: ReactNode;
}) {
  return (
    <div data-hue={hue} className="min-h-full">
      <div className={cn("mx-auto flex w-full max-w-[1520px] flex-col gap-5 px-5 py-7", className)}>{children}</div>
    </div>
  );
}
