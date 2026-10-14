"use client";

import type { ReactNode } from "react";
import { cn } from "@/lib/cn";
import type { Tone } from "./Button";

const FG: Record<Tone, string> = {
  ink: "text-fg",
  run: "text-run",
  ok: "text-ok",
  warn: "text-warn",
  err: "text-err",
  queue: "text-queue",
  neutral: "text-faint",
};

const BG: Record<Tone, string> = {
  ink: "bg-ink",
  run: "bg-run",
  ok: "bg-ok",
  warn: "bg-warn",
  err: "bg-err",
  queue: "bg-queue",
  neutral: "bg-line-strong",
};

const SOLID: Record<Tone, string> = {
  ink: "bg-ink text-on-ink",
  run: "bg-run text-on-solid",
  ok: "bg-ok text-on-solid",
  warn: "bg-warn text-on-solid",
  err: "bg-err text-on-solid",
  queue: "bg-queue text-on-solid",
  neutral: "bg-raise text-fg",
};

/** A square dot, never round: status dots read as an instrument, not a bullet. */
export function Dot({ tone = "neutral", className }: { tone?: Tone; className?: string }) {
  return <span aria-hidden className={cn("size-1.5 shrink-0 rounded-[2px]", BG[tone], className)} />;
}

export function Status({
  tone = "neutral",
  chip,
  children,
  className,
}: {
  tone?: Tone;
  chip?: boolean;
  children: ReactNode;
  className?: string;
}) {
  return (
    <span
      className={cn(
        "inline-flex items-center gap-1.5 text-[11px] font-medium whitespace-nowrap",
        FG[tone],
        chip && "rounded-sm border border-line bg-raise px-1.5 py-0.5",
        className,
      )}
    >
      <Dot tone={tone} />
      {children}
    </span>
  );
}

export function StatusTag({
  tone = "neutral",
  solid,
  children,
  className,
}: {
  tone?: Tone;
  solid?: boolean;
  children: ReactNode;
  className?: string;
}) {
  return (
    <span
      className={cn(
        "inline-flex items-center rounded-sm px-1.5 py-0.5 text-[11px] font-medium",
        solid ? SOLID[tone] : cn("border border-line bg-raise", FG[tone]),
        className,
      )}
    >
      {children}
    </span>
  );
}

/** Small caps label above a headline. The only other place accent colour appears. */
export function Kicker({ children, className }: { children: ReactNode; className?: string }) {
  return (
    <span className={cn("text-[11px] font-medium tracking-[0.08em] text-accent-text uppercase", className)}>
      {children}
    </span>
  );
}

export function Mono({ children, className }: { children: ReactNode; className?: string }) {
  return <span className={cn("tnum font-mono text-[12px] text-dim", className)}>{children}</span>;
}

/** Monospaced identifier chip for ids in a dense list. */
export function Identifier({ children, className }: { children: ReactNode; className?: string }) {
  return (
    <span className={cn("rounded-sm border border-line bg-raise px-1 py-px font-mono text-[9px] text-dim", className)}>
      {children}
    </span>
  );
}

export function Meter({ value, tone = "run", className }: { value: number; tone?: Tone; className?: string }) {
  const pct = Math.max(0, Math.min(100, value));
  return (
    <div
      role="meter"
      aria-valuenow={pct}
      aria-valuemin={0}
      aria-valuemax={100}
      className={cn("h-1 overflow-hidden rounded-[2px] bg-sunken", className)}
    >
      <div className={cn("h-full rounded-[2px] transition-[width] duration-[260ms]", BG[tone])} style={{ width: `${pct}%` }} />
    </div>
  );
}
