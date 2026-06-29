"use client";

import type { ReactNode } from "react";
import { cn } from "@/lib/cn";

/**
 * Palette-aware pill. Meaning is carried by state colour; the single brand
 * accent is yellow. Each variant uses dedicated `-bg` / `-line` tokens (var-based
 * colours don't take Tailwind opacity modifiers on v3), so it re-skins per theme.
 */
export type ChipVariant = "neutral" | "accent" | "info" | "ok" | "warn" | "danger";

const VARIANT_CLASS: Record<ChipVariant, string> = {
  neutral: "border-border bg-sunk text-text2",
  accent: "border-accent bg-accent-soft text-accent-fg",
  info: "border-info-line bg-info-bg text-info",
  ok: "border-ok-line bg-ok-bg text-ok",
  warn: "border-sev-high-line bg-sev-high-bg text-sev-high",
  danger: "border-sev-critical-line bg-sev-critical-bg text-sev-critical",
};

export interface ChipProps {
  children: ReactNode;
  variant?: ChipVariant;
  /** Leading dot in the current colour. */
  dot?: boolean;
  /** Pulse (for active / processing states). */
  pulse?: boolean;
  /** Mono font (codes / hashes). */
  mono?: boolean;
  className?: string;
}

export function Chip({ children, variant = "neutral", dot = false, pulse = false, mono = false, className }: ChipProps) {
  return (
    <span
      className={cn(
        "inline-flex items-center gap-1.5 whitespace-nowrap border px-2 py-0.5 text-[11px] font-bold leading-[1.45]",
        mono && "mono tabular-nums",
        pulse && "animate-pulse",
        VARIANT_CLASS[variant],
        className,
      )}
    >
      {dot ? <span className="h-1.5 w-1.5 shrink-0 bg-current" /> : null}
      {children}
    </span>
  );
}

export default Chip;
