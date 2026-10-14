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
  neutral: "border-line bg-raise text-dim",
  accent: "border-line bg-raise text-accent-text",
  info: "border-queue-line bg-queue-bg text-queue",
  ok: "border-ok-line bg-ok-bg text-ok",
  warn: "border-warn-line bg-warn-bg text-warn",
  danger: "border-err-line bg-err-bg text-err",
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
        "inline-flex items-center gap-1.5 rounded-sm border px-1.5 py-0.5 text-[11px] font-medium whitespace-nowrap",
        mono && "tnum font-mono",
        pulse && "af-pulse",
        VARIANT_CLASS[variant],
        className,
      )}
    >
      {dot ? <span className="size-1.5 shrink-0 rounded-[2px] bg-current" /> : null}
      {children}
    </span>
  );
}

export default Chip;
