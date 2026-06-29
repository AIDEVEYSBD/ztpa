"use client";

import type { ReactNode } from "react";
import { ShieldHalf } from "lucide-react";
import { cn } from "@/lib/cn";

export function Spinner({ label }: { label?: string }) {
  // The ring inherits `currentColor` so it stays visible on any surface —
  // including the yellow primary button (where a yellow ring would vanish).
  return (
    <span className="inline-flex items-center gap-2 text-[13px]">
      <span className="h-3.5 w-3.5 animate-spin rounded-full border-2 border-current border-t-transparent" />
      {label}
    </span>
  );
}

/** Plain uppercase section label (no leading square). */
export function SectionLabel({ children, className = "" }: { children: ReactNode; className?: string }) {
  return <div className={cn("label mb-3", className)}>{children}</div>;
}

/** Signature eyebrow — yellow square + uppercase micro-label. */
export function Eyebrow({ children, accent = false, className }: { children: ReactNode; accent?: boolean; className?: string }) {
  return <span className={cn("eyebrow", accent && "accent", className)}>{children}</span>;
}

/** Thin spectrum keyline (decorative rule). */
export function SpectrumLine({ thin = false, warm = false, className }: { thin?: boolean; warm?: boolean; className?: string }) {
  return <span aria-hidden className={cn("spectrum-line", thin && "thin", warm && "warm", className)} />;
}

/** Squared brand mark — the shield in a flat yellow tile + wordmark. */
export function Brand({ size = "md", showSub = true, className }: { size?: "sm" | "md"; showSub?: boolean; className?: string }) {
  const tile = size === "sm" ? 26 : 30;
  const glyph = Math.round(tile * 0.56);
  return (
    <div className={cn("flex items-center gap-2.5", className)}>
      <span className="grid shrink-0 place-items-center bg-accent" style={{ width: tile, height: tile }}>
        <ShieldHalf size={glyph} className="text-accent-ink" />
      </span>
      <div className="leading-[1.15]">
        <div className={cn("font-bold tracking-[-0.01em]", size === "sm" ? "text-[13px]" : "text-[14px]")}>ZeroTrust</div>
        {showSub && <div className="text-[10px] uppercase tracking-[0.14em] text-text3">Policy Advisor</div>}
      </div>
    </div>
  );
}

export function EmptyState({ icon: Icon, title, sub }: { icon: typeof ShieldHalf; title: string; sub?: string }) {
  return (
    <div className="flex flex-col items-center justify-center gap-2 p-10 text-center text-text3">
      <Icon size={26} />
      <div className="text-[13px] font-bold text-text2">{title}</div>
      {sub && <div className="text-[11.5px]">{sub}</div>}
    </div>
  );
}
