import clsx from "clsx";
import { OctagonAlert, TriangleAlert, CircleAlert, Circle, ShieldAlert, GitBranch } from "lucide-react";
import type { Band } from "@/lib/types";

export const cn = clsx;

const SEV: Record<Band, { Icon: any; cls: string; varName: string }> = {
  critical: { Icon: OctagonAlert, cls: "bg-sev-critical-bg text-sev-critical border-sev-critical-line", varName: "--sev-critical" },
  high: { Icon: TriangleAlert, cls: "bg-sev-high-bg text-sev-high border-sev-high-line", varName: "--sev-high" },
  medium: { Icon: CircleAlert, cls: "bg-sev-medium-bg text-sev-medium border-sev-medium-line", varName: "--sev-medium" },
  low: { Icon: Circle, cls: "bg-sev-low-bg text-sev-low border-sev-low-line", varName: "--sev-low" },
};

/** Severity is always color + icon + label (per the design language). */
export function SeverityPill({ band, severity, forced }: { band: Band; severity?: number; forced?: boolean }) {
  const { Icon, cls } = SEV[band];
  return (
    <span className={cn("inline-flex h-[21px] shrink-0 items-center gap-1.5 border px-2 text-[10.5px] font-bold uppercase tracking-[0.03em]", cls)}>
      <Icon size={12} />
      {band}
      {severity != null && <span className="mono font-normal opacity-70">{severity}</span>}
      {forced && <ShieldAlert size={11} aria-label="guardrail-forced" />}
    </span>
  );
}

const TOOL_DOT: Record<string, string> = {
  algosec: "bg-blue-400", guardicore: "bg-violet-400", wiz: "bg-cyan-400", sd_wan: "bg-emerald-400", sd_lan: "bg-teal-400",
};

/** Provenance chip: source tool (+ optional device/rule). */
export function ToolBadge({ tool, detail }: { tool: string; detail?: string }) {
  return (
    <span className="chip mono text-[10.5px]">
      <GitBranch size={10} className="text-text3" />
      <span className={cn("h-1.5 w-1.5 shrink-0", TOOL_DOT[tool] ?? "bg-text3")} />
      {tool}{detail ? ` · ${detail}` : ""}
    </span>
  );
}

export function Tag({ children }: { children: React.ReactNode }) {
  return <span className="chip mono text-[10.5px] uppercase tracking-[0.02em]">{children}</span>;
}

export function Spinner({ label }: { label?: string }) {
  return (
    <span className="inline-flex items-center gap-2 text-[13px] text-text2">
      <span className="h-3.5 w-3.5 animate-spin rounded-full border-2 border-accent border-t-transparent" />
      {label}
    </span>
  );
}

export function SectionLabel({ children, className = "" }: { children: React.ReactNode; className?: string }) {
  return <div className={cn("label mb-3", className)}>{children}</div>;
}

/** Severity stat card with a top accent rule + big tabular number. */
export function Stat({ band, value, label, sub }: { band: Band; value: number | string; label: string; sub?: string }) {
  const { Icon } = SEV[band];
  return (
    <div className="panel px-4 py-3.5" style={{ borderTop: `2px solid var(${SEV[band].varName})` }}>
      <div className="flex items-center gap-1.5">
        <Icon size={15} style={{ color: `var(${SEV[band].varName})` }} />
        <span className="text-[12px] font-bold text-text2">{label}</span>
      </div>
      <div className="mono mt-2 text-[30px] font-bold leading-none tracking-[-0.02em] tabular-nums">{value}</div>
      {sub && <div className="mt-1 text-[11.5px] text-text3">{sub}</div>}
    </div>
  );
}

/* --- Skeleton loaders -------------------------------------------------------
   Shown wherever data is being fetched, so the layout never flashes empty. */

export function Skeleton({ className = "" }: { className?: string }) {
  return <span className={cn("skeleton block", className)} />;
}

export function SkeletonText({ lines = 3, className = "" }: { lines?: number; className?: string }) {
  return (
    <div className={cn("space-y-2", className)}>
      {Array.from({ length: lines }).map((_, i) => (
        <Skeleton key={i} className={cn("h-3", i === lines - 1 ? "w-2/3" : "w-full")} />
      ))}
    </div>
  );
}

/** List of card rows that mirror the Risk To-Do / table item shape. */
export function SkeletonRows({ rows = 5 }: { rows?: number }) {
  return (
    <div className="space-y-3">
      {Array.from({ length: rows }).map((_, i) => (
        <div key={i} className="panel flex items-center gap-3 p-4">
          <Skeleton className="h-7 w-9 shrink-0" />
          <div className="min-w-0 flex-1 space-y-2">
            <Skeleton className="h-3.5 w-1/3" />
            <Skeleton className="h-3 w-3/4" />
          </div>
          <Skeleton className="hidden h-5 w-20 shrink-0 sm:block" />
        </div>
      ))}
    </div>
  );
}

/** A panel placeholder with a header line and body text (for prose/graph slots). */
export function SkeletonPanel({ className = "", lines = 4 }: { className?: string; lines?: number }) {
  return (
    <div className={cn("panel space-y-3 p-4", className)}>
      <Skeleton className="h-4 w-40" />
      <SkeletonText lines={lines} />
    </div>
  );
}

export function EmptyState({ icon: Icon, title, sub }: { icon: any; title: string; sub?: string }) {
  return (
    <div className="flex flex-col items-center justify-center gap-2 p-10 text-center text-text3">
      <Icon size={26} />
      <div className="text-[13px] font-bold text-text2">{title}</div>
      {sub && <div className="text-[11.5px]">{sub}</div>}
    </div>
  );
}
