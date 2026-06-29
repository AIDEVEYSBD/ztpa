"use client";

import type { ReactNode } from "react";
import { ShieldAlert, GitBranch } from "lucide-react";
import type { Band } from "@/lib/types";
import { cn } from "@/lib/cn";
import { SEV } from "./severity";

/** Severity is always colour + icon + label. */
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

export function Tag({ children }: { children: ReactNode }) {
  return <span className="chip mono text-[10.5px] uppercase tracking-[0.02em]">{children}</span>;
}
