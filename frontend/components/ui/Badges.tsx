"use client";

import type { ReactNode } from "react";
import { ShieldAlert, GitBranch } from "lucide-react";
import type { Band } from "@/lib/types";
import { cn } from "@/lib/cn";
import { toolColour , toolLabel } from "@/lib/toolColour";
import { SEV } from "./severity";

/** Severity is always colour + icon + label. */
export function SeverityPill({ band, severity, forced }: { band: Band; severity?: number; forced?: boolean }) {
  const { Icon, cls } = SEV[band];
  return (
    <span className={cn("inline-flex shrink-0 items-center gap-1.5 rounded-sm border px-1.5 py-0.5 text-[11px] font-medium", cls)}>
      <Icon size={11} />
      {band}
      {severity != null && <span className="tnum font-mono text-[10.5px] opacity-70">{severity}</span>}
      {forced && <ShieldAlert size={11} aria-label="guardrail-forced" />}
    </span>
  );
}

/** Provenance chip: source tool (+ optional device/rule).
 *
 *  The dot used to carry its own `TOOL_DOT` map of Tailwind classes covering
 *  five of the twelve registered tools, so a badge could disagree with the edge
 *  the same tool drew on the map, and the other seven all shared the unknown
 *  grey — badging a tool the product ingests as one it cannot attribute. */
export function ToolBadge({ tool, detail }: { tool: string; detail?: string }) {
  return (
    <span className="inline-flex items-center gap-1.5 rounded-sm border border-line bg-raise px-1.5 py-0.5 font-mono text-[10.5px] text-dim">
      <GitBranch size={10} className="text-faint" />
      <span className="size-1.5 shrink-0 rounded-[2px]" style={{ background: toolColour(tool) }} />
      {toolLabel(tool)}{detail ? ` · ${detail}` : ""}
    </span>
  );
}

export function Tag({ children }: { children: ReactNode }) {
  return (
    <span className="inline-flex items-center rounded-sm border border-line bg-raise px-1.5 py-0.5 font-mono text-[10.5px] text-dim">
      {children}
    </span>
  );
}
