"use client";

/**
 * THE GATE'S RULING, AS ONE SET OF COMPONENTS.
 *
 * The Change Gate stopped being a place you navigate to and became a step you
 * complete inside a finding's side panel. That only works if both surfaces
 * render THE SAME ruling — two hand-built designs of one decision drift, and
 * then the screen a reviewer approves on and the screen an auditor reads are
 * not describing the same thing. Everything about a ruling that can be drawn
 * lives here; `ChangeGate.tsx` and the Risk To-Do side panel both import it.
 */

import { Check, CornerDownRight, Search, ShieldAlert, ShieldCheck, X } from "lucide-react";
import type { InvestigationStep } from "@/lib/types";
import { cn } from "@/lib/cn";
import { Prose } from "@/components/Markdown";
import { RuleToken } from "./RuleToken";

export const CRITERIA_LABELS: Record<string, string> = {
  standard_template: "Matches a standard-change template",
  no_new_sensitive_reachability: "Opens no new path to a sensitive asset",
  no_new_boundary_crossing: "Crosses no new trust boundary",
  no_over_permissive_pattern: "Introduces no over-permissive pattern",
};

/** A remediation is ruled on by two criteria, not the four an "add allow"
 *  request is judged by. Labelling a remediation with the add-allow list showed
 *  two permanently-failing criteria that were never evaluated. */
export const REMEDIATION_CRITERIA_LABELS: Record<string, string> = {
  resolves: "Re-analysis shows the finding resolved",
  no_new_criticals: "Introduces no new critical finding",
};

export function CriteriaList({ criteria, labels }: { criteria?: Record<string, any>; labels: Record<string, string> }) {
  const keys = Object.keys(labels).filter((k) => criteria && k in criteria);
  // Only criteria the ruling actually carries are listed. A label with no
  // matching key is a criterion nobody evaluated, and drawing it with a red
  // cross invents a failure.
  if (!keys.length) {
    return <div className="text-[11px] text-text3">This ruling carries no criteria block.</div>;
  }
  return (
    <ul className="space-y-1">
      {keys.map((k) => {
        const pass = !!criteria![k];
        return (
          <li key={k} className="flex items-center gap-2 text-[12px]">
            {pass ? <Check size={14} className="shrink-0 text-ok" /> : <X size={14} className="shrink-0 text-sev-critical" />}
            <span className={cn(!pass && "text-text2")}>{labels[k]}</span>
          </li>
        );
      })}
    </ul>
  );
}

export function DeltaRow({ label, items }: { label: string; items: string[] }) {
  return (
    <div className="flex flex-col gap-1 border-b border-hair py-1.5 text-[12px] last:border-0 sm:flex-row sm:gap-2">
      <span className="shrink-0 text-text3 sm:w-52">{label}</span>
      <span className="min-w-0 flex-1">
        {items.length
          ? items.map((it, i) => <span key={i} className="mono mb-1 mr-1 inline-block break-all border border-border bg-sunk px-1.5 py-0.5 text-[10.5px]">{it}</span>)
          : <span className="text-ok">none</span>}
      </span>
    </div>
  );
}

export function DeltaPathRow({ label, paths }: { label: string; paths: string[][] }) {
  return (
    <div className="flex flex-col gap-1 border-b border-hair py-1.5 text-[12px] last:border-0 sm:flex-row sm:gap-2">
      <span className="shrink-0 text-text3 sm:w-52">{label}</span>
      <span className="min-w-0 flex-1 space-y-1">
        {paths.length
          ? paths.map((nodes, i) => (
              <span key={i} className="flex flex-wrap items-center gap-1.5">
                {nodes.map((n, j) => (
                  <span key={j} className="inline-flex items-center gap-1.5">
                    <span className="mono break-all border border-border bg-sunk px-1.5 py-0.5 text-[10.5px]">{n}</span>
                    {j < nodes.length - 1 && <span aria-hidden className="text-text3">→</span>}
                  </span>
                ))}
              </span>
            ))
          : <span className="text-ok">none</span>}
      </span>
    </div>
  );
}

const asPath = (s: any): string[] =>
  typeof s === "string" ? s.split(" -> ") : Array.isArray(s) ? s.map(String) : [String(s)];

/** The reachability delta an "add allow" request was judged on. */
export function ComputedDelta({ delta }: { delta?: Record<string, any> }) {
  const d = delta ?? {};
  return (
    <div>
      <DeltaPathRow label="New internet → sensitive paths" paths={(d.new_paths ?? []).map((p: any) => p?.display_path ?? asPath(p))} />
      <DeltaRow label="Newly exposed assets" items={d.new_exposed_assets ?? []} />
      <DeltaRow label="Boundaries crossed" items={d.boundaries_crossed ?? []} />
      <DeltaRow label="Over-permissive patterns" items={d.new_over_permissive ?? []} />
    </div>
  );
}

/** The re-simulation a REMEDIATION was judged on. */
export function RemediationValidation({ dd }: { dd?: Record<string, any> }) {
  const d = dd ?? {};
  return (
    <div>
      <DeltaRow label="Resolves the finding" items={d.resolves === true ? ["yes"] : d.resolves === false ? ["no"] : []} />
      <DeltaRow label="Introduces new criticals" items={d.introduces_new_criticals ?? []} />
      {d.engine_corrected_ai && (
        <div className="mt-1.5 text-[11px] text-sev-high">The engine corrected the AI&apos;s proposal before proving this one.</div>
      )}
    </div>
  );
}

/** One-line summary of a deterministic tool result, so the evidence trail reads
 *  as facts rather than raw JSON. */
function summarizeResult(tool?: string, r?: any): string {
  if (!r || typeof r !== "object") return "";
  switch (tool) {
    case "effective_policy": return `${r.internet_exposed ? "internet-exposed" : "not internet-exposed"} · ${(r.sources ?? []).length} source(s)`;
    case "find_paths": return `${r.count ?? (r.paths ?? []).length} path(s)`;
    case "reachable": return r.reachable ? `reachable${(r.paths ?? []).length ? ` via ${r.paths.length} path(s)` : ""}` : "not reachable";
    case "resolve": return r.found ? `${r.asset_key}${(r.tags ?? []).length ? ` [${r.tags.join(", ")}]` : ""}` : "not a known asset";
    case "risk_findings": return `${r.count ?? (r.findings ?? []).length} finding(s)`;
    default: return JSON.stringify(r).slice(0, 120);
  }
}

/** The tools the triage investigator called before the gate ruled, each with the
 *  engine's factual answer — the reasoning, not just the verdict. */
export function InvestigationTrail({ steps, className }: { steps?: InvestigationStep[]; className?: string }) {
  if (!steps?.length) return null;
  return (
    <div className={className}>
      <div className="mb-2 flex items-center gap-1.5 text-[9.5px] font-bold uppercase tracking-[0.14em] text-text3">
        <Search size={11} /> Agent investigation
        <span className="font-normal normal-case tracking-normal">— evidence gathered before ruling</span>
      </div>
      <ol className="space-y-2 border-l border-border pl-3">
        {steps.map((s, i) => (
          <li key={i} className="text-[11.5px]">
            {s.done ? (
              <div className="flex items-start gap-1.5 text-ok"><Check size={12} className="mt-0.5 shrink-0" /><span className="text-text2">{s.thought || "Concluded the investigation."}</span></div>
            ) : s.error ? (
              <div className="flex flex-wrap items-center gap-1.5">
                <span className="inline-flex h-[18px] items-center border border-sev-high-line bg-sev-high-bg px-1 text-[9.5px] font-bold text-sev-high">{s.error}</span>
                <span className="mono text-text3">{s.tool ?? "?"}</span>
                {s.thought && <span className="w-full text-[10.5px] italic text-text3">{s.thought}</span>}
              </div>
            ) : (
              <div>
                <div className="flex flex-wrap items-center gap-1.5">
                  <span className="mono inline-flex h-[18px] items-center border border-accent bg-accent-soft px-1 text-[9.5px] font-bold text-accent-fg">{s.tool}</span>
                  {s.args && Object.keys(s.args).length > 0 && (
                    <span className="mono text-[10.5px] text-text3">({Object.entries(s.args).map(([k, v]) => `${k}=${v}`).join(", ")})</span>
                  )}
                </div>
                {s.thought && <div className="mt-0.5 text-[10.5px] italic text-text3">{s.thought}</div>}
                <div className="mt-0.5 flex items-start gap-1">
                  <CornerDownRight size={11} className="mt-0.5 shrink-0 text-text3" />
                  <span className="mono text-[10.5px] text-text2">{summarizeResult(s.tool, s.result)}</span>
                </div>
              </div>
            )}
          </li>
        ))}
      </ol>
    </div>
  );
}

export type Verdict = "auto_approve" | "escalate" | string;

/** The verdict itself. Icon + word + colour, never colour alone. */
export function VerdictHeader({ decision, forced, confidence, decidedBy, compact }: {
  decision: Verdict;
  forced?: boolean;
  confidence?: number;
  decidedBy?: string;
  compact?: boolean;
}) {
  const ok = decision === "auto_approve";
  const Icon = ok ? ShieldCheck : ShieldAlert;
  return (
    <div className={cn("flex items-center gap-2.5 border p-2.5", ok ? "border-ok-line bg-ok-bg" : "border-sev-critical-line bg-sev-critical-bg")}>
      <Icon size={compact ? 18 : 24} className={cn("shrink-0", ok ? "text-ok" : "text-sev-critical")} />
      <div className="min-w-0">
        <div className={cn("font-bold uppercase tracking-[0.06em]", compact ? "text-[13px]" : "text-[16px]", ok ? "text-ok" : "text-sev-critical")}>
          {ok ? "auto-approve" : "escalate"}
        </div>
        <div className="text-[10.5px] text-text2">
          {decidedBy ? <>decided by <span className="mono">{decidedBy}</span></> : "decided by the gate"}
          {confidence != null && Number.isFinite(Number(confidence)) && <> · confidence {(Number(confidence) * 100).toFixed(0)}%</>}
          {forced && <> · guardrail-forced</>}
        </div>
      </div>
    </div>
  );
}

/**
 * The whole explanation behind one ruling. `kind === "remediation"` switches
 * both the criteria vocabulary and the evidence block, because the two request
 * shapes are judged on different things.
 */
export function GateRuling({ kind, criteria, deltaSummary, triggeringReason, rationale, justification, className }: {
  kind?: string;
  criteria?: Record<string, any>;
  deltaSummary?: Record<string, any>;
  triggeringReason?: string | null;
  rationale?: string;
  justification?: string | null;
  className?: string;
}) {
  const isRemediation = kind === "remediation";
  return (
    <div className={cn("space-y-3", className)}>
      {triggeringReason && (
        <div className="border border-sev-high-line bg-sev-high-bg p-2.5 text-[11.5px]">
          <b>Trigger.</b> {triggeringReason}
        </div>
      )}
      <div>
        <div className="mb-1.5 text-[9.5px] font-bold uppercase tracking-[0.14em] text-text3">
          {isRemediation ? "Approval criteria" : "Auto-approve criteria"}
        </div>
        <CriteriaList criteria={criteria} labels={isRemediation ? REMEDIATION_CRITERIA_LABELS : CRITERIA_LABELS} />
      </div>
      <div>
        <div className="mb-1.5 text-[9.5px] font-bold uppercase tracking-[0.14em] text-text3">
          {isRemediation ? "Re-analysis" : "Computed delta"}
        </div>
        {isRemediation ? <RemediationValidation dd={deltaSummary} /> : <ComputedDelta delta={deltaSummary} />}
      </div>
      <InvestigationTrail steps={deltaSummary?.investigation as InvestigationStep[] | undefined} />
      {rationale && (
        <div>
          <div className="mb-1 text-[9.5px] font-bold uppercase tracking-[0.14em] text-text3">Rationale</div>
          <Prose>{rationale}</Prose>
        </div>
      )}
      {justification && (
        <div>
          <div className="text-[9.5px] font-bold uppercase tracking-[0.14em] text-text3">
            Justification <span className="font-normal normal-case tracking-normal">— untrusted, not used as evidence</span>
          </div>
          <div className="mt-1 text-[11.5px] italic text-text2">“{justification}”</div>
        </div>
      )}
    </div>
  );
}

/** The change a request proposes, one line. A remediation names a rule, so the
 *  rule number is an expandable token rather than a bare string. */
export function ProposedLine({ proposed, kind, snapshot, className }: {
  proposed?: Record<string, any>;
  kind?: string;
  snapshot?: string;
  className?: string;
}) {
  const p = proposed ?? {};
  if (kind === "remediation" || p.target_ref) {
    return (
      <span className={cn("mono inline-flex flex-wrap items-center gap-1.5 text-[11.5px] text-text2", className)}>
        <span className="font-bold text-text">{p.op ?? "change"}</span>
        {p.target_ref && <RuleToken refId={String(p.target_ref)} snapshot={snapshot} tone="loud" />}
        {p.new_source && <><span aria-hidden className="text-text3">→</span><span className="break-all">{String(p.new_source)}</span></>}
        {p.new_service && <><span aria-hidden className="text-text3">→</span><span className="break-all">{String(p.new_service)}</span></>}
      </span>
    );
  }
  return (
    <span className={cn("mono inline-flex flex-wrap items-center gap-1.5 text-[11.5px] text-text2", className)}>
      <span className="break-all">{p.source}</span>
      <span aria-hidden className="text-text3">→</span>
      <span className="break-all">{p.destination}</span>
      <span className="text-text3">· {p.service}</span>
    </span>
  );
}
