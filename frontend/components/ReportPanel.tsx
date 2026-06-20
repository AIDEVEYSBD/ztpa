"use client";

import { useState } from "react";
import { FileText, RefreshCw, Printer, Route, ShieldCheck, ArrowRight, Sparkles } from "lucide-react";
import { api } from "@/lib/api";
import { SeverityPill, Spinner, Stat, Skeleton, SkeletonText } from "./ui";
import { Prose } from "./Markdown";
import { RuleRef } from "./RuleRef";

const BANDS = ["critical", "high", "medium", "low"] as const;
const BAND_VAR: Record<string, string> = {
  critical: "var(--sev-critical)", high: "var(--sev-high)", medium: "var(--sev-medium)", low: "var(--sev-low)",
};
const TYPE_LABEL: Record<string, string> = {
  over_permissive: "Over-permissive rules", cidr_overlap: "CIDR overlaps",
  shadowed_rule: "Shadowed rules", cross_tool_path: "Cross-tool paths",
};

/** A path rendered as professional chips separated by arrow icons (no glyphs). */
function PathChips({ nodes }: { nodes: string[] }) {
  return (
    <div className="flex flex-wrap items-center gap-1.5">
      {nodes.map((n, i) => (
        <span key={i} className="inline-flex items-center gap-1.5">
          <span className="mono break-all text-[12px]">{n}</span>
          {i < nodes.length - 1 && <ArrowRight size={12} className="shrink-0 text-text3" />}
        </span>
      ))}
    </div>
  );
}

export function ReportPanel() {
  const [r, setR] = useState<any>();
  const [loading, setLoading] = useState(false);
  const [narrLoading, setNarrLoading] = useState(false);
  const [err, setErr] = useState(false);

  const gen = async () => {
    setLoading(true); setErr(false);
    try {
      const facts = await api.report();         // instant, deterministic
      setR(facts);
      // Fetch the richer LLM narrative separately; keep the deterministic one on failure.
      if (facts?.narrative_pending) {
        setNarrLoading(true);
        api.reportNarrative()
          .then((n) => setR((cur: any) => (cur ? { ...cur, narrative_md: n.narrative_md, by: n.by, narrative_pending: false } : cur)))
          .catch(() => { /* keep deterministic narrative */ })
          .finally(() => setNarrLoading(false));
      }
    } catch { setErr(true); } finally { setLoading(false); }
  };

  if (!r) {
    return (
      <div className="panel mx-auto max-w-3xl p-6">
        <div className="mb-3 flex items-center gap-2 text-[13px] font-bold"><FileText size={16} /> Executive &amp; compliance posture report</div>
        <p className="mb-4 max-w-2xl text-[13px] text-text2">
          A board-ready report: severity breakdown, the cross-tool exposures, a prioritised remediation plan, and a
          PCI-DSS / Zero-Trust compliance read. The orchestrator returns the facts instantly; the local model then
          writes the narrative. Every rule reference is clickable.
        </p>
        {err && <div className="mb-3 border border-sev-critical-line bg-sev-critical-bg px-3 py-2 text-[12px] text-sev-critical">The report service did not respond. Make sure the API is running, then try again.</div>}
        <button onClick={gen} disabled={loading} className="btn-primary">
          {loading ? <Spinner label="Assembling report…" /> : <><FileText size={14} /> Generate report</>}
        </button>
      </div>
    );
  }

  const sev = r.severity_breakdown ?? {};
  const total = BANDS.reduce((a, b) => a + (sev[b] ?? 0), 0) || 1;
  const s = r.summary ?? {};
  const byType: Record<string, number> = r.by_type ?? {};

  return (
    <div className="space-y-4">
      <div className="print:hidden">
        <div className="flex flex-wrap items-center gap-2">
          <button onClick={gen} disabled={loading} className="btn-ghost"><RefreshCw size={13} className={loading ? "animate-spin" : ""} /> Regenerate</button>
          <button onClick={() => window.print()} className="btn-primary"><Printer size={14} /> Download / Print</button>
          <span className="ml-auto text-[11px] text-text3">{narrLoading ? "writing narrative locally…" : `via ${r.by}`} · grounded in the deterministic snapshot</span>
        </div>
        <p className="mt-1.5 text-[11px] text-text3">In the print dialog choose &ldquo;Save as PDF&rdquo; and turn off <b className="font-semibold text-text2">Headers and footers</b> to remove the URL/page-number line.</p>
      </div>

      <div id="report" className="panel mx-auto max-w-4xl space-y-7 p-5 sm:p-8">
        {/* Letterhead */}
        <div className="flex items-center gap-3 border-b border-border pb-4">
          <div className="grid h-10 w-10 shrink-0 place-items-center bg-accent-ink"><ShieldCheck size={20} className="text-accent" /></div>
          <div className="min-w-0">
            <div className="text-[17px] font-bold leading-tight sm:text-[19px]">ZeroTrust Posture Report</div>
            <div className="text-[11px] text-text3 sm:text-[12px]">
              Cross-tool network-policy risk · {s.total_findings ?? 0} findings · {r.cross_tool_paths?.length ?? 0} cross-tool paths · {(r.sensitive_assets ?? []).length} regulated assets
            </div>
          </div>
          <div className="ml-auto hidden text-right text-[11px] text-text3 sm:block">
            AlgoSec · Guardicore · Wiz<br />consolidated snapshot
          </div>
        </div>

        {/* Severity stat cards */}
        <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
          {BANDS.map((b) => <Stat key={b} band={b} value={sev[b] ?? 0} label={b[0].toUpperCase() + b.slice(1)} />)}
        </div>

        {/* Severity distribution bar */}
        <div>
          <div className="label mb-1.5">Severity distribution</div>
          <div className="flex h-3.5 w-full overflow-hidden border border-border">
            {BANDS.map((b) => (sev[b] ? <div key={b} style={{ width: `${(sev[b] / total) * 100}%`, background: BAND_VAR[b] }} title={`${b}: ${sev[b]}`} /> : null))}
          </div>
          <div className="mt-2 flex flex-wrap gap-x-4 gap-y-1 text-[11px] text-text3">
            {BANDS.map((b) => (
              <span key={b} className="inline-flex items-center gap-1.5">
                <span className="h-2 w-2 shrink-0" style={{ background: BAND_VAR[b] }} /> {sev[b] ?? 0} {b}
              </span>
            ))}
          </div>
        </div>

        {/* Finding mix by type */}
        <div>
          <div className="label mb-2">Finding mix</div>
          <div className="grid grid-cols-2 gap-2 sm:grid-cols-4">
            {Object.entries(byType).map(([t, n]) => (
              <div key={t} className="sunk px-3 py-2">
                <div className="mono text-[20px] font-bold tabular-nums">{n}</div>
                <div className="text-[11px] text-text2">{TYPE_LABEL[t] ?? t}</div>
              </div>
            ))}
          </div>
        </div>

        {/* LLM narrative (streams in after the facts) */}
        {narrLoading && r.narrative_pending ? (
          <div className="space-y-3">
            <div className="flex items-center gap-1.5 text-[11px] text-text3"><Sparkles size={12} className="text-accent" /> writing executive narrative with the local model…</div>
            <Skeleton className="h-5 w-52" />
            <SkeletonText lines={4} />
            <Skeleton className="h-5 w-44" />
            <SkeletonText lines={3} />
          </div>
        ) : (
          <Prose>{r.narrative_md ?? ""}</Prose>
        )}

        {/* Cross-tool attack paths */}
        {r.cross_tool_paths?.length > 0 && (
          <div>
            <div className="label mb-2 flex items-center gap-1.5"><Route size={13} /> Cross-tool attack paths</div>
            <div className="space-y-2">
              {r.cross_tool_paths.map((p: any, i: number) => (
                <div key={i} className="sunk p-3 text-[12px]">
                  <PathChips nodes={p.display_path || []} />
                  <div className="mt-1.5 text-[11px] text-text3">
                    reaches <b className="text-text2">{p.terminal}</b> ({(p.terminal_tags || []).join(", ")}) · {p.boundary} · spans {(p.tools || []).join(", ")}
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Prioritised remediation */}
        <div>
          <div className="label mb-2">Prioritised remediation plan</div>
          <div className="space-y-2">
            {(r.actions ?? []).map((a: any) => {
              const refs: string[] = Array.from(new Set((a.findings ?? []).flatMap((f: any) => f.refs ?? [])));
              return (
                <div key={a.action_id} className="panel p-3">
                  <div className="flex flex-wrap items-center gap-2">
                    <span className="mono text-[12px] text-text3">{a.priority}.</span>
                    <span className="text-[13px] font-bold">{a.title}</span>
                    <span className="ml-auto"><SeverityPill band={a.band} /></span>
                  </div>
                  <div className="mt-1 text-[12px] text-text2">{a.rationale}</div>
                  {refs.length > 0 && (
                    <div className="mt-1.5 flex flex-wrap items-center gap-x-2 gap-y-1">
                      <span className="text-[10px] uppercase tracking-wide text-text3">rules</span>
                      {refs.map((ref) => <RuleRef key={ref} refId={ref} />)}
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        </div>

        {/* Regulated assets in scope */}
        {(r.sensitive_assets ?? []).length > 0 && (
          <div>
            <div className="label mb-2 flex items-center gap-1.5"><ShieldCheck size={13} /> Regulated assets in scope</div>
            <div className="flex flex-wrap gap-1.5">
              {r.sensitive_assets.map((a: string) => <span key={a} className="chip mono text-[11px]">{a}</span>)}
            </div>
          </div>
        )}

        <div className="border-t border-border pt-3 text-[10px] text-text3">
          Generated via {r.by} · ranked by {r.ranked_by} · all counts and paths computed by the deterministic engine; narrative reasons only from those facts.
        </div>
      </div>
    </div>
  );
}
