"use client";

import { useEffect, useState } from "react";
import { AnimatePresence, motion } from "framer-motion";
import { Rocket, Wand2, Check, AlertTriangle, ArrowRight, ChevronRight, Sparkles, ShieldCheck, GitBranch, Send } from "lucide-react";
import { api } from "@/lib/api";
import type { CampaignPlan, CampaignStep, CampaignSubmitResult } from "@/lib/types";
import type { ScreenId } from "./Sidebar";
import { cn, Spinner } from "./ui";

/** The Remediation Campaign agent: one click plans a worst-first campaign across the
 *  whole snapshot, drafting + re-simulating a fix for each finding and driving the
 *  critical count down. Advisory only — each accepted fix still goes through the
 *  Change Gate individually. This is the higher-order agent that composes the
 *  per-finding remediation loop. */
export function CampaignPanel({ readOnly = false, onNavigate }: { readOnly?: boolean; onNavigate?: (s: ScreenId) => void }) {
  const [plan, setPlan] = useState<CampaignPlan>();
  const [loading, setLoading] = useState(false);
  const [initial, setInitial] = useState(true);
  const [err, setErr] = useState<string>();
  const [open, setOpen] = useState<number | null>(null);
  const [sending, setSending] = useState(false);
  const [sent, setSent] = useState<CampaignSubmitResult>();

  // Load the persisted plan on mount so navigating away and back re-uses the proven
  // plan — only the explicit Plan/Re-plan button spends a (model-backed) planning pass.
  useEffect(() => {
    if (readOnly) { setInitial(false); return; }
    let live = true;
    api.campaignGet().then((r) => { if (live && r.plan) setPlan(r.plan); }).catch(() => {}).finally(() => { if (live) setInitial(false); });
    return () => { live = false; };
  }, [readOnly]);

  const run = async () => {
    setLoading(true); setErr(undefined); setPlan(undefined); setSent(undefined); setOpen(null);
    try { setPlan(await api.campaignPlan()); }
    catch { setErr("Could not run the campaign (the model may be loading). Try again."); }
    finally { setLoading(false); }
  };

  const send = async () => {
    setSending(true); setErr(undefined);
    try { setSent(await api.campaignSubmit()); }
    catch { setErr("Could not send the fixes to the Change Gate. Try again."); }
    finally { setSending(false); }
  };

  const sendable = plan ? plan.steps.filter((s) => s.status === "applied" && s.finding_id).length : 0;

  return (
    <div className="panel overflow-hidden">
      <div className="flex flex-wrap items-center gap-3 p-4">
        <span className="grid h-9 w-9 shrink-0 place-items-center rounded-lg border border-accent bg-accent-soft text-accent-fg">
          <Wand2 size={18} />
        </span>
        <div className="min-w-0 flex-1">
          <div className="text-sm font-bold">Remediation campaign</div>
          <div className="text-xs text-muted">
            The agent plans a worst-first fix sequence and re-simulates after every step, proving it drives the
            critical count down. Nothing is applied — send the proven fixes to the Change Gate to act on them.
          </div>
        </div>
        {!readOnly && (
          <button onClick={run} disabled={loading || initial} className="btn-primary shrink-0 !py-2 text-xs">
            {loading ? <Spinner label="Planning + re-simulating each fix…" />
              : initial ? <Spinner label="Loading…" />
              : <><Sparkles size={14} /> {plan ? "Re-plan" : "Plan the campaign"}</>}
          </button>
        )}
      </div>

      {err && <div className="border-t px-4 py-2 text-[12px] text-sev-high">{err}</div>}

      <AnimatePresence initial={false}>
        {plan && (
          <motion.div initial={{ height: 0, opacity: 0 }} animate={{ height: "auto", opacity: 1 }} exit={{ height: 0, opacity: 0 }}
            className="overflow-hidden border-t">
            <div className="space-y-4 p-4">
              <Trajectory plan={plan} />

              {!readOnly && (sent ? (
                <div className="flex flex-wrap items-center gap-2 rounded-lg border border-ok-line bg-ok-bg p-2.5 text-[12px]">
                  <Check size={14} className="shrink-0 text-ok" />
                  <span className="font-semibold text-ok">
                    Sent {sent.submitted.length} fix{sent.submitted.length !== 1 ? "es" : ""} to the Change Gate
                    {sent.auto_approved > 0 ? ` · ${sent.auto_approved} auto-approved` : ""}
                    {sent.escalated > 0 ? ` · ${sent.escalated} escalated` : ""}
                  </span>
                  {sent.skipped.length > 0 && <span className="text-text3">{sent.skipped.length} skipped</span>}
                  {onNavigate && <button onClick={() => onNavigate("change")} className="ml-auto font-bold underline">Open Change Gate</button>}
                </div>
              ) : sendable > 0 ? (
                <div className="flex flex-wrap items-center gap-2 rounded-lg border bg-panel p-2.5 text-[12px]">
                  <GitBranch size={14} className="shrink-0 text-text2" />
                  <span className="min-w-0 text-text2">{sendable} proven fix{sendable !== 1 ? "es" : ""} ready — each is re-evaluated by the gate before it can be staged.</span>
                  <button onClick={send} disabled={sending} className="btn-primary ml-auto !py-1.5 text-xs">
                    {sending ? <Spinner label="Sending…" /> : <><Send size={13} /> Send all to Change Gate</>}
                  </button>
                </div>
              ) : null)}

              <div className="grid gap-2">
                {plan.steps.map((s) => (
                  <StepRow key={s.n} s={s} open={open === s.n} onToggle={() => setOpen(open === s.n ? null : s.n)} />
                ))}
              </div>

              {plan.residual_findings.length > 0 && (
                <div className="sunk p-3">
                  <div className="mb-1.5 flex items-center gap-1.5 text-[12px] font-semibold text-sev-high">
                    <AlertTriangle size={13} /> {plan.residual_findings.length} finding{plan.residual_findings.length !== 1 ? "s" : ""} still need a human
                  </div>
                  <div className="flex flex-wrap gap-1.5">
                    {plan.residual_findings.map((r, i) => (
                      <span key={i} className="chip border-sev-high-line bg-sev-high-bg text-[10px] text-sev-high">{r.title}</span>
                    ))}
                  </div>
                </div>
              )}
              <div className="text-[10px] text-muted">via {plan.by === "llm" ? "the AI agent (fixes proven by the engine)" : "the deterministic engine (model unavailable)"}</div>
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
}

/** The headline: criticals N -> 0, with the per-step trajectory the engine measured. */
function Trajectory({ plan }: { plan: CampaignPlan }) {
  const t = plan.criticals_trajectory;
  const start = plan.initial_counts.critical;
  const end = plan.final_counts.critical;
  return (
    <div className="rounded-lg border bg-panel p-3">
      <div className="mb-2 flex flex-wrap items-center gap-2">
        {plan.cleared_all_criticals ? <ShieldCheck size={16} className="text-ok" /> : <Rocket size={16} className="text-accent-fg" />}
        <span className="text-sm font-bold">
          {plan.cleared_all_criticals
            ? <>Drove criticals <span className="text-sev-critical">{start}</span> → <span className="text-ok">0</span></>
            : <>Reduced criticals <span className="text-sev-critical">{start}</span> → <span className={end > 0 ? "text-sev-high" : "text-ok"}>{end}</span></>}
        </span>
        <span className="ml-auto flex items-center gap-2 text-[11px] text-muted">
          <span className="chip border-ok-line bg-ok-bg text-ok"><Check size={11} /> {plan.applied_count} applied</span>
          {plan.needs_review_count > 0 && <span className="chip border-sev-high-line bg-sev-high-bg text-sev-high"><AlertTriangle size={11} /> {plan.needs_review_count} to review</span>}
        </span>
      </div>
      <div className="flex flex-wrap items-center gap-1.5">
        {t.map((c, i) => (
          <span key={i} className="flex items-center gap-1.5">
            <span className={cn("mono grid h-7 min-w-[28px] place-items-center rounded px-1.5 text-[13px] font-bold tabular-nums",
              c > 0 ? "border border-sev-critical-line bg-sev-critical-bg text-sev-critical" : "border border-ok-line bg-ok-bg text-ok")}>
              {c}
            </span>
            {i < t.length - 1 && <ArrowRight size={13} className="shrink-0 text-text3" />}
          </span>
        ))}
        <span className="ml-1 text-[11px] text-text3">criticals after each proven step</span>
      </div>
    </div>
  );
}

function StepRow({ s, open, onToggle }: { s: CampaignStep; open: boolean; onToggle: () => void }) {
  const applied = s.status === "applied";
  return (
    <div className={cn("rounded-lg border", applied ? "border-border" : "border-sev-high-line")}>
      <button onClick={onToggle} className="flex w-full items-center gap-2.5 p-2.5 text-left hover:bg-surfaceHover">
        <span className="mono grid h-6 w-6 shrink-0 place-items-center rounded bg-sunk text-[11px] font-bold text-text2">{s.n}</span>
        {applied
          ? <Check size={15} className="shrink-0 text-ok" />
          : <AlertTriangle size={15} className="shrink-0 text-sev-high" />}
        <span className="min-w-0 flex-1">
          <span className="block truncate text-[13px] font-medium">{s.target.title}</span>
          <span className="mono block truncate text-[11px] text-muted">
            {s.change?.op} {s.change?.target_ref}
            {s.change?.new_source ? ` → ${s.change.new_source}` : ""}
            {s.change?.new_service ? ` → ${s.change.new_service}` : ""}
          </span>
        </span>
        <span className="shrink-0" style={{ color: `var(--sev-${s.target.band})` }}>
          <span className="chip text-[10px]" style={{ borderColor: `var(--sev-${s.target.band}-line)`, background: `var(--sev-${s.target.band}-bg)` }}>{s.target.band}</span>
        </span>
        {applied && typeof s.criticals_after === "number" && (
          <span className="hidden shrink-0 text-[11px] text-muted sm:inline">
            crit {s.criticals_before}→{s.criticals_after}
          </span>
        )}
        <ChevronRight size={15} className={cn("shrink-0 text-text3 transition-transform", open && "rotate-90")} />
      </button>

      <AnimatePresence initial={false}>
        {open && (
          <motion.div initial={{ height: 0 }} animate={{ height: "auto" }} exit={{ height: 0 }} className="overflow-hidden border-t">
            <div className="space-y-2 p-3 text-[12px]">
              {s.fix_text && <p className="text-text2">{s.fix_text}</p>}
              <div className="flex flex-wrap items-center gap-2 text-[11px] text-muted">
                {s.target.refs.map((r) => <span key={r} className="mono chip text-[10px]">{r}</span>)}
                {s.target.tools.map((tl) => <span key={tl} className="chip text-[10px] capitalize">{tl}</span>)}
              </div>
              {applied ? (
                <div className="flex flex-wrap gap-x-4 gap-y-1 text-[11px] text-text3">
                  <span>criticals <b className="text-text2">{s.criticals_before} → {s.criticals_after}</b></span>
                  {typeof s.findings_cleared === "number" && s.findings_cleared > 1 && (
                    <span>cleared <b className="text-text2">{s.findings_cleared} findings</b> (cascade)</span>
                  )}
                  {s.sub_attempts != null && <span>fix found in <b className="text-text2">{s.sub_attempts} round{s.sub_attempts !== 1 ? "s" : ""}</b></span>}
                  <span>by <b className="text-text2">{s.by}</b></span>
                </div>
              ) : (
                <div className="rounded border border-sev-high-line bg-sev-high-bg p-2 text-[11px] text-sev-high">
                  Skipped — {s.reason}. The engine refused to apply it, so the campaign left the posture untouched here.
                </div>
              )}
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
}
