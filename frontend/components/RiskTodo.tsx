"use client";

import { useEffect, useMemo, useRef, useState } from "react";
import { AnimatePresence, motion } from "framer-motion";
import { ChevronRight, Sparkles, Wrench, Check, X, ArrowRight, RotateCw, Send, MessageSquarePlus } from "lucide-react";
import { api } from "@/lib/api";
import type { ActionItem, Band, Finding, Remediation } from "@/lib/types";
import type { ScreenId } from "./Sidebar";
import { SeverityPill, ToolBadge, cn, Spinner, SkeletonRows, SkeletonText } from "./ui";
import { Prose } from "./Markdown";
import { RuleRef } from "./RuleRef";
import { SearchBox } from "@/lib/tableTools";

const BAND_ORDER: Record<Band, number> = { critical: 0, high: 1, medium: 2, low: 3 };
const BANDS: Band[] = ["critical", "high", "medium", "low"];

export function RiskTodo({ actions, findings, readOnly = false, loading = false, onNavigate }: { actions: ActionItem[]; findings: Finding[]; readOnly?: boolean; loading?: boolean; onNavigate?: (s: ScreenId) => void }) {
  const byId = useMemo(() => Object.fromEntries(findings.map((f) => [f.finding_id, f])), [findings]);

  const enriched = useMemo(() => actions.map((a) => {
    const fs = a.finding_ids.map((id) => byId[id]).filter(Boolean) as Finding[];
    const worst = fs.reduce<Band>((w, f) => (BAND_ORDER[f.severity_band] < BAND_ORDER[w] ? f.severity_band : w), "low");
    const haystack = `${a.title} ${a.rationale} ${fs.map((f) => `${f.signals?.title ?? f.type} ${f.raw_refs.join(" ")} ${f.source_tools.join(" ")}`).join(" ")}`.toLowerCase();
    return { a, fs, worst, haystack };
  }), [actions, byId]);

  const counts = useMemo(() => {
    const c: Record<Band, number> = { critical: 0, high: 0, medium: 0, low: 0 };
    enriched.forEach((e) => { c[e.worst]++; });
    return c;
  }, [enriched]);

  const [q, setQ] = useState("");
  const [band, setBand] = useState<Band | "all">("all");
  const [open, setOpen] = useState<string | null>(actions[0]?.action_id ?? null);

  const shown = useMemo(() => {
    const needle = q.trim().toLowerCase();
    return enriched.filter((e) => (band === "all" || e.worst === band) && (!needle || e.haystack.includes(needle)));
  }, [enriched, band, q]);

  if (loading && actions.length === 0) {
    return (
      <div className="grid gap-3">
        <p className="text-sm text-muted">Ranking findings into prioritized actions…</p>
        <SkeletonRows rows={6} />
      </div>
    );
  }

  return (
    <div className="grid gap-3">
      <p className="text-sm text-muted">
        {findings.length} findings across three tools, grouped by root cause into{" "}
        <b className="text-ink">{actions.length} prioritized actions</b>, worst first.
      </p>

      <div className="flex flex-wrap items-center gap-2">
        <SearchBox value={q} onChange={setQ} placeholder="Search actions, assets, rules…" />
        <div className="flex flex-wrap items-center gap-1">
          <BandChip label="all" n={enriched.length} active={band === "all"} onClick={() => setBand("all")} />
          {BANDS.map((b) => <BandChip key={b} band={b} label={b} n={counts[b]} active={band === b} onClick={() => setBand(b)} />)}
        </div>
        <span className="ml-auto text-xs text-text3">showing {shown.length} of {enriched.length}</span>
      </div>

      {shown.length === 0 ? (
        <div className="panel p-6 text-center text-[13px] text-text3">No actions match this filter.</div>
      ) : shown.map(({ a, fs, worst }) => {
        const isOpen = open === a.action_id;
        return (
          <div key={a.action_id} className="panel overflow-hidden">
            <button onClick={() => setOpen(isOpen ? null : a.action_id)}
              className="flex w-full items-center gap-3 p-4 text-left hover:bg-surfaceHover">
              <span className="mono grid h-7 min-w-[30px] shrink-0 place-items-center px-1.5 text-[12px] font-bold tabular-nums"
                style={{ background: `var(--sev-${worst}-bg)`, color: `var(--sev-${worst})`, border: `1px solid var(--sev-${worst}-line)` }}>
                #{a.priority}
              </span>
              <div className="min-w-0 flex-1">
                <div className="font-semibold">{a.title}</div>
                <div className="truncate text-xs text-muted">{a.rationale}</div>
              </div>
              <SeverityPill band={worst} />
              <span className="hidden text-xs text-muted sm:inline">{fs.length} finding{fs.length !== 1 ? "s" : ""}</span>
              <ChevronRight size={16} className={cn("transition-transform", isOpen && "rotate-90")} />
            </button>
            <AnimatePresence initial={false}>
              {isOpen && (
                <motion.div initial={{ height: 0 }} animate={{ height: "auto" }} exit={{ height: 0 }}
                  className="overflow-hidden border-t">
                  <div className="divide-y">
                    {fs.map((f) => <FindingRow key={f.finding_id} f={f} readOnly={readOnly} onNavigate={onNavigate} />)}
                  </div>
                </motion.div>
              )}
            </AnimatePresence>
          </div>
        );
      })}
    </div>
  );
}

function BandChip({ band, label, n, active, onClick }: { band?: Band; label: string; n: number; active: boolean; onClick: () => void }) {
  return (
    <button onClick={onClick} data-active={active}
      className={cn("inline-flex items-center gap-1.5 border px-2 py-1 text-[11px] font-medium capitalize",
        active ? "border-accent text-text" : "border-border text-text2 hover:bg-surfaceHover")}>
      {band && <span className="h-1.5 w-1.5" style={{ background: `var(--sev-${band})` }} />}
      {label} <span className="mono text-text3">{n}</span>
    </button>
  );
}

type Expl = { explanation: string; by: string; pending?: boolean; error?: boolean; provider?: string };

// Truthfully name the provider doing the work — the engine routes to a local
// Ollama model when one is up, else a hosted one (OpenAI/Anthropic).
const providerLabel = (p?: string) =>
  p === "ollama" ? "the local model"
  : p === "openai" ? "OpenAI"
  : p === "anthropic" ? "Anthropic"
  : "the AI model";

function FindingRow({ f, readOnly, onNavigate }: { f: Finding; readOnly?: boolean; onNavigate?: (s: ScreenId) => void }) {
  const [open, setOpen] = useState(false);
  const [explain, setExplain] = useState<Expl>();
  const [exLoading, setExLoading] = useState(false);
  const [rem, setRem] = useState<Remediation>();
  const [remLoading, setRemLoading] = useState(false);
  const [remErr, setRemErr] = useState(false);
  const [comment, setComment] = useState("");
  const [refining, setRefining] = useState(false);
  const [sending, setSending] = useState(false);
  const [sent, setSent] = useState(false);
  const [actErr, setActErr] = useState<string>();
  const pollRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  useEffect(() => () => { if (pollRef.current) clearTimeout(pollRef.current); }, []);

  // The explain endpoint returns instantly with a deterministic explanation and a
  // `pending` flag; the richer LLM version is computed server-side and cached.
  // We re-fetch a few times to swap it in once ready (no proxy-blocking call).
  const fetchExplain = async (attempt = 0) => {
    try {
      const r = await api.explain(f.finding_id);
      setExplain(r);
      setExLoading(false);
      if (r.pending && attempt < 10) {
        pollRef.current = setTimeout(() => fetchExplain(attempt + 1), 7000);
      }
    } catch {
      setExLoading(false);
      setExplain({ explanation: "Could not reach the explanation service. Try again.", by: "error", error: true });
    }
  };

  const toggle = () => {
    const next = !open;
    setOpen(next);
    if (next && !explain && !exLoading) {
      if (readOnly) { setExplain({ explanation: f.explanation || "No cached explanation for this snapshot.", by: "cached" }); return; }
      setExLoading(true);
      fetchExplain(0);
    }
  };
  const retryExplain = () => { if (pollRef.current) clearTimeout(pollRef.current); setExplain(undefined); setExLoading(true); fetchExplain(0); };

  const remediate = async () => {
    setRemLoading(true); setRemErr(false); setSent(false); setActErr(undefined);
    try { setRem(await api.remediate(f.finding_id)); } catch { setRemErr(true); } finally { setRemLoading(false); }
  };

  const refine = async () => {
    if (!comment.trim() || !rem) return;
    setRefining(true); setActErr(undefined); setSent(false);
    try {
      const next = await api.remediateRefine(f.finding_id, comment.trim(), rem.change);
      setRem(next); setComment("");
    } catch { setActErr("Could not re-iterate right now. Try again."); } finally { setRefining(false); }
  };

  const sendToGate = async () => {
    if (!rem) return;
    setSending(true); setActErr(undefined);
    try {
      await api.changeSubmit({ finding_id: f.finding_id, change: rem.change, revision_id: rem.revision_id });
      setSent(true);
    } catch { setActErr("Could not send to the Change Gate. Try again."); } finally { setSending(false); }
  };

  return (
    <div className="px-4 py-3">
      <div role="button" tabIndex={0} onClick={toggle} className="flex w-full cursor-pointer items-center gap-2 text-left">
        <SeverityPill band={f.severity_band} severity={f.severity} forced={f.forced_critical} />
        <span className="min-w-0 flex-1 truncate text-sm">{f.signals?.title ?? f.type}</span>
        {f.source_tools.map((t) => <ToolBadge key={t} tool={t} />)}
        <span className="flex shrink-0 flex-wrap justify-end gap-1" onClick={(e) => e.stopPropagation()}>
          {f.raw_refs.map((r) => <RuleRef key={r} refId={r} />)}
        </span>
      </div>

      <AnimatePresence>
        {open && (
          <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}
            className="mt-3 space-y-3 rounded-lg bg-surfaceHover p-3">
            <div>
              <div className="mb-1 flex items-center gap-1.5 text-xs font-semibold text-muted">
                <Sparkles size={12} className="text-text2" /> Why this matters
              </div>
              {exLoading && !explain ? <SkeletonText lines={3} /> :
                explain ? <Prose>{explain.explanation}</Prose> : null}
              {explain?.pending && (
                <div className="mt-1.5 flex items-center gap-1.5 text-[11px] text-text3">
                  <span className="h-3 w-3 animate-spin rounded-full border-2 border-accent border-t-transparent" />
                  Refining with {providerLabel(explain.provider)}…
                </div>
              )}
              {explain?.error ? (
                <button onClick={retryExplain} className="btn-ghost mt-1.5 text-xs"><RotateCw size={12} /> Retry</button>
              ) : explain && !explain.pending && <div className="mt-1 text-[10px] text-muted">via {explain.by}</div>}
            </div>

            {!rem ? (readOnly ? null : (
              <div className="space-y-1.5">
                <button onClick={remediate} disabled={remLoading} className="btn-ghost text-xs">
                  {remLoading ? <Spinner label="Drafting + re-simulating…" /> : <><Wrench size={13} /> Draft &amp; validate a fix</>}
                </button>
                {remErr && <div className="text-[11px] text-sev-high">Could not draft a fix right now (the model may be loading). Try again.</div>}
              </div>
            )) : (
              <div className="space-y-2.5">
                <div className="rounded-lg border bg-panel p-3">
                  <div className="mb-1 flex items-center gap-1.5 text-xs font-semibold">
                    <Wrench size={12} className="text-text2" /> Suggested fix
                    {rem.seq != null && rem.seq > 0 && <span className="chip border-border text-[10px] text-text3">revision {rem.seq + 1}</span>}
                    <span className={cn("chip ml-auto", rem.validation.resolves
                      ? "border-sev-low-line bg-sev-low-bg text-sev-low" : "border-sev-high-line bg-sev-high-bg text-sev-high")}>
                      {rem.validation.resolves ? <><Check size={12} /> re-simulated: resolves</> : <><X size={12} /> does not resolve</>}
                    </span>
                  </div>
                  <Prose className="!text-sm">{rem.fix_text}</Prose>
                  <div className="mt-2 flex flex-wrap items-center gap-1.5 font-mono text-[11px] text-muted">
                    <span>{rem.change.op}</span><span className="text-text2">{rem.change.target_ref}</span>
                    {rem.change.new_source && <><ArrowRight size={11} className="shrink-0" /><span>{rem.change.new_source}</span></>}
                    {rem.change.new_service && <><ArrowRight size={11} className="shrink-0" /><span>{rem.change.new_service}</span></>}
                  </div>
                  {rem.validation.engine_corrected_ai && (
                    <div className="mt-1 text-[10px] text-text2">engine corrected the AI's first proposal, then proved this one</div>
                  )}
                </div>

                {readOnly ? null : sent ? (
                  <div className="flex flex-wrap items-center gap-2 rounded-lg border border-ok-line bg-ok-bg p-2.5 text-[12px]">
                    <Check size={14} className="text-ok" />
                    <span className="font-semibold text-ok">Sent to the Change Gate.</span>
                    {onNavigate && (
                      <button onClick={() => onNavigate("change")} className="ml-auto font-bold underline">Open Change Gate</button>
                    )}
                  </div>
                ) : (
                  <div className="space-y-2">
                    {/* Iterate: comment -> re-draft -> repeat, until it's right */}
                    <label className="block">
                      <span className="label mb-1 flex items-center gap-1.5"><MessageSquarePlus size={12} /> Comment to refine this fix</span>
                      <textarea value={comment} onChange={(e) => setComment(e.target.value)} rows={2}
                        placeholder="e.g. don't remove the rule — scope the source to the jump host instead"
                        className="field !text-[12px]" />
                    </label>
                    <div className="flex flex-wrap items-center gap-2">
                      <button onClick={refine} disabled={refining || !comment.trim()} className="btn-ghost text-xs">
                        {refining ? <Spinner label="Re-iterating…" /> : <><RotateCw size={13} /> Re-iterate</>}
                      </button>
                      <button onClick={sendToGate} disabled={sending || !rem.validation.resolves}
                        className="btn-primary ml-auto !py-1.5 text-xs" title={rem.validation.resolves ? "" : "Refine until the fix resolves the finding"}>
                        {sending ? <Spinner label="Sending…" /> : <><Send size={13} /> Accept &amp; send to Change Gate</>}
                      </button>
                    </div>
                    {!rem.validation.resolves && (
                      <div className="text-[11px] text-text3">Refine with a comment until the fix re-simulates as resolving, then you can send it to the gate.</div>
                    )}
                    {actErr && <div className="text-[11px] text-sev-high">{actErr}</div>}
                  </div>
                )}
              </div>
            )}
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
}
