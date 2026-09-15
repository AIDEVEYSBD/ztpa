"use client";

import { useEffect, useMemo, useRef, useState } from "react";
import { AnimatePresence, motion } from "framer-motion";
import { ChevronRight, Sparkles, Wrench, Check, X, ArrowRight, RotateCw, Send, MessageSquarePlus } from "lucide-react";
import { api, asApiError, type ApiError } from "@/lib/api";
import type { ActionItem, Band, Finding, Remediation, RemediationAttempt } from "@/lib/types";
import type { ScreenId } from "./Sidebar";
import { SeverityPill, ToolBadge, cn, Spinner, SkeletonRows, SkeletonText } from "./ui";
import { ErrorState, InlineError } from "./ui/Feedback";
import { Prose } from "./Markdown";
import { RuleRef } from "./RuleRef";
import { CampaignPanel } from "./Campaign";
import { SearchBox } from "@/lib/tableTools";

const BAND_ORDER: Record<Band, number> = { critical: 0, high: 1, medium: 2, low: 3 };
const BANDS: Band[] = ["critical", "high", "medium", "low"];

export function RiskTodo({ actions, findings, readOnly = false, loading = false, actionsError, findingsError, onRetry, onNavigate }:
  { actions: ActionItem[]; findings: Finding[]; readOnly?: boolean; loading?: boolean;
    actionsError?: ApiError; findingsError?: ApiError; onRetry?: () => void; onNavigate?: (s: ScreenId) => void }) {
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

  // Checked BEFORE the loading and empty paths, because an error is definitive:
  // with no findings and no actions this screen would otherwise print
  // "0 findings across three tools, grouped into 0 prioritized actions", which
  // is indistinguishable from a clean estate. An unanswered question is not a
  // clean bill of health, and the user has no way to tell the two apart.
  if (findingsError || actionsError) {
    return (
      <div className="grid gap-3">
        {findingsError && <ErrorState resource="findings" error={findingsError} onRetry={onRetry} />}
        {actionsError && <ErrorState resource="prioritized actions" error={actionsError} onRetry={onRetry} />}
        <p className="text-[12px] leading-relaxed text-text3">
          No risk list is shown on purpose. Nothing here has been assessed as clean — the data behind this screen
          did not load, so the estate&apos;s posture is unknown.
        </p>
      </div>
    );
  }

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

      <CampaignPanel readOnly={readOnly} onNavigate={onNavigate} />

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

/** Decoded L7 application tag (e.g. QUIC). Highlighted when the app is uninspectable. */
function L7Chip({ app, uninspectable }: { app: string; uninspectable?: boolean }) {
  return (
    <span title={uninspectable ? "Uninspectable application — likely a firewall blind spot" : "Decoded application"}
      className={cn("chip shrink-0 text-[10px] uppercase tracking-wide",
        uninspectable ? "border-sev-high-line bg-sev-high-bg text-sev-high" : "border-border text-text2")}>
      {app}
    </span>
  );
}

/** The agent's propose -> re-simulate -> revise trace: how it converged on the fix.
 *  Only shown when the agent actually iterated (or the engine had to step in), so a
 *  one-shot clean fix stays visually quiet. */
function RemediationTrace({ trace, attempts }: { trace?: RemediationAttempt[]; attempts?: number }) {
  if (!trace || trace.length < 2) return null;
  const verdict = (s: RemediationAttempt): { label: string; cls: string } => {
    if (s.by === "engine_fallback") return { label: "engine fallback", cls: "border-border text-text2" };
    if (!s.change) return { label: "no valid change", cls: "border-border text-text3" };
    const v = s.validation || {};
    if (v.error) return { label: "invalid change", cls: "border-sev-high-line bg-sev-high-bg text-sev-high" };
    if (!v.resolves) return { label: "still reachable", cls: "border-sev-high-line bg-sev-high-bg text-sev-high" };
    if (v.introduces_new_criticals?.length) return { label: "opens new critical", cls: "border-sev-medium-line bg-sev-medium-bg text-sev-medium" };
    return { label: "resolved", cls: "border-sev-low-line bg-sev-low-bg text-sev-low" };
  };
  return (
    <details className="mt-2 group">
      <summary className="flex cursor-pointer list-none items-center gap-1.5 text-[11px] font-medium text-muted hover:text-ink">
        <ChevronRight size={12} className="transition-transform group-open:rotate-90" />
        How the agent got here — {attempts ?? trace.filter((t) => t.change).length} propose/re-simulate round{(attempts ?? 0) !== 1 ? "s" : ""}
      </summary>
      <ol className="mt-1.5 space-y-1 border-l border-border pl-3">
        {trace.map((s, i) => {
          const v = verdict(s);
          return (
            <li key={i} className="flex flex-wrap items-center gap-1.5 text-[11px]">
              <span className="mono text-text3">{s.attempt}.</span>
              {s.change ? (
                <span className="mono text-muted">{s.change.op} <span className="text-text2">{s.change.target_ref}</span>
                  {s.change.new_source && <> → {s.change.new_source}</>}
                  {s.change.new_service && <> → {s.change.new_service}</>}
                </span>
              ) : <span className="text-text3 italic">{s.note || "no change proposed"}</span>}
              <span className={cn("chip ml-auto text-[10px]", v.cls)}>{v.label}</span>
              {s.reasoning && <div className="w-full pl-4 text-[10px] text-text3">{s.reasoning}</div>}
            </li>
          );
        })}
      </ol>
    </details>
  );
}

function BandChip({ band, label, n, active, onClick }: { band?: Band; label: string; n: number; active: boolean; onClick: () => void }) {
  return (
    <button onClick={onClick} data-active={active}
      className={cn("inline-flex items-center gap-1.5 border px-2 py-1 text-[11px] font-medium capitalize",
        active ? "border-accent bg-accent-soft text-accent-fg" : "border-border text-text2 hover:bg-surfaceHover")}>
      {band && <span className="h-1.5 w-1.5" style={{ background: `var(--sev-${band})` }} />}
      {label} <span className="mono text-text3">{n}</span>
    </button>
  );
}

/** The advisory layer's answer about one finding.
 *
 *  `explanation` is nullable because it is MODEL PROSE and null until a model
 *  has written one. The engine's own deterministic explanation is not in here —
 *  it arrives on the finding itself as `engine_explanation`, is always present,
 *  and is what this card shows while (or instead of) the model's.
 *
 *  `unavailable_reason` is a FINISHED answer: a model was asked and produced
 *  nothing. Polling past it is a loop with no exit. */
type Expl = {
  explanation: string | null; by: string | null; pending?: boolean;
  error?: ApiError; provider?: string; unavailable_reason?: string;
};

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
  const [remErr, setRemErr] = useState<ApiError>();
  const [comment, setComment] = useState("");
  const [refining, setRefining] = useState(false);
  const [sending, setSending] = useState(false);
  const [sent, setSent] = useState(false);
  const [actErr, setActErr] = useState<{ what: string; error: ApiError }>();
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
      // `unavailable_reason` ends the wait: the model ran and produced nothing,
      // so there is no later state to poll towards.
      if (r.pending && !r.unavailable_reason && attempt < 14) {
        // Adaptive backoff: poll fast at first so a hosted-model explanation
        // (~1-2s) swaps in almost immediately, then ease off for a slow/cold
        // local model. ~0.8s, 1.2s, 1.9s, … capped at 6s.
        const wait = Math.min(800 * 1.5 ** attempt, 6000);
        pollRef.current = setTimeout(() => fetchExplain(attempt + 1), wait);
      }
    } catch (e) {
      // Name the failure: a 403 on the explain endpoint is a capability the
      // role does not have, not "the model is warming up".
      setExLoading(false);
      setExplain({ explanation: null, by: "error", error: asApiError(e) });
    }
  };

  const toggle = () => {
    const next = !open;
    setOpen(next);
    if (next && !explain && !exLoading) {
      // A historical snapshot is read-only, so no model call is made. The
      // cached model prose is shown if one was written at the time; the engine's
      // own explanation is on the finding regardless and is rendered below it,
      // so this branch never leaves the card empty.
      if (readOnly) { setExplain({ explanation: f.explanation ?? null, by: "cached" }); return; }
      setExLoading(true);
      fetchExplain(0);
    }
  };
  const retryExplain = () => { if (pollRef.current) clearTimeout(pollRef.current); setExplain(undefined); setExLoading(true); fetchExplain(0); };

  const remediate = async () => {
    setRemLoading(true); setRemErr(undefined); setSent(false); setActErr(undefined);
    try { setRem(await api.remediate(f.finding_id)); }
    catch (e) { setRemErr(asApiError(e)); }
    finally { setRemLoading(false); }
  };

  const refine = async () => {
    if (!comment.trim() || !rem) return;
    setRefining(true); setActErr(undefined); setSent(false);
    try {
      const next = await api.remediateRefine(f.finding_id, comment.trim(), rem.change);
      setRem(next); setComment("");
    } catch (e) { setActErr({ what: "the refined fix", error: asApiError(e) }); } finally { setRefining(false); }
  };

  const sendToGate = async () => {
    if (!rem) return;
    setSending(true); setActErr(undefined);
    try {
      await api.changeSubmit({ finding_id: f.finding_id, change: rem.change, revision_id: rem.revision_id });
      setSent(true);
    } catch (e) { setActErr({ what: "the Change Gate submission", error: asApiError(e) }); } finally { setSending(false); }
  };

  return (
    <div className="px-4 py-3">
      <div role="button" tabIndex={0} onClick={toggle} className="flex w-full cursor-pointer items-center gap-2 text-left">
        <SeverityPill band={f.severity_band} severity={f.severity} forced={f.forced_critical} />
        <span className="min-w-0 flex-1 truncate text-sm">{f.signals?.title ?? f.type}</span>
        {f.signals?.l7_app && <L7Chip app={f.signals.l7_app} uninspectable={!!f.signals.uninspectable} />}
        {f.source_tools.map((t) => <ToolBadge key={t} tool={t} />)}
        <span className="flex shrink-0 flex-wrap justify-end gap-1" onClick={(e) => e.stopPropagation()}>
          {f.raw_refs.map((r) => <RuleRef key={r} refId={r} />)}
        </span>
      </div>

      <AnimatePresence>
        {open && (
          <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}
            className="mt-3 space-y-3 sunk p-3">
            <div>
              <div className="mb-1 flex items-center gap-1.5 text-xs font-semibold text-muted">
                <Sparkles size={12} className="text-text2" /> Why this matters
              </div>
              {/* THE ENGINE'S ANSWER, ALWAYS. It is deterministic, it is on the
                  finding already, and it needs no model and no network. This
                  card used to render only the advisory response, so a finding
                  nobody had asked a model about showed nothing -- while the
                  engine had computed exactly what was wrong and could say so. */}
              {f.engine_explanation ? (
                <>
                  <Prose>{f.engine_explanation}</Prose>
                  <div className="mt-1 text-[10px] text-muted">via the engine</div>
                </>
              ) : exLoading && !explain ? <SkeletonText lines={3} /> : null}

              {/* ...and the model's, BELOW it and separately attributed, when a
                  model has actually written one. Never merged with the above:
                  they have different authors and different warranties. */}
              {explain?.error ? (
                <div className="mt-2">
                  <InlineError resource="the advisory explanation" error={explain.error} onRetry={retryExplain} />
                </div>
              ) : explain?.explanation ? (
                <div className="mt-2.5 border-t border-hair pt-2">
                  <Prose>{explain.explanation}</Prose>
                  <div className="mt-1 text-[10px] text-muted">via {explain.by}</div>
                </div>
              ) : null}

              {explain?.unavailable_reason && !explain.explanation ? (
                // A model ran and produced nothing. Stated once, plainly, and
                // not as an error: the engine's answer above is complete.
                <div className="mt-2 text-[11px] leading-relaxed text-text3">
                  {explain.unavailable_reason}
                </div>
              ) : null}

              {explain?.pending && !explain.unavailable_reason && (
                <div className="mt-1.5 flex items-center gap-1.5 text-[11px] text-text3">
                  <span className="h-3 w-3 animate-spin rounded-full border-2 border-accent border-t-transparent" />
                  Adding {providerLabel(explain.provider)}’s wording… the explanation above is already complete.
                </div>
              )}
            </div>

            {!rem ? (readOnly ? null : (
              <div className="space-y-1.5">
                <button onClick={remediate} disabled={remLoading} className="btn-ghost text-xs">
                  {remLoading ? <Spinner label="Drafting + re-simulating…" /> : <><Wrench size={13} /> Draft &amp; validate a fix</>}
                </button>
                {remErr && <InlineError resource="a drafted fix" error={remErr} onRetry={remediate} />}
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
                    <div className="mt-1 text-[10px] text-text2">engine corrected the AI&apos;s first proposal, then proved this one</div>
                  )}
                  <RemediationTrace trace={rem.trace} attempts={rem.attempts} />
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
                    {actErr && <InlineError resource={actErr.what} error={actErr.error} />}
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
