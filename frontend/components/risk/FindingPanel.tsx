"use client";

/**
 * ONE FINDING, END TO END.
 *
 * The Change Gate used to be a place you navigated to, which meant the reviewer
 * had to carry the finding in their head across a screen boundary and trust that
 * the request waiting on the other side was the same one. It is now a STEP in
 * this panel, and the panel is the whole story in order:
 *
 *   1  what is wrong            the analyzer's own title + the engine's explanation
 *   2  the actual rules         action, endpoints as assets, service, direction
 *   3  the proposed fix         drafted, re-simulated, refined — and what it cuts
 *   4  the gate's ruling        criteria, delta, verdict — decided here
 *   5  implementation           queued, applied, and the way back out
 *
 * Nothing here invents an action with no endpoint behind it, and every step that
 * is not yet reachable says why rather than rendering a dead control.
 */

import { useEffect, useRef, useState } from "react";
import {
  AlertTriangle, ArrowRight, Check, MessageSquarePlus, Rocket, RotateCw, Scissors, Send,
  ShieldCheck, Sparkles, Wrench, X,
} from "lucide-react";
import { api, asApiError, type ApiError } from "@/lib/api";
import type { Finding, ActionItem, PushPlan, Remediation, RemediationAttempt } from "@/lib/types";
import { cn } from "@/lib/cn";
import { Prose } from "@/components/Markdown";
import { SeverityPill, Spinner, ToolBadge, SkeletonText } from "@/components/ui";
import { InlineError } from "@/components/ui/Feedback";
import { Step } from "./bits";
import { DirectionLegend } from "./direction";
import { GateRuling, ProposedLine, VerdictHeader } from "./gate";
import { AppliedChangeCard, StatusChip, toolLabel, type QueueRow } from "./implementation";
import { AssetBlock, RuleUnavailable } from "./RuleCard";
import { RuleFull, RuleToken } from "./RuleToken";
import { useRule } from "./useRule";

/** The gate's ruling on one request, however it arrived — freshly returned by
 *  `/api/change/submit` or read back off `/api/change-decisions`. Normalising
 *  the two here is what lets the panel and the Change Gate screen render the
 *  same component instead of two shapes of the same fact. */
export interface Ruling {
  request_id: string;
  decision: string;
  forced_escalate?: boolean;
  confidence?: number;
  decided_by?: string;
  criteria?: Record<string, any>;
  delta_summary?: Record<string, any>;
  triggering_reason?: string | null;
  kind?: string;
  proposed?: Record<string, any>;
  justification?: string | null;
  request_status?: string;
  rejected_by?: string | null;
  reject_reason?: string | null;
  staged_id?: string | null;
  staged_status?: string | null;
  decided_at?: string | null;
  requested_by?: string | null;
}

/** Pull the ruling for one finding out of the decision log. The link is
 *  `proposed.finding_id`, which `/api/change/submit` writes onto every
 *  remediation request — this is the mapping from Risk To-Do to the gate. */
export function rulingForFinding(decisions: any[] | undefined, findingId: string): Ruling | undefined {
  return (decisions ?? []).find((d) => (d?.proposed ?? {}).finding_id === findingId) as Ruling | undefined;
}

// Truthfully name the provider doing the work — the engine routes to a local
// Ollama model when one is up, else a hosted one.
const providerLabel = (p?: string) =>
  p === "ollama" ? "the local model" : p === "openai" ? "OpenAI" : p === "anthropic" ? "Anthropic" : "the AI model";

/** The advisory layer's answer. `explanation` is MODEL PROSE and null until a
 *  model writes one; `unavailable_reason` is a FINISHED answer, so polling past
 *  it is a loop with no exit. */
type Expl = { explanation: string | null; by: string | null; pending?: boolean; error?: ApiError; provider?: string; unavailable_reason?: string };

/**
 * What the re-simulation actually proved.
 *
 * The verdict was a badge reading "re-simulated: resolves" and nothing else,
 * so a reviewer being asked to approve a change to a production firewall had a
 * green pill and a word. The proof existed in the payload the whole time.
 *
 * This renders it as a ledger: band counts either side, every finding the change
 * clears, every finding it introduces, and which analyzers were re-run. Numbers
 * a reader can check, not an assurance.
 */
function VerificationEvidence({ v }: { v: Remediation["validation"] }) {
  const e = (v as { evidence?: EvidenceRecord }).evidence;
  if (!e) return null;
  const BANDS = ["critical", "high", "medium", "low"] as const;
  const delta = (b: (typeof BANDS)[number]) =>
    (e.bands_after?.[b] ?? 0) - (e.bands_before?.[b] ?? 0);

  return (
    <div className="border border-border bg-sunk">
      <div className="flex flex-wrap items-baseline justify-between gap-x-3 border-b border-hair px-2.5 py-1.5">
        <span className="text-[10px] font-bold uppercase tracking-[0.08em] text-text2">
          Verification
        </span>
        <span className="text-[10.5px] text-text3">{e.method_detail}</span>
      </div>

      <div className="grid grid-cols-4 gap-px bg-border">
        {BANDS.map((b) => {
          const d = delta(b);
          return (
            <div key={b} className="bg-sunk px-2.5 py-1.5">
              <div className="text-[9.5px] uppercase tracking-[0.06em] text-text3">{b}</div>
              <div className="mono flex items-baseline gap-1.5 text-[13px] tabular-nums">
                <span className="text-text3">{e.bands_before?.[b] ?? 0}</span>
                <span className="text-text3">&rarr;</span>
                <span className="font-bold">{e.bands_after?.[b] ?? 0}</span>
                {d !== 0 && (
                  <span className={cn("text-[10px] font-bold", d < 0 ? "text-ok" : "text-sev-high")}>
                    {d > 0 ? `+${d}` : d}
                  </span>
                )}
              </div>
            </div>
          );
        })}
      </div>

      <FindingDelta
        label={`Cleared by this change (${e.cleared.length})`}
        rows={e.cleared}
        tone="ok"
        empty="Nothing cleared. The change does not remove any finding."
      />
      <FindingDelta
        label={`Introduced (${e.introduced.length})`}
        rows={e.introduced}
        tone="warn"
        // The load-bearing empty state. "Nothing new appeared" is the half of the
        // proof that says the fix is safe, so it is stated rather than left as an
        // absent section a reader has to notice is missing.
        empty="Nothing new appeared anywhere in the estate."
      />

      {e.analyzers?.length ? (
        <div className="border-t border-hair px-2.5 py-1.5 text-[10.5px] text-text3">
          Re-ran {e.analyzers.length} analyzers:{" "}
          <span className="mono">{e.analyzers.join(", ")}</span>
        </div>
      ) : null}
    </div>
  );
}

function FindingDelta({ label, rows, tone, empty }: {
  label: string;
  rows: EvidenceFinding[];
  tone: "ok" | "warn";
  empty: string;
}) {
  return (
    <div className="border-t border-hair px-2.5 py-1.5">
      <div className="text-[10px] font-bold uppercase tracking-[0.06em] text-text3">{label}</div>
      {rows.length === 0 ? (
        <div className="mt-0.5 text-[11px] text-text3">{empty}</div>
      ) : (
        <ul className="mt-1 space-y-1">
          {rows.map((r, i) => (
            <li key={`${r.type}-${i}`} className="flex items-start gap-1.5 text-[11.5px] leading-snug">
              <span className={cn("mt-[3px] h-1.5 w-1.5 shrink-0",
                tone === "ok" ? "bg-ok" : "bg-sev-high")} />
              <span className="min-w-0">
                <span className="text-text">{r.title}</span>{" "}
                <span className="mono text-[10px] text-text3">
                  {r.band} · {r.refs.join(", ")}
                </span>
              </span>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}

interface EvidenceFinding {
  type: string; title: string; band: string; severity: number;
  refs: string[]; tools: string[];
}
interface EvidenceRecord {
  method: string;
  method_detail: string;
  bands_before: Record<string, number>;
  bands_after: Record<string, number>;
  cleared: EvidenceFinding[];
  introduced: EvidenceFinding[];
  analyzers: string[];
}

export function FindingPanel({
  finding: f, action, snapshot, readOnly, canApprove, decisions, decisionsError, staged, stagingError,
  onGovernanceChanged, onClose,
}: {
  finding: Finding;
  action?: ActionItem;
  snapshot?: string;
  readOnly?: boolean;
  canApprove: boolean;
  decisions?: any[];
  decisionsError?: ApiError;
  staged?: QueueRow[];
  stagingError?: ApiError;
  onGovernanceChanged: () => void;
  onClose: () => void;
}) {
  const ruling = rulingForFinding(decisions, f.finding_id);
  const queued = ruling ? (staged ?? []).find((s) => s.request_id === ruling.request_id) : undefined;

  return (
    <>
      <header className="shrink-0 border-b border-border px-4 py-3">
        <div className="flex items-start gap-2.5">
          <SeverityPill band={f.severity_band} severity={f.severity} forced={f.forced_critical} />
          <div className="min-w-0 flex-1">
            <h2 className="text-[14px] font-bold leading-snug">{f.title ?? f.signals?.title ?? f.type}</h2>
            <div className="mono mt-1 flex flex-wrap items-center gap-x-2 gap-y-1 text-[10px] text-text3">
              <span>{f.type.replace(/_/g, " ")}</span>
              {action && <span>· action #{action.priority} {action.title}</span>}
              <span>· {f.finding_id}</span>
            </div>
          </div>
          <button onClick={onClose} aria-label="Close" className="btn-ghost shrink-0 !h-[26px] !w-[26px] !px-0">
            <X size={14} />
          </button>
        </div>
      </header>

      <div className="zt-scroll min-h-0 flex-1 space-y-2.5 overflow-y-auto p-3">
        <WhatIsWrong f={f} readOnly={readOnly} />
        <TheRules f={f} snapshot={snapshot} />
        <TheFix
          f={f} snapshot={snapshot} readOnly={readOnly} canApprove={canApprove}
          ruling={ruling} onGovernanceChanged={onGovernanceChanged}
        />
        <TheGate
          f={f} ruling={ruling} decisionsError={decisionsError} readOnly={readOnly}
          canApprove={canApprove} snapshot={snapshot} queued={queued} onGovernanceChanged={onGovernanceChanged}
        />
        <TheImplementation
          ruling={ruling} queued={queued} stagingError={stagingError} canApprove={canApprove}
          snapshot={snapshot} readOnly={readOnly} onGovernanceChanged={onGovernanceChanged}
        />
      </div>
    </>
  );
}

// ── 1 ── what is wrong ──────────────────────────────────────────────────────

/** The industry term for a rulebase anomaly (Al-Shaer & Hamed), carried by the
 *  analyzer as `signals.anomaly_class`. Rendered from the data, never inferred
 *  from our own prose. */
function AnomalyChip({ cls }: { cls: string }) {
  const shadowed = cls === "shadowed";
  return (
    <span
      title={shadowed
        ? "SHADOWED — an earlier rule with a different action matches all of this rule's packets, so it never fires. The operator believes traffic is blocked."
        : "REDUNDANT — an earlier rule already covers this one with the same action, so removing it changes nothing. Clutter, not exposure."}
      className={cn("inline-flex h-[20px] items-center border px-1.5 text-[10px] font-bold uppercase tracking-[0.08em]",
        shadowed ? "border-sev-high-line bg-sev-high-bg text-sev-high" : "border-border bg-sunk text-text2")}
    >
      {cls}
    </span>
  );
}

function WhatIsWrong({ f, readOnly }: { f: Finding; readOnly?: boolean }) {
  const [explain, setExplain] = useState<Expl>();
  const [exLoading, setExLoading] = useState(false);
  const [asked, setAsked] = useState(false);
  const poll = useRef<ReturnType<typeof setTimeout> | null>(null);
  useEffect(() => () => { if (poll.current) clearTimeout(poll.current); }, []);
  // A new finding is a new question: drop the previous answer rather than
  // showing one finding's prose under another's title.
  useEffect(() => { setExplain(undefined); setAsked(false); setExLoading(false); }, [f.finding_id]);

  const fetchExplain = async (attempt = 0) => {
    try {
      const r = await api.explain(f.finding_id);
      setExplain(r); setExLoading(false);
      if (r.pending && !r.unavailable_reason && attempt < 14) {
        poll.current = setTimeout(() => fetchExplain(attempt + 1), Math.min(800 * 1.5 ** attempt, 6000));
      }
    } catch (e) {
      setExLoading(false);
      setExplain({ explanation: null, by: "error", error: asApiError(e) });
    }
  };

  const ask = () => { setAsked(true); setExLoading(true); setExplain(undefined); fetchExplain(0); };
  const anomaly = typeof f.signals?.anomaly_class === "string" ? f.signals.anomaly_class : undefined;

  return (
    <Step n={1} title="What is wrong"
      note={<span className="inline-flex items-center gap-1.5">
        {anomaly && <AnomalyChip cls={anomaly} />}
        {f.source_tools.map((t) => <ToolBadge key={t} tool={t} />)}
      </span>}>
      {/* THE ENGINE'S ANSWER, ALWAYS. It is deterministic, it is already on the
          finding, and it needs no model and no network. There is no empty
          explanation state on this screen. */}
      {f.engine_explanation ? (
        <>
          <Prose className="!text-[12.5px]">{f.engine_explanation}</Prose>
          <div className="mt-1 text-[10px] text-text3">via the engine</div>
        </>
      ) : (
        <div className="text-[11.5px] text-text3">
          This build of the API sent no engine explanation with the finding. The signals below are what it computed.
        </div>
      )}

      {/* The analyzer's raw signal, shown only when the engine's explanation
          does not already contain it — otherwise it is the same sentence twice. */}
      {typeof f.signals?.reason === "string" && !(f.engine_explanation ?? "").includes(f.signals.reason) && (
        <div className="mono mt-2 border border-border bg-sunk p-2 text-[10.5px] leading-relaxed text-text2">{f.signals.reason}</div>
      )}

      {/* ...and the model's, BELOW it and separately attributed. Never merged:
          they have different authors and different warranties. */}
      {explain?.error ? (
        <div className="mt-2"><InlineError resource="the advisory explanation" error={explain.error} onRetry={ask} /></div>
      ) : explain?.explanation ? (
        <div className="mt-2.5 border-t border-hair pt-2">
          <Prose className="!text-[12.5px]">{explain.explanation}</Prose>
          <div className="mt-1 text-[10px] text-text3">via {explain.by}</div>
        </div>
      ) : exLoading ? (
        <div className="mt-2.5 border-t border-hair pt-2"><SkeletonText lines={2} /></div>
      ) : null}

      {explain?.unavailable_reason && !explain.explanation && (
        <div className="mt-2 text-[10.5px] leading-relaxed text-text3">{explain.unavailable_reason}</div>
      )}

      {explain?.pending && !explain.unavailable_reason && (
        <div className="mt-1.5 flex items-center gap-1.5 text-[10.5px] text-text3">
          <span className="h-3 w-3 animate-spin rounded-full border-2 border-accent border-t-transparent" />
          Adding {providerLabel(explain.provider)}&apos;s wording — the explanation above is already complete.
        </div>
      )}

      {!asked && !readOnly && (
        <button onClick={ask} className="btn-ghost mt-2 !h-[24px] !px-2 text-[11px]">
          <Sparkles size={11} /> Ask the advisory layer
        </button>
      )}
    </Step>
  );
}

// ── 2 ── the actual rules ───────────────────────────────────────────────────

/** A cross-tool finding IS a chain, and the chain is the story: no single
 *  console sees more than one link of it. */
function HopChain({ hops, snapshot }: { hops: any[]; snapshot?: string }) {
  return (
    <ol className="space-y-1">
      {hops.map((h, i) => (
        <li key={i} className="flex flex-wrap items-center gap-1.5 text-[11.5px]">
          <span className="mono w-4 shrink-0 text-text3">{i + 1}.</span>
          <span className="mono truncate">{h.src_display ?? h.src}</span>
          <ArrowRight size={11} className="shrink-0 text-text3" />
          <span className="mono truncate">{h.dst_display ?? h.dst}</span>
          <span className="mono text-[10px] text-text3">{h.service}</span>
          {h.ref && <RuleToken refId={String(h.ref)} snapshot={snapshot} />}
          {h.tool && <ToolBadge tool={h.tool} />}
        </li>
      ))}
    </ol>
  );
}

function TheRules({ f, snapshot }: { f: Finding; snapshot?: string }) {
  const hops: any[] = Array.isArray(f.signals?.hops) ? f.signals.hops : [];
  return (
    <Step n={2} title="The rules behind it"
      note={`${f.raw_refs.length} reference${f.raw_refs.length === 1 ? "" : "s"}`}>
      {hops.length > 0 && (
        <div className="mb-2.5 border border-border bg-sunk p-2">
          <div className="mb-1.5 text-[9.5px] font-bold uppercase tracking-[0.14em] text-text3">the path, hop by hop</div>
          <HopChain hops={hops} snapshot={snapshot} />
        </div>
      )}
      <div className="space-y-2">
        {f.raw_refs.length === 0 ? (
          <div className="text-[11.5px] text-text3">This finding names no rule reference.</div>
        ) : (
          f.raw_refs.map((r) => <RuleFull key={r} refId={r} snapshot={snapshot} />)
        )}
      </div>
      <DirectionLegend className="mt-2.5 border-t border-hair pt-2" />
    </Step>
  );
}

// ── 3 ── the proposed fix ───────────────────────────────────────────────────

/** The agent's propose → re-simulate → revise trace. Only shown when it
 *  actually iterated, so a one-shot clean fix stays visually quiet. */
function RemediationTrace({ trace, attempts }: { trace?: RemediationAttempt[]; attempts?: number }) {
  if (!trace || trace.length < 2) return null;
  const rounds = attempts ?? trace.filter((t) => t.change).length;
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
    <details className="group mt-2">
      <summary className="cursor-pointer list-none text-[10.5px] font-bold uppercase tracking-[0.1em] text-text3 hover:text-text2">
        How the agent got here — {rounds} propose/re-simulate round{rounds === 1 ? "" : "s"}
      </summary>
      <ol className="mt-1.5 space-y-1 border-l border-border pl-3">
        {trace.map((s, i) => {
          const v = verdict(s);
          return (
            <li key={i} className="flex flex-wrap items-center gap-1.5 text-[10.5px]">
              <span className="mono text-text3">{s.attempt}.</span>
              {s.change ? (
                <span className="mono text-text2">{s.change.op} <span className="text-text">{s.change.target_ref}</span></span>
              ) : <span className="italic text-text3">{s.note || "no change proposed"}</span>}
              <span className={cn("ml-auto inline-flex h-[17px] items-center border px-1 text-[9px] font-bold", v.cls)}>{v.label}</span>
              {s.reasoning && <span className="w-full pl-4 text-[9.5px] text-text3">{s.reasoning}</span>}
            </li>
          );
        })}
      </ol>
    </details>
  );
}

/**
 * WHAT THE FIX DISCONNECTS — "in details need to add assets names on the rules
 * that to remove".
 *
 * A reviewer approving a removal must be able to see what loses access: the
 * asset display name, kind, regulated tags, addresses, and which consoles saw
 * it. The wording is per-op, because a reorder disconnects nothing and saying
 * it does would be the same class of lie as an invented zero.
 */
function Disconnects({ change, snapshot }: { change: Record<string, any>; snapshot?: string }) {
  const ref = String(change.target_ref ?? "");
  const { detail, context, loading, error, retry } = useRule(ref, snapshot, !!ref);
  const op = String(change.op ?? "");
  const ctx = context?.[0];

  const headline =
    op === "remove" ? "Removing this rule disconnects"
    : op === "scope_source" ? `Narrowing the source to ${change.new_source ?? "the stated host"} removes access for everything else currently covered`
    : op === "restrict_service" ? `Restricting the service to ${change.new_service ?? "the stated port"} removes the rest of the port range`
    : op === "reorder_before" ? "Reordering removes no grant — it makes the deny take effect"
    : "This change affects";

  if (!ref) return null;
  if (loading && !detail) return <div className="text-[11px] text-text3">Resolving what {ref} touches…</div>;
  if (error || !ctx) return <RuleUnavailable refId={ref} error={error} onRetry={retry} />;

  return (
    <div className="border border-border bg-sunk p-2">
      <div className="mb-1.5 flex flex-wrap items-center gap-1.5">
        <Scissors size={11} className="shrink-0 text-text3" />
        <span className="text-[9.5px] font-bold uppercase tracking-[0.14em] text-text3">{headline}</span>
      </div>
      {op === "reorder_before" ? (
        <p className="text-[11.5px] leading-relaxed text-text2">
          Both endpoints keep every grant they have from other rules. What changes is that{" "}
          <span className="mono">{ref}</span> starts matching first, so the traffic it names stops being permitted by{" "}
          <span className="mono">{String(change.shadowing_ref ?? "the rule above it")}</span>.
        </p>
      ) : (
        <div className="grid gap-2 sm:grid-cols-2">
          <AssetBlock side="source" endpoint={ctx.source} emphasis={ctx.source.public} />
          <AssetBlock side="destination" endpoint={ctx.destination} emphasis={ctx.destination.public} />
        </div>
      )}
      <div className="mt-1.5 text-[10.5px] text-text3">
        on <span className="mono text-text2">{ctx.service}</span>
        {ctx.l7_app ? <> ({ctx.l7_app})</> : null} · {ctx.direction.flow} — {ctx.direction.detail}
      </div>
      {ctx.direction.bidirectional && op === "remove" && (
        // The mistake this whole direction model exists to prevent.
        <div role="alert" className="mt-2 flex items-start gap-1.5 border border-sev-high-line bg-sev-high-bg p-2 text-[11px]">
          <AlertTriangle size={12} className="mt-0.5 shrink-0 text-sev-high" />
          <span>
            <b className="text-sev-high">The reverse grant stays open.</b> This pair is two-way; removing{" "}
            <span className="mono">{ref}</span> leaves{" "}
            {ctx.direction.reverse_ref
              ? <RuleToken refId={ctx.direction.reverse_ref} snapshot={snapshot} tone="loud" />
              : <span className="mono">the reverse rule</span>}{" "}
            in place.
          </span>
        </div>
      )}
    </div>
  );
}

function TheFix({ f, snapshot, readOnly, canApprove, ruling, onGovernanceChanged }: {
  f: Finding; snapshot?: string; readOnly?: boolean; canApprove: boolean;
  ruling?: Ruling; onGovernanceChanged: () => void;
}) {
  const [rem, setRem] = useState<Remediation>();
  const [loading, setLoading] = useState(false);
  const [err, setErr] = useState<ApiError>();
  const [comment, setComment] = useState("");
  const [refining, setRefining] = useState(false);
  const [sending, setSending] = useState(false);
  // Flips step 3 to its record view the instant the submission is accepted,
  // rather than leaving the drafting form up until the decision log re-reads.
  const [submitted, setSubmitted] = useState(false);
  const [actErr, setActErr] = useState<{ what: string; error: ApiError }>();

  useEffect(() => { setRem(undefined); setErr(undefined); setComment(""); setActErr(undefined); setSubmitted(false); }, [f.finding_id]);

  const draft = async () => {
    setLoading(true); setErr(undefined); setActErr(undefined);
    try { setRem(await api.remediate(f.finding_id)); }
    catch (e) { setErr(asApiError(e)); }
    finally { setLoading(false); }
  };
  const refine = async () => {
    if (!comment.trim() || !rem) return;
    setRefining(true); setActErr(undefined);
    try { setRem(await api.remediateRefine(f.finding_id, comment.trim(), rem.change)); setComment(""); }
    catch (e) { setActErr({ what: "the refined fix", error: asApiError(e) }); }
    finally { setRefining(false); }
  };
  const submit = async () => {
    if (!rem) return;
    setSending(true); setActErr(undefined);
    try {
      await api.changeSubmit({ finding_id: f.finding_id, change: rem.change, revision_id: rem.revision_id });
      setSubmitted(true);
      onGovernanceChanged();
    } catch (e) { setActErr({ what: "the gate submission", error: asApiError(e) }); }
    finally { setSending(false); }
  };

  // A ruling already exists: the fix that produced it is the record, so the
  // drafting controls are not offered again over the top of it.
  const settled = ruling ?? (submitted && rem ? { proposed: rem.change, kind: "remediation" } : undefined);
  if (settled) {
    return (
      <Step n={3} title="The proposed fix" note="submitted to the gate">
        <ProposedLine proposed={(settled as any).proposed} kind={(settled as any).kind} snapshot={snapshot} />
        <div className="mt-2"><Disconnects change={(settled as any).proposed ?? {}} snapshot={snapshot} /></div>
      </Step>
    );
  }

  return (
    <Step n={3} title="The proposed fix" note={rem?.seq != null && rem.seq > 0 ? `revision ${rem.seq + 1}` : undefined}>
      {!rem ? (
        readOnly ? (
          <div className="text-[11.5px] text-text3">A past snapshot is read-only — no fix can be drafted against it.</div>
        ) : !canApprove ? (
          <div className="text-[11.5px] text-text3">
            Drafting a fix is an approver action. The rules and assets above are the full evidence behind this finding.
          </div>
        ) : (
          <div className="space-y-1.5">
            <button onClick={draft} disabled={loading} className="btn-ghost !h-[26px] !px-2 text-[11px]">
              {loading ? <Spinner label="Drafting + re-simulating…" /> : <><Wrench size={12} /> Draft &amp; validate a fix</>}
            </button>
            {err && <InlineError resource="a drafted fix" error={err} onRetry={draft} />}
          </div>
        )
      ) : (
        <div className="space-y-2">
          <div className="flex flex-wrap items-center gap-2">
            <span className={cn("inline-flex h-[20px] items-center gap-1.5 border px-1.5 text-[10px] font-bold uppercase tracking-[0.08em]",
              rem.validation.resolves ? "border-ok-line bg-ok-bg text-ok" : "border-sev-high-line bg-sev-high-bg text-sev-high")}>
              {rem.validation.resolves ? <><Check size={11} /> re-simulated: resolves</> : <><X size={11} /> does not resolve</>}
            </span>
            {rem.validation.engine_corrected_ai && (
              <span className="text-[10px] text-text3">engine corrected the AI&apos;s first proposal, then proved this one</span>
            )}
          </div>
          <Prose className="!text-[12.5px]">{rem.fix_text}</Prose>
          <ProposedLine proposed={rem.change} kind="remediation" snapshot={snapshot} />
          <VerificationEvidence v={rem.validation} />
          <RemediationTrace trace={rem.trace} attempts={rem.attempts} />

          <Disconnects change={rem.change} snapshot={snapshot} />

          {!readOnly && canApprove && (
            <div className="space-y-2 border-t border-hair pt-2">
              <label className="block">
                <span className="mb-1 flex items-center gap-1.5 text-[9.5px] font-bold uppercase tracking-[0.14em] text-text3">
                  <MessageSquarePlus size={11} /> comment to refine this fix
                </span>
                <textarea value={comment} onChange={(e) => setComment(e.target.value)} rows={2}
                  placeholder="e.g. don't remove the rule — scope the source to the jump host instead"
                  className="field !h-auto !py-1.5 !text-[11.5px]" />
              </label>
              <div className="flex flex-wrap items-center gap-2">
                <button onClick={refine} disabled={refining || !comment.trim()} className="btn-ghost !h-[26px] !px-2 text-[11px]">
                  {refining ? <Spinner label="Re-iterating…" /> : <><RotateCw size={12} /> Re-iterate</>}
                </button>
                <button onClick={submit} disabled={sending || !rem.validation.resolves}
                  title={rem.validation.resolves ? "" : "Refine until the fix re-simulates as resolving"}
                  className="btn-primary ml-auto !h-[26px] !px-2 text-[11px]">
                  {sending ? <Spinner label="Submitting…" /> : <><Send size={12} /> Submit to the gate</>}
                </button>
              </div>
              {!rem.validation.resolves && (
                <div className="text-[10.5px] text-text3">The gate will not take a fix that does not resolve its finding.</div>
              )}
              {actErr && <InlineError resource={actErr.what} error={actErr.error} />}
            </div>
          )}
        </div>
      )}
    </Step>
  );
}

// ── 4 ── the gate's ruling, decided here ────────────────────────────────────

function TheGate({ f, ruling, decisionsError, readOnly, canApprove, snapshot, queued, onGovernanceChanged }: {
  f: Finding; ruling?: Ruling; decisionsError?: ApiError; readOnly?: boolean; canApprove: boolean;
  snapshot?: string; queued?: QueueRow; onGovernanceChanged: () => void;
}) {
  const [busy, setBusy] = useState<"stage" | "reject" | null>(null);
  const [err, setErr] = useState<{ what: string; error: ApiError }>();

  const act = async (what: "stage" | "reject", fn: () => Promise<unknown>) => {
    setBusy(what); setErr(undefined);
    try { await fn(); onGovernanceChanged(); }
    catch (e) { setErr({ what: what === "stage" ? "the implementation request" : "the rejection", error: asApiError(e) }); }
    finally { setBusy(null); }
  };

  if (decisionsError) {
    return (
      <Step n={4} title="The gate's ruling">
        <InlineError resource="the change decision log" error={decisionsError} />
        <p className="mt-1.5 text-[11px] text-text3">
          Whether this finding has already been through the gate is unknown — not &ldquo;it has not&rdquo;.
        </p>
      </Step>
    );
  }
  if (!ruling) {
    return (
      <Step n={4} title="The gate's ruling" note="not yet submitted">
        <p className="text-[11.5px] leading-relaxed text-text2">
          The gate rules on the computed delta, not on the request&apos;s wording. Submit the fix in step 3 and the
          ruling lands here.
        </p>
      </Step>
    );
  }

  const rejected = ruling.request_status === "rejected";
  const approve = ruling.decision === "auto_approve";

  return (
    <Step n={4} title="The gate's ruling"
      note={ruling.decided_at ? new Date(ruling.decided_at).toLocaleString() : undefined}
      tone={rejected ? "border-sev-critical-line" : undefined}>
      <div className="space-y-2.5">
        <VerdictHeader compact decision={ruling.decision} forced={ruling.forced_escalate}
          confidence={ruling.confidence} decidedBy={ruling.decided_by} />
        <GateRuling kind={ruling.kind} criteria={ruling.criteria} deltaSummary={ruling.delta_summary}
          triggeringReason={ruling.triggering_reason} justification={ruling.justification} />

        {err && <InlineError resource={err.what} error={err.error} />}

        <div className="flex flex-wrap items-center gap-2 border-t border-hair pt-2">
          {rejected ? (
            <span className="text-[11px] text-sev-critical">
              Rejected{ruling.rejected_by ? ` by ${ruling.rejected_by}` : ""}
              {ruling.reject_reason ? ` — “${ruling.reject_reason}”` : ""}. It cannot be sent to implementation.
            </span>
          ) : queued ? (
            <span className="inline-flex items-center gap-1.5 text-[11px] text-text3">
              <Check size={12} className="text-ok" /> Sent to implementation — step 5.
            </span>
          ) : readOnly ? (
            <span className="text-[11px] text-text3">A past snapshot is read-only.</span>
          ) : !canApprove ? (
            // The viewer sees the ruling and not a control they cannot use.
            <span className="text-[11px] text-text3">
              {approve ? "Auto-approved." : "Escalated."} Sending a change to implementation is an approver action.
            </span>
          ) : (
            <>
              <button onClick={() => act("stage", () => api.sendToStaging({ request_id: ruling.request_id, manual_approve: !approve }))}
                disabled={busy !== null} className="btn-primary !h-[26px] !px-2 text-[11px]">
                {busy === "stage" ? <Spinner label="Sending…" />
                  : approve ? <><Send size={12} /> Send to implementation</>
                  : <><ShieldCheck size={12} /> Approve &amp; send to implementation</>}
              </button>
              <button onClick={() => act("reject", () => api.rejectChange({ request_id: ruling.request_id }))}
                disabled={busy !== null} className="btn-danger ml-auto !h-[26px] !px-2 text-[11px]">
                {busy === "reject" ? <Spinner label="Rejecting…" /> : <><X size={12} /> Reject</>}
              </button>
            </>
          )}
        </div>
      </div>
    </Step>
  );
}

// ── 5 ── implementation, and the way back out ───────────────────────────────

function TheImplementation({ ruling, queued, stagingError, canApprove, snapshot, readOnly, onGovernanceChanged }: {
  ruling?: Ruling; queued?: QueueRow; stagingError?: ApiError; canApprove: boolean;
  snapshot?: string; readOnly?: boolean; onGovernanceChanged: () => void;
}) {
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<ApiError>();
  const [plan, setPlan] = useState<PushPlan>();

  const apply = async () => {
    if (!queued) return;
    setBusy(true); setErr(undefined);
    try { setPlan((await api.stagingPush(queued.staged_id)) as PushPlan); onGovernanceChanged(); }
    catch (e) { setErr(asApiError(e)); }
    finally { setBusy(false); }
  };

  if (stagingError) {
    return (
      <Step n={5} title="Implementation">
        <InlineError resource="the implementation queue" error={stagingError} />
        <p className="mt-1.5 text-[11px] text-text3">Whether this change is queued or applied is unknown.</p>
      </Step>
    );
  }
  if (!ruling || !queued) {
    return (
      <Step n={5} title="Implementation" note="nothing queued">
        <p className="text-[11.5px] text-text2">
          An approved change lands in the Implementation Queue, where applying it is a stepped dry run against the
          current snapshot. Nothing is written to AlgoSec, Guardicore or Wiz — this build has no connector.
        </p>
      </Step>
    );
  }

  const applied = queued.status === "pushed" || queued.status === "rolled_back";
  return (
    <Step n={5} title="Implementation"
      note={<StatusChip size="sm" status={queued.status} />}>
      {applied ? (
        <AppliedChangeCard row={queued} canApprove={canApprove && !readOnly} snapshot={snapshot} onChanged={onGovernanceChanged} />
      ) : (
        <div className="space-y-2">
          <ProposedLine proposed={queued.payload} kind={queued.kind} snapshot={snapshot} />
          <div className="text-[10.5px] text-text3">target {toolLabel(queued.target_tool)}</div>
          {plan?.push_steps?.length ? (
            <ol className="space-y-1 border border-border bg-sunk p-2">
              {plan.push_steps.map((s) => (
                <li key={s.key} className="flex items-start gap-1.5 text-[11px]">
                  {s.status === "ok" ? <Check size={12} className="mt-0.5 shrink-0 text-ok" />
                    : s.status === "warn" ? <AlertTriangle size={12} className="mt-0.5 shrink-0 text-sev-high" />
                    : <X size={12} className="mt-0.5 shrink-0 text-sev-critical" />}
                  <span><b>{s.label}</b> <span className="text-text3">{s.detail}</span></span>
                </li>
              ))}
            </ol>
          ) : null}
          {err && <InlineError resource="the implementation run" error={err} onRetry={apply} />}
          {readOnly ? null : !canApprove ? (
            <span className="text-[11px] text-text3">Applying a queued change is an approver action.</span>
          ) : (
            <button onClick={apply} disabled={busy} className="btn-primary !h-[26px] !px-2 text-[11px]">
              {busy ? <Spinner label="Running…" /> : <><Rocket size={12} /> Implement on {toolLabel(queued.target_tool)} (simulated)</>}
            </button>
          )}
        </div>
      )}
    </Step>
  );
}
