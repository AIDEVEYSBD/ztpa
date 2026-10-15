"use client";

/**
 * THE CHANGE GATE — the change board's view of the same governance the Risk
 * To-Do side panel now carries inline.
 *
 * The gate stopped being a place a reviewer must navigate to in order to act on
 * a finding: that story is told end to end in one panel on Risk To-Do. This
 * screen is what remains once that is true — the board view. Every proposed
 * change, however it arrived, with the ruling behind it; plus the one thing the
 * side panel cannot do, which is simulate a change nobody has proposed yet.
 *
 * IT RENDERS THE SAME COMPONENTS AS THE PANEL (components/risk/gate.tsx). Two
 * hand-built designs of one ruling drift, and then the screen a reviewer
 * approves on and the screen an auditor reads are not describing the same fact.
 */

import { useCallback, useEffect, useMemo, useState } from "react";
import { useSession } from "next-auth/react";
import { motion } from "framer-motion";
import {
  ChevronDown, ChevronRight, FlaskConical, Globe, History, Inbox, Play, Rocket, ShieldCheck, Wrench, X,
} from "lucide-react";
import { api, asApiError, type ApiError } from "@/lib/api";
import type { ChangeResult } from "@/lib/types";
import { canApprove as canApproveChanges, type AppRole } from "@/lib/roles";
import type { ScreenId } from "./Sidebar";
import { cn, Skeleton, SkeletonText, Spinner, Button } from "./ui";
import { ErrorState, InlineError } from "./ui/Feedback";
import { Readout, type FigureSpec } from "./risk/bits";
import { GateRuling, ProposedLine, VerdictHeader } from "./risk/gate";
import { StatusChip } from "./risk/implementation";

const COMMON_SERVICES = ["tcp/443", "tcp/22", "tcp/3389", "tcp/445", "tcp/1433", "tcp/3306", "udp/53", "any"];
const CIDR_RE = /^(\d{1,3}\.){3}\d{1,3}(\/\d{1,2})?$/;

/** Classify a free-text endpoint against known assets so we guide input without
 *  blocking the legitimate "what if the internet reaches X" case. */
function endpointKind(v: string, assetSet: Set<string>): { label: string; tone: "ok" | "neutral" | "warn" } | null {
  const t = v.trim();
  if (!t) return null;
  if (assetSet.has(t)) return { label: "known asset", tone: "ok" };
  if (t === "0.0.0.0/0") return { label: "the internet", tone: "neutral" };
  if (CIDR_RE.test(t)) return { label: "CIDR range (external)", tone: "neutral" };
  return { label: "not a known asset or CIDR", tone: "warn" };
}
const TONE: Record<string, string> = { ok: "text-ok", neutral: "text-text3", warn: "text-sev-high" };

export function ChangeGate({ onNavigate }: { onNavigate?: (s: ScreenId) => void }) {
  const { data: session } = useSession();
  const role = ((session?.user as any)?.role ?? null) as AppRole | null;
  const canApprove = canApproveChanges(role);

  const [requests, setRequests] = useState<any[]>([]);
  const [reqLoading, setReqLoading] = useState(true);
  const [sel, setSel] = useState<string>();                 // a preset id, or "custom"
  // `action` is part of the request, not an assumption. A firewall change is
  // source / destination / service / ACTION, and a form that omits the last one
  // silently only ever composes an allow -- while the presets above it say
  // "Allow ...", which is what made this panel read as nonsense to a network
  // engineer. The backend has always taken it (`simulate_change` branches on
  // `is_deny`); only the form was missing.
  const [custom, setCustom] = useState<{
    source: string; destination: string; service: string;
    action: "allow" | "deny"; justification: string;
  }>({ source: "10.20.5.0/24", destination: "app-server-07", service: "tcp/443", action: "allow", justification: "" });
  const [result, setResult] = useState<ChangeResult & { request_id?: string }>();
  const [loading, setLoading] = useState(false);
  const [assets, setAssets] = useState<string[]>([]);
  const [decisions, setDecisions] = useState<any[]>();
  const [staging, setStaging] = useState<string>();         // request_id being sent
  const [rejecting, setRejecting] = useState<string>();     // request_id being rejected
  const [decisionsErr, setDecisionsErr] = useState<ApiError>();
  const [reqErr, setReqErr] = useState<ApiError>();
  const [assetsErr, setAssetsErr] = useState<ApiError>();
  // The failure of the last thing the user PRESSED, kept separate from the
  // background loads so a dead Simulate button can never look like a no-op.
  const [actionErr, setActionErr] = useState<{ what: string; error: ApiError; retry: () => void }>();

  const assetSet = useMemo(() => new Set(assets), [assets]);

  const loadDecisions = useCallback(() =>
    api.changeDecisions()
      .then((r) => { setDecisions(r.decisions); setDecisionsErr(undefined); })
      // Never fall back to [] here: an empty decision log means "this estate has
      // no governance history", which is a claim we cannot make from a failure.
      .catch((e) => { setDecisions(undefined); setDecisionsErr(asApiError(e)); }), []);

  const send = async (requestId: string, escalated: boolean) => {
    setStaging(requestId); setActionErr(undefined);
    try {
      await api.sendToStaging({ request_id: requestId, manual_approve: escalated });
      await loadDecisions();
      onNavigate?.("staging");
    } catch (e) {
      // A 403 here is the governance boundary doing its job; show it as that.
      setActionErr({ what: "the implementation request", error: asApiError(e), retry: () => send(requestId, escalated) });
    } finally { setStaging(undefined); }
  };

  const reject = async (requestId: string) => {
    setRejecting(requestId); setActionErr(undefined);
    try { await api.rejectChange({ request_id: requestId }); await loadDecisions(); }
    catch (e) { setActionErr({ what: "the rejection", error: asApiError(e), retry: () => reject(requestId) }); }
    finally { setRejecting(undefined); }
  };

  const loadRequests = useCallback(() => {
    setReqLoading(true); setReqErr(undefined);
    api.changeRequests()
      .then((r) => { setRequests(r.requests); setSel(r.requests[0]?.id); })
      .catch((e) => setReqErr(asApiError(e)))
      .finally(() => setReqLoading(false));
  }, []);

  const loadAssets = useCallback(() => {
    setAssetsErr(undefined);
    api.assets().then((a) => {
      const list = a.assets ?? [];
      setAssets(list.map((x: any) => x.asset_key));
      // Prefill the custom destination with a real asset from THIS snapshot
      // (prefer a regulated one) so the form is valid across scenarios.
      const SENS = ["pci", "customer-data", "crown-jewel", "phi"];
      const pick = (list.find((x: any) => (x.tags ?? []).some((t: string) => SENS.includes(t))) ?? list[0])?.asset_key;
      if (pick) setCustom((c) => (list.some((x: any) => x.asset_key === c.destination) ? c : { ...c, destination: pick }));
    // Without assets the endpoint validator downgrades every known asset to
    // "not a known asset or CIDR", so the user must be told why.
    }).catch((e) => setAssetsErr(asApiError(e)));
  }, []);

  useEffect(() => { loadRequests(); }, [loadRequests]);
  useEffect(() => { loadAssets(); }, [loadAssets]);
  useEffect(() => { loadDecisions(); }, [loadDecisions]);

  const evaluate = async () => {
    setLoading(true); setResult(undefined); setActionErr(undefined);
    try {
      const body = sel === "custom" ? custom : { request_id: sel };
      setResult(await api.classify(body));
      loadDecisions();   // refresh the audit trail
    } catch (e) {
      setActionErr({ what: "the simulated decision", error: asApiError(e), retry: evaluate });
    } finally { setLoading(false); }
  };

  const d = result?.decision;
  const isRejected = (x: any) => x.request_status === "rejected";
  const pending = (decisions ?? []).filter((x) => !x.staged_id && !isRejected(x));
  const done = (decisions ?? []).filter((x) => !!x.staged_id || isRejected(x));
  const known = decisions !== undefined;
  const unknown = "The change decision log did not load, so this is unknown — not zero.";
  const figures: FigureSpec[] = [
    { key: "open", label: "awaiting action", value: known ? pending.length : null, unknown },
    { key: "auto", label: "auto-approved", value: known ? (decisions ?? []).filter((x) => x.decision === "auto_approve").length : null, unknown, tone: "text-ok" },
    { key: "esc", label: "escalated", value: known ? (decisions ?? []).filter((x) => x.decision !== "auto_approve").length : null, unknown, tone: "text-sev-critical" },
    { key: "rejected", label: "rejected", value: known ? (decisions ?? []).filter(isRejected).length : null, unknown },
    { key: "sent", label: "sent to implementation", value: known ? (decisions ?? []).filter((x) => !!x.staged_id).length : null, unknown },
  ];

  return (
    <div className="space-y-2.5">
      <Readout title="Change governance" figures={figures}
        note="Every ruling is computed from the simulated delta, not from the request's wording." />

      <div className="grid gap-5 lg:grid-cols-[360px_1fr]">
        <div className="flex flex-col gap-5">
          <section className="overflow-hidden rounded-lg border border-line bg-surface elev-1">
            <div data-hue="amber" data-hue-bar="" className="border-b border-line bg-raise/55 px-4 py-2.5">
              <span className="text-[12.5px] font-semibold tracking-[-0.005em]">Simulate a change</span>
            </div>
            <div className="flex flex-col gap-2 p-4">
              {reqErr && <ErrorState resource="the pending change requests" error={reqErr} onRetry={loadRequests} />}
              {reqLoading && requests.length === 0
                ? Array.from({ length: 2 }).map((_, i) => (
                    <div key={i} className="space-y-2 rounded-md border border-line bg-canvas p-3"><Skeleton className="h-3.5 w-2/3" /><Skeleton className="h-3 w-full" /></div>
                  ))
                : requests.map((r) => (
                    // div[role=button], not <button>: `ProposedLine` renders an
                    // expandable rule token, and a button inside a button is
                    // invalid HTML that React reports as a hydration error.
                    <div key={r.id} role="button" tabIndex={0}
                      onClick={() => { setSel(r.id); setResult(undefined); }}
                      onKeyDown={(e) => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); setSel(r.id); setResult(undefined); } }}
                      className={cn("focusable w-full cursor-pointer rounded-md border bg-canvas p-3 text-left transition-colors duration-100",
                        sel === r.id ? "border-fg" : "border-line hover:border-line-strong")}>
                      <div className="text-[12px] font-medium text-fg">{r.title}</div>
                      <ProposedLine proposed={r.proposed} kind={r.kind} className="mt-1" />
                      {r.justification && <div className="mt-1 text-[10.5px] text-faint italic">“{r.justification}”</div>}
                    </div>
                  ))}

              <button onClick={() => { setSel("custom"); setResult(undefined); }}
                className={cn("focusable w-full cursor-pointer rounded-md border bg-canvas p-3 text-left transition-colors duration-100",
                  sel === "custom" ? "border-fg" : "border-line hover:border-line-strong")}>
                <div className="flex items-center gap-2 text-[12px] font-medium text-fg"><FlaskConical size={13} /> Compose one</div>
              </button>

              {sel === "custom" && (
                <div className="space-y-2 rounded-md border border-line bg-canvas p-3">
                  <datalist id="zt-assets">{assets.map((a) => <option key={a} value={a} />)}<option value="0.0.0.0/0" /></datalist>
                  <datalist id="zt-services">{COMMON_SERVICES.map((s) => <option key={s} value={s} />)}</datalist>
                  {([["source", "Source", "asset, or a CIDR like 0.0.0.0/0"], ["destination", "Destination", "pick a known asset"]] as const).map(([k, lab, ph]) => {
                    const kind = endpointKind((custom as any)[k], assetSet);
                    return (
                      <label key={k} className="block">
                        <span className="mb-1 block text-[12.5px] font-medium text-mist">{lab}</span>
                        <input list="zt-assets" value={(custom as any)[k]} placeholder={ph}
                          onChange={(e) => setCustom({ ...custom, [k]: e.target.value })} className="field !h-8 font-mono !text-[12.5px]" />
                        {kind && <span className={cn("mt-1 block text-[11.5px]", TONE[kind.tone])}>{kind.label}</span>}
                      </label>
                    );
                  })}
                  <label className="block">
                    <span className="mb-1 block text-[12.5px] font-medium text-mist">Service</span>
                    <input list="zt-services" value={custom.service} placeholder="tcp/443"
                      onChange={(e) => setCustom({ ...custom, service: e.target.value })} className="field !h-8 font-mono !text-[12.5px]" />
                  </label>
                  <div>
                    <span className="mb-1 block text-[12.5px] font-medium text-mist">Action</span>
                    <div className="inline-flex w-full items-center gap-px rounded-md border border-line bg-raise p-px">
                      {(["allow", "deny"] as const).map((a) => (
                        <button key={a} type="button"
                          onClick={() => setCustom({ ...custom, action: a })}
                          aria-pressed={custom.action === a}
                          className={cn(
                            "focusable flex-1 cursor-pointer rounded-sm px-2.5 py-1 text-[12.5px] transition-colors duration-100",
                            custom.action === a
                              ? a === "allow" ? "bg-surface font-medium text-ok shadow-[var(--shadow-1)]" : "bg-surface font-medium text-err shadow-[var(--shadow-1)]"
                              : "text-faint hover:text-dim",
                          )}>
                          {a}
                        </button>
                      ))}
                    </div>
                    {custom.action === "deny" && (
                      // Stated BEFORE simulating, not only in the result. The
                      // reachability graph is built from allow grants, so a deny
                      // subtracts nothing from it -- the delta shows what the
                      // rule does not OPEN, never what it blocks. A reader who
                      // learns that after pressing the button has already formed
                      // the wrong expectation.
                      <span className="mt-1 block text-[11.5px] leading-[1.5] text-warn">
                        A deny tightens policy. The graph holds allow grants only, so the delta
                        shows what this does not open, not what it blocks.
                      </span>
                    )}
                  </div>
                  <label className="block">
                    <span className="mb-1 block text-[12.5px] font-medium text-mist">Justification</span>
                    <input value={custom.justification} onChange={(e) => setCustom({ ...custom, justification: e.target.value })}
                      placeholder="e.g. urgent, pre-approved" className="field !h-[28px] !text-[12px]" />
                    <span className="mt-1 block text-[11.5px] text-faint">Free text. The gate rules on the computed delta, not on this.</span>
                  </label>
                  {assetsErr && <InlineError resource={"this snapshot's assets"} error={assetsErr} onRetry={loadAssets} />}
                </div>
              )}

              <Button variant="solid" tone="ink" onClick={evaluate} disabled={loading || !sel} className="w-full">
                {loading ? <Spinner label="Simulating + judging…" /> : <><Play size={13} /> Simulate &amp; evaluate</>}
              </Button>
            </div>
          </section>
        </div>

        <div className="flex flex-col gap-5">
          {actionErr && <ErrorState resource={actionErr.what} error={actionErr.error} onRetry={actionErr.retry} />}
          {loading ? (
            <div className="flex flex-col gap-5">
              <div className="flex items-center gap-3 rounded-lg border border-line bg-surface p-4 elev-1"><Skeleton className="h-7 w-7 shrink-0" /><div className="flex-1 space-y-2"><Skeleton className="h-4 w-40" /><Skeleton className="h-3 w-56" /></div></div>
              <div className="space-y-2 rounded-lg border border-line bg-surface p-4 elev-1"><Skeleton className="h-3.5 w-44" /><SkeletonText lines={4} /></div>
            </div>
          ) : !result ? (
            <DecisionBoard
              decisions={decisions} error={decisionsErr} onRetry={loadDecisions}
              onSend={send} sending={staging} onReject={reject} rejecting={rejecting}
              canApprove={canApprove} onNavigate={onNavigate}
            />
          ) : (
            <motion.div initial={{ opacity: 0, y: 6 }} animate={{ opacity: 1, y: 0 }} className="flex flex-col gap-5">
              <VerdictHeader decision={d!.decision} forced={d!.forced_escalate} confidence={d!.confidence} decidedBy={d!.decided_by} />
              {result.request?.id && (
                <div className="flex flex-wrap items-center gap-2 rounded-lg border border-line bg-surface p-3 text-[12.5px] elev-1">
                  <Rocket size={13} className="shrink-0 text-dim" />
                  <span className="text-dim">
                    {d!.decision === "auto_approve"
                      ? "Approved — send it to the Implementation Queue."
                      : "Escalated — an approver can override and send it."}
                  </span>
                  <Button
                    size="sm"
                    variant="solid"
                    tone="ink"
                    className="ml-auto"
                    onClick={() => send(result.request.id, d!.decision !== "auto_approve")}
                    disabled={(d!.decision !== "auto_approve" && !canApprove) || staging === result.request.id}
                    title={d!.decision === "auto_approve" || canApprove ? "" : "Only admin or analyst can approve an escalated change"}
                  >
                    {staging === result.request.id ? <Spinner label="Sending…" />
                      : d!.decision === "auto_approve" ? <><Rocket size={12} /> Send to implementation</>
                      : <><ShieldCheck size={12} /> Approve &amp; send</>}
                  </Button>
                </div>
              )}
              <div className="rounded-lg border border-line bg-surface p-4 elev-1">
                {/* A classify request is an add-allow, never a remediation, so the
                    add-allow criteria and the reachability delta are the right
                    vocabulary here. */}
                <GateRuling
                  criteria={d!.criteria}
                  deltaSummary={{ ...(result.delta ?? {}), investigation: d!.delta_summary?.investigation }}
                  triggeringReason={d!.triggering_reason}
                  rationale={d!.rationale}
                />
              </div>
            </motion.div>
          )}
        </div>
      </div>
    </div>
  );
}

/**
 * The change board: every ruling, split by whether it still needs someone.
 *   Awaiting action — evaluated, not yet sent to implementation and not rejected.
 *   Decided        — sent to implementation, or declined. The audit trail.
 */
function DecisionBoard({ decisions, error, onRetry, onSend, sending, onReject, rejecting, canApprove, onNavigate }: {
  decisions?: any[];
  error?: ApiError;
  onRetry?: () => void;
  onSend?: (requestId: string, escalated: boolean) => void;
  sending?: string;
  onReject?: (requestId: string) => void;
  rejecting?: string;
  canApprove?: boolean;
  onNavigate?: (s: ScreenId) => void;
}) {
  const [tab, setTab] = useState<"actions" | "log">("actions");
  const [open, setOpen] = useState<string>();

  const isRejected = (x: any) => x.request_status === "rejected";
  const pending = (decisions ?? []).filter((x) => !x.staged_id && !isRejected(x));
  const done = (decisions ?? []).filter((x) => !!x.staged_id || isRejected(x));
  const items = tab === "actions" ? pending : done;

  // Land on whichever tab has work.
  useEffect(() => {
    if (decisions && pending.length === 0 && done.length > 0) setTab("log");
  }, [decisions]);  // eslint-disable-line react-hooks/exhaustive-deps

  // While the log is in error the tab counters must not read 0 — that is the
  // "clean estate" lie in miniature.
  const TABS = [
    { id: "actions" as const, label: "Awaiting action", icon: Inbox, count: error ? "—" : pending.length },
    { id: "log" as const, label: "Decided", icon: History, count: error ? "—" : done.length },
  ];

  return (
    <div className="flex h-[calc(100vh-17rem)] min-h-[360px] flex-col overflow-hidden rounded-lg border border-line bg-surface elev-1">
      <div className="flex shrink-0 items-center gap-5 border-b border-line px-4">
        {TABS.map((t) => (
          <button key={t.id} onClick={() => { setTab(t.id); setOpen(undefined); }}
            className={cn("focusable relative -mb-px flex cursor-pointer items-center gap-1.5 pb-2.5 text-[13px] transition-colors duration-100",
              tab === t.id ? "font-medium text-fg" : "text-faint hover:text-dim")}>
            <t.icon size={12} /> {t.label}
            <span className={cn("tnum ml-0.5 font-mono text-[10.5px]", tab === t.id ? "text-dim" : "text-faint")}>{t.count}</span>
            {tab === t.id && <span aria-hidden className="absolute inset-x-0 -bottom-px h-0.5 rounded-[2px] bg-fg" />}
          </button>
        ))}
      </div>

      <div className="zt-scroll min-h-0 flex-1 space-y-2 overflow-y-auto p-4">
        {error ? (
          <ErrorState resource="the change decision log" error={error} onRetry={onRetry} />
        ) : decisions === undefined ? (
          Array.from({ length: 3 }).map((_, i) => (
            <div key={i} className="space-y-2 rounded-md border border-line bg-canvas p-3"><Skeleton className="h-4 w-2/3" /><Skeleton className="h-3 w-1/2" /></div>
          ))
        ) : items.length === 0 ? (
          <div className="grid h-full min-h-[200px] place-items-center p-6 text-center text-[12.5px] text-dim">
            {tab === "actions"
              ? (done.length ? "Nothing waiting — every evaluated change has been acted on." : "No change evaluated yet.")
              : "No change has been sent to implementation or rejected yet."}
          </div>
        ) : items.map((x) => (
          <DecisionCard key={x.decision_id} x={x} open={open === x.decision_id}
            onToggle={() => setOpen(open === x.decision_id ? undefined : x.decision_id)}
            onSend={onSend} sending={sending} onReject={onReject} rejecting={rejecting}
            canApprove={canApprove} onNavigate={onNavigate} />
        ))}
      </div>
    </div>
  );
}

/** One ruling: a clickable summary that expands into the full explanation. */
function DecisionCard({ x, open, onToggle, onSend, sending, onReject, rejecting, canApprove, onNavigate }: {
  x: any; open: boolean; onToggle: () => void;
  onSend?: (requestId: string, escalated: boolean) => void;
  sending?: string; onReject?: (requestId: string) => void; rejecting?: string;
  canApprove?: boolean; onNavigate?: (s: ScreenId) => void;
}) {
  const approve = x.decision === "auto_approve";
  const p = x.proposed ?? {};
  const isRemediation = x.kind === "remediation";
  const staged = !!x.staged_id;
  const rejected = x.request_status === "rejected";
  return (
    <div className={cn("border bg-surface2", approve ? "border-ok-line" : "border-sev-critical-line")}>
      {/* div[role=button]: the proposed line carries an expandable rule token,
          which is itself a button — nesting the two is invalid HTML. */}
      <div role="button" tabIndex={0} onClick={onToggle}
        onKeyDown={(e) => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); onToggle(); } }}
        className="block w-full cursor-pointer p-2.5 text-left hover:bg-surfaceHover">
        <div className="flex flex-wrap items-center gap-1.5">
          <span className={cn("inline-flex h-[19px] items-center border px-1.5 text-[9.5px] font-bold uppercase tracking-[0.08em]",
            approve ? "border-ok-line bg-ok-bg text-ok" : "border-sev-critical-line bg-sev-critical-bg text-sev-critical")}>
            {approve ? "auto-approve" : "escalate"}
          </span>
          {x.forced_escalate && <span className="chip text-[9.5px]">guardrail</span>}
          {isRemediation && (
            <span className="inline-flex h-[19px] items-center gap-1 border border-accent bg-accent-soft px-1.5 text-[9.5px] font-bold uppercase tracking-[0.08em] text-accent-fg">
              <Wrench size={10} /> remediation
            </span>
          )}
          {staged && <StatusChip size="sm" status={x.staged_status ?? "staged"} />}
          {rejected && (
            <span className="inline-flex h-[19px] items-center gap-1 border border-sev-critical-line bg-sev-critical-bg px-1.5 text-[9.5px] font-bold uppercase tracking-[0.08em] text-sev-critical">
              <X size={10} /> rejected
            </span>
          )}
          <span className="mono ml-auto flex items-center gap-1 text-[10px] text-text3">
            {x.decided_at ? new Date(x.decided_at).toLocaleString() : ""}
            {open ? <ChevronDown size={12} /> : <ChevronRight size={12} />}
          </span>
        </div>
        <div className="mt-1.5 flex flex-wrap items-center gap-1.5">
          {p.source === "0.0.0.0/0" && <Globe size={11} className="shrink-0 text-text3" />}
          <ProposedLine proposed={p} kind={x.kind} />
        </div>
        <div className="mt-1 text-[10px] text-text3">
          decided by <span className="mono">{x.decided_by}</span> · {(Number(x.confidence) * 100).toFixed(0)}% confidence
          · requested by <span className="mono">{x.requested_by ?? "?"}</span>
          {/* The mapping back to Risk To-Do: a remediation ruling names the
              finding it came from, so the board is never a list of orphans. */}
          {p.finding_id && <> · finding <span className="mono">{String(p.finding_id)}</span></>}
        </div>
        {p.finding_id && onNavigate && (
          <span role="button" tabIndex={0}
            onClick={(e) => { e.stopPropagation(); onNavigate("risks"); }}
            onKeyDown={(e) => { if (e.key === "Enter") { e.stopPropagation(); onNavigate("risks"); } }}
            className="mt-1 inline-block cursor-pointer text-[10.5px] font-bold underline hover:text-accent-fg">
            Open in Risk To-Do
          </span>
        )}
      </div>

      {open && (
        <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} className="border-t border-hair bg-sunk p-2.5">
          {rejected && (
            <div className="mb-2.5 border border-sev-critical-line bg-sev-critical-bg p-2 text-[11.5px]">
              <b>Rejected{x.rejected_by ? ` by ${x.rejected_by}` : ""}.</b>
              {x.reject_reason ? ` ${x.reject_reason}` : " This request was declined and cannot be implemented."}
            </div>
          )}
          <GateRuling kind={x.kind} criteria={x.criteria} deltaSummary={x.delta_summary}
            triggeringReason={x.triggering_reason} justification={x.justification}
            rationale={typeof x.delta_summary?.rationale === "string" ? x.delta_summary.rationale : undefined} />
          <div className="mono mt-2.5 flex flex-wrap gap-x-4 gap-y-1 border-t border-hair pt-2 text-[10px] text-text3">
            {x.origin && <span>origin {x.origin}</span>}
            <span className="break-all">{x.request_id}</span>
          </div>
        </motion.div>
      )}

      <div className="flex flex-wrap items-center gap-2 border-t border-hair px-2.5 py-1.5">
        {rejected ? (
          <span className="text-[10.5px] text-text3">
            Rejected{x.rejected_by ? ` by ${x.rejected_by}` : ""}{x.reject_reason ? ` — “${x.reject_reason}”` : ""}.
          </span>
        ) : staged ? (
          onNavigate && (
            <button onClick={() => onNavigate("staging")} className="text-[10.5px] font-bold underline">
              Open in the Implementation Queue
            </button>
          )
        ) : !canApprove ? (
          // A viewer sees the ruling and not a control the API would refuse.
          <span className="text-[10.5px] text-text3">
            {approve ? "Auto-approved." : "Escalated."} Acting on a change is an approver action.
          </span>
        ) : (
          <>
            <button onClick={() => onSend?.(x.request_id, !approve)} disabled={sending === x.request_id}
              className="btn-ghost !h-[24px] !px-2 text-[10.5px]">
              {sending === x.request_id ? <Spinner label="Sending…" />
                : approve ? <><Rocket size={11} /> Send to implementation</>
                : <><ShieldCheck size={11} /> Approve &amp; send</>}
            </button>
            <button onClick={() => onReject?.(x.request_id)} disabled={rejecting === x.request_id}
              className="btn-danger ml-auto !h-[24px] !px-2 text-[10.5px]">
              {rejecting === x.request_id ? <Spinner label="Rejecting…" /> : <><X size={11} /> Reject</>}
            </button>
          </>
        )}
      </div>
    </div>
  );
}
