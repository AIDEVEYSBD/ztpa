"use client";

import { useEffect, useMemo, useState } from "react";
import { useSession } from "next-auth/react";
import { motion } from "framer-motion";
import { Check, ShieldAlert, ShieldCheck, X, Play, FlaskConical, ArrowRight, Globe, Rocket, ChevronDown, ChevronRight, Inbox, History, Wrench } from "lucide-react";
import { api } from "@/lib/api";
import type { ChangeResult } from "@/lib/types";
import type { ScreenId } from "./Sidebar";
import { cn, Spinner, Skeleton, SkeletonText } from "./ui";
import { Prose } from "./Markdown";

const CRITERIA_LABELS: Record<string, string> = {
  standard_template: "Matches a standard-change template",
  no_new_sensitive_reachability: "Opens no new path to a sensitive asset",
  no_new_boundary_crossing: "Crosses no new trust boundary",
  no_over_permissive_pattern: "Introduces no over-permissive pattern",
};
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
  const role = (session?.user as any)?.role ?? "viewer";
  const canApprove = role === "admin" || role === "analyst";
  const [requests, setRequests] = useState<any[]>([]);
  const [reqLoading, setReqLoading] = useState(true);
  const [sel, setSel] = useState<string>();           // a preset id, or "custom"
  const [custom, setCustom] = useState({ source: "10.20.5.0/24", destination: "app-server-07", service: "tcp/443", justification: "" });
  const [result, setResult] = useState<ChangeResult & { request_id?: string }>();
  const [loading, setLoading] = useState(false);
  const [assets, setAssets] = useState<string[]>([]);
  const [decisions, setDecisions] = useState<any[]>();
  const [staging, setStaging] = useState<string>();   // request_id currently being staged
  const [rejecting, setRejecting] = useState<string>();   // request_id currently being rejected

  const assetSet = useMemo(() => new Set(assets), [assets]);
  const loadDecisions = () => api.changeDecisions().then((r) => setDecisions(r.decisions)).catch(() => setDecisions([]));

  const stage = async (requestId: string, escalated: boolean) => {
    setStaging(requestId);
    try {
      await api.sendToStaging({ request_id: requestId, manual_approve: escalated });
      await loadDecisions();
      onNavigate?.("staging");
    } catch { /* surfaced via reload */ } finally { setStaging(undefined); }
  };

  const reject = async (requestId: string) => {
    setRejecting(requestId);
    try {
      await api.rejectChange({ request_id: requestId });
      await loadDecisions();
    } catch { /* surfaced via reload */ } finally { setRejecting(undefined); }
  };

  useEffect(() => { api.changeRequests().then((r) => { setRequests(r.requests); setSel(r.requests[0]?.id); }).catch(() => {}).finally(() => setReqLoading(false)); }, []);
  useEffect(() => {
    api.assets().then((a) => {
      const list = a.assets ?? [];
      setAssets(list.map((x: any) => x.asset_key));
      // Prefill the custom destination with a real asset from THIS snapshot (prefer a
      // regulated one) so the form is valid across scenarios -- not a hardcoded name.
      const SENS = ["pci", "customer-data", "crown-jewel", "phi"];
      const pick = (list.find((x: any) => (x.tags ?? []).some((t: string) => SENS.includes(t))) ?? list[0])?.asset_key;
      if (pick) setCustom((c) => (list.some((x: any) => x.asset_key === c.destination) ? c : { ...c, destination: pick }));
    }).catch(() => {});
  }, []);
  useEffect(() => { loadDecisions(); }, []);

  const evaluate = async () => {
    setLoading(true); setResult(undefined);
    try {
      const body = sel === "custom" ? custom : { request_id: sel };
      setResult(await api.classify(body));
      loadDecisions();   // refresh the audit trail
    } catch { /* ignore */ } finally { setLoading(false); }
  };

  const d = result?.decision;
  const approve = d?.decision === "auto_approve";

  return (
    <div className="space-y-4">
      <p className="max-w-3xl text-[13px] text-text2">
        Every proposed change is simulated on a copy of the policy graph. The engine computes what would newly become
        reachable, then the gate decides from that delta, not from the request&apos;s wording. Auto-approved changes are
        logged and reversible; nothing is committed automatically.
      </p>

      <div className="grid gap-4 lg:grid-cols-[380px_1fr]">
        <div className="space-y-3">
          {reqLoading && requests.length === 0
            ? Array.from({ length: 3 }).map((_, i) => (
                <div key={i} className="panel space-y-2 p-3"><Skeleton className="h-3.5 w-2/3" /><Skeleton className="h-3 w-full" /></div>
              ))
            : requests.map((r) => (
            <button key={r.id} onClick={() => { setSel(r.id); setResult(undefined); }}
              className={cn("panel w-full p-3 text-left", sel === r.id ? "border-accent" : "hover:bg-surfaceHover")}>
              <div className="text-[13px] font-bold">{r.title}</div>
              <div className="mono mt-1 flex flex-wrap items-center gap-1.5 text-[12px] text-text2">
                <span className="break-all">{r.proposed.source}</span><ArrowRight size={11} className="shrink-0" /><span className="break-all">{r.proposed.destination}</span><span className="text-text3">· {r.proposed.service}</span>
              </div>
              {r.justification && <div className="mt-1 text-[11px] italic text-text3">“{r.justification}”</div>}
            </button>
          ))}

          <button onClick={() => { setSel("custom"); setResult(undefined); }}
            className={cn("panel w-full p-3 text-left", sel === "custom" ? "border-accent" : "hover:bg-surfaceHover")}>
            <div className="flex items-center gap-2 text-[13px] font-bold"><FlaskConical size={14} /> Simulate a custom change</div>
            <div className="text-[11px] text-text3">Try any rule and see the delta + decision.</div>
          </button>
          {sel === "custom" && (
            <div className="panel space-y-2.5 p-3">
              {/* shared autocomplete sources */}
              <datalist id="zt-assets">{assets.map((a) => <option key={a} value={a} />)}<option value="0.0.0.0/0" /></datalist>
              <datalist id="zt-services">{COMMON_SERVICES.map((s) => <option key={s} value={s} />)}</datalist>

              {([["source", "Source", "asset, or a CIDR like 0.0.0.0/0"], ["destination", "Destination", "pick a known asset"]] as const).map(([k, lab, ph]) => {
                const kind = endpointKind((custom as any)[k], assetSet);
                return (
                  <label key={k} className="block">
                    <span className="label mb-1 block">{lab}</span>
                    <input list="zt-assets" value={(custom as any)[k]} placeholder={ph}
                      onChange={(e) => setCustom({ ...custom, [k]: e.target.value })} className="field mono" />
                    {kind && <span className={cn("mt-1 block text-[11px]", TONE[kind.tone])}>{kind.label}</span>}
                  </label>
                );
              })}
              <label className="block">
                <span className="label mb-1 block">Service (proto/port)</span>
                <input list="zt-services" value={custom.service} placeholder="tcp/443"
                  onChange={(e) => setCustom({ ...custom, service: e.target.value })} className="field mono" />
              </label>
              <label className="block">
                <span className="label mb-1 block">Justification (untrusted)</span>
                <input value={custom.justification} onChange={(e) => setCustom({ ...custom, justification: e.target.value })}
                  placeholder="e.g. urgent, pre-approved" className="field" />
                <span className="mt-1 block text-[11px] text-text3">Free text. The gate ignores this and rules on the computed delta.</span>
              </label>
            </div>
          )}

          <button onClick={evaluate} disabled={loading || !sel} className="btn-primary w-full">
            {loading ? <Spinner label="Simulating + judging…" /> : <><Play size={15} /> Simulate &amp; evaluate</>}
          </button>
        </div>

        <div>
          {loading ? (
            <div className="space-y-4">
              <div className="panel flex items-center gap-3 p-4"><Skeleton className="h-7 w-7 shrink-0" /><div className="flex-1 space-y-2"><Skeleton className="h-4 w-40" /><Skeleton className="h-3 w-56" /></div></div>
              <div className="panel space-y-2 p-4"><Skeleton className="h-3.5 w-44" /><SkeletonText lines={4} /></div>
              <div className="panel space-y-2 p-4"><Skeleton className="h-3.5 w-36" /><SkeletonText lines={3} /></div>
            </div>
          ) : !result ? (
            <DecisionLog decisions={decisions} onStage={stage} staging={staging} onReject={reject} rejecting={rejecting} canApprove={canApprove} onNavigate={onNavigate} />
          ) : (
            <motion.div initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} className="space-y-4">
              <div className={cn("panel flex items-center gap-3 p-4", approve ? "border-ok-line" : "border-sev-critical-line")}>
                {approve ? <ShieldCheck className="text-ok" size={28} /> : <ShieldAlert className="text-sev-critical" size={28} />}
                <div className="flex-1">
                  <div className={cn("text-[18px] font-bold", approve ? "text-ok" : "text-sev-critical")}>
                    {approve ? "AUTO-APPROVE" : "ESCALATE"}
                  </div>
                  <div className="text-[12px] text-text2">
                    decided by {d!.decided_by} · confidence {(d!.confidence * 100).toFixed(0)}%
                    {d!.forced_escalate && " · guardrail-forced"}
                  </div>
                </div>
              </div>

              {d!.triggering_reason && (
                <div className="panel border-sev-high-line bg-sev-high-bg p-3 text-[13px]"><b>Trigger.</b> {d!.triggering_reason}</div>
              )}

              {result.request?.id && (
                <div className="panel flex flex-wrap items-center gap-2 p-3 text-[13px]">
                  <Rocket size={15} className="text-text2" />
                  <span className="text-text2">
                    {approve ? "Approved — stage this change for the source system." : "Escalated — an approver can override and stage it."}
                  </span>
                  {approve ? (
                    <button onClick={() => stage(result.request.id, false)} disabled={staging === result.request.id} className="btn-primary ml-auto !py-1.5 text-xs">
                      {staging === result.request.id ? <Spinner label="Staging…" /> : <><Rocket size={13} /> Send to staging</>}
                    </button>
                  ) : (
                    <button onClick={() => stage(result.request.id, true)} disabled={!canApprove || staging === result.request.id}
                      title={canApprove ? "" : "Only admin or analyst can approve an escalated change"}
                      className="btn-primary ml-auto !py-1.5 text-xs">
                      {staging === result.request.id ? <Spinner label="Staging…" /> : <><ShieldCheck size={13} /> Approve &amp; stage</>}
                    </button>
                  )}
                </div>
              )}

              <div className="panel p-4">
                <div className="eyebrow mb-2.5">Auto-approve criteria</div>
                <ul className="space-y-1.5">
                  {Object.entries(CRITERIA_LABELS).map(([k, label]) => {
                    const pass = d!.criteria[k];
                    return (
                      <li key={k} className="flex items-center gap-2 text-[13px]">
                        {pass ? <Check size={15} className="text-ok" /> : <X size={15} className="text-sev-critical" />}
                        <span className={cn(!pass && "text-text2")}>{label}</span>
                      </li>
                    );
                  })}
                </ul>
              </div>

              <div className="panel p-4">
                <div className="eyebrow mb-2.5">Computed delta</div>
                <DeltaPathRow label="New internet to sensitive paths" paths={(result.delta.new_paths ?? []).map((p: any) => p.display_path ?? (Array.isArray(p) ? p : [String(p)]))} />
                <DeltaRow label="Newly exposed assets" items={result.delta.new_exposed_assets ?? []} />
                <DeltaRow label="Boundaries crossed" items={result.delta.boundaries_crossed ?? []} />
                <DeltaRow label="Over-permissive patterns" items={result.delta.new_over_permissive ?? []} />
              </div>

              {d!.rationale && <div className="panel p-4"><div className="eyebrow mb-2">Rationale</div><Prose>{d!.rationale}</Prose></div>}
            </motion.div>
          )}
        </div>
      </div>
    </div>
  );
}

function DeltaRow({ label, items }: { label: string; items: string[] }) {
  return (
    <div className="flex flex-col gap-1 border-b border-hair py-1.5 text-[13px] last:border-0 sm:flex-row sm:gap-2">
      <span className="shrink-0 text-text2 sm:w-56">{label}</span>
      <span className="min-w-0 flex-1">
        {items.length
          ? items.map((it, i) => <span key={i} className="mono mb-1 mr-1 inline-block break-all bg-surfaceHover px-1.5 py-0.5 text-[11px]">{it}</span>)
          : <span className="text-ok">none</span>}
      </span>
    </div>
  );
}

/** Delta row whose items are reachability paths, rendered as chips + arrow icons. */
function DeltaPathRow({ label, paths }: { label: string; paths: string[][] }) {
  return (
    <div className="flex flex-col gap-1 border-b border-hair py-1.5 text-[13px] last:border-0 sm:flex-row sm:gap-2">
      <span className="shrink-0 text-text2 sm:w-56">{label}</span>
      <span className="min-w-0 flex-1 space-y-1">
        {paths.length
          ? paths.map((nodes, i) => (
              <span key={i} className="flex flex-wrap items-center gap-1.5">
                {nodes.map((n, j) => (
                  <span key={j} className="inline-flex items-center gap-1.5">
                    <span className="mono break-all bg-surfaceHover px-1.5 py-0.5 text-[11px]">{n}</span>
                    {j < nodes.length - 1 && <ArrowRight size={11} className="shrink-0 text-text3" />}
                  </span>
                ))}
              </span>
            ))
          : <span className="text-ok">none</span>}
      </span>
    </div>
  );
}

/** The change audit trail (change_requests + change_decisions), shown in the idle
 *  panel. Split into two tabs:
 *    - "Actions"      — evaluated changes NOT yet acted upon (no staged record).
 *    - "Decision log" — changes already staged (i.e. done) — the audit trail.
 *  The panel is a fixed height with its own scroll, and each row expands into a
 *  detailed card explaining the criteria, computed delta and rationale. */
function DecisionLog({ decisions, onStage, staging, onReject, rejecting, canApprove, onNavigate }: {
  decisions?: any[];
  onStage?: (requestId: string, escalated: boolean) => void;
  staging?: string;
  onReject?: (requestId: string) => void;
  rejecting?: string;
  canApprove?: boolean;
  onNavigate?: (s: ScreenId) => void;
}) {
  const [tab, setTab] = useState<"actions" | "log">("actions");
  const [open, setOpen] = useState<string>();   // expanded decision_id

  // "Actions" = still open (not staged, not rejected); "Decision log" = resolved
  // (staged → applied, or rejected → declined).
  const isRejected = (x: any) => x.request_status === "rejected";
  const pending = (decisions ?? []).filter((x) => !x.staged_id && !isRejected(x));
  const done = (decisions ?? []).filter((x) => !!x.staged_id || isRejected(x));
  const items = tab === "actions" ? pending : done;

  // Land on whichever tab has work: if nothing is pending, open the log instead.
  useEffect(() => {
    if (decisions && pending.length === 0 && done.length > 0) setTab("log");
  }, [decisions]);  // eslint-disable-line react-hooks/exhaustive-deps

  const TABS = [
    { id: "actions" as const, label: "Actions", icon: Inbox, count: pending.length,
      hint: "Evaluated changes not yet acted upon. Send approved ones to staging; an approver can clear escalations." },
    { id: "log" as const, label: "Decision log", icon: History, count: done.length,
      hint: "Changes already staged — the audit trail a change board or auditor reviews." },
  ];
  const active = TABS.find((t) => t.id === tab)!;

  return (
    <div className="panel flex h-[calc(100vh-13rem)] min-h-[360px] flex-col overflow-hidden">
      <div className="flex shrink-0 border-b border-hair">
        {TABS.map((t) => (
          <button key={t.id} onClick={() => { setTab(t.id); setOpen(undefined); }}
            className={cn("flex items-center gap-1.5 px-3.5 py-2.5 text-[13px] font-bold",
              tab === t.id ? "border-b-2 border-accent text-text" : "text-text3 hover:text-text2")}>
            <t.icon size={14} /> {t.label}
            <span className={cn("ml-0.5 px-1.5 py-0.5 text-[10px] font-bold", tab === t.id ? "border border-accent text-accent" : "bg-surfaceHover text-text3")}>
              {t.count}
            </span>
          </button>
        ))}
      </div>
      <p className="shrink-0 px-3.5 pt-2.5 text-[11px] text-text3">{active.hint}</p>

      <div className="min-h-0 flex-1 space-y-2.5 overflow-y-auto p-3.5">
        {decisions === undefined ? (
          Array.from({ length: 3 }).map((_, i) => (
            <div key={i} className="panel space-y-2 p-3"><Skeleton className="h-4 w-2/3" /><Skeleton className="h-3 w-1/2" /></div>
          ))
        ) : items.length === 0 ? (
          <div className="grid h-full min-h-[200px] place-items-center p-6 text-center text-[13px] text-text3">
            {tab === "actions"
              ? (done.length ? "Nothing waiting — every evaluated change has been staged." : "No changes evaluated yet. Pick or compose a change, then simulate it.")
              : "No staged changes yet. Approve an action to send it to staging."}
          </div>
        ) : items.map((x) => (
          <DecisionCard key={x.decision_id} x={x} open={open === x.decision_id}
            onToggle={() => setOpen(open === x.decision_id ? undefined : x.decision_id)}
            onStage={onStage} staging={staging} onReject={onReject} rejecting={rejecting}
            canApprove={canApprove} onNavigate={onNavigate} />
        ))}
      </div>
    </div>
  );
}

/** One row in the Actions / Decision-log list: a clickable summary that expands
 *  into the full DecisionDetail, plus the stage/approve action footer. */
function DecisionCard({ x, open, onToggle, onStage, staging, onReject, rejecting, canApprove, onNavigate }: {
  x: any; open: boolean; onToggle: () => void;
  onStage?: (requestId: string, escalated: boolean) => void;
  staging?: string; onReject?: (requestId: string) => void; rejecting?: string;
  canApprove?: boolean; onNavigate?: (s: ScreenId) => void;
}) {
  const approve = x.decision === "auto_approve";
  const p = x.proposed ?? {};
  const isRemediation = x.kind === "remediation";
  const staged = !!x.staged_id;
  const rejected = x.request_status === "rejected";
  return (
    <div className={cn("panel overflow-hidden", approve ? "border-ok-line" : "border-sev-critical-line")}>
      <button onClick={onToggle} className="block w-full p-3 text-left hover:bg-surfaceHover">
        <div className="flex flex-wrap items-center gap-2">
          {approve ? <ShieldCheck size={15} className="shrink-0 text-ok" /> : <ShieldAlert size={15} className="shrink-0 text-sev-critical" />}
          <span className={cn("text-[12px] font-bold", approve ? "text-ok" : "text-sev-critical")}>{approve ? "AUTO-APPROVE" : "ESCALATE"}</span>
          {x.forced_escalate && <span className="chip text-[10px]">guardrail</span>}
          {isRemediation && <span className="chip border-accent text-[10px]"><Wrench size={11} /> remediation</span>}
          {staged && (
            <span className={cn("chip text-[10px]", x.staged_status === "pushed" ? "border-ok-line bg-ok-bg text-ok"
              : x.staged_status === "conflict" ? "border-sev-high-line bg-sev-high-bg text-sev-high" : "border-border text-text2")}>
              <Rocket size={11} /> {x.staged_status ?? "staged"}
            </span>
          )}
          {rejected && <span className="chip border-sev-critical-line bg-sev-critical-bg text-[10px] text-sev-critical"><X size={11} /> rejected</span>}
          <span className="ml-auto flex items-center gap-1 text-[10px] text-text3">
            {x.decided_at ? new Date(x.decided_at).toLocaleString() : ""}
            {open ? <ChevronDown size={13} /> : <ChevronRight size={13} />}
          </span>
        </div>
        <div className="mono mt-1.5 flex flex-wrap items-center gap-1.5 text-[12px] text-text2">
          {isRemediation ? (
            <span className="break-all">{p.summary || `${p.op ?? ""} ${p.target_ref ?? ""}`.trim()}</span>
          ) : (
            <>
              {p.source === "0.0.0.0/0" && <Globe size={11} className="shrink-0 text-text3" />}
              <span className="break-all">{p.source}</span><ArrowRight size={11} className="shrink-0" /><span className="break-all">{p.destination}</span>
              <span className="text-text3">· {p.service}</span>
            </>
          )}
        </div>
        <div className="mt-1 text-[10px] text-text3">decided by {x.decided_by} · {(Number(x.confidence) * 100).toFixed(0)}% confidence · requested by {x.requested_by ?? "?"}</div>
        {!open && x.justification && <div className="mt-1 truncate text-[11px] italic text-text3">“{x.justification}”</div>}
      </button>

      {open && <DecisionDetail x={x} />}

      <div className="flex flex-wrap items-center gap-2 border-t border-hair px-3 py-2">
        {rejected ? (
          <span className="text-[11px] text-text3">Rejected{x.rejected_by ? ` by ${x.rejected_by}` : ""}{x.reject_reason ? ` — “${x.reject_reason}”` : ""}.</span>
        ) : staged ? (
          onNavigate && <button onClick={() => onNavigate("staging")} className="text-[11px] font-bold underline">Open in staging</button>
        ) : (
          <>
            {approve ? (
              <button onClick={() => onStage?.(x.request_id, false)} disabled={staging === x.request_id} className="btn-ghost text-[11px]">
                {staging === x.request_id ? <Spinner label="Staging…" /> : <><Rocket size={12} /> Send to staging</>}
              </button>
            ) : (
              <button onClick={() => onStage?.(x.request_id, true)} disabled={!canApprove || staging === x.request_id}
                title={canApprove ? "" : "Only admin or analyst can approve an escalated change"} className="btn-ghost text-[11px]">
                {staging === x.request_id ? <Spinner label="Staging…" /> : <><ShieldCheck size={12} /> Approve &amp; stage</>}
              </button>
            )}
            <button onClick={() => onReject?.(x.request_id)} disabled={!canApprove || rejecting === x.request_id}
              title={canApprove ? "" : "Only admin or analyst can reject a change"} className="btn-danger ml-auto text-[11px]">
              {rejecting === x.request_id ? <Spinner label="Rejecting…" /> : <><X size={12} /> Reject</>}
            </button>
          </>
        )}
      </div>
    </div>
  );
}

/** The full explanation behind a single gate ruling: the auto-approve criteria,
 *  the computed reachability delta (or, for a remediation, its validation), the
 *  escalation trigger and the model/engine rationale. Reads only fields the
 *  /api/change-decisions endpoint returns (criteria + delta_summary jsonb). */
function DecisionDetail({ x }: { x: any }) {
  const dd = x.delta_summary ?? {};
  const isRemediation = x.kind === "remediation";
  const rationale = typeof dd.rationale === "string" ? dd.rationale : "";
  return (
    <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} className="space-y-3 border-t border-hair bg-surfaceHover p-3">
      {x.request_status === "rejected" && (
        <div className="panel border-sev-critical-line bg-sev-critical-bg p-2.5 text-[12px]">
          <b>Rejected{x.rejected_by ? ` by ${x.rejected_by}` : ""}.</b>{x.reject_reason ? ` ${x.reject_reason}` : " This request was declined and cannot be staged."}
        </div>
      )}
      {x.triggering_reason && (
        <div className="panel border-sev-high-line bg-sev-high-bg p-2.5 text-[12px]"><b>Trigger.</b> {x.triggering_reason}</div>
      )}

      <div>
        <div className="eyebrow mb-2">Auto-approve criteria</div>
        <ul className="space-y-1.5">
          {Object.entries(CRITERIA_LABELS).map(([k, label]) => {
            const pass = (x.criteria ?? {})[k];
            return (
              <li key={k} className="flex items-center gap-2 text-[12px]">
                {pass ? <Check size={14} className="shrink-0 text-ok" /> : <X size={14} className="shrink-0 text-sev-critical" />}
                <span className={cn(!pass && "text-text2")}>{label}</span>
              </li>
            );
          })}
        </ul>
      </div>

      {isRemediation ? (
        <div>
          <div className="eyebrow mb-2">Remediation validation</div>
          <DeltaRow label="Resolves the finding" items={dd.resolves === true ? ["yes"] : dd.resolves === false ? ["no"] : []} />
          <DeltaRow label="Introduces new criticals" items={dd.introduces_new_criticals ?? []} />
          {dd.engine_corrected_ai && <div className="mt-1.5 text-[11px] text-sev-high">⚠ Engine corrected the AI-proposed fix before accepting it.</div>}
        </div>
      ) : (
        <div>
          <div className="eyebrow mb-2">Computed delta</div>
          <DeltaPathRow label="New internet to sensitive paths"
            paths={(dd.new_paths ?? []).map((s: any) => (typeof s === "string" ? s.split(" -> ") : Array.isArray(s) ? s : [String(s)]))} />
          <DeltaRow label="Newly exposed assets" items={dd.new_exposed_assets ?? []} />
          <DeltaRow label="Boundaries crossed" items={dd.boundaries_crossed ?? []} />
          <DeltaRow label="Over-permissive patterns" items={dd.new_over_permissive ?? []} />
        </div>
      )}

      {rationale && <div><div className="eyebrow mb-1.5">Rationale</div><Prose>{rationale}</Prose></div>}

      {x.justification && (
        <div>
          <div className="label">Justification <span className="font-normal normal-case text-text3">— untrusted, not used as evidence</span></div>
          <div className="mt-1 text-[12px] italic text-text2">“{x.justification}”</div>
        </div>
      )}

      <div className="flex flex-wrap gap-x-4 gap-y-1 border-t border-hair pt-2.5 text-[10px] text-text3">
        <span>decided by <b className="text-text2">{x.decided_by}</b></span>
        <span>confidence <b className="text-text2">{(Number(x.confidence) * 100).toFixed(0)}%</b></span>
        <span>requested by <b className="text-text2">{x.requested_by ?? "?"}</b></span>
        {x.origin && <span>origin <b className="text-text2">{x.origin}</b></span>}
        <span className="mono break-all">{x.request_id}</span>
      </div>
    </motion.div>
  );
}
