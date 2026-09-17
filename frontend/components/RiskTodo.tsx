"use client";

/**
 * RISK TO-DO — the list, and the whole story behind one row.
 *
 * WHAT CHANGED AND WHY. The feedback was blunt: this screen still spoke the old
 * language while Explorer and Inventory had been rebuilt as instruments, so it
 * "looked completely off" beside them — big airy cards, no figure row, and a
 * page that ran out of content below five items. And the substance was thin: a
 * finding printed bare references (`WIZ-001 GC-002 ALGO-029`) and left the
 * reviewer to guess what they were, which way they pointed, and what would be
 * cut off if one were removed.
 *
 * So: a figure readout, facet chips with counts, dense rows — and selecting a
 * row opens a SIDE PANEL carrying the finding end to end, with the CHANGE GATE
 * merged into it as a step rather than a screen you navigate to. The gate keeps
 * its own screen for the change-board view; both render the same components
 * (components/risk/gate.tsx) so they cannot drift apart.
 *
 * THE HONESTY RULES ARE LOAD-BEARING HERE, because this is the screen a client
 * is shown:
 *   - a figure whose fetch failed is an em-dash with its reason, never a 0;
 *   - an empty list from a FAILED fetch never reads as "none";
 *   - `engine_explanation` renders immediately and always, and model prose is an
 *     upgrade shown below it and separately attributed;
 *   - a viewer sees every state and none of the controls they cannot use.
 */

import { useCallback, useEffect, useMemo, useState } from "react";
import { useSession } from "next-auth/react";
import { ChevronDown, ChevronRight, RotateCw, Undo2, Wand2 } from "lucide-react";
import { api, asApiError, type ApiError } from "@/lib/api";
import type { ActionItem, Band, Finding } from "@/lib/types";
import { canApprove as canApproveChanges, type AppRole } from "@/lib/roles";
import { SearchBox } from "@/lib/tableTools";
import type { ScreenId } from "./Sidebar";
import { cn, Overlay, SeverityPill, SkeletonRows, ToolBadge } from "./ui";
import { ErrorState, InlineError } from "./ui/Feedback";
import { CampaignPanel } from "./Campaign";
import { FacetChip, FacetRow, Readout, type FigureSpec } from "./risk/bits";
import { DirectionChip } from "./risk/direction";
import { FindingPanel, rulingForFinding, type Ruling } from "./risk/FindingPanel";
import { AppliedChanges, StatusChip, type QueueRow } from "./risk/implementation";
import { RuleToken } from "./risk/RuleToken";
import { primaryContext, useRule } from "./risk/useRule";

const BAND_ORDER: Record<Band, number> = { critical: 0, high: 1, medium: 2, low: 3 };
const BANDS: Band[] = ["critical", "high", "medium", "low"];
const BAND_SWATCH: Record<Band, string> = {
  critical: "bg-sev-critical", high: "bg-sev-high", medium: "bg-sev-medium", low: "bg-sev-low",
};
const BAND_TONE: Record<Band, string> = {
  critical: "text-sev-critical", high: "text-sev-high", medium: "text-sev-medium", low: "text-text",
};

/** Where a finding stands in the change workflow. Derived from the decision log
 *  and the implementation queue, which is the mapping the Risk To-Do list was
 *  missing: a row now says whether its fix is in the gate, queued or live. */
type Stage = "open" | "gate" | "rejected" | "queued" | "applied" | "rolled_back";

const STAGE_LABEL: Record<Stage, string> = {
  open: "open", gate: "in the gate", rejected: "rejected",
  queued: "queued", applied: "applied", rolled_back: "rolled back",
};
const STAGE_ORDER: Stage[] = ["open", "gate", "queued", "applied", "rolled_back", "rejected"];

function stageOf(ruling?: Ruling, queued?: QueueRow): Stage {
  if (!ruling) return "open";
  if (ruling.request_status === "rejected") return "rejected";
  if (!queued) return "gate";
  if (queued.status === "pushed") return "applied";
  if (queued.status === "rolled_back") return "rolled_back";
  return "queued";
}

export function RiskTodo({ actions, findings, readOnly = false, loading = false, actionsError, findingsError, onRetry, onNavigate }:
  { actions: ActionItem[]; findings: Finding[]; readOnly?: boolean; loading?: boolean;
    actionsError?: ApiError; findingsError?: ApiError; onRetry?: () => void; onNavigate?: (s: ScreenId) => void }) {
  const { data: session } = useSession();
  const role = ((session?.user as any)?.role ?? null) as AppRole | null;
  const canApprove = canApproveChanges(role) && !readOnly;

  // ── the governance join: decisions + the implementation queue ────────────
  // Loaded here rather than inside each row so the list, the side panel and the
  // applied-change history are all reading one answer.
  const [decisions, setDecisions] = useState<any[]>();
  const [decisionsError, setDecisionsError] = useState<ApiError>();
  const [staged, setStaged] = useState<QueueRow[]>();
  const [stagingError, setStagingError] = useState<ApiError>();

  const loadGovernance = useCallback(() => {
    // Never fall back to []: "this estate has no change history" is a claim a
    // failed request cannot make, and it is the claim that would make the
    // workflow counts below read as zeros.
    api.changeDecisions()
      .then((r) => { setDecisions(r.decisions); setDecisionsError(undefined); })
      .catch((e) => { setDecisions(undefined); setDecisionsError(asApiError(e)); });
    api.staging()
      .then((r) => { setStaged(r.staged as QueueRow[]); setStagingError(undefined); })
      .catch((e) => { setStaged(undefined); setStagingError(asApiError(e)); });
  }, []);
  useEffect(() => { loadGovernance(); }, [loadGovernance]);

  const byId = useMemo(() => Object.fromEntries(findings.map((f) => [f.finding_id, f])), [findings]);

  const stageFor = useCallback((f: Finding): { stage: Stage; ruling?: Ruling; queued?: QueueRow } => {
    const ruling = rulingForFinding(decisions, f.finding_id);
    const queued = ruling ? (staged ?? []).find((s) => s.request_id === ruling.request_id) : undefined;
    return { stage: stageOf(ruling, queued), ruling, queued };
  }, [decisions, staged]);

  const enriched = useMemo(() => actions.map((a) => {
    const fs = a.finding_ids.map((id) => byId[id]).filter(Boolean) as Finding[];
    const worst = fs.reduce<Band>((w, f) => (BAND_ORDER[f.severity_band] < BAND_ORDER[w] ? f.severity_band : w), "low");
    return { a, fs, worst };
  }), [actions, byId]);

  const counts = useMemo(() => {
    const c: Record<Band, number> = { critical: 0, high: 0, medium: 0, low: 0 };
    findings.forEach((f) => { c[f.severity_band]++; });
    return c;
  }, [findings]);

  // The workflow counts are only knowable when BOTH reads landed: a finding's
  // stage is a join across them, so one failure makes every count unknown
  // rather than partially wrong.
  const workflowKnown = decisions !== undefined && staged !== undefined;
  const stageCounts = useMemo(() => {
    const c: Record<Stage, number> = { open: 0, gate: 0, rejected: 0, queued: 0, applied: 0, rolled_back: 0 };
    if (!workflowKnown) return c;
    findings.forEach((f) => { c[stageFor(f).stage]++; });
    return c;
  }, [findings, stageFor, workflowKnown]);

  const [q, setQ] = useState("");
  const [band, setBand] = useState<Band | "all">("all");
  const [stage, setStage] = useState<Stage | "all">("all");
  const [collapsed, setCollapsed] = useState<Record<string, boolean>>({});
  const [campaignOpen, setCampaignOpen] = useState(false);
  const [openId, setOpenId] = useState<string | null>(null);

  const matches = useCallback((f: Finding) => {
    if (band !== "all" && f.severity_band !== band) return false;
    if (stage !== "all") {
      if (!workflowKnown) return false;
      if (stageFor(f).stage !== stage) return false;
    }
    const needle = q.trim().toLowerCase();
    if (!needle) return true;
    const hay = `${f.title ?? ""} ${f.type} ${f.raw_refs.join(" ")} ${f.involved.join(" ")} ${f.source_tools.join(" ")}`.toLowerCase();
    return hay.includes(needle);
  }, [band, stage, q, stageFor, workflowKnown]);

  const shown = useMemo(() => enriched
    .map((e) => ({ ...e, fs: e.fs.filter(matches) }))
    .filter((e) => e.fs.length > 0), [enriched, matches]);

  const shownCount = shown.reduce((n, e) => n + e.fs.length, 0);
  const selected = openId ? byId[openId] : undefined;
  const selectedAction = selected ? actions.find((a) => a.finding_ids.includes(selected.finding_id)) : undefined;

  // Checked BEFORE the loading and empty paths, because an error is definitive:
  // with no findings and no actions this screen would otherwise read as a clean
  // estate, and an unanswered question is not a clean bill of health.
  if (findingsError || actionsError) {
    return (
      <div className="grid gap-3">
        {findingsError && <ErrorState resource="findings" error={findingsError} onRetry={onRetry} />}
        {actionsError && <ErrorState resource="prioritized actions" error={actionsError} onRetry={onRetry} />}
        <p className="text-[12px] leading-relaxed text-text3">
          No risk list is shown on purpose. Nothing here has been assessed as clean — the data behind this screen did
          not load, so the estate&apos;s posture is unknown.
        </p>
      </div>
    );
  }

  if (loading && actions.length === 0) {
    return <div className="grid gap-3"><SkeletonRows rows={8} /></div>;
  }

  const figures: FigureSpec[] = [
    { key: "critical", label: "critical", value: counts.critical, tone: BAND_TONE.critical, active: band === "critical",
      onClick: () => setBand(band === "critical" ? "all" : "critical") },
    { key: "high", label: "high", value: counts.high, tone: BAND_TONE.high, active: band === "high",
      onClick: () => setBand(band === "high" ? "all" : "high") },
    { key: "medium", label: "medium", value: counts.medium, tone: BAND_TONE.medium, active: band === "medium",
      onClick: () => setBand(band === "medium" ? "all" : "medium") },
    { key: "low", label: "low", value: counts.low, tone: BAND_TONE.low, active: band === "low",
      onClick: () => setBand(band === "low" ? "all" : "low") },
    { key: "actions", label: "actions", value: actions.length },
    { key: "applied", label: "applied", value: workflowKnown ? stageCounts.applied : null,
      unknown: "The change log or the implementation queue did not load, so how many fixes are live is unknown — not zero." },
  ];

  return (
    <div className="space-y-2.5">
      <Readout
        title="What the analysis found"
        note={<>grouped by root cause into <b className="text-text2">{actions.length}</b> actions, worst first</>}
        figures={figures}
      />

      {/* The campaign agent is a bulk action over this list, not a lesson about
          itself — collapsed by default so the screen stays an instrument. */}
      <div className="border border-border bg-surface2">
        <button onClick={() => setCampaignOpen((o) => !o)}
          className="flex w-full items-center gap-2 px-3.5 py-2 text-left hover:bg-surfaceHover">
          <Wand2 size={13} className="shrink-0 text-text3" />
          <span className="text-[11px] font-bold uppercase tracking-[0.12em]">Remediation campaign</span>
          <span className="text-[10.5px] text-text3">one worst-first pass over every finding</span>
          <ChevronDown size={13} className={cn("ml-auto shrink-0 transition-transform", campaignOpen && "rotate-180")} />
        </button>
        {campaignOpen && <div className="border-t border-hair p-3"><CampaignPanel readOnly={readOnly} onNavigate={onNavigate} /></div>}
      </div>

      <div className="border border-border bg-surface2">
        <div className="flex flex-wrap items-center gap-2 border-b border-hair px-3.5 py-2">
          <span className="eyebrow">Risk to-do</span>
          <span className="ml-auto text-[10.5px] text-text3">
            showing {shownCount} of {findings.length} findings
          </span>
          <button onClick={() => { onRetry?.(); loadGovernance(); }} className="btn-ghost !h-[24px] !px-2 text-[11px]">
            <RotateCw size={11} /> Refresh
          </button>
        </div>

        <div className="space-y-2 border-b border-hair px-3.5 py-2.5">
          <FacetRow label="severity">
            <FacetChip label="all" n={findings.length} active={band === "all"} onClick={() => setBand("all")} />
            {BANDS.map((b) => (
              <FacetChip key={b} label={b} n={counts[b]} swatch={BAND_SWATCH[b]} active={band === b} onClick={() => setBand(b)} />
            ))}
          </FacetRow>
          <FacetRow label="workflow">
            <FacetChip label="all" active={stage === "all"} onClick={() => setStage("all")} />
            {STAGE_ORDER.map((s) => (
              <FacetChip key={s} label={STAGE_LABEL[s]} n={workflowKnown ? stageCounts[s] : null}
                active={stage === s} onClick={() => setStage(stage === s ? "all" : s)}
                title={workflowKnown ? undefined : "The change log or the implementation queue did not load — these counts are unknown, not zero."} />
            ))}
          </FacetRow>
          <FacetRow label="search">
            <SearchBox value={q} onChange={setQ} placeholder="title, rule reference, asset, tool…" />
          </FacetRow>
          {(decisionsError || stagingError) && (
            <div className="space-y-1">
              {decisionsError && <InlineError resource="the change decision log" error={decisionsError} onRetry={loadGovernance} />}
              {stagingError && <InlineError resource="the implementation queue" error={stagingError} onRetry={loadGovernance} />}
              <p className="text-[10.5px] text-text3">
                Every workflow count and chip below reads &ldquo;—&rdquo; while this is unread. None of these findings has been
                assessed as un-actioned.
              </p>
            </div>
          )}
        </div>

        {shown.length === 0 ? (
          <div className="p-6 text-center text-[12px] text-text3">
            {findings.length === 0
              ? "The analysis returned no findings for this snapshot."
              : "No finding matches this filter."}
          </div>
        ) : (
          <div>
            {shown.map(({ a, fs, worst }) => {
              const shut = !!collapsed[a.action_id];
              return (
                <section key={a.action_id} className="border-b border-hair last:border-0">
                  <button onClick={() => setCollapsed((c) => ({ ...c, [a.action_id]: !shut }))}
                    className="flex w-full items-center gap-2.5 px-3.5 py-2 text-left hover:bg-surfaceHover">
                    <span className={cn("mono grid h-[22px] min-w-[26px] shrink-0 place-items-center border px-1 text-[11px] font-bold tabular-nums",
                      worst === "critical" ? "border-sev-critical-line bg-sev-critical-bg text-sev-critical"
                      : worst === "high" ? "border-sev-high-line bg-sev-high-bg text-sev-high"
                      : worst === "medium" ? "border-sev-medium-line bg-sev-medium-bg text-sev-medium"
                      : "border-sev-low-line bg-sev-low-bg text-sev-low")}>
                      {a.priority}
                    </span>
                    <span className="min-w-0 flex-1">
                      <span className="block truncate text-[12.5px] font-bold">{a.title}</span>
                      <span className="block truncate text-[10.5px] text-text3">{a.rationale}</span>
                    </span>
                    <span className="mono shrink-0 text-[10.5px] tabular-nums text-text3">{fs.length}</span>
                    <ChevronRight size={13} className={cn("shrink-0 text-text3 transition-transform", !shut && "rotate-90")} />
                  </button>
                  {!shut && (
                    <ul>
                      {fs.map((f) => {
                        const { stage: st, queued } = stageFor(f);
                        return (
                          <FindingRow key={f.finding_id} f={f} snapshot={undefined} stage={workflowKnown ? st : undefined}
                            queuedStatus={queued?.status} selected={openId === f.finding_id}
                            onOpen={() => setOpenId(f.finding_id)} />
                        );
                      })}
                    </ul>
                  )}
                </section>
              );
            })}
          </div>
        )}
      </div>

      {/* WHERE THE CHANGES WE MADE ARE LISTED, and the way back out of them. */}
      <div className="border border-border bg-surface2">
        <div className="flex flex-wrap items-center gap-2 border-b border-hair px-3.5 py-2">
          <Undo2 size={13} className="shrink-0 text-text3" />
          <span className="eyebrow">Applied changes</span>
          <span className="text-[10.5px] text-text3">what this console has put into the engine&apos;s applied overlay</span>
          {onNavigate && (
            <button onClick={() => onNavigate("staging")} className="ml-auto text-[10.5px] font-bold underline">
              Open the Implementation Queue
            </button>
          )}
        </div>
        <div className="p-3">
          <AppliedChanges rows={staged} error={stagingError} loading={staged === undefined && !stagingError}
            canApprove={canApprove} onChanged={loadGovernance} onRetry={loadGovernance}
            findingSlot={(row) => {
              const fid = (row.payload ?? {}).finding_id;
              const f = fid ? byId[String(fid)] : undefined;
              return f ? (
                <button onClick={() => setOpenId(f.finding_id)} className="truncate text-[10.5px] underline decoration-dotted hover:text-accent-fg">
                  {f.title ?? f.type}
                </button>
              ) : null;
            }} />
        </div>
      </div>

      <Overlay open={!!selected} onClose={() => setOpenId(null)} widthClass="max-w-[min(96vw,760px)]"
        label={selected ? `Finding ${selected.finding_id}` : undefined}>
        {selected && (
          <FindingPanel
            finding={selected} action={selectedAction} readOnly={readOnly} canApprove={canApprove}
            decisions={decisions} decisionsError={decisionsError} staged={staged} stagingError={stagingError}
            onGovernanceChanged={loadGovernance} onClose={() => setOpenId(null)}
          />
        )}
      </Overlay>
    </div>
  );
}

/**
 * One finding, one line.
 *
 * The DIRECTION CHIP is fetched lazily off the finding's primary rule through
 * the shared cache, so a strip of rows reads as inbound / outbound / internal
 * before anything is opened. While it is unknown the cell is EMPTY — a flow is
 * never guessed, and a failed lookup must not render as "internal".
 */
/** The rule a finding is ABOUT, which is not always its first reference:
 *  `raw_refs` is sorted, so a shadowed/redundant finding leads with the rule
 *  doing the shadowing rather than the one the row names. */
function subjectRef(f: Finding): string | undefined {
  const shadowed = f.signals?.shadowed_ref;
  if (typeof shadowed === "string") return shadowed;
  const udp = f.signals?.udp_refs;
  if (Array.isArray(udp) && typeof udp[0] === "string") return udp[0];
  return f.raw_refs[0];
}

function FindingRow({ f, snapshot, stage, queuedStatus, selected, onOpen }: {
  f: Finding; snapshot?: string; stage?: Stage; queuedStatus?: string; selected: boolean; onOpen: () => void;
}) {
  const primaryRef = subjectRef(f);
  const { context } = useRule(primaryRef ?? "", snapshot, !!primaryRef);
  const ctx = primaryContext(context);
  const anomaly = typeof f.signals?.anomaly_class === "string" ? f.signals.anomaly_class : undefined;

  return (
    <li>
      <div role="button" tabIndex={0} onClick={onOpen}
        onKeyDown={(e) => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); onOpen(); } }}
        className={cn("flex w-full cursor-pointer items-center gap-2 border-t border-hair px-3.5 py-1.5 text-left",
          selected ? "bg-accent-soft" : "hover:bg-surfaceHover")}>
        <SeverityPill band={f.severity_band} />
        {ctx ? <DirectionChip size="sm" refId={ctx.raw_ref} direction={ctx.direction} /> : <span className="w-[62px] shrink-0" aria-hidden />}
        <span className="min-w-0 flex-1 truncate text-[12px]" title={f.title ?? f.type}>{f.title ?? f.signals?.title ?? f.type}</span>
        {anomaly && (
          <span className="mono hidden h-[17px] shrink-0 items-center border border-border bg-sunk px-1 text-[9px] font-bold uppercase tracking-[0.06em] text-text2 lg:inline-flex">
            {anomaly}
          </span>
        )}
        {stage && stage !== "open" && (
          queuedStatus ? <StatusChip size="sm" status={queuedStatus} />
            : <span className="hidden h-[18px] shrink-0 items-center border border-accent bg-accent-soft px-1.5 text-[9.5px] font-bold uppercase tracking-[0.08em] text-accent-fg sm:inline-flex">
                {STAGE_LABEL[stage]}
              </span>
        )}
        <span className="hidden shrink-0 items-center gap-1 md:inline-flex">
          {f.source_tools.map((t) => <ToolBadge key={t} tool={t} />)}
        </span>
        <span className="hidden shrink-0 flex-wrap items-center justify-end gap-1 xl:inline-flex" onClick={(e) => e.stopPropagation()}>
          {f.raw_refs.slice(0, 4).map((r) => <RuleToken key={r} refId={r} snapshot={snapshot} />)}
        </span>
        <ChevronRight size={13} className="shrink-0 text-text3" />
      </div>
    </li>
  );
}
