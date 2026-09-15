"use client";

/**
 * The walkthrough sidebar: one finding at a time, with the canvas showing what
 * it is talking about.
 *
 * The rule for this panel is that every sentence in it comes off a payload. The
 * engine wrote the detail, the engine measured the blast radius, the engine
 * published the severity vector's three terms — so a client can recompute the
 * number by hand from what is on screen. Where a payload has nothing (a policy
 * finding the advisory layer has not explained yet) the panel SAYS that and
 * offers to ask, rather than paraphrasing the signals into a sentence that
 * sounds like a conclusion.
 */

import { AlertTriangle, ChevronLeft, ChevronRight, PanelRightClose, PanelRightOpen, RotateCw, Sparkles, Wrench } from "lucide-react";
import type { ApiError } from "@/lib/api";
import { cn } from "@/lib/cn";
import { Chip, SeverityPill, ToolBadge, Spinner } from "@/components/ui";
import { ErrorState, InlineError } from "@/components/ui/Feedback";
import { RuleRef } from "@/components/RuleRef";
import { blastLines, type WalkFinding } from "./findings";

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div className="border-t border-hair px-3.5 py-3">
      <div className="label mb-1.5">{title}</div>
      {children}
    </div>
  );
}

function KV({ k, v, mono = true }: { k: string; v: string; mono?: boolean }) {
  return (
    <div className="flex items-baseline justify-between gap-3 py-[3px] text-[11.5px]">
      <span className="min-w-0 text-text3">{k}</span>
      <span className={cn("shrink-0 text-right text-text", mono && "mono tabular-nums")}>{v}</span>
    </div>
  );
}

export interface FindingSidebarProps {
  items: WalkFinding[];
  /** `null` = the canvas is open with nothing selected, which is a real state:
   *  fullscreen is also just a bigger canvas. Nothing is dimmed until a finding
   *  is chosen, and the counter says so rather than implying item 1 is live. */
  index: number | null;
  onIndex: (i: number) => void;
  collapsed: boolean;
  onToggleCollapsed: () => void;
  loading: boolean;
  error?: ApiError;
  onRetry: () => void;
  /** `/api/resilience.analysed`. `null` = the payload has not arrived. */
  analysed: boolean | null;
  notAnalysedReason?: string | null;
  blastBasis?: string;
  /** How many isolated devices the staged replay has revealed so far. */
  isolatedShown: number;
  /** How many of the finding's devices are actually drawn on the canvas. Zero
   *  is a real answer — a capped response, or a finding about something in no
   *  lane — and it is said rather than left as a canvas that lights nothing. */
  involvedOnCanvas: number;
  replayDone: boolean;
  onReplay: () => void;
  nameFor: (key: string) => string;
  onExplain?: (item: WalkFinding) => void;
  explainingId?: string;
  explainError?: ApiError;
  skippedPolicy: number;
  snapshot?: string;
}

function AllFindings({ items, index, onIndex }: { items: WalkFinding[]; index: number | null; onIndex: (i: number) => void }) {
  return (
    <Section title={`All findings (${items.length})`}>
      <ul className="-mx-1">
        {items.map((f, i) => (
          <li key={f.id}>
            <button
              type="button"
              onClick={() => onIndex(i)}
              className={cn("row flex w-full items-start gap-2 px-1 py-1.5 text-left", i === index && "bg-surfaceHover")}
              aria-current={i === index}
            >
              <span className="mono w-5 shrink-0 pt-px text-[10px] tabular-nums text-text3">{i + 1}</span>
              <span
                aria-hidden
                className={cn(
                  "mt-1 h-2 w-2 shrink-0",
                  f.band === "critical" && "bg-sev-critical",
                  f.band === "high" && "bg-sev-high",
                  f.band === "medium" && "bg-sev-medium",
                  f.band === "low" && "bg-sev-low",
                )}
              />
              <span className="min-w-0 flex-1">
                <span className="block truncate text-[11.5px] font-bold text-text2">{f.title}</span>
                <span className="mono block truncate text-[10px] text-text3">{f.type}</span>
              </span>
            </button>
          </li>
        ))}
      </ul>
    </Section>
  );
}

export function FindingSidebar(p: FindingSidebarProps) {
  const item = p.index == null ? undefined : p.items[p.index];

  if (p.collapsed) {
    return (
      <aside className="flex h-full w-[44px] shrink-0 flex-col items-center gap-2 border-l border-border bg-surface py-2">
        <button
          type="button"
          onClick={p.onToggleCollapsed}
          className="btn-ghost !h-7 !w-7 !px-0"
          aria-label="Expand the findings sidebar"
          title="Expand the findings sidebar"
        >
          <PanelRightOpen size={14} />
        </button>
        <div className="mono rotate-180 text-[10px] tabular-nums text-text3" style={{ writingMode: "vertical-rl" }}>
          {p.items.length === 0
            ? "no findings"
            : p.index == null
              ? `${p.items.length} findings`
              : `${p.index + 1} of ${p.items.length}`}
        </div>
      </aside>
    );
  }

  return (
    <aside className="zt-scroll flex h-full w-[380px] shrink-0 flex-col overflow-y-auto border-l border-border bg-surface">
      <header className="sticky top-0 z-10 flex shrink-0 items-center gap-1.5 border-b border-border bg-surface px-3 py-2">
        <span className="eyebrow">Findings</span>
        <span className="mono ml-auto text-[11px] tabular-nums text-text2">
          {p.items.length === 0
            ? "0"
            : p.index == null
              ? `${p.items.length} findings`
              : `${p.index + 1} of ${p.items.length}`}
        </span>
        <button
          type="button"
          onClick={() => p.onIndex((p.index ?? 0) - 1)}
          disabled={p.items.length === 0 || p.index == null || p.index <= 0}
          className="btn-ghost !h-7 !w-7 !px-0"
          aria-label="Previous finding"
          title="Previous finding (left arrow)"
        >
          <ChevronLeft size={14} />
        </button>
        <button
          type="button"
          onClick={() => p.onIndex(p.index == null ? 0 : p.index + 1)}
          disabled={p.items.length === 0 || (p.index != null && p.index >= p.items.length - 1)}
          className="btn-ghost !h-7 !w-7 !px-0"
          aria-label="Next finding"
          title="Next finding (right arrow)"
        >
          <ChevronRight size={14} />
        </button>
        <button
          type="button"
          onClick={p.onToggleCollapsed}
          className="btn-ghost !h-7 !w-7 !px-0"
          aria-label="Collapse the findings sidebar"
          title="Collapse the findings sidebar"
        >
          <PanelRightClose size={14} />
        </button>
      </header>

      {p.error ? (
        <div className="p-3">
          <ErrorState resource="the resilience analysis" error={p.error} onRetry={p.onRetry} />
        </div>
      ) : p.loading ? (
        <div className="flex items-center gap-2 p-4 text-[12px] text-text2">
          <Spinner label="Reading the resilience analysis…" />
        </div>
      ) : p.analysed === false ? (
        // An empty findings list from an analysis that never ran must not read
        // as a clean bill of health. This is that sentence.
        <div className="m-3 border border-sev-medium-line bg-sev-medium-bg p-3">
          <div className="text-[12.5px] font-bold text-sev-medium">Nothing was analysed</div>
          <p className="mt-1 text-[11.5px] leading-relaxed text-text2">
            The resilience analyzer reports that it had nothing to work on, so the absence of findings below is not a
            statement that this estate has no single point of failure.
          </p>
          {p.notAnalysedReason ? <div className="mono mt-1.5 text-[11px] text-text3">{p.notAnalysedReason}</div> : null}
        </div>
      ) : p.items.length === 0 ? (
        <div className="p-4 text-[12px] leading-relaxed text-text2">
          The analysis ran and returned no finding that names a device on this canvas.
          {p.skippedPolicy > 0 ? (
            <> {p.skippedPolicy} policy finding{p.skippedPolicy === 1 ? "" : "s"} in this snapshot name nothing here; they are on the Risk To-Do screen.</>
          ) : null}
        </div>
      ) : item == null ? (
        <>
          <div className="px-3.5 py-3 text-[12px] leading-relaxed text-text2">
            {p.items.length} finding{p.items.length === 1 ? "" : "s"} name a device on this canvas. Pick one — or press
            the right arrow — and everything not involved dims while the path is traced hop by hop.
          </div>
          <AllFindings items={p.items} index={p.index} onIndex={p.onIndex} />
        </>
      ) : (
        <>
          <div className="px-3.5 py-3">
            <div className="flex flex-wrap items-center gap-1.5">
              <SeverityPill band={item.band} severity={item.severity} forced={item.forcedCritical} />
              <Chip variant={item.kind === "resilience" ? "accent" : "neutral"}>
                {item.kind === "resilience" ? "resilience" : "policy"}
              </Chip>
              <span className="mono text-[10.5px] text-text3">{item.type}</span>
            </div>
            <h3 className="mt-2 text-[14px] font-bold leading-snug">{item.title}</h3>
            {p.involvedOnCanvas === 0 ? (
              <p className="mt-1.5 border border-sev-medium-line bg-sev-medium-bg px-2 py-1.5 text-[11px] leading-snug text-text2">
                None of the {item.involved.length} device{item.involved.length === 1 ? "" : "s"} this finding names is
                drawn on the canvas, so nothing is highlighted for it. That is a gap in what this topology response
                covers — check the cap notice above — not a finding without a subject.
              </p>
            ) : null}
          </div>

          <Section title="What the problem is">
            {item.detail ? (
              <p className="whitespace-pre-line text-[12px] leading-relaxed text-text2">{item.detail}</p>
            ) : (
              <div className="space-y-2">
                <p className="text-[12px] leading-relaxed text-text2">
                  No explanation has been written for this finding yet. Rather than paraphrase the signals below into
                  something that reads like a conclusion, this panel leaves it unwritten.
                </p>
                {p.onExplain ? (
                  <button
                    type="button"
                    onClick={() => p.onExplain?.(item)}
                    disabled={p.explainingId === item.id}
                    className="btn-ghost text-[11.5px]"
                  >
                    {p.explainingId === item.id ? <Spinner label="Asking…" /> : <><Sparkles size={12} /> Ask the advisory layer</>}
                  </button>
                ) : null}
                {p.explainError ? <InlineError resource="the explanation" error={p.explainError} /> : null}
              </div>
            )}
          </Section>

          {item.blast ? (
            <Section title="Blast radius — measured, not assumed">
              <div className="border border-sev-critical-line bg-sev-critical-bg px-2.5 py-2">
                <div className="mono text-[17px] font-bold leading-none tabular-nums text-sev-critical">
                  {item.blast.paths_lost} of {item.blast.paths_before}
                </div>
                <div className="mt-1 text-[11.5px] leading-snug text-text2">
                  paths to a circuit are lost when <span className="mono">{item.blast.device_key}</span> fails.
                </div>
                {item.blast.devices_isolated.length > 0 ? (
                  <div className="mono mt-1.5 text-[11px] tabular-nums text-text2">
                    {p.replayDone ? item.blast.devices_isolated.length : p.isolatedShown} of{" "}
                    {item.blast.devices_isolated.length} device
                    {item.blast.devices_isolated.length === 1 ? "" : "s"} isolated
                    {p.replayDone ? "" : " …"}
                  </div>
                ) : null}
              </div>
              <div className="mt-2">
                {blastLines(item.blast).map((l) => (
                  <KV key={l.label} k={l.label} v={l.value} mono={l.label !== "Circuits stranded"} />
                ))}
              </div>
              {item.blast.devices_isolated.length > 0 ? (
                <div className="mt-1.5 flex flex-wrap gap-1">
                  {item.blast.devices_isolated.map((d) => (
                    <span key={d} className="mono border border-border bg-sunk px-1 text-[10px] text-text2" title={d}>
                      {p.nameFor(d)}
                    </span>
                  ))}
                </div>
              ) : null}
              {p.blastBasis ? (
                <p className="mt-2 text-[11px] leading-snug text-text3">{p.blastBasis}</p>
              ) : null}
              <button type="button" onClick={p.onReplay} className="btn-ghost mt-2 text-[11.5px]">
                <RotateCw size={12} /> Replay the failure
              </button>
            </Section>
          ) : null}

          {Object.keys(item.vector).length > 0 ? (
            <Section title={item.kind === "resilience" ? "Severity vector" : "Signals"}>
              {item.kind === "resilience" ? (
                <p className="mb-1.5 mono text-[10.5px] leading-snug text-text3">
                  severity = round(100 × min(1, R × L × S))
                </p>
              ) : null}
              {Object.entries(item.vector).map(([k, v]) => (
                <KV key={k} k={k} v={typeof v === "object" && v !== null ? JSON.stringify(v) : String(v)} />
              ))}
            </Section>
          ) : null}

          {item.ruleRefs.length > 0 ? (
            <Section title="Rule references">
              <div className="flex flex-wrap gap-x-2 gap-y-1">
                {item.ruleRefs.map((r) => (
                  <RuleRef key={r} refId={r} snapshot={p.snapshot} />
                ))}
              </div>
            </Section>
          ) : null}

          {item.sourceTools.length > 0 ? (
            <Section title="Attributed to">
              <div className="flex flex-wrap gap-1">
                {item.sourceTools.map((t) => (
                  <ToolBadge key={t} tool={t} />
                ))}
              </div>
            </Section>
          ) : null}

          <Section title="Remediation">
            {item.remediation ? (
              <div className="flex gap-2">
                <Wrench size={13} className="mt-0.5 shrink-0 text-accent-fg" />
                <p className="text-[12px] leading-relaxed text-text2">{item.remediation}</p>
              </div>
            ) : (
              <p className="text-[12px] leading-relaxed text-text3">
                This payload carries no remediation for this finding. A proposed change for a policy finding is generated
                on the Risk To-Do screen, where it is validated before it can be submitted.
              </p>
            )}
          </Section>

          <AllFindings items={p.items} index={p.index} onIndex={p.onIndex} />

          {p.skippedPolicy > 0 ? (
            <div className="flex items-start gap-1.5 px-3.5 py-3 text-[11px] leading-snug text-text3">
              <AlertTriangle size={11} className="mt-0.5 shrink-0" />
              {p.skippedPolicy} policy finding{p.skippedPolicy === 1 ? "" : "s"} in this snapshot name no device on this
              canvas and are not listed here. They are on the Risk To-Do screen.
            </div>
          ) : null}
        </>
      )}
    </aside>
  );
}
