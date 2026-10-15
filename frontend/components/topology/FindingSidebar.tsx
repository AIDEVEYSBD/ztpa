"use client";

/**
 * The walkthrough panel: one finding at a time, with the canvas showing what it
 * is talking about.
 *
 * The rule for this panel is that every sentence in it comes off a payload. The
 * engine wrote the detail, the engine measured the blast radius, the engine
 * published the severity vector's three terms — so a client can recompute the
 * number by hand from what is on screen.
 *
 * TWO THINGS IN HERE WERE BUGS AND ARE NOW THE OPPOSITE.
 *
 * "No explanation has been written for this finding yet" used to appear
 * whenever `Finding.explanation` was null. That sentence was FALSE. `explanation`
 * is model prose and is null until somebody asks; `engine_explanation` is the
 * engine's own account of the finding, deterministic, written from the
 * finding's own signals by the code that computed them, and present on every
 * row. Reading one field and reporting the other's absence made a fully
 * explained finding look unexamined. Both are now rendered, separately
 * attributed, and the model prose is an UPGRADE that never overwrites the
 * engine text.
 *
 * And this panel could not be dismissed without leaving the canvas dimmed on
 * the finding it was showing. Closing or collapsing it now CLEARS the selection
 * — see `onDismiss`. A panel that can hide the reason the canvas is dimmed, and
 * cannot undim it, is a trap.
 */

import { useEffect, useRef, useState } from "react";
import {
  AlertTriangle, ChevronLeft, ChevronRight, Cpu, PanelRightClose, PanelRightOpen,
  RotateCw, Sparkles, Wrench, X,
} from "lucide-react";
import type { ApiError } from "@/lib/api";
import { cn } from "@/lib/cn";
import { Chip, SeverityPill, ToolBadge, Spinner } from "@/components/ui";
import { ErrorState, InlineError } from "@/components/ui/Feedback";
import { RuleTokens } from "@/components/risk/RuleToken";
import { KV, SignalList } from "./kv";
import { blastLines, type WalkFinding } from "./findings";

/**
 * One collapsible block.
 *
 * Every section used to render open, so opening a finding presented nine
 * headings at once -- blast radius, severity vector, signals, raw references,
 * attribution, remediation -- and the sentence that says what is wrong was one
 * of nine equal things rather than the answer. `defaultOpen` is set on the two
 * a reader wants first; the rest are one click away and announce themselves by
 * title.
 *
 * Uncontrolled on purpose. The open set is per-finding scratch state, and
 * hoisting it would mean deciding whether it survives selecting a different
 * finding -- for which there is no good answer and no request.
 */
function Section({
  title, children, defaultOpen = false, count,
}: {
  title: string;
  children: React.ReactNode;
  defaultOpen?: boolean;
  /** Shown beside the title, so a collapsed section still says how much it holds. */
  count?: number;
}) {
  const [open, setOpen] = useState(defaultOpen);
  return (
    <div className="min-w-0 border-t border-hair">
      <button
        type="button"
        onClick={() => setOpen((v) => !v)}
        aria-expanded={open}
        className="flex w-full items-center gap-1.5 px-3.5 py-2 text-left hover:bg-surface-hover"
      >
        <ChevronRight
          size={11}
          className={cn("shrink-0 text-text3 transition-transform", open && "rotate-90")}
        />
        <span className="label !text-text2">{title}</span>
        {count != null && (
          <span className="mono text-[10px] text-text3">{count}</span>
        )}
      </button>
      {open && <div className="min-w-0 px-3.5 pb-3">{children}</div>}
    </div>
  );
}

/** Who wrote the text under this heading. Never implicit: the whole point of
 *  keeping two explanations is that a reader can tell them apart. */
function Attribution({ icon: Icon, who, note }: { icon: typeof Cpu; who: string; note: string }) {
  return (
    <>
      <div className="flex items-center gap-1.5">
        <Icon size={11} className="shrink-0 text-dim" />
        <span className="text-[11px] font-medium tracking-[0.06em] text-faint uppercase">{who}</span>
      </div>
      <p className="mt-0.5 text-[10.5px] leading-[1.5] text-ghost">{note}</p>
    </>
  );
}

export interface FindingSidebarProps {
  items: WalkFinding[];
  /** `null` = the canvas is open with nothing selected, which is a real state:
   *  fullscreen is also just a bigger canvas. Nothing is dimmed until a finding
   *  is chosen, and the counter says so rather than implying item 1 is live. */
  index: number | null;
  onIndex: (i: number) => void;
  /** Back to "nothing selected", with the panel left open. */
  onClearSelection: () => void;
  /** Close the panel. MUST clear the selection: see the file header. */
  onDismiss: () => void;
  collapsed: boolean;
  /** Collapse to the rail. Also clears the selection, for the same reason. */
  onToggleCollapsed: () => void;
  loading: boolean;
  error?: ApiError;
  onRetry: () => void;
  /** `/api/resilience.analysed`. `null` = the payload has not arrived. */
  analysed: boolean | null;
  notAnalysedReason?: string | null;
  blastBasis?: string;
  /** How many of the lost cards the staged replay has faded so far, and how
   *  many there are. Both counts are of things actually on the canvas. */
  lostShown: number;
  lostTotal: number;
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
  className?: string;
}

function AllFindings({ items, index, onIndex }: { items: WalkFinding[]; index: number | null; onIndex: (i: number) => void }) {
  return (
    <Section title={`All findings (${items.length})`} defaultOpen>
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

/**
 * What the problem is — in the ENGINE's words, always, and in the model's words
 * too once somebody has asked for them.
 */
function Explanation({
  item, onExplain, explainingId, explainError,
}: Pick<FindingSidebarProps, "onExplain" | "explainingId" | "explainError"> & { item: WalkFinding }) {
  const engineWho = item.kind === "resilience" ? "The resilience analyzer" : "The engine";
  const asking = explainingId === item.id;

  return (
    <Section title="What the problem is" defaultOpen>
      {item.engineDetail ? (
        <div className="min-w-0">
          <Attribution
            icon={Cpu}
            who={engineWho}
            note="Deterministic, written from this finding's own signals by the code that computed them. No model and no network."
          />
          <p className="mt-1.5 whitespace-pre-line break-words text-[12px] leading-relaxed text-text2">
            {item.engineDetail}
          </p>
        </div>
      ) : (
        // Not "nobody has explained this": a named absence of a specific FIELD.
        <div className="border border-sev-medium-line bg-sev-medium-bg px-2.5 py-2 text-[11.5px] leading-snug text-text2">
          This build&rsquo;s API sent no <span className="mono">engine_explanation</span> for this finding. The signals it
          was computed from are below, unaltered; nothing here paraphrases them into a sentence the engine did not write.
        </div>
      )}

      {item.modelDetail ? (
        <div className="mt-3 min-w-0 border-t border-hair pt-2.5">
          <Attribution
            icon={Sparkles}
            who="The advisory layer"
            note="Prose written by a language model on request. It sits alongside the engine text above, which is unchanged and remains the record."
          />
          <p className="mt-1.5 whitespace-pre-line break-words text-[12px] leading-relaxed text-text2">
            {item.modelDetail}
          </p>
        </div>
      ) : (
        <div className="mt-2.5 space-y-1.5">
          {onExplain ? (
            <button
              type="button"
              onClick={() => onExplain(item)}
              disabled={asking}
              className="btn-ghost text-[11.5px]"
              title="Adds model prose beneath the engine's own explanation. It does not replace it."
            >
              {asking ? <Spinner label="Asking…" /> : <><Sparkles size={12} /> Ask the advisory layer for prose</>}
            </button>
          ) : null}
          {explainError ? <InlineError resource="the explanation" error={explainError} /> : null}
        </div>
      )}
    </Section>
  );
}

export function FindingSidebar(p: FindingSidebarProps) {
  const item = p.index == null ? undefined : p.items[p.index];
  const scroller = useRef<HTMLElement | null>(null);

  // A new finding starts at the top of its own panel. Carrying the previous
  // finding's scroll position over lands the reader in the middle of a
  // remediation paragraph for something they did not select.
  useEffect(() => { scroller.current?.scrollTo({ top: 0 }); }, [p.index]);

  if (p.collapsed) {
    return (
      <aside className="flex h-full w-[42px] shrink-0 flex-col items-center gap-2 border-l border-border bg-surface py-2">
        <button
          type="button"
          onClick={p.onToggleCollapsed}
          className="btn-ghost !h-7 !w-7 !px-0"
          aria-label="Expand the findings panel"
          title="Expand the findings panel"
        >
          <PanelRightOpen size={14} />
        </button>
        <div className="mono rotate-180 text-[10px] tabular-nums text-text3" style={{ writingMode: "vertical-rl" }}>
          {p.items.length === 0 ? "no findings" : `${p.items.length} findings`}
        </div>
      </aside>
    );
  }

  return (
    <aside ref={scroller} className={cn("zt-scroll flex h-full min-w-0 flex-col overflow-y-auto border-l border-border bg-surface", p.className)}>
      <header className="sticky top-0 z-10 flex shrink-0 items-center gap-1 border-b border-border bg-surface px-2.5 py-2">
        <span className="eyebrow min-w-0 truncate">Findings</span>
        <span className="mono ml-auto shrink-0 text-[11px] tabular-nums text-text2">
          {p.items.length === 0
            ? "0"
            : p.index == null
              ? `${p.items.length}`
              : `${p.index + 1} / ${p.items.length}`}
        </span>
        <button
          type="button"
          onClick={() => p.onIndex((p.index ?? 0) - 1)}
          disabled={p.items.length === 0 || p.index == null || p.index <= 0}
          className="btn-ghost !h-7 !w-7 !px-0"
          aria-label="Previous finding"
          title="Previous finding (↑ / ←)"
        >
          <ChevronLeft size={14} />
        </button>
        <button
          type="button"
          onClick={() => p.onIndex(p.index == null ? 0 : p.index + 1)}
          disabled={p.items.length === 0 || (p.index != null && p.index >= p.items.length - 1)}
          className="btn-ghost !h-7 !w-7 !px-0"
          aria-label="Next finding"
          title="Next finding (↓ / →)"
        >
          <ChevronRight size={14} />
        </button>
        <button
          type="button"
          onClick={p.onToggleCollapsed}
          className="btn-ghost !hidden !h-7 !w-7 !px-0 lg:!inline-flex"
          aria-label="Collapse the findings panel"
          title="Collapse the panel — this also clears the selection, so nothing is left dimmed"
        >
          <PanelRightClose size={14} />
        </button>
        <button
          type="button"
          onClick={p.onDismiss}
          className="btn-ghost !h-7 !w-7 !px-0"
          aria-label="Close the findings panel"
          title="Close the panel — this also clears the selection, so nothing is left dimmed"
        >
          <X size={14} />
        </button>
      </header>

      {/* Always reachable, whatever else is on screen: the way back to a canvas
          with nothing dimmed and everything clickable. */}
      {item ? (
        <div className="flex items-center gap-2 border-b border-hair bg-sunk px-3.5 py-1.5">
          <span className="min-w-0 flex-1 truncate text-[11px] text-text3">
            The canvas is showing this finding.
          </span>
          <button
            type="button"
            onClick={p.onClearSelection}
            className="btn-ghost !h-6 shrink-0 px-2 text-[10.5px]"
            title="Clear the selection (Esc). The canvas un-dims and every card is clickable again."
          >
            Clear <span className="mono ml-1 text-text3">Esc</span>
          </button>
        </div>
      ) : null}

      {/* The state of the resilience read, reported ALONGSIDE the list rather
          than instead of it. A failed read does not make the policy findings
          below untrue — it makes the list incomplete, and those are different
          sentences. */}
      {p.error ? (
        <div className="p-3">
          <ErrorState resource="the resilience analysis" error={p.error} onRetry={p.onRetry} />
          <p className="mt-2 text-[11px] leading-snug text-text3">
            Policy findings only — the resilience read failed, so its findings are missing rather than absent.
          </p>
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
          {p.notAnalysedReason ? <div className="mono mt-1.5 break-words text-[11px] text-text3">{p.notAnalysedReason}</div> : null}
        </div>
      ) : null}

      {p.items.length === 0 ? (
        p.loading && !p.error ? null : (
          <div className="p-4 text-[12px] leading-relaxed text-text2">
            {p.error
              ? "Nothing is listed: the resilience read failed, and no policy finding names a device on this canvas."
              : p.analysed === false
                ? "Nothing is listed, and nothing was analysed."
                : "The analysis ran and returned no finding that names a device on this canvas."}
            {p.skippedPolicy > 0 ? (
              <> {p.skippedPolicy} policy finding{p.skippedPolicy === 1 ? "" : "s"} in this snapshot name nothing here; they are on the Risk To-Do screen.</>
            ) : null}
          </div>
        )
      ) : item == null ? (
        <>
          <div className="px-3.5 py-3 text-[12px] leading-relaxed text-text2">
            {p.items.length} finding{p.items.length === 1 ? "" : "s"} name a device on this canvas. Pick one — or press
            the down arrow — and everything not involved dims while the path is traced hop by hop.
          </div>
          <AllFindings items={p.items} index={p.index} onIndex={p.onIndex} />
        </>
      ) : (
        <>
          <div className="min-w-0 px-3.5 py-3">
            <div className="flex flex-wrap items-center gap-1.5">
              <SeverityPill band={item.band} severity={item.severity} forced={item.forcedCritical} />
              <Chip variant={item.kind === "resilience" ? "accent" : "neutral"}>
                {item.kind === "resilience" ? "resilience" : "policy"}
              </Chip>
              <span className="mono break-all text-[10.5px] text-text3">{item.type}</span>
            </div>
            <h3 className="mt-2 break-words text-[14px] font-bold leading-snug">{item.title}</h3>
            {p.involvedOnCanvas === 0 ? (
              <p className="mt-1.5 border border-sev-medium-line bg-sev-medium-bg px-2 py-1.5 text-[11px] leading-snug text-text2">
                None of the {item.involved.length} device{item.involved.length === 1 ? "" : "s"} this finding names is
                on the canvas, so nothing is highlighted.
              </p>
            ) : null}
          </div>

          <Explanation
            item={item}
            onExplain={p.onExplain}
            explainingId={p.explainingId}
            explainError={p.explainError}
          />

          {item.blast ? (
            <Section title="Blast radius — measured, not assumed">
              <div className="border border-sev-critical-line bg-sev-critical-bg px-2.5 py-2">
                <div className="mono text-[17px] font-bold leading-none tabular-nums text-sev-critical">
                  {item.blast.paths_lost} of {item.blast.paths_before}
                </div>
                <div className="mt-1 break-words text-[11.5px] leading-snug text-text2">
                  device-to-circuit paths are lost when <span className="mono">{item.blast.device_key}</span> fails.
                </div>
                {/* The live count while the failure plays out. It counts cards
                    actually fading on the canvas, so it can never get ahead of
                    what the viewer can see, and it lands on the payload's own
                    totals rather than on an interpolation. */}
                {p.lostTotal > 0 ? (
                  <div className="mono mt-1.5 text-[11px] tabular-nums text-text2">
                    {p.replayDone ? p.lostTotal : p.lostShown} of {p.lostTotal}{" "}
                    {item.blast.circuits_stranded.length > 0 && item.blast.devices_isolated.length > 0
                      ? "circuits and devices"
                      : item.blast.circuits_stranded.length > 0
                        ? `circuit${p.lostTotal === 1 ? "" : "s"}`
                        : `device${p.lostTotal === 1 ? "" : "s"}`}{" "}
                    lose their path{p.replayDone ? "" : " …"}
                  </div>
                ) : (
                  <div className="mt-1.5 text-[11px] leading-snug text-text2">
                    No circuit is stranded and no device is left with no path at all —{" "}
                    {item.blast.devices_degraded} lose a path they had. Nothing fades on the canvas because nothing is
                    cut off; the cost here is redundancy, not reachability.
                  </div>
                )}
              </div>
              <div className="mt-2">
                {blastLines(item.blast).map((l) => (
                  <KV key={l.label} k={l.label} v={l.value} mono={l.label !== "Circuits stranded"} />
                ))}
              </div>
              {item.lost.length > 0 ? (
                <div className="mt-1.5 flex flex-wrap gap-1">
                  {item.lost.map((d) => (
                    <span key={d} className="mono max-w-full truncate border border-border bg-sunk px-1 text-[10px] text-text2" title={d}>
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
          ) : item.failing.length > 0 ? (
            // A finding scored over the loss of SEVERAL elements at once. The
            // engine measured a combined cut for it; this payload carries only
            // per-device radii, and not one of them is the number behind the
            // vector below. So the failure is shown and the radius is not —
            // printing the nearest-looking row would be a real number answering
            // a different question.
            <Section title="Simultaneous failure">
              <div className="border border-sev-critical-line bg-sev-critical-bg px-2.5 py-2">
                <div className="break-words text-[11.5px] leading-snug text-text2">
                  {item.failing.length} element{item.failing.length === 1 ? "" : "s"} fail together:{" "}
                  {item.failing.map((f, i) => (
                    <span key={f}>
                      {i > 0 ? ", " : ""}
                      <span className="mono text-text">{p.nameFor(f)}</span>
                    </span>
                  ))}
                  . The severity below was measured over losing all of them at once.
                </div>
                {p.lostTotal > 0 ? (
                  <div className="mono mt-1.5 text-[11px] tabular-nums text-text2">
                    {p.replayDone ? p.lostTotal : p.lostShown} of {p.lostTotal} circuit
                    {p.lostTotal === 1 ? "" : "s"} lose their path{p.replayDone ? "" : " …"}
                  </div>
                ) : null}
              </div>
              {item.circuits.length > 0 ? (
                <div className="mt-1.5 flex flex-wrap gap-1">
                  {item.circuits.map((c) => (
                    <span key={c} className="mono max-w-full truncate border border-border bg-sunk px-1 text-[10px] text-text2">
                      {c}
                    </span>
                  ))}
                </div>
              ) : null}
              <p className="mt-2 text-[11px] leading-snug text-text3">
                No blast radius is printed here. This response carries a radius per DEVICE, and a combined failure has
                its own — the one the R term below was measured from. It is not in the payload, so it is not shown.
              </p>
              <button type="button" onClick={p.onReplay} className="btn-ghost mt-2 text-[11.5px]">
                <RotateCw size={12} /> Replay the failure
              </button>
            </Section>
          ) : null}

          {Object.keys(item.vector).length > 0 ? (
            <Section title={item.kind === "resilience" ? "Severity vector" : "Signals the engine computed this from"}>
              {item.kind === "resilience" ? (
                <>
                  <p className="mono mb-1 break-words text-[10.5px] leading-snug text-text3">
                    severity = round(100 × min(1, R × L × S))
                  </p>
                  <p className="mb-1.5 text-[10.5px] leading-snug text-text3">
                    R is the share of circuit reachability this failure destroys, measured
                    {item.combinedFailure ? " over the simultaneous loss of every element named above" : ""}; L is how
                    long it stays destroyed, by lane; S is how much the redundancy that should cover it is nominal
                    rather than real. Recomputable by hand from these three.
                  </p>
                </>
              ) : null}
              <SignalList signals={item.vector} />
            </Section>
          ) : null}

          {item.ruleRefs.length > 0 ? (
            <Section title="Rule references" defaultOpen count={item.ruleRefs.length}>
              {/* RuleTokens, not RuleRef. RuleRef anchors its card with
                  `absolute`, and this sidebar is `overflow-y-auto` -- an
                  absolutely-positioned child is clipped by a scrolling
                  ancestor's overflow box no matter what its z-index is, so the
                  rule card was cut off at the panel edge. `right-0` made it
                  worse by pushing a 300px card off the left side. RuleToken
                  portals to the body with a viewport-clamped fixed position,
                  which cannot be clipped by anything, and it carries the
                  direction chip and the full rule card the Risk To-Do panel
                  shows -- so the two screens now explain a rule identically. */}
              <RuleTokens refs={item.ruleRefs} snapshot={p.snapshot} />
            </Section>
          ) : null}

          {item.rawRefs.length > 0 ? (
            <Section title="Raw references" count={item.rawRefs.length}>
              <div className="flex flex-wrap gap-1">
                {item.rawRefs.map((r) => (
                  <span key={r} className="mono max-w-full truncate border border-border bg-sunk px-1 text-[10px] text-text2" title={r}>
                    {r}
                  </span>
                ))}
              </div>
              <p className="mt-1 text-[10.5px] leading-snug text-text3">
                Device keys and circuit ids, not rule references — the records this finding was computed from.
              </p>
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

          <Section title="Remediation" defaultOpen>
            {item.remediation ? (
              <div className="flex gap-2">
                <Wrench size={13} className="mt-0.5 shrink-0 text-accent-fg" />
                <p className="min-w-0 break-words text-[12px] leading-relaxed text-text2">{item.remediation}</p>
              </div>
            ) : (
              <p className="text-[12px] leading-relaxed text-text3">
                {item.kind === "resilience"
                  ? "This build's resilience payload carries no remediation sentence for this finding. What the fix is follows from the finding itself — a second path that does not share the element named above — and it is not invented here."
                  : "A proposed change for a policy finding is generated on the Risk To-Do screen, where it is validated against the engine before it can be submitted."}
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
