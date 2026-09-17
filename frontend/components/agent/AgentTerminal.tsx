"use client";

/**
 * What the agent did, as a terminal.
 *
 * Every screen where the advisory layer works shows a conclusion. This shows
 * the work: which provider answered on which model, how long it took, what was
 * sent, what came back, which tool ran between calls, and where a deterministic
 * fallback took over. One component, used everywhere that happens, so the
 * reader learns to read it once.
 *
 * A FAILED CALL IS A STEP, drawn as loudly as a successful one. This product
 * spent days serving deterministic fallbacks against a placeholder API key --
 * correct behaviour, and indistinguishable on screen from a model that had
 * answered. The header says "no model answered" when that is what happened, and
 * it is computed from whether a call actually succeeded rather than from a
 * `by` label that can still mention an llm on a fallback path.
 *
 * Collapsed by default. It is evidence for a reader who wants it, not the
 * answer, and the answer is above it.
 */

import { useState } from "react";
import { ChevronRight, Cpu, Terminal, Wrench, CornerDownRight, AlertTriangle } from "lucide-react";
import { cn } from "@/lib/cn";
import type { AgentStep } from "@/lib/types";

export type { AgentStep };


const GLYPH: Record<AgentStep["kind"], { icon: typeof Cpu; sigil: string }> = {
  model_call: { icon: Cpu, sigil: "$" },
  tool: { icon: Wrench, sigil: "⚙" },
  deduction: { icon: CornerDownRight, sigil: "⊢" },
  fallback: { icon: AlertTriangle, sigil: "!" },
  note: { icon: CornerDownRight, sigil: "·" },
};

function ms(n?: number | null) {
  if (n == null) return null;
  return n >= 1000 ? `${(n / 1000).toFixed(1)}s` : `${n}ms`;
}

/** One verbatim block of the exchange. Pre-wrapped and scrollable: a prompt is
 *  worth showing exactly, and exactly is often long. */
function Payload({ title, body, chars }: { title: string; body?: string | null; chars?: number }) {
  if (!body) return null;
  return (
    <div className="min-w-0">
      <div className="flex items-baseline gap-2">
        <span className="text-[9.5px] font-bold uppercase tracking-[0.1em] text-text3">{title}</span>
        <span className="mono text-[9.5px] text-text3">{chars ?? body.length} chars</span>
      </div>
      <pre className="zt-scroll mono mt-1 max-h-[220px] overflow-auto whitespace-pre-wrap break-words border border-hair bg-bg px-2 py-1.5 text-[10.5px] leading-relaxed text-text2">
        {body}
      </pre>
    </div>
  );
}

function StepRow({ s }: { s: AgentStep }) {
  const [open, setOpen] = useState(false);
  const failed = s.ok === false;
  const isCall = s.kind === "model_call";
  const g = GLYPH[s.kind] ?? GLYPH.note;
  // Only a model call has an exchange to drill into. Everything else is fully
  // described by its own line, and a disclosure that opens onto nothing is
  // worse than no disclosure.
  const expandable = isCall && !!(s.system || s.user || s.response || s.error);

  return (
    <li className={cn("border-t border-hair first:border-t-0", failed && "bg-sev-high-bg/40")}>
      <div
        role={expandable ? "button" : undefined}
        tabIndex={expandable ? 0 : undefined}
        aria-expanded={expandable ? open : undefined}
        onClick={expandable ? () => setOpen((v) => !v) : undefined}
        onKeyDown={expandable ? (e) => {
          if (e.key === "Enter" || e.key === " ") { e.preventDefault(); setOpen((v) => !v); }
        } : undefined}
        className={cn("flex items-baseline gap-2 px-2 py-1", expandable && "cursor-pointer hover:bg-surface-hover")}
      >
        <span aria-hidden className={cn("mono w-3 shrink-0 text-[11px]",
          failed ? "text-sev-high" : isCall ? "text-accent-fg" : "text-text3")}>
          {g.sigil}
        </span>
        <span className={cn("mono min-w-0 flex-1 break-words text-[11px]", failed ? "text-sev-high" : "text-text2")}>
          {s.label}
        </span>
        {s.ms != null && <span className="mono shrink-0 text-[10px] tabular-nums text-text3">{ms(s.ms)}</span>}
        {failed && (
          <span className="shrink-0 border border-sev-high-line px-1 text-[9px] font-bold uppercase text-sev-high">
            failed
          </span>
        )}
        {expandable && (
          <ChevronRight size={11}
            className={cn("shrink-0 text-text3 transition-transform", open && "rotate-90")} />
        )}
      </div>

      {/* The model's own words for why it proposed what it did. Shown inline
          rather than behind a disclosure: it is the step's content. */}
      {s.detail && (
        <div className="px-2 pb-1.5 pl-7 text-[10.5px] leading-snug text-text3">{s.detail}</div>
      )}

      {open && (
        <div className="space-y-2 border-t border-hair bg-sunk px-2 py-2 pl-7">
          <div className="flex flex-wrap items-baseline gap-x-3 gap-y-1 text-[10px] text-text3">
            {s.provider && <span>provider <span className="mono text-text2">{s.provider}</span></span>}
            {s.model && <span>model <span className="mono text-text2">{s.model}</span></span>}
            {s.prompt_tokens != null && <span>prompt <span className="mono text-text2">{s.prompt_tokens}</span></span>}
            {s.completion_tokens != null && <span>completion <span className="mono text-text2">{s.completion_tokens}</span></span>}
          </div>
          {s.error && (
            <div className="border border-sev-high-line bg-sev-high-bg px-2 py-1 text-[10.5px] text-sev-high">
              {s.error}
            </div>
          )}
          <Payload title="sent · system" body={s.system} />
          <Payload title="sent · user" body={s.user} />
          <Payload title="received" body={s.response} />
          {s.truncated && (
            <p className="text-[10px] text-text3">
              Payloads over 12,000 characters are cut here. The call itself sent and received the whole thing.
            </p>
          )}
        </div>
      )}
    </li>
  );
}

export interface AgentTerminalProps {
  steps?: AgentStep[] | null;
  /** Whether a model call actually SUCCEEDED. Never inferred from a `by` label. */
  usedAModel?: boolean;
  /** What this trace is of, e.g. "drafting a fix". Shown in the header. */
  what?: string;
  className?: string;
  defaultOpen?: boolean;
}

export function AgentTerminal({
  steps, usedAModel, what = "the agent's work", className, defaultOpen = false,
}: AgentTerminalProps) {
  const [open, setOpen] = useState(defaultOpen);
  if (!steps || steps.length === 0) return null;

  const calls = steps.filter((s) => s.kind === "model_call");
  const okCalls = calls.filter((s) => s.ok !== false);
  const model = okCalls[0]?.model ?? calls[0]?.model;
  const provider = okCalls[0]?.provider ?? calls[0]?.provider;
  const total = steps.reduce((n, s) => n + (s.ms ?? 0), 0);
  // `usedAModel` is authoritative when the caller supplies it; otherwise fall
  // back to the same question, asked of the steps.
  const modelled = usedAModel ?? okCalls.length > 0;

  return (
    <div className={cn("border border-border bg-sunk", className)}>
      <button
        type="button"
        onClick={() => setOpen((v) => !v)}
        aria-expanded={open}
        className="flex w-full flex-wrap items-center gap-x-2 gap-y-1 px-2.5 py-1.5 text-left hover:bg-surface-hover"
      >
        <ChevronRight size={11} className={cn("shrink-0 text-text3 transition-transform", open && "rotate-90")} />
        <Terminal size={12} className="shrink-0 text-text3" />
        <span className="text-[10px] font-bold uppercase tracking-[0.08em] text-text2">Agent trace</span>
        <span className="mono text-[10.5px] text-text3">
          {steps.length} step{steps.length === 1 ? "" : "s"}
          {calls.length > 0 && ` · ${calls.length} model call${calls.length === 1 ? "" : "s"}`}
          {total > 0 && ` · ${ms(total)}`}
        </span>
        <span className="ml-auto shrink-0">
          {modelled ? (
            <span className="mono border border-accent bg-accent-soft px-1 text-[9.5px] font-bold text-accent-fg">
              {provider}{model ? ` · ${model}` : ""}
            </span>
          ) : (
            // The load-bearing state. No model answered, so the output above is
            // the engine's deterministic work -- and saying so is the whole
            // reason this header is computed from the calls rather than a label.
            <span className="mono border border-border px-1 text-[9.5px] font-bold text-text3"
              title="Every model call failed or none was made. The answer above is the engine's deterministic fallback.">
              no model answered
            </span>
          )}
        </span>
      </button>

      {open && (
        <>
          <div className="border-t border-hair px-2.5 py-1 text-[10px] text-text3">
            {what} — click a <span className="mono">$</span> line to see what was sent and what came back.
          </div>
          <ol className="min-w-0">
            {steps.map((s, i) => <StepRow key={`${i}-${s.label}`} s={s} />)}
          </ol>
        </>
      )}
    </div>
  );
}

export default AgentTerminal;
