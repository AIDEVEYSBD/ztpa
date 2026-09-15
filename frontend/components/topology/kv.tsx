"use client";

/**
 * Label/value rows that cannot overlap — and the renderer for a finding's raw
 * signal bag.
 *
 * WHAT WAS WRONG. The old `KV` was
 *
 *     <div className="flex items-baseline justify-between gap-3">
 *       <span className="min-w-0 text-text3">{k}</span>
 *       <span className="shrink-0 text-right">{v}</span>
 *
 * and `shrink-0` on the VALUE is the bug: a long value refuses to shrink, the
 * flex line overflows, and the label — which was the only thing allowed to
 * shrink — is run over by it. Both ends then render on top of each other. The
 * `reasons` signal (a JSON array of three sentences) hit it every time.
 *
 * THE RULE HERE. The label is short, known and never truncated, so it is the
 * thing that holds its width; the value is the thing that wraps. A value too
 * long to sit beside its label moves BELOW it instead of squeezing it, and a
 * value long enough to be a wall of text collapses behind a disclosure that
 * still carries the whole string — truncation with the full value one click (or
 * one hover) away, never truncation that loses it.
 *
 * And a signal bag is not a bag of strings: `reasons` is an array, `hops` is an
 * array of objects, `exposed_ports` is frequently null. Each renders as itself,
 * because `String(v)` on an object produces `[object Object]` and `JSON
 * .stringify` on a 4-hop path produces 900 characters with nowhere to go.
 */

import { useState } from "react";
import { ChevronDown, ChevronRight } from "lucide-react";
import { cn } from "@/lib/cn";

/** Beyond this a value goes under its label rather than beside it. */
const INLINE_MAX = 34;
/** Beyond this a value is collapsed behind a disclosure. */
const FOLD_MAX = 260;

function Label({ children, title }: { children: React.ReactNode; title?: string }) {
  return (
    <span className="shrink-0 text-[11.5px] leading-[1.5] text-text3" title={title}>
      {children}
    </span>
  );
}

export interface KVProps {
  k: string;
  v: string;
  mono?: boolean;
  /** Long-form explanation of the key, on hover. */
  hint?: string;
  className?: string;
}

/**
 * One label/value row. Short values sit beside the label; long ones stack under
 * it and wrap. Neither can ever overrun the other.
 */
export function KV({ k, v, mono = true, hint, className }: KVProps) {
  const stack = v.length > INLINE_MAX;
  const valueCls = cn("min-w-0 break-words text-[11.5px] leading-[1.5] text-text", mono && "mono tabular-nums");

  if (stack) {
    return (
      <div className={cn("py-[3px]", className)}>
        <Label title={hint}>{k}</Label>
        <div className={cn(valueCls, "mt-0.5 whitespace-pre-wrap")} title={v}>
          {v}
        </div>
      </div>
    );
  }
  return (
    <div className={cn("flex items-baseline justify-between gap-3 py-[3px]", className)}>
      <Label title={hint}>{k}</Label>
      <span className={cn(valueCls, "text-right")} title={v}>
        {v}
      </span>
    </div>
  );
}

/** A value the payload carries as `null`. Not zero, not false, not "none". */
function NullValue({ k }: { k: string }) {
  return (
    <span
      className="mono text-[11.5px] text-text3"
      title={`The payload carries ${k} as null. That is "no value", not zero and not false.`}
    >
      —
    </span>
  );
}

function Foldable({ label, text, count }: { label: string; text: string; count?: string }) {
  const [open, setOpen] = useState(false);
  return (
    <div className="py-[3px]">
      <button
        type="button"
        onClick={() => setOpen((o) => !o)}
        aria-expanded={open}
        className="flex w-full items-baseline gap-1 text-left"
      >
        {open ? (
          <ChevronDown size={11} className="mt-[3px] shrink-0 text-text3" />
        ) : (
          <ChevronRight size={11} className="mt-[3px] shrink-0 text-text3" />
        )}
        <span className="min-w-0 flex-1 text-[11.5px] leading-[1.5] text-text3">{label}</span>
        <span className="mono shrink-0 text-[10.5px] text-text2">{count ?? `${text.length} chars`}</span>
      </button>
      {open ? (
        <pre className="zt-scroll mono mt-1 max-h-60 overflow-auto whitespace-pre-wrap break-words border border-border bg-sunk p-2 text-[10.5px] leading-[1.45] text-text2">
          {text}
        </pre>
      ) : null}
    </div>
  );
}

/** Is every member of this array a scalar we can print on its own line? */
function isScalarArray(v: unknown[]): v is (string | number | boolean)[] {
  return v.every((x) => typeof x === "string" || typeof x === "number" || typeof x === "boolean");
}

/**
 * One row of a finding's `signals` (or of a resilience severity vector),
 * rendered as whatever it actually is.
 */
export function SignalRow({ k, v }: { k: string; v: unknown }) {
  if (v === null || v === undefined) {
    return (
      <div className="flex items-baseline justify-between gap-3 py-[3px]">
        <Label>{k}</Label>
        <NullValue k={k} />
      </div>
    );
  }

  if (Array.isArray(v)) {
    if (v.length === 0) {
      return <KV k={k} v="empty list" mono={false} hint="The payload carries this signal as an empty array." />;
    }
    if (isScalarArray(v)) {
      // `reasons` — the row that used to overlap. Each entry gets its own line
      // and wraps; nothing is squeezed against the label.
      return (
        <div className="py-[3px]">
          <div className="flex items-baseline justify-between gap-3">
            <Label>{k}</Label>
            <span className="mono shrink-0 text-[10.5px] text-text3">{v.length}</span>
          </div>
          <ul className="mt-0.5 space-y-0.5">
            {v.map((x, i) => (
              <li key={i} className="flex gap-1.5 text-[11.5px] leading-[1.45] text-text">
                <span aria-hidden className="mt-[7px] h-[3px] w-[3px] shrink-0 bg-text3" />
                <span className="mono min-w-0 break-words">{String(x)}</span>
              </li>
            ))}
          </ul>
        </div>
      );
    }
    return <Foldable label={k} text={JSON.stringify(v, null, 2)} count={`${v.length} entries`} />;
  }

  if (typeof v === "object") {
    const entries = Object.entries(v as Record<string, unknown>);
    if (entries.length === 0) {
      return <KV k={k} v="empty object" mono={false} hint="The payload carries this signal as an empty object." />;
    }
    // A small flat object (a severity vector) is worth reading inline.
    const flat = entries.every(([, x]) => x === null || typeof x !== "object");
    if (flat && entries.length <= 6) {
      return (
        <div className="py-[3px]">
          <Label>{k}</Label>
          <div className="mt-0.5 border-l border-border pl-2">
            {entries.map(([ek, ev]) => (
              <SignalRow key={ek} k={ek} v={ev} />
            ))}
          </div>
        </div>
      );
    }
    return <Foldable label={k} text={JSON.stringify(v, null, 2)} count={`${entries.length} fields`} />;
  }

  const s = String(v);
  if (s.length > FOLD_MAX) return <Foldable label={k} text={s} />;
  return <KV k={k} v={s} mono={typeof v !== "string" || s.length <= INLINE_MAX} />;
}

/** The whole bag, in a stable order: the payload's own key order, which is the
 *  order the analyzer wrote them in. */
export function SignalList({ signals }: { signals: Record<string, unknown> }) {
  const entries = Object.entries(signals);
  if (entries.length === 0) return null;
  return (
    <div className="min-w-0">
      {entries.map(([k, v]) => (
        <SignalRow key={k} k={k} v={v} />
      ))}
    </div>
  );
}
