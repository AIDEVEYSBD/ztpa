"use client";

/**
 * AN EXPANDABLE RULE REFERENCE.
 *
 * The direct note was: "in the risk to do page the remediation part Rule number
 * should have details also there for viewer understanding." So a rule number is
 * never a bare token anywhere on this screen — every one of them opens the
 * rule.
 *
 * WHY A PORTAL. These tokens live inside dense, clickable rows and inside
 * `<span>`-only contexts; an absolutely-positioned child inherits the row's
 * overflow clipping and its click handler, and a `<div>` card cannot legally
 * nest inside a `<span>`. Rendering the card into `document.body` sidesteps all
 * three, so the same token works in a table row, a chip strip and a sentence.
 */

import { useCallback, useEffect, useLayoutEffect, useRef, useState } from "react";
import { createPortal } from "react-dom";
import { ChevronDown } from "lucide-react";
import type { RuleContext } from "@/lib/api";
import { cn } from "@/lib/cn";
import { Skeleton } from "@/components/ui";
import { DirectionChip } from "./direction";
import { RuleBody, RuleUnavailable, rowFor } from "./RuleCard";
import { primaryContext, useRule } from "./useRule";

const CARD_W = 460;

/**
 * The resolved rule, rendered. Used inline (the side panel's "the rule" step)
 * and inside the token's popover, so both are literally the same component
 * rather than two drifting designs of one thing.
 */
export function RuleFull({ refId, snapshot, compact, depth = 0 }: {
  refId: string;
  snapshot?: string;
  compact?: boolean;
  /** Guards the reverse-rule token from opening its own reverse token forever. */
  depth?: number;
}) {
  const { detail, context, loading, error, retry } = useRule(refId, snapshot);

  if (loading && !detail) {
    return (
      <div className="space-y-1.5 border border-border bg-surface2 p-2.5">
        <Skeleton className="h-3.5 w-40" />
        <Skeleton className="h-3 w-full" />
        <Skeleton className="h-3 w-2/3" />
      </div>
    );
  }
  if (error || !context?.length) {
    return <RuleUnavailable refId={refId} error={error} onRetry={retry} />;
  }
  return (
    <div className="divide-y divide-hair border border-border bg-surface2">
      {context.map((ctx) => (
        <RuleBody
          key={`${ctx.tool}:${ctx.raw_ref}`}
          ctx={ctx}
          row={rowFor(ctx, detail?.rules)}
          compact={compact}
          reverseSlot={
            ctx.direction.reverse_ref
              ? (depth > 0
                  // Stop at one hop: the reverse of a reverse is this rule, and
                  // an infinitely nestable card is a way to lose the reviewer.
                  ? <span className="mono text-text2">{ctx.direction.reverse_ref}</span>
                  : <RuleToken refId={ctx.direction.reverse_ref} snapshot={snapshot} depth={depth + 1} />)
              : undefined
          }
        />
      ))}
    </div>
  );
}

/** The clickable reference itself. */
export function RuleToken({ refId, snapshot, tone = "quiet", depth = 0, className }: {
  refId: string;
  snapshot?: string;
  /** `loud` is used where the reference IS the subject (a remediation target). */
  tone?: "quiet" | "loud";
  depth?: number;
  className?: string;
}) {
  const [open, setOpen] = useState(false);
  const anchor = useRef<HTMLButtonElement>(null);
  const [pos, setPos] = useState<{ left: number; top?: number; bottom?: number } | null>(null);
  // Only fetched once the token has been opened at least once: a list of forty
  // references must not fire forty requests to draw forty chips.
  const [armed, setArmed] = useState(false);
  const { context } = useRule(refId, snapshot, armed);

  const place = useCallback(() => {
    const el = anchor.current;
    if (!el) return;
    const r = el.getBoundingClientRect();
    const left = Math.min(Math.max(8, r.left), Math.max(8, window.innerWidth - CARD_W - 8));
    // Below by default; above when the viewport bottom is closer than the card.
    // Flipping up anchors the card's BOTTOM edge to the token: computing a `top`
    // from an assumed height leaves a short card floating away from the
    // reference it explains.
    setPos(window.innerHeight - r.bottom > 320
      ? { left, top: r.bottom + 6 }
      : { left, bottom: Math.max(8, window.innerHeight - r.top + 6) });
  }, []);

  useLayoutEffect(() => { if (open) place(); }, [open, place]);

  useEffect(() => {
    if (!open) return;
    // Any scroll or resize invalidates a fixed position computed from a rect,
    // and a card left floating beside the wrong row is worse than a closed one.
    const close = () => setOpen(false);
    const onKey = (e: KeyboardEvent) => { if (e.key === "Escape") setOpen(false); };
    window.addEventListener("scroll", close, true);
    window.addEventListener("resize", close);
    window.addEventListener("keydown", onKey);
    return () => {
      window.removeEventListener("scroll", close, true);
      window.removeEventListener("resize", close);
      window.removeEventListener("keydown", onKey);
    };
  }, [open]);

  const ctx: RuleContext | undefined = primaryContext(context);

  return (
    <>
      <button
        ref={anchor}
        type="button"
        onClick={(e) => { e.stopPropagation(); setArmed(true); setOpen((o) => !o); }}
        onMouseEnter={() => setArmed(true)}
        aria-expanded={open}
        title={`Open rule ${refId}`}
        className={cn("mono inline-flex h-[18px] max-w-full shrink-0 items-center gap-1 border px-1 text-[10px] font-bold leading-none transition-colors",
          tone === "loud"
            ? "border-borderStrong bg-surface2 text-text hover:border-accent hover:text-accent-fg"
            : "border-border bg-sunk text-text2 hover:border-accent hover:text-accent-fg",
          open && "border-accent text-accent-fg",
          className)}
      >
        {/* The flow colour is on the token once the rule is known, so a strip of
            references reads as directions before anything is expanded. It is
            NEVER guessed: no swatch until the engine has answered. */}
        {ctx && <span aria-hidden className={cn("h-1.5 w-1.5 shrink-0", ctxSwatch(ctx))} />}
        <span className="truncate">{refId}</span>
        <ChevronDown size={9} className={cn("shrink-0 opacity-60 transition-transform", open && "rotate-180")} />
      </button>

      {open && pos && typeof document !== "undefined" && createPortal(
        <>
          <div className="fixed inset-0 z-[70]" onClick={() => setOpen(false)} />
          <div
            role="dialog"
            aria-label={`Rule ${refId}`}
            style={{ top: pos.top, bottom: pos.bottom, left: pos.left, width: CARD_W }}
            className="popover zt-scroll fixed z-[71] max-h-[min(420px,80vh)] max-w-[calc(100vw-16px)] overflow-y-auto"
            onClick={(e) => e.stopPropagation()}
          >
            <div className="flex items-center gap-2 border-b border-hair px-2.5 py-1.5">
              <span className="text-[9.5px] font-bold uppercase tracking-[0.14em] text-text3">the rule</span>
              {ctx && <DirectionChip size="sm" refId={ctx.raw_ref} direction={ctx.direction} />}
              <button onClick={() => setOpen(false)} className="ml-auto text-[10px] font-bold uppercase tracking-[0.08em] text-text3 hover:text-text">
                close
              </button>
            </div>
            <div className="p-2">
              <RuleFull refId={refId} snapshot={snapshot} depth={depth} />
            </div>
          </div>
        </>,
        document.body,
      )}
    </>
  );
}

function ctxSwatch(ctx: RuleContext): string {
  switch (ctx.direction.flow) {
    case "inbound": return "bg-sev-critical";
    case "outbound": return "bg-sev-high";
    case "transit": return "bg-sev-medium";
    case "internal": return "bg-info";
    default: return "bg-borderStrong";
  }
}

/** A strip of references. */
export function RuleTokens({ refs, snapshot, tone, className }: {
  refs: string[]; snapshot?: string; tone?: "quiet" | "loud"; className?: string;
}) {
  return (
    <span className={cn("inline-flex flex-wrap items-center gap-1", className)}>
      {refs.map((r) => <RuleToken key={r} refId={r} snapshot={snapshot} tone={tone} />)}
    </span>
  );
}
