"use client";

/**
 * The instrument furniture this screen shares with Inventory and Explorer.
 *
 * Risk To-Do was the last screen still speaking the old language — big airy
 * cards, no figure row, a page that ran out of content halfway down. These are
 * the same primitives the rebuilt screens use: one hairline readout block with
 * big mono figures, and squared facet chips with their counts on them.
 *
 * THE NULL RULE TRAVELS WITH THEM. A figure whose source did not load is an
 * em-dash carrying its reason, never a 0 — "no change has been approved" and
 * "we could not read the change log" are different sentences, and only one of
 * them is safe to put in front of a client.
 */

import type { ReactNode } from "react";
import { cn } from "@/lib/cn";

export type FigureSpec = {
  key: string;
  label: string;
  /** `null` = the source for this figure did not load. Renders as —, not 0. */
  value: number | null;
  /** Why it is unknown, said on hover when `value` is null. */
  unknown?: string;
  icon?: ReactNode;
  /** Severity/state token class for the figure itself, e.g. "text-sev-critical". */
  tone?: string;
  onClick?: () => void;
  active?: boolean;
};

export function Readout({ title, note, figures, className }: {
  title: string;
  note?: ReactNode;
  figures: FigureSpec[];
  className?: string;
}) {
  return (
    <div className={cn("border border-border bg-surface2", className)} style={{ borderTopWidth: 2, borderTopColor: "var(--accent)" }}>
      <div className="flex flex-wrap items-center justify-between gap-x-4 gap-y-1 border-b border-hair px-3.5 py-2">
        <span className="eyebrow">{title}</span>
        {note ? <span className="text-[10.5px] text-text3">{note}</span> : null}
      </div>
      <div className={cn("grid gap-px bg-border", figures.length > 5 ? "grid-cols-2 sm:grid-cols-3 xl:grid-cols-6" : "grid-cols-2 sm:grid-cols-3 xl:grid-cols-5")}>
        {figures.map((f) => {
          const body = (
            <>
              <span className="flex items-center gap-1.5 text-[9.5px] font-bold uppercase tracking-[0.16em] text-text3">
                {f.icon ? <span className="shrink-0">{f.icon}</span> : null}
                {f.label}
              </span>
              {f.value === null ? (
                <span
                  className="mono cursor-help text-[26px] font-bold leading-none tracking-[-0.02em] text-text3 underline decoration-dotted decoration-1 underline-offset-[6px]"
                  title={f.unknown ?? "The source for this figure did not load. This is unknown, not zero."}
                  aria-label={`${f.label}: unknown`}
                >
                  —
                </span>
              ) : (
                <span className={cn("mono text-[26px] font-bold leading-none tracking-[-0.02em] tabular-nums", f.tone)}
                  aria-label={`${f.value} ${f.label}`}>
                  {f.value.toLocaleString()}
                </span>
              )}
            </>
          );
          return f.onClick ? (
            <button key={f.key} onClick={f.onClick} data-active={f.active || undefined}
              className={cn("flex flex-col items-start gap-2 px-3.5 py-3 text-left transition-colors",
                f.active ? "bg-accent-soft" : "bg-surface2 hover:bg-surfaceHover")}>
              {body}
            </button>
          ) : (
            <div key={f.key} className="flex flex-col gap-2 bg-surface2 px-3.5 py-3">{body}</div>
          );
        })}
      </div>
    </div>
  );
}

/** A squared facet chip with its count — the Inventory filter vocabulary. */
export function FacetChip({ label, n, active, onClick, swatch, title, className }: {
  label: string;
  n?: number | null;
  active?: boolean;
  onClick?: () => void;
  /** A colour square, for facets that also have a colour elsewhere on screen. */
  swatch?: string;
  title?: string;
  className?: string;
}) {
  return (
    <button type="button" onClick={onClick} data-active={active || undefined} title={title}
      className={cn("inline-flex h-[24px] items-center gap-1.5 border px-2 text-[11px] font-bold transition-colors first-letter:uppercase",
        active ? "border-accent bg-accent-soft text-accent-fg" : "border-border bg-sunk text-text2 hover:border-borderStrong hover:text-text",
        className)}>
      {swatch && <span aria-hidden className={cn("h-1.5 w-1.5 shrink-0", swatch)} />}
      {label}
      {n !== undefined && (
        <span className="mono font-normal tabular-nums text-text3">{n === null ? "—" : n}</span>
      )}
    </button>
  );
}

/** A labelled strip of facets, matching the Inventory filter block. */
export function FacetRow({ label, children, className }: { label: string; children: ReactNode; className?: string }) {
  return (
    <div className={cn("flex flex-wrap items-center gap-x-3 gap-y-1.5", className)}>
      <span className="w-[74px] shrink-0 text-[9.5px] font-bold uppercase tracking-[0.14em] text-text3">{label}</span>
      <span className="flex min-w-0 flex-wrap items-center gap-1">{children}</span>
    </div>
  );
}

/** A numbered step header inside the side panel. The panel tells one story end
 *  to end, and the numbers are what make it read as a sequence rather than as a
 *  pile of sections. */
export function Step({ n, title, note, action, children, tone }: {
  n: number;
  title: string;
  note?: ReactNode;
  action?: ReactNode;
  children?: ReactNode;
  /** Border-colour class for a step that carries a verdict. */
  tone?: string;
}) {
  return (
    <section className={cn("border border-border bg-surface2", tone)}>
      <header className="flex flex-wrap items-center gap-2 border-b border-hair px-3 py-2">
        <span className="mono grid h-[19px] w-[19px] shrink-0 place-items-center bg-accent text-[10.5px] font-bold text-accent-ink">{n}</span>
        <h3 className="text-[11px] font-bold uppercase tracking-[0.12em]">{title}</h3>
        {note ? <span className="text-[10.5px] text-text3">{note}</span> : null}
        {action ? <span className="ml-auto shrink-0">{action}</span> : null}
      </header>
      {children ? <div className="p-3">{children}</div> : null}
    </section>
  );
}
