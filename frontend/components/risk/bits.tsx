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
import { hueFor } from "@/lib/hue";

export type FigureSpec = {
  key: string;
  label: string;
  /** `null` = the source for this figure did not load. Renders as —, not 0. */
  value: number | null;
  /** Why it is unknown, said on hover when `value` is null. */
  unknown?: string;
  icon?: ReactNode;
  /** Tone class for the figure itself, e.g. "text-err". */
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
    <div className={cn("overflow-hidden rounded-lg border border-line bg-surface elev-1", className)}>
      <div
        data-hue={hueFor(title)}
        data-hue-bar=""
        className="flex flex-wrap items-center justify-between gap-x-4 gap-y-1 border-b border-line bg-raise/55 px-4 py-2.5"
      >
        <span className="text-[12.5px] font-semibold tracking-[-0.005em]">{title}</span>
        {note ? <span className="text-[11px] leading-[1.55] text-faint">{note}</span> : null}
      </div>
      <div className={cn("grid", figures.length > 5 ? "grid-cols-2 sm:grid-cols-3 xl:grid-cols-6" : "grid-cols-2 sm:grid-cols-3 xl:grid-cols-5")}>
        {figures.map((f) => {
          const body = (
            <>
              <span className="flex items-center gap-1.5 truncate text-[10.5px] text-faint">
                {f.icon ? <span className="shrink-0">{f.icon}</span> : null}
                {f.label}
              </span>
              {f.value === null ? (
                <span
                  className="tnum cursor-help text-[22px] leading-none font-semibold tracking-[-0.02em] text-ghost underline decoration-dotted decoration-1 underline-offset-[6px]"
                  title={f.unknown ?? "The source for this figure did not load. This is unknown, not zero."}
                  aria-label={`${f.label}: unknown`}
                >
                  unknown
                </span>
              ) : (
                <span className={cn("tnum text-[22px] leading-none font-semibold tracking-[-0.02em]", f.tone)}
                  aria-label={`${f.value} ${f.label}`}>
                  {f.value.toLocaleString("en-GB")}
                </span>
              )}
            </>
          );
          return f.onClick ? (
            <button key={f.key} onClick={f.onClick} data-active={f.active || undefined}
              className={cn("focusable -mr-px -mb-px flex cursor-pointer flex-col items-start gap-1 border-r border-b border-line px-3 py-2.5 text-left",
                f.active ? "bg-raise/80" : "hover:bg-raise/50")}>
              {body}
            </button>
          ) : (
            <div key={f.key} className="-mr-px -mb-px flex flex-col gap-1 border-r border-b border-line px-3 py-2.5">{body}</div>
          );
        })}
      </div>
    </div>
  );
}

/** A facet chip with its count — a button, never a dropdown. */
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
      className={cn("focusable inline-flex h-7 cursor-pointer items-center gap-1.5 rounded-sm border px-2.5 text-[12px] font-medium whitespace-nowrap transition-colors duration-100 first-letter:uppercase",
        active ? "border-transparent bg-ink text-on-ink" : "border-line bg-surface text-dim hover:bg-raise hover:text-fg",
        className)}>
      {swatch && <span aria-hidden className={cn("size-1.5 shrink-0 rounded-[2px]", swatch)} />}
      {label}
      {n !== undefined && (
        <span className={cn("tnum font-mono text-[10.5px]", active ? "opacity-70" : "text-faint")}>{n === null ? "—" : n}</span>
      )}
    </button>
  );
}

/** A labelled strip of facets, matching the Inventory filter block. */
export function FacetRow({ label, children, className }: { label: string; children: ReactNode; className?: string }) {
  return (
    <div className={cn("flex flex-wrap items-center gap-x-3 gap-y-1.5", className)}>
      <span className="mr-0.5 w-[74px] shrink-0 text-[11px] font-medium text-faint">{label}</span>
      <span className="flex min-w-0 flex-wrap items-center gap-1.5">{children}</span>
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
    <section className={cn("overflow-hidden rounded-lg border border-line bg-surface elev-1", tone)}>
      <header className="flex flex-wrap items-center gap-2 border-b border-line bg-raise/40 px-3 py-2">
        <span className="tnum grid size-[19px] shrink-0 place-items-center rounded-xs bg-ink font-mono text-[10.5px] font-medium text-on-ink">{n}</span>
        <h3 className="text-[12px] font-semibold">{title}</h3>
        {note ? <span className="text-[11px] text-faint">{note}</span> : null}
        {action ? <span className="ml-auto shrink-0">{action}</span> : null}
      </header>
      {children ? <div className="p-3">{children}</div> : null}
    </section>
  );
}
