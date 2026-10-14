"use client";

import type { ReactNode } from "react";
import { cn } from "@/lib/cn";
import { hueFor } from "@/lib/hue";

export interface PanelProps {
  /** Header title — a string renders as the card title. */
  title?: ReactNode;
  /** Content on the right side of the header. */
  actions?: ReactNode;
  /** Small icon/element left of the title. */
  icon?: ReactNode;
  /** Supporting line beside the title: what the card does, never a guarantee. */
  caption?: ReactNode;
  children?: ReactNode;
  className?: string;
  bodyClassName?: string;
  /** Remove default body padding (for scroll lists / canvases). */
  noPadding?: boolean;
  /** Render a string title as a kicker (small caps) instead of a card title. */
  plainTitle?: boolean;
  /** Deprecated: the gradient hairline border is retired. */
  ring?: boolean;
}

/**
 * Hairline card with a tinted header bar — the workhorse surface. The header
 * takes its subject tint from the title, so callers never pick a colour.
 */
export function Panel({
  title,
  actions,
  icon,
  caption,
  children,
  className,
  bodyClassName,
  noPadding,
  plainTitle,
}: PanelProps) {
  return (
    <section
      className={cn(
        "flex min-h-0 flex-col overflow-hidden rounded-lg border border-line bg-surface elev-1",
        className,
      )}
    >
      {(title || actions) && (
        <header
          data-hue={hueFor(typeof title === "string" ? title : undefined)}
          data-hue-bar=""
          className="flex shrink-0 items-start gap-3 border-b border-line bg-raise/55 px-4 py-2.5"
        >
          <div className="flex min-w-0 items-center gap-2">
            {icon ? <span className="shrink-0 text-dim">{icon}</span> : null}
            {typeof title === "string" ? (
              plainTitle ? (
                <h2 className="truncate text-[11px] font-medium tracking-[0.06em] text-faint uppercase">{title}</h2>
              ) : (
                <h2 className="truncate text-[12.5px] font-semibold tracking-[-0.005em]">{title}</h2>
              )
            ) : (
              title
            )}
          </div>
          {caption ? (
            <span className="max-w-[110ch] text-[11px] leading-[1.55] text-faint">{caption}</span>
          ) : null}
          {actions ? <div className="ml-auto flex shrink-0 items-center gap-1.5">{actions}</div> : null}
        </header>
      )}
      <div className={cn("min-h-0 flex-1", !noPadding && "p-4", bodyClassName)}>{children}</div>
    </section>
  );
}

export default Panel;
