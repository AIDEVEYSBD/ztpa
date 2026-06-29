"use client";

import type { ReactNode } from "react";
import { cn } from "@/lib/cn";

export interface PanelProps {
  /** Header title — a string renders as an eyebrow (yellow square + uppercase). */
  title?: ReactNode;
  /** Content on the right side of the header. */
  actions?: ReactNode;
  /** Small icon/element left of the title. */
  icon?: ReactNode;
  children?: ReactNode;
  className?: string;
  bodyClassName?: string;
  /** Remove default body padding (for scroll lists / canvases). */
  noPadding?: boolean;
  /** Render a string title as a bold heading instead of an eyebrow. */
  plainTitle?: boolean;
  /** Add the gradient hairline border for feature panels. */
  ring?: boolean;
}

/**
 * Frosted glass panel with a hairline eyebrow header — the workhorse surface.
 * The `.panel` / `.panel-head` / `.eyebrow` classes (globals.css) carry the
 * look so it stays consistent everywhere and adapts to light / dark.
 */
export function Panel({
  title,
  actions,
  icon,
  children,
  className,
  bodyClassName,
  noPadding,
  plainTitle,
  ring,
}: PanelProps) {
  return (
    <section className={cn("panel flex min-h-0 flex-col overflow-hidden", ring && "ring-grad", className)}>
      {(title || actions) && (
        <header className="panel-head shrink-0">
          <div className="flex min-w-0 items-center gap-2">
            {icon ? <span className="shrink-0 text-accent-fg">{icon}</span> : null}
            {typeof title === "string" ? (
              plainTitle ? (
                <h2 className="truncate text-[13px] font-bold">{title}</h2>
              ) : (
                <h2 className="eyebrow truncate">{title}</h2>
              )
            ) : (
              title
            )}
          </div>
          {actions ? <div className="flex shrink-0 items-center gap-1.5">{actions}</div> : null}
        </header>
      )}
      <div className={cn("min-h-0 flex-1", !noPadding && "p-4", bodyClassName)}>{children}</div>
    </section>
  );
}

export default Panel;
