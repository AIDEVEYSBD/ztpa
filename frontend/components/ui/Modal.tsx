"use client";

import { useEffect, type ReactNode } from "react";
import { cn } from "@/lib/cn";
import { Button, type Tone } from "./Button";

function useEscape(onClose: () => void) {
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") onClose();
    };
    document.addEventListener("keydown", onKey);
    return () => document.removeEventListener("keydown", onKey);
  }, [onClose]);
}

/**
 * The drill-down every figure opens. A KPI tile, chart segment, table row or
 * matrix cell that cannot be clicked through to its records is a bug.
 */
export function DrillModal({
  title,
  count,
  subtitle,
  actions,
  onClose,
  size = "default",
  children,
}: {
  title: ReactNode;
  count?: ReactNode;
  subtitle?: ReactNode;
  actions?: ReactNode;
  onClose: () => void;
  size?: "default" | "document";
  children: ReactNode;
}) {
  useEscape(onClose);

  return (
    <div
      role="dialog"
      aria-modal="true"
      onClick={onClose}
      className="fixed inset-0 z-50 flex items-center justify-center bg-canvas/75 p-3 sm:p-6"
    >
      <div
        onClick={(e) => e.stopPropagation()}
        className={cn(
          "af-pop flex flex-col overflow-hidden rounded-lg border border-line bg-surface elev-3",
          size === "document"
            ? "h-[min(92vh,980px)] w-[min(1180px,100%)]"
            : "max-h-[88vh] w-[min(1080px,100%)]",
        )}
      >
        <header className="flex shrink-0 flex-wrap items-center gap-3 border-b border-line px-4 py-3">
          <h2 className="text-[14px] font-semibold tracking-[-0.005em]">{title}</h2>
          {count != null ? <span className="tnum text-[12px] text-faint">{count}</span> : null}
          {subtitle ? (
            <span className="max-w-[100ch] text-[11.5px] leading-[1.5] text-faint">{subtitle}</span>
          ) : null}
          <span className="grow" />
          {actions}
          <Button size="sm" variant="solid" tone="err" onClick={onClose}>
            Close
          </Button>
        </header>
        <div className="min-h-0 grow overflow-y-auto zt-scroll">{children}</div>
      </div>
    </div>
  );
}

export function Dialog({
  title,
  onClose,
  onConfirm,
  confirmLabel = "Confirm",
  confirmTone = "ink",
  busy,
  children,
}: {
  title: ReactNode;
  onClose: () => void;
  onConfirm: () => void;
  confirmLabel?: string;
  confirmTone?: Tone;
  busy?: boolean;
  children?: ReactNode;
}) {
  useEscape(onClose);

  return (
    <div
      role="dialog"
      aria-modal="true"
      onClick={onClose}
      className="fixed inset-0 z-[70] flex items-center justify-center bg-canvas/70 p-4"
    >
      <div
        onClick={(e) => e.stopPropagation()}
        className="af-pop w-full max-w-[420px] rounded-xl border border-line bg-surface elev-3"
      >
        <div className="p-5 pb-4">
          <h2 className="text-[16px] font-semibold tracking-tight">{title}</h2>
          {children ? <div className="mt-2 text-[12.5px] leading-[1.55] text-dim">{children}</div> : null}
        </div>
        <footer className="flex items-center justify-end gap-2 border-t border-line px-5 py-3">
          <Button size="sm" variant="solid" tone="err" onClick={onClose}>
            Cancel
          </Button>
          <Button size="sm" variant="solid" tone={confirmTone} loading={busy} onClick={onConfirm}>
            {confirmLabel}
          </Button>
        </footer>
      </div>
    </div>
  );
}

const RULE: Record<Tone, string> = {
  ink: "bg-ink",
  run: "bg-run",
  ok: "bg-ok",
  warn: "bg-warn",
  err: "bg-err",
  queue: "bg-queue",
  neutral: "bg-line-strong",
};

/** Surfaces are never tinted: the tone shows as a 3px rule on the left edge. */
export function Banner({
  tone = "queue",
  title,
  children,
  actions,
  className,
}: {
  tone?: Tone;
  title?: ReactNode;
  children?: ReactNode;
  actions?: ReactNode;
  className?: string;
}) {
  return (
    <div
      className={cn(
        "relative flex gap-3 overflow-hidden rounded-lg border border-line bg-surface p-3.5 pl-4 elev-1",
        className,
      )}
    >
      <span aria-hidden className={cn("absolute inset-y-0 left-0 w-[3px]", RULE[tone])} />
      <div className="min-w-0 grow">
        {title ? <p className="text-[13px] font-medium text-fg">{title}</p> : null}
        {children ? <div className="text-[12.5px] leading-[1.55] text-dim">{children}</div> : null}
      </div>
      {actions ? <div className="flex shrink-0 items-center gap-2">{actions}</div> : null}
    </div>
  );
}
