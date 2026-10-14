"use client";

import type { InputHTMLAttributes, ReactNode, SelectHTMLAttributes, TextareaHTMLAttributes } from "react";
import { cn } from "@/lib/cn";

const FIELD_BASE =
  "w-full rounded-md border border-line-strong bg-field px-3 text-[13px] text-fg placeholder:text-ghost " +
  "focus:outline-none focus-visible:border-fg focus-visible:ring-2 focus-visible:ring-fg/15 " +
  "disabled:cursor-not-allowed disabled:bg-raise disabled:text-ghost";

export function Field({
  label,
  hint,
  error,
  htmlFor,
  children,
  className,
}: {
  label?: ReactNode;
  hint?: ReactNode;
  error?: ReactNode;
  htmlFor?: string;
  children: ReactNode;
  className?: string;
}) {
  return (
    <div className={cn("flex flex-col gap-1.5", className)}>
      {label ? (
        <label htmlFor={htmlFor} className="text-[12.5px] font-medium text-mist">
          {label}
        </label>
      ) : null}
      {children}
      {hint && !error ? <span className="text-[11.5px] text-faint">{hint}</span> : null}
      {error ? (
        <span role="alert" className="flex items-center gap-1.5 text-[11.5px] text-err">
          <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" aria-hidden>
            <circle cx="12" cy="12" r="9" />
            <path d="M12 8v5" strokeLinecap="round" />
            <path d="M12 16.5v.01" strokeLinecap="round" />
          </svg>
          {error}
        </span>
      ) : null}
    </div>
  );
}

export interface InputProps extends InputHTMLAttributes<HTMLInputElement> {
  mono?: boolean;
  compact?: boolean;
  invalid?: boolean;
}

export function Input({ mono, compact, invalid, className, ...rest }: InputProps) {
  return (
    <input
      aria-invalid={invalid || undefined}
      className={cn(
        FIELD_BASE,
        compact ? "h-8 px-2.5" : "h-9",
        mono && "font-mono text-[12.5px]",
        invalid && "border-err focus-visible:ring-err/20",
        className,
      )}
      {...rest}
    />
  );
}

export function Textarea({ className, ...rest }: TextareaHTMLAttributes<HTMLTextAreaElement>) {
  return <textarea className={cn(FIELD_BASE, "min-h-20 py-2 leading-[1.55]", className)} {...rest} />;
}

export function Select({ className, children, ...rest }: SelectHTMLAttributes<HTMLSelectElement>) {
  return (
    <select className={cn(FIELD_BASE, "h-9 cursor-pointer pr-8", className)} {...rest}>
      {children}
    </select>
  );
}

export function SearchBox({ className, ...rest }: InputHTMLAttributes<HTMLInputElement>) {
  return (
    <div className={cn("relative", className)}>
      <svg
        width="13"
        height="13"
        viewBox="0 0 24 24"
        fill="none"
        stroke="currentColor"
        strokeWidth="2"
        strokeLinecap="round"
        aria-hidden
        className="pointer-events-none absolute top-1/2 left-2.5 -translate-y-1/2 text-faint"
      >
        <circle cx="11" cy="11" r="7" />
        <path d="m20 20-3.5-3.5" />
      </svg>
      <input
        type="search"
        className="focusable h-7 w-full rounded-sm border border-line bg-canvas pr-2 pl-7 text-[12px] text-fg placeholder:text-ghost focus:outline-none"
        {...rest}
      />
    </div>
  );
}

export function Checkbox({
  checked,
  onChange,
  label,
  disabled,
  className,
}: {
  checked: boolean;
  onChange: (next: boolean) => void;
  label?: ReactNode;
  disabled?: boolean;
  className?: string;
}) {
  return (
    <label className={cn("inline-flex cursor-pointer items-center gap-2 select-none", disabled && "opacity-40", className)}>
      <span
        role="checkbox"
        aria-checked={checked}
        aria-disabled={disabled || undefined}
        tabIndex={disabled ? -1 : 0}
        onClick={() => !disabled && onChange(!checked)}
        onKeyDown={(e) => {
          if (!disabled && (e.key === " " || e.key === "Enter")) {
            e.preventDefault();
            onChange(!checked);
          }
        }}
        className={cn(
          "focusable grid size-4 shrink-0 place-items-center rounded-xs border transition-colors duration-100",
          checked ? "border-ink bg-ink text-on-ink" : "border-line-strong bg-field",
        )}
      >
        {checked ? (
          <svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="3.5" strokeLinecap="round" strokeLinejoin="round" aria-hidden>
            <path d="m5 13 4.5 4.5L19 7" />
          </svg>
        ) : null}
      </span>
      {label ? <span className="text-[13px] text-mist">{label}</span> : null}
    </label>
  );
}

export function Switch({
  checked,
  onChange,
  label,
  disabled,
}: {
  checked: boolean;
  onChange: (next: boolean) => void;
  label: string;
  disabled?: boolean;
}) {
  return (
    <button
      type="button"
      role="switch"
      aria-checked={checked}
      aria-label={label}
      disabled={disabled}
      onClick={() => onChange(!checked)}
      className={cn(
        "focusable relative h-5 w-9 shrink-0 cursor-pointer rounded-sm border transition-colors duration-150 disabled:pointer-events-none disabled:opacity-40",
        checked ? "border-ink bg-ink" : "border-line-strong bg-raise",
      )}
    >
      <span
        className={cn(
          "absolute top-1/2 h-3.5 w-3 -translate-y-1/2 rounded-[2px] transition-[left] duration-150",
          checked ? "left-[19px] bg-on-ink" : "left-[2px] bg-faint",
        )}
      />
    </button>
  );
}

export function Segmented<T extends string>({
  options,
  value,
  onChange,
  className,
}: {
  options: ReadonlyArray<{ value: T; label: string }>;
  value: T;
  onChange: (next: T) => void;
  className?: string;
}) {
  return (
    <div className={cn("inline-flex items-center gap-px rounded-md border border-line bg-raise p-px", className)}>
      {options.map((o) => (
        <button
          key={o.value}
          type="button"
          onClick={() => onChange(o.value)}
          aria-pressed={o.value === value}
          className={cn(
            "focusable cursor-pointer rounded-sm px-2.5 py-1 text-[12.5px] transition-colors duration-100",
            o.value === value ? "bg-surface font-medium text-fg shadow-[var(--shadow-1)]" : "text-faint hover:text-dim",
          )}
        >
          {o.label}
        </button>
      ))}
    </div>
  );
}

export const WINDOWS = ["24h", "7d", "30d", "90d", "All"] as const;
export type Window = (typeof WINDOWS)[number];

export function WindowPick({
  value,
  onChange,
  inherited,
  className,
}: {
  value: Window;
  onChange: (next: Window) => void;
  /** The card is following the page window rather than overriding it. */
  inherited?: boolean;
  className?: string;
}) {
  return (
    <div className={cn("inline-flex items-center gap-px rounded-sm border border-line bg-canvas p-px", className)}>
      {WINDOWS.map((w) => (
        <button
          key={w}
          type="button"
          onClick={() => onChange(w)}
          aria-pressed={w === value}
          className={cn(
            "focusable cursor-pointer rounded-[3px] px-1.5 py-0.5 font-mono text-[10px] transition-colors duration-100",
            w === value ? (inherited ? "bg-raise text-fg" : "bg-ink text-on-ink") : "text-faint hover:text-dim",
          )}
        >
          {w}
        </button>
      ))}
    </div>
  );
}
