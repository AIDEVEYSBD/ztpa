"use client";

import type { ButtonHTMLAttributes, ReactNode } from "react";
import { cn } from "@/lib/cn";

export type Tone = "ink" | "run" | "ok" | "warn" | "err" | "queue" | "neutral";
export type ButtonVariant = "solid" | "outline" | "quiet";
export type ButtonSize = "sm" | "md" | "lg";

const SIZE: Record<ButtonSize, string> = {
  sm: "h-7 gap-1.5 rounded-sm px-2.5 text-[12px]",
  md: "h-9 gap-2 rounded-md px-3.5 text-[13px]",
  lg: "h-11 gap-2 rounded-md px-5 text-[14px]",
};

const SOLID: Record<Tone, string> = {
  ink: "bg-ink text-on-ink",
  run: "bg-run text-on-solid",
  ok: "bg-ok text-on-solid",
  warn: "bg-warn text-on-solid",
  err: "bg-err text-on-solid",
  queue: "bg-queue text-on-solid",
  neutral: "bg-raise text-fg",
};

const OUTLINE: Record<Tone, string> = {
  ink: "border-line-strong text-fg",
  run: "border-run-line text-run",
  ok: "border-ok-line text-ok",
  warn: "border-warn-line text-warn",
  err: "border-err-line text-err",
  queue: "border-queue-line text-queue",
  neutral: "border-line text-dim",
};

const QUIET: Record<Tone, string> = {
  ink: "text-fg",
  run: "text-run",
  ok: "text-ok",
  warn: "text-warn",
  err: "text-err",
  queue: "text-queue",
  neutral: "text-dim",
};

const BASE =
  "focusable inline-flex cursor-pointer items-center justify-center font-medium whitespace-nowrap select-none " +
  "transition-[background-color,border-color,filter,opacity] duration-100 disabled:pointer-events-none disabled:opacity-40";

export interface ButtonProps extends Omit<ButtonHTMLAttributes<HTMLButtonElement>, "children"> {
  variant?: ButtonVariant;
  tone?: Tone;
  size?: ButtonSize;
  loading?: boolean;
  children?: ReactNode;
  /** Renders an anchor styled as a button. Never nest a button inside a link. */
  href?: string;
}

/**
 * Buttons are always solid or filled, never a bare border. Cancel, delete,
 * close and refuse are solid red from the first render.
 */
export function Button({
  variant = "outline",
  tone = "ink",
  size = "md",
  loading,
  disabled,
  className,
  children,
  href,
  ...rest
}: ButtonProps) {
  const skin =
    variant === "solid"
      ? cn(SOLID[tone], "border border-transparent hover:brightness-[1.08] active:brightness-95")
      : variant === "quiet"
        ? cn(QUIET[tone], "border border-transparent bg-raise hover:brightness-[1.08]")
        : cn(OUTLINE[tone], "border bg-surface hover:bg-raise active:brightness-95");

  const classes = cn(BASE, SIZE[size], skin, className);
  const body = (
    <>
      {loading ? <Spinner size={size === "sm" ? 11 : 13} /> : null}
      {children}
    </>
  );

  if (href) {
    return (
      <a href={href} className={classes} aria-disabled={disabled || undefined}>
        {body}
      </a>
    );
  }

  return (
    <button type="button" className={classes} disabled={disabled || loading} {...rest}>
      {body}
    </button>
  );
}

export interface IconButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  size?: "sm" | "md";
  tone?: Tone;
  label: string;
}

export function IconButton({ size = "md", tone = "ink", label, className, children, ...rest }: IconButtonProps) {
  return (
    <button
      type="button"
      aria-label={label}
      title={label}
      className={cn(
        "focusable inline-grid cursor-pointer place-items-center rounded-md border border-transparent bg-raise",
        "transition-[filter,opacity] duration-100 hover:brightness-[1.08] disabled:pointer-events-none disabled:opacity-40",
        size === "sm" ? "size-7" : "size-9",
        QUIET[tone],
        className,
      )}
      {...rest}
    >
      {children}
    </button>
  );
}

export function Spinner({ size = 14, className }: { size?: number; className?: string }) {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 24 24"
      fill="none"
      aria-hidden
      className={cn("af-spin shrink-0", className)}
    >
      <circle cx="12" cy="12" r="9" stroke="currentColor" strokeWidth="2.5" opacity="0.25" />
      <path d="M21 12a9 9 0 0 0-9-9" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" />
    </svg>
  );
}
