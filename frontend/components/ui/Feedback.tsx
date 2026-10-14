"use client";

import type { ReactNode } from "react";
import { AlertTriangle, HelpCircle, Lock, PlugZap, RotateCw, ShieldHalf } from "lucide-react";
import { asApiError, type ApiError } from "@/lib/api";
import { cn } from "@/lib/cn";
import { Button } from "./Button";
import { useReportedFailure } from "@/components/PanelHealth";

export function Spinner({ label }: { label?: string }) {
  // The ring inherits `currentColor` so it stays visible on any surface,
  // including a solid button fill.
  return (
    <span className="inline-flex items-center gap-2 text-[13px]">
      <span className="af-spin size-3.5 rounded-full border-2 border-current border-t-transparent" />
      {label}
    </span>
  );
}

/** Small caps section label. */
export function SectionLabel({ children, className = "" }: { children: ReactNode; className?: string }) {
  return (
    <div className={cn("mb-3 text-[11px] font-medium tracking-[0.08em] text-faint uppercase", className)}>{children}</div>
  );
}

/** Kicker — small caps accent label above a headline. */
export function Eyebrow({ children, className }: { children: ReactNode; accent?: boolean; className?: string }) {
  return (
    <span className={cn("text-[11px] font-medium tracking-[0.08em] text-accent-text uppercase", className)}>{children}</span>
  );
}

/** Hairline rule. */
export function SpectrumLine({ className }: { thin?: boolean; warm?: boolean; className?: string }) {
  return <span aria-hidden className={cn("block h-px w-full bg-line", className)} />;
}

/** Brand mark — the shield in an ink tile + wordmark. */
export function Brand({ size = "md", showSub = true, className }: { size?: "sm" | "md"; showSub?: boolean; className?: string }) {
  const tile = size === "sm" ? 22 : 24;
  const glyph = Math.round(tile * 0.6);
  return (
    <div className={cn("flex items-center gap-2.5", className)}>
      <span className="grid shrink-0 place-items-center rounded-md bg-ink text-on-ink" style={{ width: tile, height: tile }}>
        <ShieldHalf size={glyph} />
      </span>
      <div className="leading-[1.15]">
        <div className={cn("font-bold tracking-tight text-on-grain", size === "sm" ? "text-[12px]" : "text-[13px]")}>
          {showSub ? "Network Policy" : "Network Policy Reviewer"}
        </div>
        {showSub && <div className="text-[9.5px] tracking-[0.14em] text-faint uppercase">Reviewer</div>}
      </div>
    </div>
  );
}

export function EmptyState({ icon: Icon, title, sub }: { icon: typeof ShieldHalf; title: string; sub?: string }) {
  return (
    <div className="flex flex-col items-center gap-3 rounded-lg border border-dashed border-line-strong px-6 py-12 text-center">
      <Icon size={22} className="text-faint" />
      <div className="text-[14px] font-medium">{title}</div>
      {sub && <div className="max-w-[42ch] text-[12.5px] leading-[1.55] text-dim">{sub}</div>}
    </div>
  );
}

// ───────────────────────────────────────────────────────────────────────────
// Failure states. An empty panel and a failed panel used to be pixel-identical
// ("0 findings"), which is the worst thing a security tool can do. Everything
// below exists so a caller can render WHAT failed and WHY, in one line, instead
// of degrading to a plausible-looking zero.
// ───────────────────────────────────────────────────────────────────────────

/** Headline for a failure, keyed off the status so each class of failure reads
 *  as itself — a 403 is a permissions problem and must never render as
 *  "is the API running?", which is what every failure used to say. */
export function errorHeadline(err: unknown): string {
  const e = asApiError(err);
  // `apiUnreachable`, not `isNetwork`: with the Next rewrite in front of
  // FastAPI, a stopped backend arrives as an HTTP 500 the proxy wrote, not as a
  // transport failure. Both mean the API did not answer, and both must read as
  // that rather than as an error the API supposedly logged.
  if (e.apiUnreachable) return "the API did not respond";
  if (e.status === 401) return "your session has expired";
  if (e.status === 403) return "your role is not permitted";
  if (e.status === 404) return "the API has no such resource";
  if (e.status === 409) return "it conflicts with the current state";
  if (e.status === 422) return "the API rejected the request";
  if (e.status === 429) return "the API is rate limiting us";
  if (e.status >= 500) return "the API failed handling it";
  return "the request failed";
}

/** What the user can actually do about it. */
function errorHint(e: ApiError): string {
  if (e.isNetwork) return "Nothing was returned, so nothing below is current. Check that the API is running and reachable, then retry.";
  // Same remedy, different evidence: a status came back, but the API did not
  // write it. Saying so is the point — the old text sent the operator to an API
  // log that does not contain this request, because the API never saw it.
  if (e.apiUnreachable) return "The API never received this request: it was proxied to the backend and the connection failed, so this status came from the proxy. Nothing below is current. Start the API (or fix BACKEND_URL), then retry — its log has nothing to show for this.";
  if (e.status === 401) return "Sign in again to continue.";
  if (e.status === 403) return "Ask an administrator for a role that allows this. This is a permissions decision, not an outage.";
  if (e.status === 404) return "This build of the API does not expose that endpoint. Check that the frontend and backend are the same version.";
  if (e.status === 409) return "Reload to pick up the current snapshot, then try again.";
  if (e.status >= 500) return "The API logged an error handling this request. Retrying may work; if it does not, the server log has the request id.";
  return "Retrying may work. If it does not, the status and detail below identify the failure exactly.";
}

/** `HTTP 403` / `no response` — the machine-readable half of the panel. The
 *  proxy case keeps its real status (a 500 DID come back) and names who wrote
 *  it, so the line stays a faithful record of the wire rather than a summary.
 *  Exported for RuleRef, whose popover must hand-roll the markup but must not
 *  hand-roll a second, divergent vocabulary for the same facts. */
export function errorStatusLabel(e: ApiError): string {
  if (e.isNetwork) return "no response";
  return e.apiUnreachable ? `HTTP ${e.status} from the proxy` : `HTTP ${e.status}`;
}
const statusLabel = errorStatusLabel;

export interface ErrorStateProps {
  /** What failed to load, in the user's words ("findings", "the change log"). */
  resource: string;
  error: unknown;
  onRetry?: () => void;
  className?: string;
}

/**
 * The block-level failure panel: name the resource, say what class of failure
 * it was, and print the exact status + detail so the failure is reportable.
 * Use this ANYWHERE a zero, an empty list or a green state would otherwise be
 * rendered from data that never arrived.
 */
export function ErrorState({ resource, error, onRetry, className }: ErrorStateProps) {
  const e = asApiError(error);
  // Put this failure on the console's record while it is on screen, so the
  // degraded banner above cannot claim the panels below it are fine. See
  // components/PanelHealth.tsx for why the registration lives here.
  useReportedFailure(resource, true);
  // Permission failures are amber, not red: nothing is broken, the answer is no.
  const denied = e.status === 401 || e.status === 403;
  const Icon = denied ? Lock : e.apiUnreachable ? PlugZap : AlertTriangle;
  return (
    <div
      role="alert"
      className={cn(
        "relative flex gap-3 overflow-hidden rounded-lg border border-line bg-surface p-3.5 pl-4 elev-1",
        className,
      )}
    >
      <span aria-hidden className={cn("absolute inset-y-0 left-0 w-[3px]", denied ? "bg-warn" : "bg-err")} />
      <Icon size={15} className={cn("mt-0.5 shrink-0", denied ? "text-warn" : "text-err")} />
      <div className="min-w-0 flex-1">
        <div className="text-[13px] font-medium text-fg">
          Could not load {resource} — {errorHeadline(e)}
        </div>
        <p className="mt-1 text-[12.5px] leading-[1.55] text-dim">{errorHint(e)}</p>
        <div className="mt-1.5 font-mono text-[10.5px] break-words text-faint">
          {statusLabel(e)} · {e.detail}
          {e.path ? ` · ${e.path}` : ""}
        </div>
      </div>
      {onRetry && (
        <Button size="sm" variant="solid" tone="ink" className="shrink-0" onClick={onRetry}>
          <RotateCw size={12} /> Retry
        </Button>
      )}
    </div>
  );
}

/**
 * The 200 that is not an answer.
 *
 * A backend that is running but cannot reach its system of record answers some
 * reads with an EMPTY payload plus the reason it is empty (`degraded_reason`).
 * Putting that through the ordinary empty state would print "No snapshots found
 * — run an analysis to create one" out of a database that was never read: the
 * empty-vs-failed lie again, arriving with a 200 instead of a 500. So an
 * empty-with-a-reason gets its own surface — amber rather than red, because
 * nothing is broken; the fact being reported is that nothing is KNOWN.
 */
export function UnavailableState({ resource, reason, onRetry, className }: {
  /** What could not be read, in the user's words ("the snapshot history"). */
  resource: string;
  /** The backend's own `degraded_reason`, rendered verbatim. */
  reason: string;
  onRetry?: () => void;
  className?: string;
}) {
  return (
    <div
      role="status"
      className={cn(
        "relative flex gap-3 overflow-hidden rounded-lg border border-line bg-surface p-3.5 pl-4 elev-1",
        className,
      )}
    >
      <span aria-hidden className="absolute inset-y-0 left-0 w-[3px] bg-run" />
      <HelpCircle size={15} className="mt-0.5 shrink-0 text-run" />
      <div className="min-w-0 flex-1">
        <div className="text-[13px] font-medium text-fg">
          {resource} is unknown, not empty
        </div>
        <p className="mt-1 text-[12.5px] leading-[1.55] text-dim">
          The backend answered, and told us it could not read this from the system of record.
          Nothing here has been counted, so treat it as unread rather than as none.
        </p>
        <div className="mt-1.5 font-mono text-[10.5px] break-words text-faint">{reason}</div>
      </div>
      {onRetry && (
        <Button size="sm" variant="solid" tone="ink" className="shrink-0" onClick={onRetry}>
          <RotateCw size={12} /> Retry
        </Button>
      )}
    </div>
  );
}


/** One-line variant for a failure inside a row, a toolbar or a side rail —
 *  same facts, no panel chrome. */
export function InlineError({ resource, error, onRetry, className }: ErrorStateProps) {
  const e = asApiError(error);
  // A failure in a row or a toolbar is still a failure the banner may not paper
  // over — same registration as the block panel above.
  useReportedFailure(resource, true);
  const denied = e.status === 401 || e.status === 403;
  return (
    <div role="alert" className={cn("flex flex-wrap items-center gap-1.5 text-[11.5px]", denied ? "text-warn" : "text-err", className)}>
      <AlertTriangle size={12} className="shrink-0" />
      <span className="font-medium">Could not load {resource}</span>
      <span className="font-mono text-[10.5px] text-faint">
        {statusLabel(e)} · {e.detail}
      </span>
      {onRetry && (
        <button onClick={onRetry} className="focusable cursor-pointer font-medium underline">
          Retry
        </button>
      )}
    </div>
  );
}
