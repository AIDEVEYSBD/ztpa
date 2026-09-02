"use client";

import type { ReactNode } from "react";
import { AlertTriangle, HelpCircle, Lock, PlugZap, RotateCw, ShieldHalf } from "lucide-react";
import { asApiError, type ApiError } from "@/lib/api";
import { cn } from "@/lib/cn";
import { useReportedFailure } from "@/components/PanelHealth";

export function Spinner({ label }: { label?: string }) {
  // The ring inherits `currentColor` so it stays visible on any surface —
  // including the yellow primary button (where a yellow ring would vanish).
  return (
    <span className="inline-flex items-center gap-2 text-[13px]">
      <span className="h-3.5 w-3.5 animate-spin rounded-full border-2 border-current border-t-transparent" />
      {label}
    </span>
  );
}

/** Plain uppercase section label (no leading square). */
export function SectionLabel({ children, className = "" }: { children: ReactNode; className?: string }) {
  return <div className={cn("label mb-3", className)}>{children}</div>;
}

/** Signature eyebrow — yellow square + uppercase micro-label. */
export function Eyebrow({ children, accent = false, className }: { children: ReactNode; accent?: boolean; className?: string }) {
  return <span className={cn("eyebrow", accent && "accent", className)}>{children}</span>;
}

/** Thin spectrum keyline (decorative rule). */
export function SpectrumLine({ thin = false, warm = false, className }: { thin?: boolean; warm?: boolean; className?: string }) {
  return <span aria-hidden className={cn("spectrum-line", thin && "thin", warm && "warm", className)} />;
}

/** Squared brand mark — the shield in a flat yellow tile + wordmark. */
export function Brand({ size = "md", showSub = true, className }: { size?: "sm" | "md"; showSub?: boolean; className?: string }) {
  const tile = size === "sm" ? 26 : 30;
  const glyph = Math.round(tile * 0.56);
  return (
    <div className={cn("flex items-center gap-2.5", className)}>
      <span className="grid shrink-0 place-items-center bg-accent" style={{ width: tile, height: tile }}>
        <ShieldHalf size={glyph} className="text-accent-ink" />
      </span>
      <div className="leading-[1.15]">
        <div className={cn("font-bold tracking-[-0.01em]", size === "sm" ? "text-[13px]" : "text-[14px]")}>
          {showSub ? "Network Policy" : "Network Policy Reviewer"}
        </div>
        {showSub && <div className="text-[10px] uppercase tracking-[0.14em] text-text3">Reviewer</div>}
      </div>
    </div>
  );
}

export function EmptyState({ icon: Icon, title, sub }: { icon: typeof ShieldHalf; title: string; sub?: string }) {
  return (
    <div className="flex flex-col items-center justify-center gap-2 p-10 text-center text-text3">
      <Icon size={26} />
      <div className="text-[13px] font-bold text-text2">{title}</div>
      {sub && <div className="text-[11.5px]">{sub}</div>}
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
        "border p-3.5",
        denied ? "border-sev-high-line bg-sev-high-bg" : "border-sev-critical-line bg-sev-critical-bg",
        className,
      )}
    >
      <div className="flex items-start gap-2.5">
        <Icon size={16} className={cn("mt-0.5 shrink-0", denied ? "text-sev-high" : "text-sev-critical")} />
        <div className="min-w-0 flex-1">
          <div className={cn("text-[13px] font-bold", denied ? "text-sev-high" : "text-sev-critical")}>
            Could not load {resource} — {errorHeadline(e)}
          </div>
          <p className="mt-1 text-[12px] leading-relaxed text-text2">{errorHint(e)}</p>
          <div className="mono mt-1.5 break-words text-[11px] text-text3">
            {statusLabel(e)} · {e.detail}
            {e.path ? ` · ${e.path}` : ""}
          </div>
        </div>
        {onRetry && (
          <button onClick={onRetry} className="btn-ghost shrink-0 text-xs">
            <RotateCw size={12} /> Retry
          </button>
        )}
      </div>
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
    <div role="status" className={cn("border border-sev-medium-line bg-sev-medium-bg p-3.5", className)}>
      <div className="flex items-start gap-2.5">
        <HelpCircle size={16} className="mt-0.5 shrink-0 text-sev-medium" />
        <div className="min-w-0 flex-1">
          <div className="text-[13px] font-bold text-sev-medium">
            {resource} is unknown, not empty
          </div>
          <p className="mt-1 text-[12px] leading-relaxed text-text2">
            The backend answered, and told us it could not read this from the system of record.
            Nothing here has been counted, so treat it as unread rather than as none.
          </p>
          <div className="mono mt-1.5 break-words text-[11px] text-text3">{reason}</div>
        </div>
        {onRetry && (
          <button onClick={onRetry} className="btn-ghost shrink-0 text-xs">
            <RotateCw size={12} /> Retry
          </button>
        )}
      </div>
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
    <div role="alert" className={cn("flex flex-wrap items-center gap-1.5 text-[11.5px]", denied ? "text-sev-high" : "text-sev-critical", className)}>
      <AlertTriangle size={12} className="shrink-0" />
      <span className="font-bold">Could not load {resource}</span>
      <span className="mono text-text3">
        {statusLabel(e)} · {e.detail}
      </span>
      {onRetry && (
        <button onClick={onRetry} className="font-bold underline">
          Retry
        </button>
      )}
    </div>
  );
}
