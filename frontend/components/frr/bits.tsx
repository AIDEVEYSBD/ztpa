"use client";

/**
 * Shared pieces for the Rule Review screens: formatting, labels, the caller's
 * duties, and the monospace command block with a copy button.
 */

import { useCallback, useEffect, useState, type ReactNode } from "react";
import { AlertTriangle, Check, ChevronDown, ChevronRight, Copy, FileSearch } from "lucide-react";
import { asApiError, type ApiError } from "@/lib/api";
import { frr } from "@/lib/frr";
import type { AvailabilityImpact, FrrDuty, FrrMe, PackageStatus } from "@/lib/frrTypes";
import type { Band } from "@/lib/types";
import { Button, Chip, EmptyState, cn, type ChipVariant } from "../ui";
import { errorHeadline, errorStatusLabel } from "../ui/Feedback";

/** Load state, as app/console/page.tsx defines it: `error` carries no data, so
 *  nothing derived from a failed fetch can be shown as a value. */
export type Resource<T> = { status: "loading" | "ok" | "error"; data?: T; error?: ApiError };

export const BANDS: Band[] = ["critical", "high", "medium", "low"];

/** Local time with seconds; the raw string when it does not parse. */
export function when(ts: string | null | undefined): string {
  if (!ts) return "—";
  const d = new Date(ts);
  return Number.isNaN(d.getTime()) ? ts : d.toLocaleString(undefined, { hour12: false });
}

export function bytes(n: number | null | undefined): string {
  if (n == null) return "—";
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / 1024 / 1024).toFixed(1)} MB`;
}

export const CHECK_LABEL: Record<string, string> = {
  any_any: "any → any",
  admin_port_exposed: "admin port exposed",
  broad_source: "broad source",
  over_permissive: "over-permissive",
  shadowed: "shadowed",
  expired: "expired",
  expiring_soon: "expiring soon",
  disabled: "disabled",
  unused: "unused",
};
export const checkLabel = (k: string) => CHECK_LABEL[k] ?? k.replace(/_/g, " ");

export const PROPOSAL_LABEL: Record<string, string> = {
  remove: "Remove",
  disable_then_remove: "Disable, then remove",
  reorder: "Reorder",
  time_bound_and_narrow: "Time-bound and narrow",
  revisit_after: "Revisit later",
};
export const proposalLabel = (k: string) => PROPOSAL_LABEL[k] ?? k.replace(/_/g, " ");

/** Availability impact. "likely" and "changes_behaviour" are the two a reviewer
 *  must not miss, so they take the loud colours. */
export const IMPACT: Record<AvailabilityImpact, { label: string; variant: ChipVariant; loud: boolean }> = {
  none: { label: "no availability impact", variant: "ok", loud: false },
  possible: { label: "possible impact", variant: "warn", loud: false },
  likely: { label: "likely impact", variant: "danger", loud: true },
  changes_behaviour: { label: "changes behaviour", variant: "danger", loud: true },
};
export function impactMeta(k: string) {
  return IMPACT[k as AvailabilityImpact] ?? { label: k.replace(/_/g, " "), variant: "neutral" as ChipVariant, loud: false };
}

export const PACKAGE_STATUS: Record<PackageStatus, { label: string; variant: ChipVariant }> = {
  draft: { label: "draft", variant: "neutral" },
  owner_validated: { label: "owner validated", variant: "info" },
  approved: { label: "approved", variant: "ok" },
  rejected: { label: "rejected", variant: "danger" },
  superseded: { label: "superseded", variant: "neutral" },
};

/** Does the caller hold `duty` for `layer`? `*` covers every layer. Display
 *  only — the backend checks again on every action. */
export function hasDuty(me: FrrMe | undefined, duty: FrrDuty, layer: string): boolean {
  return !!me?.duties?.some((d) => d.duty === duty && (d.scope === "*" || d.scope === layer));
}
export function hasDutyForAll(me: FrrMe | undefined, duty: FrrDuty, layers: string[]): boolean {
  return layers.every((l) => hasDuty(me, duty, l));
}

/** The caller's FRR duties. */
export function useFrrMe(): { me: Resource<FrrMe>; reload: () => void } {
  const [me, setMe] = useState<Resource<FrrMe>>({ status: "loading" });
  const [attempt, setAttempt] = useState(0);
  useEffect(() => {
    let live = true;
    setMe({ status: "loading" });
    frr.me()
      .then((data) => { if (live) setMe({ status: "ok", data }); })
      .catch((e) => { if (live) setMe({ status: "error", error: asApiError(e) }); });
    return () => { live = false; };
  }, [attempt]);
  const reload = useCallback(() => setAttempt((n) => n + 1), []);
  return { me, reload };
}

/** First UUID in a string — used to pick the existing package id out of the
 *  backend's 409 "export already has a draft change package <id>". */
export function firstUuid(s: string): string | undefined {
  return s.match(/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/i)?.[0];
}

/** Hand a text file to the browser. Returns false when it could not, so the
 *  caller can say so rather than leave a button that looks like it worked. */
export function downloadText(filename: string, text: string): boolean {
  try {
    const blob = new Blob([text], { type: "text/plain;charset=utf-8" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = filename;
    a.style.display = "none";
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    setTimeout(() => URL.revokeObjectURL(url), 2000);
    return true;
  } catch {
    return false;
  }
}

/** Collapsible monospace block (commands, rollback) with a copy button. */
export function CodeBlock({ title, lines, tone = "neutral", defaultOpen = false }: {
  title: string;
  lines: string[];
  tone?: "neutral" | "warn";
  defaultOpen?: boolean;
}) {
  const [open, setOpen] = useState(defaultOpen);
  const [copy, setCopy] = useState<"idle" | "done" | "failed">("idle");
  const text = lines.join("\n");

  const doCopy = () => {
    if (!navigator.clipboard) { setCopy("failed"); return; }
    navigator.clipboard.writeText(text)
      .then(() => setCopy("done"))
      .catch(() => setCopy("failed"))
      .finally(() => setTimeout(() => setCopy("idle"), 2000));
  };

  return (
    <div className="overflow-hidden rounded-md border border-line">
      <div className="flex items-center gap-2 bg-raise/55 px-2.5 py-1.5">
        <button type="button" onClick={() => setOpen((o) => !o)} aria-expanded={open}
          className="focusable flex min-w-0 flex-1 cursor-pointer items-center gap-1.5 text-left text-[11.5px] font-medium text-fg">
          {open ? <ChevronDown size={12} /> : <ChevronRight size={12} />}
          <span className={cn(tone === "warn" && "text-warn")}>{title}</span>
          <span className="tnum font-mono text-[10.5px] text-faint">{lines.length} line{lines.length === 1 ? "" : "s"}</span>
        </button>
        {lines.length > 0 && (
          <Button size="sm" variant="quiet" tone={copy === "failed" ? "err" : "neutral"} onClick={doCopy}
            aria-label={`Copy ${title.toLowerCase()}`}>
            {copy === "done" ? <Check size={12} /> : <Copy size={12} />}
            {copy === "done" ? "Copied" : copy === "failed" ? "Copy failed — select the text" : "Copy"}
          </Button>
        )}
      </div>
      {open && (
        lines.length > 0 ? (
          <pre className="zt-scroll max-h-72 overflow-auto bg-sunken px-3 py-2 font-mono text-[11px] leading-[1.6] whitespace-pre text-fg">{text}</pre>
        ) : (
          <p className="bg-sunken px-3 py-2 text-[11.5px] text-faint">None for this item.</p>
        )
      )}
    </div>
  );
}

/** Shown on the export-scoped screens when nothing is selected yet. */
export function NoExportSelected({ onGoToExports, what }: { onGoToExports: () => void; what: string }) {
  return (
    <div className="space-y-3">
      <EmptyState icon={FileSearch} title="No export selected"
        sub={`Pick an accepted export on the Exports screen to see its ${what}.`} />
      <div className="flex justify-center">
        <Button size="sm" variant="solid" tone="ink" onClick={onGoToExports}>Go to Exports</Button>
      </div>
    </div>
  );
}

/** Compact key/value rendering for free-form evidence objects. */
export function EvidenceList({ evidence }: { evidence: Record<string, unknown> | null | undefined }) {
  const entries = Object.entries(evidence ?? {});
  if (entries.length === 0) return <span className="text-[11px] text-faint">No evidence recorded.</span>;
  return (
    <dl className="grid grid-cols-[max-content_1fr] gap-x-3 gap-y-0.5 text-[11px]">
      {entries.map(([k, v]) => (
        <EvidenceRow key={k} k={k} v={v} />
      ))}
    </dl>
  );
}

function EvidenceRow({ k, v }: { k: string; v: unknown }) {
  let text: ReactNode;
  if (v == null) text = <span className="text-faint">unknown</span>;
  else if (Array.isArray(v)) text = v.length ? v.map((x) => (typeof x === "object" ? JSON.stringify(x) : String(x))).join(", ") : <span className="text-faint">none</span>;
  else if (typeof v === "object") text = JSON.stringify(v);
  else text = String(v);
  return (
    <>
      <dt className="text-faint">{k.replace(/_/g, " ")}</dt>
      <dd className="min-w-0 font-mono break-words text-dim">{text}</dd>
    </>
  );
}

/** Label for a narrative's author. `engine_fallback` is the deterministic
 *  engine, not a model, and must never be labelled as AI. */
export function authorLabel(by: string | null | undefined): { ai: boolean; text: string } {
  if (!by || by === "engine_fallback") return { ai: false, text: "Engine" };
  return { ai: true, text: by };
}

export function AuthorChip({ by, aiLabel = "AI" }: { by: string | null | undefined; aiLabel?: string }) {
  const a = authorLabel(by);
  return a.ai
    ? <Chip variant="accent" mono>{aiLabel} · {a.text}</Chip>
    : <Chip variant="neutral" mono>deterministic engine</Chip>;
}

/**
 * A failed ACTION (upload, decision, grant), as opposed to a failed read.
 * InlineError's "Could not load …" is the wrong sentence for "the API refused
 * your decision", and the server's `detail` is the point here — it says which
 * input was missing or which duty is needed — so it is the body, not a footnote.
 */
export function ActionError({ action, error, className }: { action: string; error: unknown; className?: string }) {
  const e = asApiError(error);
  const denied = e.status === 401 || e.status === 403;
  return (
    <div role="alert" className={cn("flex gap-2 rounded-md border px-2.5 py-2 text-[12px]",
      denied ? "border-warn-line bg-warn-bg" : "border-err-line bg-err-bg", className)}>
      <AlertTriangle size={13} className={cn("mt-0.5 shrink-0", denied ? "text-warn" : "text-err")} />
      <div className="min-w-0">
        <div className={cn("font-medium", denied ? "text-warn" : "text-err")}>Could not {action} — {errorHeadline(e)}</div>
        <div className="mt-0.5 break-words text-fg">{e.detail}</div>
        <div className="mt-0.5 font-mono text-[10.5px] text-faint">{errorStatusLabel(e)}{e.path ? ` · ${e.path}` : ""}</div>
      </div>
    </div>
  );
}
