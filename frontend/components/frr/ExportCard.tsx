"use client";

import { useState } from "react";
import { Bot, ListChecks, XOctagon } from "lucide-react";
import { asApiError, type ApiError } from "@/lib/api";
import { frr } from "@/lib/frr";
import type { FrrExport } from "@/lib/frrTypes";
import { Button, Chip, cn } from "../ui";
import { Spinner } from "../ui/Button";
import { ActionError, BANDS, bytes, when } from "./bits";

const BAND_TEXT = { critical: "text-err", high: "text-warn", medium: "text-run", low: "text-dim" } as const;

function StatusChip({ status }: { status: FrrExport["status"] }) {
  if (status === "received") {
    return <Chip variant="info"><Spinner size={10} />received · parsing</Chip>;
  }
  if (status === "accepted") return <Chip variant="ok" dot>accepted</Chip>;
  return <Chip variant="danger" dot>rejected</Chip>;
}

function Count({ label, value }: { label: string; value: number | string | undefined | null }) {
  return (
    <div className="flex flex-col">
      <span className="text-[10.5px] text-faint">{label}</span>
      <span className="tnum text-[14px] font-semibold">{value ?? "—"}</span>
    </div>
  );
}

export function ExportCard({ exp, selected, canRun, onSelect, onOpenReview, onRunStarted }: {
  exp: FrrExport;
  selected: boolean;
  canRun: boolean;
  onSelect: () => void;
  onOpenReview: () => void;
  onRunStarted: (runId: string) => void;
}) {
  const [busy, setBusy] = useState(false);
  const [runErr, setRunErr] = useState<ApiError>();
  const s = exp.summary;
  const review = s?.review;

  const runAgents = () => {
    setBusy(true);
    setRunErr(undefined);
    frr.startRun(exp.export_id)
      .then((run) => onRunStarted(run.run_id))
      .catch((e) => setRunErr(asApiError(e)))
      .finally(() => setBusy(false));
  };

  return (
    <article
      className={cn(
        "relative overflow-hidden rounded-lg border bg-surface elev-1",
        selected ? "border-line-strong" : "border-line",
      )}
    >
      {selected && <span aria-hidden className="absolute inset-y-0 left-0 w-[3px] bg-ink" />}
      <div className="flex flex-wrap items-start gap-3 px-4 py-3">
        <button type="button" onClick={onSelect} aria-pressed={selected}
          className="focusable min-w-0 flex-1 cursor-pointer text-left">
          <div className="flex flex-wrap items-center gap-2">
            <span className="truncate text-[13px] font-semibold">{exp.filename || "unnamed export"}</span>
            <StatusChip status={exp.status} />
            {selected && <Chip variant="accent">selected</Chip>}
          </div>
          <div className="mt-1 flex flex-wrap gap-x-3 gap-y-0.5 text-[11px] text-faint">
            <span>uploaded {when(exp.uploaded_at)}{exp.uploaded_by ? ` by ${exp.uploaded_by}` : ""}</span>
            <span>{bytes(exp.size_bytes)}</span>
            <span>exported {exp.exported_at ? when(exp.exported_at) : exp.declared_exported_at ? `${when(exp.declared_exported_at)} (declared)` : "at an unknown time"}</span>
            <span className="font-mono" title={exp.sha256}>sha256 {exp.sha256.slice(0, 12)}</span>
          </div>
        </button>
        {exp.status === "accepted" && (
          <div className="flex shrink-0 items-center gap-2">
            <Button size="sm" variant="solid" tone="ink" onClick={onOpenReview}>
              <ListChecks size={12} /> Open review
            </Button>
            <Button size="sm" variant="outline" tone="run" onClick={runAgents} loading={busy} disabled={!canRun}
              title={canRun ? "Run the five review agents and draft a change package" : "Running agents requires the admin or analyst role"}>
              <Bot size={12} /> Run agents
            </Button>
          </div>
        )}
      </div>

      {exp.status === "rejected" && (
        <div role="alert" className="mx-4 mb-3 flex gap-2.5 rounded-md border border-err-line bg-err-bg px-3 py-2.5">
          <XOctagon size={15} className="mt-0.5 shrink-0 text-err" />
          <div className="min-w-0">
            <div className="text-[12.5px] font-semibold text-err">Rejected by the intake</div>
            <p className="mt-0.5 text-[12.5px] leading-[1.55] break-words text-fg">
              {exp.rejection_reason || "The intake recorded no reason. That is itself a defect worth reporting."}
            </p>
          </div>
        </div>
      )}

      {exp.status === "accepted" && s && (
        <div className="flex flex-wrap items-end gap-x-6 gap-y-2 border-t border-line px-4 py-2.5">
          <Count label="Rules" value={s.rules} />
          <Count label="Enabled" value={s.rules_enabled} />
          <Count label="Grants" value={s.grants} />
          <Count label="NAT rules" value={s.nat_rules} />
          <Count label="Flagged rules" value={review?.rules_with_findings} />
          {review && (
            <div className="flex flex-col">
              <span className="text-[10.5px] text-faint">By worst band</span>
              <span className="flex gap-2.5 text-[12px]">
                {BANDS.map((b) => (
                  <span key={b} className={cn("tnum font-semibold", BAND_TEXT[b])}>{review.by_band?.[b] ?? 0} {b}</span>
                ))}
              </span>
            </div>
          )}
          <div className="flex flex-col">
            <span className="text-[10.5px] text-faint">Layers</span>
            <span className="text-[12px] text-dim">{s.layers?.length ? s.layers.join(", ") : "—"}</span>
          </div>
          {!s.hit_counts_present && <Chip variant="warn">no hit counters in export</Chip>}
          {!!s.limitations_total && <Chip variant="warn">{s.limitations_total} limitation{s.limitations_total === 1 ? "" : "s"}</Chip>}
        </div>
      )}
      {exp.status === "accepted" && !s && (
        <p className="border-t border-line px-4 py-2.5 text-[11.5px] text-faint">Accepted, but the API returned no summary for it.</p>
      )}
      {runErr && <div className="border-t border-line px-4 py-2"><ActionError action="start a review run" error={runErr} /></div>}
    </article>
  );
}
