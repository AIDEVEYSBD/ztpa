"use client";

/**
 * Rule Review · Register — the deterministic rule-risk register for one export.
 *
 * The limitations box is never collapsible and never hidden while non-empty: it
 * is the statement of what this review could NOT see (no hit counters, objects
 * that did not resolve, layers skipped), and a register read without it claims
 * more than it proves.
 */

import { useEffect, useState } from "react";
import { ChevronLeft, ChevronRight, Info, RotateCw, ShieldCheck } from "lucide-react";
import { asApiError, type ApiError } from "@/lib/api";
import { frr } from "@/lib/frr";
import { CHECK_KINDS, type FrrExport, type ReviewPage } from "@/lib/frrTypes";
import type { Band } from "@/lib/types";
import { Button, Checkbox, EmptyState, Field, KpiBand, KpiTile, Select, Skeleton } from "../ui";
import { ErrorState, InlineError } from "../ui/Feedback";
import { BANDS, checkLabel, when } from "./bits";
import { RegisterTable } from "./RegisterTable";

const PAGE_SIZES = [25, 50, 100] as const;

export function ReviewScreen({ exportId, onGoToExports }: { exportId: string; onGoToExports: () => void }) {
  const [exp, setExp] = useState<FrrExport>();
  const [expErr, setExpErr] = useState<ApiError>();
  const [page, setPage] = useState<ReviewPage>();
  const [err, setErr] = useState<ApiError>();
  const [loading, setLoading] = useState(true);
  const [band, setBand] = useState<Band | "">("");
  const [check, setCheck] = useState("");
  const [flaggedOnly, setFlaggedOnly] = useState(true);
  const [limit, setLimit] = useState<number>(50);
  const [offset, setOffset] = useState(0);
  const [attempt, setAttempt] = useState(0);

  useEffect(() => {
    let live = true;
    setExpErr(undefined);
    frr.exportById(exportId)
      .then((e) => { if (live) setExp(e); })
      .catch((e) => { if (live) setExpErr(asApiError(e)); });
    return () => { live = false; };
  }, [exportId, attempt]);

  useEffect(() => {
    let live = true;
    setLoading(true);
    setErr(undefined);
    frr.review(exportId, { band: band || undefined, check: check || undefined, flagged_only: flaggedOnly, limit, offset })
      .then((p) => { if (live) setPage(p); })
      .catch((e) => { if (live) { setPage(undefined); setErr(asApiError(e)); } })
      .finally(() => { if (live) setLoading(false); });
    return () => { live = false; };
  }, [exportId, band, check, flaggedOnly, limit, offset, attempt]);

  const retry = () => setAttempt((n) => n + 1);
  const resetPaging = () => setOffset(0);

  const header = (
    <div className="flex flex-wrap items-center gap-2">
      <div className="min-w-0">
        <div className="text-[13px] font-semibold">{exp?.filename ?? (expErr ? "Export" : <Skeleton className="h-4 w-48" />)}</div>
        <div className="text-[11px] text-faint">
          {exp ? `uploaded ${when(exp.uploaded_at)} · exported ${exp.exported_at ? when(exp.exported_at) : "at an unknown time"}` : null}
          {page?.reference_time ? ` · ages and expiry measured from ${when(page.reference_time)}` : null}
        </div>
      </div>
      <Button size="sm" variant="quiet" tone="neutral" className="ml-auto" onClick={onGoToExports}>Change export</Button>
      <Button size="sm" variant="quiet" tone="neutral" onClick={retry} loading={loading}><RotateCw size={12} /> Refresh</Button>
    </div>
  );

  if (err && !page) {
    return (
      <div className="space-y-4">
        {header}
        {expErr && <InlineError resource="the export record" error={expErr} onRetry={retry} />}
        <ErrorState resource="the rule-risk register" error={err} onRetry={retry} />
      </div>
    );
  }

  const stats = page?.stats;
  const first = page && page.total > 0 ? page.offset + 1 : 0;
  const last = page ? page.offset + page.items.length : 0;

  return (
    <div className="space-y-4">
      {header}
      {expErr && <InlineError resource="the export record" error={expErr} onRetry={retry} />}

      {!stats ? (
        <Skeleton className="h-[68px] w-full rounded-md" />
      ) : (
        <KpiBand className="xl:grid-cols-6">
          <KpiTile label="Rules" value={stats.rules} sub="in the export"
            active={!band && !flaggedOnly} onOpen={() => { setBand(""); setFlaggedOnly(false); resetPaging(); }} />
          <KpiTile label="Flagged" value={stats.rules_with_findings} sub="rules with at least one finding"
            active={!band && flaggedOnly} onOpen={() => { setBand(""); setFlaggedOnly(true); resetPaging(); }} />
          {BANDS.map((b) => (
            <KpiTile key={b} label={`Worst band: ${b}`} value={stats.by_band?.[b] ?? 0}
              tone={b === "critical" ? "err" : b === "high" ? "warn" : b === "medium" ? "run" : undefined}
              active={band === b} onOpen={() => { setBand(band === b ? "" : b); resetPaging(); }} />
          ))}
        </KpiBand>
      )}

      {page && page.limitations.length > 0 && (
        <section aria-labelledby="frr-limits" className="relative overflow-hidden rounded-lg border border-warn-line bg-surface p-3.5 pl-4 elev-1">
          <span aria-hidden className="absolute inset-y-0 left-0 w-[3px] bg-warn" />
          <h3 id="frr-limits" className="flex items-center gap-1.5 text-[13px] font-medium text-fg">
            <Info size={14} className="text-warn" /> What this review cannot prove ({page.limitations.length})
          </h3>
          <p className="mt-0.5 text-[11.5px] text-dim">These bound every finding below. A rule absent from the register is not proven safe where one of these applies.</p>
          <ul className="mt-2 space-y-1 text-[12px] leading-[1.5] text-fg">
            {page.limitations.map((l, i) => <li key={i} className="flex gap-2"><span className="text-faint">·</span><span className="min-w-0 break-words">{l}</span></li>)}
          </ul>
        </section>
      )}

      <div className="flex flex-wrap items-end gap-3">
        <Field label="Band" htmlFor="frr-band" className="w-40">
          <Select id="frr-band" value={band} onChange={(e) => { setBand(e.target.value as Band | ""); resetPaging(); }}>
            <option value="">All bands</option>
            {BANDS.map((b) => <option key={b} value={b}>{b}</option>)}
          </Select>
        </Field>
        <Field label="Check" htmlFor="frr-check" className="w-52">
          <Select id="frr-check" value={check} onChange={(e) => { setCheck(e.target.value); resetPaging(); }}>
            <option value="">All checks</option>
            {CHECK_KINDS.map((c) => (
              <option key={c} value={c}>{checkLabel(c)}{stats?.by_check?.[c] != null ? ` (${stats.by_check[c]})` : ""}</option>
            ))}
          </Select>
        </Field>
        <Field label="Page size" htmlFor="frr-limit" className="w-28">
          <Select id="frr-limit" value={limit} onChange={(e) => { setLimit(Number(e.target.value)); resetPaging(); }}>
            {PAGE_SIZES.map((n) => <option key={n} value={n}>{n}</option>)}
          </Select>
        </Field>
        <Checkbox className="mb-2" checked={flaggedOnly} disabled={!!band}
          onChange={(v) => { setFlaggedOnly(v); resetPaging(); }} label="Flagged rules only" />
        <span className="mb-2 ml-auto text-[11.5px] text-faint">
          {page ? (page.total === 0 ? "0 rules" : `${first}–${last} of ${page.total} rules`) : "…"}
        </span>
      </div>

      {err && <InlineError resource="this page of the register" error={err} onRetry={retry} />}

      {!page ? (
        <div className="space-y-2">
          {Array.from({ length: 6 }).map((_, i) => <Skeleton key={i} className="h-9 w-full" />)}
        </div>
      ) : page.items.length === 0 ? (
        <EmptyState icon={ShieldCheck}
          title={page.total === 0 ? (band || check ? "No rules match these filters" : flaggedOnly ? "No rule has a finding" : "The export has no rules") : "No rules on this page"}
          sub={page.total === 0
            ? "This is what the deterministic checks found within the limitations above — not a statement that the policy is safe."
            : "The register is shorter than this offset. Go back a page."} />
      ) : (
        <div className={loading ? "opacity-60 transition-opacity" : undefined}>
          <RegisterTable items={page.items} />
        </div>
      )}

      {page && page.total > 0 && (
        <div className="flex items-center gap-2">
          <Button size="sm" variant="outline" tone="ink" disabled={offset === 0 || loading}
            onClick={() => setOffset(Math.max(0, offset - limit))}><ChevronLeft size={12} /> Previous</Button>
          <Button size="sm" variant="outline" tone="ink" disabled={last >= page.total || loading}
            onClick={() => setOffset(offset + limit)}>Next <ChevronRight size={12} /></Button>
          <span className="text-[11px] text-faint">page {Math.floor(offset / limit) + 1} of {Math.max(1, Math.ceil(page.total / limit))}</span>
        </div>
      )}
    </div>
  );
}
