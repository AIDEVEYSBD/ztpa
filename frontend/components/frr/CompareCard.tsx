"use client";

/**
 * What changed since an earlier review of the same rulebase: findings that are
 * new, findings that are gone, rules added or removed, bands that moved. Keyed by
 * the console's rule uid, which survives renumbering.
 */

import { useEffect, useState } from "react";
import { GitCompareArrows } from "lucide-react";
import { asApiError, type ApiError } from "@/lib/api";
import { frr } from "@/lib/frr";
import type { CompareResult, FrrExport } from "@/lib/frrTypes";
import { Chip, Field, KpiBand, KpiTile, Select, SeverityPill, Skeleton } from "../ui";
import { InlineError } from "../ui/Feedback";
import { checkLabel, when } from "./bits";

export function CompareCard({ exportId }: { exportId: string }) {
  const [candidates, setCandidates] = useState<FrrExport[]>();
  const [listErr, setListErr] = useState<ApiError>();
  const [baseline, setBaseline] = useState("");
  const [result, setResult] = useState<CompareResult>();
  const [err, setErr] = useState<ApiError>();
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    let live = true;
    frr.exports({ limit: 50 })
      .then((r) => { if (live) setCandidates(r.items.filter((e) => e.status === "accepted" && e.export_id !== exportId)); })
      .catch((e) => { if (live) setListErr(asApiError(e)); });
    return () => { live = false; };
  }, [exportId]);

  useEffect(() => {
    if (!baseline) { setResult(undefined); return; }
    let live = true;
    setLoading(true);
    setErr(undefined);
    frr.compare(exportId, baseline)
      .then((r) => { if (live) setResult(r); })
      .catch((e) => { if (live) { setResult(undefined); setErr(asApiError(e)); } })
      .finally(() => { if (live) setLoading(false); });
    return () => { live = false; };
  }, [exportId, baseline]);

  return (
    <section aria-labelledby="frr-compare" className="rounded-lg border border-line bg-surface p-3.5 elev-1">
      <h3 id="frr-compare" className="flex items-center gap-1.5 text-[13px] font-medium text-fg">
        <GitCompareArrows size={14} className="text-dim" /> Compare with an earlier review
      </h3>
      {listErr ? <InlineError resource="earlier exports" error={listErr} /> : !candidates ? <Skeleton className="mt-2 h-8 w-72" /> : (
        <Field label="Earlier export" htmlFor="frr-baseline" className="mt-2 max-w-md">
          <Select id="frr-baseline" value={baseline} onChange={(e) => setBaseline(e.target.value)}>
            <option value="">{candidates.length ? "Choose…" : "No other accepted export"}</option>
            {candidates.map((e) => (
              <option key={e.export_id} value={e.export_id}>{e.filename ?? e.export_id.slice(0, 8)} · exported {e.exported_at ? when(e.exported_at) : "?"}</option>
            ))}
          </Select>
        </Field>
      )}
      {err && <div className="mt-2"><InlineError resource="the comparison" error={err} /></div>}
      {loading && <Skeleton className="mt-3 h-16 w-full" />}
      {result && !loading && (
        <div className="mt-3 space-y-3">
          <KpiBand className="xl:grid-cols-5">
            <KpiTile label="New findings" value={result.summary.findings_new} tone={result.summary.findings_new ? "warn" : undefined} />
            <KpiTile label="Resolved findings" value={result.summary.findings_resolved} />
            <KpiTile label="Rules added" value={result.summary.rules_added} />
            <KpiTile label="Rules removed" value={result.summary.rules_removed} />
            <KpiTile label="Band changes" value={result.summary.band_changes} />
          </KpiBand>
          <div className="grid gap-3 lg:grid-cols-2">
            <div>
              <div className="mb-1 text-[11.5px] font-medium text-dim">New since then (worst first)</div>
              <ul className="space-y-1 text-[12px]">
                {result.new_findings.slice(0, 25).map((f) => (
                  <li key={`${f.rule_uid}-${f.check}`} className="flex flex-wrap items-center gap-2">
                    {f.band && <SeverityPill band={f.band} />}
                    <span className="font-mono text-dim">#{f.number ?? "?"}</span>
                    <span className="text-fg">{f.name ?? f.rule_uid}</span>
                    <Chip variant="neutral">{checkLabel(f.check)}</Chip>
                    {f.new_rule && <Chip variant="info">new rule</Chip>}
                  </li>
                ))}
                {result.new_findings.length === 0 && <li className="text-faint">None.</li>}
              </ul>
            </div>
            <div>
              <div className="mb-1 text-[11.5px] font-medium text-dim">Resolved since then</div>
              <ul className="space-y-1 text-[12px]">
                {result.resolved_findings.slice(0, 25).map((f) => (
                  <li key={`${f.rule_uid}-${f.check}`} className="flex flex-wrap items-center gap-2">
                    <span className="font-mono text-dim">#{f.number ?? "?"}</span>
                    <span className="text-fg">{f.name ?? f.rule_uid}</span>
                    <Chip variant="ok">{checkLabel(f.check)}</Chip>
                    {f.rule_removed && <Chip variant="neutral">rule removed</Chip>}
                  </li>
                ))}
                {result.resolved_findings.length === 0 && <li className="text-faint">None.</li>}
              </ul>
            </div>
          </div>
          {(result.new_findings.length >= result.limit || result.resolved_findings.length >= result.limit) && (
            <p className="text-[11px] text-faint">Lists show the first {result.limit} of each; counts above are complete.</p>
          )}
        </div>
      )}
    </section>
  );
}
