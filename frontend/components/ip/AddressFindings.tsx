"use client";

/**
 * SECTION 3 — THE FINDINGS THIS ADDRESS APPEARS IN.
 *
 * The ids are the address lookup's own answer and are authoritative here. The
 * titles and severities beside them come from a SECOND read (/api/findings), and
 * the two must not be allowed to fail as one: if the enrichment read dies, the
 * ids stay on screen with the failure named next to them, because "this address
 * is implicated in F-0041" is still true when we could not fetch what F-0041
 * says.
 *
 * Two qualifications ride on the enrichment payload and both change what an
 * EMPTY list means, so both are printed rather than kept:
 *   • `degraded_analyzers` non-empty — analyzers failed, so findings are MISSING
 *     from the snapshot. "No findings" cannot be read as clean.
 *   • `analysis_complete: null` — the API cannot say. Also not clean.
 */

import { ShieldAlert } from "lucide-react";
import type { Finding } from "@/lib/types";
import { Eyebrow, SeverityPill, Skeleton, cn } from "@/components/ui";
import { InlineError } from "@/components/ui/Feedback";
import type { FindingIndex, Loadable, SourceIndex } from "./data";
import { MonoChip, SourceToolBadge } from "./atoms";

function Completeness({ index }: { index?: FindingIndex }) {
  if (!index) return null;
  if (index.degradedAnalyzers.length > 0) {
    return (
      <p className="border border-sev-high-line bg-sev-high-bg px-3 py-2 text-[11.5px] leading-relaxed text-sev-high">
        <b>Findings are missing from this snapshot.</b>{" "}
        <span className="text-text2">
          {index.degradedAnalyzers.length} analyzer
          {index.degradedAnalyzers.length === 1 ? "" : "s"} did not finish (
          <span className="mono">{index.degradedAnalyzers.join(", ")}</span>), so whatever is listed here is
          a floor, not a total.
        </span>
      </p>
    );
  }
  if (index.analysisComplete === null) {
    return (
      <p className="border border-sev-medium-line bg-sev-medium-bg px-3 py-2 text-[11.5px] leading-relaxed text-sev-medium">
        <b>Analysis completeness is unknown for this snapshot.</b>{" "}
        <span className="text-text2">
          The API could not say whether every analyzer finished, so this list must not be read as exhaustive.
        </span>
      </p>
    );
  }
  return null;
}

function FindingRow({ f, sources }: { f: Finding; sources?: SourceIndex }) {
  return (
    <div className="space-y-1 border-b border-hair px-3 py-2 last:border-0">
      <div className="flex flex-wrap items-center gap-x-2.5 gap-y-1.5">
        <SeverityPill band={f.severity_band} severity={f.severity} forced={f.forced_critical} />
        <span className="mono text-[11.5px] font-bold">{f.type}</span>
        <span className="mono ml-auto text-[10.5px] text-text3">{f.finding_id}</span>
      </div>
      {f.involved.length > 0 && (
        <div className="mono break-all text-[11px] text-text2">{f.involved.join("  ·  ")}</div>
      )}
      {f.source_tools.length > 0 && (
        <div className="flex flex-wrap items-center gap-1">
          {f.source_tools.map((t) => (
            <SourceToolBadge key={t} tool={t} sources={sources} />
          ))}
        </div>
      )}
    </div>
  );
}

export function AddressFindings({
  ids,
  index,
  sources,
  address,
}: {
  ids: string[];
  index: Loadable<FindingIndex>;
  sources?: SourceIndex;
  address: string;
}) {
  const idx = index.data;

  return (
    <section className="space-y-3">
      <div className="flex flex-wrap items-center gap-2">
        <Eyebrow>Findings this address appears in</Eyebrow>
        <span className="mono text-[11px] text-text3">
          {ids.length} finding{ids.length === 1 ? "" : "s"}
        </span>
      </div>

      <Completeness index={idx} />

      {index.error && (
        <InlineError
          resource="the detail for these findings"
          error={index.error}
          className="border border-border bg-sunk px-3 py-2"
        />
      )}

      {ids.length === 0 ? (
        <p className="flex items-start gap-1.5 border border-border bg-sunk px-3 py-2.5 text-[12px] leading-relaxed text-text2">
          <ShieldAlert size={13} className="mt-0.5 shrink-0 text-text3" />
          <span>
            {address} appears in no finding in this snapshot
            {idx && idx.degradedAnalyzers.length > 0
              ? " — but see the analyzer failures above: this cannot be read as clean."
              : idx && idx.analysisComplete === null
                ? " — but completeness is unknown, so this cannot be read as clean."
                : "."}
          </span>
        </p>
      ) : (
        <div className="border border-border">
          {ids.map((id) => {
            const f = idx?.byId.get(id);
            if (f) return <FindingRow key={id} f={f} sources={sources} />;
            return (
              <div key={id} className={cn("flex flex-wrap items-center gap-2 border-b border-hair px-3 py-2 last:border-0")}>
                <span className="mono text-[11.5px] font-bold">{id}</span>
                {index.loading ? (
                  <Skeleton className="h-3 w-40" />
                ) : index.error ? (
                  <span className="text-[11px] text-text3">detail not loaded — the read above failed</span>
                ) : idx?.partial ? (
                  <MonoChip title={`The findings read returned ${idx.read} of ${idx.total}; this id was not on that page, which is not the same as it not existing.`}>
                    not on the page read ({idx.read}/{idx.total})
                  </MonoChip>
                ) : (
                  <MonoChip
                    tone="warn"
                    title={`All ${idx?.total ?? 0} findings in this snapshot were read and none carried this id. The address lookup and the findings list disagree.`}
                  >
                    not among this snapshot&apos;s findings
                  </MonoChip>
                )}
              </div>
            );
          })}
        </div>
      )}
    </section>
  );
}
