"use client";

import { useCallback, useEffect, useState } from "react";
import { GitMerge, Layers, Link2, Check } from "lucide-react";
import { api } from "@/lib/api";
import type { Asset, Correlation, MergeSuggestion } from "@/lib/types";
import { ToolBadge, Tag, Chip, Skeleton, SkeletonText, Spinner, Eyebrow, EmptyState } from "./ui";
import { Prose } from "./Markdown";
import { useFilterSort, SearchBox, SortTh } from "@/lib/tableTools";

export function AssetsPanel({ snapshot }: { snapshot?: string }) {
  const [assets, setAssets] = useState<Asset[]>([]);
  const [corr, setCorr] = useState<Correlation[]>([]);
  const [sugg, setSugg] = useState<MergeSuggestion[]>();
  const [loading, setLoading] = useState(true);
  const [merging, setMerging] = useState<string>();   // "a~b" of the pair being merged
  const isLive = !snapshot;                            // merges only apply to the live snapshot

  const load = useCallback((withSpinner = true) => {
    let live = true;
    if (withSpinner) setLoading(true);
    api.assets(snapshot).then((a) => { if (live) { setAssets(a.assets); setCorr(a.correlations); } }).catch(() => {}).finally(() => { if (live) setLoading(false); });
    api.mergeSuggestions().then((s) => { if (live) setSugg(s.suggestions); }).catch(() => { if (live) setSugg([]); });
    return () => { live = false; };
  }, [snapshot]);

  useEffect(() => load(), [load]);

  const confirmMerge = async (a: string, b: string) => {
    setMerging(`${a}~${b}`);
    try { await api.confirmMerge(a, b); setSugg(undefined); load(false); }
    catch { /* ignore */ } finally { setMerging(undefined); }
  };

  const merged = new Set(corr.map((c) => c.asset_id));
  const t = useFilterSort(assets, {
    search: (a) => `${a.asset_key} ${a.kind} ${a.tags.join(" ")} ${a.ip_set.join(" ")} ${a.source_tools.join(" ")}`,
    sorts: {
      asset: (a) => a.asset_key, kind: (a) => a.kind,
      addresses: (a) => a.ip_set.length, seen: (a) => a.source_tools.length,
    },
    initialSort: "asset",
  });

  return (
    <div className="grid gap-4 lg:grid-cols-[1fr_340px]">
      <div className="panel p-4">
        <div className="mb-3 flex flex-wrap items-center gap-2">
          <Eyebrow><Layers size={13} /> Unified assets ({t.rows.length}{t.rows.length !== assets.length ? ` of ${assets.length}` : ""})</Eyebrow>
          <SearchBox value={t.q} onChange={t.setQ} placeholder="Filter assets, tags, IPs…" className="sm:ml-auto" />
        </div>
        <p className="mb-3 text-xs text-text2">One identity per asset. IP is an attribute, not the key. Multi-tool assets were correlated deterministically (exact name or shared IP).</p>
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead className="text-left text-xs text-text3">
              <tr className="border-b border-hair">
                <SortTh label="Asset" sortKey="asset" state={t} />
                <SortTh label="Kind" sortKey="kind" state={t} />
                <th className="py-1.5 pr-3 font-medium">Tags</th>
                <SortTh label="Addresses" sortKey="addresses" state={t} />
                <SortTh label="Seen by" sortKey="seen" state={t} />
              </tr>
            </thead>
            <tbody>
              {loading && assets.length === 0 ? (
                Array.from({ length: 6 }).map((_, i) => (
                  <tr key={i} className="border-b border-hair last:border-0">
                    <td className="py-2 pr-3"><Skeleton className="h-3.5 w-32" /></td>
                    <td className="pr-3"><Skeleton className="h-3 w-14" /></td>
                    <td className="pr-3"><Skeleton className="h-4 w-16" /></td>
                    <td className="pr-3"><Skeleton className="h-3 w-24" /></td>
                    <td><Skeleton className="h-4 w-20" /></td>
                  </tr>
                ))
              ) : t.rows.map((a) => (
                <tr key={a.asset_id} className="border-b border-hair last:border-0">
                  <td className="py-1.5 pr-3 font-medium">
                    <span className="inline-flex items-center gap-1.5">
                      <span className="break-all">{a.asset_key}</span>
                      {merged.has(a.asset_id) && <Link2 size={12} className="shrink-0 text-accent-fg" aria-label="cross-tool correlated" />}
                    </span>
                  </td>
                  <td className="pr-3 text-xs text-text2">{a.kind}</td>
                  <td className="space-x-1 pr-3">{a.tags.map((t) => <Tag key={t}>{t}</Tag>)}</td>
                  <td className="pr-3 font-mono text-[11px] text-text2">{a.ip_set.join(", ") || "-"}</td>
                  <td className="space-x-1">{a.source_tools.map((t) => <ToolBadge key={t} tool={t} />)}</td>
                </tr>
              ))}
              {!loading && t.rows.length === 0 && (
                <tr><td colSpan={5}><EmptyState icon={Layers} title="No matching assets" sub="No assets match this filter." /></td></tr>
              )}
            </tbody>
          </table>
        </div>
      </div>

      <div className="space-y-3">
        <Eyebrow><GitMerge size={13} /> Possible duplicates (review)</Eyebrow>
        <p className="text-xs text-text2">Embedding-based suggestions for a human to confirm. The engine never auto-merges (a wrong merge corrupts a fact).</p>
        {sugg === undefined ? (
          <div className="space-y-3">
            {Array.from({ length: 2 }).map((_, i) => (
              <div key={i} className="panel space-y-2 p-3">
                <Skeleton className="h-4 w-3/4" />
                <Skeleton className="h-3 w-1/2" />
                <SkeletonText lines={2} />
              </div>
            ))}
          </div>
        ) : sugg.length === 0 ? <div className="panel"><EmptyState icon={GitMerge} title="No candidates" sub="All identities resolved deterministically." /></div> :
            sugg.map((s, i) => {
              const busy = merging === `${s.a}~${s.b}`;
              return (
                <div key={i} className="panel p-3">
                  <div className="flex flex-wrap items-center gap-2 text-sm font-medium">
                    <span className="mono break-all">{s.a}</span><span className="text-text3">~</span><span className="mono break-all">{s.b}</span>
                    <Chip variant="accent" mono className="ml-auto">{(s.confidence * 100).toFixed(0)}%</Chip>
                  </div>
                  <div className="mt-1 flex flex-wrap gap-1">{s.shared_sensitive_tags.map((t) => <Tag key={t}>{t}</Tag>)}</div>
                  <div className="mt-2 text-xs text-text2"><Prose className="!text-xs">{s.reason}</Prose></div>
                  <button onClick={() => confirmMerge(s.a, s.b)} disabled={!isLive || !!merging}
                    className="btn-primary mt-2 w-full text-xs disabled:opacity-50"
                    title={isLive ? "Unify these into one asset (re-resolves identities + recomputes)" : "Switch to the live snapshot to confirm merges"}>
                    {busy ? <Spinner label="Merging + recomputing…" /> : <><Check size={13} /> Confirm merge</>}
                  </button>
                </div>
              );
            })}
        {sugg && sugg.length > 0 && !isLive && (
          <p className="text-[11px] text-text3">Viewing a past snapshot. Switch to <b className="text-text2">Live</b> to confirm a merge.</p>
        )}
      </div>
    </div>
  );
}
