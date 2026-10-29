"use client";

/**
 * A package's items, a page at a time with filters, whatever the package size
 * (a 70,000-rule review drafts ~32,000 items). Counts come from the package's
 * facets; the list is always read from /items so small and large packages take
 * the same path.
 */

import { useEffect, useState } from "react";
import { ChevronLeft, ChevronRight, FileStack } from "lucide-react";
import { asApiError, type ApiError } from "@/lib/api";
import { frr } from "@/lib/frr";
import type { ChangePackage, FrrMe, PackageItem, PackageItemPage } from "@/lib/frrTypes";
import { Button, Checkbox, EmptyState, Field, Select, Skeleton } from "../ui";
import { InlineError } from "../ui/Feedback";
import { BANDS, hasDuty, impactMeta } from "./bits";
import { PackageItemCard } from "./PackageItemCard";

const PAGE = 25;

export function PackageItemsList({ pkg, me, meLoading, onDecided }: {
  pkg: ChangePackage;
  me: FrrMe | undefined;
  meLoading: boolean;
  onDecided: (it: PackageItem) => void;
}) {
  const f = pkg.facets;
  const [band, setBand] = useState("");
  const [impact, setImpact] = useState("");
  const [undecidedOnly, setUndecidedOnly] = useState(false);
  const [offset, setOffset] = useState(0);
  const [page, setPage] = useState<PackageItemPage>();
  const [err, setErr] = useState<ApiError>();
  const [attempt, setAttempt] = useState(0);

  useEffect(() => {
    let live = true;
    setErr(undefined);
    frr.pkgItems(pkg.package_id, { band: band || undefined, impact: impact || undefined,
                                   decided: undecidedOnly ? false : undefined, limit: PAGE, offset })
      .then((p) => { if (live) setPage(p); })
      .catch((e) => { if (live) setErr(asApiError(e)); });
    return () => { live = false; };
  }, [pkg.package_id, band, impact, undecidedOnly, offset, attempt]);

  const reset = () => setOffset(0);
  const decided = (it: PackageItem) => {
    setPage((p) => (p ? { ...p, items: p.items.map((x) => (x.item_id === it.item_id ? { ...x, ...it } : x)) } : p));
    onDecided(it);
  };

  if (f && f.total === 0) {
    return <EmptyState icon={FileStack} title="This package has no items" sub="The register produced no change proposals for this export." />;
  }
  const last = page ? page.offset + page.items.length : 0;
  return (
    <div className="space-y-3">
      <div className="flex flex-wrap items-end gap-3">
        <Field label="Band" htmlFor="pkg-band" className="w-40">
          <Select id="pkg-band" value={band} onChange={(e) => { setBand(e.target.value); reset(); }}>
            <option value="">All bands</option>
            {BANDS.map((b) => <option key={b} value={b}>{b}{f?.by_band?.[b] != null ? ` (${f.by_band[b]})` : ""}</option>)}
          </Select>
        </Field>
        <Field label="Availability impact" htmlFor="pkg-impact" className="w-52">
          <Select id="pkg-impact" value={impact} onChange={(e) => { setImpact(e.target.value); reset(); }}>
            <option value="">All</option>
            {Object.entries(f?.by_availability_impact ?? {}).map(([k, n]) => <option key={k} value={k}>{impactMeta(k).label} ({n})</option>)}
          </Select>
        </Field>
        <Checkbox className="mb-2" checked={undecidedOnly} onChange={(v) => { setUndecidedOnly(v); reset(); }}
          label={`Undecided only${f ? ` (${f.undecided})` : ""}`} />
        <span className="mb-2 ml-auto text-[11.5px] text-faint">
          {page ? (page.total === 0 ? "0 items" : `${page.offset + 1}–${last} of ${page.total}`) : "…"}
        </span>
      </div>
      {err && <InlineError resource="the package items" error={err} onRetry={() => setAttempt((n) => n + 1)} />}
      {!page ? (
        <div className="space-y-2">{Array.from({ length: 3 }).map((_, i) => <Skeleton key={i} className="h-28 w-full" />)}</div>
      ) : page.items.length === 0 ? (
        <EmptyState icon={FileStack} title="No items match these filters" />
      ) : (
        <div className="space-y-2.5">
          {page.items.map((it) => {
            const canDecide = pkg.status === "draft" && hasDuty(me, "network_owner", it.layer);
            const decideNote = pkg.status !== "draft" ? undefined
              : meLoading ? "Checking your duties…" : `Deciding needs the network_owner duty for layer ${it.layer}.`;
            return <PackageItemCard key={it.item_id} pkgId={pkg.package_id} item={it} canDecide={canDecide}
              decideNote={decideNote} onDecided={decided} />;
          })}
        </div>
      )}
      {page && page.total > PAGE && (
        <div className="flex items-center gap-2">
          <Button size="sm" variant="outline" tone="ink" disabled={offset === 0}
            onClick={() => setOffset(Math.max(0, offset - PAGE))}><ChevronLeft size={12} /> Previous</Button>
          <Button size="sm" variant="outline" tone="ink" disabled={last >= page.total}
            onClick={() => setOffset(offset + PAGE)}>Next <ChevronRight size={12} /></Button>
        </div>
      )}
    </div>
  );
}
