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
import { Button, Checkbox, EmptyState, Field, Input, Select, Skeleton } from "../ui";
import { InlineError } from "../ui/Feedback";
import { ActionError, BANDS, hasDuty, hasDutyForAll, impactMeta } from "./bits";
import { PackageItemCard } from "./PackageItemCard";

const PAGE = 25;

export function PackageItemsList({ pkg, me, meLoading, onDecided }: {
  pkg: ChangePackage;
  me: FrrMe | undefined;
  meLoading: boolean;
  /** A decision was recorded (one item, or a bulk decision when `it` is absent). */
  onDecided: (it?: PackageItem) => void;
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
  const isOwner = pkg.status === "draft" && hasDutyForAll(me, "network_owner", Object.keys(f?.by_layer ?? {}));
  const [bulkNote, setBulkNote] = useState("");
  const [bulkBusy, setBulkBusy] = useState(false);
  const [bulkErr, setBulkErr] = useState<unknown>();
  const [bulkDone, setBulkDone] = useState<string>();
  const bulk = (decision: "accept" | "reject") => {
    setBulkBusy(true);
    setBulkErr(undefined);
    setBulkDone(undefined);
    frr.bulkDecide(pkg.package_id, { decision, note: bulkNote.trim() || undefined, band: band || undefined,
                                     impact: impact || undefined, undecided_only: true })
      .then((r) => {
        setBulkDone(`${decision === "accept" ? "Accepted" : "Rejected"} ${r.decided} of ${r.matched} matching item(s)`
          + (r.skipped_need_input ? `; ${r.skipped_need_input} need your input and must be decided one by one` : "") + ".");
        setOffset(0);
        setAttempt((n) => n + 1);
        onDecided();                                           // refresh the package facets
      })
      .catch(setBulkErr)
      .finally(() => setBulkBusy(false));
  };
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
      {isOwner && page && page.total > 1 && (
        <div className="flex flex-wrap items-end gap-2 rounded-md border border-line bg-raise/40 p-2.5">
          <div className="mb-1.5 text-[12px] text-dim">
            Decide every <strong className="text-fg">undecided</strong> item matching these filters at once:
          </div>
          <Field label="Note (required to reject)" htmlFor="pkg-bulk-note" className="min-w-[16rem] flex-1">
            <Input id="pkg-bulk-note" value={bulkNote} maxLength={4000} onChange={(e) => setBulkNote(e.target.value)} />
          </Field>
          <Button size="sm" tone="ink" loading={bulkBusy} onClick={() => bulk("accept")}>Accept all</Button>
          <Button size="sm" variant="outline" tone="ink" loading={bulkBusy} disabled={!bulkNote.trim()}
            onClick={() => bulk("reject")}>Reject all</Button>
          {bulkDone && <p role="status" className="basis-full text-[11.5px] text-dim">{bulkDone}</p>}
          {bulkErr !== undefined && <ActionError action="apply the bulk decision" error={bulkErr} className="basis-full" />}
        </div>
      )}
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
