"use client";

/**
 * THE INVENTORY TABLE — every entity, what KIND it is, and WHERE WE FOUND IT.
 *
 * The last column is the one the review is actually about. `observed_by` is a
 * LIST, not a winner: a firewall that FortiManager, the FortiGate itself and
 * AlgoSec all describe gets three badges, each carrying the tier its claim
 * came from. That is "where did we find it" answered properly, and it is why
 * the column is never collapsed to a single "source".
 */

import { TriangleAlert } from "lucide-react";
import type { InventoryItem, SourceCard } from "@/lib/types";
import { cn } from "@/lib/cn";
import { SortTh, useFilterSort } from "@/lib/tableTools";
import { NetIcon } from "@/components/net/icons";
import { Skeleton } from "@/components/ui";
import { AddressList, SourceBadges, Unreported } from "./bits";

export type DrawerFocus = "top" | "conflicts";

const COLS = 10;

export function InventoryTable({ items, cards, loading, hasMore, onOpen }: {
  items: InventoryItem[];
  cards?: Record<string, SourceCard>;
  loading?: boolean;
  hasMore?: boolean;
  onOpen: (item: InventoryItem, focus: DrawerFocus) => void;
}) {
  // Sorting is CLIENT-SIDE and therefore orders the loaded page only. Filtering
  // and paging are the server's, so the note under the table says which of the
  // two the reader is looking at rather than letting a sorted page imply a
  // sorted estate.
  const t = useFilterSort(items, {
    sorts: {
      name: (i) => i.name.toLowerCase(),
      kind: (i) => i.kind,
      make: (i) => `${i.vendor ?? "￿"} ${i.model ?? ""}`.toLowerCase(),
      os: (i) => (i.os_version ?? "￿").toLowerCase(),
      addresses: (i) => i.addresses.length,
      vlan: (i) => (i.vlan_id ?? Number.MAX_SAFE_INTEGER),
      subnet: (i) => (i.subnet ?? "￿"),
      zone: (i) => (i.zone ?? "￿"),
      sources: (i) => i.observed_by.length,
      findings: (i) => i.finding_ids.length,
    },
    initialSort: "name",
  });

  return (
    <div className="border border-border">
      <div className="zt-scroll overflow-x-auto">
        <table className="w-full min-w-[1140px] border-collapse text-[12.5px]">
          <thead>
            <tr className="border-b border-border bg-surface2 text-left">
              <SortTh label="Name" sortKey="name" state={t} className="!pl-3" />
              <SortTh label="Kind" sortKey="kind" state={t} />
              <SortTh label="Make / model" sortKey="make" state={t} />
              <SortTh label="OS" sortKey="os" state={t} />
              <SortTh label="Addresses" sortKey="addresses" state={t} />
              <SortTh label="VLAN" sortKey="vlan" state={t} />
              <SortTh label="Subnet" sortKey="subnet" state={t} />
              <SortTh label="Zone" sortKey="zone" state={t} />
              <SortTh label="Source(s)" sortKey="sources" state={t} />
              <SortTh label="Findings" sortKey="findings" state={t} className="!pr-3" />
            </tr>
          </thead>
          <tbody>
            {loading && items.length === 0
              ? Array.from({ length: 8 }).map((_, i) => <SkeletonRow key={i} />)
              : t.rows.map((item) => <Row key={item.key} item={item} cards={cards} onOpen={onOpen} />)}
          </tbody>
        </table>
      </div>
      {t.rows.length > 0 && hasMore ? (
        <p className="border-t border-hair px-3 py-1.5 text-[11px] text-text3">
          Sorting orders the {t.rows.length} rows on this page. The filter and the paging are the server&apos;s — there are
          more matches than these.
        </p>
      ) : null}
    </div>
  );
}

function Row({ item, cards, onOpen }: {
  item: InventoryItem;
  cards?: Record<string, SourceCard>;
  onOpen: (item: InventoryItem, focus: DrawerFocus) => void;
}) {
  const conflicts = item.conflicts.length;
  return (
    <tr
      onClick={() => onOpen(item, "top")}
      title="Open the full record — every field, every source, every conflict"
      className="row cursor-pointer border-b border-hair align-top last:border-0"
    >
      <td className="py-2 pl-3 pr-3">
        <span className="flex items-start gap-2">
          <span className="mt-[1px] shrink-0 text-text2">
            <NetIcon kind={item.kind} size={15} />
          </span>
          <span className="min-w-0">
            <span className="flex flex-wrap items-center gap-1.5">
              {/* The row is clickable for the mouse, but the keyboard and a
                  screen reader get a real control rather than a tabbable <tr>,
                  which would cost the table its row semantics. */}
              <button
                type="button"
                onClick={(e) => { e.stopPropagation(); onOpen(item, "top"); }}
                className="break-all text-left font-bold transition-colors hover:text-accent-fg focus-visible:text-accent-fg"
              >
                {item.name}
              </button>
              {conflicts > 0 ? (
                <button
                  type="button"
                  onClick={(e) => { e.stopPropagation(); onOpen(item, "conflicts"); }}
                  title={`Two sources state ${conflicts === 1 ? "this field" : "these fields"} differently: ${item.conflicts.map((c) => c.field).join(", ")}. Click to see both claims and both tools.`}
                  className="inline-flex h-[18px] shrink-0 items-center gap-1 border border-sev-high-line bg-sev-high-bg px-1 text-[10px] font-bold text-sev-high transition-colors hover:border-sev-high"
                >
                  <TriangleAlert size={10} />
                  {conflicts}
                </button>
              ) : null}
            </span>
            <span className="mono block break-all text-[10.5px] text-text3">{item.key}</span>
            {item.tags.length > 0 ? (
              <span className="mt-0.5 block truncate text-[10.5px] text-text3" title={item.tags.join(", ")}>
                {item.tags.join(" · ")}
              </span>
            ) : null}
          </span>
        </span>
      </td>

      <td className="py-2 pr-3">
        <KindCell item={item} />
      </td>

      <td className="py-2 pr-3 text-text2">
        {item.vendor || item.model ? (
          <>
            <span className="block">{item.vendor ?? <Unreported what="a vendor" />}</span>
            <span className="mono block text-[11px] text-text3">{item.model ?? ""}</span>
          </>
        ) : (
          <Unreported what="a make or model" />
        )}
      </td>

      <td className="py-2 pr-3">
        {item.os_version ? <span className="mono text-[11.5px] text-text2">{item.os_version}</span> : <Unreported what="an OS version" />}
      </td>

      <td className="py-2 pr-3">
        <AddressList addresses={item.addresses} />
      </td>

      <td className="py-2 pr-3">
        {item.vlan_id == null && !item.vlan_name ? (
          <Unreported what="a VLAN" />
        ) : (
          <span className="whitespace-nowrap">
            <span className="mono tabular-nums">{item.vlan_id ?? "?"}</span>
            {item.vlan_name ? <span className="text-text2"> · {item.vlan_name}</span> : null}
          </span>
        )}
      </td>

      <td className="py-2 pr-3">
        {item.subnet ? <span className="mono whitespace-nowrap text-[11.5px]">{item.subnet}</span> : <Unreported what="a subnet" />}
      </td>

      <td className="py-2 pr-3">
        {item.zone ? <span className="text-text2">{item.zone}</span> : <Unreported what="a zone" />}
      </td>

      <td className="py-2 pr-3">
        <SourceBadges observed={item.observed_by} cards={cards} />
      </td>

      <td className="py-2 pr-3">
        {item.finding_ids.length > 0 ? (
          <span
            className="inline-flex h-[21px] items-center border border-sev-high-line bg-sev-high-bg px-1.5 text-[11px] font-bold tabular-nums text-sev-high"
            title={`Named in ${item.finding_ids.length} finding${item.finding_ids.length === 1 ? "" : "s"}: ${item.finding_ids.join(", ")}`}
          >
            {item.finding_ids.length}
          </span>
        ) : (
          <span className="text-text3 tabular-nums" title="This entity is named in no finding in this snapshot.">0</span>
        )}
      </td>
    </tr>
  );
}

/**
 * The Kind cell, and the product showing its working.
 *
 * `role_source: "derived"` means NO SOURCE SAID THIS — the engine concluded it,
 * and `role_reason` is the argument. A derived kind therefore renders with a
 * dotted underline carrying that reason, so a conclusion never sits on the
 * screen looking like a declaration.
 */
function KindCell({ item }: { item: InventoryItem }) {
  const src = item.role_source;
  const derived = src === "derived";
  const unknownSource = src === "unknown";
  const reason = item.role_reason?.trim();
  return (
    <span className="inline-flex flex-col gap-0.5">
      <span
        className={cn(
          "whitespace-nowrap",
          derived && "cursor-help underline decoration-dotted decoration-from-font underline-offset-[3px]",
        )}
        title={
          derived
            ? `Derived by the engine — no source declared this role.${reason ? `\n\n${reason}` : "\n\nNo reason was supplied with it."}`
            : src === "declared"
              ? "Declared by a source, verbatim."
              : undefined
        }
      >
        {item.kind}
      </span>
      {derived ? (
        <span className="text-[9.5px] font-bold uppercase tracking-[0.1em] text-text3">derived</span>
      ) : unknownSource ? (
        <span
          className="cursor-help text-[9.5px] font-bold uppercase tracking-[0.1em] text-text3"
          title="No source declared this role and the engine could not derive one. The kind above is what the entity was filed under, not a claim about what it is."
        >
          role unknown
        </span>
      ) : null}
    </span>
  );
}

function SkeletonRow() {
  return (
    <tr className="border-b border-hair last:border-0">
      {Array.from({ length: COLS }).map((_, i) => (
        <td key={i} className={cn("py-2 pr-3", i === 0 && "pl-3")}>
          <Skeleton className={cn("h-3.5", i === 0 ? "w-40" : i === 4 ? "w-28" : i === 8 ? "w-24" : "w-16")} />
        </td>
      ))}
    </tr>
  );
}

export default InventoryTable;
