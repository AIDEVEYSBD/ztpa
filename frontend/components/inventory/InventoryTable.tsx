"use client";

/**
 * THE INVENTORY TABLE — every entity, what KIND it is, and WHERE WE FOUND IT.
 *
 * The `Source(s)` column is the one the review is actually about. `observed_by`
 * is a LIST, not a winner: a firewall that FortiManager, the FortiGate itself
 * and AlgoSec all describe gets three badges, each carrying the tier its claim
 * came from. That is "where did we find it" answered properly, and it is why
 * the column is never collapsed to a single "source".
 *
 * THE MECHANICS THAT MAKE IT USABLE ON A REAL ESTATE:
 *
 *   The header and the first column are BOTH sticky. Thirteen columns do not
 *   fit on a laptop, and a dense grid whose row labels scroll off the left is a
 *   grid nobody can read a value out of.
 *
 *   It scrolls INSIDE ITS OWN BOX. The page never scrolls sideways: the
 *   container is `overflow:auto` with a `min-w-0` chain above it, so the table
 *   can be as wide as it needs to be without dragging the whole console with
 *   it.
 *
 *   Under roughly 640px of available width it stops being a table at all and
 *   becomes a card list carrying the SAME columns. A thirteen-column grid
 *   squeezed into a phone is not a table, it is a puzzle.
 *
 *   Sorting is CLIENT-SIDE and therefore orders the LOADED PAGE only. Filtering
 *   and paging are the server's, so the note under the table says which of the
 *   two the reader is looking at rather than letting a sorted page imply a
 *   sorted estate.
 */

import { useEffect, useMemo, useRef, useState } from "react";
import { ArrowDown, ArrowUp, ArrowUpDown } from "lucide-react";
import type { InventoryItem } from "@/lib/types";
import { cn } from "@/lib/cn";
import { useFilterSort } from "@/lib/tableTools";
import { Skeleton } from "@/components/ui";
import { NetIcon } from "@/components/net/icons";
import { buildSorts, type CellCtx, type DrawerFocus, type InvColumn } from "./columns";
import type { Density } from "./prefs";

export type { DrawerFocus } from "./columns";

/** Below this much room, the grid becomes a card list.
 *
 *  Tuned against the console shell, not against a device: 640px is the width at
 *  which a two-column grid with a pinned first column stops being readable even
 *  with horizontal scroll. Above it a table that scrolls sideways inside its own
 *  box is still the better instrument — a 1024px laptop gets the table. */
const CARD_BREAKPOINT = 640;

const PAD: Record<Density, { cell: string; head: string; text: string }> = {
  comfortable: { cell: "py-2 px-3", head: "py-2 px-3", text: "text-[12.5px]" },
  compact: { cell: "py-[3px] px-2", head: "py-1.5 px-2", text: "text-[11.5px]" },
};

export interface InventoryTableProps {
  items: InventoryItem[];
  columns: InvColumn[];
  ctx: CellCtx;
  density: Density;
  loading?: boolean;
  hasMore?: boolean;
  /** Row keys currently selected. */
  selected: Set<string>;
  onToggleRow: (key: string) => void;
  /** Called with every key on the page and whether they should all be on. */
  onToggleAll: (keys: string[], on: boolean) => void;
  /** Rows in the order the table is showing them, published upward so the CSV
   *  export writes exactly what is on screen rather than re-deriving an order
   *  that could differ from it. */
  onOrderChange?: (items: InventoryItem[]) => void;
}

export function InventoryTable({
  items,
  columns,
  ctx,
  density,
  loading,
  hasMore,
  selected,
  onToggleRow,
  onToggleAll,
  onOrderChange,
}: InventoryTableProps) {
  const sorts = useMemo(() => buildSorts(ctx), [ctx]);
  const t = useFilterSort(items, { sorts, initialSort: "name" });
  const wrap = useRef<HTMLDivElement>(null);
  const [narrow, setNarrow] = useState(false);

  // The card/table decision is made from the measured container, not from a
  // media query: the console's content column is not the viewport, and the
  // first render must be deterministic or hydration throws the tree away.
  useEffect(() => {
    const el = wrap.current;
    if (!el || typeof ResizeObserver === "undefined") return;
    const ro = new ResizeObserver((entries) => {
      const w = entries[0]?.contentRect.width ?? 0;
      if (w > 0) setNarrow(w < CARD_BREAKPOINT);
    });
    ro.observe(el);
    return () => ro.disconnect();
  }, []);

  const rows = t.rows;
  const orderRef = useRef(onOrderChange);
  orderRef.current = onOrderChange;
  useEffect(() => {
    orderRef.current?.(rows);
  }, [rows]);

  const pageKeys = useMemo(() => rows.map((r) => r.key), [rows]);
  const allOn = pageKeys.length > 0 && pageKeys.every((k) => selected.has(k));
  const someOn = !allOn && pageKeys.some((k) => selected.has(k));
  const minWidth = 44 + columns.reduce((sum, c) => sum + c.minWidth, 0);
  const pad = PAD[density];

  return (
    <div ref={wrap} className="min-w-0">
      {narrow ? (
        <CardList
          rows={rows}
          columns={columns}
          ctx={ctx}
          loading={!!loading && items.length === 0}
          selected={selected}
          onToggleRow={onToggleRow}
        />
      ) : (
        <div className="min-w-0 border border-border bg-surface">
          <div className="zt-scroll relative max-h-[min(70vh,760px)] min-w-0 overflow-auto">
            <table className={cn("w-full border-collapse text-left", pad.text)} style={{ minWidth }}>
              <thead>
                <tr>
                  <th
                    scope="col"
                    className={cn(
                      "sticky left-0 top-0 z-30 border-b border-r border-border bg-surface2 text-left align-bottom",
                      pad.head,
                    )}
                    style={{ minWidth: columns[0]?.minWidth ?? 240 }}
                  >
                    <span className="flex items-center gap-2">
                      <SelectBox
                        checked={allOn}
                        indeterminate={someOn}
                        disabled={pageKeys.length === 0}
                        onChange={() => onToggleAll(pageKeys, !allOn)}
                        label={allOn ? "Clear the selection on this page" : "Select every row on this page"}
                      />
                      <SortLabel label={columns[0]?.label ?? "Name"} sortKey={columns[0]?.sortKey} state={t} />
                    </span>
                  </th>
                  {columns.slice(1).map((c) => (
                    <th
                      key={c.id}
                      scope="col"
                      className={cn(
                        "sticky top-0 z-20 border-b border-border bg-surface2 align-bottom",
                        c.align === "right" && "text-right",
                        pad.head,
                      )}
                      style={{ minWidth: c.minWidth }}
                      title={c.hint}
                    >
                      <SortLabel label={c.label} sortKey={c.sortKey} state={t} align={c.align} />
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {loading && items.length === 0
                  ? Array.from({ length: 8 }).map((_, i) => (
                      <SkeletonRow key={i} columns={columns} density={density} />
                    ))
                  : rows.map((item) => (
                      <Row
                        key={item.key}
                        item={item}
                        columns={columns}
                        ctx={ctx}
                        density={density}
                        selected={selected.has(item.key)}
                        onToggle={() => onToggleRow(item.key)}
                      />
                    ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {rows.length > 0 && hasMore ? (
        <p className="mt-1 text-[11px] text-text3">
          Sorting orders the {rows.length} {rows.length === 1 ? "row" : "rows"} on this page. The filter and the paging
          are the server&apos;s &mdash; there are more matches than these.
        </p>
      ) : null}
    </div>
  );
}

// ── Rows ───────────────────────────────────────────────────────────────────

function Row({
  item,
  columns,
  ctx,
  density,
  selected,
  onToggle,
}: {
  item: InventoryItem;
  columns: InvColumn[];
  ctx: CellCtx;
  density: Density;
  selected: boolean;
  onToggle: () => void;
}) {
  const pad = PAD[density];
  const first = columns[0];
  return (
    <tr
      onClick={() => ctx.onOpen(item, "top")}
      title="Open the full record — every field, every source, every conflict, and the policy touching its address"
      className={cn(
        "group cursor-pointer border-b border-hair align-top transition-colors last:border-0",
        selected ? "bg-accent-soft" : "hover:bg-surfaceHover",
      )}
    >
      {/* The sticky cell paints its own background, so it has to repeat the
          row's hover and selected states or it would slide under them. */}
      <td
        className={cn(
          "sticky left-0 z-10 border-r border-border align-top",
          selected ? "bg-accent-soft" : "bg-surface group-hover:bg-surfaceHover",
          pad.cell,
        )}
      >
        <span className="flex items-start gap-2">
          <SelectBox
            checked={selected}
            onChange={onToggle}
            stop
            label={`${selected ? "Deselect" : "Select"} ${item.name}`}
            className="mt-[3px]"
          />
          <span className="mt-[1px] shrink-0 text-text2">
            <NetIcon kind={item.kind} size={16} />
          </span>
          <span className="min-w-0 flex-1">{first ? first.cell(item, ctx) : item.name}</span>
        </span>
      </td>
      {columns.slice(1).map((c) => (
        <td key={c.id} className={cn("align-top", c.align === "right" && "text-right", pad.cell)}>
          {c.cell(item, ctx)}
        </td>
      ))}
    </tr>
  );
}

function SkeletonRow({ columns, density }: { columns: InvColumn[]; density: Density }) {
  const pad = PAD[density];
  return (
    <tr className="border-b border-hair last:border-0">
      {columns.map((c, i) => (
        <td
          key={c.id}
          className={cn(pad.cell, i === 0 && "sticky left-0 z-10 border-r border-border bg-surface")}
        >
          <Skeleton className={cn("h-3.5", i === 0 ? "w-44" : c.minWidth > 160 ? "w-28" : "w-16")} />
        </td>
      ))}
    </tr>
  );
}

// ── Card list (narrow viewports) ───────────────────────────────────────────

/**
 * The same facts, stacked.
 *
 * Every visible column becomes a label/value pair, in the register's order, so
 * a narrow screen shows the SAME columns the operator chose rather than a
 * second, quietly different set. Nothing is dropped on the way down.
 */
function CardList({
  rows,
  columns,
  ctx,
  loading,
  selected,
  onToggleRow,
}: {
  rows: InventoryItem[];
  columns: InvColumn[];
  ctx: CellCtx;
  loading: boolean;
  selected: Set<string>;
  onToggleRow: (key: string) => void;
}) {
  if (loading) {
    return (
      <div className="space-y-2">
        {Array.from({ length: 5 }).map((_, i) => (
          <div key={i} className="space-y-2 border border-border bg-surface p-3">
            <Skeleton className="h-4 w-2/3" />
            <Skeleton className="h-3 w-1/3" />
            <Skeleton className="h-3 w-1/2" />
          </div>
        ))}
      </div>
    );
  }
  const first = columns[0];
  const rest = columns.slice(1);
  return (
    <ul className="space-y-2">
      {rows.map((item) => {
        const on = selected.has(item.key);
        return (
          <li
            key={item.key}
            className={cn("border bg-surface transition-colors", on ? "border-accent bg-accent-soft" : "border-border")}
          >
            <div className="flex items-start gap-2 border-b border-hair p-3">
              <SelectBox
                checked={on}
                onChange={() => onToggleRow(item.key)}
                stop
                label={`${on ? "Deselect" : "Select"} ${item.name}`}
                className="mt-[3px]"
              />
              <span className="mt-[1px] shrink-0 text-text2">
                <NetIcon kind={item.kind} size={18} />
              </span>
              <span className="min-w-0 flex-1 text-[13px]">{first ? first.cell(item, ctx) : item.name}</span>
              <button
                type="button"
                onClick={() => ctx.onOpen(item, "top")}
                className="btn-ghost !h-7 shrink-0 !px-2 text-[11px]"
              >
                Open
              </button>
            </div>
            <dl className="grid grid-cols-[minmax(74px,auto)_1fr] gap-x-3 gap-y-1 p-3 text-[12px]">
              {rest.map((c) => (
                <div key={c.id} className="contents">
                  <dt className="text-[10px] font-bold uppercase tracking-[0.1em] text-text3">{c.label}</dt>
                  <dd className="min-w-0 break-words">{c.cell(item, ctx)}</dd>
                </div>
              ))}
            </dl>
          </li>
        );
      })}
    </ul>
  );
}

// ── Controls ───────────────────────────────────────────────────────────────

function SelectBox({
  checked,
  indeterminate,
  disabled,
  onChange,
  label,
  stop,
  className,
}: {
  checked: boolean;
  indeterminate?: boolean;
  disabled?: boolean;
  onChange: () => void;
  label: string;
  /** Inside a clickable row: don't let the click open the drawer as well. */
  stop?: boolean;
  className?: string;
}) {
  const ref = useRef<HTMLInputElement>(null);
  useEffect(() => {
    if (ref.current) ref.current.indeterminate = !!indeterminate && !checked;
  }, [indeterminate, checked]);
  return (
    <input
      ref={ref}
      type="checkbox"
      checked={checked}
      disabled={disabled}
      aria-label={label}
      title={label}
      onClick={stop ? (e) => e.stopPropagation() : undefined}
      onChange={onChange}
      className={cn(
        "h-[13px] w-[13px] shrink-0 cursor-pointer accent-[var(--accent)] disabled:cursor-default disabled:opacity-40",
        className,
      )}
    />
  );
}

function SortLabel({
  label,
  sortKey,
  state,
  align,
}: {
  label: string;
  sortKey?: string;
  state: { sortKey: string; dir: "asc" | "desc"; toggle: (k: string) => void };
  align?: "right";
}) {
  if (!sortKey) {
    return (
      <span className="text-[10.5px] font-bold uppercase tracking-[0.08em] text-text3">{label}</span>
    );
  }
  const active = state.sortKey === sortKey;
  const Icon = !active ? ArrowUpDown : state.dir === "asc" ? ArrowUp : ArrowDown;
  return (
    <button
      type="button"
      onClick={() => state.toggle(sortKey)}
      className={cn(
        "inline-flex items-center gap-1 text-[10.5px] font-bold uppercase tracking-[0.08em] transition-colors hover:text-text2",
        align === "right" && "justify-end",
        active ? "text-text" : "text-text3",
      )}
      title={`Sort the loaded page by ${label.toLowerCase()}`}
    >
      {label}
      <Icon size={10} className={active ? "text-accent-fg" : "text-text3"} />
    </button>
  );
}

export default InventoryTable;
