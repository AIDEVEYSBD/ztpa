"use client";

/**
 * The table's own controls: which columns are on, how dense the rows are, and
 * getting the view out as a file.
 *
 * THE EXPORT IS THE PART WITH A HONESTY PROBLEM, and it is worth being explicit
 * about why the confirmation line is as wordy as it is. The table holds ONE
 * PAGE of a server-side result set. A button labelled "Export CSV" that writes
 * 50 of 4,000 matching rows hands somebody a file they will treat as the
 * estate, and every number they derive from it will be wrong — silently, and
 * with the product's name on it. So the export states three things every time:
 * how many rows it wrote, how many matched the filter, and how many columns of
 * the register went in. If rows were left behind it says so in amber, with the
 * remedy (raise the page size, or narrow the filter).
 */

import { useEffect, useMemo, useRef, useState } from "react";
import { Check, Columns3, Download, Rows3, X } from "lucide-react";
import { cn } from "@/lib/cn";
import {
  DEFAULT_COLUMN_IDS,
  INVENTORY_COLUMNS,
  type InvColumn,
} from "./columns";
import { DENSITY_LABEL, type Density } from "./prefs";

// ── Column visibility ──────────────────────────────────────────────────────

export function ColumnMenu({
  visible,
  onChange,
  onReset,
}: {
  visible: string[];
  onChange: (ids: string[]) => void;
  onReset: () => void;
}) {
  const [open, setOpen] = useState(false);
  const root = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!open) return;
    const onDown = (e: MouseEvent) => {
      if (root.current && !root.current.contains(e.target as Node)) setOpen(false);
    };
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") setOpen(false);
    };
    document.addEventListener("mousedown", onDown);
    document.addEventListener("keydown", onKey);
    return () => {
      document.removeEventListener("mousedown", onDown);
      document.removeEventListener("keydown", onKey);
    };
  }, [open]);

  const on = useMemo(() => new Set(visible), [visible]);
  const shown = INVENTORY_COLUMNS.filter((c) => on.has(c.id) || c.locked).length;
  const isDefault =
    shown === DEFAULT_COLUMN_IDS.length && DEFAULT_COLUMN_IDS.every((id) => on.has(id));

  const toggle = (c: InvColumn) => {
    if (c.locked) return;
    const next = new Set(on);
    if (next.has(c.id)) next.delete(c.id);
    else next.add(c.id);
    // Never let the table become a single column of names with no facts in it.
    if (INVENTORY_COLUMNS.filter((x) => next.has(x.id) || x.locked).length === 0) return;
    onChange(INVENTORY_COLUMNS.filter((x) => next.has(x.id)).map((x) => x.id));
  };

  return (
    <div ref={root} className="relative">
      <button
        type="button"
        onClick={() => setOpen((v) => !v)}
        aria-expanded={open}
        className={cn("btn-ghost focusable !h-7 !px-2.5 !text-[12px]", open && "!bg-ink !text-on-ink")}
        title="Choose which columns this table shows. Your choice is remembered on this browser."
      >
        <Columns3 size={12} />
        Columns
        <span className={cn("tnum font-mono text-[10.5px]", open ? "opacity-70" : "text-faint")}>
          {shown}/{INVENTORY_COLUMNS.length}
        </span>
      </button>

      {open ? (
        <div className="popover af-pop absolute right-0 top-[calc(100%+4px)] z-40 w-[290px] max-w-[calc(100vw-2rem)]">
          <div className="flex items-center justify-between gap-2 border-b border-line px-3 py-2">
            <span className="text-[11px] font-medium tracking-[0.06em] text-faint uppercase">Columns</span>
            <button
              type="button"
              onClick={onReset}
              disabled={isDefault}
              className="focusable cursor-pointer text-[11.5px] font-medium text-faint underline underline-offset-2 transition-colors duration-100 hover:text-fg disabled:no-underline disabled:opacity-40"
            >
              reset
            </button>
          </div>
          <ul className="zt-scroll max-h-[320px] overflow-y-auto py-1">
            {INVENTORY_COLUMNS.map((c) => {
              const checked = c.locked || on.has(c.id);
              return (
                <li key={c.id}>
                  <button
                    type="button"
                    onClick={() => toggle(c)}
                    disabled={c.locked}
                    title={c.locked ? `${c.hint}\n\nAlways shown.` : c.hint}
                    className={cn(
                      "focusable flex w-full items-start gap-2 rounded-sm px-3 py-1.5 text-left transition-colors duration-100",
                      c.locked ? "cursor-default opacity-70" : "cursor-pointer hover:bg-raise/50",
                    )}
                  >
                    <span
                      aria-hidden
                      className={cn(
                        "mt-[2px] grid size-4 shrink-0 place-items-center rounded-xs border",
                        checked ? "border-ink bg-ink text-on-ink" : "border-line-strong bg-field",
                      )}
                    >
                      {checked ? <Check size={10} strokeWidth={3.5} /> : null}
                    </span>
                    <span className="min-w-0 flex-1">
                      <span className="block text-[12px] font-medium text-fg">{c.label}</span>
                      <span className="block text-[10.5px] leading-[1.5] text-faint">{c.hint}</span>
                    </span>
                    {c.locked ? (
                      <span className="mt-[2px] shrink-0 rounded-[3px] border border-line-strong px-1 py-px font-mono text-[9px] font-semibold text-dim">
                        pinned
                      </span>
                    ) : null}
                  </button>
                </li>
              );
            })}
          </ul>
          <p className="border-t border-hair px-3 py-2 text-[10.5px] leading-relaxed text-text3">
            Hiding a column changes the layout, not the record. The row drawer always carries every field, and the CSV
            export says how many columns it wrote.
          </p>
        </div>
      ) : null}
    </div>
  );
}

// ── Density ────────────────────────────────────────────────────────────────

const DENSITIES: Density[] = ["comfortable", "compact"];

export function DensityToggle({ value, onChange }: { value: Density; onChange: (d: Density) => void }) {
  return (
    <div
      className="inline-flex h-7 items-stretch border border-border"
      role="group"
      aria-label="Row density"
      title="Row height. Remembered on this browser."
    >
      <span className="flex items-center px-2 text-text3">
        <Rows3 size={12} />
      </span>
      {DENSITIES.map((d) => (
        <button
          key={d}
          type="button"
          aria-pressed={value === d}
          onClick={() => onChange(d)}
          className={cn(
            "border-l border-border px-2 text-[11px] font-bold transition-colors",
            value === d ? "bg-accent-soft text-accent-fg" : "bg-surface2 text-text2 hover:text-accent-fg",
          )}
        >
          {DENSITY_LABEL[d]}
        </button>
      ))}
    </div>
  );
}

// ── Export ─────────────────────────────────────────────────────────────────

export interface ExportReceipt {
  ok: boolean;
  /** Rows actually written. */
  rows: number;
  /** Rows loaded on this page, whatever the export narrowed to. */
  loaded: number;
  /** Rows matching the filter, as the SERVER counted them. `undefined` when no
   *  successful read has told us — and then the file is stated as possibly a
   *  subset rather than quietly presented as the whole. */
  total?: number;
  columns: number;
  registerColumns: number;
  /** What was exported, in the operator's words ("the 12 rows this page view
   *  shows", "the selection"). */
  scope: string;
  filename?: string;
}

export function ExportButton({
  label,
  disabled,
  onExport,
  title,
}: {
  label: string;
  disabled?: boolean;
  title: string;
  onExport: () => void;
}) {
  return (
    <button
      type="button"
      onClick={onExport}
      disabled={disabled}
      className="btn-ghost !h-7 !px-2 text-[11.5px]"
      title={title}
    >
      <Download size={12} />
      {label}
    </button>
  );
}

/**
 * The receipt. Deliberately not a toast that disappears: the sentence about
 * rows left behind is the one thing the operator has to read, and a 3-second
 * toast is how a warning goes unread.
 */
export function ExportReceiptNote({ receipt, onDismiss }: { receipt: ExportReceipt; onDismiss: () => void }) {
  // The rows the FILTER matched but the PAGE never loaded. Measured against the
  // page, not against the export, so a page view or a selection narrowing the
  // file is described separately rather than being blamed on paging.
  const missed =
    receipt.total !== undefined && receipt.total > receipt.loaded ? receipt.total - receipt.loaded : 0;
  const unknownTotal = receipt.total === undefined;
  const warn = missed > 0 || unknownTotal || !receipt.ok;

  return (
    <div
      role="status"
      className={cn(
        "flex flex-wrap items-start gap-x-2 gap-y-1 border px-3 py-2 text-[11.5px]",
        warn ? "border-sev-medium-line bg-sev-medium-bg text-sev-medium" : "border-ok-line bg-ok-bg text-ok",
      )}
    >
      {!receipt.ok ? (
        <span className="font-bold">
          The browser refused the download, so nothing was saved. Check that downloads are allowed for this site.
        </span>
      ) : (
        <>
          <span className="font-bold">
            Exported {receipt.rows.toLocaleString()} {receipt.rows === 1 ? "row" : "rows"} ({receipt.scope}).
          </span>
          <span className="text-text2">
            {unknownTotal ? (
              <>How many rows match this filter in total is unknown, so this file may be a subset.</>
            ) : missed > 0 ? (
              <>
                {receipt.total!.toLocaleString()} rows match this filter &mdash; {missed.toLocaleString()} of them{" "}
                {missed === 1 ? "was" : "were"} NOT loaded and so {missed === 1 ? "is" : "are"} not in this file. Raise
                the page size or narrow the filter and export again.
              </>
            ) : (
              <>That is every row matching this filter.</>
            )}{" "}
            {receipt.columns} of {receipt.registerColumns} columns were written &mdash; the ones this table is showing.
            {receipt.filename ? ` Saved as ${receipt.filename}.` : ""}
          </span>
        </>
      )}
      <button
        type="button"
        onClick={onDismiss}
        aria-label="Dismiss the export receipt"
        className="ml-auto shrink-0 text-text3 transition-colors hover:text-text"
      >
        <X size={12} />
      </button>
    </div>
  );
}
