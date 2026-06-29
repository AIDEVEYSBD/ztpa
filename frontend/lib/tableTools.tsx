"use client";

import { useMemo, useState } from "react";
import { ArrowUpDown, ArrowUp, ArrowDown, Search } from "lucide-react";
import { cn } from "@/components/ui";

export type Getter<T> = (r: T) => string | number;
export type SortDir = "asc" | "desc";

/** Filter + sort for any row list. Search is a single derived haystack per row;
 *  sorts is a map of column-key -> value getter. Stable for lists up to a few thousand. */
export function useFilterSort<T>(rows: T[], cfg: {
  search?: Getter<T>;
  sorts?: Record<string, Getter<T>>;
  initialSort?: string;
  initialDir?: SortDir;
}) {
  const [q, setQ] = useState("");
  const [sortKey, setSortKey] = useState(cfg.initialSort ?? "");
  const [dir, setDir] = useState<SortDir>(cfg.initialDir ?? "asc");
  const toggle = (k: string) => {
    if (k === sortKey) setDir((d) => (d === "asc" ? "desc" : "asc"));
    else { setSortKey(k); setDir("asc"); }
  };
  const toggleDir = () => setDir((d) => (d === "asc" ? "desc" : "asc"));

  const out = useMemo(() => {
    let r = rows;
    const needle = q.trim().toLowerCase();
    if (needle && cfg.search) r = r.filter((x) => String(cfg.search!(x)).toLowerCase().includes(needle));
    const g = sortKey && cfg.sorts ? cfg.sorts[sortKey] : undefined;
    if (g) {
      r = [...r].sort((a, b) => {
        const va = g(a), vb = g(b);
        const c = typeof va === "number" && typeof vb === "number" ? va - vb : String(va).localeCompare(String(vb));
        return dir === "asc" ? c : -c;
      });
    }
    return r;
    // cfg holds pure getters that don't change behavior across renders
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [rows, q, sortKey, dir]);

  return { q, setQ, sortKey, setSortKey, dir, setDir, toggle, toggleDir, rows: out };
}

export function SearchBox({ value, onChange, placeholder, className }: { value: string; onChange: (v: string) => void; placeholder?: string; className?: string }) {
  return (
    <div className={cn("field flex h-8 w-full items-center gap-2 !px-2.5 focus-within:border-accent sm:w-64", className)}>
      <Search size={13} className="shrink-0 text-text3" />
      <input value={value} onChange={(e) => onChange(e.target.value)} placeholder={placeholder ?? "Search…"}
        className="min-w-0 flex-1 bg-transparent text-[12px] text-text outline-none placeholder:text-text3" />
    </div>
  );
}

type SortState = { sortKey: string; dir: SortDir; toggle: (k: string) => void };

/** Clickable, sortable table header cell. */
export function SortTh({ label, sortKey, state, className }: { label: string; sortKey: string; state: SortState; className?: string }) {
  const active = state.sortKey === sortKey;
  const Icon = !active ? ArrowUpDown : state.dir === "asc" ? ArrowUp : ArrowDown;
  return (
    <th className={cn("cursor-pointer select-none py-1.5 pr-3 text-[11px] font-bold uppercase tracking-[0.08em] text-text3", className)} onClick={() => state.toggle(sortKey)}>
      <span className={cn("inline-flex items-center gap-1 transition-colors hover:text-text2", active && "text-text")}>{label}<Icon size={11} className={active ? "text-accent-fg" : "text-text3"} /></span>
    </th>
  );
}

/** Sort control for non-table (card/list) layouts: a select + direction toggle. */
export function SortSelect({ options, sortKey, setSortKey, dir, toggleDir }: {
  options: { key: string; label: string }[]; sortKey: string; setSortKey: (k: string) => void; dir: SortDir; toggleDir: () => void;
}) {
  return (
    <div className="flex items-center gap-1">
      <select value={sortKey} onChange={(e) => setSortKey(e.target.value)} className="field !h-8 w-auto text-[12px]">
        {options.map((o) => <option key={o.key} value={o.key}>sort: {o.label}</option>)}
      </select>
      <button onClick={toggleDir} className="btn-ghost !h-8 !px-2" title={dir === "asc" ? "ascending" : "descending"}>
        {dir === "asc" ? <ArrowUp size={13} /> : <ArrowDown size={13} />}
      </button>
    </div>
  );
}
