"use client";

/**
 * The filter rail.
 *
 * Two of these are hard requirements of the review, and both are here for the
 * same reason: an inventory nobody can interrogate is a list, not a review.
 *
 *   IP ADDRESS, with CONTAINMENT SEMANTICS. Typing 10.30.0.0/16 has to find the
 *   hosts inside it, which is set arithmetic over address blocks and not a
 *   substring match. The mode is a visible control rather than an invisible
 *   default, because the same address under two modes is two different
 *   questions and the answer on screen has to say which one was asked.
 *
 *   SOURCE. "Which console told us this" is the question the whole screen
 *   exists to answer, so it is also a way to slice it.
 *
 * Everything here is SERVER-SIDE. The table is paged; a filter applied in the
 * browser would narrow one page while `total` kept describing the estate, and
 * the screen would report a subset as the whole.
 */

import { useEffect, useState } from "react";
import { Filter, ScanSearch, X } from "lucide-react";
import type { IpFilterMode } from "@/lib/api";
import type { InventoryResponse, SourceCard } from "@/lib/types";
import { cn } from "@/lib/cn";
import { SearchBox } from "@/lib/tableTools";
import { isKnownNetIconKind, NetIcon } from "@/components/net/icons";

export type FacetGroup = "kind" | "vlan" | "zone";

/** The four containment modes, in the order they escalate from forgiving to
 *  literal. The description is rendered under the control, always — a mode the
 *  user cannot read is a filter whose result they cannot interpret. */
export const IP_MODES: { value: IpFilterMode; label: string; help: string }[] = [
  {
    value: "intersects",
    label: "intersects",
    help: "Any overlap between an entity's addresses and the block you type — including every host inside it. The forgiving one.",
  },
  {
    value: "contained_by",
    label: "is inside",
    help: "Only entities whose addresses fall INSIDE what you type. 10.30.0.0/16 finds the hosts in it, and not the block itself.",
  },
  {
    value: "contains",
    label: "contains",
    help: "Only entities whose own block CONTAINS what you type — the supernet, subnet or interface a single host sits in.",
  },
  {
    value: "exact",
    label: "exactly",
    help: "The address or block exactly as written, and nothing else.",
  },
];

/**
 * Is this worth sending as an address filter?
 *
 * Deliberately permissive — the backend owns containment arithmetic and this is
 * only here to stop obvious prose being posted as an address. It never
 * rewrites what was typed.
 */
export function looksLikeAddress(raw: string): boolean {
  const v = raw.trim();
  if (!v) return false;
  const parts = v.split("/");
  if (parts.length > 2) return false;
  const [addr, prefix] = parts;
  if (prefix !== undefined) {
    if (!/^\d{1,3}$/.test(prefix)) return false;
    const max = addr.includes(":") ? 128 : 32;
    if (Number(prefix) > max) return false;
  }
  if (addr.includes(":")) return /^[0-9a-fA-F:.]+$/.test(addr) && (addr.match(/:/g) ?? []).length >= 2;
  const octets = addr.split(".");
  return octets.length === 4 && octets.every((o) => /^\d{1,3}$/.test(o) && Number(o) <= 255);
}

export interface InventoryFiltersProps {
  facets?: InventoryResponse["facets"];
  cards?: Record<string, SourceCard>;
  q: string;
  onQ: (v: string) => void;
  ip: string;
  ipMode: IpFilterMode;
  onIp: (ip: string, mode: IpFilterMode) => void;
  source: string;
  onSource: (v: string) => void;
  selected: Record<FacetGroup, string[]>;
  onToggleFacet: (group: FacetGroup, value: string) => void;
  onClearAll: () => void;
  /** Rendered on the active-filter line — "showing N of M". */
  summary?: React.ReactNode;
  disabled?: boolean;
}

export function InventoryFilters(p: InventoryFiltersProps) {
  const active = activeChips(p);

  return (
    <div className="overflow-hidden rounded-lg border border-line bg-surface elev-1">
      <div data-hue="blue" data-hue-bar="" className="flex flex-wrap items-center gap-2 border-b border-line bg-raise/55 px-4 py-2.5">
        <span className="flex items-center gap-1.5 text-[12.5px] font-semibold tracking-[-0.005em]">
          <Filter size={12} /> Filters
        </span>
        <SearchBox value={p.q} onChange={p.onQ} placeholder="name, address or tag…" className="min-w-0 sm:ml-auto sm:w-56" />
        <SourceSelect value={p.source} onChange={p.onSource} facets={p.facets} cards={p.cards} disabled={p.disabled} />
      </div>

      <IpFilter ip={p.ip} mode={p.ipMode} onApply={p.onIp} disabled={p.disabled} />

      <div className="flex flex-col gap-2 border-b border-line px-4 py-3">
        <FacetRow group="kind" label="Kind" counts={p.facets?.kinds} selected={p.selected.kind} onToggle={p.onToggleFacet} withIcon />
        <FacetRow group="vlan" label="VLAN" counts={p.facets?.vlans} selected={p.selected.vlan} onToggle={p.onToggleFacet} />
        <FacetRow group="zone" label="Zone" counts={p.facets?.zones} selected={p.selected.zone} onToggle={p.onToggleFacet} />
      </div>

      <div className="flex flex-wrap items-center gap-x-3 gap-y-2 px-4 py-2.5">
        {active.length > 0 ? (
          <>
            <span className="mr-0.5 text-[11px] font-medium text-faint">Active</span>
            {active.map((c) => (
              <button
                key={c.key}
                type="button"
                onClick={c.clear}
                title={`Remove this filter — ${c.title}`}
                className="focusable inline-flex h-7 cursor-pointer items-center gap-1.5 rounded-sm border border-line-strong bg-raise px-2 text-[11.5px] font-medium transition-colors duration-100 hover:border-err-line hover:bg-err-bg hover:text-err"
              >
                {c.label}
                <X size={11} />
              </button>
            ))}
            <button type="button" onClick={p.onClearAll} className="focusable cursor-pointer text-[11.5px] font-medium text-faint underline underline-offset-2 transition-colors duration-100 hover:text-fg">
              Clear {active.length} {active.length === 1 ? "filter" : "filters"} ×
            </button>
          </>
        ) : (
          <span className="text-[11.5px] text-faint">No filter applied — every entity in the snapshot is in scope.</span>
        )}
        {p.summary ? <span className="ml-auto text-[11.5px] text-dim">{p.summary}</span> : null}
      </div>
    </div>
  );
}

// ── IP address, with containment semantics ─────────────────────────────────

function IpFilter({ ip, mode, onApply, disabled }: {
  ip: string;
  mode: IpFilterMode;
  onApply: (ip: string, mode: IpFilterMode) => void;
  disabled?: boolean;
}) {
  const [draft, setDraft] = useState(ip);
  const [draftMode, setDraftMode] = useState<IpFilterMode>(mode);
  // Keep the draft honest when the filter is cleared from an active chip.
  useEffect(() => setDraft(ip), [ip]);
  useEffect(() => setDraftMode(mode), [mode]);

  const trimmed = draft.trim();
  const valid = looksLikeAddress(trimmed);
  const dirty = trimmed !== ip.trim() || draftMode !== mode;
  const help = IP_MODES.find((m) => m.value === draftMode)?.help ?? "";

  const apply = () => {
    if (!trimmed) { onApply("", draftMode); return; }
    if (!valid) return;
    onApply(trimmed, draftMode);
  };

  return (
    <div className="border-b border-hair px-3 py-2.5">
      <div className="flex flex-wrap items-center gap-2">
        <span className="flex w-[52px] shrink-0 items-center gap-1.5 text-[10px] font-bold uppercase tracking-[0.12em] text-text3">
          <ScanSearch size={11} /> IP
        </span>
        <div className="flex min-w-0 flex-1 items-stretch">
          <select
            aria-label="IP match mode"
            value={draftMode}
            disabled={disabled}
            onChange={(e) => {
              const next = e.target.value as IpFilterMode;
              setDraftMode(next);
              // A mode change with an address already applied re-asks the
              // question immediately: the old answer is not an answer to it.
              if (ip.trim() && trimmed === ip.trim()) onApply(ip.trim(), next);
            }}
            className="field !h-8 w-auto shrink-0 border-r-0 text-[12px] font-bold"
          >
            {IP_MODES.map((m) => <option key={m.value} value={m.value}>{m.label}</option>)}
          </select>
          <input
            value={draft}
            disabled={disabled}
            onChange={(e) => setDraft(e.target.value)}
            onKeyDown={(e) => { if (e.key === "Enter") apply(); }}
            placeholder="10.30.0.0/16 or 10.30.4.7"
            aria-label="IP address or CIDR block"
            aria-invalid={!!trimmed && !valid}
            className={cn("field mono !h-8 min-w-0 flex-1 text-[12px]", !!trimmed && !valid && "!border-sev-critical-line")}
          />
          <button
            type="button"
            onClick={apply}
            disabled={disabled || (!!trimmed && !valid) || !dirty}
            className="btn-ghost !h-8 shrink-0 border-l-0"
            title={trimmed ? `Find entities whose addresses ${draftMode === "exact" ? "are exactly" : draftMode === "contains" ? "contain" : draftMode === "contained_by" ? "fall inside" : "overlap"} ${trimmed}` : "Clear the address filter"}
          >
            Apply
          </button>
        </div>
      </div>
      <p className={cn("mt-1.5 pl-[60px] text-[11px] leading-relaxed", !!trimmed && !valid ? "text-sev-critical" : "text-text2")}>
        {!!trimmed && !valid
          ? `"${trimmed}" is not an address or a CIDR block, so it was not sent — an address filter that silently matched nothing would read as an empty estate.`
          : help}
      </p>
    </div>
  );
}

// ── Source ─────────────────────────────────────────────────────────────────

function SourceSelect({ value, onChange, facets, cards, disabled }: {
  value: string;
  onChange: (v: string) => void;
  facets?: InventoryResponse["facets"];
  cards?: Record<string, SourceCard>;
  disabled?: boolean;
}) {
  const entries = Object.entries(facets?.sources ?? {}).sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]));
  return (
    <select
      aria-label="Filter by source"
      value={value}
      disabled={disabled || !facets}
      onChange={(e) => onChange(e.target.value)}
      className="field !h-8 w-auto min-w-0 max-w-full text-[12px] sm:max-w-[220px]"
      title="Only entities this console observed. A row three consoles describe stays visible under any one of them."
    >
      <option value="">{facets ? "source: any" : "source: unknown"}</option>
      {entries.map(([tool, n]) => (
        <option key={tool} value={tool}>
          {tool}{cards?.[tool]?.simulated ? " (seeded)" : ""} — {n}
        </option>
      ))}
    </select>
  );
}

// ── Facets ─────────────────────────────────────────────────────────────────

const FACET_CAP = 14;

function FacetRow({ group, label, counts, selected, onToggle, withIcon }: {
  group: FacetGroup;
  label: string;
  counts?: Record<string, number>;
  selected: string[];
  onToggle: (g: FacetGroup, v: string) => void;
  withIcon?: boolean;
}) {
  const [all, setAll] = useState(false);
  // Facet KEYS are the backend's spelling and are echoed back verbatim as the
  // query value. Rendering them means rendering them, not prettifying them.
  const live = Object.entries(counts ?? {}).sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]));
  // A selected value that a narrowing combination has dropped out of the live
  // facets keeps its chip, with a null count rather than a 0 - it would
  // otherwise vanish from the row that is supposed to let you switch it off,
  // and "no longer in this result set" is not "matches nothing".
  const entries: [string, number | null][] = [
    ...live,
    ...selected.filter((v) => !(v in (counts ?? {}))).map((v) => [v, null] as [string, null]),
  ];
  const shown = all ? entries : entries.slice(0, FACET_CAP);
  const hidden = entries.length - shown.length;

  return (
    <div className="flex flex-wrap items-start gap-2">
      <span className="mt-0.5 w-[52px] shrink-0 text-[10px] font-bold uppercase tracking-[0.12em] text-text3">{label}</span>
      <div className="flex min-w-0 flex-1 flex-wrap items-center gap-1.5">
        {!counts ? (
          <span className="text-[11px] text-text3">not loaded</span>
        ) : entries.length === 0 ? (
          <span className="text-[11.5px] text-faint">nothing in this snapshot carries a {label.toLowerCase()}</span>
        ) : (
          <>
            {shown.map(([key, n]) => {
              const on = selected.includes(key);
              return (
                <button
                  key={key}
                  type="button"
                  aria-pressed={on}
                  onClick={() => onToggle(group, key)}
                  title={n === null
                    ? `Selected, but no longer in the live facets for this result set - the other filters have narrowed past it. Click to switch it off.`
                    : `${n} ${n === 1 ? "entity" : "entities"} match ${label.toLowerCase()} "${key}"`}
                  className={cn(
                    "focusable inline-flex h-7 max-w-full cursor-pointer items-center gap-1.5 rounded-sm border px-2.5 text-[12px] font-medium whitespace-nowrap transition-colors duration-100 sm:max-w-[190px]",
                    on
                      ? "border-transparent bg-ink text-on-ink"
                      : "border-line bg-surface text-dim hover:bg-raise hover:text-fg",
                  )}
                >
                  {withIcon && isKnownNetIconKind(key) ? <NetIcon kind={key} size={11} /> : null}
                  <span className="truncate">{key}</span>
                  <span className={cn("tnum shrink-0 font-mono text-[10.5px]", on ? "opacity-70" : "text-faint")}>{n === null ? "\u2014" : n}</span>
                </button>
              );
            })}
            {hidden > 0 && (
              <button type="button" onClick={() => setAll(true)} className="focusable cursor-pointer text-[11.5px] font-medium text-faint underline underline-offset-2 hover:text-fg">
                +{hidden} more
              </button>
            )}
            {all && entries.length > FACET_CAP && (
              <button type="button" onClick={() => setAll(false)} className="text-[11px] font-bold text-text3 underline underline-offset-2 hover:text-accent-fg">
                fewer
              </button>
            )}
          </>
        )}
      </div>
    </div>
  );
}

// ── Active-filter chips ────────────────────────────────────────────────────

type ActiveChip = { key: string; label: string; title: string; clear: () => void };

function activeChips(p: InventoryFiltersProps): ActiveChip[] {
  const out: ActiveChip[] = [];
  if (p.q.trim()) {
    out.push({ key: "q", label: `text "${p.q.trim()}"`, title: "free text over name, address and tag", clear: () => p.onQ("") });
  }
  if (p.ip.trim()) {
    const m = IP_MODES.find((x) => x.value === p.ipMode);
    out.push({
      key: "ip",
      label: `ip ${m?.label ?? p.ipMode} ${p.ip.trim()}`,
      title: m?.help ?? p.ipMode,
      clear: () => p.onIp("", p.ipMode),
    });
  }
  if (p.source) {
    out.push({ key: "source", label: `source ${p.source}`, title: "only entities this console observed", clear: () => p.onSource("") });
  }
  (["kind", "vlan", "zone"] as FacetGroup[]).forEach((g) => {
    p.selected[g].forEach((v) => {
      out.push({ key: `${g}:${v}`, label: `${g} ${v}`, title: `facet ${g} = ${v}`, clear: () => p.onToggleFacet(g, v) });
    });
  });
  return out;
}

export default InventoryFilters;
