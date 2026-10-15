"use client";

/**
 * THE COLUMN REGISTER.
 *
 * One definition per column, carrying everything three different surfaces need
 * from it — the table cell, the narrow-viewport card, and the CSV export — so
 * those three can never drift into disagreeing about what a column means. A
 * column added here appears in all three and in the visibility menu at once.
 *
 * TWO RULES THE REGISTER ENFORCES:
 *
 *   A hidden column is a LAYOUT choice, never a dropped fact. `name` is locked
 *   on (a table of anonymous rows is not a table), the drawer always carries
 *   the complete record whatever the table shows, and the export states how
 *   many of the register's columns it actually wrote.
 *
 *   `csv` is not `cell` with the tags stripped. An em-dash on screen means "no
 *   source reported this"; in a spreadsheet an empty cell reads as zero, so the
 *   export writes an explicit token instead (see csv.ts).
 */

import type { ReactNode } from "react";
import { GitMerge, Link2, TriangleAlert } from "lucide-react";
import type { InventoryItem, SourceCard } from "@/lib/types";
import { cn } from "@/lib/cn";
import { CSV_UNKNOWN } from "./csv";
import type { RowIdentity } from "./identity";
import { AddressList, SourceBadges, tierShort, Unreported } from "./bits";

/** Where the drawer should land when it opens. Every member has a producer (a
 *  cell that opens the drawer at it) AND a handler in `InventoryDrawer` — a
 *  focus nobody can reach is vocabulary that rots. */
export type DrawerFocus = "top" | "conflicts" | "identity";

/** Everything a cell may need that is not on the row itself. */
export interface CellCtx {
  cards?: Record<string, SourceCard>;
  /** The asset layer joined to this row, when it describes it. */
  identity: (item: InventoryItem) => RowIdentity | undefined;
  /** True when the asset read FAILED — so "was this correlated?" is unknown
   *  here rather than no. */
  identityUnknown: boolean;
  onOpen: (item: InventoryItem, focus: DrawerFocus) => void;
}

export interface InvColumn {
  id: string;
  label: string;
  /** What the column means, on the visibility menu. */
  hint: string;
  /** Key into the table's local sort map. Omitted for columns with no natural
   *  order. */
  sortKey?: string;
  /** Cannot be switched off. */
  locked?: boolean;
  /** On for an operator who has never touched the menu. */
  defaultOn: boolean;
  /** Minimum width, so a dense column cannot be squeezed to unreadable. */
  minWidth: number;
  /** Right-aligned numerics. */
  align?: "right";
  cell: (item: InventoryItem, ctx: CellCtx) => ReactNode;
  csv: (item: InventoryItem, ctx: CellCtx) => string;
}

const dash = (v: string | null | undefined) => (v === null || v === undefined || v === "" ? CSV_UNKNOWN : v);

// ── Identity ───────────────────────────────────────────────────────────────

/**
 * "Did the engine decide this row was the same thing another console called
 * something else?"
 *
 * Four different answers, and they are deliberately four different renders —
 * the one that used to be missing is the first, where a failed asset read
 * quietly looked identical to "no, this row stands alone".
 */
function IdentityCell({ item, ctx }: { item: InventoryItem; ctx: CellCtx }) {
  if (ctx.identityUnknown) {
    return (
      <span
        className="inline-flex h-[20px] cursor-help items-center gap-1 border border-sev-medium-line bg-sev-medium-bg px-1.5 text-[10px] font-bold uppercase tracking-[0.06em] text-sev-medium"
        title="The asset layer could not be read, so whether this row was correlated across tools is UNKNOWN. It is not being reported as uncorrelated."
      >
        unknown
      </span>
    );
  }

  const id = ctx.identity(item);
  if (!id) {
    return (
      <span
        className="cursor-help text-text3 underline decoration-dotted decoration-from-font underline-offset-2"
        title="The asset layer does not describe this row — a VLAN, a subnet or a circuit is not an identity the engine correlates — so there is nothing here to merge. This is not applicable, not 'no match found'."
        aria-label="not modelled by the asset layer"
      >
        &mdash;
      </span>
    );
  }

  const correlated = id.correlations.length > 0;
  const suggested = id.suggestions.length > 0;

  if (!correlated && !suggested) {
    return (
      <span
        className="cursor-help text-ghost underline decoration-dotted decoration-from-font underline-offset-2"
        title={`This row is in the asset layer under "${id.asset?.asset_key ?? item.key}" and carries no cross-tool correlation: no other console's record was proven to be the same thing.`}
        aria-label="no cross-tool correlation"
      >
        unknown
      </span>
    );
  }

  return (
    <span className="inline-flex flex-wrap items-center gap-1">
      {correlated ? (
        <button
          type="button"
          onClick={(e) => {
            e.stopPropagation();
            ctx.onOpen(item, "identity");
          }}
          title={[
            `Correlated across ${id.tools.length} ${id.tools.length === 1 ? "console" : "consoles"}: ${id.tools.join(", ")}.`,
            id.aliases.length ? `Also known as: ${id.aliases.join(", ")}.` : "",
            `Matched on ${id.correlations.map((c) => c.match_key).join(", ")}.`,
            "Click for the evidence.",
          ]
            .filter(Boolean)
            .join("\n")}
          className="focusable inline-flex cursor-pointer items-center gap-1 rounded-sm border border-line-strong bg-raise px-1.5 py-0.5 text-[10.5px] font-medium text-dim transition-colors duration-100 hover:text-fg"
        >
          <Link2 size={10} />
          merged
          <span className="tnum font-mono opacity-70">{id.tools.length}</span>
        </button>
      ) : null}
      {suggested ? (
        <button
          type="button"
          onClick={(e) => {
            e.stopPropagation();
            ctx.onOpen(item, "identity");
          }}
          title={`An unconfirmed duplicate proposal names this row: ${id.suggestions
            .map((s) => `${s.a} ~ ${s.b} (${Math.round(s.confidence * 100)}%)`)
            .join("; ")}. Nothing has been merged — confirm it in Identity & merges.`}
          className="inline-flex h-[20px] items-center gap-1 border border-sev-medium-line bg-sev-medium-bg px-1.5 text-[10px] font-bold uppercase tracking-[0.06em] text-sev-medium transition-colors hover:border-sev-medium"
        >
          <GitMerge size={10} />
          duplicate?
        </button>
      ) : null}
    </span>
  );
}

function identityCsv(item: InventoryItem, ctx: CellCtx): string {
  if (ctx.identityUnknown) return "(unknown - the asset layer could not be read)";
  const id = ctx.identity(item);
  if (!id) return "(not in the asset layer)";
  const bits: string[] = [];
  if (id.correlations.length) {
    bits.push(`merged across ${id.tools.join(" ")} on ${id.correlations.map((c) => c.match_key).join(" ")}`);
    if (id.aliases.length) bits.push(`aka ${id.aliases.join(" ")}`);
  }
  if (id.suggestions.length) {
    bits.push(`unconfirmed duplicate proposal: ${id.suggestions.map((s) => `${s.a}~${s.b}`).join(" ")}`);
  }
  return bits.length ? bits.join("; ") : "no cross-tool correlation";
}

/** Sort weight: proposals first (they need a decision), then settled merges,
 *  then everything else. */
function identityRank(item: InventoryItem, ctx: CellCtx): number {
  if (ctx.identityUnknown) return 3;
  const id = ctx.identity(item);
  if (!id) return 4;
  if (id.suggestions.length) return 0;
  if (id.correlations.length) return 1;
  return 2;
}

// ── Kind ───────────────────────────────────────────────────────────────────

/**
 * `role_source: "derived"` means NO SOURCE SAID THIS — the engine concluded it,
 * and `role_reason` is the argument. A derived kind renders with a dotted
 * underline carrying that reason, so a conclusion never sits on the screen
 * looking like a declaration.
 */
function KindCell({ item }: { item: InventoryItem }) {
  const src = item.role_source;
  const derived = src === "derived";
  const reason = item.role_reason?.trim();
  return (
    <span className="inline-flex flex-col gap-0.5">
      <span className="flex items-center gap-1.5">
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
      </span>
      {derived ? (
        <span className="text-[9.5px] font-bold uppercase tracking-[0.1em] text-text3">derived</span>
      ) : src === "unknown" ? (
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

// ── The register ───────────────────────────────────────────────────────────

export const INVENTORY_COLUMNS: InvColumn[] = [
  {
    id: "name",
    label: "Name",
    hint: "The entity and its key. Always shown, and pinned while the table scrolls sideways.",
    sortKey: "name",
    locked: true,
    defaultOn: true,
    minWidth: 240,
    cell: (item, ctx) => <NameCell item={item} ctx={ctx} />,
    csv: (item) => item.name,
  },
  {
    id: "kind",
    label: "Kind",
    hint: "Device role or entity kind, and whether a source declared it or the engine derived it.",
    sortKey: "kind",
    defaultOn: true,
    minWidth: 120,
    cell: (item) => <KindCell item={item} />,
    csv: (item) => `${item.kind}${item.role_source === "derived" ? " (derived)" : ""}`,
  },
  {
    id: "identity",
    label: "Identity",
    hint: "Whether the engine correlated this row with another console's record of the same thing — and whether an unconfirmed duplicate proposal names it.",
    sortKey: "identity",
    defaultOn: true,
    minWidth: 130,
    cell: (item, ctx) => <IdentityCell item={item} ctx={ctx} />,
    csv: identityCsv,
  },
  {
    id: "make",
    label: "Make / model",
    hint: "Vendor and model, as the source reported them.",
    sortKey: "make",
    defaultOn: true,
    minWidth: 140,
    cell: (item) =>
      item.vendor || item.model ? (
        <>
          <span className="block">{item.vendor ?? <Unreported what="a vendor" />}</span>
          <span className="mono block text-[11px] text-text3">{item.model ?? ""}</span>
        </>
      ) : (
        <Unreported what="a make or model" />
      ),
    csv: (item) => dash([item.vendor, item.model].filter(Boolean).join(" ")),
  },
  {
    id: "os",
    label: "OS",
    hint: "Operating-system version. Off by default — switch it on for a patch review.",
    sortKey: "os",
    defaultOn: false,
    minWidth: 110,
    cell: (item) =>
      item.os_version ? (
        <span className="mono text-[11.5px] text-text2">{item.os_version}</span>
      ) : (
        <Unreported what="an OS version" />
      ),
    csv: (item) => dash(item.os_version),
  },
  {
    id: "addresses",
    label: "Addresses",
    hint: "Every address on the entity, first two shown with a +N that opens in place.",
    sortKey: "addresses",
    defaultOn: true,
    minWidth: 170,
    cell: (item) => <AddressList addresses={item.addresses} />,
    csv: (item) => (item.addresses.length ? item.addresses.join(" ") : CSV_UNKNOWN),
  },
  {
    id: "vlan",
    label: "VLAN",
    hint: "VLAN id and name.",
    sortKey: "vlan",
    defaultOn: true,
    minWidth: 120,
    cell: (item) =>
      item.vlan_id == null && !item.vlan_name ? (
        <Unreported what="a VLAN" />
      ) : (
        <span className="whitespace-nowrap">
          <span className="mono tabular-nums">{item.vlan_id ?? "?"}</span>
          {item.vlan_name ? <span className="text-text2"> &middot; {item.vlan_name}</span> : null}
        </span>
      ),
    csv: (item) =>
      item.vlan_id == null && !item.vlan_name
        ? CSV_UNKNOWN
        : `${item.vlan_id ?? "?"}${item.vlan_name ? ` ${item.vlan_name}` : ""}`,
  },
  {
    id: "subnet",
    label: "Subnet",
    hint: "The block the entity's address falls in.",
    sortKey: "subnet",
    defaultOn: true,
    minWidth: 130,
    cell: (item) =>
      item.subnet ? (
        <span className="mono whitespace-nowrap text-[11.5px]">{item.subnet}</span>
      ) : (
        <Unreported what="a subnet" />
      ),
    csv: (item) => dash(item.subnet),
  },
  {
    id: "zone",
    label: "Zone",
    hint: "The firewall zone a source placed the entity in.",
    sortKey: "zone",
    defaultOn: true,
    minWidth: 100,
    cell: (item) => (item.zone ? <span className="text-text2">{item.zone}</span> : <Unreported what="a zone" />),
    csv: (item) => dash(item.zone),
  },
  {
    id: "tags",
    label: "Tags",
    hint: "Classification tags carried by the sources — pci, customer-data, internet-facing.",
    sortKey: "tags",
    defaultOn: false,
    minWidth: 150,
    cell: (item) =>
      item.tags.length ? (
        <span className="flex flex-wrap gap-1">
          {item.tags.map((t) => (
            <span key={t} className="chip mono !h-[18px] !px-1.5 text-[9.5px] uppercase tracking-[0.02em]">
              {t}
            </span>
          ))}
        </span>
      ) : (
        <Unreported what="a tag" />
      ),
    csv: (item) => (item.tags.length ? item.tags.join(" ") : CSV_UNKNOWN),
  },
  {
    id: "layer",
    label: "Layer",
    hint: "Where the topology engine placed the entity, outside-in. Off by default.",
    sortKey: "layer",
    defaultOn: false,
    minWidth: 110,
    cell: (item) =>
      item.layer ? (
        <span
          className={cn(
            "mono text-[11.5px]",
            item.layer_source === "derived" &&
              "cursor-help underline decoration-dotted decoration-from-font underline-offset-[3px]",
          )}
          title={
            item.layer_source === "derived"
              ? `Derived by the engine — no source declared a layer.${item.layer_reason ? `\n\n${item.layer_reason}` : ""}`
              : undefined
          }
        >
          {item.layer}
        </span>
      ) : (
        <Unreported what="a topology layer" />
      ),
    csv: (item) => `${dash(item.layer)}${item.layer_source === "derived" ? " (derived)" : ""}`,
  },
  {
    id: "sources",
    label: "Source(s)",
    hint: "EVERY console that saw this row, not the one that won — each with the tier its claim came from.",
    sortKey: "sources",
    defaultOn: true,
    minWidth: 200,
    cell: (item, ctx) => <SourceBadges observed={item.observed_by} cards={ctx.cards} />,
    csv: (item) =>
      item.observed_by.length
        ? item.observed_by.map((o) => `${o.tool}:${tierShort(o.tier)}`).join(" ")
        : CSV_UNKNOWN,
  },
  {
    id: "findings",
    label: "Findings",
    hint: "How many findings in this snapshot name the entity.",
    sortKey: "findings",
    defaultOn: true,
    minWidth: 90,
    align: "right",
    cell: (item, ctx) =>
      item.finding_ids.length > 0 ? (
        <button
          type="button"
          onClick={(e) => {
            e.stopPropagation();
            ctx.onOpen(item, "top");
          }}
          className="inline-flex h-[21px] items-center border border-sev-high-line bg-sev-high-bg px-1.5 text-[11px] font-bold tabular-nums text-sev-high transition-colors hover:border-sev-high"
          title={`Named in ${item.finding_ids.length} finding${item.finding_ids.length === 1 ? "" : "s"}: ${item.finding_ids.join(", ")}`}
        >
          {item.finding_ids.length}
        </button>
      ) : (
        <span className="text-text3 tabular-nums" title="This entity is named in no finding in this snapshot.">
          0
        </span>
      ),
    csv: (item) => String(item.finding_ids.length),
  },
];

export const COLUMN_BY_ID: Record<string, InvColumn> = Object.fromEntries(
  INVENTORY_COLUMNS.map((c) => [c.id, c]),
);

export const DEFAULT_COLUMN_IDS: string[] = INVENTORY_COLUMNS.filter((c) => c.defaultOn).map((c) => c.id);

export const LOCKED_COLUMN_IDS: string[] = INVENTORY_COLUMNS.filter((c) => c.locked).map((c) => c.id);

/** Resolve a stored preference into real columns: unknown ids are dropped (an
 *  older build's column), locked ids are forced back in, and the register's
 *  order is preserved so the table never reshuffles itself. */
export function resolveColumns(ids: string[]): InvColumn[] {
  const on = new Set(ids);
  for (const id of LOCKED_COLUMN_IDS) on.add(id);
  const picked = INVENTORY_COLUMNS.filter((c) => on.has(c.id));
  return picked.length ? picked : INVENTORY_COLUMNS.filter((c) => c.defaultOn);
}

/** The sort getters, built against the same register so a column can never be
 *  sortable by a key nothing computes. */
export function buildSorts(ctx: CellCtx): Record<string, (i: InventoryItem) => string | number> {
  return {
    name: (i) => i.name.toLowerCase(),
    kind: (i) => i.kind,
    identity: (i) => identityRank(i, ctx),
    make: (i) => `${i.vendor ?? "￿"} ${i.model ?? ""}`.toLowerCase(),
    os: (i) => (i.os_version ?? "￿").toLowerCase(),
    addresses: (i) => i.addresses.length,
    vlan: (i) => i.vlan_id ?? Number.MAX_SAFE_INTEGER,
    subnet: (i) => i.subnet ?? "￿",
    zone: (i) => i.zone ?? "￿",
    tags: (i) => (i.tags.length ? i.tags.join(" ") : "￿"),
    layer: (i) => i.layer ?? "￿",
    sources: (i) => i.observed_by.length,
    findings: (i) => i.finding_ids.length,
  };
}

// ── The name cell ──────────────────────────────────────────────────────────

function NameCell({ item, ctx }: { item: InventoryItem; ctx: CellCtx }) {
  const conflicts = item.conflicts.length;
  return (
    <span className="flex min-w-0 flex-col gap-0.5">
      <span className="flex flex-wrap items-center gap-1.5">
        {/* The row is clickable for the mouse, but the keyboard and a screen
            reader get a real control rather than a tabbable <tr>, which would
            cost the table its row semantics. */}
        <button
          type="button"
          onClick={(e) => {
            e.stopPropagation();
            ctx.onOpen(item, "top");
          }}
          className="break-all text-left font-bold transition-colors hover:text-accent-fg focus-visible:text-accent-fg"
        >
          {item.name}
        </button>
        {conflicts > 0 ? (
          <button
            type="button"
            onClick={(e) => {
              e.stopPropagation();
              ctx.onOpen(item, "conflicts");
            }}
            title={`Two sources state ${conflicts === 1 ? "this field" : "these fields"} differently: ${item.conflicts
              .map((c) => c.field)
              .join(", ")}. Click to see both claims and both tools.`}
            className="inline-flex h-[18px] shrink-0 items-center gap-1 border border-sev-high-line bg-sev-high-bg px-1 text-[10px] font-bold text-sev-high transition-colors hover:border-sev-high"
          >
            <TriangleAlert size={10} />
            {conflicts}
          </button>
        ) : null}
      </span>
      {item.key !== item.name ? (
        <span className="mono block break-all text-[10.5px] text-text3">{item.key}</span>
      ) : null}
    </span>
  );
}
