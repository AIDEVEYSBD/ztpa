"use client";

/**
 * THE RULE, IN FULL.
 *
 * The screen used to print `WIZ-001 GC-002 ALGO-029` and stop. A reference is
 * not a rule: deciding whether a grant should exist needs the action, both
 * endpoints as ASSETS rather than tokens, the service and decoded application,
 * which console and which device it lives on, and where it sits in the
 * rulebase — because "remove ALGO-021" and "ALGO-021 is a deny that never fires
 * because ALGO-001 is above it" are different instructions.
 *
 * ASSETS, NAMED. When a proposed fix removes or narrows a rule, the reviewer
 * approving it has to be able to see WHAT LOSES ACCESS: the display name, the
 * kind, the regulated tags, the addresses, and which consoles saw it. That is
 * what `AssetBlock` is for, and it is why a null asset is rendered as "no asset
 * resolves this token" rather than quietly as the token itself.
 */

import { AlertTriangle, RotateCw } from "lucide-react";
import type { ApiError, RuleAsset, RuleContext, RuleEndpoint, RuleRow } from "@/lib/api";
import { cn } from "@/lib/cn";
import { ToolBadge } from "@/components/ui";
import { errorStatusLabel } from "@/components/ui/Feedback";
import { DirectionChip, FlowArrow, OneWayChip, TwoWayChip } from "./direction";

/** Tags that change the answer. A reviewer skimming a removal needs to see
 *  "this is the PCI database" before anything else on the card. */
const REGULATED = new Set(["pci", "customer-data", "phi", "crown-jewel", "internet-facing"]);

export function AssetTag({ tag }: { tag: string }) {
  const hot = REGULATED.has(tag);
  return (
    <span
      title={hot ? `"${tag}" is a regulated / exposure tag — removing or widening access here is a compliance-relevant change.` : undefined}
      className={cn("mono inline-flex h-[18px] items-center border px-1 text-[9.5px] font-bold uppercase tracking-[0.04em]",
        hot ? "border-sev-critical-line bg-sev-critical-bg text-sev-critical" : "border-border bg-sunk text-text2")}
    >
      {tag}
    </span>
  );
}

/** One field line inside a rule card. */
function Field({ label, children, className }: { label: string; children: React.ReactNode; className?: string }) {
  return (
    <div className={cn("grid grid-cols-[76px_1fr] items-start gap-2 py-1", className)}>
      <span className="pt-px text-[9.5px] font-bold uppercase tracking-[0.12em] text-text3">{label}</span>
      <span className="min-w-0 break-words text-[11.5px]">{children}</span>
    </div>
  );
}

/**
 * One side of a rule, as an asset rather than as a string.
 *
 * `side` is spelled out ("source" / "destination") because on a bidirectional
 * pair the words are the only thing separating the two halves of the card.
 */
export function AssetBlock({ side, endpoint, emphasis }: {
  side: "source" | "destination";
  endpoint: RuleEndpoint;
  /** Draw the hairline in the direction's colour — used for the end of the
   *  grant that sits in public space. */
  emphasis?: boolean;
}) {
  const a: RuleAsset | null = endpoint.asset;
  return (
    <div className={cn("min-w-0 border bg-sunk p-2", emphasis ? "border-borderStrong" : "border-border")}>
      <div className="flex items-center gap-1.5">
        <span className="text-[9.5px] font-bold uppercase tracking-[0.14em] text-text3">{side}</span>
        {endpoint.public && (
          <span
            title="This endpoint is public address space. The engine's own is_public classifier decided it — the same one the severity scorer uses."
            className="inline-flex h-[16px] items-center border border-sev-critical-line bg-sev-critical-bg px-1 text-[9px] font-bold uppercase tracking-[0.08em] text-sev-critical"
          >
            public
          </span>
        )}
      </div>

      <div className="mono mt-1 truncate text-[12.5px] font-bold" title={a?.display ?? endpoint.token}>
        {a?.display ?? endpoint.token}
      </div>

      {a ? (
        <>
          <div className="mono mt-0.5 text-[10px] text-text3">
            {a.kind}
            {a.key !== a.display ? ` · ${a.key}` : ""}
            {endpoint.resolved_to ? ` · resolved from ${endpoint.token}` : ""}
          </div>
          {a.tags.length > 0 && (
            <div className="mt-1.5 flex flex-wrap gap-1">{a.tags.map((t) => <AssetTag key={t} tag={t} />)}</div>
          )}
          <Field label="addresses">
            {a.addresses.length ? (
              <span className="mono tabular-nums">{a.addresses.join(", ")}</span>
            ) : (
              <span className="cursor-help text-text3 underline decoration-dotted underline-offset-2"
                title="No onboarded source reported an address for this asset. Unknown, not absent.">—</span>
            )}
          </Field>
          <Field label="seen by">
            {a.seen_by.length ? (
              <span className="inline-flex flex-wrap gap-1">{a.seen_by.map((t) => <ToolBadge key={t} tool={t} />)}</span>
            ) : (
              <span className="cursor-help text-text3 underline decoration-dotted underline-offset-2"
                title="No console is recorded against this asset in the snapshot.">—</span>
            )}
          </Field>
        </>
      ) : (
        <>
          {/* NOT rendered as the token dressed up as an asset: nothing in this
              snapshot resolves it, and a reviewer approving a removal needs to
              know that nobody can say what is behind it. */}
          <div className="mt-1 text-[10.5px] leading-relaxed text-text3">
            No asset in this snapshot resolves this token, so what sits behind it is unknown.
          </div>
          {endpoint.cidrs.length > 0 && (
            <Field label="covers"><span className="mono tabular-nums">{endpoint.cidrs.join(", ")}</span></Field>
          )}
        </>
      )}
    </div>
  );
}

/** The service line: transport, ports as the rulebase spells them, and the
 *  decoded L7 application when the engine inferred one. */
function ServiceLine({ ctx, row }: { ctx: RuleContext; row?: RuleRow }) {
  const ports = row?.ports ?? [];
  const spelled = ports.length
    ? ports.map((p) => (p.port_start === p.port_end ? `${p.proto}/${p.port_start}` : `${p.proto}/${p.port_start}-${p.port_end}`)).join(", ")
    : null;
  return (
    <span className="inline-flex flex-wrap items-center gap-1.5">
      <span className="mono border border-border bg-sunk px-1.5 py-0.5 text-[10.5px] font-bold tabular-nums">{ctx.service}</span>
      {spelled && spelled !== ctx.service && (
        <span className="mono text-[10px] text-text3" title="The port range exactly as the rulebase spells it.">{spelled}</span>
      )}
      <span className="mono text-[10px] uppercase tracking-[0.06em] text-text3">{ctx.protocol}</span>
      {ctx.l7_app && (
        <span
          title="Decoded application. The engine infers this from the service; it is not read off the wire."
          className="mono inline-flex h-[18px] items-center border border-border bg-sunk px-1 text-[9.5px] font-bold uppercase tracking-[0.06em] text-text2"
        >
          {ctx.l7_app}
        </span>
      )}
    </span>
  );
}

/**
 * One resolved rule. `row` is the canonical DB row for the same reference when
 * one is available — it is the only source for `rule_order` and the device the
 * rule lives on, and both change what "remove this rule" means.
 */
export function RuleBody({ ctx, row, reverseSlot, compact }: {
  ctx: RuleContext;
  row?: RuleRow;
  /** The expandable token for `direction.reverse_ref`, injected by the caller
   *  (this file cannot import RuleToken without a cycle). */
  reverseSlot?: React.ReactNode;
  compact?: boolean;
}) {
  const deny = ctx.action !== "allow";
  return (
    <div className="min-w-0">
      {/* Identity: which console, which device, where in the rulebase. */}
      <div className="flex flex-wrap items-center gap-1.5 border-b border-hair px-2.5 py-1.5">
        <span className="mono text-[12px] font-bold">{ctx.raw_ref}</span>
        <span
          className={cn("mono inline-flex h-[18px] items-center border px-1 text-[9.5px] font-bold uppercase tracking-[0.06em]",
            deny ? "border-ok-line bg-ok-bg text-ok" : "border-sev-critical-line bg-sev-critical-bg text-sev-critical")}
          title={deny ? "A deny rule." : "An allow rule — this is a grant of access."}
        >
          {ctx.action}
        </span>
        <ToolBadge tool={ctx.tool} detail={row?.source_device ?? undefined} />
        {row?.rule_order != null && (
          <span className="mono text-[10px] text-text3" title="Position in the rulebase. Order decides which rule matches first, so it decides whether this one ever fires.">
            order {row.rule_order}
          </span>
        )}
      </div>

      {/* Direction, then the flow line itself. */}
      <div className="flex flex-wrap items-center gap-1.5 px-2.5 py-1.5">
        <DirectionChip refId={ctx.raw_ref} direction={ctx.direction} />
        <span className="text-[10.5px] text-text3">{ctx.direction.detail}</span>
        <span className="ml-auto inline-flex items-center gap-1.5">
          {ctx.direction.bidirectional ? <TwoWayChip /> : <OneWayChip />}
          {ctx.direction.bidirectional && (
            <span className="inline-flex items-center gap-1 text-[10.5px] text-text3">
              reverse {reverseSlot ?? <span className="mono text-text2">{ctx.direction.reverse_ref ?? "—"}</span>}
            </span>
          )}
        </span>
      </div>

      <div className="flex flex-wrap items-center gap-2 border-y border-hair px-2.5 py-2">
        <span className="mono min-w-0 max-w-full truncate text-[12px]" title={ctx.source.token}>
          {ctx.source.asset?.display ?? ctx.source.token}
        </span>
        <FlowArrow direction={ctx.direction} />
        <span className="mono min-w-0 max-w-full truncate text-[12px]" title={ctx.destination.token}>
          {ctx.destination.asset?.display ?? ctx.destination.token}
        </span>
        <span className="ml-auto"><ServiceLine ctx={ctx} row={row} /></span>
      </div>

      {/* The assets behind each side — what a removal would disconnect. */}
      {!compact && (
        <div className="grid gap-2 p-2.5 sm:grid-cols-2">
          <AssetBlock side="source" endpoint={ctx.source} emphasis={ctx.source.public} />
          <AssetBlock side="destination" endpoint={ctx.destination} emphasis={ctx.destination.public} />
        </div>
      )}

      {row?.tags && row.tags.length > 0 && (
        <div className="flex flex-wrap items-center gap-1 border-t border-hair px-2.5 py-1.5">
          <span className="text-[9.5px] font-bold uppercase tracking-[0.12em] text-text3">rule tags</span>
          {row.tags.map((t) => <AssetTag key={t} tag={t} />)}
        </div>
      )}
    </div>
  );
}

/** The failure and not-found states, kept apart on purpose: "the lookup failed"
 *  and "this snapshot has no such rule" are different facts, and only one of
 *  them is a statement about the estate. */
export function RuleUnavailable({ refId, error, onRetry }: { refId: string; error?: ApiError; onRetry?: () => void }) {
  if (error) {
    return (
      <div role="alert" className="flex flex-wrap items-start gap-1.5 border border-sev-critical-line bg-sev-critical-bg p-2 text-[11px]">
        <AlertTriangle size={12} className="mt-0.5 shrink-0 text-sev-critical" />
        <span className="min-w-0 flex-1">
          <b className="text-sev-critical">Could not load rule {refId}</b>
          <span className="mono ml-1 break-words text-text3">{errorStatusLabel(error)} · {error.detail}</span>
          <span className="mt-0.5 block text-text3">This is not an empty rule — nothing about it is known.</span>
        </span>
        {onRetry && (
          <button onClick={onRetry} className="btn-ghost shrink-0 !h-[22px] !px-1.5 text-[10px]">
            <RotateCw size={10} /> Retry
          </button>
        )}
      </div>
    );
  }
  return (
    <div className="border border-border bg-sunk p-2 text-[11px] text-text3">
      Rule <span className="mono text-text2">{refId}</span> is not in this snapshot. It was named by a finding, so it
      existed when the finding was computed.
    </div>
  );
}

/** Reference a rule row to a context entry by tool, so `rule_order` and the
 *  device come from the row that describes the same console. */
export function rowFor(ctx: RuleContext, rows?: RuleRow[]): RuleRow | undefined {
  return (rows ?? []).find((r) => r.source_tool === ctx.tool) ?? (rows ?? [])[0];
}
