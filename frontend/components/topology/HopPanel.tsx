"use client";

/**
 * The hop-by-hop readout for one cross-tool path — the money shot, explained.
 *
 * This panel came off NetworkMap.tsx unchanged in substance, because it was the
 * good half of that screen: a chain of allow rules, each hop attributed to the
 * console that permits it and to the rule reference that proves it, ending in a
 * verdict that names the boundary crossed and the tags on the terminal. What it
 * lost was its own private graph. The hops now light the SAME cards the estate
 * is drawn on, so "the internet reaches db-prod-01" and "db-prod-01 is in VLAN
 * 50, behind the core pair" are one picture instead of two.
 *
 * The honesty rule here is specific: a hop whose endpoint is in no lane of the
 * topology response is NOT quietly skipped. It is listed as undrawable, by name,
 * because a chain that renders shorter than the one the engine found understates
 * exposure — and understating exposure is the one direction this product is not
 * allowed to be wrong in.
 */

import { ArrowRight, OctagonAlert, Route, X } from "lucide-react";
import type { ApiError } from "@/lib/api";
import { cn } from "@/lib/cn";
import { Chip, Skeleton, ToolBadge } from "@/components/ui";
import { ErrorState } from "@/components/ui/Feedback";
import { RuleRef } from "@/components/RuleRef";
import { toolColour } from "@/lib/toolColour";
import type { CrossToolPath, PlacedPath } from "./paths";

export interface HopPanelProps {
  paths: CrossToolPath[];
  index: number;
  onIndex: (i: number) => void;
  /** The selected path, resolved onto the canvas. */
  placed: PlacedPath | null;
  /** How many hops the reveal has played. */
  stage: number;
  onReplay: () => void;
  /** Centre the canvas on a card. */
  onFocusCard: (cardId: string) => void;
  /** True once `/api/graph` has answered. Before that, "no path" is not a claim
   *  anybody has checked. */
  ready: boolean;
  error?: ApiError;
  onRetry?: () => void;
  onDismiss: () => void;
  snapshot?: string;
  className?: string;
}

export function HopPanel(p: HopPanelProps) {
  const hero: CrossToolPath | undefined = p.paths[p.index];
  const hops = hero?.hops ?? [];

  return (
    <aside className={cn("zt-scroll flex h-full min-w-0 flex-col overflow-y-auto border-l border-border bg-surface", p.className)}>
      <header className="sticky top-0 z-10 flex shrink-0 items-center gap-1.5 border-b border-border bg-surface px-3 py-2">
        <span className="eyebrow min-w-0 truncate">
          Cross-tool path{p.ready && p.paths.length > 1 ? ` · ${p.paths.length}` : ""}
        </span>
        <div className="ml-auto flex shrink-0 items-center gap-1.5">
          {p.ready && hero ? (
            <span className="inline-flex items-center gap-1 text-[10.5px] font-bold uppercase tracking-[0.03em] text-sev-critical">
              <OctagonAlert size={12} /> Reachable
            </span>
          ) : null}
          <button
            type="button"
            onClick={p.onDismiss}
            className="btn-ghost !h-7 !w-7 !px-0"
            aria-label="Close the path panel"
            title="Close (Esc)"
          >
            <X size={14} />
          </button>
        </div>
      </header>

      {p.ready && p.paths.length > 1 ? (
        <div className="flex flex-wrap gap-1.5 border-b border-border p-2">
          {p.paths.map((path, i) => (
            <button
              key={`${path.terminal}:${i}`}
              type="button"
              onClick={() => p.onIndex(i)}
              className={cn(
                "mono inline-flex max-w-full items-center gap-1 border px-2 py-1 text-[11px]",
                i === p.index ? "border-accent bg-accent-soft font-bold text-text" : "border-border text-text2 hover:border-accent",
              )}
            >
              <ArrowRight size={11} className="shrink-0" />
              <span className="min-w-0 truncate">{path.terminal}</span>
            </button>
          ))}
        </div>
      ) : null}

      {p.error ? (
        <div className="p-3.5">
          <ErrorState resource="cross-tool paths" error={p.error} onRetry={p.onRetry} className="bg-transparent" />
        </div>
      ) : !p.ready ? (
        <div className="space-y-3 p-3.5">
          <Skeleton className="h-3 w-full" />
          <Skeleton className="h-3 w-4/5" />
          <div className="space-y-2 pt-1">
            {Array.from({ length: 4 }).map((_, i) => <Skeleton key={i} className="h-10 w-full" />)}
          </div>
          <Skeleton className="h-14 w-full" />
        </div>
      ) : !hero ? (
        <div className="p-10 text-center text-text3">
          <Route size={26} className="mx-auto mb-2" />
          <div className="text-[12.5px] text-text2">No cross-tool path in this snapshot.</div>
          <p className="mt-1.5 text-[11px] leading-snug text-text3">
            The analysis ran and found no chain of allow rules crossing more than one console. That is this snapshot&rsquo;s
            policy sets, not a guarantee about the estate.
          </p>
        </div>
      ) : (
        <div className="min-w-0 p-3.5">
          <p className="mb-3 break-words text-[12px] leading-relaxed text-text2">
            The internet reaches <span className="mono text-text">{hero.terminal}</span> in {hops.length} hop
            {hops.length === 1 ? "" : "s"} across <b className="text-text">{hero.tools.length}</b> tool
            {hero.tools.length === 1 ? "" : "s"}. No single console can show you this chain — each hop is in a different
            vendor&rsquo;s policy set.
          </p>

          {/* What the canvas could not draw. Named, never dropped. */}
          {p.placed && p.placed.missing.length > 0 ? (
            <div className="mb-3 border border-sev-medium-line bg-sev-medium-bg px-2.5 py-2 text-[11px] leading-snug text-text2">
              {p.placed.missing.length} node{p.placed.missing.length === 1 ? "" : "s"} on this chain
              {p.placed.missing.length === 1 ? " is" : " are"} in no lane of the topology response, so that part of the
              path is not drawn: <span className="mono break-all">{p.placed.missing.join(", ")}</span>. The hops below are
              the complete chain the engine found.
            </div>
          ) : null}
          {p.placed && p.placed.collapsed > 0 ? (
            <div className="mb-3 border border-border bg-sunk px-2.5 py-2 text-[11px] leading-snug text-text2">
              {p.placed.collapsed} hop{p.placed.collapsed === 1 ? "" : "s"} run between two devices inside one collapsed
              group card, so no line is drawn for {p.placed.collapsed === 1 ? "it" : "them"}. Expand that lane to see the
              hop on the canvas.
            </div>
          ) : null}

          <div className="space-y-0">
            {hops.map((h, i) => {
              const revealed = i < p.stage;
              const card = p.placed?.hops.find((x) => x.index === i);
              return (
                <div key={i} className={cn("min-w-0", !revealed && "opacity-45")}>
                  <button
                    type="button"
                    onClick={() => card && p.onFocusCard(card.from.id)}
                    disabled={!card}
                    className="flex w-full items-start gap-2.5 text-left disabled:cursor-default"
                    title={card ? `Centre the canvas on ${h.src_display}` : `${h.src_display} is in no lane of this topology response.`}
                  >
                    <span className="mt-1 h-2.5 w-2.5 shrink-0 border-2 border-accent bg-accent" />
                    <span className="mono min-w-0 break-all text-[12px] font-bold">{h.src_display}</span>
                  </button>
                  <div className="ml-[4px] min-w-0 border-l border-border py-1.5 pl-[14px]">
                    <div
                      className="min-w-0 border border-border bg-surface2 px-2.5 py-1.5"
                      style={{ borderLeft: `2px solid ${toolColour(h.tool)}` }}
                    >
                      <div className="break-words text-[11px] text-text2">
                        permits <span className="mono font-bold text-text">{h.service || "a service the payload does not name"}</span>
                        {h.l7_app ? (
                          <span
                            className="chip ml-1.5 border-sev-high-line bg-sev-high-bg px-1 py-0 text-[9px] uppercase text-sev-high"
                            title={`Decoded application${h.l7_source ? ` (${h.l7_source})` : ""}`}
                          >
                            {h.l7_app}
                          </span>
                        ) : null}
                      </div>
                      <div className="mt-1.5 flex flex-wrap items-center gap-1.5">
                        <ToolBadge tool={h.tool} />
                        <span className="text-[10px] text-text3">rule</span>
                        <RuleRef refId={h.ref} snapshot={p.snapshot} />
                      </div>
                    </div>
                  </div>
                  {i === hops.length - 1 ? (
                    <button
                      type="button"
                      onClick={() => card && p.onFocusCard(card.to.id)}
                      disabled={!card}
                      className="flex w-full items-start gap-2.5 text-left disabled:cursor-default"
                      title={card ? `Centre the canvas on ${h.dst_display}` : `${h.dst_display} is in no lane of this topology response.`}
                    >
                      <span className="mt-1 h-2.5 w-2.5 shrink-0 border-2 border-sev-critical bg-sev-critical" />
                      <span className="mono min-w-0 break-all text-[12px] font-bold">{h.dst_display}</span>
                    </button>
                  ) : null}
                </div>
              );
            })}
          </div>

          <div className="mt-2.5 border border-sev-critical-line bg-sev-critical-bg px-3 py-2.5">
            <div className="text-[11px] font-bold uppercase tracking-[0.04em] text-sev-critical">Verdict</div>
            <div className="mt-1 break-words text-[12px] leading-relaxed">
              Cross-tool path exposes a{" "}
              {hero.terminal_tags.length ? hero.terminal_tags.join(", ") : "host with no tags in this snapshot"} host to
              the internet ({hero.boundary || "boundary not stated"}). Break it at the cheapest hop.
            </div>
            {hero.terminal_service ? (
              <div className="mono mt-1 text-[11px] text-text2">terminal service: {hero.terminal_service}</div>
            ) : null}
          </div>

          <div className="mt-2 flex flex-wrap items-center gap-1.5">
            <button type="button" onClick={p.onReplay} className="btn-ghost text-[11.5px]">
              <Route size={12} /> Replay the trace
            </button>
            {hero.tools.map((t) => <Chip key={t} variant="neutral" mono>{t}</Chip>)}
          </div>
        </div>
      )}
    </aside>
  );
}
