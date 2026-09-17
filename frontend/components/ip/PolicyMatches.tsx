"use client";

/**
 * SECTION 2 — THE POLICIES, IN THREE GROUPS.
 *
 * The grouping IS the feature. "Which rules mention 10.30.7.7" is a text search
 * anybody can run; the question that matters is which rules REACH it, and the
 * dangerous answer is almost never in the list of rules that name it:
 *
 *   EXACT      names this address. Easy to find, easy to audit, rarely the risk.
 *   COVERING   permits this address WITHOUT NAMING IT — a rule on 10.30.0.0/16
 *              that nobody reviewing 10.30.7.7 would ever read. This is the group
 *              people forget, so it gets the same weight as the other two here:
 *              same type size, same row treatment, its own keyline, and a
 *              sentence saying why it is the one to look at.
 *   CONTAINED  sits inside the query. Only possible when the query is a block —
 *              for a host it is NOT APPLICABLE, which is a different statement
 *              from "none found" and renders as one.
 *
 * `matched_via` is printed on every row as a mono chip, because "this rule
 * covers that address" is set arithmetic and the operator is entitled to see the
 * step rather than take the engine's word for it.
 */

import { useMemo, useState } from "react";
import { ShieldCheck, Sigma } from "lucide-react";
import type { IpMatchRelation, IpPolicyMatch, IpLookupResponse } from "@/lib/types";
import { Eyebrow, cn } from "@/components/ui";
import { SearchBox } from "@/lib/tableTools";
import { RuleRef } from "@/components/RuleRef";
import type { SourceIndex } from "./data";
import { ActionChip, Flow, MonoChip, SourceToolBadge } from "./atoms";
import { IP_MODE_LABEL, type AddressShape, type IpMode } from "./addr";

/** What the engine means by each `matched_via` value, on hover. An unrecognised
 *  value is shown verbatim — a vocabulary the client has not caught up with is
 *  not a reason to hide how a match was made. */
const VIA_NOTE: Record<string, string> = {
  containment: "Address containment: the query falls inside an address object this rule names.",
  alias_map: "The identity layer resolves a named object in this rule to this address.",
  interface: "This rule names an interface that carries this address.",
  nat: "A NAT translation ties this address to one this rule names.",
};

interface GroupSpec {
  key: IpMatchRelation;
  title: string;
  blurb: string;
  keyline: string;
  emphasis?: boolean;
}

const GROUPS: GroupSpec[] = [
  {
    key: "exact",
    title: "Exact matches",
    blurb: "Rules that name this address. What a text search of the rule base would find.",
    keyline: "border-l-borderStrong",
  },
  {
    key: "covering",
    title: "Covering rules",
    blurb:
      "Rules whose source or destination CONTAINS this address without naming it. A review of this host would never surface these, and this is usually where the risk is.",
    keyline: "border-l-sev-high",
    emphasis: true,
  },
  {
    key: "contained",
    title: "Contained rules",
    blurb: "Rules that sit inside the queried block — the policy this range already carries.",
    keyline: "border-l-info",
  },
];

function MatchRow({
  m,
  sources,
  snapshot,
  onFinding,
}: {
  m: IpPolicyMatch;
  sources?: SourceIndex;
  snapshot?: string;
  onFinding?: (id: string) => void;
}) {
  return (
    <div className="row border-b border-hair px-3 py-2 last:border-0">
      <div className="flex flex-wrap items-center gap-x-2.5 gap-y-1.5">
        <RuleRef refId={m.rule_ref} snapshot={snapshot} />
        <SourceToolBadge tool={m.source_tool} sources={sources} />
        <ActionChip action={m.action} />
        <MonoChip title="The service this rule applies to, as the source tool states it.">{m.service || "any"}</MonoChip>
        <MonoChip
          tone="accent"
          title={VIA_NOTE[m.matched_via] ?? `How the address reached this rule, as the engine reported it: ${m.matched_via}`}
          className="ml-auto"
        >
          via {m.matched_via || "unstated"}
        </MonoChip>
        {m.finding_ids.length > 0 && (
          <button
            type="button"
            onClick={() => onFinding?.(m.finding_ids[0])}
            title={`This rule appears in: ${m.finding_ids.join(", ")}`}
            className="mono border border-sev-critical-line bg-sev-critical-bg px-1.5 text-[10px] font-bold leading-[18px] text-sev-critical"
          >
            {m.finding_ids.length} finding{m.finding_ids.length === 1 ? "" : "s"}
          </button>
        )}
      </div>
      <div className="mt-1">
        <Flow from={m.source} to={m.destination} />
      </div>
    </div>
  );
}

function emptyLine(key: IpMatchRelation, shape: AddressShape, mode: IpMode, address: string): string {
  if (key === "exact") return `No rule names ${address}.`;
  if (key === "covering") {
    return mode === "intersects"
      ? `No rule's source or destination contains ${address} without naming it.`
      : `None under mode ${IP_MODE_LABEL[mode]}. This mode does not look outward from the query — switch to intersects to ask whether anything covers this address.`;
  }
  return shape === "host"
    ? `Not applicable — ${address} is a single host, and a host contains nothing. This group is only populated for a block.`
    : `No rule sits inside ${address}.`;
}

export function PolicyMatches({
  data,
  shape,
  mode,
  sources,
  snapshot,
  onFinding,
}: {
  data: IpLookupResponse;
  shape: AddressShape;
  mode: IpMode;
  sources?: SourceIndex;
  snapshot?: string;
  onFinding?: (id: string) => void;
}) {
  const [q, setQ] = useState("");

  const all = useMemo(
    () => [...data.matches.exact, ...data.matches.covering, ...data.matches.contained],
    [data],
  );
  const allowCount = all.filter((m) => m.action.toLowerCase() === "allow").length;

  const needle = q.trim().toLowerCase();
  const match = (m: IpPolicyMatch) =>
    !needle ||
    `${m.rule_ref} ${m.source_tool} ${m.source} ${m.destination} ${m.service} ${m.action} ${m.matched_via}`
      .toLowerCase()
      .includes(needle);

  return (
    <section className="space-y-3">
      <div className="flex flex-wrap items-center gap-2">
        <Eyebrow>Policies reaching this address</Eyebrow>
        <span className="mono text-[11px] text-text3">
          {all.length} rule{all.length === 1 ? "" : "s"}
          {all.length > 0 && ` · ${allowCount} allow`}
        </span>
        {all.length > 0 && (
          <SearchBox value={q} onChange={setQ} placeholder="Filter rules, endpoints, services…" className="sm:ml-auto sm:w-56" />
        )}
      </div>

      <p className="flex items-start gap-1.5 text-[11.5px] leading-relaxed text-text2">
        <Sigma size={12} className="mt-0.5 shrink-0 text-text3" />
        <span>
          Every row carries <span className="mono text-text">via …</span> — the step by which the address
          reached the rule (<span className="mono">containment</span>, <span className="mono">alias_map</span>,{" "}
          <span className="mono">interface</span>, <span className="mono">nat</span>). Hover it for what the
          engine means. Counts are the payload&apos;s, not the filter&apos;s.
        </span>
      </p>

      {GROUPS.map((g) => {
        const rows = data.matches[g.key];
        const shown = rows.filter(match);
        return (
          <div key={g.key} className={cn("border border-border", g.emphasis && "border-sev-high-line")}>
            <header className={cn("border-l-2 px-3 py-2", g.keyline, g.emphasis ? "bg-sev-high-bg" : "bg-surface2")}>
              <div className="flex flex-wrap items-baseline gap-x-2 gap-y-1">
                <h3
                  className={cn(
                    "text-[12px] font-bold uppercase tracking-[0.1em]",
                    g.emphasis ? "text-sev-high" : "text-text",
                  )}
                >
                  {g.title}
                </h3>
                <span
                  className={cn(
                    "mono text-[14px] font-bold leading-none tabular-nums",
                    g.emphasis ? "text-sev-high" : "text-text",
                  )}
                >
                  ({rows.length})
                </span>
                {needle && rows.length > 0 && (
                  <span className="mono text-[10.5px] text-text3">{shown.length} match the filter</span>
                )}
              </div>
              <p className={cn("mt-0.5 text-[11.5px] leading-relaxed", g.emphasis ? "text-text2" : "text-text3")}>
                {g.blurb}
              </p>
            </header>

            {rows.length === 0 ? (
              <p className="px-3 py-3 text-[12px] text-text3">{emptyLine(g.key, shape, mode, data.address)}</p>
            ) : shown.length === 0 ? (
              <p className="px-3 py-3 text-[12px] text-text3">
                All {rows.length} hidden by the filter “{q}”.
              </p>
            ) : (
              <div>
                {shown.map((m, i) => (
                  <MatchRow key={`${m.rule_ref}-${i}`} m={m} sources={sources} snapshot={snapshot} onFinding={onFinding} />
                ))}
              </div>
            )}
          </div>
        );
      })}

      {all.length === 0 && (
        <p className="flex items-start gap-1.5 border border-border bg-sunk px-3 py-2.5 text-[12px] leading-relaxed text-text2">
          <ShieldCheck size={13} className="mt-0.5 shrink-0 text-text3" />
          <span>
            This address matched no rule in this snapshot, under mode{" "}
            <span className="mono text-text">{IP_MODE_LABEL[mode]}</span>. The rule base was read and nothing
            in it reaches {data.address} — this is a checked result, not a failed lookup.
          </span>
        </p>
      )}
    </section>
  );
}
