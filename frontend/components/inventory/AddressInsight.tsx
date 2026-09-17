"use client";

/**
 * WHAT THE POLICY LAYER DOES TO THIS ROW'S ADDRESS.
 *
 * The inventory answers "what is it and where did we find it". The question a
 * reviewer asks next is always "so what reaches it", and making them copy an
 * address into another screen to find out is how a review stops halfway. So the
 * drawer runs `GET /api/ip` for the row and renders the answer in place.
 *
 * THE GROUPING IS THE FEATURE, and it is the same grouping the address screen
 * uses, for the same reason:
 *
 *   EXACT      rules that NAME this address. What a text search of the rule base
 *              would find. Easy to audit, and rarely where the risk is.
 *   COVERING   rules that permit this address WITHOUT NAMING IT — a rule on
 *              10.30.0.0/16 that nobody reviewing 10.30.4.7 would ever read.
 *              This is the group people forget, so it is given the most weight
 *              here rather than the least.
 *   CONTAINED  rules that sit INSIDE the queried block. Only possible when the
 *              query is a block; for a single host it is NOT APPLICABLE, which
 *              is a different statement from "none found" and renders as one.
 *
 * `matched_via` is printed on every row, because "this rule covers that
 * address" is set arithmetic and the reviewer is entitled to see the step
 * rather than take the engine's word for it.
 *
 * And `effective.reachable_from_internet` is rendered WITH its caveat attached,
 * never as a bare verdict: the engine models the union of allow edges and does
 * not implement deny precedence, so "not reachable" means "no allow path was
 * found", not "provably blocked". A three-word verdict without that sentence is
 * the most dangerous thing this screen could print.
 */

import { useEffect, useRef, useState } from "react";
import { Cable, Globe, ShieldCheck } from "lucide-react";
import { api, asApiError, type ApiError } from "@/lib/api";
import type { InventoryItem, IpLookupResponse, IpMatchRelation, IpPolicyMatch } from "@/lib/types";
import { cn } from "@/lib/cn";
import { toolColour } from "@/lib/toolColour";
import { Skeleton } from "@/components/ui";
import { ErrorState } from "@/components/ui/Feedback";
// The allow/deny chip is the address screen's, on purpose: two surfaces that
// colour the same fact differently is how an operator learns to distrust both.
import { ActionChip } from "@/components/ip/atoms";
import { DrawerSection } from "./bits";

/** Host masks are dropped so the lookup asks about the host, not a /32 literal
 *  that some rule bases spell differently. Everything else goes as written. */
function queryForm(addr: string): string {
  const v = addr.trim();
  const slash = v.indexOf("/");
  if (slash < 0) return v;
  const prefix = v.slice(slash + 1);
  return prefix === "32" || prefix === "128" ? v.slice(0, slash) : v;
}

function isBlock(addr: string): boolean {
  const slash = addr.indexOf("/");
  if (slash < 0) return false;
  const p = addr.slice(slash + 1);
  return p !== "32" && p !== "128";
}

export function AddressInsight({ item, snapshot }: { item: InventoryItem; snapshot?: string }) {
  const addresses = item.addresses;
  const [picked, setPicked] = useState(0);
  const address = addresses[Math.min(picked, addresses.length - 1)];

  const [data, setData] = useState<IpLookupResponse>();
  const [error, setError] = useState<ApiError>();
  const [loading, setLoading] = useState(false);
  const [nonce, setNonce] = useState(0);
  const token = useRef(0);

  useEffect(() => setPicked(0), [item.key]);

  useEffect(() => {
    if (!address) {
      token.current += 1;
      setData(undefined);
      setError(undefined);
      setLoading(false);
      return;
    }
    const mine = ++token.current;
    setLoading(true);
    setError(undefined);
    api
      .ipLookup(queryForm(address), "intersects", snapshot)
      .then((d) => {
        // A slow answer to an abandoned query must never overwrite the answer
        // to the current one — this drawer is re-opened row after row.
        if (token.current === mine) {
          setData(d);
          setLoading(false);
        }
      })
      .catch((e) => {
        if (token.current !== mine) return;
        // No stale payload beside a fresh error: that is how a failed lookup
        // ends up rendering somebody else's address.
        setData(undefined);
        setError(asApiError(e));
        setLoading(false);
      });
  }, [address, snapshot, nonce]);

  if (!addresses.length) {
    return (
      <DrawerSection title="Policy touching this entity">
        <p className="text-[12px] leading-relaxed text-text2">
          No source reported an address for this entity, so there is nothing to look up. This is a gap in what the
          consoles told us &mdash; not a statement that no rule reaches it.
        </p>
      </DrawerSection>
    );
  }

  return (
    <>
      <DrawerSection
        title="Policy touching this entity"
        note="Run against one of this entity's own addresses. The engine answers with set arithmetic over address blocks, so a rule can reach this row without ever naming it."
      >
        <div className="mb-2 flex flex-wrap items-center gap-2">
          <span className="text-[10px] font-bold uppercase tracking-[0.1em] text-text3">address</span>
          {addresses.length > 1 ? (
            <select
              value={picked}
              onChange={(e) => setPicked(Number(e.target.value))}
              aria-label="Which of this entity's addresses to look up"
              className="field mono !h-7 w-auto max-w-full text-[11.5px]"
            >
              {addresses.map((a, i) => (
                <option key={`${a}-${i}`} value={i}>
                  {a}
                </option>
              ))}
            </select>
          ) : (
            <span className="mono text-[12px]">{addresses[0]}</span>
          )}
          <span className="text-[10.5px] text-text3">
            matched with <span className="mono">intersects</span> &mdash; any overlap, so covering blocks are included
          </span>
          {addresses.length > 1 ? (
            <span className="ml-auto text-[10.5px] text-text3">
              1 of {addresses.length} addresses &mdash; the others are separate questions
            </span>
          ) : null}
        </div>

        {error ? (
          <ErrorState
            resource={`the policy touching ${address}`}
            error={error}
            onRetry={() => setNonce((n) => n + 1)}
          />
        ) : loading || !data ? (
          <div className="space-y-2">
            {Array.from({ length: 3 }).map((_, i) => (
              <Skeleton key={i} className="h-9 w-full" />
            ))}
          </div>
        ) : (
          <div className="space-y-3">
            <Effective effective={data.effective} />
            {(["exact", "covering", "contained"] as IpMatchRelation[]).map((rel) => (
              <MatchGroup key={rel} rel={rel} matches={data.matches[rel] ?? []} block={isBlock(address)} />
            ))}
          </div>
        )}
      </DrawerSection>

      <DrawerSection
        title="Interfaces carrying this address"
        note="The physical or logical legs an onboarded source reported for this address. An empty list is a coverage gap, not proof the address is unattached."
      >
        {error ? (
          <p className="text-[12px] text-text2">
            The address lookup failed, so the interfaces behind this address are <span className="font-bold">unknown</span>{" "}
            &mdash; see the failure above. They are not being reported as none.
          </p>
        ) : loading || !data ? (
          <div className="space-y-2">
            <Skeleton className="h-8 w-full" />
            <Skeleton className="h-8 w-2/3" />
          </div>
        ) : data.interfaces.length === 0 ? (
          <p className="text-[12px] leading-relaxed text-text2">
            The read succeeded and no onboarded source reported an interface carrying{" "}
            <span className="mono">{address}</span>. For an address the policy layer knows but no device console
            enumerates, that is exactly what you would expect &mdash; the Sources screen lists what each console is blind
            to.
          </p>
        ) : (
          <ul className="space-y-1.5">
            {data.interfaces.map((i) => (
              <li key={i.interface_key} className="border border-border bg-sunk px-2.5 py-1.5">
                <div className="flex flex-wrap items-center gap-2">
                  <Cable size={12} className="shrink-0 text-text3" />
                  <span className="mono break-all text-[12px] font-bold">{i.name}</span>
                  <span className="text-[11px] text-text2">on</span>
                  <span className="mono break-all text-[11.5px] text-text2">{i.device_key}</span>
                  {i.vlan_id != null ? (
                    <span className="chip mono !h-[17px] text-[9.5px]">vlan {i.vlan_id}</span>
                  ) : null}
                </div>
                <div className="mono mt-0.5 break-all text-[10.5px] tabular-nums text-text3">
                  {i.addresses.length ? i.addresses.join(", ") : "no address on this interface record"}
                </div>
              </li>
            ))}
          </ul>
        )}
      </DrawerSection>
    </>
  );
}

// ── Effective access ───────────────────────────────────────────────────────

function Effective({ effective }: { effective: IpLookupResponse["effective"] }) {
  const v = effective.reachable_from_internet;
  const unknown = v === null || v === undefined;
  return (
    <div
      className={cn(
        "border px-2.5 py-2",
        unknown
          ? "border-border bg-sunk"
          : v
            ? "border-sev-high-line bg-sev-high-bg"
            : "border-ok-line bg-ok-bg",
      )}
    >
      <div
        className={cn(
          "flex items-center gap-1.5 text-[12px] font-bold",
          unknown ? "text-text2" : v ? "text-sev-high" : "text-ok",
        )}
      >
        <Globe size={13} className="shrink-0" />
        {unknown
          ? "Whether an allow path from the internet exists is unknown"
          : v
            ? "An allow path from the internet was found"
            : "No allow path from the internet was found"}
      </div>
      {/* The caveat travels with the verdict, always. Printed, not linked. */}
      <p className="mt-1 text-[10.5px] leading-relaxed text-text2">{effective.caveat}</p>
    </div>
  );
}

// ── Policy groups ──────────────────────────────────────────────────────────

const GROUP: Record<IpMatchRelation, { title: string; blurb: string; keyline: string; emphasis?: boolean }> = {
  exact: {
    title: "Exact",
    blurb: "Rules that NAME this address. What a text search of the rule base would find.",
    keyline: "border-l-borderStrong",
  },
  covering: {
    title: "Covering",
    blurb:
      "Rules whose source or destination CONTAINS this address without naming it. A review of this entity alone would never surface these, and this is usually where the risk is.",
    keyline: "border-l-sev-high",
    emphasis: true,
  },
  contained: {
    title: "Contained",
    blurb: "Rules that sit inside the queried block — the policy this range already carries.",
    keyline: "border-l-info",
  },
};

function MatchGroup({ rel, matches, block }: { rel: IpMatchRelation; matches: IpPolicyMatch[]; block: boolean }) {
  const g = GROUP[rel];
  // For a single host, "contained" is not a question that can have an answer.
  // "Not applicable" and "none found" are different facts.
  const na = rel === "contained" && !block;
  return (
    <div className={cn("border-l-2 pl-2.5", g.keyline)}>
      <div className="flex flex-wrap items-baseline gap-2">
        <span
          className={cn(
            "text-[11px] font-bold uppercase tracking-[0.1em]",
            g.emphasis ? "text-sev-high" : "text-text2",
          )}
        >
          {g.title}
        </span>
        <span className="mono text-[11px] tabular-nums text-text3">
          {na ? "n/a" : `${matches.length} ${matches.length === 1 ? "rule" : "rules"}`}
        </span>
      </div>
      <p className="mt-0.5 text-[10.5px] leading-relaxed text-text3">{g.blurb}</p>
      {na ? (
        <p className="mt-1 text-[11px] text-text2">
          This query is a single host, so nothing can sit inside it. Not applicable &mdash; not &ldquo;none
          found&rdquo;.
        </p>
      ) : matches.length === 0 ? (
        <p className="mt-1 text-[11px] text-text2">
          The read succeeded and no rule in this snapshot matched this way.
        </p>
      ) : (
        <ul className="mt-1.5 space-y-1">
          {matches.map((m, i) => (
            <MatchRow key={`${m.rule_ref}-${i}`} m={m} />
          ))}
        </ul>
      )}
    </div>
  );
}

function MatchRow({ m }: { m: IpPolicyMatch }) {
  return (
    <li className="border border-border bg-sunk px-2 py-1.5">
      <div className="flex flex-wrap items-center gap-x-2 gap-y-1">
        <ActionChip action={m.action} />
        <span className="mono text-[11px] font-bold">{m.rule_ref}</span>
        <span className="inline-flex items-center gap-1">
          <span aria-hidden className="h-2 w-2 shrink-0" style={{ background: toolColour(m.source_tool) }} />
          <span className="mono text-[10.5px] text-text2">{m.source_tool}</span>
        </span>
        {m.finding_ids.length > 0 ? (
          <span
            className="mono inline-flex h-[17px] items-center border border-sev-high-line bg-sev-high-bg px-1 text-[9.5px] font-bold tabular-nums text-sev-high"
            title={`Named in ${m.finding_ids.length} finding${m.finding_ids.length === 1 ? "" : "s"}: ${m.finding_ids.join(", ")}`}
          >
            {m.finding_ids.length} finding{m.finding_ids.length === 1 ? "" : "s"}
          </span>
        ) : null}
      </div>
      <div className="mono mt-1 flex flex-wrap items-center gap-x-1.5 gap-y-0.5 break-all text-[11px]">
        <span>{m.source}</span>
        <span className="text-text3">&rarr;</span>
        <span>{m.destination}</span>
        <span className="text-text3">&middot;</span>
        <span className="text-text2">{m.service}</span>
      </div>
      <div className="mt-0.5 flex items-start gap-1.5 text-[10.5px] leading-snug text-text3">
        <ShieldCheck size={10} className="mt-[2px] shrink-0" />
        <span>{m.matched_via}</span>
      </div>
    </li>
  );
}

export default AddressInsight;
