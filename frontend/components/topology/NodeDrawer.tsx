"use client";

/**
 * Everything one node is, down to the rule level — the drawer a click on a card
 * opens.
 *
 * THE COMPLAINT THIS ANSWERS. "i cant use it or click on something to see
 * details about it". Before this, selection on the canvas was driven only by
 * findings: a device nothing had flagged was unclickable, and a device that HAD
 * been flagged could only be reached through the walkthrough. Every fact the
 * payload carried about a box — its interfaces, its OS, its serial, which
 * consoles saw it, which rules reach it — was either on a tooltip or on another
 * screen.
 *
 * WHAT IS IN HERE AND WHERE IT COMES FROM. Nothing below is computed in the
 * browser except the joins that are explicitly the payload's own:
 *
 *   identity, interfaces, provenance   `/api/topology`, on the node
 *   VLAN -> subnet / gateway           `/api/topology.vlans`, looked up by the
 *                                      node's own vlan_ids — the payload's map,
 *                                      not an inference from an address
 *   findings it appears in             `TopoNode.finding_ids`, the backend's join
 *   rules that touch it                `GET /api/ip?address=…`, grouped exactly
 *                                      as that endpoint groups them
 *   blast radius                       `/api/resilience.blast_radius`, measured
 *                                      over the whole adjacency by the engine
 *
 * AND WHAT IT REFUSES TO DO. A host the policy layer placed by address has no
 * serial, no model and no interfaces, because no console ever described it as
 * hardware. Those rows are NOT printed as em-dashes in a list of specifications
 * — that reads as a fetch that failed. The drawer says which consoles described
 * this node and what that kind of source does not carry.
 */

import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import {
  Activity, AlertTriangle, ArrowRight, Cable, Radio, Route, Server, ShieldAlert, X, Zap,
} from "lucide-react";
import { api, asApiError, type ApiError } from "@/lib/api";
import type { BlastRadius, IpLookupResponse, IpPolicyMatch, SourceConflict } from "@/lib/types";
import { cn } from "@/lib/cn";
import { Chip, SeverityPill, Spinner, ToolBadge } from "@/components/ui";
import { ErrorState, InlineError } from "@/components/ui/Feedback";
import { NetIcon } from "@/components/net/icons";
import { RuleRef } from "@/components/RuleRef";
import { KV } from "./kv";
import type { WalkFinding } from "./findings";
import { allAddresses, distinctTools, primaryAddress, type ExplorerNode, type NodeInterface, type VlanFacts } from "./node";

function Section({ title, icon: Icon, children, note }: {
  title: string; icon?: typeof Server; children: React.ReactNode; note?: string;
}) {
  return (
    <section className="min-w-0 border-t border-line px-4 py-3">
      <div className="mb-1.5 flex items-center gap-1.5">
        {Icon ? <Icon size={11} className="shrink-0 text-dim" /> : null}
        <span className="text-[11px] font-medium tracking-[0.06em] text-faint uppercase">{title}</span>
      </div>
      {note ? <p className="mb-1.5 text-[10.5px] leading-[1.5] text-ghost">{note}</p> : null}
      {children}
    </section>
  );
}

/** A fact the payload does not carry, said as itself. Never an em-dash in a
 *  spec sheet, which reads as a failed read. */
function NotCarried({ children }: { children: React.ReactNode }) {
  return <p className="text-[11px] leading-snug text-text3">{children}</p>;
}

function Addr({ value }: { value: string }) {
  return (
    <span className="mono max-w-full truncate border border-border bg-sunk px-1 text-[10.5px] text-text2" title={value}>
      {value}
    </span>
  );
}

function IfaceRow({ i }: { i: NodeInterface }) {
  const bits = [
    i.vlan_id != null ? `VLAN ${i.vlan_id}` : null,
    i.speed_mbps ? `${i.speed_mbps} Mb/s` : null,
    i.lag_group ? `LAG ${i.lag_group}` : null,
    i.admin_up === false ? "admin down" : null,
    i.oper_up === false ? "oper down" : null,
  ].filter(Boolean);
  return (
    <li className="min-w-0 border border-border bg-surface px-2 py-1.5">
      <div className="flex flex-wrap items-baseline gap-x-2 gap-y-0.5">
        <span className="mono min-w-0 break-all text-[11.5px] font-bold">{i.name}</span>
        {bits.length > 0 ? <span className="mono text-[10px] text-text3">{bits.join(" · ")}</span> : null}
      </div>
      {i.addresses?.length ? (
        <div className="mt-1 flex flex-wrap gap-1">
          {i.addresses.map((a) => <Addr key={a} value={a} />)}
        </div>
      ) : (
        <div className="text-[10.5px] text-text3">no address reported on this interface</div>
      )}
      {i.description ? <div className="mt-1 break-words text-[10.5px] leading-snug text-text2">{i.description}</div> : null}
      {i.neighbor_device ? (
        <div className="mono mt-0.5 break-all text-[10.5px] text-text3">
          neighbour {i.neighbor_device}
          {i.neighbor_interface ? ` ${i.neighbor_interface}` : ""}
        </div>
      ) : null}
      {i.networks_behind?.length ? (
        <div className="mono mt-0.5 break-all text-[10.5px] text-text3">
          networks behind: {i.networks_behind.join(", ")}
        </div>
      ) : null}
    </li>
  );
}

function MatchRow({ m, snapshot }: { m: IpPolicyMatch; snapshot?: string }) {
  const deny = m.action !== "allow";
  return (
    <li className={cn("min-w-0 border bg-surface px-2 py-1.5", deny ? "border-border" : "border-sev-high-line")}>
      <div className="flex flex-wrap items-center gap-1.5">
        <RuleRef refId={m.rule_ref} snapshot={snapshot} />
        <span className={cn("mono text-[10px] font-bold uppercase", deny ? "text-text3" : "text-sev-high")}>{m.action}</span>
        <span className="mono text-[10.5px] text-text3">{m.source_tool}</span>
      </div>
      <div className="mono mt-1 flex flex-wrap items-center gap-1 break-all text-[11px] text-text2">
        <span className="text-text">{m.source}</span>
        <ArrowRight size={10} className="shrink-0 text-text3" />
        <span className="text-text">{m.destination}</span>
        <span className="text-text3">· {m.service}</span>
      </div>
      <div className="mt-0.5 break-words text-[10.5px] leading-snug text-text3">{m.matched_via}</div>
    </li>
  );
}

const RELATION_COPY: Record<string, { title: string; note: string }> = {
  exact: {
    title: "Rules that name this address",
    note: "The rule's source or destination IS this address, exactly as written.",
  },
  covering: {
    title: "Rules that cover it without naming it",
    note: "The group people forget: a rule written over a wider block that this address falls inside. It permits the traffic just as effectively, and no console lists it under this host.",
  },
  contained: {
    title: "Rules inside this block",
    note: "This node's address is a block, and these rules name something inside it.",
  },
};

export interface NodeDrawerProps {
  node: ExplorerNode;
  /** Which lane it sits in, in the lane's own words. */
  layerLabel: string;
  vlans: Map<number, VlanFacts>;
  simulatedTools: ReadonlySet<string> | null;
  /** Estate-level conflicts, already filtered to the ones naming this node. */
  sourceConflicts: SourceConflict[];
  findings: WalkFinding[];
  onSelectFinding: (id: string) => void;
  /** Cards this node has a drawn link to, so the drawer can walk the estate. */
  neighbours: { id: string; name: string; evidence: string }[];
  onSelectNode: (cardId: string) => void;
  /** The engine's measured radius for this device, when it has one. */
  blast?: BlastRadius;
  /** True once `/api/resilience` has answered. Until then the absence of a
   *  radius is "not read yet", not "this device has none". */
  blastRead: boolean;
  blastError?: ApiError;
  blastBasis?: string;
  simulating: boolean;
  onSimulateLoss: () => void;
  onStopSimulation: () => void;
  unlinkedReason?: string | null;
  snapshot?: string;
  onClose: () => void;
  className?: string;
}

export function NodeDrawer(p: NodeDrawerProps) {
  const n = p.node;
  const [ip, setIp] = useState<IpLookupResponse>();
  const [ipErr, setIpErr] = useState<ApiError>();
  const [ipLoading, setIpLoading] = useState(false);

  const scroller = useRef<HTMLElement | null>(null);
  // Opening a different node starts at the top of its own drawer.
  useEffect(() => { scroller.current?.scrollTo({ top: 0 }); }, [n.key]);

  const address = useMemo(() => primaryAddress(n), [n]);
  const addresses = useMemo(() => allAddresses(n), [n]);
  const ifaces = n.interfaces ?? [];
  const tools = n.observed_by ?? [];
  const toolNames = useMemo(() => distinctTools(n), [n]);
  const conflicts = useMemo(
    () => [...(n.conflicts ?? []), ...p.sourceConflicts],
    [n.conflicts, p.sourceConflicts],
  );

  const lookup = useCallback(() => {
    if (!address) return;
    let live = true;
    setIpLoading(true);
    setIpErr(undefined);
    // `intersects` is sent explicitly: the "covering" group — the rules that
    // permit this address without naming it — only appears under a mode that
    // looks outward from the query, and which mode ran has to be visible.
    api.ipLookup(address, "intersects", p.snapshot)
      .then((r) => { if (live) setIp(r); })
      .catch((e) => { if (live) { setIp(undefined); setIpErr(asApiError(e)); } })
      .finally(() => { if (live) setIpLoading(false); });
    return () => { live = false; };
  }, [address, p.snapshot]);

  useEffect(() => {
    setIp(undefined);
    setIpErr(undefined);
    return lookup();
  }, [lookup]);

  const mine = useMemo(
    () => new Set(n.finding_ids ?? []),
    [n.finding_ids],
  );
  const named = useMemo(
    () => p.findings.filter((f) => mine.has(f.id) || f.involved.includes(n.key)),
    [p.findings, mine, n.key],
  );

  const vlanRows = (n.vlan_ids ?? []).map((id) => ({ id, facts: p.vlans.get(id) }));
  const simulated = p.simulatedTools ? tools.filter((t) => p.simulatedTools!.has(t.tool)) : [];

  const matches = ip?.matches;
  const matchTotal = matches ? matches.exact.length + matches.covering.length + matches.contained.length : 0;

  return (
    <aside
      ref={scroller}
      className={cn("zt-scroll flex h-full min-w-0 flex-col overflow-y-auto border-l border-line bg-surface", p.className)}
      aria-label={`Details for ${n.name || n.key}`}
    >
      <header className="sticky top-0 z-10 flex shrink-0 items-start gap-2 border-b border-line bg-surface px-3 py-2">
        <NetIcon kind={n.role ?? n.kind} size={18} className="mt-0.5 shrink-0 text-dim" />
        <div className="min-w-0 flex-1">
          <div className="font-mono text-[12.5px] leading-tight font-medium break-all text-fg">{n.name || n.key}</div>
          <div className="font-mono text-[10.5px] break-all text-faint">{n.key}</div>
        </div>
        <button
          type="button"
          onClick={p.onClose}
          className="btn-ghost !h-7 !w-7 shrink-0 !px-0"
          aria-label="Close details"
          title="Close (Esc)"
        >
          <X size={14} />
        </button>
      </header>

      {/* ── What it is, and why we say so ─────────────────────────────────── */}
      <Section title="What this is" icon={Server}>
        <div className="flex flex-wrap items-center gap-1.5">
          <Chip variant="neutral" mono>{n.role ?? n.kind}</Chip>
          <Chip variant="neutral">{p.layerLabel}</Chip>
          {n.ha_group ? <Chip variant="accent" mono>HA {n.ha_group}{n.ha_role ? ` · ${n.ha_role}` : ""}</Chip> : null}
          {(n.tags ?? []).map((t) => <Chip key={t} variant="warn" mono>{t}</Chip>)}
        </div>
        <div className="mt-2 space-y-1.5">
          {n.role_reason ? (
            <p className="break-words text-[11px] leading-snug text-text2">
              <span className="text-text3">role:</span> {n.role_reason}
              {n.role_source ? <span className="mono text-text3"> ({n.role_source})</span> : null}
            </p>
          ) : null}
          {n.layer_reason ? (
            <p className="break-words text-[11px] leading-snug text-text2">
              <span className="text-text3">lane:</span> {n.layer_reason}
            </p>
          ) : null}
        </div>

        <div className="mt-2 min-w-0">
          {n.vendor || n.model || n.os_version || n.serial || n.site || n.mgmt_ip ? (
            <>
              {n.vendor ? <KV k="Vendor" v={n.vendor} /> : null}
              {n.model ? <KV k="Model" v={n.model} /> : null}
              {n.os_version ? <KV k="OS" v={n.os_version} /> : null}
              {n.serial ? <KV k="Serial" v={n.serial} /> : null}
              {n.site ? <KV k="Site" v={n.site} /> : null}
              {n.mgmt_ip ? <KV k="Management address" v={n.mgmt_ip} /> : null}
            </>
          ) : (
            <NotCarried>
              No console described this node as hardware, so there is no make, model, OS or serial to show. It is on the
              canvas because {toolNames.length > 0
                ? `${toolNames.join(", ")} named it in ${toolNames.length === 1 ? "its" : "their"} policy or asset data`
                : "something in this snapshot named it"}
              , which places it by address rather than by cable.
            </NotCarried>
          )}
        </div>

        {p.unlinkedReason ? (
          <div className="mt-2 flex items-start gap-1.5 border border-sev-high-line bg-sev-high-bg px-2 py-1.5">
            <Cable size={12} className="mt-0.5 shrink-0 text-sev-high" />
            <span className="break-words text-[11px] leading-snug text-text2">{p.unlinkedReason}</span>
          </div>
        ) : null}
      </Section>

      {/* ── Addresses, VLAN, subnet ───────────────────────────────────────── */}
      <Section title="Addresses" icon={Radio}>
        {addresses.length > 0 ? (
          <div className="flex flex-wrap gap-1">
            {addresses.map((a) => <Addr key={a} value={a} />)}
          </div>
        ) : (
          <NotCarried>No source reported an address for this node.</NotCarried>
        )}

        {vlanRows.length > 0 ? (
          <div className="mt-2 space-y-1">
            {vlanRows.map(({ id, facts }) => (
              <div key={id} className="min-w-0 border border-border bg-sunk px-2 py-1.5">
                <div className="mono text-[11px] font-bold">
                  VLAN {id}{facts?.name ? ` · ${facts.name}` : ""}
                </div>
                {facts ? (
                  <>
                    <div className="mono mt-0.5 break-all text-[10.5px] text-text2">
                      subnet{facts.subnets.length === 1 ? "" : "s"}: {facts.subnets.length ? facts.subnets.join(", ") : "none declared"}
                    </div>
                    {facts.gateways.length ? (
                      <div className="mono break-all text-[10.5px] text-text3">gateway: {facts.gateways.join(", ")}</div>
                    ) : null}
                  </>
                ) : (
                  <div className="text-[10.5px] leading-snug text-text3">
                    An interface reported this tag and the VLAN register in this response does not declare it, so it has
                    no name and no subnet here. The tag is real; the description of it is missing.
                  </div>
                )}
              </div>
            ))}
          </div>
        ) : (
          <p className="mt-2 text-[11px] text-text3">No VLAN tag is reported for this node.</p>
        )}
      </Section>

      {/* ── Interfaces ────────────────────────────────────────────────────── */}
      <Section title={`Interfaces${ifaces.length ? ` (${ifaces.length})` : ""}`} icon={Cable}>
        {ifaces.length > 0 ? (
          <ul className="space-y-1">
            {ifaces.map((i) => <IfaceRow key={i.name} i={i} />)}
          </ul>
        ) : (
          <NotCarried>
            No onboarded console enumerates interfaces for this node. A policy aggregator names hosts; it does not
            describe their ports.
          </NotCarried>
        )}
      </Section>

      {/* ── Provenance ────────────────────────────────────────────────────── */}
      <Section title="Every console that saw it" icon={Activity}>
        {tools.length > 0 ? (
          <ul className="space-y-1">
            {tools.map((o, i) => (
              <li key={`${o.tool}:${i}`} className="flex min-w-0 flex-wrap items-center gap-1.5">
                <ToolBadge tool={o.tool} />
                <span className="mono text-[10.5px] text-text3">{o.tier}</span>
                {o.evidence ? <span className="mono text-[10.5px] text-text3">· {o.evidence}</span> : null}
                {o.raw_ref ? <span className="mono min-w-0 break-all text-[10.5px] text-text3">· {o.raw_ref}</span> : null}
              </li>
            ))}
          </ul>
        ) : (
          <NotCarried>Nothing in this snapshot is recorded as having observed this node.</NotCarried>
        )}
        {p.simulatedTools === null ? (
          <p className="mt-1.5 text-[10.5px] leading-snug text-text3">
            The source register could not be read, so this build cannot say which of these consoles are seeded exports
            rather than live connectors. Treat the provenance above as unverified rather than as live.
          </p>
        ) : simulated.length > 0 ? (
          <p className="mt-1.5 text-[10.5px] leading-snug text-info">
            {simulated.map((s) => s.tool).join(", ")} {simulated.length === 1 ? "is a" : "are"} seeded export
            {simulated.length === 1 ? "" : "s"}, not {simulated.length === 1 ? "a live connector" : "live connectors"}.
          </p>
        ) : null}
      </Section>

      {/* ── Conflicts ─────────────────────────────────────────────────────── */}
      {conflicts.length > 0 ? (
        <Section
          title={`Fields two consoles state differently (${conflicts.length})`}
          icon={AlertTriangle}
          note="Not an error: a stale entry, or a box replaced without the aggregator being told. It is what a review is for."
        >
          <ul className="space-y-1">
            {conflicts.map((c, i) => (
              <li key={`${c.entity}.${c.field}:${i}`} className="min-w-0 border border-sev-medium-line bg-sev-medium-bg px-2 py-1.5">
                <div className="mono break-all text-[11px] font-bold">{c.field}</div>
                <ul className="mt-0.5 space-y-0.5">
                  {c.claims.map((k, j) => (
                    <li key={j} className="mono break-all text-[10.5px] text-text2">
                      {k.tool} <span className="text-text3">({k.tier})</span> = {String(k.value)}
                    </li>
                  ))}
                </ul>
              </li>
            ))}
          </ul>
        </Section>
      ) : null}

      {/* ── Neighbours ────────────────────────────────────────────────────── */}
      {p.neighbours.length > 0 ? (
        <Section title={`Linked to (${p.neighbours.length})`} icon={Cable}>
          <ul className="flex flex-wrap gap-1">
            {p.neighbours.map((nb) => (
              <li key={nb.id}>
                <button
                  type="button"
                  onClick={() => p.onSelectNode(nb.id)}
                  className="mono border border-border bg-sunk px-1.5 py-0.5 text-[10.5px] text-text2 hover:border-accent hover:text-accent-fg"
                  title={`${nb.evidence} — open ${nb.name}`}
                >
                  {nb.name}
                </button>
              </li>
            ))}
          </ul>
        </Section>
      ) : null}

      {/* ── Findings ──────────────────────────────────────────────────────── */}
      <Section title={`Findings that name it (${named.length})`} icon={ShieldAlert}>
        {named.length > 0 ? (
          <ul className="space-y-1">
            {named.map((f) => (
              <li key={f.id}>
                <button
                  type="button"
                  onClick={() => p.onSelectFinding(f.id)}
                  className="row flex w-full items-start gap-2 border border-border bg-surface px-2 py-1.5 text-left hover:border-accent"
                >
                  <span className="min-w-0 flex-1">
                    <span className="block break-words text-[11.5px] font-bold">{f.title}</span>
                    <span className="mono block break-all text-[10px] text-text3">{f.type}</span>
                  </span>
                  <SeverityPill band={f.band} severity={f.severity} forced={f.forcedCritical} />
                </button>
              </li>
            ))}
          </ul>
        ) : mine.size > 0 ? (
          <NotCarried>
            The backend joins {mine.size} finding{mine.size === 1 ? "" : "s"} to this node, and none of them is in the
            set this screen loaded. They are on the Risk To-Do screen.
          </NotCarried>
        ) : (
          <NotCarried>No finding in this snapshot names this node.</NotCarried>
        )}
      </Section>

      {/* ── Down to the rule ──────────────────────────────────────────────── */}
      <Section
        title="Policies that touch it"
        icon={Route}
        note={address ? "Every rule /api/ip finds for this node's address, grouped the way that endpoint groups them." : undefined}
      >
        {!address ? (
          <NotCarried>
            This node has no address in the payload, so there is nothing to look up. Rules are matched by address; a
            node without one cannot be placed in anybody&rsquo;s policy.
          </NotCarried>
        ) : ipErr ? (
          <ErrorState resource={`the rules that touch ${address}`} error={ipErr} onRetry={lookup} />
        ) : ipLoading || !ip ? (
          <div className="flex items-center gap-2 text-[12px] text-text2">
            <Spinner label={`Reading every rule that reaches ${address}…`} />
          </div>
        ) : (
          <>
            <div className="mb-2 flex flex-wrap items-center gap-1.5">
              <Chip variant="neutral" mono>{ip.address}</Chip>
              <Chip variant="neutral" mono>mode {ip.mode}</Chip>
              <span className="mono text-[10.5px] text-text3">{matchTotal} rule{matchTotal === 1 ? "" : "s"}</span>
            </div>
            {/* The endpoint normalises a host address to the block it sits in,
                so the answer is sometimes about a wider thing than the question.
                Said out loud, because "10 rules" for 10.254.0.8/30 is not the
                same claim as "10 rules" for 10.254.0.10/30. */}
            {ip.address !== address ? (
              <p className="mb-2 break-all text-[10.5px] leading-snug text-text3">
                Asked for <span className="mono">{address}</span>; the endpoint answered for{" "}
                <span className="mono">{ip.address}</span>, the block that address sits in.
              </p>
            ) : null}

            {matchTotal === 0 ? (
              <NotCarried>
                No rule in this snapshot names this address or a block containing it. That is what the policy sets say,
                not a statement that nothing can reach it.
              </NotCarried>
            ) : (
              (["exact", "covering", "contained"] as const).map((rel) => {
                const rows = matches?.[rel] ?? [];
                if (rows.length === 0) return null;
                return (
                  <div key={rel} className="mb-2.5 min-w-0 last:mb-0">
                    <div className="text-[11px] font-bold text-text2">
                      {RELATION_COPY[rel].title} <span className="mono text-text3">({rows.length})</span>
                    </div>
                    <p className="mb-1 text-[10.5px] leading-snug text-text3">{RELATION_COPY[rel].note}</p>
                    <ul className="space-y-1">
                      {rows.map((m, i) => <MatchRow key={`${m.rule_ref}:${i}`} m={m} snapshot={p.snapshot} />)}
                    </ul>
                  </div>
                );
              })
            )}

            {/* The reachability claim, with its caveat beside it rather than in
                a doc nobody opens. */}
            <div className="mt-2 border border-border bg-sunk px-2 py-1.5">
              <div className="text-[11px] font-bold text-text2">
                {ip.effective.reachable_from_internet == null
                  ? "Reachable from the internet: unknown"
                  : ip.effective.reachable_from_internet
                    ? "An allow path from the internet exists"
                    : "No allow path from the internet was found"}
              </div>
              <p className="mt-0.5 break-words text-[10.5px] leading-snug text-text3">{ip.effective.caveat}</p>
            </div>
          </>
        )}
      </Section>

      {/* ── Lose this device ──────────────────────────────────────────────── */}
      <Section
        title="Lose this device"
        icon={Zap}
        note="What the estate loses if this node fails — a graph cut the engine performed over the whole adjacency, never recomputed here."
      >
        {p.blastError ? (
          <InlineError resource="the resilience analysis" error={p.blastError} />
        ) : !p.blastRead ? (
          <div className="flex items-center gap-2 text-[12px] text-text2">
            <Spinner label="Reading the resilience analysis…" />
          </div>
        ) : !p.blast ? (
          <NotCarried>
            The resilience analyzer measured no radius for this node. It cuts the adjacency graph — the cabled estate —
            and this node is not a vertex in it, so losing it has no measured effect on which devices can still reach a
            circuit. That is a statement about the adjacency, not a claim that nothing depends on this node.
          </NotCarried>
        ) : (
          <>
            <div className="border border-sev-critical-line bg-sev-critical-bg px-2.5 py-2">
              <div className="mono text-[17px] font-bold leading-none tabular-nums text-sev-critical">
                {p.blast.paths_lost} of {p.blast.paths_before}
              </div>
              <div className="mt-1 text-[11.5px] leading-snug text-text2">
                device-to-circuit paths are lost when this node fails
                {p.blast.paths_lost === 0 ? " — none, on this adjacency" : ""}.
              </div>
            </div>
            <div className="mt-2">
              <KV k="Share of reachability destroyed" v={`${Math.round(p.blast.fraction * 1000) / 10}%`} />
              <KV
                k="Circuits stranded"
                v={p.blast.circuits_stranded.length ? p.blast.circuits_stranded.join(", ") : "none"}
                mono={p.blast.circuits_stranded.length > 0}
              />
              <KV k="Devices isolated (no path at all)" v={String(p.blast.devices_isolated.length)} />
              <KV k="Devices degraded (fewer paths)" v={String(p.blast.devices_degraded)} />
              <KV k="Components after the cut" v={String(p.blast.components_after)} />
            </div>
            {p.blastBasis ? <p className="mt-1.5 text-[10.5px] leading-snug text-text3">{p.blastBasis}</p> : null}
            <div className="mt-2 flex flex-wrap gap-1.5">
              <button
                type="button"
                onClick={p.onSimulateLoss}
                className={cn(p.simulating ? "btn-ghost" : "btn-primary", "text-[11.5px]")}
                title="Play the failure on the canvas: this node goes critical and everything that loses its path fades."
              >
                <Zap size={12} /> {p.simulating ? "Replay the failure" : "Play the failure"}
              </button>
              {p.simulating ? (
                <button type="button" onClick={p.onStopSimulation} className="btn-ghost text-[11.5px]">
                  Restore the estate
                </button>
              ) : null}
            </div>
            {p.blast.paths_lost === 0 ? (
              <p className="mt-1.5 text-[10.5px] leading-snug text-text3">
                Nothing fades when this one is played: every device that reaches a circuit through it has another way.
                The picture staying still IS the result.
              </p>
            ) : null}
          </>
        )}
      </Section>
    </aside>
  );
}
