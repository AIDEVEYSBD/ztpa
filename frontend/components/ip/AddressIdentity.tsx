"use client";

/**
 * SECTION 1 — WHAT THIS ADDRESS IS.
 *
 * The identity block answers "whose address is this" before anything answers
 * "what may reach it", because a rule about an address nobody owns is a very
 * different finding from the same rule about the payroll database.
 *
 * THE INTERESTING ANSWER IS THE EMPTY ONE. An address that no asset, device,
 * interface, VLAN or subnet in the snapshot describes is not a blank section and
 * not a bug — it is a real result, and often the one worth acting on, because
 * the policy groups underneath may still be full of rules that name it. So the
 * empty case gets MORE type on screen than the populated one, not less.
 */

import { Boxes, Cable, Layers, ScanSearch } from "lucide-react";
import type { IpLookupResponse } from "@/lib/types";
import { Eyebrow, Tag, cn } from "@/components/ui";
import { NetIcon } from "@/components/net/icons";
import type { SourceIndex } from "./data";
import { Field, MonoChip, ObservedBy, SourceToolBadge, Unknown } from "./atoms";
import type { ParsedAddress } from "./addr";

/** Does anything in the payload describe this address at all? */
export function describesAddress(d: IpLookupResponse): boolean {
  return (
    d.assets.length > 0 ||
    d.devices.length > 0 ||
    d.interfaces.length > 0 ||
    !!d.vlan ||
    !!d.subnet
  );
}

function SubLabel({ icon: Icon, children }: { icon: typeof Boxes; children: React.ReactNode }) {
  return (
    <div className="label mb-2 flex items-center gap-1.5 !text-[9.5px]">
      <Icon size={11} />
      {children}
    </div>
  );
}

export function AddressIdentity({
  data,
  parsed,
  sources,
  ruleCount,
}: {
  data: IpLookupResponse;
  parsed: ParsedAddress | null;
  sources?: SourceIndex;
  /** Rules that reached this address, so the "nothing holds it" case can point
   *  at the contradiction rather than leaving the reader to spot it. */
  ruleCount: number;
}) {
  const described = describesAddress(data);
  const tags = Array.from(new Set(data.assets.flatMap((a) => a.tags)));

  return (
    <section className="space-y-3">
      <Eyebrow>What this address is</Eyebrow>

      {!described ? (
        <div className="border border-sev-medium-line bg-sev-medium-bg p-3.5" role="status">
          <div className="flex items-start gap-2.5">
            <ScanSearch size={16} className="mt-0.5 shrink-0 text-sev-medium" />
            <div className="min-w-0">
              <div className="text-[13px] font-bold text-sev-medium">
                No source in this snapshot describes {data.address}
              </div>
              <p className="mt-1 text-[12px] leading-relaxed text-text2">
                Nothing holds it: no asset claims it, no interface carries it, and it falls in no VLAN or
                subnet any console declared. That is an answer, not an empty screen — this address is
                outside the estate we have a record of.
              </p>
              {ruleCount > 0 && (
                <p className="mt-1.5 text-[12px] leading-relaxed text-text2">
                  <b className="text-sev-medium">
                    {ruleCount} {ruleCount === 1 ? "rule reaches" : "rules reach"} it anyway.
                  </b>{" "}
                  Policy refers to an address inventory cannot account for — either the estate is wider
                  than the sources describe, or the rules are.
                </p>
              )}
            </div>
          </div>
        </div>
      ) : null}

      <div className="sunk grid gap-x-5 gap-y-3 p-3.5 sm:grid-cols-2 lg:grid-cols-4">
        <Field label="Subnet">
          {data.subnet ? (
            <span className="mono break-all">{data.subnet}</span>
          ) : (
            <Unknown reason="no source placed this address in a declared subnet" />
          )}
        </Field>
        <Field label="VLAN">
          {data.vlan ? (
            <span className="mono">
              {data.vlan.vlan_id}
              {data.vlan.name ? <span className="text-text2"> · {data.vlan.name}</span> : null}
            </span>
          ) : (
            <Unknown reason="no source placed this address in a declared VLAN" />
          )}
        </Field>
        <Field label="Zone">
          {/* Zone is an inventory attribute and the address lookup does not carry
              it. Rendering "internal" from anywhere else here would be this
              screen inventing a security classification. */}
          <Unknown reason="the address lookup does not carry a zone. Zone is an inventory attribute — read it on the Inventory row for the asset holding this address, where its source is visible." />
        </Field>
        <Field label="Tags">
          {tags.length > 0 ? (
            <span className="inline-flex flex-wrap gap-1">
              {tags.map((t) => (
                <Tag key={t}>{t}</Tag>
              ))}
            </span>
          ) : data.assets.length > 0 ? (
            <span className="text-[11.5px] text-text3">no tags on the holding asset(s)</span>
          ) : (
            <Unknown reason="tags come from the asset holding this address, and no asset claims it" />
          )}
        </Field>
      </div>

      {data.assets.length > 0 && (
        <div>
          <SubLabel icon={Boxes}>Asset{data.assets.length === 1 ? "" : "s"} holding it ({data.assets.length})</SubLabel>
          <div className="divide-y divide-hair border border-border">
            {data.assets.map((a) => (
              <div key={a.asset_key} className="flex flex-wrap items-center gap-x-3 gap-y-1.5 px-3 py-2">
                <span className="inline-flex min-w-0 items-center gap-2">
                  <NetIcon kind={a.kind} size={15} className="shrink-0 text-text3" />
                  <span className="mono break-all text-[12px] font-bold">{a.asset_key}</span>
                </span>
                <MonoChip>{a.kind}</MonoChip>
                {a.tags.map((t) => (
                  <Tag key={t}>{t}</Tag>
                ))}
                <span className="ml-auto inline-flex flex-wrap items-center gap-1">
                  {a.source_tools.length > 0 ? (
                    a.source_tools.map((t) => <SourceToolBadge key={t} tool={t} sources={sources} showTier />)
                  ) : (
                    <Unknown reason="this asset lists no source tool, so which console described it is not stated" />
                  )}
                </span>
              </div>
            ))}
          </div>
        </div>
      )}

      {data.devices.length > 0 && (
        <div>
          <SubLabel icon={Layers}>Device{data.devices.length === 1 ? "" : "s"} carrying it ({data.devices.length})</SubLabel>
          <div className="divide-y divide-hair border border-border">
            {data.devices.map((d) => (
              <div key={d.key} className="space-y-1.5 px-3 py-2">
                <div className="flex flex-wrap items-center gap-x-3 gap-y-1.5">
                  <span className="inline-flex min-w-0 items-center gap-2">
                    <NetIcon kind={d.role ?? d.kind} size={15} className="shrink-0 text-text3" />
                    <span className="mono break-all text-[12px] font-bold">{d.name}</span>
                  </span>
                  <MonoChip>{d.role ?? d.kind}</MonoChip>
                  {(d.vendor || d.model) && (
                    <span className="text-[11.5px] text-text2">
                      {[d.vendor, d.model].filter(Boolean).join(" ")}
                    </span>
                  )}
                  {d.ha_group && (
                    <MonoChip tone="info" title="High-availability group membership as the source reported it.">
                      HA {d.ha_group}
                      {d.ha_role ? ` · ${d.ha_role}` : ""}
                    </MonoChip>
                  )}
                </div>
                {d.addresses.length > 0 && (
                  <div className="mono break-all text-[11px] text-text2">{d.addresses.join("  ")}</div>
                )}
                <div className="flex flex-wrap items-center gap-1.5">
                  <ObservedBy observations={d.observed_by} sources={sources} />
                </div>
                {d.unlinked_reason && (
                  <div className="border border-dashed border-sev-medium-line bg-sev-medium-bg px-2 py-1 text-[11px] text-sev-medium">
                    Not linked to anything on the topology: {d.unlinked_reason}
                    {d.would_be_filled_by ? (
                      <>
                        {" "}
                        <span className="text-text2">Would be filled by {d.would_be_filled_by}.</span>
                      </>
                    ) : null}
                  </div>
                )}
              </div>
            ))}
          </div>
        </div>
      )}

      {data.interfaces.length > 0 && (
        <div>
          <SubLabel icon={Cable}>Interface{data.interfaces.length === 1 ? "" : "s"} configured with it ({data.interfaces.length})</SubLabel>
          <div className="divide-y divide-hair border border-border">
            {data.interfaces.map((i) => (
              <div key={i.interface_key} className="flex flex-wrap items-center gap-x-3 gap-y-1 px-3 py-2">
                <span className="mono text-[12px] font-bold">{i.name}</span>
                <span className="mono text-[11px] text-text2">on {i.device_key}</span>
                {i.vlan_id != null && <MonoChip tone="info">vlan {i.vlan_id}</MonoChip>}
                <span
                  className={cn(
                    "mono ml-auto break-all text-[11px]",
                    parsed && i.addresses.includes(parsed.value) ? "text-accent-fg" : "text-text3",
                  )}
                >
                  {i.addresses.join("  ") || "no addresses listed"}
                </span>
              </div>
            ))}
          </div>
        </div>
      )}
    </section>
  );
}
