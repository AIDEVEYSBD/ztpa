"use client";

/**
 * The full record for one entity.
 *
 * The table is a summary; this is the evidence behind it. Everything the API
 * sent is here — every field, every console that saw the row with its tier and
 * its raw record reference, every field two consoles disagree about, and the
 * layer the engine placed it at together with the argument for that placement.
 * The product should always be able to show its working, and this is where it
 * does.
 */

import { useEffect, useRef } from "react";
import { TriangleAlert, X } from "lucide-react";
import type { InventoryItem, SourceCard } from "@/lib/types";
import { toolColour } from "@/lib/toolColour";
import { NetIcon } from "@/components/net/icons";
import { Overlay } from "@/components/ui";
import { claimValue, DrawerSection, Field, tierMeaning, tierShort, Unreported, Value } from "./bits";
import type { DrawerFocus } from "./InventoryTable";

export function InventoryDrawer({ item, focus, cards, cardsUnknown, onClose }: {
  item?: InventoryItem;
  focus: DrawerFocus;
  cards?: Record<string, SourceCard>;
  /** True when the source register could not be read — so "live vs seeded"
   *  is UNKNOWN here rather than absent. */
  cardsUnknown?: boolean;
  onClose: () => void;
}) {
  const conflictsRef = useRef<HTMLDivElement>(null);
  const bodyRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!item) return;
    if (focus === "conflicts" && conflictsRef.current) conflictsRef.current.scrollIntoView({ block: "start" });
    else if (bodyRef.current) bodyRef.current.scrollTop = 0;
  }, [item, focus]);

  return (
    <Overlay open={!!item} onClose={onClose} placement="right" widthClass="max-w-[min(96vw,680px)]" label="Entity detail">
      {item ? (
        <>
          <header className="shrink-0 border-b border-border px-4 py-3">
            <div className="flex items-start gap-3">
              <span className="mt-0.5 shrink-0 text-accent-fg">
                <NetIcon kind={item.kind} size={20} />
              </span>
              <div className="min-w-0 flex-1">
                <h2 className="break-all text-[15px] font-bold leading-tight">{item.name}</h2>
                <div className="mono mt-0.5 break-all text-[11px] text-text3">{item.key}</div>
              </div>
              <button type="button" onClick={onClose} className="btn-ghost !h-7 !px-2 shrink-0" aria-label="Close">
                <X size={13} />
              </button>
            </div>
          </header>

          <div ref={bodyRef} className="zt-scroll min-h-0 flex-1 space-y-3 overflow-y-auto p-4">
            <DrawerSection title="Classification">
              <Field label="Kind"><span className="mono text-[12px]">{item.kind}</span></Field>
              <Field label="Role"><Value value={item.role} what="a role" mono /></Field>
              <Field label="Role source">
                <RoleSource source={item.role_source} reason={item.role_reason} />
              </Field>
              <Field label="Layer"><Value value={item.layer} what="a topology layer" mono /></Field>
              <Field label="Layer source">
                <RoleSource source={item.layer_source} reason={item.layer_reason} noun="layer" />
              </Field>
              <Field label="Tags">
                {item.tags.length ? (
                  <span className="flex flex-wrap gap-1">
                    {item.tags.map((t) => <span key={t} className="chip mono text-[10.5px]">{t}</span>)}
                  </span>
                ) : (
                  <Unreported what="a tag" />
                )}
              </Field>
            </DrawerSection>

            <DrawerSection title="Hardware">
              <Field label="Vendor"><Value value={item.vendor} what="a vendor" /></Field>
              <Field label="Model"><Value value={item.model} what="a model" mono /></Field>
              <Field label="OS version"><Value value={item.os_version} what="an OS version" mono /></Field>
            </DrawerSection>

            <DrawerSection title="Placement">
              <Field label="VLAN">
                {item.vlan_id == null && !item.vlan_name ? (
                  <Unreported what="a VLAN" />
                ) : (
                  <span>
                    <span className="mono tabular-nums">{item.vlan_id ?? "?"}</span>
                    {item.vlan_name ? <span className="text-text2"> · {item.vlan_name}</span> : null}
                  </span>
                )}
              </Field>
              <Field label="Subnet"><Value value={item.subnet} what="a subnet" mono /></Field>
              <Field label="Zone"><Value value={item.zone} what="a zone" /></Field>
            </DrawerSection>

            <DrawerSection
              title={`Addresses (${item.addresses.length})`}
              note="Every address on this entity, in full — the table shows the first two, and the one that matters is routinely not one of them."
            >
              {item.addresses.length ? (
                <ul className="mono space-y-0.5 text-[12px] tabular-nums">
                  {item.addresses.map((a, i) => <li key={`${a}-${i}`} className="break-all">{a}</li>)}
                </ul>
              ) : (
                <Unreported what="an address" />
              )}
            </DrawerSection>

            <DrawerSection
              title={`Where we found it (${item.observed_by.length})`}
              note="Every console that reported this row, not just the one that won. The tier says where on the collection ladder the claim came from."
            >
              {item.observed_by.length ? (
                <ul className="space-y-1.5">
                  {item.observed_by.map((o, i) => {
                    const card = cards?.[o.tool];
                    return (
                      <li key={`${o.tool}-${o.raw_ref ?? i}`} className="border border-border bg-sunk px-2.5 py-1.5">
                        <div className="flex flex-wrap items-center gap-2">
                          <span aria-hidden className="h-2.5 w-2.5 shrink-0" style={{ background: toolColour(o.tool) }} />
                          <span className="mono text-[12px] font-bold">{o.tool}</span>
                          <span className="chip mono !h-[18px] text-[9.5px]" title={tierMeaning(o.tier)}>{tierShort(o.tier)}</span>
                          {card ? (
                            card.simulated ? (
                              <span className="inline-flex h-[18px] items-center border border-sev-medium-line bg-sev-medium-bg px-1.5 text-[9.5px] font-bold uppercase tracking-[0.06em] text-sev-medium">
                                seeded export
                              </span>
                            ) : (
                              <span className="inline-flex h-[18px] items-center border border-ok-line bg-ok-bg px-1.5 text-[9.5px] font-bold uppercase tracking-[0.06em] text-ok">
                                live connector
                              </span>
                            )
                          ) : (
                            <span
                              className="inline-flex h-[18px] cursor-help items-center border border-border bg-surface2 px-1.5 text-[9.5px] font-bold uppercase tracking-[0.06em] text-text3"
                              title={cardsUnknown
                                ? "The source register could not be read, so whether this source is a live connector or a seeded export is unknown — it is not being reported as live."
                                : "This tool is not in the source register for this snapshot."}
                            >
                              origin unknown
                            </span>
                          )}
                          {o.evidence ? <span className="text-[10.5px] text-text3">evidence: {o.evidence}</span> : null}
                        </div>
                        <div className="mono mt-1 break-all text-[10.5px] text-text3">
                          {o.raw_ref ? `raw record: ${o.raw_ref}` : "no raw record reference on this observation"}
                        </div>
                      </li>
                    );
                  })}
                </ul>
              ) : (
                <p className="text-[12px] text-text2">
                  This entity carries no observation at all. It is in the inventory without a console behind it, which is a
                  gap in the record rather than a property of the estate.
                </p>
              )}
            </DrawerSection>

            <div ref={conflictsRef}>
              <DrawerSection
                title={`Conflicts (${item.conflicts.length})`}
                note="Two consoles stated the same field differently. That is not an error: it is a fact about the estate's own record-keeping — a stale entry, or a box replaced without the aggregator being told — and it is what a review is for."
              >
                {item.conflicts.length ? (
                  <ul className="space-y-2">
                    {item.conflicts.map((c, i) => (
                      <li key={`${c.entity}-${c.field}-${i}`} className="border border-sev-high-line bg-sev-high-bg px-2.5 py-2">
                        <div className="flex items-center gap-1.5 text-[11.5px] font-bold text-sev-high">
                          <TriangleAlert size={12} />
                          <span className="mono">{c.field}</span>
                          <span className="font-normal text-text2">on</span>
                          <span className="mono break-all font-normal text-text2">{c.entity}</span>
                        </div>
                        <table className="mt-1.5 w-full border-collapse text-[11.5px]">
                          <tbody>
                            {c.claims.map((cl, k) => (
                              <tr key={`${cl.tool}-${k}`} className="border-t border-sev-high-line">
                                <td className="py-1 pr-2 align-top">
                                  <span className="inline-flex items-center gap-1.5">
                                    <span aria-hidden className="h-2 w-2 shrink-0" style={{ background: toolColour(cl.tool) }} />
                                    <span className="mono font-bold">{cl.tool}</span>
                                  </span>
                                </td>
                                <td className="py-1 pr-2 align-top">
                                  <span className="chip mono !h-[17px] text-[9.5px]" title={tierMeaning(cl.tier)}>{tierShort(cl.tier)}</span>
                                </td>
                                <td className="mono break-all py-1 align-top">{claimValue(cl.value)}</td>
                              </tr>
                            ))}
                          </tbody>
                        </table>
                      </li>
                    ))}
                  </ul>
                ) : (
                  <p className="text-[12px] text-text2">No source disagreed with another about this entity.</p>
                )}
              </DrawerSection>
            </div>

            <DrawerSection
              title={`Findings (${item.finding_ids.length})`}
              note="The findings this entity is named in, by id. Open the Risk To-Do to read them."
            >
              {item.finding_ids.length ? (
                <span className="flex flex-wrap gap-1">
                  {item.finding_ids.map((f) => <span key={f} className="chip mono text-[10.5px]">{f}</span>)}
                </span>
              ) : (
                <p className="text-[12px] text-text2">This entity is named in no finding in this snapshot.</p>
              )}
            </DrawerSection>
          </div>
        </>
      ) : null}
    </Overlay>
  );
}

/** "Declared" and "derived" are different claims and are rendered as such: a
 *  derived value carries the engine's argument for it, verbatim. */
function RoleSource({ source, reason, noun = "role" }: { source?: "declared" | "derived" | "unknown"; reason?: string; noun?: string }) {
  if (!source) return <Unreported what={`how the ${noun} was decided`} />;
  if (source === "declared") {
    return <span className="text-ok">declared by a source, verbatim</span>;
  }
  if (source === "unknown") {
    return (
      <span className="text-text2">
        unknown — no source declared the {noun} and the engine could not derive one
      </span>
    );
  }
  return (
    <span className="block">
      <span className="text-sev-medium">derived by the engine — no source declared it</span>
      <span className="mt-1 block border-l-2 border-accent pl-2 text-[12px] leading-relaxed text-text2">
        {reason?.trim() || "No reason was supplied with this derivation."}
      </span>
    </span>
  );
}

export default InventoryDrawer;
