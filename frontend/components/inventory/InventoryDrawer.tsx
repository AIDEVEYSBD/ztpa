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
import { GitMerge, Link2, TriangleAlert, X } from "lucide-react";
import type { InventoryItem, SourceCard } from "@/lib/types";
import { toolColour } from "@/lib/toolColour";
import { NetIcon } from "@/components/net/icons";
import { Overlay, Button } from "@/components/ui";
import { claimValue, DrawerSection, Field, tierMeaning, tierShort, Unreported, Value } from "./bits";
import type { DrawerFocus } from "./columns";
import { matchKeyMeaning, type RowIdentity } from "./identity";
import { AddressInsight } from "./AddressInsight";

export function InventoryDrawer({ item, focus, cards, cardsUnknown, identity, identityUnknown, snapshot, onClose }: {
  item?: InventoryItem;
  focus: DrawerFocus;
  cards?: Record<string, SourceCard>;
  /** True when the source register could not be read — so "live vs seeded"
   *  is UNKNOWN here rather than absent. */
  cardsUnknown?: boolean;
  /** The asset layer's view of this row, when it describes it. */
  identity?: RowIdentity;
  /** True when the asset read FAILED — so "was this correlated?" is unknown
   *  here rather than no. */
  identityUnknown?: boolean;
  snapshot?: string;
  onClose: () => void;
}) {
  const conflictsRef = useRef<HTMLDivElement>(null);
  const identityRef = useRef<HTMLDivElement>(null);
  const bodyRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!item) return;
    if (focus === "conflicts" && conflictsRef.current) conflictsRef.current.scrollIntoView({ block: "start" });
    else if (focus === "identity" && identityRef.current) identityRef.current.scrollIntoView({ block: "start" });
    else if (bodyRef.current) bodyRef.current.scrollTop = 0;
  }, [item, focus]);

  return (
    <Overlay open={!!item} onClose={onClose} placement="right" widthClass="max-w-[min(96vw,680px)]" label="Entity detail">
      {item ? (
        <>
          <header className="shrink-0 border-b border-line px-4 py-3">
            <div className="flex items-start gap-3">
              <span className="mt-0.5 shrink-0 text-dim">
                <NetIcon kind={item.kind} size={20} />
              </span>
              <div className="min-w-0 flex-1">
                <h2 className="text-[14px] leading-tight font-semibold tracking-[-0.005em] break-all">{item.name}</h2>
                <div className="mt-0.5 font-mono text-[10.5px] break-all text-faint">{item.key}</div>
              </div>
              <Button size="sm" variant="solid" tone="err" className="shrink-0" onClick={onClose} aria-label="Close">
                <X size={13} /> Close
              </Button>
            </div>
          </header>

          <div ref={bodyRef} className="zt-scroll min-h-0 flex-1 space-y-4 overflow-y-auto p-4">
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

            <div ref={identityRef}>
              <IdentitySection item={item} identity={identity} unknown={!!identityUnknown} />
            </div>

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

            <AddressInsight item={item} snapshot={snapshot} />

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
      <span className="text-dim">
        unknown — no source declared the {noun} and the engine could not derive one
      </span>
    );
  }
  return (
    <span className="block">
      <span className="text-run">derived by the engine — no source declared it</span>
      <span className="mt-1 block border-l-2 border-line-strong pl-3 text-[12.5px] leading-[1.55] text-dim">
        {reason?.trim() || "No reason was supplied with this derivation."}
      </span>
    </span>
  );
}

/**
 * IDENTITY — what the asset layer decided this row IS.
 *
 * Three answers, three renders, and the first is the one that used to be
 * missing: when the asset read fails, "was this correlated across tools?" is
 * UNKNOWN. A silent absence there reads as "no", which is a claim about the
 * estate made out of a failed fetch.
 */
function IdentitySection({ item, identity, unknown }: {
  item: InventoryItem;
  identity?: RowIdentity;
  unknown: boolean;
}) {
  if (unknown) {
    return (
      <DrawerSection title="Identity">
        <p className="text-[12px] leading-relaxed text-text2">
          The asset layer could not be read, so whether this row was correlated with another console&apos;s record of the
          same thing is <span className="font-bold text-text">unknown</span>. It is not being reported as uncorrelated —
          the failure is stated on the inventory panel above.
        </p>
      </DrawerSection>
    );
  }

  if (!identity) {
    return (
      <DrawerSection title="Identity">
        <p className="text-[12px] leading-relaxed text-text2">
          The asset layer does not describe <span className="mono">{item.key}</span>. A VLAN, a subnet or a circuit is
          not an identity the engine correlates, so there is nothing here to merge — this is not applicable rather than
          &ldquo;no match found&rdquo;.
        </p>
      </DrawerSection>
    );
  }

  const { asset, correlations, aliases, tools, suggestions } = identity;

  return (
    <DrawerSection
      title="Identity"
      note="One identity per asset; an IP is an attribute of it, not its key. A correlation here means two consoles were proven to be describing the same thing."
    >
      <Field label="Asset key">
        <span className="mono break-all text-[12px]">{asset?.asset_key ?? item.key}</span>
      </Field>
      <Field label="Also known as">
        {aliases.length ? (
          <span className="flex flex-wrap gap-1">
            {aliases.map((a) => <span key={a} className="chip mono text-[10.5px]">{a}</span>)}
          </span>
        ) : (
          <span className="text-text2">No other name collapsed into this identity.</span>
        )}
      </Field>
      <Field label="Seen by">
        {tools.length ? (
          <span className="flex flex-wrap items-center gap-2">
            {tools.map((t) => (
              <span key={t} className="inline-flex items-center gap-1.5">
                <span aria-hidden className="h-2 w-2 shrink-0" style={{ background: toolColour(t) }} />
                <span className="mono text-[11.5px]">{t}</span>
              </span>
            ))}
          </span>
        ) : (
          <Unreported what="a console behind this identity" />
        )}
      </Field>

      <div className="mt-2">
        <div className="mb-1.5 flex items-center gap-1.5 text-[11px] font-medium tracking-[0.06em] text-faint uppercase">
          <Link2 size={11} /> Settled correlations ({correlations.length})
        </div>
        {correlations.length ? (
          <ul className="space-y-1.5">
            {correlations.map((c, i) => (
              <li key={`${c.match_key}-${i}`} className="rounded-md border border-line bg-canvas px-3 py-2">
                <div className="flex flex-wrap items-center gap-2">
                  <span className="font-mono text-[11.5px] font-medium text-fg" title={matchKeyMeaning(c.match_key)}>
                    {c.match_key}
                  </span>
                  <span className="tnum font-mono text-[10.5px] text-dim">
                    {Math.round(c.confidence * 100)}% confidence
                  </span>
                </div>
                <p className="mt-0.5 text-[11.5px] leading-[1.55] text-dim">{matchKeyMeaning(c.match_key)}</p>
                <div className="mt-1 font-mono text-[10.5px] break-all text-faint">
                  evidence: {claimValue(c.evidence)}
                </div>
              </li>
            ))}
          </ul>
        ) : (
          <p className="text-[12px] text-text2">
            This row is in the asset layer and carries no cross-tool correlation: no other console&apos;s record was
            proven to be the same thing.
          </p>
        )}
      </div>

      {suggestions.length ? (
        <div className="mt-2">
          <div className="mb-1 flex items-center gap-1.5 text-[10px] font-bold uppercase tracking-[0.1em] text-sev-medium">
            <GitMerge size={11} /> Unconfirmed duplicate proposals ({suggestions.length})
          </div>
          <ul className="space-y-1.5">
            {suggestions.map((s) => (
              <li key={`${s.a}~${s.b}`} className="border border-sev-medium-line bg-sev-medium-bg px-2.5 py-1.5">
                <div className="flex flex-wrap items-center gap-1.5 text-[11.5px]">
                  <span className="mono break-all font-bold">{s.a}</span>
                  <span className="text-text3">~</span>
                  <span className="mono break-all font-bold">{s.b}</span>
                  <span className="mono ml-auto text-[10.5px] tabular-nums text-sev-medium">
                    {Math.round(s.confidence * 100)}%
                  </span>
                </div>
                <p className="mt-1 text-[10.5px] leading-relaxed text-text2">{s.reason}</p>
              </li>
            ))}
          </ul>
          <p className="mt-1 text-[10.5px] text-text3">
            Nothing has been merged. The engine never merges on its own — confirm or ignore these in{" "}
            <span className="font-bold text-text2">Identity &amp; merges</span>, under the table.
          </p>
        </div>
      ) : null}
    </DrawerSection>
  );
}

export default InventoryDrawer;
