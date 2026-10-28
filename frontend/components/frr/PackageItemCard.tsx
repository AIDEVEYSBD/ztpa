"use client";

import { useState } from "react";
import { ChevronDown, ChevronRight, HelpCircle, Sparkles } from "lucide-react";
import type { PackageItem } from "@/lib/frrTypes";
import { Chip, SeverityPill, cn } from "../ui";
import { AuthorChip, CodeBlock, EvidenceList, authorLabel, checkLabel, impactMeta, proposalLabel, when } from "./bits";
import { ItemContext } from "./ItemContext";
import { OwnerDecisionForm } from "./OwnerDecisionForm";

const DECISION_VARIANT = { accept: "ok", modify: "info", reject: "danger" } as const;

function OwnerRecord({ item }: { item: PackageItem }) {
  if (!item.owner_decision) return <Chip variant="neutral">awaiting owner decision</Chip>;
  return (
    <span className="flex flex-wrap items-center gap-1.5 text-[11px] text-faint">
      <Chip variant={DECISION_VARIANT[item.owner_decision]} dot>owner: {item.owner_decision}</Chip>
      {item.decided_by && <span>by {item.decided_by}</span>}
      {item.decided_at && <span>· {when(item.decided_at)}</span>}
    </span>
  );
}

export function PackageItemCard({ pkgId, item, canDecide, decideNote, onDecided }: {
  pkgId: string;
  item: PackageItem;
  /** Package is draft and the caller holds network_owner for this layer. */
  canDecide: boolean;
  /** Why the decision controls are absent, when they are. */
  decideNote?: string;
  onDecided: (item: PackageItem) => void;
}) {
  const [showEvidence, setShowEvidence] = useState(false);
  const [deciding, setDeciding] = useState(false);
  const impact = impactMeta(item.availability_impact);
  const n = item.narrative;
  const author = authorLabel(n?.by);

  return (
    <article className={cn("relative overflow-hidden rounded-lg border bg-surface elev-1", impact.loud ? "border-err-line" : "border-line")}>
      {impact.loud && <span aria-hidden className="absolute inset-y-0 left-0 w-[3px] bg-err" />}
      <header className="flex flex-wrap items-center gap-2 border-b border-line bg-raise/40 px-4 py-2.5">
        <SeverityPill band={item.band} />
        <span className="text-[13px] font-semibold">
          {item.layer} rule {item.rule_number ?? "?"}{item.rule_name ? ` · ${item.rule_name}` : ""}
        </span>
        <Chip variant="neutral">{checkLabel(item.check_kind)}</Chip>
        <span className="grow" />
        <Chip variant={impact.variant} dot className={impact.loud ? "font-semibold" : undefined}>{impact.label}</Chip>
      </header>

      <div className="space-y-3 px-4 py-3">
        <div className="flex flex-wrap items-baseline gap-2">
          <span className="text-[11px] text-faint">Proposal</span>
          <span className="text-[13px] font-semibold">{proposalLabel(item.proposal)}</span>
          {(item.requires_owner_input?.length ?? 0) > 0 && <Chip variant="warn">needs owner input</Chip>}
        </div>
        <p className="text-[12.5px] leading-[1.55] text-fg">{item.rationale}</p>

        {n && (
          <div className={cn("rounded-md border p-3", author.ai ? "border-line bg-raise/40" : "border-line bg-sunken/40")}>
            <div className="mb-1.5 flex flex-wrap items-center gap-2">
              {author.ai ? <Sparkles size={12} className="text-accent-text" /> : null}
              <span className="text-[11.5px] font-medium">{author.ai ? "AI impact assessment" : "Engine impact note"}</span>
              <AuthorChip by={n.by} />
              {n.fallback_reason && <span className="text-[11px] text-faint">fallback: {n.fallback_reason}</span>}
            </div>
            <p className="text-[12.5px] leading-[1.55] text-fg">{n.summary}</p>
            {n.availability_note && <p className="mt-1.5 text-[12px] leading-[1.55] text-dim"><span className="font-medium text-fg">Availability: </span>{n.availability_note}</p>}
            {!!n.owner_questions?.length && (
              <div className="mt-2">
                <div className="flex items-center gap-1.5 text-[11px] font-medium text-fg"><HelpCircle size={12} /> Questions for the network owner</div>
                <ul className="mt-1 space-y-0.5 text-[12px] text-dim">
                  {n.owner_questions.map((q, i) => <li key={i}>· {q}</li>)}
                </ul>
              </div>
            )}
            {!!n.cites?.length && (
              <div className="mt-2 flex flex-wrap items-center gap-1.5">
                <span className="text-[11px] text-faint">Cites</span>
                {n.cites.map((c) => <Chip key={c} variant="neutral" mono>{c}</Chip>)}
              </div>
            )}
          </div>
        )}

        <ItemContext item={item} />

        <div className="grid gap-2 lg:grid-cols-2">
          <CodeBlock title="Commands" lines={item.commands ?? []} />
          <CodeBlock title="Rollback" lines={item.rollback ?? []} tone="warn" />
        </div>

        <button type="button" onClick={() => setShowEvidence((v) => !v)} aria-expanded={showEvidence}
          className="focusable flex cursor-pointer items-center gap-1 text-[11.5px] text-dim hover:text-fg">
          {showEvidence ? <ChevronDown size={12} /> : <ChevronRight size={12} />} Evidence
        </button>
        {showEvidence && <div className="rounded-md border border-line p-2.5"><EvidenceList evidence={item.evidence} /></div>}

        <div className="flex flex-wrap items-center gap-2 border-t border-line pt-2.5">
          <OwnerRecord item={item} />
          {item.owner_note && <span className="text-[11.5px] text-dim">“{item.owner_note}”</span>}
          {item.owner_input && Object.keys(item.owner_input).length > 0 && (
            <span className="font-mono text-[10.5px] break-all text-faint">{JSON.stringify(item.owner_input)}</span>
          )}
          <span className="grow" />
          {canDecide && (
            <button type="button" onClick={() => setDeciding((v) => !v)} aria-expanded={deciding}
              className="focusable cursor-pointer text-[12px] font-medium text-fg underline">
              {deciding ? "Close" : item.owner_decision ? "Change decision" : "Decide"}
            </button>
          )}
          {!canDecide && decideNote && <span className="text-[11px] text-faint">{decideNote}</span>}
        </div>
        {canDecide && deciding && (
          <OwnerDecisionForm pkgId={pkgId} item={item} onDecided={(it) => { setDeciding(false); onDecided(it); }} />
        )}
      </div>
    </article>
  );
}
