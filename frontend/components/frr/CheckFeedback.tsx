"use client";

/**
 * Reviewer feedback on one rule's checks. AGREE with a raised check; DISAGREE
 * (with a reason) marks it a false positive; "report a missed finding" names a
 * check the review did not raise, with the band it should have had. Feedback
 * becomes evaluation labels, so the reason matters: it is what a tuning change
 * will cite.
 */

import { useState } from "react";
import { Check, X } from "lucide-react";
import { frr } from "@/lib/frr";
import { CHECK_KINDS, type FeedbackBand, type FeedbackRow, type RegisterEntry } from "@/lib/frrTypes";
import { Button, Chip, Field, Select, Textarea } from "../ui";
import { ActionError, checkLabel } from "./bits";

const BAND_OPTIONS: FeedbackBand[] = ["critical", "high", "medium", "low", "none"];

function Verdict({ row }: { row?: FeedbackRow }) {
  if (!row) return null;
  return (
    <Chip variant={row.verdict === "agree" ? "ok" : "warn"}>
      you {row.verdict === "agree" ? "agreed" : "disagreed"}{row.suggested_band ? ` · ${row.suggested_band}` : ""}
    </Chip>
  );
}

function Form({ exportId, ruleUid, check, missed, onSaved, onCancel }: {
  exportId: string; ruleUid: string; check?: string; missed?: boolean;
  onSaved: (r: FeedbackRow) => void; onCancel: () => void;
}) {
  const [kind, setKind] = useState(check ?? "");
  const [band, setBand] = useState<FeedbackBand | "">("");
  const [comment, setComment] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>();
  const ready = !!kind && comment.trim().length > 0 && (!missed || !!band);

  const save = () => {
    setBusy(true);
    setError(undefined);
    frr.giveFeedback(exportId, ruleUid, { check: kind, verdict: "disagree", suggested_band: band || undefined,
                                          comment: comment.trim() })
      .then(onSaved)
      .catch(setError)
      .finally(() => setBusy(false));
  };

  return (
    <div className="mt-2 space-y-2 rounded-md border border-line bg-raise/40 p-2.5">
      {missed && (
        <Field label="Check the review missed" htmlFor={`fb-kind-${ruleUid}`}>
          <Select id={`fb-kind-${ruleUid}`} value={kind} onChange={(e) => setKind(e.target.value)}>
            <option value="">Choose…</option>
            {CHECK_KINDS.map((c) => <option key={c} value={c}>{checkLabel(c)}</option>)}
          </Select>
        </Field>
      )}
      <Field label={missed ? "Band it should have" : "Band it should have (optional)"} htmlFor={`fb-band-${ruleUid}-${kind}`}>
        <Select id={`fb-band-${ruleUid}-${kind}`} value={band} onChange={(e) => setBand(e.target.value as FeedbackBand | "")}>
          <option value="">{missed ? "Choose…" : "Keep the engine's band"}</option>
          {BAND_OPTIONS.map((b) => <option key={b} value={b}>{b}</option>)}
        </Select>
      </Field>
      <Field label="Why (required)" htmlFor={`fb-why-${ruleUid}-${kind}`}>
        <Textarea id={`fb-why-${ruleUid}-${kind}`} rows={2} maxLength={2000} value={comment}
          onChange={(e) => setComment(e.target.value)}
          placeholder={missed ? "What the review should have flagged, and why" : "Why this finding is wrong for this rule"} />
      </Field>
      {error !== undefined && <ActionError action="save the feedback" error={error} />}
      <div className="flex gap-2">
        <Button size="sm" tone="ink" disabled={!ready} loading={busy} onClick={save}>Save</Button>
        <Button size="sm" variant="quiet" tone="neutral" onClick={onCancel}>Cancel</Button>
      </div>
    </div>
  );
}

export function CheckFeedback({ exportId, entry, mine, onChange }: {
  exportId: string; entry: RegisterEntry; mine: Record<string, FeedbackRow>;
  onChange: (r: FeedbackRow) => void;
}) {
  const [editing, setEditing] = useState<string | null>(null);
  const [busy, setBusy] = useState<string | null>(null);
  const [error, setError] = useState<unknown>();

  const agree = (check: string) => {
    setBusy(check);
    setError(undefined);
    frr.giveFeedback(exportId, entry.rule_uid, { check, verdict: "agree" })
      .then(onChange)
      .catch(setError)
      .finally(() => setBusy(null));
  };
  const raised = new Set(entry.checks.map((c) => c.check));
  const missed = Object.values(mine).filter((r) => !raised.has(r.check_kind));

  return (
    <div className="space-y-2 border-t border-line pt-2.5">
      <div className="text-[11px] font-medium text-dim">Your review of these checks</div>
      {entry.checks.map((c) => (
        <div key={c.check}>
          <div className="flex flex-wrap items-center gap-2 text-[11.5px]">
            <span className="min-w-[9rem] text-fg">{checkLabel(c.check)}</span>
            <Verdict row={mine[c.check]} />
            <Button size="sm" variant="outline" tone="ink" loading={busy === c.check} onClick={() => agree(c.check)}>
              <Check size={12} /> Agree
            </Button>
            <Button size="sm" variant="outline" tone="ink" onClick={() => setEditing(editing === c.check ? null : c.check)}>
              <X size={12} /> Disagree
            </Button>
          </div>
          {editing === c.check && (
            <Form exportId={exportId} ruleUid={entry.rule_uid} check={c.check}
              onSaved={(r) => { onChange(r); setEditing(null); }} onCancel={() => setEditing(null)} />
          )}
        </div>
      ))}
      {missed.map((r) => (
        <div key={r.check_kind} className="flex items-center gap-2 text-[11.5px]">
          <span className="min-w-[9rem] text-fg">{checkLabel(r.check_kind)}</span>
          <Chip variant="warn">you reported this as missed{r.suggested_band ? ` · ${r.suggested_band}` : ""}</Chip>
        </div>
      ))}
      <Button size="sm" variant="quiet" tone="neutral" onClick={() => setEditing(editing === "__missed" ? null : "__missed")}>
        Report a missed finding
      </Button>
      {editing === "__missed" && (
        <Form exportId={exportId} ruleUid={entry.rule_uid} missed
          onSaved={(r) => { onChange(r); setEditing(null); }} onCancel={() => setEditing(null)} />
      )}
      {error !== undefined && <ActionError action="record your agreement" error={error} />}
    </div>
  );
}
