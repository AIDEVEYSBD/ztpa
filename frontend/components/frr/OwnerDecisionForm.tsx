"use client";

/**
 * The network owner's decision on one package item.
 *
 * A narrowing item (non-empty `requires_owner_input`) cannot be accepted or
 * modified without every listed input: the proposal is "narrow this rule", and
 * only the owner knows what to narrow it TO. A rejection needs a note — it is
 * the record that the finding was looked at and consciously kept. Both rules
 * are enforced by the API; they are mirrored here so the button says why it is
 * disabled instead of failing on click.
 */

import { useState } from "react";
import { asApiError, type ApiError } from "@/lib/api";
import { frr } from "@/lib/frr";
import type { OwnerDecision, OwnerInput, PackageItem } from "@/lib/frrTypes";
import { Button, Field, Input, Segmented, Textarea } from "../ui";
import { ActionError } from "./bits";

const LIST_KEYS = new Set(["allowed_sources", "allowed_services"]);

const INPUT_LABEL: Record<string, { label: string; hint: string }> = {
  allowed_sources: { label: "Allowed sources", hint: "Comma or newline separated: hosts, networks or object names" },
  allowed_services: { label: "Allowed services", hint: "Comma or newline separated, e.g. tcp/443, https" },
  business_justification: { label: "Business justification", hint: "Why this access is needed, and for how long" },
};

export const splitList = (s: string): string[] =>
  s.split(/[\n,]/).map((x) => x.trim()).filter(Boolean);

function initialText(item: PackageItem, key: string): string {
  const v = item.owner_input?.[key];
  if (Array.isArray(v)) return v.join("\n");
  return typeof v === "string" ? v : "";
}

export function OwnerDecisionForm({ pkgId, item, onDecided }: {
  pkgId: string;
  item: PackageItem;
  onDecided: (item: PackageItem) => void;
}) {
  const required = item.requires_owner_input ?? [];
  const [decision, setDecision] = useState<OwnerDecision>(item.owner_decision ?? "accept");
  const [note, setNote] = useState(item.owner_note ?? "");
  const [inputs, setInputs] = useState<Record<string, string>>(
    () => Object.fromEntries(required.map((k) => [k, initialText(item, k)])),
  );
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<ApiError>();

  const needsInput = decision !== "reject" && required.length > 0;
  const missing = needsInput
    ? required.filter((k) => (LIST_KEYS.has(k) ? splitList(inputs[k] ?? "").length === 0 : !(inputs[k] ?? "").trim()))
    : [];
  const noteMissing = decision === "reject" && !note.trim();
  const blocked = missing.length > 0 || noteMissing;

  const submit = () => {
    if (blocked) return;
    const input: OwnerInput & Record<string, unknown> = {};
    if (needsInput) {
      for (const k of required) input[k] = LIST_KEYS.has(k) ? splitList(inputs[k] ?? "") : (inputs[k] ?? "").trim();
    }
    setBusy(true);
    setErr(undefined);
    frr.decideItem(pkgId, item.item_id, {
      decision,
      input: needsInput ? input : undefined,
      note: note.trim() || undefined,
    })
      .then(onDecided)
      .catch((e) => setErr(asApiError(e)))
      .finally(() => setBusy(false));
  };

  const id = (k: string) => `frr-${item.item_id}-${k}`;

  return (
    <div className="space-y-3 rounded-md border border-line bg-raise/30 p-3">
      <div className="flex flex-wrap items-center gap-2">
        <span className="text-[12px] font-medium">Your decision</span>
        <Segmented<OwnerDecision>
          value={decision}
          onChange={(d) => { setDecision(d); setErr(undefined); }}
          options={[{ value: "accept", label: "Accept" }, { value: "modify", label: "Modify" }, { value: "reject", label: "Reject" }]}
        />
        {item.owner_decision && <span className="text-[11px] text-faint">Re-deciding replaces the recorded {item.owner_decision}.</span>}
      </div>

      {needsInput && (
        <div className="grid gap-3 md:grid-cols-2">
          {required.map((k) => {
            const meta = INPUT_LABEL[k] ?? { label: k.replace(/_/g, " "), hint: "" };
            const isMissing = missing.includes(k);
            return (
              <Field key={k} label={`${meta.label} (required)`} htmlFor={id(k)} hint={meta.hint}
                className={k === "business_justification" ? "md:col-span-2" : undefined}>
                {LIST_KEYS.has(k) || k === "business_justification" ? (
                  <Textarea id={id(k)} value={inputs[k] ?? ""} rows={k === "business_justification" ? 2 : 3}
                    aria-invalid={isMissing || undefined}
                    onChange={(e) => setInputs((s) => ({ ...s, [k]: e.target.value }))}
                    className={LIST_KEYS.has(k) ? "font-mono text-[12px]" : undefined} />
                ) : (
                  <Input id={id(k)} value={inputs[k] ?? ""} invalid={isMissing}
                    onChange={(e) => setInputs((s) => ({ ...s, [k]: e.target.value }))} />
                )}
              </Field>
            );
          })}
        </div>
      )}

      <Field label={decision === "reject" ? "Why you are rejecting this change (required)" : "Note (optional)"} htmlFor={id("note")}>
        <Textarea id={id("note")} rows={2} value={note} onChange={(e) => setNote(e.target.value)} />
      </Field>

      <div className="flex flex-wrap items-center gap-2">
        <Button size="sm" variant="solid" tone={decision === "reject" ? "err" : "ink"} onClick={submit} loading={busy} disabled={blocked}>
          Record {decision}
        </Button>
        {blocked && (
          <span className="text-[11.5px] text-faint">
            {noteMissing ? "A rejection needs a note." : `Fill in: ${missing.map((k) => (INPUT_LABEL[k]?.label ?? k).toLowerCase()).join(", ")}.`}
          </span>
        )}
      </div>
      {err && <ActionError action={`record this ${decision}`} error={err} />}
    </div>
  );
}
