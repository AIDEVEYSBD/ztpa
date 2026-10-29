"use client";

/**
 * The package-level half of the workflow: the status timeline, the owner's
 * "validate" step, the security approver's decision (four eyes), and the
 * runbook download.
 */

import { useState, type ReactNode } from "react";
import { Download } from "lucide-react";
import { asApiError, type ApiError } from "@/lib/api";
import { frr } from "@/lib/frr";
import type { ChangePackage, FrrMe } from "@/lib/frrTypes";
import { Banner, Button, Field, Panel, Textarea, cn } from "../ui";
import { ActionError, downloadText, hasDutyForAll, when } from "./bits";

type StageState = "done" | "current" | "pending" | "failed";

function Stage({ label, state, who, at, note }: { label: string; state: StageState; who?: string | null; at?: string | null; note?: string | null }) {
  return (
    <li className="relative flex min-w-[180px] flex-1 flex-col gap-0.5 pt-3">
      <span aria-hidden className={cn("absolute top-0 left-0 h-[3px] w-full rounded-[2px]",
        state === "done" ? "bg-ok" : state === "current" ? "bg-run" : state === "failed" ? "bg-err" : "bg-line")} />
      <span className={cn("text-[12.5px] font-medium", state === "pending" ? "text-faint" : state === "failed" ? "text-err" : "text-fg")}>{label}</span>
      {who || at ? <span className="text-[11px] text-dim">{who ?? "unattributed"}{at ? ` · ${when(at)}` : ""}</span>
        : <span className="text-[11px] text-ghost">{state === "current" ? "in progress" : "not yet"}</span>}
      {note && <span className="text-[11.5px] leading-[1.5] text-dim">“{note}”</span>}
    </li>
  );
}

export function PackageTimeline({ pkg }: { pkg: ChangePackage }) {
  const s = pkg.status;
  const validated = s === "owner_validated" || s === "approved" || s === "rejected";
  const decided = s === "approved" || s === "rejected";
  return (
    <ol className="flex flex-wrap gap-4" aria-label="Package status">
      <Stage label="Drafted" state="done" who={pkg.created_by} at={pkg.created_at} />
      <Stage label="Owner validated" state={validated ? "done" : s === "draft" ? "current" : "pending"}
        who={pkg.validated_by} at={pkg.validated_at} note={pkg.validation_note} />
      <Stage label={s === "rejected" ? "Rejected" : "Approved"}
        state={s === "approved" ? "done" : s === "rejected" ? "failed" : s === "owner_validated" ? "current" : "pending"}
        who={decided ? pkg.decided_by : undefined} at={decided ? pkg.decided_at : undefined} note={pkg.decision_note} />
    </ol>
  );
}

export function PackageActions({ pkg, me, onChanged }: { pkg: ChangePackage; me: FrrMe | undefined; onChanged: () => void }) {
  // From the facets, not the items: a large package's items are paged.
  const layers = Object.keys(pkg.facets?.by_layer ?? {});
  const undecided = pkg.facets?.undecided ?? 0;
  const total = pkg.facets?.total ?? 0;
  const isOwner = hasDutyForAll(me, "network_owner", layers);
  const isApprover = hasDutyForAll(me, "security_approver", layers);
  const myEmail = me?.email?.toLowerCase() ?? "";
  const iValidated = !!myEmail && myEmail === (pkg.validated_by ?? "").toLowerCase();

  const [note, setNote] = useState("");
  const [busy, setBusy] = useState<string | null>(null);
  const [err, setErr] = useState<{ action: string; error: ApiError }>();
  const [dlNote, setDlNote] = useState<string>();

  const act = (action: string, p: Promise<unknown>) => {
    setBusy(action);
    setErr(undefined);
    p.then(() => { setNote(""); onChanged(); })
      .catch((e) => setErr({ action, error: asApiError(e) }))
      .finally(() => setBusy(null));
  };

  const download = () => {
    setBusy("download the runbook");
    setErr(undefined);
    setDlNote(undefined);
    frr.runbook(pkg.package_id)
      .then((text) => {
        if (!downloadText(`frr-${pkg.package_id}.txt`, text)) setDlNote("The browser refused the download. Allow downloads for this site and try again.");
      })
      .catch((e) => setErr({ action: "download the runbook", error: asApiError(e) }))
      .finally(() => setBusy(null));
  };

  let body: ReactNode = null;
  if (pkg.status === "draft") {
    body = !isOwner ? (
      <p className="text-[12.5px] text-dim">
        Waiting for the network owner. Validating needs the network_owner duty for every layer in this package
        ({layers.join(", ") || "none"}); you do not hold it.
      </p>
    ) : (
      <div className="space-y-2">
        <p className="text-[12.5px] text-dim">
          {undecided === 0
            ? "Every item has a decision. Validating hands the package to a security approver; items can no longer be changed."
            : `${undecided} of ${total} item${total === 1 ? "" : "s"} still need a decision before the package can be validated.`}
        </p>
        <Field label="Validation note (optional)" htmlFor="frr-validate-note">
          <Textarea id="frr-validate-note" rows={2} value={note} onChange={(e) => setNote(e.target.value)} />
        </Field>
        <Button size="sm" variant="solid" tone="ink" disabled={undecided > 0} loading={busy === "validate the package"}
          onClick={() => act("validate the package", frr.validate(pkg.package_id, note.trim()))}>
          Validate package
        </Button>
      </div>
    );
  } else if (pkg.status === "owner_validated") {
    body = !isApprover ? (
      <p className="text-[12.5px] text-dim">Waiting for a security approver. You do not hold the security_approver duty for every layer in this package.</p>
    ) : iValidated ? (
      <Banner tone="warn" title="Four eyes: you validated this package">
        The person who validated a package cannot also approve or reject it. Another security approver has to decide.
      </Banner>
    ) : (
      <div className="space-y-2">
        <Field label="Decision note (required to reject)" htmlFor="frr-decision-note">
          <Textarea id="frr-decision-note" rows={2} value={note} onChange={(e) => setNote(e.target.value)} />
        </Field>
        <div className="flex flex-wrap gap-2">
          <Button size="sm" variant="solid" tone="ok" loading={busy === "approve the package"}
            onClick={() => act("approve the package", frr.decide(pkg.package_id, "approve", note.trim()))}>Approve</Button>
          <Button size="sm" variant="solid" tone="err" disabled={!note.trim()} loading={busy === "reject the package"}
            title={note.trim() ? undefined : "A rejection needs a note"}
            onClick={() => act("reject the package", frr.decide(pkg.package_id, "reject", note.trim()))}>Reject</Button>
          {!note.trim() && <span className="self-center text-[11.5px] text-faint">A rejection needs a note.</span>}
        </div>
      </div>
    );
  } else if (pkg.status === "approved") {
    body = (
      <div className="flex flex-wrap items-center gap-2">
        <p className="text-[12.5px] text-dim">Approved. The runbook lists the accepted and modified changes, each with its rollback. Nothing has been applied.</p>
        <Button size="sm" variant="solid" tone="ink" loading={busy === "download the runbook"} onClick={download}>
          <Download size={12} /> Download runbook
        </Button>
      </div>
    );
  } else if (pkg.status === "rejected") {
    body = <p className="text-[12.5px] text-dim">Rejected by the security approver. Upload a new export or redraft to start again.</p>;
  } else {
    body = <p className="text-[12.5px] text-dim">Superseded by a newer package for this export. It is kept for the record only.</p>;
  }

  return (
    <Panel title="Workflow" caption="Every action is checked again by the API; these controls only reflect your duties.">
      <div className="space-y-4">
        <PackageTimeline pkg={pkg} />
        {body}
        {err && <ActionError action={err.action} error={err.error} />}
        {dlNote && <p role="alert" className="text-[11.5px] text-err">{dlNote}</p>}
      </div>
    </Panel>
  );
}
