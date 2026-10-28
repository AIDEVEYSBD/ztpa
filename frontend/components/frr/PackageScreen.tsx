"use client";

/**
 * Rule Review · Change package — for the selected export: the agent run (live),
 * the package it drafted, the network owner's per-item decisions, and the
 * security approver's ruling.
 *
 * Finding the package. The API has no "package for export X" read, so the id
 * comes from (a) the run that drafted it, (b) a deterministic draft made here,
 * (c) the existing id the API names in its 409 when a draft already exists, or
 * (d) an id pasted in. It is remembered per export in this browser only (see
 * ./selection.ts) and always read back from the API.
 */

import { useCallback, useEffect, useState, type ReactNode } from "react";
import { Bot, FileStack, RotateCw } from "lucide-react";
import { asApiError, type ApiError } from "@/lib/api";
import { frr } from "@/lib/frr";
import type { ChangePackage, FrrMe, FrrRun, PackageItem } from "@/lib/frrTypes";
import { Banner, Button, Chip, EmptyState, Field, Input, Panel, Skeleton } from "../ui";
import { ErrorState, InlineError } from "../ui/Feedback";
import { ActionError, BANDS, IMPACT, PACKAGE_STATUS, firstUuid, hasDuty, impactMeta, proposalLabel, useFrrMe, when, AuthorChip, authorLabel } from "./bits";
import { PackageItemCard } from "./PackageItemCard";
import { PackageActions } from "./PackageWorkflow";
import { RunSteps } from "./RunSteps";
import type { FrrLink } from "./selection";

export function PackageScreen({ exportId, link, setLink, onGoToExports }: {
  exportId: string;
  link: FrrLink;
  setLink: (patch: FrrLink) => void;
  onGoToExports: () => void;
}) {
  const { me } = useFrrMe();
  const canStart = me.status === "ok" && !!me.data?.can_upload;
  const [startErr, setStartErr] = useState<{ action: string; error: ApiError }>();
  const [busy, setBusy] = useState<string | null>(null);
  const [conflictId, setConflictId] = useState<string>();
  const [pasted, setPasted] = useState("");

  const startRun = () => {
    setBusy("run");
    setStartErr(undefined);
    frr.startRun(exportId)
      .then((r) => setLink({ runId: r.run_id }))
      .catch((e) => setStartErr({ action: "start a review run", error: asApiError(e) }))
      .finally(() => setBusy(null));
  };

  const draft = (supersede: boolean) => {
    setBusy(supersede ? "supersede" : "draft");
    setStartErr(undefined);
    setConflictId(undefined);
    frr.draftPackage(exportId, supersede)
      .then((p) => setLink({ packageId: p.package_id, runId: undefined }))
      .catch((e) => {
        const err = asApiError(e);
        setStartErr({ action: "draft a change package", error: err });
        if (err.status === 409) setConflictId(firstUuid(err.detail));
      })
      .finally(() => setBusy(null));
  };

  const onRunFinished = useCallback((run: FrrRun) => {
    if (run.status === "succeeded" && run.package_id) setLink({ packageId: run.package_id });
  }, [setLink]);

  const startControls = (
    <div className="space-y-3">
      <div className="flex flex-wrap items-center gap-2">
        <Button size="sm" variant="solid" tone="ink" onClick={startRun} loading={busy === "run"} disabled={!canStart}>
          <Bot size={12} /> Run agents
        </Button>
        <Button size="sm" variant="outline" tone="ink" onClick={() => draft(false)} loading={busy === "draft"} disabled={!canStart}>
          Draft without narratives
        </Button>
        {!canStart && me.status === "ok" && (
          <span className="text-[11.5px] text-faint">Running agents and drafting need the admin or analyst role (yours: {me.data?.role ?? "none"}).</span>
        )}
      </div>
      {startErr && <ActionError action={startErr.action} error={startErr.error} />}
      {conflictId && (
        <div className="flex flex-wrap items-center gap-2">
          <Button size="sm" variant="solid" tone="ink" onClick={() => { setLink({ packageId: conflictId, runId: undefined }); setStartErr(undefined); setConflictId(undefined); }}>
            Open existing package {conflictId.slice(0, 8)}
          </Button>
          <Button size="sm" variant="outline" tone="err" onClick={() => draft(true)} loading={busy === "supersede"}>
            Supersede it and redraft
          </Button>
        </div>
      )}
      <form className="flex flex-wrap items-end gap-2" onSubmit={(e) => { e.preventDefault(); const id = pasted.trim(); if (id) { setLink({ packageId: id, runId: undefined }); setPasted(""); } }}>
        <Field label="Open a package by id" htmlFor="frr-pkg-id" className="w-[360px] max-w-full">
          <Input id="frr-pkg-id" mono compact value={pasted} onChange={(e) => setPasted(e.target.value)} placeholder="00000000-0000-0000-0000-000000000000" />
        </Field>
        <Button size="sm" variant="outline" tone="ink" type="submit" disabled={!pasted.trim()}>Open</Button>
      </form>
    </div>
  );

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center gap-2">
        <span className="text-[11.5px] text-faint">Export <span className="font-mono text-dim">{exportId.slice(0, 8)}</span></span>
        <Button size="sm" variant="quiet" tone="neutral" className="ml-auto" onClick={onGoToExports}>Change export</Button>
      </div>
      {me.status === "error" && <InlineError resource="your review duties" error={me.error} />}

      {link.runId && <RunSteps key={link.runId} runId={link.runId} onFinished={onRunFinished} />}

      {link.packageId ? (
        <PackageLoader key={link.packageId} packageId={link.packageId} me={me.data} meLoading={me.status === "loading"}
          footer={<Panel title="Start over" plainTitle>{startControls}</Panel>} />
      ) : (
        <Panel title="No change package yet" icon={<FileStack size={13} />}
          caption="Run the agents for a package with AI impact narratives, or draft the deterministic package alone.">
          {startControls}
        </Panel>
      )}
    </div>
  );
}

function PackageLoader({ packageId, me, meLoading, footer }: {
  packageId: string;
  me: FrrMe | undefined;
  meLoading: boolean;
  footer: ReactNode;
}) {
  const [pkg, setPkg] = useState<ChangePackage>();
  const [err, setErr] = useState<ApiError>();
  const [attempt, setAttempt] = useState(0);

  useEffect(() => {
    let live = true;
    setErr(undefined);
    frr.pkg(packageId)
      .then((p) => { if (live) setPkg(p); })
      .catch((e) => { if (live) setErr(asApiError(e)); });
    return () => { live = false; };
  }, [packageId, attempt]);

  const reload = () => setAttempt((n) => n + 1);
  const onItem = (it: PackageItem) =>
    setPkg((p) => (p ? { ...p, items: p.items.map((x) => (x.item_id === it.item_id ? { ...x, ...it } : x)) } : p));

  if (err && !pkg) return <div className="space-y-4"><ErrorState resource={`change package ${packageId.slice(0, 8)}`} error={err} onRetry={reload} />{footer}</div>;
  if (!pkg) return <div className="space-y-3"><Skeleton className="h-[120px] w-full rounded-lg" /><Skeleton className="h-[220px] w-full rounded-lg" /></div>;

  return (
    <div className="space-y-4">
      {err && <InlineError resource="the latest package state" error={err} onRetry={reload} />}
      <PackageHeader pkg={pkg} onReload={reload} />
      <PackageActions pkg={pkg} me={me} onChanged={reload} />
      <PackageItems pkg={pkg} me={me} meLoading={meLoading} onItem={onItem} />
      {pkg.status === "draft" || pkg.status === "rejected" || pkg.status === "superseded" ? footer : null}
    </div>
  );
}

function PackageHeader({ pkg, onReload }: { pkg: ChangePackage; onReload: () => void }) {
  const st = PACKAGE_STATUS[pkg.status] ?? { label: pkg.status, variant: "neutral" as const };
  const byImpact = pkg.summary?.by_impact ?? {};
  const byProposal = pkg.summary?.by_proposal ?? {};
  const n = pkg.narrative;
  const author = authorLabel(n?.by);
  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center gap-2">
        <h2 className="text-[15px] font-semibold">Change package</h2>
        <Chip variant={st.variant} dot>{st.label}</Chip>
        <span className="font-mono text-[11px] text-faint">{pkg.package_id}</span>
        <span className="text-[11px] text-faint">· drafted {when(pkg.created_at)}{pkg.created_by ? ` by ${pkg.created_by}` : ""}</span>
        <Button size="sm" variant="quiet" tone="neutral" className="ml-auto" onClick={onReload}><RotateCw size={12} /> Refresh</Button>
      </div>
      {pkg.status === "superseded" && (
        <Banner tone="warn" title="Superseded">A newer package replaced this one. Decisions here no longer count.</Banner>
      )}

      {n ? (
        <Panel title={author.ai ? "AI summary" : "Engine summary"} actions={<AuthorChip by={n.by} />}
          caption={author.ai ? "Written by a model from the deterministic findings. Check it against the items below." : "No model summary: this was assembled by the deterministic engine."}>
          <p className="text-[13px] leading-[1.6] text-fg">{n.summary}</p>
          {!!n.key_risks?.length && (
            <ul className="mt-2 space-y-0.5 text-[12.5px] text-dim">{n.key_risks.map((r, i) => <li key={i}>· {r}</li>)}</ul>
          )}
          {n.limitations_note && <p className="mt-2 text-[12px] text-warn">Limitations: {n.limitations_note}</p>}
        </Panel>
      ) : (
        <p className="text-[12px] text-faint">No executive summary: this package was drafted without the agents. Run the agents to add narratives.</p>
      )}

      <div className="flex flex-wrap gap-x-8 gap-y-3 rounded-lg border border-line bg-surface px-4 py-3 elev-1">
        <div>
          <div className="text-[10.5px] text-faint">Items</div>
          <div className="tnum text-[20px] font-semibold">{pkg.summary?.items ?? pkg.items.length}</div>
        </div>
        <div>
          <div className="text-[10.5px] text-faint">By availability impact</div>
          <div className="mt-1 flex flex-wrap gap-1.5">
            {Object.keys(IMPACT).filter((k) => byImpact[k] != null).concat(Object.keys(byImpact).filter((k) => !(k in IMPACT))).map((k) => {
              const m = impactMeta(k);
              return <Chip key={k} variant={m.variant} className={m.loud ? "font-semibold" : undefined}>{byImpact[k]} · {m.label}</Chip>;
            })}
            {Object.keys(byImpact).length === 0 && <span className="text-[11.5px] text-faint">not reported</span>}
          </div>
        </div>
        <div>
          <div className="text-[10.5px] text-faint">By proposal</div>
          <div className="mt-1 flex flex-wrap gap-1.5">
            {Object.entries(byProposal).map(([k, v]) => <Chip key={k} variant="neutral">{v} · {proposalLabel(k)}</Chip>)}
            {Object.keys(byProposal).length === 0 && <span className="text-[11.5px] text-faint">not reported</span>}
          </div>
        </div>
      </div>

      {(!!pkg.limitations?.length || !!pkg.notes?.length) && (
        <Banner tone="warn" title="Limitations and notes">
          <ul className="mt-1 space-y-0.5">
            {(pkg.limitations ?? []).map((l, i) => <li key={`l${i}`}>· {l}</li>)}
            {(pkg.notes ?? []).map((l, i) => <li key={`n${i}`} className="text-faint">· {l}</li>)}
          </ul>
        </Banner>
      )}
    </div>
  );
}

function PackageItems({ pkg, me, meLoading, onItem }: {
  pkg: ChangePackage;
  me: FrrMe | undefined;
  meLoading: boolean;
  onItem: (it: PackageItem) => void;
}) {
  if (pkg.items.length === 0) {
    return <EmptyState icon={FileStack} title="This package has no items" sub="The register produced no change proposals for this export." />;
  }
  return (
    <div className="space-y-5">
      {BANDS.map((b) => {
        const xs = pkg.items.filter((i) => i.band === b);
        if (xs.length === 0) return null;
        return (
          <section key={b} className="space-y-2.5" aria-label={`${b} items`}>
            <h3 className="text-[11px] font-medium tracking-[0.08em] text-faint uppercase">{b} · {xs.length}</h3>
            {xs.map((it) => {
              const owner = hasDuty(me, "network_owner", it.layer);
              const canDecide = pkg.status === "draft" && owner;
              const decideNote = pkg.status !== "draft" ? undefined
                : meLoading ? "Checking your duties…"
                  : `Deciding needs the network_owner duty for layer ${it.layer}.`;
              return <PackageItemCard key={it.item_id} pkgId={pkg.package_id} item={it} canDecide={canDecide} decideNote={decideNote} onDecided={onItem} />;
            })}
          </section>
        );
      })}
    </div>
  );
}
