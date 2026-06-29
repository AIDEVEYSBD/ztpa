"use client";

import { useEffect, useState } from "react";
import { Trash2, Eye, History } from "lucide-react";
import { api } from "@/lib/api";
import { Skeleton, cn, Chip, EmptyState } from "../ui";
import { useFilterSort, SearchBox, SortSelect } from "@/lib/tableTools";

export function SnapshotsAdmin({ onView }: { onView: (id: string) => void }) {
  const [snaps, setSnaps] = useState<any[]>();
  const [active, setActive] = useState("");
  const [confirm, setConfirm] = useState<string>();
  const [busy, setBusy] = useState(false);

  const load = () => api.snapshots().then((s) => { setSnaps(s.snapshots); setActive(s.active); }).catch(() => setSnaps([]));
  useEffect(() => { load(); }, []);

  const del = async (id: string) => {
    setBusy(true);
    try { await api.deleteSnapshot(id); } catch { /* ignore */ } finally { setBusy(false); setConfirm(undefined); load(); }
  };

  if (!snaps) {
    return (
      <div className="space-y-4">
        <Skeleton className="h-4 w-3/4 max-w-2xl" />
        <div className="space-y-3">
          {Array.from({ length: 4 }).map((_, i) => (
            <div key={i} className="panel space-y-2 p-3">
              <Skeleton className="h-3.5 w-48" />
              <Skeleton className="h-3 w-64" />
              <Skeleton className="h-7 w-40" />
            </div>
          ))}
        </div>
      </div>
    );
  }

  return <SnapshotTimeline snaps={snaps} active={active} onView={onView} confirm={confirm} setConfirm={setConfirm} busy={busy} del={del} />;
}

function SnapshotTimeline({ snaps, active, onView, confirm, setConfirm, busy, del }: {
  snaps: any[]; active: string; onView: (id: string) => void; confirm?: string; setConfirm: (v?: string) => void; busy: boolean; del: (id: string) => void;
}) {
  const t = useFilterSort(snaps, {
    search: (s) => `${s.snapshot_id} ${s.label ?? ""}`,
    sorts: {
      time: (s) => s.created_at ?? "", findings: (s) => s.findings ?? 0,
      critical: (s) => s.critical ?? 0, assets: (s) => s.assets ?? 0,
    },
    initialSort: "time", initialDir: "desc",
  });

  return (
    <div className="space-y-4">
      <p className="max-w-3xl text-[13px] text-text2">
        Every analysis run is a point-in-time snapshot stored in Postgres. View a past one to time-travel the dashboard,
        or delete its data permanently. The active snapshot cannot be deleted.
      </p>

      <div className="flex flex-wrap items-center gap-2">
        <SearchBox value={t.q} onChange={t.setQ} placeholder="Filter by label or id…" />
        <SortSelect options={[{ key: "time", label: "time" }, { key: "findings", label: "findings" }, { key: "critical", label: "critical" }, { key: "assets", label: "assets" }]}
          sortKey={t.sortKey} setSortKey={t.setSortKey} dir={t.dir} toggleDir={t.toggleDir} />
        <span className="ml-auto text-[11px] text-text3">{t.rows.length} snapshot{t.rows.length !== 1 ? "s" : ""}</span>
      </div>

      {t.rows.length === 0 ? (
        <div className="panel"><EmptyState icon={History} title="No snapshots found" sub="Try a different search, or run an analysis to create one." /></div>
      ) : (
      <div className="relative pl-5">
        <div className="absolute bottom-2 left-[7px] top-2 w-px bg-border" />
        {t.rows.map((s) => {
          const isActive = s.snapshot_id === active;
          return (
            <div key={s.snapshot_id} className="relative mb-3">
              <span className={cn("absolute -left-[14px] top-3 h-2.5 w-2.5 border-2",
                isActive ? "border-accent bg-accent" : "border-borderStrong bg-surface")} />
              <div className="panel p-3">
                <div className="flex flex-wrap items-center gap-2">
                  <span className="mono text-[13px] font-bold">@{s.snapshot_id.replace(/^snap_/, "").slice(0, 10)}</span>
                  {s.label && <Chip variant="neutral">{s.label}</Chip>}
                  {isActive && <Chip variant="accent" mono>ACTIVE</Chip>}
                  <span className="ml-auto text-[11px] text-text3">{new Date(s.created_at).toLocaleString()}</span>
                </div>
                <div className="mono mt-2 flex flex-wrap gap-x-4 gap-y-1 text-[11px] text-text2">
                  <span>{s.assets} assets</span><span>{s.rules} rules</span><span>{s.findings} findings</span>
                  <span className={s.critical ? "text-sev-critical" : ""}>{s.critical} critical</span>
                  <span>{s.paths} cross-tool</span>
                </div>
                <div className="mt-3 flex flex-wrap items-center gap-2">
                  <button onClick={() => onView(s.snapshot_id)} className="btn-ghost !h-7 text-[11px]"><Eye size={12} /> View</button>
                  {confirm === s.snapshot_id ? (
                    <span className="flex flex-wrap items-center gap-2 text-[11px]">
                      <span className="text-sev-critical">Delete this snapshot and all its data?</span>
                      <button onClick={() => del(s.snapshot_id)} disabled={busy}
                        className="btn-danger !h-7 !px-2.5 text-[11px]">{busy ? "Deleting…" : "Yes, delete"}</button>
                      <button onClick={() => setConfirm(undefined)} className="btn-ghost !h-7 text-[11px]">Cancel</button>
                    </span>
                  ) : (
                    <button onClick={() => setConfirm(s.snapshot_id)} disabled={isActive}
                      className="btn-danger !h-7 text-[11px]"
                      title={isActive ? "The active snapshot can't be deleted" : "Delete snapshot"}>
                      <Trash2 size={12} /> Delete
                    </button>
                  )}
                </div>
              </div>
            </div>
          );
        })}
      </div>
      )}
    </div>
  );
}
