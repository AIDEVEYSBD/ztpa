"use client";

/**
 * Rule Review · Exports — upload a policy export and pick the one the review
 * screens look at.
 *
 * A `received` export is being parsed in the background, so the screen polls
 * those rows (and only those) every 2 seconds. Polling is bounded: after five
 * minutes still `received`, it stops and says so, because an intake worker that
 * is not running looks exactly like one that is slow.
 */

import { useCallback, useEffect, useState } from "react";
import { FileJson, RotateCw } from "lucide-react";
import { ApiError, asApiError } from "@/lib/api";
import { frr } from "@/lib/frr";
import type { FrrExport } from "@/lib/frrTypes";
import { Banner, Button, EmptyState, Skeleton } from "../ui";
import { ErrorState, InlineError } from "../ui/Feedback";
import { ExportCard } from "./ExportCard";
import { UploadCard } from "./UploadCard";
import { useFrrMe } from "./bits";

const POLL_MS = 2000;
/** 150 × 2s = five minutes of "received" before the screen stops asking. */
const MAX_POLLS = 150;
const PAGE = 50;

export function ExportsScreen({ selectedId, onSelect, onOpenReview, onRunStarted }: {
  selectedId?: string;
  onSelect: (id: string) => void;
  onOpenReview: (id: string) => void;
  /** A run was queued for this export; the caller remembers it and navigates. */
  onRunStarted: (exportId: string, runId: string) => void;
}) {
  const { me } = useFrrMe();
  const [items, setItems] = useState<FrrExport[]>();
  const [nextBefore, setNextBefore] = useState<string | null>(null);
  const [loadErr, setLoadErr] = useState<ApiError>();
  const [loading, setLoading] = useState(true);
  const [olderBusy, setOlderBusy] = useState(false);
  const [olderErr, setOlderErr] = useState<ApiError>();
  const [pollErr, setPollErr] = useState<ApiError>();
  const [polls, setPolls] = useState(0);
  const [attempt, setAttempt] = useState(0);

  useEffect(() => {
    let live = true;
    setLoading(true);
    setLoadErr(undefined);
    frr.exports({ limit: PAGE })
      .then((p) => {
        if (!live) return;
        if (!p || !Array.isArray(p.items)) {
          setItems(undefined);
          setLoadErr(new ApiError(200, "The API answered, but not with the export list shape this screen reads ({items, next_before}). The frontend and backend are probably different builds.", "/api/exports"));
          return;
        }
        setItems(p.items);
        setNextBefore(p.next_before);
        setPolls(0);
      })
      .catch((e) => { if (live) { setItems(undefined); setLoadErr(asApiError(e)); } })
      .finally(() => { if (live) setLoading(false); });
    return () => { live = false; };
  }, [attempt]);

  const merge = useCallback((rows: FrrExport[]) => {
    setItems((cur) => {
      if (!cur) return cur;
      const byId = new Map(rows.map((r) => [r.export_id, r]));
      return cur.map((x) => byId.get(x.export_id) ?? x);
    });
  }, []);

  // Poll the received rows only. Rescheduled after each successful round
  // (`polls` changes), stopped on error, on the cap, and on unmount.
  const pendingKey = (items ?? []).filter((x) => x.status === "received").map((x) => x.export_id).join(",");
  const capped = polls >= MAX_POLLS;
  useEffect(() => {
    if (!pendingKey || pollErr || capped) return;
    let live = true;
    const t = setTimeout(() => {
      Promise.all(pendingKey.split(",").map((id) => frr.exportById(id)))
        .then((rows) => { if (live) { merge(rows); setPolls((n) => n + 1); } })
        .catch((e) => { if (live) setPollErr(asApiError(e)); });
    }, POLL_MS);
    return () => { live = false; clearTimeout(t); };
  }, [pendingKey, pollErr, capped, polls, merge]);

  const loadOlder = () => {
    if (!nextBefore) return;
    setOlderBusy(true);
    setOlderErr(undefined);
    frr.exports({ limit: PAGE, before: nextBefore })
      .then((p) => {
        setItems((cur) => {
          const seen = new Set((cur ?? []).map((x) => x.export_id));
          return [...(cur ?? []), ...p.items.filter((x) => !seen.has(x.export_id))];
        });
        setNextBefore(p.next_before);
      })
      .catch((e) => setOlderErr(asApiError(e)))
      .finally(() => setOlderBusy(false));
  };

  const onUploaded = (e: FrrExport) => {
    setItems((cur) => [e, ...(cur ?? []).filter((x) => x.export_id !== e.export_id)]);
    setPolls(0);
    setPollErr(undefined);
    onSelect(e.export_id);
  };

  const canUpload = me.status === "ok" && !!me.data?.can_upload;
  const roleNote = me.status === "ok"
    ? `Uploading exports and running agents require the admin or analyst role; your role is ${me.data?.role ?? "none"}.`
    : undefined;

  return (
    <div className="space-y-5">
      {me.status === "error" && <InlineError resource="your review duties" error={me.error} />}
      {me.status === "loading"
        ? <Skeleton className="h-[120px] w-full rounded-lg" />
        : <UploadCard canUpload={canUpload} roleNote={roleNote} onUploaded={onUploaded} />}

      <div className="flex flex-wrap items-center gap-2">
        <h2 className="text-[13px] font-semibold">Exports</h2>
        <span className="text-[11.5px] text-faint">Newest first. Select one to review it.</span>
        <Button size="sm" variant="quiet" tone="neutral" className="ml-auto" onClick={() => setAttempt((n) => n + 1)} loading={loading}>
          <RotateCw size={12} /> Refresh
        </Button>
      </div>

      {pollErr && (
        <InlineError resource="the status of exports still being parsed" error={pollErr}
          onRetry={() => setPollErr(undefined)} />
      )}
      {capped && pendingKey && (
        <Banner tone="warn" title="Still being parsed after five minutes"
          actions={<Button size="sm" variant="solid" tone="ink" onClick={() => setPolls(0)}>Keep checking</Button>}>
          Automatic status checks have stopped. A large export can take this long, but so does an intake
          worker that is not running — if this persists, check the backend job queue.
        </Banner>
      )}

      {loadErr ? (
        <ErrorState resource="the export list" error={loadErr} onRetry={() => setAttempt((n) => n + 1)} />
      ) : loading && !items ? (
        <div className="space-y-3">
          {Array.from({ length: 3 }).map((_, i) => <Skeleton key={i} className="h-[92px] w-full rounded-lg" />)}
        </div>
      ) : items && items.length === 0 ? (
        <EmptyState icon={FileJson} title="No exports uploaded yet"
          sub="Upload a policy export above. Once it is parsed, its rule-risk register and change package are reviewed here." />
      ) : (
        <div className="space-y-3">
          {(items ?? []).map((x) => (
            <ExportCard key={x.export_id} exp={x} selected={x.export_id === selectedId}
              canRun={canUpload} onSelect={() => onSelect(x.export_id)}
              onOpenReview={() => { onSelect(x.export_id); onOpenReview(x.export_id); }}
              onRunStarted={(runId) => { onSelect(x.export_id); onRunStarted(x.export_id, runId); }} />
          ))}
          {olderErr && <InlineError resource="older exports" error={olderErr} onRetry={loadOlder} />}
          {nextBefore && (
            <div className="flex justify-center">
              <Button size="sm" variant="outline" tone="ink" onClick={loadOlder} loading={olderBusy}>Load older exports</Button>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
