"use client";

/**
 * Rule Review · Context data — CMDB/IPAM ownership and observed flows. The newest
 * accepted dataset of each kind is active: change packages show destination
 * owners from it, and narrowing proposals offer observed sources from flows.
 * A rejected dataset shows why and is never used.
 */

import { useCallback, useEffect, useRef, useState } from "react";
import { Database, Upload } from "lucide-react";
import { ApiError, asApiError } from "@/lib/api";
import { frr } from "@/lib/frr";
import type { ContextDataset, ContextKind } from "@/lib/frrTypes";
import { Button, Chip, EmptyState, Field, Panel, Select, Skeleton, Table, THead, Th, Td, Tr } from "../ui";
import { ErrorState } from "../ui/Feedback";
import { ActionError, bytes, when } from "./bits";

const KIND_LABEL: Record<ContextKind, string> = { cmdb: "CMDB / IPAM", flows: "Flows" };
const HELP: Record<ContextKind, string> = {
  cmdb: "CSV with a network column (CIDR, address or range) and optionally owner, application, environment, zone, criticality.",
  flows: "CSV flow export (e.g. Stealthwatch): source and destination IP, port or port/protocol, and last-seen time.",
};

function Summary({ s }: { s: Record<string, unknown> | null }) {
  if (!s) return <span className="text-faint">—</span>;
  return <span className="font-mono text-[11px] text-dim">{Object.entries(s).map(([k, v]) => `${k.replace(/_/g, " ")} ${String(v)}`).join(" · ")}</span>;
}

function UploadContext({ onUploaded }: { onUploaded: () => void }) {
  const [kind, setKind] = useState<ContextKind>("cmdb");
  const [file, setFile] = useState<File>();
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<unknown>();
  const input = useRef<HTMLInputElement>(null);
  const send = () => {
    if (!file) return;
    setBusy(true);
    setErr(undefined);
    frr.uploadContext(kind, file, file.name)
      .then(() => { setFile(undefined); if (input.current) input.current.value = ""; onUploaded(); })
      .catch(setErr)
      .finally(() => setBusy(false));
  };
  return (
    <Panel title="Upload a dataset" icon={<Upload size={13} />}>
      <div className="flex flex-wrap items-end gap-3">
        <Field label="Kind" htmlFor="ctx-kind" className="w-44">
          <Select id="ctx-kind" value={kind} onChange={(e) => setKind(e.target.value as ContextKind)}>
            <option value="cmdb">{KIND_LABEL.cmdb}</option>
            <option value="flows">{KIND_LABEL.flows}</option>
          </Select>
        </Field>
        <Field label="CSV file" htmlFor="ctx-file">
          <input ref={input} id="ctx-file" type="file" accept=".csv,text/csv"
            className="text-[12px]" onChange={(e) => setFile(e.target.files?.[0])} />
        </Field>
        <Button tone="ink" disabled={!file} loading={busy} onClick={send}>Upload</Button>
      </div>
      <p className="mt-2 text-[11.5px] text-dim">{HELP[kind]}</p>
      {err !== undefined && <ActionError action="upload the dataset" error={err} className="mt-2" />}
    </Panel>
  );
}

export function ContextScreen() {
  const [items, setItems] = useState<ContextDataset[]>();
  const [err, setErr] = useState<ApiError>();
  const [tick, setTick] = useState(0);
  const load = useCallback(() => setTick((n) => n + 1), []);

  useEffect(() => {
    let live = true;
    setErr(undefined);
    frr.contextDatasets()
      .then((r) => { if (live) setItems(r.items); })
      .catch((e) => { if (live) setErr(asApiError(e)); });
    return () => { live = false; };
  }, [tick]);

  // Poll only while something is still being processed.
  const pending = items?.some((d) => d.status === "received");
  useEffect(() => {
    if (!pending) return;
    const t = setTimeout(load, 2000);
    return () => clearTimeout(t);
  }, [pending, items, load]);

  return (
    <div className="space-y-5">
      <UploadContext onUploaded={load} />
      <Panel title="Datasets" icon={<Database size={13} />} noPadding>
        {err ? <div className="p-3"><ErrorState resource="the context datasets" error={err} onRetry={load} /></div>
          : !items ? <div className="space-y-2 p-3">{Array.from({ length: 3 }).map((_, i) => <Skeleton key={i} className="h-8 w-full" />)}</div>
          : items.length === 0 ? <EmptyState icon={Database} title="No context loaded"
              sub="Without CMDB data, packages show no owners; without flows, narrowing proposals carry no observed sources." />
          : (
            <Table minWidth={820}>
              <THead><Th>Kind</Th><Th>File</Th><Th>Status</Th><Th>Contents</Th><Th>Uploaded</Th></THead>
              <tbody>
                {items.map((d) => (
                  <Tr key={d.dataset_id}>
                    <Td>{KIND_LABEL[d.kind]}{d.active && <Chip variant="ok" className="ml-2">active</Chip>}</Td>
                    <Td><div className="font-mono text-[11.5px]">{d.filename ?? "—"}</div><div className="text-[11px] text-faint">{bytes(d.size_bytes)}</div></Td>
                    <Td>
                      <Chip variant={d.status === "accepted" ? "ok" : d.status === "rejected" ? "danger" : "info"}>{d.status === "received" ? "processing" : d.status}</Chip>
                      {d.rejection_reason && <div className="mt-1 max-w-[28rem] text-[11.5px] text-err break-words">{d.rejection_reason}</div>}
                    </Td>
                    <Td><Summary s={d.summary} /></Td>
                    <Td className="whitespace-nowrap text-dim">{when(d.uploaded_at)}{d.uploaded_by ? <div className="text-[11px] text-faint">{d.uploaded_by}</div> : null}</Td>
                  </Tr>
                ))}
              </tbody>
            </Table>
          )}
      </Panel>
    </div>
  );
}
