"use client";

import { useRef, useState } from "react";
import { Upload } from "lucide-react";
import { asApiError, type ApiError } from "@/lib/api";
import { frr } from "@/lib/frr";
import type { FrrExport } from "@/lib/frrTypes";
import { Banner, Button, Field, Input, Panel, Select } from "../ui";
import { ActionError, bytes, when } from "./bits";

/** Sources the intake can parse. One today; a select so adding the next one is
 *  a row here rather than a redesign. */
const SOURCES = [{ value: "checkpoint", label: "Check Point (Show Package JSON)" }] as const;

/** The backend accepts letters, digits, space and . _ - ( ) in a filename, up to
 *  200 characters. Anything else is replaced so a valid file is never refused
 *  for its name. */
export function safeFilename(name: string): string {
  return name.replace(/[^A-Za-z0-9 ._()-]/g, "_").slice(0, 200) || "export.json";
}

/** `datetime-local` has no zone; it is the reviewer's local time, which `Date`
 *  reads as local, and `toISOString` writes with an explicit `Z`. */
export function localToIso(v: string): string | undefined {
  if (!v) return undefined;
  const d = new Date(v);
  return Number.isNaN(d.getTime()) ? undefined : d.toISOString();
}

const MULTIPART_ABOVE = 16 * 1024 * 1024;

export function UploadCard({ canUpload, roleNote, onUploaded }: {
  canUpload: boolean;
  /** Why uploading is not offered, when it is not. */
  roleNote?: string;
  onUploaded: (e: FrrExport, duplicate: boolean) => void;
}) {
  const fileRef = useRef<HTMLInputElement>(null);
  const [file, setFile] = useState<File | null>(null);
  const [source, setSource] = useState<string>(SOURCES[0].value);
  const [exportedAt, setExportedAt] = useState("");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<ApiError>();
  const [result, setResult] = useState<{ export: FrrExport; duplicate: boolean }>();
  const [progress, setProgress] = useState<number | null>(null);

  const iso = localToIso(exportedAt);
  const badDate = !!exportedAt && !iso;

  const submit = () => {
    if (!file || badDate) return;
    setBusy(true);
    setErr(undefined);
    setResult(undefined);
    const params = { source, filename: safeFilename(file.name), exported_at: iso };
    // One request up to 16 MiB; above that, a multipart session (Cloud Run caps a request at 32 MiB).
    const upload = file.size > MULTIPART_ABOVE
      ? frr.uploadExportMultipart(file, params, (f) => setProgress(f))
      : frr.uploadExport(file, params);
    upload
      .then((r) => {
        setResult({ export: r.export, duplicate: r.duplicate });
        onUploaded(r.export, r.duplicate);
        setFile(null);
        if (fileRef.current) fileRef.current.value = "";
      })
      .catch((e) => setErr(asApiError(e)))
      .finally(() => { setBusy(false); setProgress(null); });
  };

  return (
    <Panel title="Upload a policy export" icon={<Upload size={13} />}
      caption="The file is stored as uploaded, hashed, and parsed in the background. Nothing is sent to a firewall.">
      {!canUpload ? (
        <p className="text-[12.5px] text-dim">{roleNote ?? "Uploading exports requires the admin or analyst role."}</p>
      ) : (
        <div className="space-y-3">
          <div className="grid gap-3 md:grid-cols-[1fr_1.4fr_1fr_auto] md:items-end">
            <Field label="Source" htmlFor="frr-source">
              <Select id="frr-source" value={source} onChange={(e) => setSource(e.target.value)}>
                {SOURCES.map((s) => <option key={s.value} value={s.value}>{s.label}</option>)}
              </Select>
            </Field>
            <Field label="Export file" htmlFor="frr-file"
              hint={file ? `${file.name} · ${bytes(file.size)}` : "The JSON produced by the export tool"}>
              <input ref={fileRef} id="frr-file" type="file" accept=".json,application/json"
                onChange={(e) => { setFile(e.target.files?.[0] ?? null); setResult(undefined); setErr(undefined); }}
                className="focusable block w-full cursor-pointer text-[12.5px] text-dim file:mr-3 file:cursor-pointer file:rounded-sm file:border file:border-line file:bg-raise file:px-2.5 file:py-1 file:text-[12px] file:text-fg" />
            </Field>
            <Field label="Exported at (optional)" htmlFor="frr-exported-at"
              hint={iso ? `Sent as ${iso}` : "Your local time; stale-rule checks are measured from it"}
              error={badDate ? "Not a valid date and time" : undefined}>
              <Input id="frr-exported-at" type="datetime-local" step={1} value={exportedAt}
                onChange={(e) => setExportedAt(e.target.value)} invalid={badDate} />
            </Field>
            <Button variant="solid" tone="ink" onClick={submit} disabled={!file || badDate} loading={busy}>
              <Upload size={13} /> Upload
            </Button>
          </div>
          {progress !== null && (
            <div className="text-[11.5px] text-dim" role="status" aria-live="polite">
              {progress < 1 ? `Sending in parts… ${Math.round(progress * 100)}%` : "Assembling and hashing the upload…"}
            </div>
          )}
          {file && safeFilename(file.name) !== file.name && (
            <p className="text-[11.5px] text-faint">
              The file name will be recorded as <span className="font-mono text-dim">{safeFilename(file.name)}</span> (the API accepts letters, digits, spaces and . _ - ( ) only).
            </p>
          )}
          {err && <ActionError action="upload the export" error={err} />}
          {result && (
            result.duplicate ? (
              <Banner tone="queue" title="This exact file was already uploaded">
                Same SHA-256 as the export received {when(result.export.uploaded_at)}
                {result.export.uploaded_by ? ` by ${result.export.uploaded_by}` : ""}. Nothing new was stored; that export is selected below.
              </Banner>
            ) : (
              <Banner tone="ok" title="Received">
                Stored and queued for parsing. Its status below updates as soon as the intake finishes.
              </Banner>
            )
          )}
        </div>
      )}
    </Panel>
  );
}
