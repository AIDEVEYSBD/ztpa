"use client";

/**
 * Rule Review · Knowledge (admin) — the standards, exceptions and runbooks the
 * impact assessor retrieves from. The search box runs the same retrieval the
 * assessor runs, so an admin can see exactly which chunks a question surfaces.
 */

import { useCallback, useEffect, useRef, useState } from "react";
import { useSession } from "next-auth/react";
import { BookOpen, Search, Trash2, Upload } from "lucide-react";
import { ApiError, asApiError } from "@/lib/api";
import { frr } from "@/lib/frr";
import type { KnowledgeDoc, KnowledgeHit, KnowledgeKind } from "@/lib/frrTypes";
import { isAdmin, type AppRole } from "@/lib/roles";
import { Button, Chip, Dialog, EmptyState, Field, IconButton, Input, Panel, Segmented, Select, Skeleton, Table, THead, Th, Td, Tr, Textarea } from "../ui";
import { ErrorState } from "../ui/Feedback";
import { ActionError, bytes, when } from "./bits";

const KINDS: { value: KnowledgeKind; label: string }[] = [
  { value: "standard", label: "Standard" },
  { value: "exception", label: "Exception" },
  { value: "runbook", label: "Runbook" },
];

const EXCERPT = 360;

export function KnowledgeAdmin() {
  const { data: session } = useSession();
  const role = ((session?.user as { role?: AppRole | null } | undefined)?.role ?? null) as AppRole | null;

  const [docs, setDocs] = useState<KnowledgeDoc[]>();
  const [err, setErr] = useState<ApiError>();
  const [loading, setLoading] = useState(true);
  const [confirm, setConfirm] = useState<KnowledgeDoc>();
  const [deleting, setDeleting] = useState(false);
  const [delErr, setDelErr] = useState<ApiError>();

  const load = useCallback(() => {
    setLoading(true);
    setErr(undefined);
    frr.knowledge()
      .then((r) => {
        if (!r || !Array.isArray(r.items)) {
          setDocs(undefined);
          setErr(new ApiError(200, "The API answered, but not with the document list shape this screen reads ({items}).", "/api/knowledge"));
          return;
        }
        setDocs(r.items);
      })
      .catch((e) => { setDocs(undefined); setErr(asApiError(e)); })
      .finally(() => setLoading(false));
  }, []);

  useEffect(() => { if (isAdmin(role)) load(); }, [load, role]);

  if (!isAdmin(role)) {
    return <ErrorState resource="the knowledge base" error={new ApiError(403, `Managing the knowledge base is restricted to administrators. Your session carries the role ${role ?? "none"}.`, "/api/knowledge")} />;
  }

  const remove = () => {
    if (!confirm) return;
    setDeleting(true);
    setDelErr(undefined);
    frr.deleteKnowledge(confirm.doc_id)
      .then(() => { setConfirm(undefined); load(); })
      .catch((e) => { setConfirm(undefined); setDelErr(asApiError(e)); })
      .finally(() => setDeleting(false));
  };

  return (
    <div className="space-y-5">
      <p className="max-w-3xl text-[12.5px] leading-[1.55] text-dim">
        The impact assessor grounds each narrative in these documents and cites the chunks it used. Add your rule standards,
        approved exceptions and change runbooks as plain text or Markdown; headings split a document into chunks.
      </p>

      <UploadDoc onAdded={load} />

      <Panel title="Documents" icon={<BookOpen size={13} />} noPadding>
        {err ? (
          <div className="p-4"><ErrorState resource="the knowledge documents" error={err} onRetry={load} /></div>
        ) : loading && !docs ? (
          <div className="space-y-2 p-4">{Array.from({ length: 3 }).map((_, i) => <Skeleton key={i} className="h-9 w-full" />)}</div>
        ) : docs && docs.length === 0 ? (
          <div className="p-4"><EmptyState icon={BookOpen} title="No documents yet"
            sub="Without documents the assessor has nothing to cite, so its narratives rest on the deterministic evidence alone." /></div>
        ) : (
          <Table minWidth={720}>
            <THead><Th>Title</Th><Th>Kind</Th><Th>Chunks</Th><Th>Uploaded</Th><Th><span className="sr-only">Delete</span></Th></THead>
            <tbody>
              {(docs ?? []).map((d) => (
                <Tr key={d.doc_id}>
                  <Td>
                    <div className="font-medium">{d.title}</div>
                    <div className="font-mono text-[10px] text-faint">{d.doc_id}</div>
                  </Td>
                  <Td><Chip variant="neutral">{d.kind}</Chip></Td>
                  <Td className="tnum">{d.chunks}</Td>
                  <Td className="text-dim">{when(d.uploaded_at)}{d.uploaded_by ? ` by ${d.uploaded_by}` : ""}</Td>
                  <Td className="text-right">
                    <IconButton size="sm" tone="err" label={`Delete ${d.title}`} onClick={() => setConfirm(d)}><Trash2 size={13} /></IconButton>
                  </Td>
                </Tr>
              ))}
            </tbody>
          </Table>
        )}
        {delErr && <div className="border-t border-line p-3"><ActionError action="delete the document" error={delErr} /></div>}
      </Panel>

      <SearchPanel />

      {confirm && (
        <Dialog title="Delete this document?" confirmLabel="Delete" confirmTone="err" busy={deleting}
          onClose={() => setConfirm(undefined)} onConfirm={remove}>
          <span className="font-medium text-fg">{confirm.title}</span> and its {confirm.chunks} chunk{confirm.chunks === 1 ? "" : "s"} will
          no longer be retrieved. Narratives already written keep their citations.
        </Dialog>
      )}
    </div>
  );
}

function UploadDoc({ onAdded }: { onAdded: () => void }) {
  const fileRef = useRef<HTMLInputElement>(null);
  const [title, setTitle] = useState("");
  const [kind, setKind] = useState<KnowledgeKind>("standard");
  const [mode, setMode] = useState<"file" | "paste">("file");
  const [file, setFile] = useState<File | null>(null);
  const [text, setText] = useState("");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<ApiError>();
  const [added, setAdded] = useState<KnowledgeDoc>();

  const ready = !!title.trim() && (mode === "file" ? !!file : !!text.trim());

  const submit = () => {
    if (!ready) return;
    setBusy(true);
    setErr(undefined);
    setAdded(undefined);
    const body = mode === "file" && file ? file.text() : Promise.resolve(text);
    body
      .then((t) => frr.addKnowledge(kind, title.trim(), t))
      .then((doc) => {
        setAdded(doc);
        setTitle(""); setText(""); setFile(null);
        if (fileRef.current) fileRef.current.value = "";
        onAdded();
      })
      .catch((e) => setErr(asApiError(e)))
      .finally(() => setBusy(false));
  };

  return (
    <Panel title="Add a document" icon={<Upload size={13} />}>
      <form className="space-y-3" onSubmit={(e) => { e.preventDefault(); submit(); }}>
        <div className="grid gap-3 md:grid-cols-[2fr_1fr]">
          <Field label="Title" htmlFor="kb-title">
            <Input id="kb-title" value={title} maxLength={300} onChange={(e) => setTitle(e.target.value)} placeholder="Firewall rule standard v3" />
          </Field>
          <Field label="Kind" htmlFor="kb-kind">
            <Select id="kb-kind" value={kind} onChange={(e) => setKind(e.target.value as KnowledgeKind)}>
              {KINDS.map((k) => <option key={k.value} value={k.value}>{k.label}</option>)}
            </Select>
          </Field>
        </div>
        <Segmented value={mode} onChange={setMode} options={[{ value: "file", label: "Upload a file" }, { value: "paste", label: "Paste text" }]} />
        {mode === "file" ? (
          <Field label="Text or Markdown file" htmlFor="kb-file" hint={file ? `${file.name} · ${bytes(file.size)}` : "UTF-8 .md or .txt"}>
            <input ref={fileRef} id="kb-file" type="file" accept=".md,.markdown,.txt,text/plain,text/markdown"
              onChange={(e) => setFile(e.target.files?.[0] ?? null)}
              className="focusable block w-full cursor-pointer text-[12.5px] text-dim file:mr-3 file:cursor-pointer file:rounded-sm file:border file:border-line file:bg-raise file:px-2.5 file:py-1 file:text-[12px] file:text-fg" />
          </Field>
        ) : (
          <Field label="Text" htmlFor="kb-text">
            <Textarea id="kb-text" rows={8} value={text} onChange={(e) => setText(e.target.value)} className="font-mono text-[12px]" />
          </Field>
        )}
        <Button type="submit" variant="solid" tone="ink" loading={busy} disabled={!ready}><Upload size={13} /> Add document</Button>
        {err && <ActionError action="add the document" error={err} />}
        {added && <p role="status" className="text-[12px] text-ok">Added “{added.title}”{typeof added.chunks === "number" ? ` (${added.chunks} chunks)` : ""}.</p>}
      </form>
    </Panel>
  );
}

function SearchPanel() {
  const [q, setQ] = useState("");
  const [hits, setHits] = useState<KnowledgeHit[]>();
  const [asked, setAsked] = useState("");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<ApiError>();

  const search = () => {
    const s = q.trim();
    if (s.length < 2) return;
    setBusy(true);
    setErr(undefined);
    frr.searchKnowledge(s, 8)
      .then((r) => { setHits(r.items); setAsked(s); })
      .catch((e) => { setHits(undefined); setErr(asApiError(e)); })
      .finally(() => setBusy(false));
  };

  return (
    <Panel title="What the assessor will see" icon={<Search size={13} />}
      caption="Runs the assessor's retrieval. Try the words a finding would use, e.g. 'any any ssh admin'.">
      <form className="flex flex-wrap items-end gap-2" onSubmit={(e) => { e.preventDefault(); search(); }}>
        <Field label="Query" htmlFor="kb-q" className="min-w-[280px] flex-1">
          <Input id="kb-q" type="search" value={q} maxLength={500} onChange={(e) => setQ(e.target.value)} />
        </Field>
        <Button type="submit" variant="solid" tone="ink" loading={busy} disabled={q.trim().length < 2}>Search</Button>
      </form>
      <div className="mt-3 space-y-2">
        {err && <ErrorState resource="knowledge search results" error={err} onRetry={search} />}
        {hits && hits.length === 0 && (
          <p className="text-[12.5px] text-dim">No chunk matches “{asked}”. The assessor would get no grounding for this query.</p>
        )}
        {hits?.map((h) => (
          <div key={`${h.doc_id}#${h.ord}`} className="rounded-md border border-line p-3">
            <div className="mb-1 flex flex-wrap items-center gap-2">
              <Chip variant="neutral" mono>{h.cite}</Chip>
              <span className="text-[12.5px] font-medium">{h.heading || "(no heading)"}</span>
              <span className="text-[11px] text-faint">in {h.title} · {h.kind}</span>
              <span className="tnum ml-auto font-mono text-[10.5px] text-faint">rank {Number(h.rank).toFixed(3)}</span>
            </div>
            <p className="text-[12px] leading-[1.55] whitespace-pre-wrap text-dim">
              {h.body.length > EXCERPT ? `${h.body.slice(0, EXCERPT)}…` : h.body}
            </p>
          </div>
        ))}
      </div>
    </Panel>
  );
}
