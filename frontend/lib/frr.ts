/**
 * Firewall Rule Review requests. Every call goes through `requestJson` /
 * `requestText` from lib/api.ts, so a 403, a 409 and a stopped backend each
 * reject with an ApiError that names itself — nothing here resolves to an empty
 * payload on failure.
 */

import { requestJson as j, requestText } from "./api";
import type {
  ApproverGrant, ChangePackage, ExportList, FrrExport, FrrMe, FrrRun, KnowledgeDoc, KnowledgeHit,
  KnowledgeKind, OwnerDecision, OwnerInput, PackageItem, ReviewPage, ReviewQuery, UploadResult,
  FrrDuty, FeedbackBand, FeedbackList, FeedbackRow, FeedbackVerdict, ContextDataset, ContextKind, EffectivePolicyGateway, CompareResult,
} from "./frrTypes";

const enc = encodeURIComponent;

const postJson = (body?: unknown, method = "POST"): RequestInit => ({
  method,
  headers: { "content-type": "application/json" },
  body: body === undefined ? undefined : JSON.stringify(body),
});

const query = (params: Record<string, string | number | boolean | undefined | null>): string => {
  const parts = Object.entries(params)
    .filter(([, v]) => v !== undefined && v !== null && v !== "")
    .map(([k, v]) => `${enc(k)}=${enc(String(v))}`);
  return parts.length ? `?${parts.join("&")}` : "";
};

export const frr = {
  me: () => j<FrrMe>("/api/frr/me"),

  // ── exports ───────────────────────────────────────────────────────────────
  /** The body is the file's raw bytes. The backend reads the stream as-is; the
   *  content type is declared JSON because a Check Point export is JSON. */
  uploadExport: (file: Blob, p: { source: string; filename: string; exported_at?: string }) =>
    j<UploadResult>(`/api/exports${query({ source: p.source, filename: p.filename, exported_at: p.exported_at })}`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: file,
    }),
  /** Large files: a multipart session (Cloud Run caps one request at 32 MiB).
   *  Parts go three at a time; `onProgress` gets the fraction sent. Resolves
   *  once the server has assembled, hashed and registered the export. */
  uploadExportMultipart: async (file: Blob, p: { source: string; filename: string; exported_at?: string },
                                onProgress?: (fraction: number) => void): Promise<UploadResult> => {
    const s = await j<{ upload_id: string; part_size: number }>("/api/exports/uploads",
      postJson({ source: p.source, filename: p.filename, exported_at: p.exported_at }));
    const total = Math.max(1, Math.ceil(file.size / s.part_size));
    let sent = 0;
    let next = 1;
    const worker = async () => {
      while (next <= total) {
        const n = next++;
        const blob = file.slice((n - 1) * s.part_size, Math.min(file.size, n * s.part_size));
        await j(`/api/exports/uploads/${enc(s.upload_id)}/parts/${n}`,
          { method: "PUT", headers: { "content-type": "application/octet-stream" }, body: blob });
        sent += 1;
        onProgress?.(sent / total);
      }
    };
    await Promise.all([worker(), worker(), worker()]);
    await j(`/api/exports/uploads/${enc(s.upload_id)}/complete`, postJson({ parts: total }));
    for (let i = 0; i < 600; i++) {
      const st = await j<{ status: string; export_id: string | null; duplicate: boolean; failure_reason: string | null }>(
        `/api/exports/uploads/${enc(s.upload_id)}`);
      if (st.status === "done" && st.export_id) {
        return { export: await j<FrrExport>(`/api/exports/${enc(st.export_id)}`), job: null, duplicate: st.duplicate };
      }
      if (st.status === "failed") throw new Error(st.failure_reason ?? "the upload could not be assembled");
      await new Promise((r) => setTimeout(r, 1000));
    }
    throw new Error("the upload was assembled but not registered within 10 minutes; check Exports later");
  },
  exports: (p: { limit?: number; before?: string } = {}) =>
    j<ExportList>(`/api/exports${query({ limit: p.limit ?? 50, before: p.before })}`),
  exportById: (id: string) => j<FrrExport>(`/api/exports/${enc(id)}`),
  review: (id: string, q: ReviewQuery = {}) =>
    j<ReviewPage>(`/api/exports/${enc(id)}/review${query({
      band: q.band, check: q.check, flagged_only: q.flagged_only ?? true, limit: q.limit ?? 100, offset: q.offset ?? 0,
    })}`),

  // ── agent runs ────────────────────────────────────────────────────────────
  startRun: (exportId: string) => j<FrrRun>(`/api/exports/${enc(exportId)}/review-runs`, postJson()),
  run: (runId: string) => j<FrrRun>(`/api/frr/runs/${enc(runId)}`),

  // ── change packages ───────────────────────────────────────────────────────
  draftPackage: (exportId: string, supersede = false) =>
    j<ChangePackage>(`/api/exports/${enc(exportId)}/change-package${supersede ? "?supersede=true" : ""}`, postJson()),
  pkg: (id: string) => j<ChangePackage>(`/api/change-packages/${enc(id)}`),
  decideItem: (pkgId: string, itemId: string, body: { decision: OwnerDecision; input?: OwnerInput; note?: string }) =>
    j<PackageItem>(`/api/change-packages/${enc(pkgId)}/items/${enc(itemId)}`, postJson(body, "PUT")),
  validate: (pkgId: string, note?: string) =>
    j<ChangePackage>(`/api/change-packages/${enc(pkgId)}/validate`, postJson({ note: note || undefined })),
  decide: (pkgId: string, decision: "approve" | "reject", note?: string) =>
    j<ChangePackage>(`/api/change-packages/${enc(pkgId)}/decision`, postJson({ decision, note: note || undefined })),
  runbook: (pkgId: string) => requestText(`/api/change-packages/${enc(pkgId)}/runbook`),

  compare: (exportId: string, baseline: string) =>
    j<CompareResult>(`/api/exports/${enc(exportId)}/compare${query({ baseline })}`),
  /** Same-origin URL; the browser downloads it with the session cookie. */
  registerCsvUrl: (exportId: string, q: { band?: string; check?: string; flagged_only?: boolean } = {}) =>
    `/api/exports/${enc(exportId)}/register.csv${query({ band: q.band, check: q.check, flagged_only: q.flagged_only ?? true })}`,
  effectivePolicy: (exportId: string, layer: string, gateway: string) =>
    j<EffectivePolicyGateway>(`/api/exports/${enc(exportId)}/effective-policy${query({ layer, gateway })}`),

  // ── context datasets (CMDB/IPAM, flows) ──────────────────────────────────
  contextDatasets: () => j<{ items: ContextDataset[] }>("/api/context"),
  uploadContext: (kind: ContextKind, file: Blob, filename: string) =>
    j<{ dataset: ContextDataset; duplicate: boolean }>(`/api/context/${kind}${query({ filename })}`, {
      method: "POST", headers: { "content-type": "text/csv" }, body: file,
    }),

  // ── reviewer feedback ─────────────────────────────────────────────────────
  feedback: (exportId: string) => j<FeedbackList>(`/api/exports/${enc(exportId)}/feedback`),
  giveFeedback: (exportId: string, ruleUid: string,
                 body: { check: string; verdict: FeedbackVerdict; suggested_band?: FeedbackBand; comment?: string }) =>
    j<FeedbackRow>(`/api/exports/${enc(exportId)}/review/${enc(ruleUid)}/feedback`, postJson(body, "PUT")),

  // ── approver matrix (admin) ───────────────────────────────────────────────
  approvers: () => j<{ items: ApproverGrant[] }>("/api/admin/frr/approvers"),
  grant: (g: { principal: string; duty: FrrDuty; scope: string }) =>
    j<ApproverGrant>("/api/admin/frr/approvers", postJson(g)),
  revoke: (g: { principal: string; duty: string; scope: string }) =>
    j<{ revoked: boolean }>(`/api/admin/frr/approvers${query(g)}`, { method: "DELETE" }),

  // ── knowledge base ────────────────────────────────────────────────────────
  knowledge: () => j<{ items: KnowledgeDoc[] }>("/api/knowledge"),
  addKnowledge: (kind: KnowledgeKind, title: string, text: string) =>
    j<KnowledgeDoc>(`/api/knowledge${query({ kind, title })}`, {
      method: "POST",
      headers: { "content-type": "text/markdown; charset=utf-8" },
      body: text,
    }),
  deleteKnowledge: (docId: string) => j<{ deleted: boolean }>(`/api/knowledge/${enc(docId)}`, { method: "DELETE" }),
  searchKnowledge: (q: string, k = 5) => j<{ items: KnowledgeHit[] }>(`/api/knowledge/search${query({ q, k })}`),
};
