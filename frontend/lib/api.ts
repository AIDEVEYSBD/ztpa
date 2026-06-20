import type {
  ActionItem, AskResult, ChangeResult, Finding, GraphData, Health, MergeSuggestion, Remediation,
} from "./types";

async function j<T>(url: string, init?: RequestInit): Promise<T> {
  const r = await fetch(url, { cache: "no-store", ...init });
  if (!r.ok) throw new Error(`${url} -> ${r.status}`);
  return r.json() as Promise<T>;
}

const post = (body?: unknown): RequestInit =>
  ({ method: "POST", headers: { "content-type": "application/json" }, body: body ? JSON.stringify(body) : undefined });

const qs = (snap?: string) => (snap ? `?snapshot=${encodeURIComponent(snap)}` : "");

export const api = {
  health: () => j<Health>("/api/health"),
  recompute: () => j<{ ok: boolean; summary: Record<string, any> }>("/api/recompute", post()),
  scenarios: () => j<{ scenarios: { id: string; label: string; description: string }[]; active: string }>("/api/scenarios"),
  switchDataset: (scenario: string, n = 500) => j<{ ok: boolean; scenario: string; summary: Record<string, any> }>("/api/admin/dataset", post({ scenario, n })),
  snapshots: () => j<{ snapshots: any[]; active: string }>("/api/snapshots"),
  deleteSnapshot: (id: string) => j<{ ok: boolean; deleted: string }>(`/api/snapshots/${encodeURIComponent(id)}`, { method: "DELETE" }),
  ingest: (snap?: string) => j<{ active_scenario: string; sources: any[]; resolved_objects: any[]; canonical_rules: any[] }>(`/api/ingest${qs(snap)}`),
  snapshot: (snap?: string) => j<{ snapshot: any; counts: Record<string, number>; viewing: string; active: string }>(`/api/snapshot${qs(snap)}`),
  graph: (snap?: string) => j<GraphData>(`/api/graph${qs(snap)}`),
  findings: (snap?: string) => j<{ findings: Finding[] }>(`/api/findings${qs(snap)}`),
  actions: (snap?: string) => j<{ actions: ActionItem[]; ranked_by: string }>(`/api/actions${qs(snap)}`),
  explain: (id: string) => j<{ explanation: string; by: string; cached?: boolean; pending?: boolean }>(`/api/findings/${id}/explain`, post()),
  remediate: (id: string) => j<Remediation>(`/api/findings/${id}/remediate`, post()),
  changeRequests: () => j<{ requests: any[] }>("/api/change-requests"),
  changeDecisions: () => j<{ decisions: any[] }>("/api/change-decisions"),
  classify: (body: { request_id?: string; source?: string; destination?: string; service?: string; justification?: string }) =>
    j<ChangeResult>("/api/change/classify", post(body)),
  ask: (question: string) => j<AskResult>("/api/agent/ask", post({ question })),
  askSuggestions: () => j<{ suggestions: string[] }>("/api/agent/suggestions"),
  report: () => j<any>("/api/report"),
  reportNarrative: () => j<{ narrative_md: string; by: string }>("/api/report/narrative"),
  assets: (snap?: string) => j<{ assets: any[]; correlations: any[] }>(`/api/assets${qs(snap)}`),
  mergeSuggestions: () => j<{ suggestions: MergeSuggestion[] }>("/api/assets/merge-suggestions"),
  confirmMerge: (a: string, b: string) => j<{ ok: boolean; merged: string[] }>("/api/assets/merge", post({ a, b })),
  rule: (ref: string, snap?: string) => j<{ ref: string; rules: any[] }>(`/api/rule/${encodeURIComponent(ref)}${qs(snap)}`),
  propose: (sample: unknown, tool_hint: string) =>
    j<any>("/api/connectors/propose", post({ sample, tool_hint })),
};
