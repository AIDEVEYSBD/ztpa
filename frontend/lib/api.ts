import type {
  ActionItem, AdminMetrics, AskResult, CampaignPlan, CampaignSubmitResult, ChangeResult, Finding, GraphData,
  Health, MergeSuggestion, Remediation, RemediationRevision, StagedChange, ToolInfo,
} from "./types";

/**
 * A failed API call, carrying the two facts a UI needs in order to tell the
 * truth about what broke: the HTTP status and FastAPI's `detail`.
 *
 * Why this exists: every call used to reject with `Error("/api/x -> 500")`, so
 * a 403 (your role may not do this), a 409 (the snapshot moved under you) and a
 * dead backend were indistinguishable at the call site — and every screen
 * rendered the same "is the API running?" line, or nothing at all.
 */
export class ApiError extends Error {
  /** HTTP status, or 0 when no response was received at all (see `isNetwork`). */
  readonly status: number;
  /** FastAPI's `{"detail": ...}` payload flattened to one human sentence. */
  readonly detail: string;
  /** Request path, so an error panel can name the resource that failed. */
  readonly path: string;
  /**
   * Did FastAPI itself answer this request?
   *
   * `false` means the status above was minted by something in front of the API —
   * in this app, the Next.js rewrite that proxies /api/* to the backend (see
   * `looksLikeDeadUpstream`). It matters because the two cases have opposite
   * remedies and opposite meanings: "the API logged an error handling this" is
   * a bug report, "nothing is listening at the API" is a process that is not
   * running, and the second must never be reported as the first.
   */
  readonly reachedApi: boolean;

  // `reachedApi` defaults off the status so the transport-failure constructor
  // (`new ApiError(0, ...)`) cannot forget it: status 0 means no response, which
  // by definition never reached the API.
  constructor(status: number, detail: string, path: string, reachedApi: boolean = status !== 0) {
    super(`${path || "request"} -> ${status || "no response"}: ${detail}`);
    this.name = "ApiError";
    this.status = status;
    this.detail = detail;
    this.path = path;
    this.reachedApi = reachedApi;
    // Downlevelled `extends Error` loses the prototype chain, which would make
    // `instanceof ApiError` false in every consumer. Restore it explicitly.
    Object.setPrototypeOf(this, ApiError.prototype);
  }

  /** True when the request never reached a server: backend down, DNS/proxy
   *  failure, or an aborted request. Distinct from any HTTP answer. */
  get isNetwork(): boolean {
    return this.status === 0;
  }

  /**
   * True when the API never answered — whether that surfaced as no response at
   * all (`isNetwork`) or as a status invented on its behalf by the proxy in
   * front of it. This, not `isNetwork`, is the question a UI is actually asking
   * when it wants to say "is the backend up?".
   */
  get apiUnreachable(): boolean {
    return !this.reachedApi;
  }
}

/** Human fallbacks for when the body carries no usable `detail` — a proxy's
 *  HTML 502 page, an empty 500, a response we could not read. */
const FALLBACK_DETAIL: Record<number, string> = {
  400: "The API rejected the request as malformed.",
  401: "Not signed in, or the session has expired.",
  403: "This role is not permitted to perform this action.",
  404: "No such resource on this API build.",
  405: "The API does not accept this method on that path.",
  409: "The request conflicts with the current state of the snapshot.",
  422: "The request body failed the API's validation.",
  429: "Rate limited by the API.",
  500: "The API hit an unhandled error.",
  502: "The proxy could not reach the API.",
  503: "The API is unavailable.",
  504: "The API timed out.",
};

/** Flatten FastAPI's `detail` — a plain string for `HTTPException`, a list of
 *  `{loc, msg}` objects for a 422 — into one readable sentence. */
function flattenDetail(body: unknown): string {
  if (typeof body === "string") return body.trim();
  if (!body || typeof body !== "object") return "";
  const detail = (body as { detail?: unknown }).detail;
  if (typeof detail === "string") return detail.trim();
  if (Array.isArray(detail)) {
    return detail
      .map((d) => {
        if (typeof d === "string") return d;
        const loc = Array.isArray((d as any)?.loc) ? (d as any).loc.join(".") : undefined;
        const msg = (d as any)?.msg ?? JSON.stringify(d);
        return loc ? `${loc}: ${msg}` : String(msg);
      })
      .join("; ");
  }
  if (detail != null) return JSON.stringify(detail);
  // Some handlers answer `{"error": "..."}`; take that rather than nothing.
  const err = (body as { error?: unknown }).error;
  return typeof err === "string" ? err.trim() : "";
}

/** A response body, parsed as far as it can be: JSON when it is JSON, a short
 *  plain-text excerpt when it is not, and "" for an HTML error page (that is a
 *  proxy talking, not the API, and pasting markup into a panel helps nobody). */
function parseBody(text: string): unknown {
  if (!text) return text;
  try {
    return JSON.parse(text);
  } catch {
    return text.trimStart().startsWith("<") ? "" : text.slice(0, 300);
  }
}

/** Status + body -> one human sentence. A body we cannot read is NOT swallowed:
 *  the status is the fact we surface, and FALLBACK_DETAIL puts it into words. */
function detailFor(status: number, parsed: unknown, path: string): string {
  const flat = flattenDetail(parsed);
  return flat || FALLBACK_DETAIL[status] || `${path} failed with HTTP ${status}.`;
}

/**
 * THE DEAD BACKEND THAT LOOKED LIKE AN APPLICATION BUG.
 *
 * The browser never talks to FastAPI directly: `next.config.mjs` rewrites
 * /api/* to BACKEND_URL, so every call goes through the Next server. When
 * nothing is listening on the backend port, that proxy hop fails with
 * ECONNREFUSED and Next answers the browser itself:
 *
 *     HTTP/1.1 500 Internal Server Error
 *     (no content-type header at all)
 *     Internal Server Error
 *
 * — measured, not assumed, against `next start` 14.2.35 with the backend
 * stopped. `fetch` resolves, so the transport-failure branch below never fires,
 * `isNetwork` stays false, and the 502 fallback text never applies. The console
 * then told the user "The API logged an error handling this request. Retrying
 * may work; if it does not, the server log has the request id" — about a process
 * that was not running, whose log therefore contains nothing, and which no
 * amount of retrying will summon. That is the same class of defect Phase 0
 * existed to fix, arriving from the other side: a failure reported as the wrong
 * failure.
 *
 * THE DISCRIMINATOR IS THE CONTENT-TYPE HEADER, and it has to be, because the
 * BODY is ambiguous: Starlette's own last-resort handler answers an unhandled
 * exception with the plain text `Internal Server Error` too — byte for byte the
 * same string. What separates them is that every response FastAPI produces
 * declares a type (`application/json` for HTTPException, for the global
 * {error, request_id} handler and for every route; `text/plain` for Starlette's
 * fallback), while the Next proxy failure carries NO content-type at all. So:
 *
 *   json          -> the API answered. Never an outage.
 *   text/plain    -> the API answered, badly. Its log DOES have this request.
 *   html          -> a gateway error page. This app's API never serves HTML.
 *   absent        -> nobody wrote a body on purpose. The proxy is talking.
 *
 * The rule errs deliberately toward "the API spoke": anything that declared a
 * type is credited to the API, so a real 500 can never be explained away as an
 * outage. The cost is that a future proxy which starts labelling its errors
 * `text/plain` would go undetected — which is why the console test suite drives
 * this path against a genuinely stopped backend rather than trusting the rule.
 */
function looksLikeDeadUpstream(r: Response): boolean {
  // Only the statuses a proxy invents when it cannot reach its upstream. A 4xx
  // is always an answer about the request itself, so it is always the API's.
  if (![500, 502, 503, 504].includes(r.status)) return false;
  const type = (r.headers.get("content-type") || "").toLowerCase();
  return type === "" || type.includes("html");
}

/** What to tell the user when the request never reached the API. Names the one
 *  thing that is actually wrong, and the one thing that fixes it. */
function deadUpstreamDetail(status: number): string {
  return (
    `Nothing answered at the API. This app proxies /api/* to the backend, the ` +
    `connection failed, and the proxy returned HTTP ${status} on its behalf — ` +
    `so this is not an error the API logged, it is the API not running or not ` +
    `reachable from this server.`
  );
}

/** Turn an already-read failure body into the ApiError that describes it — the
 *  single place that decides whether the API answered or something spoke for it. */
function failureFrom(r: Response, parsed: unknown, path: string): ApiError {
  return looksLikeDeadUpstream(r)
    ? new ApiError(r.status, deadUpstreamDetail(r.status), path, false)
    : new ApiError(r.status, detailFor(r.status, parsed, path), path);
}

/** Read the failure body once and classify it. */
async function readFailure(r: Response, path: string): Promise<ApiError> {
  return failureFrom(r, parseBody(await r.text().catch(() => "")), path);
}

/** Normalize anything thrown at a call site into an ApiError, so an error state
 *  always has a status + detail to render no matter what actually failed. */
export function asApiError(e: unknown): ApiError {
  if (e instanceof ApiError) return e;
  const msg = e instanceof Error ? e.message : String(e);
  return new ApiError(0, msg || "Unknown error.", "");
}

/**
 * The single fetch wrapper. Rejects with `ApiError` on ANY non-2xx and on
 * transport failure — never with a bare Error, and never resolving to a
 * plausible-looking empty payload, which is what made a dead database and a
 * clean estate render identically.
 */
async function j<T>(url: string, init?: RequestInit): Promise<T> {
  let r: Response;
  try {
    r = await fetch(url, { cache: "no-store", ...init });
  } catch (e) {
    // fetch only rejects on transport failure (server down, DNS, abort, CORS).
    // Status 0 lets a caller say "no answer" instead of guessing a status.
    throw new ApiError(0, e instanceof Error && e.message ? e.message : "The request could not be sent.", url);
  }
  if (!r.ok) throw await readFailure(r, url);
  try {
    return (await r.json()) as T;
  } catch {
    // A 2xx whose body is not JSON means the proxy answered, not the API.
    throw new ApiError(r.status, "The API returned a success status with a body that is not JSON.", url);
  }
}

/**
 * `/api/health` with its degraded fields. The backend's payload is additive, and
 * only this call reads the extra keys, so they are declared here rather than
 * widening the shared `Health` type.
 */
export type HealthReport = Health & {
  /** Why the backend calls itself degraded. Present (and non-empty) iff status is "degraded". */
  degraded_reasons?: string[];
  /** False = the x-npr-* identity headers are trusted with no shared secret. */
  proxy_auth?: boolean;
  snapshot?: { persisted: boolean | null; inputs_ok: boolean };
  request_id?: string;
};

/**
 * The one endpoint whose FAILURE STATUS IS DATA.
 *
 * /api/health answers 503 when it is running but cannot do its whole job (no
 * database, an unpersisted snapshot, a failed rebuild), and that body is the
 * most informative payload in the product: it names every reason, and carries
 * the `ai` block the residency chip needs. Putting it through `j()` threw the
 * body away and left the console unable to tell "degraded" from "dead" — with no
 * database it painted a red API-is-down panel on every screen and a grey "AI
 * residency unknown" chip, out of a backend that was answering fine and had just
 * told it which provider it was using.
 *
 * So a 503 carrying a health payload RESOLVES, and the caller renders the
 * degradation. Anything else — a 500, a 404 from a stale build, an HTML page
 * from a proxy, no response at all — still rejects with ApiError, because those
 * really are failures to read health.
 */
async function readHealth(): Promise<HealthReport> {
  const url = "/api/health";
  let r: Response;
  try {
    r = await fetch(url, { cache: "no-store" });
  } catch (e) {
    throw new ApiError(0, e instanceof Error && e.message ? e.message : "The request could not be sent.", url);
  }
  const parsed = parseBody(await r.text().catch(() => ""));
  const isReport = !!parsed && typeof parsed === "object" && typeof (parsed as HealthReport).status === "string";
  // 503 is this endpoint's considered answer about itself, not a transport
  // failure — but only when the body actually is the report.
  if (isReport && (r.ok || r.status === 503)) return parsed as HealthReport;
  // Not the report. It may still not be the API talking at all: with the backend
  // stopped, THIS is the call that decides whether the whole console reads
  // "degraded" or "down", so it must not mistake the proxy's 500 for the API's.
  throw failureFrom(r, parsed, url);
}

/**
 * WHERE a dashboard read came from, attached by the backend to every payload it
 * serves for a snapshot.
 *
 * `database` is the system of record. `engine_memory` means Postgres could not
 * be read and the running engine recomputed the answer instead — real numbers,
 * but not the persisted ones, and nothing durable is being written. `unavailable`
 * means neither could answer and the payload is EMPTY ON PURPOSE: the snapshot
 * timeline is a history of persisted runs, so it does not exist without the
 * store, and `[]` there must render as "unknown", never as "none".
 *
 * A caller that ignores this field renders a true number; a caller that reads it
 * can say which of those three things it is looking at.
 */
export type ServedFrom = "database" | "engine_memory" | "unavailable";

export type Provenance = {
  served_from?: ServedFrom;
  /** Why the read fell back. Present iff `served_from` is not "database". */
  degraded_reason?: string;
};

export type SnapshotSummary = {
  snapshot: any;
  counts: Record<string, number>;
  viewing: string;
  active: string;
} & Provenance;

export type SnapshotList = { snapshots: any[]; active: string } & Provenance;

/**
 * One row of the governance audit trail (`ztpa.audit_log`).
 *
 * `actor` is the coarse kind the CHECK constraint allows — 'agent' | 'user' |
 * 'system' — and is NOT a person. The person is `actor_email` / `actor_sub`,
 * written inside `db.audit()` from the request context so no call site can
 * forget them, and `actor_role` is the role that request carried. All three are
 * optional here on purpose: rows written before those columns existed have
 * them null, and an audit screen that rendered a missing actor as a present one
 * would be lying about exactly the field the screen exists to show. The UI
 * renders "unattributed" for a null, never a guess.
 */
export type AuditEntry = {
  id: string;
  ts: string;
  actor: string;
  action: string;
  subject?: string | null;
  snapshot_id?: string | null;
  detail?: Record<string, unknown> | null;
  actor_email?: string | null;
  actor_sub?: string | null;
  actor_role?: string | null;
};

/** A page of the audit trail. `total` is the count of ALL matching rows, not of
 *  `items` — the pager needs to know what it is a window onto. */
export type AuditPage = {
  items: AuditEntry[];
  total: number;
  limit: number;
  offset: number;
};

const post = (body?: unknown): RequestInit =>
  ({ method: "POST", headers: { "content-type": "application/json" }, body: body ? JSON.stringify(body) : undefined });

const qs = (snap?: string) => (snap ? `?snapshot=${encodeURIComponent(snap)}` : "");

export const api = {
  health: readHealth,
  recompute: () => j<{ ok: boolean; summary: Record<string, any> }>("/api/recompute", post()),
  scenarios: () => j<{ scenarios: { id: string; label: string; description: string }[]; active: string }>("/api/scenarios"),
  switchDataset: (scenario: string, n = 500) => j<{ ok: boolean; scenario: string; summary: Record<string, any> }>("/api/admin/dataset", post({ scenario, n })),
  snapshots: () => j<SnapshotList>("/api/snapshots"),
  deleteSnapshot: (id: string) => j<{ ok: boolean; deleted: string }>(`/api/snapshots/${encodeURIComponent(id)}`, { method: "DELETE" }),
  ingest: (snap?: string) => j<{ active_scenario: string; sources: any[]; resolved_objects: any[]; canonical_rules: any[] }>(`/api/ingest${qs(snap)}`),
  snapshot: (snap?: string) => j<SnapshotSummary>(`/api/snapshot${qs(snap)}`),
  graph: (snap?: string) => j<GraphData & Provenance>(`/api/graph${qs(snap)}`),
  findings: (snap?: string) => j<{ findings: Finding[] } & Provenance>(`/api/findings${qs(snap)}`),
  actions: (snap?: string) => j<{ actions: ActionItem[]; ranked_by: string } & Provenance>(`/api/actions${qs(snap)}`),
  explain: (id: string) => j<{ explanation: string; by: string; cached?: boolean; pending?: boolean }>(`/api/findings/${id}/explain`, post()),
  remediate: (id: string) => j<Remediation>(`/api/findings/${id}/remediate`, post()),
  remediateRefine: (id: string, comment: string, prior_change?: Record<string, any>) =>
    j<Remediation>(`/api/findings/${id}/remediate/refine`, post({ comment, prior_change })),
  remediationThread: (id: string) => j<{ revisions: RemediationRevision[] }>(`/api/findings/${id}/remediation-thread`),
  campaignGet: () => j<{ plan: CampaignPlan | null }>("/api/campaign/plan"),
  campaignPlan: (target_bands?: string[]) => j<CampaignPlan>("/api/campaign/plan", post(target_bands ? { target_bands } : {})),
  campaignSubmit: (justification?: string) => j<CampaignSubmitResult>("/api/campaign/submit", post(justification ? { justification } : {})),
  changeSubmit: (body: { kind?: string; finding_id: string; change: Record<string, any>; revision_id?: string; justification?: string }) =>
    j<{ request_id: string; kind: string; decision: any; target_tool: string }>("/api/change/submit", post({ kind: "remediation", ...body })),
  changeRequests: () => j<{ requests: any[] }>("/api/change-requests"),
  changeDecisions: () => j<{ decisions: any[] }>("/api/change-decisions"),
  classify: (body: { request_id?: string; source?: string; destination?: string; service?: string; justification?: string }) =>
    j<ChangeResult>("/api/change/classify", post(body)),
  rejectChange: (body: { request_id: string; reason?: string }) =>
    j<{ ok: boolean; request_id: string; status: string; rejected_by: string }>("/api/change/reject", post(body)),
  resetDemo: () => j<{ ok: boolean; cleared: Record<string, number>; snapshot_id: string }>("/api/admin/reset-demo", post()),
  sendToStaging: (body: { request_id: string; target_tool?: string; manual_approve?: boolean }) =>
    j<{ ok: boolean; staged_id: string; status: string; target_tool: string }>("/api/staging", post(body)),
  staging: () => j<{ staged: StagedChange[] }>("/api/staging"),
  stagingPush: (id: string) => j<{ staged_id: string; status: string; conflicts: any[]; resolution: any; push_steps: any[] }>(`/api/staging/${encodeURIComponent(id)}/push`, post()),
  stagingDiscard: (id: string) => j<{ ok: boolean; deleted: string }>(`/api/staging/${encodeURIComponent(id)}`, { method: "DELETE" }),
  adminTools: () => j<{ tools: ToolInfo[]; roles: string[] }>("/api/admin/tools"),
  setToolRoles: (key: string, enabled_roles: string[]) => j<{ ok: boolean; tool_key: string; enabled_roles: string[] }>(`/api/admin/tools/${encodeURIComponent(key)}`, post({ enabled_roles })),
  adminMetrics: (days = 30) => j<AdminMetrics>(`/api/admin/metrics?days=${days}`),
  // Admin-only, newest first, `limit` bounded by the API. The offset/limit pair
  // is passed explicitly rather than defaulted here so the screen's pager and
  // the request it makes can never disagree about which window is on screen.
  audit: (limit: number, offset: number) =>
    j<AuditPage>(`/api/audit?limit=${encodeURIComponent(limit)}&offset=${encodeURIComponent(offset)}`),
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
