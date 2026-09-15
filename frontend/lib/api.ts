import type {
  ActionItem, AdminMetrics, AiActiveConfig, AiConfigResponse, AiConfigSave, AiTestResult,
  AnalysisCompleteness, AskResult,
  AzureAiAccount, AzureDeployment, AzureDiscovery, AzureResourceGroup, AzureSubscription, CampaignPlan,
  CampaignSubmitResult, ChangeResult, Finding, GraphData, Health, IpLookupResponse, MergeSuggestion, Remediation,
  InventoryResponse, RemediationRevision, SourceCard, StagedChange, ToolInfo,
} from "./types";

// The topology canvas's two reads. A second import statement rather than five
// more names in the block above, so this addition cannot collide with an edit
// to the original list.
import type { AnalysisState, ResilienceResponse, TopologyResponse } from "./types";

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
} & AnalysisCompleteness & Provenance;

/**
 * ONE PAGE of /api/findings — never the estate.
 *
 * `findings` was typed as the whole set, so every band counter on the console is
 * computed over at most `limit` rows and reports a number smaller than the truth
 * with nothing on screen saying so. The endpoint has always sent the fields that
 * make that visible; the types dropped them on the floor.
 *
 * `total` is the count for the WHOLE snapshot and `has_more` says this page is
 * not all of it — `has_more` comes from an overshoot row the server actually
 * fetched, so it is exact even when `total` was counted by a separate statement.
 * `next_cursor` is non-null exactly when `has_more` is true and must be passed
 * back verbatim; it is a keyset token, not an offset.
 */
export type FindingsPage = {
  findings: Finding[];
  /** Findings in the snapshot, not on this page. */
  total: number;
  /** The page size the server applied (it clamps what was asked for). */
  limit: number;
  /** Opaque continuation token, or null when this page is the last one. */
  next_cursor: string | null;
  has_more: boolean;
} & AnalysisCompleteness & Provenance;

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

// ───────────────────────────────────────────────────────────────────────────
// Azure discovery + AI configuration
//
// These reads back the admin Configuration screen, and they carry two
// obligations the rest of this file does not.
//
// 1. AN EMPTY ANSWER IS AMBIGUOUS. Azure Resource Manager filters list results
//    by role assignment, so an identity with no Reader receives an empty 200
//    rather than a 403 — `[]` from ARM equally means "the subscription has none"
//    and "you may not see any". The backend refuses to pass that ambiguity on:
//    every discovery route raises a TYPED error envelope
//    (`{code, detail, error, azure_detail}` — see `_arm_exception` in
//    backend/app/main.py) instead of returning `[]`, so `[]` on the wire is a
//    real, positive "Azure was asked, and answered none". `armList` below keeps
//    that guarantee intact on this side: a body it cannot read becomes a
//    REPORTED FAILURE, never an empty list.
//
// 2. A TRUNCATED LIST IS NOT A LIST. Every discovery route is bounded, and a
//    dropdown silently cut off at the limit fails exactly like an empty one —
//    the operator's resource group is missing and the page says nothing. The
//    bound rides on `x-npr-result-truncated` response headers, which is the
//    reason these calls read the Response themselves rather than going through
//    `j()`, which returns only the parsed body.
// ───────────────────────────────────────────────────────────────────────────

/**
 * A discovery failure carrying ARM's own words.
 *
 * Extends `ApiError`, so every existing consumer — `asApiError`, `ErrorState`,
 * `InlineError` — handles it unchanged and renders the same status + detail as
 * any other failure. The two extra fields are what a discovery panel can say on
 * top of that: `code` is the machine-readable `ArmError.kind`, so the UI can
 * branch on "this identity can see several subscriptions" without parsing an
 * English sentence, and `azureDetail` is ARM's raw message, which for the
 * authorization case names the exact missing permission and scope and is the
 * single most useful string an operator can be handed.
 */
export class AzureDiscoveryError extends ApiError {
  /** `ArmError.kind`: azure_forbidden, azure_subscription_ambiguous, … */
  readonly code?: string;
  /** ARM's own error message, verbatim. */
  readonly azureDetail?: string;

  constructor(status: number, detail: string, path: string, code?: string, azureDetail?: string) {
    super(status, detail, path);
    this.name = "AzureDiscoveryError";
    this.code = code;
    this.azureDetail = azureDetail;
    // `ApiError`'s constructor pins the prototype to ApiError; re-pin it here or
    // `instanceof AzureDiscoveryError` is false in every consumer.
    Object.setPrototypeOf(this, AzureDiscoveryError.prototype);
  }
}

/** True for a JSON object (not an array, not null). */
function isRecord(v: unknown): v is Record<string, unknown> {
  return !!v && typeof v === "object" && !Array.isArray(v);
}

const str = (v: unknown): string | undefined => (typeof v === "string" && v.trim() ? v.trim() : undefined);

/** The bound that stopped a listing, as a sentence, or nothing. */
function truncationReason(r: Response): string | undefined {
  if ((r.headers.get("x-npr-result-truncated") || "").toLowerCase() !== "true") return undefined;
  const by = r.headers.get("x-npr-result-truncated-by") || "the endpoint's limit";
  return (
    `Azure returned more than this endpoint serves in one response, so the list was cut off at ` +
    `${by}. What is missing here is not absent from your subscription — narrow the scope, or use ` +
    `the manual configuration if you already know the target.`
  );
}

/** The backend's own word for "I answered 200 and enumerated nothing, and here
 *  is why". `degraded_reason` is the name the snapshot/graph/findings envelopes
 *  already use for exactly this claim; both are accepted. */
function unavailableReason(body: Record<string, unknown>): string | undefined {
  return str(body.unavailable_reason) ?? str(body.degraded_reason);
}

/**
 * A discovery body -> the items in it, or a rejection.
 *
 * Tolerant about the ENVELOPE (a bare array — what this API build serves — or
 * `{items: [...]}` / `{<key>: [...]}`) and strict about the CONTENT: a body with
 * no array in it throws rather than yielding `[]`, because the caller renders an
 * empty list as "Azure answered none" and no unreadable body earns that claim.
 */
function asItems<T>(body: unknown, key: string, url: string): { items: T[]; reason?: string } {
  if (Array.isArray(body)) return { items: body as T[] };
  if (isRecord(body)) {
    const list = body[key] ?? body.items;
    if (Array.isArray(list)) return { items: list as T[], reason: unavailableReason(body) };
    // An object carrying a reason and no list is still a legible answer: the
    // lookup did not happen, and saying so is the point of the field.
    const reason = unavailableReason(body);
    if (reason) return { items: [], reason };
  }
  throw new ApiError(
    200,
    `The API answered, but not with the ${key} shape this screen reads (an array of ${key}, ` +
      `optionally wrapped). The frontend and backend are probably different builds — nothing ` +
      `about your Azure estate can be concluded from this.`,
    url,
  );
}

/**
 * One discovery read. Reads the Response itself (rather than going through
 * `j()`) for the truncation headers and for ARM's typed error envelope, but
 * delegates to the SAME dead-upstream classification every other call uses, so a
 * stopped backend still reads as "nothing answered at the API" here.
 */
async function armList<T>(url: string, key: string): Promise<AzureDiscovery<T>> {
  let r: Response;
  try {
    r = await fetch(url, { cache: "no-store" });
  } catch (e) {
    throw new ApiError(0, e instanceof Error && e.message ? e.message : "The request could not be sent.", url);
  }
  const parsed = parseBody(await r.text().catch(() => ""));
  if (!r.ok) {
    if (looksLikeDeadUpstream(r)) throw new ApiError(r.status, deadUpstreamDetail(r.status), url, false);
    const body = isRecord(parsed) ? parsed : {};
    throw new AzureDiscoveryError(r.status, detailFor(r.status, parsed, url), url,
                                  str(body.code), str(body.azure_detail));
  }
  const { items, reason } = asItems<T>(parsed, key, url);
  return { items, unavailable_reason: reason, incomplete_reason: truncationReason(r) };
}

/**
 * `GET /api/admin/ai/config` -> `{stored, active}`.
 *
 * The API serves the stored row FLAT, with `resolved` + `azure_ready` +
 * `azure_reason` + `azure_api_key_present` alongside it; this splits the two
 * apart, because they answer different questions and the screen renders both.
 * When there is no resolution block it leaves `active` UNSET rather than copying
 * `stored` into it — that asymmetry is the point. A screen that assumed saved ==
 * live would assert the operator's choice is in effect on exactly the
 * deployments where it is not: a stale read, an unreachable store, or the
 * AI_CONFIG_IGNORE_DB break-glass.
 */
function asAiConfig(body: unknown, url: string): AiConfigResponse {
  if (isRecord(body)) {
    // `{stored, active}` if some build ever serves it that way…
    const nested = isRecord(body.stored) ? body.stored : undefined;
    // …otherwise the flat form, recognised by the two fields that make it a
    // configuration read rather than an arbitrary object.
    const flat = !nested && "provider" in body && "source" in body ? body : undefined;
    const stored = nested ?? flat;
    if (stored) {
      const resolved = isRecord(body.resolved) ? body.resolved : isRecord(body.active) ? body.active : undefined;
      return {
        stored: stored as unknown as AiConfigResponse["stored"],
        active: resolved
          ? ({
              ...resolved,
              // Readiness and the key indicator sit beside `resolved` on the
              // wire; the screen reads them as part of the active configuration
              // because that is the question they answer.
              ready: typeof body.azure_ready === "boolean" ? body.azure_ready : undefined,
              reason: str(body.azure_reason) ?? null,
              key_present: typeof body.azure_api_key_present === "boolean" ? body.azure_api_key_present : undefined,
            } as unknown as AiActiveConfig)
          : undefined,
        default_api_version: str(body.default_api_version),
        providers: Array.isArray(body.providers) ? (body.providers as string[]) : undefined,
      };
    }
  }
  throw new ApiError(
    200,
    "The API answered, but not with the AI-configuration shape this screen reads (the stored row, " +
      "plus a `resolved` block). The frontend and backend are probably different builds — the " +
      "configuration below cannot be shown, and it must not be guessed at.",
    url,
  );
}

/** `?subscription=` only when one was chosen. Omitted, the backend resolves it
 *  itself — and refuses to guess when more than one is visible, which is why the
 *  screen has a subscription dropdown at all. */
const subQ = (subscription?: string) => (subscription ? `subscription=${encodeURIComponent(subscription)}` : "");
const joinQ = (...parts: (string | undefined)[]) => {
  const q = parts.filter(Boolean).join("&");
  return q ? `?${q}` : "";
};

const post = (body?: unknown): RequestInit =>
  ({ method: "POST", headers: { "content-type": "application/json" }, body: body ? JSON.stringify(body) : undefined });

const qs = (snap?: string) => (snap ? `?snapshot=${encodeURIComponent(snap)}` : "");

/**
 * How `/api/inventory`'s `ip` filter is interpreted. This is SET ARITHMETIC over
 * address blocks, not a substring match, and the four members are four different
 * questions — which is why the mode travels on the wire beside the address
 * instead of being a default the user cannot see:
 *
 *   intersects    — any overlap at all between the entity's addresses and the
 *                   block asked about. The forgiving one, and the default.
 *   contains      — entities whose own block CONTAINS what was typed (the
 *                   supernet: "which subnet is this host in?").
 *   contained_by  — entities whose addresses fall INSIDE what was typed
 *                   ("10.30.0.0/16" -> every host in it).
 *   exact         — the address or block exactly as written, and nothing else.
 */
export type IpFilterMode = "intersects" | "contains" | "contained_by" | "exact";

/** The inventory screen's filter state, as query params. Every field is
 *  server-side on purpose: the table is paged, so a filter applied in the
 *  browser would narrow one page and report its `total` as the estate's. */
export interface InventoryQuery {
  snapshot?: string;
  /** Free text over name / address / tag. */
  q?: string;
  /** An address or CIDR block, read under `ip_mode`. */
  ip?: string;
  ip_mode?: IpFilterMode;
  /** One source tool key, as `facets.sources` spells it. */
  source?: string;
  /** Facet selections, passed as repeated params. The values are echoed back
   *  from `facets` verbatim — they are the backend's spelling, not ours. */
  kind?: string[];
  vlan?: string[];
  zone?: string[];
  limit?: number;
  offset?: number;
}

const inventoryQs = (p: InventoryQuery): string => {
  const u = new URLSearchParams();
  const put = (k: string, v: string | number | undefined) => {
    if (v !== undefined && v !== "") u.append(k, String(v));
  };
  put("snapshot", p.snapshot);
  put("q", p.q?.trim() || undefined);
  // `ip` and `ip_mode` are sent as a pair or not at all: an address with no mode
  // beside it is a containment question with an invisible answer.
  if (p.ip?.trim()) {
    u.append("ip", p.ip.trim());
    u.append("ip_mode", p.ip_mode ?? "intersects");
  }
  put("source", p.source);
  for (const v of p.kind ?? []) put("kind", v);
  for (const v of p.vlan ?? []) put("vlan", v);
  for (const v of p.zone ?? []) put("zone", v);
  put("limit", p.limit);
  put("offset", p.offset);
  const s = u.toString();
  return s ? `?${s}` : "";
};

/**
 * `GET /api/topology` — the lanes, outside-in, and the links between them.
 *
 * Two fields on it are the whole reason the canvas can be trusted, and a caller
 * that reads past either is drawing a picture that claims more than the payload
 * does. `TopoLane.observed: false` means NOTHING was seen at that layer: the
 * lane renders as a named absence carrying its reason and the console API that
 * would fill it, never as a faded device. `caps` says what this response left
 * out — it is present from the first commit rather than added when payloads
 * grew, because silent truncation reads as "covered everything".
 */
export type TopologyPayload = TopologyResponse & AnalysisState & Provenance;

/**
 * `GET /api/resilience` — single points of failure, and what each one takes
 * with it.
 *
 * `analysed: false` is the field that stops an empty `findings` from reading as
 * a clean bill of health, and `blast_radius` is measured by the engine over the
 * whole adjacency. The canvas ANIMATES the blast radius; it never recomputes
 * one in the browser, because a number derived from the lanes that happen to be
 * on screen would disagree with the report for a reason nobody could find.
 */
export type ResiliencePayload = ResilienceResponse & Provenance;

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
  findings: (snap?: string) => j<FindingsPage>(`/api/findings${qs(snap)}`),
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

  // ── AI configuration (admin) ────────────────────────────────────────────
  /** The saved provider choice and the one this deployment is actually routing
   *  on. Admin-only; 503 when the store exists but could not be read, which is
   *  NOT the same answer as "nothing is configured". */
  aiConfig: () => j<unknown>("/api/admin/ai/config").then((b) => asAiConfig(b, "/api/admin/ai/config")),
  /** Save the choice. No API key is sent, because the row cannot hold one — see
   *  lib/types.ts and db/migrations/0004_ai_config.sql.
   *
   *  Typed `unknown` on purpose: the screen re-reads `aiConfig()` after a save
   *  rather than trusting the echo, because "the PUT returned 200" and "this
   *  deployment is now routing on what I saved" are different facts — the stored
   *  row loses to a break-glass env var, and only the re-read can show that. */
  saveAiConfig: (body: AiConfigSave) =>
    j<unknown>("/api/admin/ai/config", { method: "PUT", headers: { "content-type": "application/json" }, body: JSON.stringify(body) }),
  /** Make one real model call with the SAVED configuration and report what came
   *  back. A 200 with `ok: false` is a reachable provider that refused; only a
   *  rejection here means the request never got an answer. */
  testAiConfig: () => j<AiTestResult>("/api/admin/ai/test", post()),

  // ── Azure discovery (admin) ─────────────────────────────────────────────
  azureSubscriptions: () =>
    armList<AzureSubscription>("/api/admin/azure/subscriptions", "subscriptions"),
  azureResourceGroups: (subscription?: string) =>
    armList<AzureResourceGroup>(`/api/admin/azure/resource-groups${joinQ(subQ(subscription))}`, "resource_groups"),
  azureAccounts: (resourceGroup: string, subscription?: string) =>
    armList<AzureAiAccount>(
      `/api/admin/azure/accounts${joinQ(`resource_group=${encodeURIComponent(resourceGroup)}`, subQ(subscription))}`,
      "accounts",
    ),
  azureDeployments: (resourceGroup: string, account: string, subscription?: string) =>
    armList<AzureDeployment>(
      `/api/admin/azure/deployments${joinQ(
        `resource_group=${encodeURIComponent(resourceGroup)}`,
        `account=${encodeURIComponent(account)}`,
        subQ(subscription),
      )}`,
      "deployments",
    ),

  // ── The infrastructure layer ─────────────────────────────────────────
  /**
   * Every source this deployment collects from, as cards.
   *
   * Read by the address drawer for one reason beyond the Connectors screen:
   * `simulated` and `tier`. A tool badge that does not say a source is a seeded
   * export is a badge that implies a live connector, and this build's exports
   * are all seeded. A caller that cannot load this map must therefore render
   * provenance as UNKNOWN rather than falling back to the flattering reading.
   */
  sources: (snap?: string) => j<{ sources: SourceCard[] }>(`/api/sources${qs(snap)}`),

  /**
   * Everything one address is involved in — what holds it, which rules reach it,
   * which findings name it, and whether an allow path from the internet exists.
   *
   * `mode` is the inventory filter's containment vocabulary
   * (`intersects` | `exact` | `contains` | `contained_by`) and is sent
   * explicitly on every call: the group the drawer exists to show — rules that
   * COVER this address without naming it — only appears under a mode that looks
   * outward from the query, so which mode ran has to be a stated fact on both
   * the request and the rendered answer, never a default nobody can see.
   */
  ipLookup: (address: string, mode: string, snap?: string) =>
    j<IpLookupResponse>(
      `/api/ip${joinQ(
        `address=${encodeURIComponent(address)}`,
        `mode=${encodeURIComponent(mode)}`,
        snap ? `snapshot=${encodeURIComponent(snap)}` : undefined,
      )}`,
    ),

  /**
   * ONE PAGE of the estate inventory, plus the estate's own counts and the
   * facet counts the filters are drawn from.
   *
   * THREE THINGS ON THE PAYLOAD ARE NOT INTERCHANGEABLE and a caller that
   * collapses them is back to the empty-vs-failed lie in a new place:
   *
   *   `counts`  is the ESTATE readout ("I have these many subnets"), and a
   *             member of it is `number | null` — `null` meaning no onboarded
   *             source declares that figure. It renders as an em-dash, never 0.
   *   `total`   is how many entities match the CURRENT filter, which is not the
   *             number of rows in `items`: `items` is one `limit`-sized window.
   *   `has_more`says this page is not the whole match set. A table that hides it
   *             reads as a complete one.
   *
   * Filtering is entirely server-side (see `InventoryQuery`) so `total` and the
   * rows on screen are answers to the same question.
   */
  inventory: (params: InventoryQuery = {}) =>
    j<InventoryResponse>(`/api/inventory${inventoryQs(params)}`),

  /** The reconstructed topology the canvas draws: lanes, links, VLANs, counts,
   *  the unlinked devices nothing reported a cable for, and the caps. */
  topology: (snap?: string) => j<TopologyPayload>(`/api/topology${qs(snap)}`),

  /** Single points of failure, with the blast radius behind each one. */
  resilience: (snap?: string) => j<ResiliencePayload>(`/api/resilience${qs(snap)}`),
};
