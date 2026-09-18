export type Band = "low" | "medium" | "high" | "critical";

export interface Finding {
  finding_id: string;
  type: string;
  severity: number;
  severity_band: Band;
  forced_critical: boolean;
  signals: Record<string, any>;
  involved: string[];
  raw_refs: string[];
  source_tools: string[];
  /** The ANALYZER's own deterministic one-liner — "RDP open from the internet to
   *  db-prod-01". Specific to this finding, and the right heading for it.
   *
   *  Optional only because it is derived on the way out rather than stored, so a
   *  frontend running against an older backend must not throw. When it is
   *  absent the caller should fall back to the type — but note that is exactly
   *  the fallback that made all five over-permissive findings render under one
   *  identical heading, so treat it as a degraded state, not a normal one. */
  title?: string;
  /** MODEL PROSE, and null until somebody asks for it. Not the only explanation
   *  available — see `engine_explanation`. */
  explanation?: string | null;
  /** The ENGINE's own explanation. Always present, deterministic, no model and
   *  no network: it is written from the finding's own signals by the same code
   *  that computed them.
   *
   *  These two are separate fields and must stay separately attributed. The
   *  console used to render "No explanation has been written for this finding
   *  yet" whenever `explanation` was null, which was false — the engine can
   *  always say what a finding means, because it computed it. What it cannot do
   *  without a model is write prose, and collapsing those two claims into one
   *  empty panel is what made a fully-explained finding look unexamined. */
  engine_explanation?: string;
}

/** One spot where path enumeration hit its scan cap, as `_record_truncations`
 *  reports it: the function that cut, the pair it was walking, and the cap. */
export interface Truncation {
  fn: string;
  src: string;
  dst: string;
  cap: number;
}

/**
 * How complete the analysis behind a payload's numbers was.
 *
 * The backend attaches this (`_analysis_block` in backend/app/main.py) to every
 * read that makes a claim about the estate as a whole — /api/findings,
 * /api/snapshot, /api/report — and the frontend types declared none of it, so a
 * run with a dead analyzer or a truncated path scan rendered byte-identically
 * to a complete one. A count is only worth as much as the analysis behind it.
 *
 * THREE-VALUED, AND `null` IS NOT `[]`. `null` means "this process cannot say"
 * — the in-memory result describes the ACTIVE snapshot only, so a read of a
 * historical one gets null rather than a positive claim that a run nobody
 * analyzed here was clean. A screen must render null as unknown, never as none.
 */
export interface AnalysisCompleteness {
  /** Did every analyzer finish? `null` = not knowable for this snapshot. */
  analysis_complete: boolean | null;
  /** Analyzers that failed, sorted. Non-empty = findings are MISSING. */
  degraded_analyzers: string[] | null;
  /** Path scans that hit their cap, sorted. Non-empty = paths are missing. */
  truncations: Truncation[] | null;
  /** Present only when a later rebuild was REFUSED: this payload is complete
   *  and also not the newest analysis, and both halves have to be said. */
  last_build_rejected?: string;
}

export interface ActionItem {
  action_id: string;
  title: string;
  finding_ids: string[];
  priority: number;
  rationale: string;
}

export interface GraphNode {
  node_id: string;
  kind: string;
  label: string;
  tags: string[];
  ip_set: string[];
  zone: string;
}
export interface GraphEdge {
  src: string;
  dst: string;
  tools: string[];
  services: string[];
  apps?: string[];
}
export interface GraphData {
  nodes: GraphNode[];
  edges: GraphEdge[];
  highlight_path: string[];
  cross_tool_paths: Record<string, any>[];
}

export interface Decision {
  request_id: string;
  decision: "auto_approve" | "escalate";
  criteria: Record<string, boolean>;
  triggering_reason?: string | null;
  delta_summary: Record<string, any>;
  confidence: number;
  forced_escalate: boolean;
  rationale?: string;
  decided_by: string;
}
export interface ChangeResult {
  request: { id: string; title: string; justification?: string };
  delta: Record<string, any>;
  decision: Decision;
}

/** What /api/health reports about the model layer. `active_provider` is the
 *  provider judgment jobs actually route to right now (NOT the configured
 *  preference), and `data_residency` is "local" only while that provider is
 *  ollama — anything else means prompt content leaves this host. The Topbar
 *  residency chip renders straight off these two fields. */
export interface ProviderStatus {
  active_provider: string;
  judge_model: string;
  prose_model: string;
  embed_model: string;
  ollama_reachable: boolean;
  ollama_models: string[];
  data_residency: string;
  anthropic_available: boolean;
  openai_available: boolean;
}

export interface Health {
  status: string;
  db: boolean;
  snapshot_id: string;
  ai: ProviderStatus;
}

export interface Asset {
  asset_id: string;
  asset_key: string;
  kind: string;
  context?: string | null;
  identifiers: Record<string, any>;
  ip_set: string[];
  tags: string[];
  source_tools: string[];
}
export interface Correlation {
  asset_id: string;
  match_key: string;
  confidence: number;
  evidence: Record<string, any>;
}
export interface MergeSuggestion {
  a: string;
  b: string;
  confidence: number;
  name_similarity: number;
  shared_sensitive_tags: string[];
  reason: string;
  a_tools: string[];
  b_tools: string[];
}

export interface AskResult {
  answer: string;
  by: string;
  trace: { tool: string; args: Record<string, any>; result: any }[];
}

export interface RemediationAttempt {
  attempt: number;
  by: string;
  change?: Record<string, any> | null;
  fix_text?: string | null;
  reasoning?: string | null;
  validation?: { resolves?: boolean; introduces_new_criticals?: string[]; error?: string } | null;
  note?: string;
}

/**
 * One step of the advisory layer's work, as the API reports it.
 *
 * `model_call` carries BOTH sides of the exchange so a reader can see what was
 * sent and what came back. A step with `ok: false` is a real step -- a failed
 * call followed by a deterministic fallback is the most useful thing this
 * record shows, and it is what was invisible while the deployment ran against
 * a placeholder API key.
 */
export interface AgentStep {
  kind: "model_call" | "tool" | "deduction" | "fallback" | "note";
  label: string;
  detail?: string | null;
  ok?: boolean;
  ms?: number | null;
  provider?: string | null;
  model?: string | null;
  system?: string | null;
  user?: string | null;
  response?: string | null;
  error?: string | null;
  prompt_tokens?: number | null;
  completion_tokens?: number | null;
  truncated?: boolean;
}

export interface Remediation {
  finding_id: string;
  fix_text: string;
  change: Record<string, any>;
  validation: { resolves: boolean; introduces_new_criticals?: string[]; engine_corrected_ai?: boolean };
  by: string;
  attempts?: number;
  trace?: RemediationAttempt[];
  /** The step-by-step record: model calls with both sides of each exchange,
   *  tool runs, and any fallback taken. Rendered by `AgentTerminal`. */
  agent_trace?: AgentStep[];
  /** Whether a model call actually succeeded. Deliberately separate from `by`,
   *  which can still mention an llm on a path that fell back. */
  used_a_model?: boolean;
  thread_id?: string;
  seq?: number;
  revision_id?: string;
}

export interface RemediationRevision {
  revision_id: string;
  thread_id: string;
  finding_id: string;
  seq: number;
  comment?: string | null;
  fix_text?: string;
  change: Record<string, any>;
  validation: { resolves?: boolean; introduces_new_criticals?: string[] };
  by?: string;
  status: string;
}

/** One ReAct step the triage investigator took: a tool call + engine result, a
 *  reasoned "done", or a recorded bad-tool-call. */
export interface InvestigationStep {
  thought?: string;
  tool?: string;
  args?: Record<string, any>;
  result?: any;
  done?: boolean;
  error?: string;
}

export type BandCounts = { critical: number; high: number; medium: number; low: number };

/** One step of a remediation campaign: a proven fix for one finding (applied) or a
 *  finding the agent could not cleanly fix and handed to a human (needs_review). */
export interface CampaignStep {
  n: number;
  status: "applied" | "needs_review";
  target: { type: string; title: string; band: string; severity: number; refs: string[]; tools: string[] };
  finding_id?: string | null;
  change: Record<string, any>;
  fix_text?: string | null;
  by?: string;
  reason?: string;
  criticals_before?: number;
  criticals_after?: number;
  findings_cleared?: number;
  band_counts_after?: BandCounts;
  sub_attempts?: number;
  sub_trace?: RemediationAttempt[];
}

export interface CampaignSubmitResult {
  submitted: { n: number; finding_id: string; request_id: string; decision: string }[];
  skipped: { n: number; title?: string; reason?: string }[];
  auto_approved: number;
  escalated: number;
}

export interface CampaignPlan {
  target_bands: string[];
  initial_counts: BandCounts;
  final_counts: BandCounts;
  criticals_trajectory: number[];
  steps: CampaignStep[];
  applied_count: number;
  needs_review_count: number;
  residual_findings: CampaignStep["target"][];
  cleared_all_criticals: boolean;
  applied_changes: Record<string, any>[];
  by: string;
}

export interface PushStep {
  key: string;
  label: string;
  status: "ok" | "warn" | "blocked";
  detail: string;
}
export interface Conflict {
  kind: string;
  detail: string;
  against?: string;
  resolution: string;
}
/** `no_op` is a real outcome, not a failure: every detected conflict resolved to
 *  "skip", so the backend deliberately did NOT record the change and the pushed-
 *  changes overlay leaves the record set untouched. It exists so the reported
 *  resolution and the executed action are the same thing. */
export type StagedStatus = "staged" | "pushing" | "pushed" | "no_op" | "conflict" | "failed";

export interface StagedChange {
  staged_id: string;
  request_id: string;
  origin: string;
  kind: string;
  target_tool: string;
  payload: Record<string, any>;
  decision: string;
  status: StagedStatus;
  conflicts: Conflict[];
  resolution: Record<string, any>;
  push_steps: PushStep[];
  /** True when the push contacted nothing (this build has no connector). Not a
   *  stored column, so it is only present on a push response; the card treats an
   *  absent flag as simulated, which is what every build without a connector is. */
  simulated?: boolean;
  created_at?: string;
  pushed_at?: string | null;
  justification?: string | null;
  requested_by?: string | null;
}

/** The POST /api/staging/{id}/push response. Wider than the declared return type
 *  of `api.stagingPush` (lib/api.ts is owned elsewhere): the card reads its
 *  wording off `simulated` rather than hardcoding a claim about a live push. */
export interface PushPlan {
  staged_id: string;
  status: StagedStatus;
  simulated?: boolean;
  conflicts: Conflict[];
  resolution: Record<string, any>;
  push_steps: PushStep[];
}

export interface ToolInfo {
  key: string;
  label: string;
  kind: "agent_tool" | "ai_capability";
  description: string;
  example_output: string;
  enabled_roles: string[];
  metrics: {
    uses: number;
    avg_latency_ms: number;
    total_tokens: number;
    est_cost_usd: number;
    errors: number;
    last_used?: string | null;
  };
}

export interface AdminMetrics {
  days: number;
  totals: { calls: number; tokens: number; cost: number; avg_latency: number; errors: number; p50_latency: number; p95_latency: number };
  by_provider: { provider: string; model: string; calls: number; tokens: number; cost: number }[];
  by_capability: { capability: string; calls: number; tokens: number; cost: number; avg_latency: number }[];
  by_role: { role: string; calls: number; tokens: number }[];
  timeseries: { day: string; calls: number; tokens: number; cost: number }[];
  top_tools: { tool_name: string; uses: number; tokens: number }[];
  decisions: Record<string, number>;
  staging: Record<string, number>;
  snapshots: number;
  findings: number;
  critical: number;
  active_snapshot: string;
}

// ───────────────────────────────────────────────────────────────────────────
// AI provider configuration + Azure discovery (the admin Configuration screen)
//
// Which model this product talks to used to be decided entirely by environment
// variables read at container start, which made "point the advisory layer at
// our own Foundry deployment" a deploy rather than an admin action, invisible
// to the audit trail and attributable to nobody. `ztpa.ai_config` holds that
// choice as one row (db/migrations/0004_ai_config.sql), and these types are the
// wire shapes the Configuration screen reads it back through.
//
// ⚠ THERE IS NO API-KEY FIELD ANYWHERE BELOW, and there must never be one. The
// row says WHICH credential to use (`azure_auth_mode`), never WHAT it is: it is
// read on every model call, lands in every pg_dump, and is served by an admin
// endpoint. A key lives in the deployment's environment (a Container Apps
// secret surfaced as AZURE_AI_API_KEY) and the UI only ever reports whether one
// is present — see `AiActiveConfig.key_present`.
// ───────────────────────────────────────────────────────────────────────────

/** The advisory-provider vocabulary, identical to the backend's `ADVISORY_PROVIDER`
 *  and to `ai_config.PROVIDERS` so a stored value and an environment value are
 *  directly comparable. `auto` is a storable choice, not the absence of one: it
 *  is how an operator says "go back to letting the deployment decide" while
 *  still leaving a record that they said it. */
export type AiProvider = "auto" | "azure" | "openai" | "anthropic" | "ollama";

/** 'identity' — the Container App's managed identity, no secret anywhere.
 *  'key'      — an API key read from the environment. Never from the database. */
export type AzureAuthMode = "identity" | "key";

/**
 * Where the configuration the backend is actually routing on came from.
 * These are NOT interchangeable and the screen renders a different sentence for
 * each, because two of them mean the operator's saved choice is not in effect:
 *
 *   database    — a stored row was read. The operator's choice is live.
 *   defaults    — no row (or no database at all). The environment decided.
 *   stale       — the store is unreadable right now; the last row read in this
 *                 process is still being used. Nothing has moved yet.
 *   unavailable — the store is unreadable and nothing was ever read from it, so
 *                 routing fell back to the environment. Inference may be going
 *                 somewhere the operator did not choose.
 *   ignored     — the AI_CONFIG_IGNORE_DB break-glass is set. Saving still
 *                 writes a row, and this deployment is ignoring it.
 */
export type AiConfigSource = "database" | "defaults" | "stale" | "unavailable" | "ignored";

/** Which of the three sources supplied a resolved field. */
export type AiConfigOrigin = "database" | "environment" | "default";

/** The stored row as `GET /api/admin/ai/config` serves it — the operator's
 *  saved choice, whether or not it is the one in effect. */
export interface AiStoredConfig {
  provider: AiProvider | null;
  azure_endpoint: string | null;
  azure_deployment: string | null;
  azure_api_version: string | null;
  azure_auth_mode: AzureAuthMode;
  azure_client_id: string | null;
  /** Actor email captured at save time (0002's audit identity). Null for a row
   *  written by a script — rendered as "unattributed", never invented. */
  configured_by: string | null;
  updated_at: string | null;
  source: AiConfigSource;
  /** True when a real row is behind these values (fresh or stale). */
  is_stored: boolean;
}

/** The configuration the backend is ACTUALLY routing on, after the row / env /
 *  default order has been applied — with the origin of each block, so the screen
 *  can say "this deployment is on the environment's setting, not yours" instead
 *  of implying the saved row is live. */
export interface AiActiveConfig {
  provider: AiProvider | string;
  provider_origin: AiConfigOrigin;
  azure_endpoint: string;
  azure_deployment: string;
  azure_api_version: string;
  azure_auth_mode: AzureAuthMode | string;
  azure_client_id: string | null;
  azure_origin: AiConfigOrigin;
  config_source: AiConfigSource;
  /** Set when the configured endpoint could not be parsed as one. Kept as data
   *  rather than an exception so a malformed AZURE_AI_ENDPOINT degrades the
   *  advisory layer instead of 500-ing every request. */
  azure_endpoint_error?: string | null;
  /** Can this configuration actually make a call? "Configured" and "will work"
   *  are different questions; conflating them turns a missing secret into 401s
   *  that read to a user as a weak model. */
  ready?: boolean;
  /** Why not, when `ready` is false. Rendered verbatim. */
  reason?: string | null;
  /** Whether this deployment's environment carries the API key that
   *  `azure_auth_mode: "key"` needs. A BOOLEAN, deliberately: the key itself is
   *  never sent to the browser and never stored in the row. */
  key_present?: boolean;
}

/** `GET /api/admin/ai/config`. Two payloads, never merged into one: the saved
 *  choice and the live one differ exactly when something is wrong, and that is
 *  the case the screen exists to show.
 *
 *  `active` is optional because an API build that has not grown the resolution
 *  block yet must degrade to "the saved row is shown, the live one is unknown"
 *  rather than to the far worse "the saved row IS the live one" — which is the
 *  precise claim this screen exists to stop the console from making. */
export interface AiConfigResponse {
  stored: AiStoredConfig;
  active?: AiActiveConfig | null;
  /** The application default used when a stored row names no API version. Read
   *  off the payload rather than hardcoded, so the placeholder in the manual
   *  form cannot drift from what the backend would actually use. */
  default_api_version?: string;
  /** The provider vocabulary this API build accepts. */
  providers?: string[];
}

/** `PUT /api/admin/ai/config` body. Mirrors the row's columns and nothing else —
 *  in particular there is no key field, by construction. */
export interface AiConfigSave {
  provider: AiProvider;
  azure_endpoint?: string | null;
  azure_deployment?: string | null;
  azure_api_version?: string | null;
  azure_auth_mode?: AzureAuthMode;
  azure_client_id?: string | null;
}

/**
 * `POST /api/admin/ai/test` — the backend made ONE real model call with the
 * saved configuration and is reporting what came back.
 *
 * `ok: false` is a successful HTTP response carrying a failed call, and the two
 * must not be collapsed: "the API could not be reached" and "the API reached
 * your Foundry deployment and it answered 401" have completely different fixes.
 */
export interface AiTestResult {
  ok: boolean;
  provider: string;
  /** The deployment/model that was actually called, as the backend names it. */
  model?: string | null;
  endpoint?: string | null;
  latency_ms?: number | null;
  /** The deployment the call actually went to. */
  deployment?: string | null;
  auth_mode?: string | null;
  /** Which configuration was under test, in the backend's words — "the
   *  configuration in force", or "nothing" when it refused to run one. */
  tested?: string | null;
  config_source?: AiConfigSource | string | null;
  /** A short excerpt of what the model said, when it said anything. Evidence
   *  that a real call happened rather than a reachability ping. */
  sample?: string | null;
  /** The real error, verbatim, when `ok` is false. */
  error?: string | null;
}

/** One Azure subscription this deployment's identity can see, from
 *  `GET /api/admin/azure/subscriptions`. It is a dropdown rather than an
 *  assumption because the backend refuses to guess: with several visible there
 *  is no defensible default, and picking the first would enumerate somebody
 *  else's estate and then report the operator's own account as missing. */
export interface AzureSubscription {
  id: string;
  name: string;
  state: string;
}

/** One Azure resource group, from `GET /api/admin/azure/resource-groups`. */
export interface AzureResourceGroup {
  name: string;
  location: string;
}

/** One Azure AI Foundry / Cognitive Services account, from
 *  `GET /api/admin/azure/accounts`. `endpoint` is the account's data-plane host
 *  as ARM reports it, which is exactly what gets stored as `azure_endpoint`. */
export interface AzureAiAccount {
  name: string;
  endpoint: string;
  kind: string;
  location: string;
  provisioning_state?: string;
}

/** One model deployment on an account, from `GET /api/admin/azure/deployments`.
 *  `name` is the DEPLOYMENT name, which is what a data-plane request path needs;
 *  `model` is the model behind it. They differ often enough that using one for
 *  the other is a 404 at request time. */
export interface AzureDeployment {
  name: string;
  model: string;
  version: string;
  sku: string;
  format?: string;
  capacity?: number;
  provisioning_state?: string;
  /** Whether the backend believes this deployment can serve a chat completion.
   *  A `false` here is the difference between a dropdown entry that works and
   *  one that 404s on the first model call, so it is shown rather than used to
   *  silently filter the list — an operator who cannot see their deployment at
   *  all learns nothing. */
  chat?: boolean;
}

/**
 * A discovery list, and the one thing this screen must never get wrong.
 *
 * An empty dropdown has two completely different causes — "there are none" and
 * "the lookup did not work" — and Azure Resource Manager makes them easy to
 * confuse, because ARM filters list results by role assignment: an identity with
 * no Reader gets an empty 200, not a 403. So an empty `items` is only allowed to
 * render as "none" when `unavailable_reason` is absent, and the screen still
 * says out loud that ARM's empty list is RBAC-filtered.
 */
export interface AzureDiscovery<T> {
  items: T[];
  /** Present when the backend answered 200 but could not enumerate. Rendered
   *  verbatim; its presence means `items` is unknown, not empty. The API build
   *  this was written against raises a typed HTTP error for that case instead,
   *  which is stronger — this field is the 200-shaped form of the same claim,
   *  kept so a future endpoint that degrades rather than fails cannot land as a
   *  confident empty dropdown. */
  unavailable_reason?: string | null;
  /** Present when the list is REAL but CUT OFF — the endpoint bounds every
   *  listing, and a dropdown silently truncated at the limit fails exactly like
   *  an empty one: the operator's resource group is missing and the page gives
   *  them nothing to read. Carried on `x-npr-result-truncated` response headers.
   */
  incomplete_reason?: string | null;
}

// ───────────────────────────────────────────────────────────────────────────
// THE INFRASTRUCTURE LAYER — sources, inventory, topology
//
// These mirror backend/src/models.py. Three things in here are load-bearing and
// a screen that drops them is lying by omission:
//
//   `tier`          where a fact came from on the collection ladder. A device
//                   read from a cross-vendor aggregator and one read off the box
//                   are not the same quality of fact.
//   `simulated`     whether a source is a live connector or a seeded export.
//                   This deployment's exports are ALL seeded, and a client-
//                   facing screen has to say so.
//   `observedBy`    every console that saw a row, not just the winning one.
//                   "Where did we find it" has three answers for a firewall
//                   FortiManager, the FortiGate itself and AlgoSec all describe.
// ───────────────────────────────────────────────────────────────────────────

export type SourceTier = "aggregator" | "management_console" | "device";

export type DeviceRole =
  | "modem" | "router" | "firewall" | "l3_switch" | "l2_switch" | "hub" | "bridge"
  | "load_balancer" | "wireless_ap" | "server" | "workstation" | "virtual_appliance"
  | "unknown";

export type TopologyLayer =
  | "internet" | "circuit" | "modem" | "edge" | "perimeter"
  | "core" | "access" | "segment" | "endpoint";

/** How we know a link exists. There is deliberately no "inferred" member — see
 *  the DB CHECK in db/migrations/0007. `containment` is the weakest: two
 *  interfaces provably in one block, which is a real L3 observation and is not a
 *  cable, so the UI must render it differently rather than blending it in. */
export type LinkEvidence =
  | "lldp" | "cdp" | "api_topology" | "config" | "routing" | "declared" | "containment";

export interface Observation {
  tool: string;
  tier: SourceTier;
  raw_ref?: string;
  evidence?: LinkEvidence;
}

/** One field two consoles stated differently. NOT an error: it is a fact about
 *  the estate's own record-keeping — a stale entry, or a box replaced without
 *  the aggregator being told — and it is what a review is for. */
export interface SourceConflict {
  entity: string;
  field: string;
  claims: { tool: string; tier: SourceTier; value: unknown }[];
}

export interface SourceCard {
  tool: string;
  label: string;
  vendor: string;
  tier: SourceTier;
  api: string;
  auth: string;
  /** What it yields, in inventory vocabulary. */
  yields: string[];
  /** What it will NOT give you. The most useful field on the card: it is what
   *  stops an operator reading an empty access lane as an empty access layer. */
  blind_to: string[];
  /** Exposed by the vendor's API and NOT read by this build. Distinct from
   *  `blind_to`: the gap is ours, not the vendor's. */
  unread?: string[];
  notes?: string | null;
  connected: boolean;
  /** True for a seeded export rather than a live connector. Rendered, always. */
  simulated: boolean;
  device?: string | null;
  last_sync?: string | null;
  /** What this source actually put into the current snapshot. Absent when it is
   *  not connected — never rendered as zero, which would read as "connected and
   *  found nothing". */
  contributed?: {
    records: number; entities: number; devices: number; interfaces: number;
    links: number; vlans: number; subnets: number; circuits: number;
  } | null;
}

export interface InventoryItem {
  key: string;
  name: string;
  /** The inventory vocabulary: a device role, or an entity kind (vlan, subnet,
   *  public_ip, wan_circuit, asset). */
  kind: string;
  role?: DeviceRole;
  role_source?: "declared" | "derived" | "unknown";
  role_reason?: string;
  vendor?: string | null;
  model?: string | null;
  os_version?: string | null;
  addresses: string[];
  vlan_id?: number | null;
  vlan_name?: string | null;
  subnet?: string | null;
  zone?: string | null;
  tags: string[];
  layer?: TopologyLayer | null;
  layer_source?: "declared" | "derived" | "unknown";
  layer_reason?: string;
  observed_by: Observation[];
  conflicts: SourceConflict[];
  finding_ids: string[];
}

/** Counts the header reads out. A count no source declared is `null`, NEVER 0 —
 *  "we don't know" must not render as "we checked, and it's none". */
export interface InventoryCounts {
  devices: number | null;
  interfaces: number | null;
  vlans: number | null;
  subnets: number | null;
  public_ips: number | null;
  circuits: number | null;
  assets: number | null;
}

export interface InventoryResponse {
  items: InventoryItem[];
  total: number;
  has_more: boolean;
  counts: InventoryCounts;
  facets: {
    kinds: Record<string, number>;
    sources: Record<string, number>;
    vlans: Record<string, number>;
    zones: Record<string, number>;
  };
}

/** One port, SVI or logical interface, as the explorer's node drawer needs it.
 *  `admin_up`/`oper_up` are THREE-VALUED: null means the source did not report
 *  link state, and rendering that as "down" invents an outage. */
export interface TopoInterface {
  name: string;
  addresses: string[];
  vlan_id?: number | null;
  zone?: string | null;
  admin_up?: boolean | null;
  oper_up?: boolean | null;
  speed_mbps?: number | null;
  lag_group?: string | null;
  description?: string | null;
  neighbor_device?: string | null;
  neighbor_interface?: string | null;
  networks_behind: string[];
}

export interface TopoNode {
  key: string;
  name: string;
  kind: string;
  role?: DeviceRole;
  /** Whether the ROLE was stated by a console or worked out by the engine, and
   *  why. The explorer must be able to show its working for "why do you call
   *  this an L3 switch". */
  role_source?: "declared" | "derived" | "unknown";
  role_reason?: string;
  vendor?: string | null;
  model?: string | null;
  os_version?: string | null;
  serial?: string | null;
  site?: string | null;
  mgmt_ip?: string | null;
  tags?: string[];
  /** Ports, carried with the node so the drawer needs no second request. */
  interfaces?: TopoInterface[];
  /** Fields two consoles stated differently. Not an error — a fact about the
   *  estate's own record-keeping, and what a review is for. */
  conflicts?: SourceConflict[];
  addresses: string[];
  vlan_ids: number[];
  ha_group?: string | null;
  ha_role?: string | null;
  layer_reason?: string;
  observed_by: Observation[];
  finding_ids: string[];
  /** Set when this device is inventoried but nothing reported a cable for it. A
   *  box with no line to anything reads as a rendering bug; it is a coverage gap
   *  and the UI must say which console would close it. */
  unlinked_reason?: string | null;
  would_be_filled_by?: string | null;
}

export interface TopoLink {
  id: string;
  a: string;
  b: string;
  a_iface?: string | null;
  b_iface?: string | null;
  evidence: LinkEvidence;
  evidence_detail: string;
  redundant_group?: string | null;
  aggregated: boolean;
  member_count: number;
  observed_by: Observation[];
}

export interface TopoLane {
  layer: TopologyLayer;
  label: string;
  nodes: TopoNode[];
  /** False when nothing was observed at this layer. `reason` and
   *  `would_be_filled_by` are then both present, and the lane renders as a NAMED
   *  ABSENCE — never as a ghost device, and never silently omitted. */
  observed: boolean;
  reason?: string | null;
  would_be_filled_by?: string | null;
}

/** A structural fact that connects two lanes, and is NOT a cable.
 *
 *  A circuit names the CPE that terminates it, a VLAN names the devices carrying
 *  it, a host's address provably sits inside a subnet. All true, none of them an
 *  observed adjacency — so no `TopoLink` exists for them and none should. They
 *  are kept in their own field, and drawn in their own line family, because the
 *  moment one is mistaken for a cable the resilience analysis reads a broadcast
 *  domain as a path and every single point of failure in the estate dissolves. */
export interface TopoRelation {
  a: string;
  b: string;
  kind: "reaches" | "terminates" | "carries" | "contains";
  detail: string;
}

export interface TopologyResponse {
  lanes: TopoLane[];
  /** Structural relations, drawn subordinate to `links`. Optional so a frontend
   *  running against a backend that predates the field degrades to the old
   *  four-island canvas rather than throwing. */
  relations?: TopoRelation[];
  links: TopoLink[];
  vlans: { vlan_id: number; name?: string | null; subnets: string[]; gateways: string[] }[];
  counts: InventoryCounts;
  source_conflicts: SourceConflict[];
  unlinked_devices: { device_key: string; reason: string; would_be_filled_by: string }[];
  /** Bounds this response applied. Present from the first commit rather than
   *  added when payloads grow: silent truncation reads as "covered everything". */
  caps: { nodes_shown: number; nodes_total: number; capped_lanes: string[] };
}

/** What the engine could and could not compute. On every payload today and read
 *  by nothing — a picture drawn over a partial analysis looks complete. */
export interface AnalysisState {
  analysis_complete?: boolean | null;
  degraded_analyzers?: string[] | null;
  truncations?: Record<string, unknown>[] | null;
}

export type IpMatchRelation = "exact" | "covering" | "contained";

export interface IpPolicyMatch {
  rule_ref: string;
  source_tool: string;
  source: string;
  destination: string;
  service: string;
  action: string;
  relation: IpMatchRelation;
  /** How the address reached this rule: address containment, the identity
   *  layer's alias map, an interface, or NAT. Shown per row so the set
   *  arithmetic is visible rather than asserted. */
  matched_via: string;
  finding_ids: string[];
}

export interface IpLookupResponse {
  address: string;
  mode: string;
  /** Grouped exactly as the drawer renders them. `covering` is the group people
   *  forget: the rules that permit this address without naming it. */
  matches: { exact: IpPolicyMatch[]; covering: IpPolicyMatch[]; contained: IpPolicyMatch[] };
  assets: { asset_key: string; kind: string; tags: string[]; source_tools: string[] }[];
  devices: TopoNode[];
  interfaces: { interface_key: string; device_key: string; name: string; addresses: string[]; vlan_id?: number | null }[];
  vlan?: { vlan_id: number; name?: string | null } | null;
  subnet?: string | null;
  finding_ids: string[];
  /** The reachability claim, with the caveat printed NEXT TO IT rather than
   *  buried in a doc: the engine models the union of allow edges and does not
   *  implement deny precedence (ENGINE.md §10.1), so "not reachable" is
   *  "no allow path found", not "provably blocked". */
  effective: { reachable_from_internet: boolean | null; caveat: string };
}

export interface ResilienceFinding {
  id: string;
  kind: string;
  title: string;
  detail: string;
  severity: number;
  severity_band: Band;
  severity_vector: Record<string, number>;
  involved: string[];
  remediation: string;
}

export interface BlastRadius {
  device_key: string;
  paths_lost: number;
  paths_before: number;
  fraction: number;
  circuits_stranded: string[];
  devices_isolated: string[];
  devices_degraded: number;
  components_after: number;
}

export interface ResilienceResponse {
  /** False when there was nothing to analyse. It must be impossible to read an
   *  empty `findings` as a clean bill of health. */
  analysed: boolean;
  reason?: string | null;
  findings: ResilienceFinding[];
  blast_radius: BlastRadius[];
  blast_basis: string;
  adjacency_count: number;
  excluded_adjacencies: { reason: string; detail: string }[];
  suppressed: { kind: string; candidate: string; detail: string }[];
}
