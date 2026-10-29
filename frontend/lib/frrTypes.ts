/**
 * Firewall Rule Review (FRR) wire types.
 *
 * These mirror the backend's FRR endpoints (backend/app/exports_api.py,
 * packages_api.py, frr_api.py) field for field. Nullable fields stay nullable:
 * a `hit_count` of null means the export carried no hit counters, which is a
 * different fact from zero hits and must render as "unknown".
 */

import type { Band } from "./types";

export type FrrDuty = "network_owner" | "security_approver";

export interface FrrMe {
  email: string | null;
  role: string | null;
  duties: { duty: FrrDuty; scope: string }[];
  can_upload: boolean;
  is_admin: boolean;
}

export type ExportStatus = "received" | "accepted" | "rejected";

export type CheckKind =
  | "any_any"
  | "admin_port_exposed"
  | "broad_source"
  | "over_permissive"
  | "shadowed"
  | "expired"
  | "expiring_soon"
  | "disabled"
  | "unused";

export const CHECK_KINDS: CheckKind[] = [
  "any_any", "admin_port_exposed", "broad_source", "over_permissive", "shadowed",
  "expired", "expiring_soon", "disabled", "unused",
];

export type BandCounts = Partial<Record<Band, number>>;

export interface ReviewStats {
  rules: number;
  rules_with_findings: number;
  /** Rules some (not all) of whose grants are matched by rules above them. */
  rules_partly_covered?: number;
  by_check: Partial<Record<CheckKind | string, number>>;
  by_band: BandCounts;
  grants_analysed?: number;
}

export interface ExportSummary {
  rules: number;
  rules_enabled: number;
  grants: number;
  nat_rules: number;
  layers: string[];
  hit_counts_present: boolean;
  exported_at: string | null;
  review?: ReviewStats;
  limitations_total?: number;
}

export interface FrrExport {
  export_id: string;
  sha256: string;
  source_type: string;
  filename: string | null;
  size_bytes: number;
  declared_exported_at: string | null;
  exported_at: string | null;
  uploaded_by: string | null;
  uploaded_at: string;
  status: ExportStatus;
  rejection_reason: string | null;
  summary: ExportSummary | null;
  job_id: string | null;
  updated_at: string | null;
}

export interface ExportList {
  items: FrrExport[];
  next_before: string | null;
}

export interface UploadResult {
  export: FrrExport;
  job?: unknown;
  duplicate: boolean;
}

export interface RuleCheck {
  check: CheckKind | string;
  severity: number;
  band: Band;
  title: string;
  evidence: Record<string, unknown>;
  finding_id: string;
}

export interface RegisterEntry {
  rule_uid: string;
  layer: string;
  number: number | null;
  name: string | null;
  section: string | null;
  action: string;
  enabled: boolean;
  sources: string[];
  destinations: string[];
  services: string[];
  hit_count: number | null;
  last_hit: string | null;
  expires_at: string | null;
  checks: RuleCheck[];
  limitations: string[];
  severity: number | null;
  band: Band | null;
  /** NAT rules whose original or translated destination this rule reaches. */
  nat?: NatContext[];
  /** Some, not all, of the rule's grants are matched by rules above it. */
  coverage?: RuleCoverage | null;
}

export interface RuleCoverage {
  grants: number;
  covered: number;
  gateway: string;
  layer: string;
  /** Gateways on which the rule is partly covered. */
  partly_covered_on: number;
  by_rules: number[];
  /** Up to ten covered grants, each with the earlier rule that takes it. */
  covered_grants: { source: string; destination: string; service: string; by_rule: number | null; by_action: string | null }[];
}

export interface NatContext {
  nat_rule: number | null;
  package: string;
  method: string;
  original_destination: string[];
  translated_destination: string[];
  translated_destination_cidrs: string[];
  more_nat_rules?: number;
}

export interface NatFinding {
  check: "nat_shadowed" | "nat_disabled" | "nat_orphan" | "nat_internet_exposure" | string;
  severity: number;
  band: Band;
  title: string;
  nat_uid: string;
  nat_number: number | null;
  package: string;
  evidence: Record<string, unknown>;
}

export interface ReviewPage {
  export_id?: string;
  stats: ReviewStats;
  limitations: string[];
  reference_time: string | null;
  total: number;
  items: RegisterEntry[];
  limit: number;
  offset: number;
  /** Per (layer, gateway): counts. The rule lists come from /effective-policy on demand. */
  effective_policy?: EffectivePolicySummary[];
  nat_findings?: NatFinding[];
}

export interface EffectivePolicySummary {
  layer: string;
  gateway: string;
  rules_installed: number;
  effective_allow_count: number;
  shadowed_count: number;
  deny_count: number;
  inactive_count: number;
  partly_covered_count?: number;
}

export interface EffectivePolicyGateway {
  layer: string;
  gateway: string;
  rules_installed: number;
  effective_allow: (number | null)[];
  shadowed: (number | null)[];
  deny: (number | null)[];
  inactive: (number | null)[];
  partly_covered?: (number | null)[];
}

export type FeedbackVerdict = "agree" | "disagree";
export type FeedbackBand = "none" | "low" | "medium" | "high" | "critical";

export interface FeedbackRow {
  export_id: string;
  rule_uid: string;
  check_kind: string;
  reviewer: string;
  verdict: FeedbackVerdict;
  suggested_band: FeedbackBand | null;
  comment: string | null;
  created_at: string;
  updated_at: string;
}

export interface FeedbackList {
  items: FeedbackRow[];
  summary: Record<string, { agree: number; disagree: number; agreement: number }>;
  suggested_bands: Record<string, number>;
}

export interface ReviewQuery {
  band?: Band;
  check?: string;
  flagged_only?: boolean;
  /** Only rules partly covered above (overrides flagged_only). */
  partly_covered?: boolean;
  limit?: number;
  offset?: number;
}

export type RunStatus = "queued" | "running" | "succeeded" | "failed";

export const FRR_AGENTS = [
  "orchestrator", "intake_parser", "policy_checker", "impact_assessor", "package_drafter",
] as const;
export type FrrAgent = (typeof FRR_AGENTS)[number];

export interface RunStep {
  agent: FrrAgent | string;
  status: string;
  at: string;
  [detail: string]: unknown;
}

export interface FrrRun {
  run_id: string;
  export_id: string;
  package_id: string | null;
  status: RunStatus;
  steps: RunStep[];
  created_by: string | null;
  created_at: string;
  finished_at: string | null;
}

export type PackageStatus = "draft" | "owner_validated" | "approved" | "rejected" | "superseded";

export type Proposal = "remove" | "disable_then_remove" | "reorder" | "time_bound_and_narrow" | "revisit_after";

export type AvailabilityImpact = "none" | "possible" | "likely" | "changes_behaviour";

export type OwnerDecision = "accept" | "reject" | "modify";

export interface ItemNarrative {
  summary: string;
  availability_note?: string;
  owner_questions?: string[];
  cites?: string[];
  by: string;
  fallback_reason?: string;
}

export interface PackageItem {
  item_id: string;
  rule_uid: string;
  layer: string;
  rule_number: number | null;
  rule_name: string | null;
  check_kind: CheckKind | string;
  band: Band;
  proposal: Proposal | string;
  rationale: string;
  availability_impact: AvailabilityImpact | string;
  requires_owner_input: string[] | null;
  commands: string[] | null;
  rollback: string[] | null;
  evidence: Record<string, unknown> | null;
  narrative: ItemNarrative | null;
  owner_decision: OwnerDecision | null;
  owner_input: Record<string, unknown> | null;
  owner_note: string | null;
  decided_by: string | null;
  decided_at: string | null;
}

export interface PackageNarrative {
  summary: string;
  key_risks?: string[];
  limitations_note?: string;
  by: string;
}

export interface ChangePackage {
  package_id: string;
  export_id: string;
  status: PackageStatus;
  summary: {
    items: number;
    by_impact?: Record<string, number>;
    by_proposal?: Record<string, number>;
  } | null;
  limitations: string[] | null;
  notes: string[] | null;
  narrative: PackageNarrative | null;
  created_by: string | null;
  created_at: string;
  validated_by: string | null;
  validated_at: string | null;
  validation_note: string | null;
  decided_by: string | null;
  decided_at: string | null;
  decision_note: string | null;
  /** Present only when `items_inline` (small packages); otherwise page through /items. */
  items?: PackageItem[];
  items_inline?: boolean;
  facets?: PackageFacets;
}

export interface PackageFacets {
  total: number;
  undecided: number;
  by_band: Record<string, number>;
  by_proposal: Record<string, number>;
  by_availability_impact: Record<string, number>;
  by_layer: Record<string, number>;
  by_owner_decision: Record<string, number>;
}

export interface PackageItemPage {
  total: number;
  items: PackageItem[];
  limit: number;
  offset: number;
}

export interface OwnerInput {
  allowed_sources?: string[];
  allowed_services?: string[];
  business_justification?: string;
}

export interface ApproverGrant {
  principal: string;
  duty: FrrDuty;
  scope: string;
  granted_by?: string | null;
  granted_at?: string | null;
}

export type KnowledgeKind = "standard" | "exception" | "runbook";

export interface KnowledgeDoc {
  doc_id: string;
  kind: KnowledgeKind;
  title: string;
  uploaded_by: string | null;
  uploaded_at: string;
  chunks: number;
}

export interface KnowledgeHit {
  doc_id: string;
  kind: KnowledgeKind;
  title: string;
  ord: number;
  heading: string | null;
  body: string;
  rank: number;
  cite: string;
}

export type ContextKind = "cmdb" | "flows";

export interface ContextDataset {
  dataset_id: string;
  kind: ContextKind;
  filename: string | null;
  size_bytes: number;
  status: "received" | "accepted" | "rejected";
  rejection_reason: string | null;
  summary: Record<string, unknown> | null;
  uploaded_by: string | null;
  uploaded_at: string;
  active: boolean;
}

export interface CompareFinding {
  rule_uid: string;
  check: string;
  number: string | null;
  name: string | null;
  layer: string | null;
  band: Band | null;
  title?: string | null;
  new_rule?: boolean;
  rule_removed?: boolean;
}

export interface CompareResult {
  export_id: string;
  baseline: string;
  summary: { rules_added: number; rules_removed: number; findings_new: number; findings_resolved: number; band_changes: number };
  new_findings: CompareFinding[];
  resolved_findings: CompareFinding[];
  band_changes: { rule_uid: string; number: string | null; name: string | null; was: Band; now: Band }[];
  limit: number;
}
