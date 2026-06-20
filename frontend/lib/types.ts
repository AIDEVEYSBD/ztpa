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
  explanation?: string | null;
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

export interface Health {
  status: string;
  db: boolean;
  snapshot_id: string;
  ai: {
    active_provider: string;
    judge_model: string;
    prose_model: string;
    embed_model: string;
    ollama_reachable: boolean;
    ollama_models: string[];
    data_residency: string;
    anthropic_available: boolean;
    openai_available: boolean;
  };
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

export interface Remediation {
  finding_id: string;
  fix_text: string;
  change: Record<string, any>;
  validation: { resolves: boolean; introduces_new_criticals?: string[]; engine_corrected_ai?: boolean };
  by: string;
}
