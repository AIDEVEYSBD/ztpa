-- ZeroTrust Policy Advisor -- database schema
-- Target: Postgres 15+ (Neon). Idempotent: safe to re-run.
-- Apply (preferred):  psql "$DATABASE_URL" --single-transaction -v ON_ERROR_STOP=1 -f db/schema.sql
-- Apply (fallback):   python db/migrate.py
-- Apply this file AS A WHOLE / IN ORDER (it sets search_path once, then creates
-- everything in the ztpa schema). Never create objects in `public`.
--
-- ID convention: every id the deterministic engine generates is a TEXT primary key
-- and must be derived deterministically (e.g. from snapshot + content) so that
-- re-running a snapshot UPSERTs to identical rows. Only audit_log -- which records
-- runtime events -- uses a random uuid.

CREATE SCHEMA IF NOT EXISTS ztpa;
SET search_path TO ztpa;

-- gen_random_uuid() is built into Postgres 13+. If you ever target < 13, run:
--   CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- ============================================================================
-- snapshots -- every analysis run is a point-in-time snapshot; all data FKs here
-- ============================================================================
CREATE TABLE IF NOT EXISTS snapshots (
    snapshot_id  text PRIMARY KEY,                 -- engine-generated, deterministic
    label        text,
    status       text NOT NULL DEFAULT 'complete'
                   CHECK (status IN ('running', 'complete', 'failed')),
    notes        text,
    created_at   timestamptz NOT NULL DEFAULT now()
);

-- ============================================================================
-- sources -- connectors / devices a snapshot ingested from
-- ============================================================================
CREATE TABLE IF NOT EXISTS sources (
    source_id    text PRIMARY KEY,
    tool         text NOT NULL
                   CHECK (tool IN ('algosec', 'guardicore', 'wiz', 'sd_wan', 'sd_lan')),
    device       text,
    config       jsonb NOT NULL DEFAULT '{}'::jsonb,
    last_sync    timestamptz
);

-- ============================================================================
-- resolved_objects -- audit of name -> value dereferencing (object/tag resolution)
-- ============================================================================
CREATE TABLE IF NOT EXISTS resolved_objects (
    id             text PRIMARY KEY,
    snapshot_id    text NOT NULL REFERENCES snapshots(snapshot_id) ON DELETE CASCADE,
    source_tool    text NOT NULL,
    source_device  text,
    object_name    text NOT NULL,                  -- e.g. WEB_SERVERS
    object_kind    text NOT NULL
                     CHECK (object_kind IN ('address','service','zone','application','user','tag_group')),
    resolved       jsonb NOT NULL,                 -- concrete contents after dereferencing
    is_dynamic     boolean NOT NULL DEFAULT false, -- DAG / label selector / FQDN (snapshot-time)
    resolved_at    timestamptz NOT NULL DEFAULT now(),
    UNIQUE (snapshot_id, source_device, object_name, object_kind)
);

-- ============================================================================
-- assets -- the identity layer. IP is an ATTRIBUTE, never the key.
-- ============================================================================
CREATE TABLE IF NOT EXISTS assets (
    asset_id      text PRIMARY KEY,                -- deterministic engine id
    snapshot_id   text NOT NULL REFERENCES snapshots(snapshot_id) ON DELETE CASCADE,
    asset_key     text NOT NULL,                   -- chosen stable identity
    kind          text NOT NULL DEFAULT 'concrete'
                    CHECK (kind IN ('concrete', 'abstract')),  -- abstract = internet/zone/subnet
    context       text,                            -- vrf / segment / vpn / tenant / account
    identifiers   jsonb NOT NULL DEFAULT '{}'::jsonb,  -- {cloud_id, uuid, mac, hostname, ...}
    ip_set        text[] NOT NULL DEFAULT '{}',    -- canonical CIDRs (text for portability)
    tags          text[] NOT NULL DEFAULT '{}',
    source_tools  text[] NOT NULL DEFAULT '{}',
    created_at    timestamptz NOT NULL DEFAULT now()
);

-- entity-resolution audit: which identities were merged, with confidence + evidence
CREATE TABLE IF NOT EXISTS asset_correlations (
    id            text PRIMARY KEY,
    snapshot_id   text NOT NULL REFERENCES snapshots(snapshot_id) ON DELETE CASCADE,
    asset_id      text NOT NULL REFERENCES assets(asset_id) ON DELETE CASCADE,
    match_key     text NOT NULL
                    CHECK (match_key IN ('cloud_id', 'hostname', 'mac', 'context_ip')),
    confidence    numeric(4,3) NOT NULL CHECK (confidence >= 0 AND confidence <= 1),
    evidence      jsonb NOT NULL DEFAULT '{}'::jsonb,
    created_at    timestamptz NOT NULL DEFAULT now()
);

-- ============================================================================
-- canonical_rules -- the normalized policy table (set-valued at rest)
-- ============================================================================
CREATE TABLE IF NOT EXISTS canonical_rules (
    rule_uid        text PRIMARY KEY,              -- deterministic
    snapshot_id     text NOT NULL REFERENCES snapshots(snapshot_id) ON DELETE CASCADE,
    source_tool     text NOT NULL,
    source_device   text,
    raw_rule_id     text,                          -- provenance back to the real rule
    policy_id       text,
    rule_order      integer,                       -- first-match / shadowing
    action          text NOT NULL CHECK (action IN ('allow', 'deny')),
    src_kind        text NOT NULL CHECK (src_kind IN ('cidr', 'identity')),
    src_value       jsonb NOT NULL,                -- {cidrs:[...]} or {identity:"expr"}
    src_context     text,
    dst_kind        text NOT NULL CHECK (dst_kind IN ('cidr', 'identity')),
    dst_value       jsonb NOT NULL,
    dst_context     text,
    protocol        text,                          -- tcp / udp / any / icmp / ...
    ports           jsonb NOT NULL DEFAULT '[]'::jsonb,  -- [{proto, port_start, port_end}]
    l7_app          text,                          -- App-ID; null for port-based rules
    nat_original    jsonb,
    nat_translated  jsonb,
    tags            text[] NOT NULL DEFAULT '{}',
    enabled         boolean NOT NULL DEFAULT true,
    schedule        text,
    direction       text,
    src_asset_refs  text[] NOT NULL DEFAULT '{}',
    dst_asset_refs  text[] NOT NULL DEFAULT '{}',
    created_at      timestamptz NOT NULL DEFAULT now()
);

-- ============================================================================
-- materialized graph -- derived from canonical_rules + assets (for the dashboard)
-- ============================================================================
CREATE TABLE IF NOT EXISTS graph_nodes (
    node_id      text NOT NULL,
    snapshot_id  text NOT NULL REFERENCES snapshots(snapshot_id) ON DELETE CASCADE,
    kind         text NOT NULL
                   CHECK (kind IN ('asset', 'zone', 'subnet', 'internet', 'enforcement_point')),
    label        text,
    context      text,
    asset_id     text REFERENCES assets(asset_id) ON DELETE SET NULL,
    tags         text[] NOT NULL DEFAULT '{}',
    ip_set       text[] NOT NULL DEFAULT '{}',
    PRIMARY KEY (snapshot_id, node_id)
);

CREATE TABLE IF NOT EXISTS graph_edges (
    edge_id            text NOT NULL,
    snapshot_id        text NOT NULL REFERENCES snapshots(snapshot_id) ON DELETE CASCADE,
    src_node           text NOT NULL,
    dst_node           text NOT NULL,
    action             text NOT NULL CHECK (action IN ('allow', 'deny')),
    ports              jsonb NOT NULL DEFAULT '[]'::jsonb,
    l7_app             text,
    rule_uid           text,                       -- provenance
    source_tool        text,
    enforcement_point  text,                       -- node_id of the device that enforces it
    PRIMARY KEY (snapshot_id, edge_id)
);

-- ============================================================================
-- findings -- deterministic risk findings (+ cached LLM explanation)
-- ============================================================================
CREATE TABLE IF NOT EXISTS findings (
    finding_id       text PRIMARY KEY,             -- deterministic
    snapshot_id      text NOT NULL REFERENCES snapshots(snapshot_id) ON DELETE CASCADE,
    type             text NOT NULL
                       CHECK (type IN ('over_permissive', 'cidr_overlap', 'shadowed_rule', 'cross_tool_path', 'transport_exposure')),
    severity         integer NOT NULL CHECK (severity BETWEEN 0 AND 100),
    severity_band    text NOT NULL CHECK (severity_band IN ('low', 'medium', 'high', 'critical')),
    forced_critical  boolean NOT NULL DEFAULT false,
    signals          jsonb NOT NULL DEFAULT '{}'::jsonb,  -- includes severity_vector
    involved         text[] NOT NULL DEFAULT '{}',
    raw_refs         text[] NOT NULL DEFAULT '{}',
    source_tools     text[] NOT NULL DEFAULT '{}',
    explanation      text,                         -- LLM-generated, cached
    explanation_by   text,                         -- provider:model that produced the cached explanation
    created_at       timestamptz NOT NULL DEFAULT now()
);
-- widen older snapshots' findings table that predate explanation_by (idempotent).
ALTER TABLE findings ADD COLUMN IF NOT EXISTS explanation_by text;
-- widen the finding type domain to include transport_exposure (QUIC / L7) (idempotent).
ALTER TABLE findings DROP CONSTRAINT IF EXISTS findings_type_check;
ALTER TABLE findings ADD CONSTRAINT findings_type_check CHECK (type IN ('over_permissive', 'cidr_overlap', 'shadowed_rule', 'cross_tool_path', 'transport_exposure'));

-- ranked, root-cause-grouped actions (LLM ranking output)
CREATE TABLE IF NOT EXISTS ranked_actions (
    action_id    text NOT NULL,
    snapshot_id  text NOT NULL REFERENCES snapshots(snapshot_id) ON DELETE CASCADE,
    title        text NOT NULL,
    finding_ids  text[] NOT NULL DEFAULT '{}',
    priority     integer NOT NULL,
    rationale    text,
    PRIMARY KEY (snapshot_id, action_id)
);

-- ============================================================================
-- change governance -- requests + decisions
-- ============================================================================
CREATE TABLE IF NOT EXISTS change_requests (
    request_id    text PRIMARY KEY,
    snapshot_id   text NOT NULL REFERENCES snapshots(snapshot_id) ON DELETE CASCADE,  -- baseline evaluated against
    proposed      jsonb NOT NULL,                  -- canonical-row-shaped object
    requested_by  text,
    justification text,                            -- UNTRUSTED free text; never used as evidence
    created_at    timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS change_decisions (
    decision_id        text PRIMARY KEY,
    request_id         text NOT NULL REFERENCES change_requests(request_id) ON DELETE CASCADE,
    decision           text NOT NULL CHECK (decision IN ('auto_approve', 'escalate')),
    criteria           jsonb NOT NULL DEFAULT '{}'::jsonb,   -- each criterion -> bool
    triggering_reason  text,
    delta_summary      jsonb NOT NULL DEFAULT '{}'::jsonb,   -- new_paths, new_exposed_assets, boundaries_crossed
    confidence         numeric(4,3) CHECK (confidence >= 0 AND confidence <= 1),
    forced_escalate    boolean NOT NULL DEFAULT false,
    model              text,
    decided_at         timestamptz NOT NULL DEFAULT now()
);

-- ============================================================================
-- audit_log -- append-only record of every agent/user action (governance)
-- ============================================================================
CREATE TABLE IF NOT EXISTS audit_log (
    id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),  -- runtime event: random uuid is fine
    ts           timestamptz NOT NULL DEFAULT now(),
    actor        text NOT NULL CHECK (actor IN ('agent', 'user', 'system')),
    action       text NOT NULL,
    subject      text,                             -- finding_id / request_id / rule_uid / ...
    snapshot_id  text REFERENCES snapshots(snapshot_id) ON DELETE SET NULL,
    detail       jsonb NOT NULL DEFAULT '{}'::jsonb
);

-- widen change_requests so remediation changes (not just add-allow) flow through
-- the same request/decision tables (idempotent).
ALTER TABLE change_requests ADD COLUMN IF NOT EXISTS kind text;
ALTER TABLE change_requests ADD COLUMN IF NOT EXISTS origin text;

-- request lifecycle: 'open' (awaiting action) or 'rejected' (declined by a reviewer).
-- Approved/staged requests are tracked via staged_changes, not this column.
ALTER TABLE change_requests ADD COLUMN IF NOT EXISTS status text NOT NULL DEFAULT 'open';
ALTER TABLE change_requests ADD COLUMN IF NOT EXISTS rejected_by text;
ALTER TABLE change_requests ADD COLUMN IF NOT EXISTS reject_reason text;

-- widen findings.type to include the transport/application-layer exposure class
-- (QUIC / HTTP-3 blind spots), added after the initial schema (idempotent).
ALTER TABLE findings DROP CONSTRAINT IF EXISTS findings_type_check;
ALTER TABLE findings ADD CONSTRAINT findings_type_check
    CHECK (type IN ('over_permissive', 'cidr_overlap', 'shadowed_rule', 'cross_tool_path', 'transport_exposure'));

-- ============================================================================
-- ai_metrics -- one row per AI / agent-tool invocation (Tools + KPI dashboards)
-- ============================================================================
CREATE TABLE IF NOT EXISTS ai_metrics (
    id                 uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    ts                 timestamptz NOT NULL DEFAULT now(),
    kind               text NOT NULL,                  -- llm | agent_tool | embed
    capability         text NOT NULL,                  -- explain | rank | classify | remediate | ...
    tool_name          text,                           -- agent tool name, else the capability
    provider           text,                           -- ollama | anthropic | openai | engine
    model              text,
    role               text,                           -- admin | analyst | viewer | system
    actor_email        text,
    latency_ms         integer,
    prompt_tokens      integer NOT NULL DEFAULT 0,
    completion_tokens  integer NOT NULL DEFAULT 0,
    total_tokens       integer NOT NULL DEFAULT 0,
    est_cost_usd       numeric(12,6) NOT NULL DEFAULT 0,
    ok                 boolean NOT NULL DEFAULT true,
    error              text,
    snapshot_id        text,
    subject            text
);

-- ============================================================================
-- tool_settings -- per-role enable/disable for each tool/capability (admin)
-- ============================================================================
CREATE TABLE IF NOT EXISTS tool_settings (
    tool_key       text PRIMARY KEY,
    enabled_roles  text[] NOT NULL DEFAULT '{admin,analyst,viewer}',
    updated_by     text,
    updated_at     timestamptz NOT NULL DEFAULT now()
);

-- ============================================================================
-- remediation_revisions -- the durable Risk-To-Do iteration thread per finding
-- ============================================================================
CREATE TABLE IF NOT EXISTS remediation_revisions (
    revision_id  text PRIMARY KEY,
    thread_id    text NOT NULL,
    finding_id   text NOT NULL,
    snapshot_id  text,
    seq          integer NOT NULL,
    comment      text,                                 -- user comment that produced this revision (null for seq 0)
    fix_text     text,
    change       jsonb NOT NULL DEFAULT '{}'::jsonb,
    validation   jsonb NOT NULL DEFAULT '{}'::jsonb,
    by           text,
    status       text NOT NULL DEFAULT 'draft',        -- draft | accepted
    created_at   timestamptz NOT NULL DEFAULT now(),
    UNIQUE (thread_id, seq)
);

-- ============================================================================
-- staged_changes -- the staging area: approved changes ready to push to source
-- ============================================================================
CREATE TABLE IF NOT EXISTS staged_changes (
    staged_id    text PRIMARY KEY,
    snapshot_id  text,
    request_id   text,                                 -- references change_requests (soft link)
    origin       text,                                 -- risk_todo | change_gate
    kind         text,                                 -- add_allow | remediation
    target_tool  text,                                 -- algosec | guardicore | wiz
    payload      jsonb NOT NULL DEFAULT '{}'::jsonb,
    decision     text,                                 -- auto_approve | escalate | manual_approved
    status       text NOT NULL DEFAULT 'staged',       -- staged | pushing | pushed | conflict | failed
    conflicts    jsonb NOT NULL DEFAULT '[]'::jsonb,
    resolution   jsonb NOT NULL DEFAULT '{}'::jsonb,
    push_steps   jsonb NOT NULL DEFAULT '[]'::jsonb,
    created_by   text,
    created_at   timestamptz NOT NULL DEFAULT now(),
    pushed_at    timestamptz
);

-- ============================================================================
-- indexes
-- ============================================================================
CREATE INDEX IF NOT EXISTS idx_canon_snapshot    ON canonical_rules (snapshot_id);
CREATE INDEX IF NOT EXISTS idx_canon_tool         ON canonical_rules (source_tool);
CREATE INDEX IF NOT EXISTS idx_canon_tags         ON canonical_rules USING gin (tags);
CREATE INDEX IF NOT EXISTS idx_assets_snapshot    ON assets (snapshot_id);
CREATE INDEX IF NOT EXISTS idx_assets_key         ON assets (asset_key);
CREATE INDEX IF NOT EXISTS idx_assets_tags        ON assets USING gin (tags);
CREATE INDEX IF NOT EXISTS idx_findings_snapshot  ON findings (snapshot_id);
CREATE INDEX IF NOT EXISTS idx_findings_sev       ON findings (snapshot_id, severity DESC);
CREATE INDEX IF NOT EXISTS idx_edges_src          ON graph_edges (snapshot_id, src_node);
CREATE INDEX IF NOT EXISTS idx_edges_dst          ON graph_edges (snapshot_id, dst_node);
CREATE INDEX IF NOT EXISTS idx_decisions_request  ON change_decisions (request_id);
CREATE INDEX IF NOT EXISTS idx_audit_subject      ON audit_log (subject);
CREATE INDEX IF NOT EXISTS idx_metrics_ts         ON ai_metrics (ts DESC);
CREATE INDEX IF NOT EXISTS idx_metrics_capability ON ai_metrics (capability);
CREATE INDEX IF NOT EXISTS idx_metrics_provider   ON ai_metrics (provider, model);
CREATE INDEX IF NOT EXISTS idx_remrev_thread      ON remediation_revisions (thread_id, seq);
CREATE INDEX IF NOT EXISTS idx_remrev_finding     ON remediation_revisions (finding_id);
CREATE INDEX IF NOT EXISTS idx_staged_status      ON staged_changes (status);
CREATE INDEX IF NOT EXISTS idx_staged_tool        ON staged_changes (target_tool);
