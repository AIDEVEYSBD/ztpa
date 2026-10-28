-- 0013 — FRR approver matrix and change packages (two-stage human review)
--
-- The approver matrix grants a person a DUTY for a SCOPE: a network owner
-- validates findings and availability impact; a network security approver
-- approves the change package. Duties are separate from product roles on
-- purpose: being an admin does not make someone an approver.
--
-- A change package is drafted from one accepted export's register. Its states:
--   draft -> owner_validated -> approved | rejected      (superseded by a redraft)
-- The CHECKs below make the four-eyes rule and the order a database fact.

SET search_path TO ztpa, public;

CREATE TABLE IF NOT EXISTS ztpa.frr_approvers (
    principal   text NOT NULL CHECK (principal = lower(principal) AND length(principal) BETWEEN 3 AND 320),
    duty        text NOT NULL CHECK (duty IN ('network_owner', 'security_approver')),
    scope       text NOT NULL DEFAULT '*' CHECK (length(scope) BETWEEN 1 AND 200),  -- '*' or a layer name
    granted_by  text,
    granted_at  timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (principal, duty, scope)
);

CREATE TABLE IF NOT EXISTS ztpa.change_packages (
    package_id       uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    export_id        uuid NOT NULL REFERENCES ztpa.exports (export_id) ON DELETE CASCADE,
    status           text NOT NULL DEFAULT 'draft'
                     CHECK (status IN ('draft', 'owner_validated', 'approved', 'rejected', 'superseded')),
    summary          jsonb NOT NULL DEFAULT '{}'::jsonb,
    limitations      jsonb NOT NULL DEFAULT '[]'::jsonb,
    notes            jsonb NOT NULL DEFAULT '[]'::jsonb,
    created_by       text,
    created_at       timestamptz NOT NULL DEFAULT now(),
    validated_by     text,
    validated_at     timestamptz,
    validation_note  text,
    decided_by       text,
    decided_at       timestamptz,
    decision_note    text,
    updated_at       timestamptz NOT NULL DEFAULT now(),
    CHECK (status NOT IN ('owner_validated', 'approved', 'rejected') OR validated_by IS NOT NULL),
    CHECK (status NOT IN ('approved', 'rejected') OR decided_by IS NOT NULL),
    CHECK (decided_by IS NULL OR decided_by <> validated_by)          -- four eyes
);

-- At most one live package per export.
CREATE UNIQUE INDEX IF NOT EXISTS uq_change_packages_live
    ON ztpa.change_packages (export_id) WHERE status <> 'superseded';

CREATE TABLE IF NOT EXISTS ztpa.change_package_items (
    package_id           uuid NOT NULL REFERENCES ztpa.change_packages (package_id) ON DELETE CASCADE,
    item_id              text NOT NULL,
    rule_uid             text NOT NULL,
    layer                text NOT NULL,
    rule_number          integer,
    rule_name            text,
    check_kind           text NOT NULL,
    band                 text NOT NULL,
    proposal             text NOT NULL,
    rationale            text NOT NULL,
    availability_impact  text NOT NULL,
    requires_owner_input jsonb NOT NULL DEFAULT '[]'::jsonb,
    commands             jsonb NOT NULL DEFAULT '[]'::jsonb,
    rollback             jsonb NOT NULL DEFAULT '[]'::jsonb,
    evidence             jsonb NOT NULL DEFAULT '{}'::jsonb,
    owner_decision       text CHECK (owner_decision IN ('accept', 'reject', 'modify')),
    owner_input          jsonb,
    owner_note           text,
    decided_by           text,
    decided_at           timestamptz,
    PRIMARY KEY (package_id, item_id)
);

COMMENT ON TABLE ztpa.change_packages IS
    'FRR change packages: drafted from an export register, validated by a network owner, '
    'approved by a different network security approver. No device write exists. '
    'See backend/src/frr/workflow.py.';
