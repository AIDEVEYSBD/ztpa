-- 0015 — structured reviewer feedback on review checks
--
-- One verdict per (export, rule, check, reviewer): agree, or disagree with an
-- optional suggested band and a reason. Feedback is how the engine is tuned
-- (FRR-05.4) and, exported as labels, the evaluation set grows from real
-- reviews (see backend/src/frr/evals.py --labels).

SET search_path TO ztpa, public;

CREATE TABLE IF NOT EXISTS ztpa.frr_feedback (
    export_id      uuid NOT NULL REFERENCES ztpa.exports (export_id) ON DELETE CASCADE,
    rule_uid       text NOT NULL,
    check_kind     text NOT NULL CHECK (check_kind ~ '^[a-z_+]{2,40}$'),
    reviewer       text NOT NULL,
    verdict        text NOT NULL CHECK (verdict IN ('agree', 'disagree')),
    suggested_band text CHECK (suggested_band IN ('none', 'low', 'medium', 'high', 'critical')),
    comment        text CHECK (length(comment) <= 2000),
    created_at     timestamptz NOT NULL DEFAULT now(),
    updated_at     timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (export_id, rule_uid, check_kind, reviewer),
    CHECK (verdict = 'agree' OR comment IS NOT NULL)
);
