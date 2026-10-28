-- 0011 — shared rate-limit counters
--
-- Model-backed endpoints cost money and seconds per call. A limit held in one
-- process's memory is a limit per replica, so N replicas would allow N times
-- the budget; the counters live here instead, shared by every replica.
-- Fixed one-minute windows; see backend/src/ratelimit.py.

SET search_path TO ztpa, public;

CREATE TABLE IF NOT EXISTS ztpa.rate_limits (
    bucket        text NOT NULL,
    subject       text NOT NULL,
    window_start  timestamptz NOT NULL,
    hits          integer NOT NULL DEFAULT 0,
    PRIMARY KEY (bucket, subject, window_start)
);

CREATE INDEX IF NOT EXISTS idx_rate_limits_window ON ztpa.rate_limits (window_start);

COMMENT ON TABLE ztpa.rate_limits IS
    'Per-minute request counters shared by all API replicas. Rows older than an '
    'hour are pruned opportunistically by backend/src/ratelimit.py.';
