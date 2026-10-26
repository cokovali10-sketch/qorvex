-- Qorvex PostgreSQL Schema v0.2.0
-- Migration: 002_pipeline_telemetry.sql
--
-- Adds per-stage telemetry and aggregate risk metadata, and relaxes the
-- findings.category CHECK so namespaced categories (forge-security,
-- stage-error:build_and_test, ...) are accepted.

-- Aggregate risk metadata on check runs
ALTER TABLE check_runs
    ADD COLUMN IF NOT EXISTS risk_level VARCHAR(20)
        CHECK (risk_level IN ('low', 'medium', 'high', 'critical'));
ALTER TABLE check_runs
    ADD COLUMN IF NOT EXISTS severity_counts JSONB NOT NULL DEFAULT '{}'::jsonb;

-- Aggregate risk metadata on reports
ALTER TABLE reports
    ADD COLUMN IF NOT EXISTS risk_level VARCHAR(20)
        CHECK (risk_level IN ('low', 'medium', 'high', 'critical'));
ALTER TABLE reports
    ADD COLUMN IF NOT EXISTS severity_counts JSONB NOT NULL DEFAULT '{}'::jsonb;

-- Per-stage execution records
CREATE TABLE IF NOT EXISTS check_stages (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    check_run_id UUID NOT NULL REFERENCES check_runs(id) ON DELETE CASCADE,
    name         VARCHAR(100) NOT NULL,
    status       VARCHAR(30) NOT NULL
                 CHECK (status IN ('pending', 'running', 'completed',
                                   'completed_with_errors', 'failed', 'skipped')),
    start_time   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    end_time     TIMESTAMPTZ,
    error_text   TEXT,
    UNIQUE (check_run_id, name)
);

CREATE INDEX IF NOT EXISTS idx_check_stages_check_run_id
    ON check_stages(check_run_id);
CREATE INDEX IF NOT EXISTS idx_check_runs_risk_level
    ON check_runs(risk_level);

-- Categories are namespaced and open-ended; constrain shape, not a fixed list.
ALTER TABLE findings DROP CONSTRAINT IF EXISTS findings_category_check;
ALTER TABLE findings
    ADD CONSTRAINT findings_category_check
    CHECK (length(category) BETWEEN 1 AND 64);
