-- Qorvex PostgreSQL Schema v0.1.0
-- Migration: 001_initial_schema.sql

-- Projects table
CREATE TABLE IF NOT EXISTS projects (
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name       VARCHAR(255) NOT NULL,
    path       TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Check runs table (verification pipeline executions)
CREATE TABLE IF NOT EXISTS check_runs (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id  UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    status      VARCHAR(20) NOT NULL DEFAULT 'pending'
                CHECK (status IN ('pending', 'running', 'completed', 'failed', 'cancelled')),
    error_text  TEXT,
    start_time  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    end_time    TIMESTAMPTZ,
    score       REAL CHECK (score >= 0 AND score <= 100)
);

-- Finding results from analyzers
CREATE TABLE IF NOT EXISTS findings (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    check_run_id UUID NOT NULL REFERENCES check_runs(id) ON DELETE CASCADE,
    project_id   UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    severity     VARCHAR(20) NOT NULL
                 CHECK (severity IN ('critical', 'high', 'medium', 'low', 'info')),
    category     VARCHAR(50) NOT NULL
                 CHECK (category IN ('security', 'quality', 'dependency', 'secret', 'sast', 'license')),
    description  TEXT NOT NULL,
    file_path    TEXT,
    line_start   INTEGER,
    line_end     INTEGER,
    cwe          VARCHAR(20),
    remediation  TEXT,
    rule_id      VARCHAR(100),
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Reports (aggregated results)
CREATE TABLE IF NOT EXISTS reports (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    check_run_id UUID NOT NULL UNIQUE REFERENCES check_runs(id) ON DELETE CASCADE,
    summary      TEXT,
    sbom         JSONB,
    score        REAL CHECK (score >= 0 AND score <= 100),
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Policy definitions
CREATE TABLE IF NOT EXISTS policies (
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name       VARCHAR(255) NOT NULL,
    version    INTEGER NOT NULL DEFAULT 1,
    rules      JSONB NOT NULL DEFAULT '[]',
    frozen     BOOLEAN NOT NULL DEFAULT false,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Audit log (immutable, signed entries)
CREATE TABLE IF NOT EXISTS audit_entries (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    timestamp   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    actor       VARCHAR(100) NOT NULL,
    action      VARCHAR(200) NOT NULL,
    resource_id VARCHAR(100),
    detail      TEXT,
    signature   VARCHAR(128) NOT NULL
);

-- Indexes for performance
CREATE INDEX IF NOT EXISTS idx_check_runs_project_id ON check_runs(project_id);
CREATE INDEX IF NOT EXISTS idx_check_runs_status ON check_runs(status);
CREATE INDEX IF NOT EXISTS idx_findings_check_run_id ON findings(check_run_id);
CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
CREATE INDEX IF NOT EXISTS idx_audit_entries_timestamp ON audit_entries(timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_audit_entries_actor ON audit_entries(actor);

-- Insert default admin policy
INSERT INTO policies (name, version, rules, frozen)
VALUES ('default', 1, '[
    {"id":"block-critical","severity":"block","category":"security","pattern":"critical","description":"Block critical findings"},
    {"id":"block-secrets","severity":"block","category":"secret","pattern":".*","description":"Block any secret leakage"},
    {"id":"warn-deps","severity":"warn","category":"dependency","pattern":"high|critical","description":"Warn on high/critical deps"}
]'::jsonb, true)
ON CONFLICT DO NOTHING;