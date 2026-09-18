-- Spectra v0.1.0: Scanning
-- Migration: 004_scanning

-- Scans (scan sessions)
CREATE TABLE IF NOT EXISTS scans (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    target_id UUID NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
    project_id UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    name VARCHAR(255),
    scan_type VARCHAR(50) NOT NULL DEFAULT 'full',
    status VARCHAR(50) NOT NULL DEFAULT 'pending',
    config JSONB NOT NULL DEFAULT '{}',
    started_at TIMESTAMPTZ,
    completed_at TIMESTAMPTZ,
    duration_ms BIGINT,
    error_message TEXT,
    metadata JSONB NOT NULL DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    deleted_at TIMESTAMPTZ
);

CREATE INDEX idx_scans_target ON scans(target_id);
CREATE INDEX idx_scans_project ON scans(project_id);
CREATE INDEX idx_scans_organization ON scans(organization_id);
CREATE INDEX idx_scans_status ON scans(status);
CREATE INDEX idx_scans_type ON scans(scan_type);
CREATE INDEX idx_scans_created ON scans(created_at DESC);

-- Scan jobs (individual work units within a scan)
CREATE TABLE IF NOT EXISTS scan_jobs (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    scan_id UUID NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    worker_id UUID,
    job_type VARCHAR(100) NOT NULL,
    status VARCHAR(50) NOT NULL DEFAULT 'pending',
    priority INTEGER NOT NULL DEFAULT 100,
    payload JSONB NOT NULL DEFAULT '{}',
    result JSONB,
    error_message TEXT,
    attempts INTEGER NOT NULL DEFAULT 0,
    max_retries INTEGER NOT NULL DEFAULT 3,
    timeout_secs INTEGER NOT NULL DEFAULT 300,
    started_at TIMESTAMPTZ,
    completed_at TIMESTAMPTZ,
    duration_ms BIGINT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_scan_jobs_scan ON scan_jobs(scan_id);
CREATE INDEX idx_scan_jobs_worker ON scan_jobs(worker_id);
CREATE INDEX idx_scan_jobs_status ON scan_jobs(status);
CREATE INDEX idx_scan_jobs_type ON scan_jobs(job_type);
CREATE INDEX idx_scan_jobs_priority ON scan_jobs(priority);

-- Observations (raw signals from scanners)
CREATE TABLE IF NOT EXISTS observations (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    scan_id UUID NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    scan_job_id UUID REFERENCES scan_jobs(id) ON DELETE SET NULL,
    asset_id UUID REFERENCES assets(id) ON DELETE SET NULL,
    endpoint_id UUID REFERENCES endpoints(id) ON DELETE SET NULL,
    source VARCHAR(100) NOT NULL,
    observation_type VARCHAR(100) NOT NULL,
    data JSONB NOT NULL DEFAULT '{}',
    confidence DOUBLE PRECISION NOT NULL DEFAULT 0.0,
    severity VARCHAR(20),
    evidence_refs JSONB NOT NULL DEFAULT '[]',
    metadata JSONB NOT NULL DEFAULT '{}',
    observed_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_observations_scan ON observations(scan_id);
CREATE INDEX idx_observations_job ON observations(scan_job_id);
CREATE INDEX idx_observations_asset ON observations(asset_id);
CREATE INDEX idx_observations_endpoint ON observations(endpoint_id);
CREATE INDEX idx_observations_source ON observations(source);
CREATE INDEX idx_observations_type ON observations(observation_type);
CREATE INDEX idx_observations_severity ON observations(severity);
CREATE INDEX idx_observations_observed ON observations(observed_at DESC);
