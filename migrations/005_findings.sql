-- Spectra v0.1.0: Findings & Evidence
-- Migration: 005_findings

-- Findings (confirmed vulnerabilities and issues)
CREATE TABLE IF NOT EXISTS findings (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    scan_id UUID NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    target_id UUID NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
    project_id UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    asset_id UUID REFERENCES assets(id) ON DELETE SET NULL,
    endpoint_id UUID REFERENCES endpoints(id) ON DELETE SET NULL,
    title VARCHAR(500) NOT NULL,
    description TEXT NOT NULL,
    severity VARCHAR(20) NOT NULL,
    confidence DOUBLE PRECISION NOT NULL DEFAULT 0.0,
    category VARCHAR(100) NOT NULL,
    finding_type VARCHAR(100) NOT NULL DEFAULT 'vulnerability',
    status VARCHAR(50) NOT NULL DEFAULT 'new',
    verification_status VARCHAR(50) NOT NULL DEFAULT 'unverified',
    detection_source VARCHAR(100) NOT NULL,
    cvss_score DOUBLE PRECISION,
    cve_id VARCHAR(50),
    cwe_id VARCHAR(50),
    remediation TEXT,
    evidence JSONB NOT NULL DEFAULT '[]',
    references JSONB NOT NULL DEFAULT '[]',
    tags JSONB NOT NULL DEFAULT '[]',
    first_seen TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    occurrence_count INTEGER NOT NULL DEFAULT 1,
    correlation_id UUID,
    assigned_to VARCHAR(255),
    metadata JSONB NOT NULL DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    deleted_at TIMESTAMPTZ
);

CREATE INDEX idx_findings_scan ON findings(scan_id);
CREATE INDEX idx_findings_target ON findings(target_id);
CREATE INDEX idx_findings_project ON findings(project_id);
CREATE INDEX idx_findings_organization ON findings(organization_id);
CREATE INDEX idx_findings_asset ON findings(asset_id);
CREATE INDEX idx_findings_endpoint ON findings(endpoint_id);
CREATE INDEX idx_findings_severity ON findings(severity);
CREATE INDEX idx_findings_status ON findings(status);
CREATE INDEX idx_findings_category ON findings(category);
CREATE INDEX idx_findings_verification ON findings(verification_status);
CREATE INDEX idx_findings_source ON findings(detection_source);
CREATE INDEX idx_findings_correlation ON findings(correlation_id);
CREATE INDEX idx_findings_created ON findings(created_at DESC);

-- Finding notes (audit trail for findings)
CREATE TABLE IF NOT EXISTS finding_notes (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    finding_id UUID NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
    author VARCHAR(255) NOT NULL,
    content TEXT NOT NULL,
    note_type VARCHAR(50) NOT NULL DEFAULT 'comment',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_finding_notes_finding ON finding_notes(finding_id);

-- Finding groups (correlated findings)
CREATE TABLE IF NOT EXISTS finding_groups (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    scan_id UUID NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    title VARCHAR(500) NOT NULL,
    description TEXT,
    group_type VARCHAR(100) NOT NULL,
    primary_finding_id UUID REFERENCES findings(id) ON DELETE SET NULL,
    metadata JSONB NOT NULL DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_finding_groups_scan ON finding_groups(scan_id);
CREATE INDEX idx_finding_groups_type ON finding_groups(group_type);

-- Finding group members
CREATE TABLE IF NOT EXISTS finding_group_members (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    group_id UUID NOT NULL REFERENCES finding_groups(id) ON DELETE CASCADE,
    finding_id UUID NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(group_id, finding_id)
);

CREATE INDEX idx_finding_group_members_group ON finding_group_members(group_id);
CREATE INDEX idx_finding_group_members_finding ON finding_group_members(finding_id);

-- Verification records
CREATE TABLE IF NOT EXISTS verification_records (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    finding_id UUID NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
    status VARCHAR(50) NOT NULL,
    method VARCHAR(100) NOT NULL,
    confidence DOUBLE PRECISION NOT NULL DEFAULT 0.0,
    details TEXT NOT NULL,
    verifier VARCHAR(255) NOT NULL,
    evidence_refs JSONB NOT NULL DEFAULT '[]',
    verified_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_verification_records_finding ON verification_records(finding_id);
CREATE INDEX idx_verification_records_status ON verification_records(status);

-- Evidence (proof for findings)
CREATE TABLE IF NOT EXISTS evidence (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    finding_id UUID NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
    scan_id UUID REFERENCES scans(id) ON DELETE SET NULL,
    evidence_type VARCHAR(100) NOT NULL,
    title VARCHAR(500) NOT NULL,
    description TEXT,
    data_type VARCHAR(50) NOT NULL,
    data_value TEXT NOT NULL,
    data_hash VARCHAR(128),
    redacted BOOLEAN NOT NULL DEFAULT false,
    redaction_policy VARCHAR(100),
    tags JSONB NOT NULL DEFAULT '[]',
    collected_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_evidence_finding ON evidence(finding_id);
CREATE INDEX idx_evidence_scan ON evidence(scan_id);
CREATE INDEX idx_evidence_type ON evidence(evidence_type);
CREATE INDEX idx_evidence_hash ON evidence(data_hash);
