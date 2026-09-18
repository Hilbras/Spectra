-- Spectra Phase 2: Target Management
-- Migration: 002_target_management

-- Organizations
CREATE TABLE IF NOT EXISTS organizations (
    id UUID PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    slug VARCHAR(255) NOT NULL UNIQUE,
    description TEXT,
    settings JSONB NOT NULL DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_organizations_slug ON organizations(slug);

-- Projects
CREATE TABLE IF NOT EXISTS projects (
    id UUID PRIMARY KEY,
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    slug VARCHAR(255) NOT NULL,
    description TEXT,
    status VARCHAR(50) NOT NULL DEFAULT 'active',
    settings JSONB NOT NULL DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(organization_id, slug)
);

CREATE INDEX idx_projects_organization ON projects(organization_id);
CREATE INDEX idx_projects_status ON projects(status);

-- Scopes
CREATE TABLE IF NOT EXISTS scopes (
    id UUID PRIMARY KEY,
    target_id UUID NOT NULL,
    allowed_rules JSONB NOT NULL DEFAULT '[]',
    excluded_rules JSONB NOT NULL DEFAULT '[]',
    rate_limits JSONB NOT NULL DEFAULT '{}',
    execution_limits JSONB NOT NULL DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Targets
CREATE TABLE IF NOT EXISTS targets (
    id UUID PRIMARY KEY,
    project_id UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    target_type VARCHAR(50) NOT NULL,
    value TEXT NOT NULL,
    scope_id UUID REFERENCES scopes(id),
    environment VARCHAR(50) NOT NULL DEFAULT 'production',
    metadata JSONB NOT NULL DEFAULT '{}',
    active BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_targets_project ON targets(project_id);
CREATE INDEX idx_targets_type ON targets(target_type);
CREATE INDEX idx_targets_active ON targets(active);
CREATE INDEX idx_targets_value ON targets(value);

-- Credentials (stored separately for security)
CREATE TABLE IF NOT EXISTS credentials (
    id UUID PRIMARY KEY,
    target_id UUID NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    credential_type VARCHAR(50) NOT NULL,
    encrypted_value BYTEA NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_credentials_target ON credentials(target_id);
