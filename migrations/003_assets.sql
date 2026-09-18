-- Spectra v0.1.0: Asset Discovery
-- Migration: 003_assets

-- Assets (discovered during network enumeration)
CREATE TABLE IF NOT EXISTS assets (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    target_id UUID NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
    parent_id UUID REFERENCES assets(id) ON DELETE SET NULL,
    asset_type VARCHAR(50) NOT NULL,
    value TEXT NOT NULL,
    metadata JSONB NOT NULL DEFAULT '{}',
    discovered_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    deleted_at TIMESTAMPTZ
);

CREATE INDEX idx_assets_target ON assets(target_id);
CREATE INDEX idx_assets_parent ON assets(parent_id);
CREATE INDEX idx_assets_type ON assets(asset_type);
CREATE INDEX idx_assets_value ON assets(value);
CREATE INDEX idx_assets_discovered ON assets(discovered_at);

-- Asset edges (relationships between assets)
CREATE TABLE IF NOT EXISTS asset_edges (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    from_asset_id UUID NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    to_asset_id UUID NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    relationship VARCHAR(50) NOT NULL,
    metadata JSONB NOT NULL DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_asset_edges_from ON asset_edges(from_asset_id);
CREATE INDEX idx_asset_edges_to ON asset_edges(to_asset_id);
CREATE INDEX idx_asset_edges_relationship ON asset_edges(relationship);

-- Services (detected network services)
CREATE TABLE IF NOT EXISTS services (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    asset_id UUID NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    port INTEGER,
    protocol VARCHAR(20),
    version VARCHAR(100),
    banner TEXT,
    metadata JSONB NOT NULL DEFAULT '{}',
    detected_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_services_asset ON services(asset_id);
CREATE INDEX idx_services_name ON services(name);

-- Endpoints (URLs discovered during crawling)
CREATE TABLE IF NOT EXISTS endpoints (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    asset_id UUID REFERENCES assets(id) ON DELETE SET NULL,
    target_id UUID NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
    url TEXT NOT NULL,
    method VARCHAR(10) NOT NULL DEFAULT 'GET',
    status_code INTEGER,
    content_type VARCHAR(255),
    title TEXT,
    depth INTEGER NOT NULL DEFAULT 0,
    parent_url TEXT,
    headers JSONB NOT NULL DEFAULT '{}',
    forms JSONB NOT NULL DEFAULT '[]',
    discovered_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_endpoints_asset ON endpoints(asset_id);
CREATE INDEX idx_endpoints_target ON endpoints(target_id);
CREATE INDEX idx_endpoints_url ON endpoints(url);
CREATE INDEX idx_endpoints_method ON endpoints(method);
CREATE INDEX idx_endpoints_status ON endpoints(status_code);

-- Technologies (detected technologies)
CREATE TABLE IF NOT EXISTS technologies (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    target_id UUID NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
    asset_id UUID REFERENCES assets(id) ON DELETE SET NULL,
    endpoint_id UUID REFERENCES endpoints(id) ON DELETE SET NULL,
    name VARCHAR(255) NOT NULL,
    category VARCHAR(100) NOT NULL,
    version VARCHAR(100),
    confidence DOUBLE PRECISION NOT NULL DEFAULT 0.0,
    detection_method VARCHAR(100) NOT NULL,
    metadata JSONB NOT NULL DEFAULT '{}',
    detected_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_technologies_target ON technologies(target_id);
CREATE INDEX idx_technologies_asset ON technologies(asset_id);
CREATE INDEX idx_technologies_endpoint ON technologies(endpoint_id);
CREATE INDEX idx_technologies_name ON technologies(name);
CREATE INDEX idx_technologies_category ON technologies(category);
