-- Spectra Phase 2: gaps that block live code
-- Migration: 007_gaps

-- Why this file exists
-- --------------------
-- `s.txt` §5.1 lists 26 tables the PostgreSQL implementation must cover. Migrations
-- 001-006 define 26 tables too, but only 12 of the names match. Comparing the two
-- lists turned up fourteen that `s.txt` requires and the schema never had.
--
-- The important ones are here because **live code produces data with nowhere to put
-- it**, not because a table list said so:
--
--   users          spectra-auth's `User`, and the API's `UserStore` that holds the
--                  password hashes. Login, RBAC and the bootstrap administrator all
--                  read it. There was no table at all, so persisting authentication
--                  was not merely unimplemented -- it was impossible.
--   ports          `spectra_network::port::PortInfo`, including the closed and
--                  filtered states. `services` holds open ports only, so a scan that
--                  found nothing listening had no way to record that.
--   dns_records    `spectra_network::dns::DnsRecord`. DNS resolution is the first
--                  thing the network engine does and it had no table.
--   metrics        `MetricsRepository` has been a trait with no table since it was
--                  written.
--   detection_rules `spectra_findings::detection::default_rules`.
--   evidence_integrity  evidence hashes, so tampering with a stored body is detectable.
--
-- Four of the fourteen are deliberately NOT added, because the existing schema
-- already covers the requirement under a different shape and a second table would
-- duplicate it. Recorded rather than silently ignored:
--
--   scope_rules     `scopes.allowed_rules` and `scopes.excluded_rules` are JSONB
--                   arrays that already hold this. A normalised table would need a
--                   migration of existing data and has no reader.
--   environments    `targets.environment` is a VARCHAR. Promoting it to a table is a
--                   refactor with no consumer that needs a list of environments.
--   target_metadata `targets.metadata` is JSONB and already holds it.
--   jobs            `scan_jobs` already covers queue items, with attempts,
--                   max_retries, priority, timeout and payload. A second `jobs`
--                   table would be the same data twice.
--
-- The column additions at the end close the struct/column drift recorded in
-- docs/audit/PHASE_0_AUDIT.md, one field at a time, without dropping anything.

-- =============================================================================
-- Users
-- =============================================================================

-- `spectra_auth::User` is { id, username, email, roles, active, created_at,
-- last_login }. The API's private `UserEntry` is { password_hash, roles } and has no
-- email, so email is nullable: the bootstrap administrator has one only if an
-- operator supplied it.
--
-- `roles` is TEXT[] because it is a short list of well-known names that is read whole
-- on every token issue and never queried by element. A join table would add a query
-- to the login path to serve no query.
--
-- The password hash is stored as produced: argon2id PHC string. It is NOT
-- encrypted — encryption at rest is not implemented, and encoding a hash would
-- obscure that rather than address it. See docs/architecture/security.md.
CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    username VARCHAR(255) NOT NULL UNIQUE,
    email VARCHAR(320),
    password_hash TEXT NOT NULL,
    roles TEXT[] NOT NULL DEFAULT '{}',
    active BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_login TIMESTAMPTZ,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Case-insensitive uniqueness: two accounts differing only in case is a
-- privilege-escalation route when an operator grants access by username.
CREATE UNIQUE INDEX idx_users_username_lower ON users (LOWER(username));
CREATE INDEX idx_users_active ON users (active);

-- =============================================================================
-- Network results
-- =============================================================================

-- `PortInfo` is { port, protocol, state, service, banner }. `state` is kept because
-- a closed or filtered port is a *result*: "nothing is listening here" is what a
-- scanner reports, and the existing `services` table cannot hold it because a service
-- requires something running.
CREATE TABLE IF NOT EXISTS ports (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    asset_id UUID NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    target_id UUID REFERENCES targets(id) ON DELETE CASCADE,
    port INTEGER NOT NULL CHECK (port BETWEEN 0 AND 65535),
    protocol VARCHAR(10) NOT NULL DEFAULT 'tcp',
    state VARCHAR(20) NOT NULL DEFAULT 'unknown',
    service VARCHAR(255),
    banner TEXT,
    metadata JSONB NOT NULL DEFAULT '{}',
    detected_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (asset_id, port, protocol)
);

CREATE INDEX idx_ports_asset ON ports(asset_id);
CREATE INDEX idx_ports_target ON ports(target_id);
CREATE INDEX idx_ports_state ON ports(state);

-- `DnsRecord` is { record_type, name, value, ttl }.
CREATE TABLE IF NOT EXISTS dns_records (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    target_id UUID REFERENCES targets(id) ON DELETE CASCADE,
    asset_id UUID REFERENCES assets(id) ON DELETE SET NULL,
    record_type VARCHAR(10) NOT NULL,
    name VARCHAR(255) NOT NULL,
    value TEXT NOT NULL,
    ttl INTEGER,
    metadata JSONB NOT NULL DEFAULT '{}',
    resolved_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (target_id, record_type, name, value)
);

CREATE INDEX idx_dns_records_target ON dns_records(target_id);
CREATE INDEX idx_dns_records_name ON dns_records(name);
CREATE INDEX idx_dns_records_type ON dns_records(record_type);

-- =============================================================================
-- Metrics
-- =============================================================================

-- `MetricsRepository` has existed as a trait since it was written, with no table for
-- it to read. One row per scan, because a per-series table would need a metric-name
-- table to give the values meaning.
CREATE TABLE IF NOT EXISTS metrics (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    scan_id UUID REFERENCES scans(id) ON DELETE CASCADE,
    target_id UUID REFERENCES targets(id) ON DELETE CASCADE,
    name VARCHAR(100) NOT NULL,
    value DOUBLE PRECISION NOT NULL,
    labels JSONB NOT NULL DEFAULT '{}',
    recorded_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_metrics_scan ON metrics(scan_id);
CREATE INDEX idx_metrics_name ON metrics(name);
CREATE INDEX idx_metrics_recorded ON metrics(recorded_at);

-- =============================================================================
-- Detection rules
-- =============================================================================

-- `spectra_findings::detection::default_rules()` returns rules that are defined in
-- code and never stored. Persisting them lets an operator see and change what will
-- run, which is the point of having a `detection_rules` table at all.
CREATE TABLE IF NOT EXISTS detection_rules (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name VARCHAR(255) NOT NULL,
    rule_type VARCHAR(100) NOT NULL,
    category VARCHAR(100) NOT NULL,
    severity VARCHAR(20) NOT NULL,
    pattern TEXT,
    confidence DOUBLE PRECISION NOT NULL DEFAULT 0.0,
    enabled BOOLEAN NOT NULL DEFAULT true,
    tags JSONB NOT NULL DEFAULT '[]',
    definition JSONB NOT NULL DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (name, rule_type)
);

CREATE INDEX idx_detection_rules_enabled ON detection_rules(enabled);
CREATE INDEX idx_detection_rules_category ON detection_rules(category);

-- =============================================================================
-- Evidence integrity
-- =============================================================================

-- Kept separate from `evidence` so a body can be replaced without its integrity
-- record being replaced with it. `evidence_integrity.id` is the identity of the
-- *assertion*, not of the row being asserted about.
--
-- `previous_hash` makes the rows a chain: altering one body changes its own hash,
-- which changes every hash after it. That is what makes tampering detectable rather
-- than merely recorded.
CREATE TABLE IF NOT EXISTS evidence_integrity (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    evidence_id UUID NOT NULL REFERENCES evidence(id) ON DELETE CASCADE,
    content_hash VARCHAR(128) NOT NULL,
    algorithm VARCHAR(20) NOT NULL DEFAULT 'sha256',
    previous_hash VARCHAR(128),
    verified_at TIMESTAMPTZ,
    verified BOOLEAN NOT NULL DEFAULT false,
    metadata JSONB NOT NULL DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_evidence_integrity_evidence ON evidence_integrity(evidence_id);
CREATE UNIQUE INDEX idx_evidence_integrity_hash ON evidence_integrity(content_hash);

-- =============================================================================
-- Column additions: struct/column drift
-- =============================================================================

-- Each of these is a field on a struct in `crates/storage/src/repositories.rs` with
-- no column to hold it. Added rather than dropped, because the fields describe real
-- state the in-memory implementation keeps: a scan does have progress, an evidence
-- body does have a size.

-- `ScanRecord.progress: f64`. A scan reports 0..1 completion, and without this the
-- only persisted progress signal is `status`, which cannot say "60%".
ALTER TABLE scans ADD COLUMN IF NOT EXISTS progress DOUBLE PRECISION NOT NULL DEFAULT 0.0;

-- `EvidenceRecord.size_bytes: u64` and `.storage_path: Option<String>`.
-- `storage_path` anticipates moving evidence bodies to object storage; it is nullable
-- because today the body is inline in `data_value`.
--
-- `content_type` is deliberately NOT added: `evidence.data_type` already exists and
-- `EvidenceRecord.content_type` maps to it. Adding a second, redundant column would
-- create two sources for one value.
ALTER TABLE evidence ADD COLUMN IF NOT EXISTS size_bytes BIGINT;
ALTER TABLE evidence ADD COLUMN IF NOT EXISTS storage_path TEXT;

-- `WorkerRecord.capacity: u32` and `.active_jobs: u32`. `workers.resources` is a
-- JSONB blob, which could hold both — but a scheduler querying for available capacity
-- across workers should not have to parse JSON to do it.
ALTER TABLE workers ADD COLUMN IF NOT EXISTS capacity INTEGER NOT NULL DEFAULT 1;
ALTER TABLE workers ADD COLUMN IF NOT EXISTS active_jobs INTEGER NOT NULL DEFAULT 0;

-- `AuditRecord.details: serde_json::Value`. `audit_logs.metadata` is the same idea
-- under another name and is already JSONB, so this maps to it rather than adding a
-- fourth JSONB column for the same payload.
--
-- Not added: `ObservationRecord.title` / `.description`. The engine writes a
-- finding's title and description inside the observation's `data` JSONB, and the
-- `observations` table already has `data` — so unlike the additions above, there is
-- live data that would go in these columns but nothing that reads them, and a
-- denormalised duplicate of `data` would be a second place to forget to update.
-- Recorded in docs/audit/PHASE_0_AUDIT.md instead.
