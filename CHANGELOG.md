# Changelog

All notable changes to Spectra will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-09-18

### Added

#### Core (`spectra-core`)
- `Id<T>` typed identifier system (UUID v4) with `Hash`, `PartialEq`, `Eq`
- `SpectraError` application-wide error type with 18 variants
- `Timestamp` ISO 8601 wrapper
- `Metadata` key-value store
- `security` module: `InputValidator`, `RateLimiter`, `ApiToken`, `constant_time_eq()`, `generate_token()`, `hash_sha256()`

#### Configuration (`spectra-config`)
- TOML-based configuration with 11 sections
- Environment variable overrides (`SPECTRA_<SECTION>__<KEY>`)
- Structured config for server, database, storage, search, queue, scanner, crawler, AI, telemetry, worker, logging

#### Events (`spectra-events`)
- Async channel-based `EventBus` with broadcast
- 27 typed event variants across 8 categories
- `EventHandler` trait for custom handlers
- Clone-safe bus for multi-consumer patterns

#### Storage (`spectra-storage`)
- `Database`, `Transaction`, `SearchIndex` traits
- `LocalStorage` filesystem implementation
- `PostgresDatabase` with connection pooling
- `PostgresSearchIndex` with full-text search

#### Target Management (`spectra-target`)
- `Organization → Project → Target` hierarchy
- `Target` types: Domain, URL, IP Address, CIDR
- `ScopeEngine` with glob matching and rate limits
- `TargetService` with full CRUD

#### HTTP Engine (`spectra-http`)
- `HttpClient` with builder pattern
- `Session` with cookie management
- `RetryPolicy` with exponential backoff
- Proxy support (HTTP/HTTPS/SOCKS5)
- 56 tests

#### Network Discovery (`spectra-network`)
- `NetworkEngine` orchestrating DNS + port scan + subdomains
- `DnsResolver` for A record resolution
- `PortScanner` with 26 common ports
- `AssetGraph` for discovered asset relationships
- 73 tests

#### Fingerprinting (`spectra-fingerprint`)
- `FingerprintEngine` with 6 detection vectors
- `RuleDatabase` with 60+ detection rules
- 9 technology categories (servers, frameworks, CMS, databases, etc.)
- Version extraction via regex
- 110 tests

#### Web Crawler (`spectra-crawler`)
- BFS `UrlFrontier` with deduplication
- `HtmlParser` for link/form extraction
- `RobotsTxt` parser with crawl-delay
- `CrawlFilter` for scope-aware URL filtering
- `CrawlPolicy` for rate limits
- 93 tests

#### Scanner Framework (`spectra-scanner`)
- `Scanner` async trait
- **SQL Injection Scanner**: 10 payloads, error+time-based blind, 20 param names
- **XSS Scanner**: 10 payloads, reflection+header checks
- **Directory Search Scanner**: 90+ paths, 10 concurrent requests
- 126 tests

#### Findings (`spectra-findings`)
- `ManagedFinding` with full lifecycle (New → Confirmed → Fixed)
- `FindingType` (Vulnerability, Misconfiguration, InformationDisclosure, etc.)
- `DetectionSource` (Scanner, Manual, AiAnalysis, Correlation)
- `CorrelationEngine` (vulnerability, asset, attack chain grouping)
- `InMemoryFindingsManager` with count/filter/delete/exists/ids
- `ReportGenerator` with risk_score, top_hosts, category_matrix, by_source, by_type
- `ObservationEngine` with 13 observation types and severity scoring
- `DetectionEngine` with 8 built-in rules and AND/OR logic composition
- 69 tests

#### Evidence (`spectra-evidence`)
- `Evidence` type with typed data (HttpRequest, Document, Screenshot, etc.)
- `EvidenceData` variants: Text, Binary, Url, Path, Json
- `EvidenceRedactor` with regex/JSON/header redaction
- `EvidenceIntegrity` with hash verification
- `InMemoryEvidenceStore` and `EvidenceEngine`
- 20 tests

#### Verification (`spectra-verification`)
- `VerificationEngine` with auto-verification by detection source/severity
- `InMemoryVerificationStore` with confidence scoring
- `VerificationStrategy` (min_confidence, batch_size, skip_info)
- Average confidence and finding outcome queries
- 20 tests

#### Scan Engine (`spectra-engine`)
- `ScanEngine` full pipeline: discover → crawl → fingerprint → scan → observe → verify → report
- `ScanPlan`, `ScanJob`, `ScanStatus`, `EngineMetrics`
- Integration with ObservationEngine and EvidenceEngine
- 10 tests

#### Scheduler (`spectra-scheduler`)
- `InMemoryJobQueue` with priority ordering
- Retry with configurable delay
- Max concurrency limits
- Job cancellation and statistics
- `Job::builder()` pattern
- 25 tests

#### Plugins (`spectra-plugins`)
- `Plugin` trait (initialize/execute/shutdown/health_check)
- `PluginCapability` enum (Scanner, Transformer, Enricher, Notifier, Reporter)
- `PluginHealth` (Healthy, Degraded, Unhealthy)
- `PluginManager` with register/get/execute/health_check_all/plugins_with_capability/remove
- Built-in: EchoPlugin, TransformPlugin, CounterPlugin, AggregatorPlugin
- 21 tests

#### Sandbox (`spectra-sandbox`)
- `LocalSandbox` process-based execution
- `ResourceLimits` (memory, CPU, disk, network, hosts)
- `SandboxPolicy` with command allow/block lists
- `AuditingSandbox` with audit logging and metrics
- `SandboxMetrics` (executions, success rate, avg duration)
- 26 tests

#### API (`apps/api`)
- Axum HTTP server with 20 endpoints
- Organization, Project, Target, Scan CRUD
- Finding, Observation, Evidence, Verification queries
- Platform statistics endpoint
- Structured JSON error responses

#### CLI (`apps/cli`)
- Clap-based CLI with 14 command groups
- Organization, Project, Target management
- Scan, Finding, Observation, Evidence management
- Verification summary, Statistics, Configuration display

#### Worker (`apps/worker`)
- Worker process with heartbeat and metrics
- Graceful shutdown handling
- Configurable polling intervals
- 13 tests

#### Infrastructure
- GitHub Actions CI/CD (fmt, clippy, test, audit, build)
- 6 PostgreSQL migrations (001–006) with 26 tables
- Architecture documentation with ADRs
- npm package wrapper (`@hilbras/spectra`)

### Known Limitations
- No built-in API authentication (use network-level security)
- PostgreSQL storage not yet wired (currently in-memory)
- No Redis-backed scheduler yet
- No WASM/Python plugin sandboxing
- No web frontend
