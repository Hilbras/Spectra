# Changelog

All notable changes to Spectra will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-09-18

### Added

#### Core
- `Id<T>` typed identifier system (UUID v4)
- `SpectraError` application-wide error type
- `Timestamp` ISO 8601 wrapper
- `Metadata` key-value store

#### Configuration
- TOML-based configuration (`spectra.toml`)
- Environment variable overrides
- Structured config for API, database, Redis, storage, network, scanner, crawler, telemetry

#### Events
- Async channel-based `EventBus`
- 14 typed event variants
- `EventHandler` trait for custom handlers

#### Storage
- `Storage` trait for object storage
- `Database` trait for SQL databases
- `SearchIndex` trait for full-text search
- `LocalStorage` filesystem implementation

#### Target Management
- `Target` model (Domain, IP, URL, CIDR)
- `Scope` with allow/exclude rules
- `TargetService` with full CRUD
- Scope engine with glob matching and rate limits

#### HTTP Engine
- `HttpClient` with builder pattern
- `Session` with cookie management
- `RetryPolicy` with exponential backoff
- Proxy support

#### Network Discovery
- `NetworkEngine` orchestrating DNS + port scan + subdomains
- `DnsResolver` for A record resolution
- `PortScanner` with 26 common ports
- `AssetGraph` for discovered asset relationships

#### Fingerprinting
- `FingerprintEngine` with 6 detection vectors
- `RuleDatabase` with 60+ detection rules
- 9 technology categories (servers, frameworks, CMS, etc.)
- Version extraction via regex

#### Web Crawler
- BFS `UrlFrontier` with deduplication
- `HtmlParser` for link/form extraction
- `RobotsTxt` parser
- `CrawlFilter` for scope-aware URL filtering
- `CrawlPolicy` for rate limits

#### Scanner Framework
- `Scanner` async trait
- **SQL Injection Scanner**: 10 payloads, error+time-based blind, 20 param names
- **XSS Scanner**: 10 payloads, reflection+header checks
- **Directory Search Scanner**: 90+ paths, 10 concurrent requests

#### Findings
- `ManagedFinding` with full lifecycle
- `FindingType`, `DetectionSource`, `VerificationStatus`
- `CorrelationEngine` (vulnerability, asset, attack chain grouping)
- `InMemoryFindingsManager`
- `ReportGenerator` (text, JSON, status grouping)

#### Evidence
- `Evidence` type with typed data (Text, Binary, Url, Path, Json)
- `EvidenceCollector` trait
- `EvidenceType` enum (HttpRequest, Screenshot, etc.)

#### Verification
- `VerificationEngine` with auto-verification
- `InMemoryVerificationStore`
- Confidence scoring (severity + evidence bonuses)

#### Scan Engine
- `ScanEngine` full pipeline: discover → crawl → fingerprint → scan → report
- `ScanPlan`, `ScanJob`, `ScanStatus`, `EngineMetrics`

#### Scheduler
- `InMemoryJobQueue` priority queue
- Retry with configurable delay
- Max concurrency limits
- Job cancellation and statistics

#### Plugins
- `Plugin` trait (initialize/execute/shutdown)
- `PluginManager` with register/get/execute
- `EchoPlugin` and `TransformPlugin` built-ins

#### Sandbox
- `LocalSandbox` process-based execution
- `ResourceLimits` (memory, CPU, disk, network)
- Host allow/block lists
- Strict and permissive presets

#### API
- Axum HTTP server
- Health check endpoint
- Organization, Project, Target CRUD
- Structured JSON error responses

#### CLI
- Clap-based command-line interface
- Organization, Project, Target management
- Configuration display

#### Worker
- Worker process skeleton
- Hostname detection
- Graceful shutdown handling

#### Infrastructure
- GitHub Actions CI/CD (check, fmt, clippy, test, audit, build)
- PostgreSQL migration for target management
- Architecture documentation

### Known Limitations
- No built-in authentication (use network-level security)
- Evidence crate is trait-only (no concrete storage implementation)
- Worker not connected to scheduler
- API scan endpoint is a stub
- No npm package yet
- No Redis-backed scheduler yet
- No WASM/Python plugin sandboxing
