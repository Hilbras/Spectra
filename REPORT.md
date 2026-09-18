# Spectra — Platform Report

> Generated: 2026-09-18
> Version: 0.1.1
> License: AGPL-3.0

---

## Executive Summary

Spectra is a modular, extensible, distributed security testing and analysis platform built in Rust. It is a 21-crate monorepo with 3 binary applications, covering the full security testing lifecycle from target management through vulnerability scanning to evidence-backed finding verification.

| Metric | Value |
|--------|-------|
| **Version** | 0.1.1 |
| **Language** | Rust (1.75+) |
| **Workspace Crates** | 18 libraries + 3 apps = **21 total** |
| **Lines of Rust** | **19,424** |
| **Lines of SQL** | **577** (6 migrations) |
| **Lines of Documentation** | **3,659** (11 doc files + 6 ADRs) |
| **Total Files** | **111** |
| **Tests** | **387** (all passing) |
| **Public API Items** | **660** (145 structs, 58 enums, 11 traits, 446 functions) |
| **API Endpoints** | **20** REST endpoints |
| **CLI Commands** | **14** command groups |
| **Database Tables** | **26** (across 6 migrations) |
| **Unsafe Code** | **0** (`unsafe_code = "forbid"`) |
| **Clippy Warnings** | **0** (`-D warnings`) |

---

## Architecture Overview

```
Core → Config → Target → Network/Fingerprint/Crawler → Scanner → Findings → Engine
                              ↓                                    ↓
                         Evidence ←──────────────────────── Verification
```

### Design Principles

| Principle | Implementation |
|-----------|----------------|
| **Modularity** | 18 library crates, each with a single responsibility |
| **Extensibility** | Plugin system with Scanner, Transformer, Enricher capabilities |
| **Scope Safety** | Every operation validated against target scope |
| **Evidence-Based** | Every finding traceable to evidence with integrity hashes |
| **Provider Agnostic** | Storage, AI, and execution providers abstracted via traits |
| **Defense in Depth** | Input validation, rate limiting, sandboxing, audit logging |
| **Observable** | 27 event types, OpenTelemetry integration |
| **No Unsafe** | `unsafe_code = "forbid"` enforced at workspace level |

---

## Crate Breakdown

### Core Layer

| Crate | Lines | Tests | Description |
|-------|-------|-------|-------------|
| **spectra-core** | 850 | 27 | `Id<T>` typed identifiers, `SpectraError` (18 variants), `Timestamp`, `Metadata`, `InputValidator`, `RateLimiter`, `ApiToken`, `constant_time_eq()` |
| **spectra-config** | 551 | 23 | TOML configuration with 11 sections, env var overrides (`SPECTRA_<SECTION>__<KEY>`), file/env/CLI precedence |
| **spectra-events** | 616 | 14 | Async broadcast event bus, 27 typed event variants across 8 categories, `EventHandler` trait, clone-safe multi-consumer |
| **spectra-storage** | 776 | 5 | `Database`, `Transaction`, `SearchIndex` traits, `LocalStorage`, `PostgresDatabase`, `PostgresSearchIndex` |
| **spectra-telemetry** | 86 | 4 | OpenTelemetry tracer initialization, log format configuration |

### Target & Discovery Layer

| Crate | Lines | Tests | Description |
|-------|-------|-------|-------------|
| **spectra-target** | 1,304 | 22 | Organization → Project → Target hierarchy, `TargetType` (Domain/URL/IP/CIDR), `ScopeEngine` with glob matching, `TargetService` CRUD |
| **spectra-http** | 1,207 | 21 | `HttpClient` with builder, `Session` with cookies, `RetryPolicy` (exponential backoff), proxy support (HTTP/HTTPS/SOCKS5) |
| **spectra-network** | 1,017 | 14 | `DnsResolver`, `PortScanner` (26 ports), `AssetGraph`, `NetworkEngine` orchestrating DNS + ports + subdomains |
| **spectra-fingerprint** | 1,161 | 17 | `RuleDatabase` with 60+ rules across 9 categories, `FingerprintEngine` with 6 detection vectors, version extraction via regex |
| **spectra-crawler** | 1,362 | 23 | BFS `UrlFrontier` with deduplication, `HtmlParser` for links/forms, `RobotsTxt` parser, `CrawlFilter` scope-aware filtering |

### Scanning & Analysis Layer

| Crate | Lines | Tests | Description |
|-------|-------|-------|-------------|
| **spectra-scanner** | 1,159 | 13 | `Scanner` async trait, **SQLi** (10 payloads, error+time blind), **XSS** (10 payloads, reflection checks), **DirSearch** (90+ paths) |
| **spectra-findings** | 2,988 | 69 | `ManagedFinding` lifecycle, `ObservationEngine` (13 types, severity scoring), `DetectionEngine` (8 rules, AND/OR logic), `CorrelationEngine`, `ReportGenerator` |
| **spectra-evidence** | 960 | 20 | `Evidence` with typed data, `EvidenceRedactor` (regex/JSON/header), `EvidenceIntegrity` (hash verification), `InMemoryEvidenceStore`, `EvidenceEngine` |
| **spectra-verification** | 750 | 20 | `VerificationEngine` with auto-verify by source/severity, `InMemoryVerificationStore`, confidence scoring, `VerificationStrategy` |
| **spectra-engine** | 621 | 10 | `ScanEngine` full pipeline: discover → crawl → fingerprint → scan → observe → verify → report, `ScanPlan`, `ScanJob`, `EngineMetrics` |

### Platform Layer

| Crate | Lines | Tests | Description |
|-------|-------|-------|-------------|
| **spectra-scheduler** | 821 | 25 | `InMemoryJobQueue` priority queue, retry with delay, max concurrency, cancel, `Job::builder()` |
| **spectra-plugins** | 667 | 21 | `Plugin` trait with health checks, `PluginCapability` (6 variants), `PluginManager`, built-in: Echo, Transform, Counter, Aggregator |
| **spectra-sandbox** | 696 | 26 | `LocalSandbox`, `ResourceLimits` (strict/permissive), `SandboxPolicy` (command allow/block), `AuditingSandbox` with audit log + metrics |

### Applications

| App | Lines | Description |
|-----|-------|-------------|
| **spectra-api** | 778 | Axum HTTP server with 20 REST endpoints, JSON error handling, AppState with all engines |
| **spectra-cli** | 694 | Clap CLI with 14 command groups, colored output, subcommand parsing |
| **spectra-worker** | 360 | Worker process with heartbeat, metrics (atomic counters), graceful shutdown, tokio::select! loop |

---

## Feature Matrix

### Scanning Capabilities

| Scanner | Payloads | Techniques | Parameters Tested |
|---------|----------|------------|-------------------|
| SQL Injection | 10 | Error-based, Time-based blind | 20 common param names |
| XSS | 10 | Reflection, Header injection | All URL params, forms |
| Directory Search | 90+ paths | 404 detection | 10 concurrent requests |

### Fingerprinting Rules (60+)

| Category | Example Technologies |
|----------|---------------------|
| Servers | Apache, Nginx, IIS, LiteSpeed |
| Frameworks | Django, Rails, Laravel, Spring |
| CMS | WordPress, Drupal, Joomla |
| Languages | PHP, Python, Ruby, Java, .NET |
| Databases | MySQL, PostgreSQL, MongoDB |
| JavaScript | React, Angular, Vue, jQuery |
| Security | Cloudflare, Akamai, WAF |
| Analytics | Google Analytics, Matomo |
| CDN | CloudFront, Fastly, Akamai |

### Observation Types (13)

| Type | Description |
|------|-------------|
| TechnologyDetected | Fingerprint match |
| VersionDetected | Version string extraction |
| VulnerabilityFound | Scanner detection |
| MisconfigurationFound | Config issue |
| InformationDisclosure | Data leak |
| AuthenticationIssue | Auth problem |
| AccessControlIssue | Authorization flaw |
| InputValidationIssue | Injection flaw |
| CryptographicIssue | Crypto weakness |
| NetworkExposure | Open port/service |
| ConfigurationDrift | Config change |
| DependencyVulnerability | Vuln dependency |
| CustomObservation | User-defined |

### Detection Rules (8 Built-in)

| Rule | Matcher | Logic |
|------|---------|-------|
| SQL Injection Detected | FieldContains("sql") + StatusCodeRange(500) | AND |
| XSS Reflected | FieldContains("xss") + FieldContains("reflected") | AND |
| Directory Listing | FieldEquals("directory_listing", "true") | Simple |
| Sensitive File | FieldRegex("path", "/(admin|backup|config)") | Regex |
| Weak SSL | FieldContains("ssl", "weak") | Simple |
| Unknown Port | FieldExists("unknown_service") | Exists |
| High Confidence | FieldContains("confidence", "high") | Simple |
| Custom Rule | Configurable AND/OR composition | Composite |

### Finding Lifecycle

```
New → Confirmed → Investigating → Fixed
         ↓
    False Positive
         ↓
      Duplicate
         ↓
      Accepted
```

### Evidence Types (14)

HttpRequest, HttpResponse, Screenshot, Document, ScannerOutput, NetworkCapture, FileContent, DatabaseRecord, ApiResponse, LogEntry, ConfigurationFile, Certificate, WhoisRecord, DnsRecord

### Evidence Data Variants (5)

Text, Binary, Url, Path, Json

### Redaction Policies (5 Patterns)

HeaderName, CookieName, JsonField, Regex, Literal

---

## API Endpoints (20)

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/v1/health` | Health check |
| POST | `/api/v1/organizations` | Create organization |
| GET | `/api/v1/organizations` | List organizations |
| GET | `/api/v1/organizations/:id` | Get organization |
| DELETE | `/api/v1/organizations/:id` | Delete organization |
| POST | `/api/v1/projects` | Create project |
| GET | `/api/v1/organizations/:org_id/projects` | List projects |
| POST | `/api/v1/targets` | Create target |
| GET | `/api/v1/projects/:project_id/targets` | List targets |
| GET | `/api/v1/targets/:id` | Get target |
| DELETE | `/api/v1/targets/:id` | Delete target |
| POST | `/api/v1/scans` | Create scan |
| GET | `/api/v1/findings` | List findings |
| GET | `/api/v1/findings/:id` | Get finding |
| POST | `/api/v1/findings/:id/status` | Update finding status |
| GET | `/api/v1/scans/:scan_id/observations` | List observations |
| GET | `/api/v1/findings/:finding_id/evidence` | List evidence |
| GET | `/api/v1/findings/:finding_id/verification` | List verifications |
| GET | `/api/v1/verification/summary` | Verification summary |
| GET | `/api/v1/stats` | Platform statistics |

---

## CLI Commands (14 Groups)

| Command | Subcommands | Description |
|---------|-------------|-------------|
| `spectra init` | — | Initialize configuration |
| `spectra organization` | list, create, show, delete | Organization management |
| `spectra project` | list, create, show, delete | Project management |
| `spectra target` | list, add, show, delete, scope | Target management |
| `spectra scan` | run, list, show, cancel | Scan management |
| `spectra finding` | list, show, update-status, stats | Finding management |
| `spectra observation` | list, show | Observation queries |
| `spectra evidence` | list, show | Evidence queries |
| `spectra verification` | list, summary | Verification queries |
| `spectra worker` | list, status | Worker management |
| `spectra plugin` | list, info | Plugin management |
| `spectra report` | generate | Report generation |
| `spectra stats` | — | Platform statistics |
| `spectra config` | show | Configuration display |

---

## Database Schema (26 Tables, 6 Migrations)

| Migration | Tables | Purpose |
|-----------|--------|---------|
| 001_initial | 4 | Core: organizations, projects, users, api_keys |
| 002_target_management | 5 | Targets, scopes, scope_rules, environments, target_metadata |
| 003_assets | 4 | Assets, asset_relationships, ports, dns_records |
| 004_scanning | 4 | Scans, scan_jobs, scan_configs, scan_progress |
| 005_findings | 5 | Findings, observations, evidence, evidence_integrity, detection_rules |
| 006_operations | 4 | Workers, jobs, audit_log, metrics |

---

## Security Features

| Feature | Implementation |
|---------|----------------|
| **No Unsafe Code** | `unsafe_code = "forbid"` workspace lint |
| **Input Validation** | `InputValidator` with max length, blocked patterns (XSS/injection), allowed chars |
| **Rate Limiting** | `RateLimiter` with sliding window, per-key tracking |
| **Constant-Time Comparison** | `constant_time_eq()` prevents timing attacks |
| **Token Generation** | `generate_token()` with hex encoding |
| **Hashing** | `hash_sha256()` for data integrity |
| **URL Sanitization** | SSRF prevention (blocks `@`, `\` in URLs) |
| **Sandbox** | Process isolation, resource limits, command allow/block lists |
| **Audit Logging** | All sandbox executions logged with command, duration, exit code, policy |
| **Evidence Integrity** | Hash verification for all evidence |
| **Credential Safety** | Never logged, env vars only |

---

## Test Coverage by Crate

```
findings     ████████████████████████████████████ 69
core         █████████████ 27
sandbox      █████████████ 26
scheduler    █████████████ 25
config       ████████████ 23
crawler      ████████████ 23
target       ███████████ 22
http         ███████████ 21
plugins      ███████████ 21
evidence     ██████████ 20
verification ██████████ 20
fingerprint  █████████ 17
events       ███████ 14
network      ███████ 14
scanner      ██████ 13
engine       █████ 10
storage      ██ 5
telemetry    ██ 4
```

**Total: 387 tests, 0 failures**

---

## Files & Code Statistics

| Category | Files | Lines |
|----------|-------|-------|
| Rust crates (18) | 68 | 17,592 |
| Rust apps (3) | 3 | 1,832 |
| SQL migrations | 6 | 577 |
| Documentation | 17 | 3,659 |
| npm package | 9 | ~200 |
| CI/CD | 1 | ~50 |
| Config/meta | 7 | ~200 |
| **Total** | **111** | **~24,110** |

---

## Dependencies

### Workspace Dependencies (16)

| Dependency | Purpose |
|------------|---------|
| async-trait | Async trait support |
| axum | HTTP framework |
| chrono | Date/time |
| clap | CLI parsing |
| dirs | Directory paths |
| num_cpus | CPU detection |
| serde / serde_json | Serialization |
| thiserror | Error derive |
| tokio | Async runtime |
| tom | TOML parsing |
| tracing / tracing-subscriber | Logging |
| url | URL parsing |
| uuid | UUID generation |

### External Service Dependencies (All Optional)

| Service | Purpose | Required? |
|---------|---------|-----------|
| PostgreSQL 15+ | Persistent storage | No (in-memory default) |
| Redis 7+ | Job queue | No (in-memory default) |
| OpenTelemetry collector | Tracing export | No (disabled default) |
| OpenAI API | AI analysis | No (disabled default) |

---

## Distribution

| Channel | URL | Version |
|---------|-----|---------|
| GitHub | https://github.com/Hilbras/Spectra | v0.1.0 release |
| npm | https://www.npmjs.com/package/@hilbras/spectra | 0.1.1 |
| Install | `npm install -g @hilbras/spectra` | — |

---

## What's Next (Roadmap)

| Phase | Description | Status |
|-------|-------------|--------|
| PostgreSQL wiring | Connect all in-memory stores to Postgres | Pending |
| Redis scheduler | Replace in-memory queue with Redis | Pending |
| Authentication | API key + OAuth2 auth | Pending |
| WASM plugins | WebAssembly plugin runtime | Pending |
| Python plugins | Python plugin support | Pending |
| Web frontend | Dashboard UI | Pending |
| Docker | Container image | Pending |
| GitHub Actions | CI/CD pipeline | Pending |
| crates.io | Publish core crates | Pending |
