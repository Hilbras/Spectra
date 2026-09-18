# Spectra Architecture Specification v1.0

> Status: Draft  
> Date: 2026-09-17  
> Authors: Spectra Development Team

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [Design Principles](#2-design-principles)
3. [System Overview](#3-system-overview)
4. [Module Specification](#4-module-specification)
5. [Data Models](#5-data-models)
6. [API Boundaries](#6-api-boundaries)
7. [Event System](#7-event-system)
8. [Plugin Contracts](#8-plugin-contracts)
9. [Worker Contracts](#9-worker-contracts)
10. [Storage Abstractions](#10-storage-abstractions)
11. [Security Boundaries](#11-security-boundaries)
12. [Dependency Direction](#12-dependency-direction)
13. [Error Handling Strategy](#13-error-handling-strategy)
14. [Configuration Strategy](#14-configuration-strategy)
15. [Testing Strategy](#15-testing-strategy)
16. [Versioning Strategy](#16-versioning-strategy)
17. [Deployment Architecture](#17-deployment-architecture)
18. [Architecture Decision Records](#18-architecture-decision-records)

---

## 1. Executive Summary

Spectra is a modular, extensible, distributed security testing and analysis platform for authorized targets. The system combines target management, asset discovery, reconnaissance, technology fingerprinting, web crawling, security scanning, network analysis, evidence collection, finding detection, finding verification, finding correlation, AI-assisted analysis, knowledge management, automation, distributed execution, a plugin ecosystem, reporting, integrations, and enterprise capabilities.

### Core Workflow

```
UNDERSTAND → DISCOVER → OBSERVE → ANALYZE → DETECT → VERIFY → CORRELATE → EXPLAIN → REPORT → AUTOMATE
```

The scanner is one component inside this pipeline, not the entire system.

---

## 2. Design Principles

| Principle | Description |
|-----------|-------------|
| **Modularity** | Every subsystem is a distinct crate/module with clear boundaries |
| **Extensibility** | Plugins extend functionality without modifying core |
| **Scope Safety** | Every active operation passes scope validation before execution |
| **Evidence-Based** | Findings require evidence; no unsupported claims |
| **Provider Agnostic** | AI, storage, and execution providers are abstracted and replaceable |
| **Incremental Complexity** | System works on one machine before distributing |
| **Defense in Depth** | Security boundaries at every layer |
| **Observable** | Every important subsystem emits metrics, logs, and traces |

---

## 3. System Overview

### 3.1 Architecture Planes

```
                         SPECTRA
                            │
        ┌───────────────────┼───────────────────┐
        │                   │                   │
       CLI                 API                 WEB
        │                   │                   │
        └───────────────────┼───────────────────┘
                            │
                       CONTROL PLANE
                            │
        ┌───────────────────┼───────────────────┐
        │                   │                   │
    Scheduler          Automation            AI Layer
        │                   │                   │
        └───────────────────┼───────────────────┘
                            │
                     EXECUTION PLANE
                            │
       ┌──────────┬─────────┼─────────┬──────────┐
       │          │         │         │          │
  Discovery   Crawler   Scanner   Verify    Analysis
       │          │         │         │          │
       └──────────┴─────────┼─────────┴──────────┘
                            │
                     PLUGIN RUNTIME
                            │
                  ┌─────────┼─────────┐
                  │         │         │
                 Rust     Python     WASM
                  │         │         │
                  └─────────┼─────────┘
                            │
                       DATA LAYER
                            │
          ┌─────────────────┼─────────────────┐
          │                 │                 │
      PostgreSQL       Object Storage      Search
          │                 │                 │
          └─────────────────┼─────────────────┘
                            │
                       OBSERVABILITY
```

### 3.2 Boundary Rules

- Core must not depend on the Web UI
- Scanners must not directly manipulate the database
- Plugins interact through defined contracts only
- AI is replaceable and optional
- Storage is abstracted behind traits
- Execution is separable from orchestration

---

## 4. Module Specification

### 4.1 Crate Map

```
spectra/
├── apps/
│   ├── api/           # Axum HTTP API server
│   ├── web/           # React frontend
│   ├── cli/           # CLI application
│   └── worker/        # Worker process
│
├── crates/
│   ├── core/          # Shared primitives, types, error definitions
│   ├── engine/        # Orchestration engine (scan lifecycle)
│   ├── target/        # Target and scope management
│   ├── crawler/       # Web crawler
│   ├── scanner/       # Scanner framework and runtime
│   ├── network/       # Network analysis (DNS, ports, services)
│   ├── fingerprint/   # Technology fingerprinting
│   ├── scheduler/     # Job scheduling and queue management
│   ├── findings/      # Finding model and management
│   ├── verification/  # Finding verification engine
│   ├── evidence/      # Evidence collection and storage
│   ├── plugins/       # Plugin runtime and contracts
│   ├── sandbox/       # Plugin sandboxing and resource limits
│   ├── events/        # Event bus and event types
│   ├── storage/       # Storage abstraction layer
│   ├── config/        # Configuration management
│   └── telemetry/     # OpenTelemetry integration
│
├── modules/
│   ├── rust/          # Built-in Rust scanner modules
│   ├── python/        # Python security modules
│   └── wasm/          # WASM plugins
│
├── packages/
│   ├── sdk/           # Developer SDK
│   ├── protocol/      # Communication protocols
│   └── types/         # Shared type definitions
│
├── migrations/        # SQLx database migrations
├── docs/              # Documentation
├── tests/             # Integration and E2E tests
└── infrastructure/    # Deployment configurations
```

### 4.2 Crate Dependency Graph

```
                    core
                     │
        ┌────────────┼────────────┐
        │            │            │
     events       config      storage
        │            │            │
        └─────┬──────┘            │
              │                   │
           target                 │
              │                   │
    ┌─────────┼─────────┐        │
    │         │         │        │
 network  fingerprint  crawler   │
    │         │         │        │
    └─────────┼─────────┘        │
              │                  │
           scanner               │
              │                  │
        ┌─────┼─────┐           │
        │           │           │
   findings    evidence         │
        │           │           │
        └─────┬─────┘           │
              │                 │
        verification            │
              │                 │
           engine ──────────────┘
              │
        ┌─────┼──────────┐
        │     │          │
   scheduler  plugins  sandbox
        │     │          │
        └─────┼──────────┘
              │
         ┌────┼────┐
         │         │
       api       cli
         │         │
         └────┬────┘
              │
            worker
```

### 4.3 Crate Descriptions

#### `core`
Shared primitives, error types, identifiers, time utilities, and common abstractions.

**Public API:**
- `SpectraError` - Unified error type
- `ErrorKind` - Error classification
- `Result<T>` - Unified result type
- `Id` - Typed identifiers (newtype over UUID)
- `Timestamp` - Time abstraction
- `Metadata` - Generic metadata container

**Dependencies:** None (leaf crate)

---

#### `events`
Event bus implementation using in-process channels with optional external transport.

**Public API:**
- `EventBus` - Publish/subscribe event bus
- `Event` - Base event envelope
- `EventType` - Event classification enum
- `EventHandler` - Trait for event consumers
- `EventFilter` - Filtering subscriptions

**Events defined:**
- `TargetCreated`, `TargetUpdated`, `TargetDeleted`
- `ScanStarted`, `ScanProgress`, `ScanCompleted`, `ScanFailed`
- `FindingCreated`, `FindingUpdated`, `FindingVerified`
- `AssetDiscovered`, `AssetUpdated`
- `WorkerRegistered`, `WorkerHeartbeat`, `WorkerOffline`
- `PluginLoaded`, `PluginUnloaded`, `PluginError`

**Dependencies:** `core`

---

#### `config`
Configuration loading from files, environment variables, and CLI arguments.

**Public API:**
- `Config` - Root configuration struct
- `DatabaseConfig` - Database connection settings
- `ApiConfig` - API server settings
- `WorkerConfig` - Worker settings
- `ScannerConfig` - Scanner behavior settings
- `PluginConfig` - Plugin system settings
- `AiConfig` - AI provider settings
- `StorageConfig` - Storage backend settings

**Configuration sources (priority order):**
1. CLI arguments
2. Environment variables
3. Config file (`spectra.toml`)
4. Defaults

**Dependencies:** `core`, `serde`, `toml`

---

#### `storage`
Storage abstraction layer over PostgreSQL, object storage, and search.

**Public API:**
- `Storage` - Main storage trait (object storage)
- `Database` - Database access trait
- `SearchIndex` - Search index trait
- `Repository<T>` - Generic repository pattern
- `Transaction` - Database transaction wrapper

**Dependencies:** `core`, `sqlx`, `serde`

---

#### `target`
Target and scope management.

**Public API:**
- `TargetService` - Target CRUD operations
- `ScopeEngine` - Scope validation
- `Target` - Target model
- `Scope` - Scope definition
- `Organization`, `Project` - Organizational units
- `Credential` - Credential storage reference
- `Environment` - Target environment classification

**Scope validation rules:**
- Allowed/excluded targets
- Domain matching (with wildcards)
- IP range matching (CIDR)
- Port range matching
- Path prefix matching
- Protocol restrictions
- Rate limits
- Execution time limits

**Dependencies:** `core`, `storage`, `events`

---

#### `network`
Network analysis and discovery.

**Public API:**
- `NetworkEngine` - Main network analysis entry point
- `DnsResolver` - DNS resolution with caching
- `PortScanner` - TCP/UDP port scanning
- `ServiceDetector` - Service identification
- `HostDiscovery` - Network host discovery
- `NetworkMap` - Network topology representation

**Capabilities:**
- DNS resolution and zone transfer
- Subdomain enumeration
- A/AAAA/MX/NS/TXT/CNAME record resolution
- TCP connect scanning
- Service banner grabbing
- OS fingerprinting (passive)

**Dependencies:** `core`, `target`, `config`, `events`

---

#### `fingerprint`
Technology detection and identification.

**Public API:**
- `FingerprintEngine` - Main fingerprinting entry point
- `Fingerprint` - Detected technology
- `TechnologyCategory` - Classification (server, framework, CMS, language, etc.)
- `FingerprintRule` - Detection rule definition
- `FingerprintResult` - Aggregated fingerprint results

**Detection categories:**
- Web servers (Apache, Nginx, IIS, etc.)
- Programming languages (PHP, Python, Node.js, etc.)
- Frameworks (Django, Rails, Express, Spring, etc.)
- CMS (WordPress, Drupal, Joomla, etc.)
- JavaScript frameworks (React, Vue, Angular, etc.)
- API technologies (REST, GraphQL, gRPC, etc.)
- Authentication mechanisms
- CDN and infrastructure indicators
- Database technologies
- Caching layers

**Dependencies:** `core`, `network`, `storage`

---

#### `crawler`
Persistent, concurrent, scope-aware web crawler.

**Public API:**
- `Crawler` - Main crawler entry point
- `CrawlRequest` - Crawl job definition
- `CrawlResult` - Crawl results
- `CrawledPage` - Individual page data
- `CrawlFilter` - URL filtering rules
- `CrawlPolicy` - Rate limiting and behavior rules

**Pipeline:**
```
Seed → Fetch → Parse → Extract → Normalize → Deduplicate → Queue → Fetch
```

**Capabilities:**
- HTML parsing and link extraction
- Form detection and parameter extraction
- JavaScript reference extraction
- API endpoint detection
- Robots.txt parsing
- Sitemap.xml parsing
- Scope-aware URL filtering
- Rate limiting per domain
- Concurrent fetching with connection pooling
- Persistent crawl state (resumable)

**Future:**
- Headless browser integration
- JavaScript rendering
- SPA crawling

**Dependencies:** `core`, `target`, `network`, `storage`, `events`, `config`

---

#### `scanner`
Scanner framework and runtime.

**Public API:**
- `ScannerRuntime` - Scanner execution engine
- `Scanner` - Scanner trait definition
- `ScannerMetadata` - Scanner identification
- `ScannerCapabilities` - What the scanner can test
- `ScannerRequirements` - What the scanner needs
- `ScanRequest` - Scan job definition
- `ScanResult` - Scan output
- `Observation` - Raw observation from scanner

**Scanner contract:**
```rust
#[async_trait]
pub trait Scanner: Send + Sync {
    fn metadata(&self) -> ScannerMetadata;
    fn capabilities(&self) -> ScannerCapabilities;
    fn requirements(&self) -> ScannerRequirements;
    
    async fn execute(
        &self,
        request: ScanRequest,
        context: ScannerContext,
    ) -> Result<ScanResult>;
}
```

**Scanner lifecycle:**
```
Scanner → Target → Requests/Observations → Detection → Evidence → Candidate Finding
```

**Dependencies:** `core`, `target`, `network`, `crawler`, `storage`, `events`, `config`, `plugins`

---

#### `findings`
Finding model, management, and correlation.

**Public API:**
- `FindingService` - Finding CRUD and queries
- `Finding` - Finding model
- `FindingSeverity` - Severity classification
- `FindingStatus` - Lifecycle status
- `FindingType` - Finding classification
- `CorrelationEngine` - Finding correlation
- `FindingGroup` - Related findings

**Finding model:**
```rust
pub struct Finding {
    pub id: Id<Finding>,
    pub title: String,
    pub severity: FindingSeverity,
    pub confidence: f64,
    pub status: FindingStatus,
    pub finding_type: FindingType,
    pub target_id: Id<Target>,
    pub asset_id: Option<Id<Asset>>,
    pub location: FindingLocation,
    pub evidence: Vec<Evidence>,
    pub detection_source: DetectionSource,
    pub verification_status: VerificationStatus,
    pub correlation_id: Option<Id<FindingGroup>>,
    pub created_at: Timestamp,
    pub updated_at: Timestamp,
}
```

**Dependencies:** `core`, `storage`, `events`, `evidence`

---

#### `evidence`
Evidence collection, storage, and redaction.

**Public API:**
- `EvidenceService` - Evidence management
- `Evidence` - Evidence model
- `EvidenceType` - Classification (request, response, timing, etc.)
- `EvidenceStore` - Evidence storage interface
- `Redactor` - Sensitive data redaction

**Evidence types:**
- HTTP request/response pairs
- Response headers
- Response body excerpts
- Timing data
- Fingerprint data
- Scanner output
- Verification results

**Redaction rules:**
- Credentials and secrets
- Personal data (PII)
- Session tokens
- API keys
- Configurable patterns

**Dependencies:** `core`, `storage`

---

#### `verification`
Finding verification engine for false positive reduction.

**Public API:**
- `VerificationEngine` - Main verification entry point
- `VerificationStrategy` - Verification approach trait
- `VerificationResult` - Verification outcome
- `VerificationEvidence` - Evidence supporting verification

**Verification strategies:**
- Re-fetch verification
- Payload verification
- Header analysis
- Response pattern matching
- Timing verification
- Technology-specific verification

**Pipeline:**
```
Candidate Finding → Verification → Evidence → Confirmed/Unconfirmed
```

**Dependencies:** `core`, `findings`, `evidence`, `network`, `scanner`

---

#### `engine`
Orchestration engine managing the scan lifecycle.

**Public API:**
- `ScanEngine` - Main scan orchestration
- `ScanPlan` - Pre-scan planning
- `ScanPipeline` - Execution pipeline stages
- `PipelineStage` - Individual stage trait
- `ScanContext` - Shared scan context

**Scan pipeline:**
```
Scope Validation → Asset Discovery → Fingerprinting → Crawling → Security Planning → Scanning → Detection → Verification → Correlation → Reporting
```

**Dependencies:** `core`, `target`, `network`, `fingerprint`, `crawler`, `scanner`, `findings`, `verification`, `evidence`, `storage`, `events`, `config`, `scheduler`

---

#### `scheduler`
Job scheduling and queue management.

**Public API:**
- `Scheduler` - Main scheduler
- `Job` - Job definition
- `JobType` - Job classification
- `JobStatus` - Job lifecycle status
- `JobQueue` - Queue interface
- `Schedule` - Cron-like scheduling

**Job types:**
- Scan jobs
- Discovery jobs
- Crawl jobs
- Verification jobs
- Report generation jobs
- Maintenance jobs

**Capabilities:**
- One-time execution
- Recurring schedules (cron)
- Priority queuing
- Concurrency control
- Timeout enforcement
- Retry with backoff
- Cancellation
- Resume from checkpoint

**Dependencies:** `core`, `storage`, `events`, `config`

---

#### `plugins`
Plugin runtime and contract definitions.

**Public API:**
- `PluginManager` - Plugin lifecycle management
- `Plugin` - Plugin trait definition
- `PluginManifest` - Plugin metadata
- `PluginContext` - Plugin execution context
- `PluginCapability` - Capability declarations
- `PluginPermission` - Permission model

**Plugin manifest:**
```toml
[plugin]
name = "example-scanner"
version = "1.0.0"
author = "Spectra Team"
description = "Example scanner plugin"

[plugin.capabilities]
scanner = true
detector = false
reporter = false
integration = false

[plugin.permissions]
network = ["example.com"]
storage = ["read"]
sandbox = "strict"

[plugin.runtime]
type = "python"
version = "3.11"
entry_point = "main.py"

[plugin.requirements]
python-packages = ["requests", "beautifulsoup4"]
```

**Dependencies:** `core`, `sandbox`, `config`, `events`

---

#### `sandbox`
Plugin sandboxing and resource limits.

**Public API:**
- `Sandbox` - Sandbox environment
- `SandboxConfig` - Resource limits
- `ResourceMonitor` - Resource usage tracking
- `PermissionGuard` - Permission enforcement

**Resource limits:**
- CPU time
- Memory usage
- Wall-clock time
- Filesystem access (read/write paths)
- Network access (allowed hosts)
- Process count
- Output size

**Isolation levels:**
- `strict` - WASM-based isolation
- `moderate` - Process-based isolation with resource limits
- `relaxed` - Process-based with monitoring only

**Dependencies:** `core`, `config`

---

#### `telemetry`
OpenTelemetry integration.

**Public API:**
- `Telemetry` - Telemetry initialization
- `Metrics` - Custom metrics definitions
- `Tracing` - Distributed tracing setup
- `HealthCheck` - Health check endpoints

**Metrics:**
- `spectra_scans_total` - Total scans executed
- `spectra_findings_total` - Total findings by severity
- `spectra_crawler_pages_total` - Pages crawled
- `spectra_scanner_observations_total` - Scanner observations
- `spectra_worker_jobs_total` - Worker job completions
- `spectra_plugin_executions_total` - Plugin executions
- `spectra_api_requests_total` - API request count
- `spectra_api_request_duration` - API request latency

**Dependencies:** `core`, `config`, `opentelemetry`

---

### 4.4 Application Crates

#### `apps/api`
Axum-based HTTP API server.

**Responsibilities:**
- HTTP routing and middleware
- Request/response serialization
- Authentication and authorization
- WebSocket/SSE for live events
- OpenAPI documentation

**Dependencies:** `axum`, `tower`, `core`, `target`, `engine`, `findings`, `scheduler`, `plugins`, `storage`, `telemetry`

---

#### `apps/web`
React + TypeScript + Tailwind CSS frontend.

**Responsibilities:**
- Dashboard and project management
- Target and scope management
- Scan initiation and monitoring
- Finding review and management
- Report generation and viewing
- Worker and plugin management
- System health monitoring

**Dependencies:** `react`, `typescript`, `tailwindcss`, `vite`

---

#### `apps/cli`
CLI application built with `clap`.

**Responsibilities:**
- All API operations accessible via CLI
- Automation-friendly output formats
- Configuration management
- Local development support

**Commands:**
```bash
spectra init
spectra project {create,list,show,delete}
spectra target {add,list,show,delete,scope}
spectra scan {run,list,show,cancel}
spectra assets {list,show}
spectra findings {list,show,verify,correlate}
spectra workers {list,status}
spectra plugins {list,install,remove,enable,disable}
spectra report {generate,list,show}
spectra config {get,set,show}
```

**Dependencies:** `clap`, `core`, `engine`, `target`, `findings`, `scheduler`, `config`

---

#### `apps/worker`
Worker process for distributed execution.

**Responsibilities:**
- Connect to scheduler
- Execute assigned jobs
- Report progress and results
- Advertise capabilities
- Handle graceful shutdown

**Worker advertisement:**
```rust
pub struct WorkerInfo {
    pub id: Id<Worker>,
    pub version: String,
    pub capabilities: Vec<WorkerCapability>,
    pub status: WorkerStatus,
    pub resources: WorkerResources,
}
```

**Dependencies:** `core`, `scheduler`, `scanner`, `crawler`, `network`, `fingerprint`, `storage`, `config`, `events`, `telemetry`

---

## 5. Data Models

### 5.1 Core Entities

```rust
// Identifiers
pub struct Id<T>(Uuid, PhantomData<T>);

// Timestamps
pub struct Timestamp {
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}
```

### 5.2 Organizational

```rust
pub struct Organization {
    pub id: Id<Organization>,
    pub name: String,
    pub slug: String,
    pub settings: OrganizationSettings,
    pub timestamp: Timestamp,
}

pub struct Project {
    pub id: Id<Project>,
    pub organization_id: Id<Organization>,
    pub name: String,
    pub slug: String,
    pub description: Option<String>,
    pub status: ProjectStatus,
    pub settings: ProjectSettings,
    pub timestamp: Timestamp,
}
```

### 5.3 Target

```rust
pub struct Target {
    pub id: Id<Target>,
    pub project_id: Id<Project>,
    pub name: String,
    pub target_type: TargetType,
    pub value: String,           // Domain, URL, IP, CIDR
    pub scope: Scope,
    pub credentials: Vec<CredentialRef>,
    pub environment: Environment,
    pub metadata: HashMap<String, Value>,
    pub timestamp: Timestamp,
}

pub enum TargetType {
    Domain,
    Url,
    IpAddress,
    CidrRange,
    Custom(String),
}

pub struct Scope {
    pub allowed: Vec<ScopeRule>,
    pub excluded: Vec<ScopeRule>,
    pub rate_limits: RateLimits,
    pub execution_limits: ExecutionLimits,
}

pub struct ScopeRule {
    pub rule_type: ScopeRuleType,
    pub value: String,
    pub description: Option<String>,
}

pub enum ScopeRuleType {
    Domain,
    DomainSuffix,
    IpRange,
    PortRange,
    PathPrefix,
    Protocol,
}
```

### 5.4 Asset

```rust
pub struct Asset {
    pub id: Id<Asset>,
    pub target_id: Id<Target>,
    pub asset_type: AssetType,
    pub value: String,
    pub parent_id: Option<Id<Asset>>,
    pub properties: HashMap<String, Value>,
    pub timestamp: Timestamp,
}

pub enum AssetType {
    Domain,
    Subdomain,
    IpAddress,
    Port,
    Service,
    WebApplication,
    Technology,
    Endpoint,
    ApiEndpoint,
}

pub struct AssetGraph {
    pub assets: Vec<Asset>,
    pub edges: Vec<AssetEdge>,
}

pub struct AssetEdge {
    pub from: Id<Asset>,
    pub to: Id<Asset>,
    pub relationship: AssetRelationship,
}
```

### 5.5 Scan

```rust
pub struct Scan {
    pub id: Id<Scan>,
    pub project_id: Id<Project>,
    pub target_id: Id<Target>,
    pub scan_type: ScanType,
    pub status: ScanStatus,
    pub config: ScanConfig,
    pub progress: ScanProgress,
    pub result: Option<ScanResult>,
    pub started_at: Option<Timestamp>,
    pub completed_at: Option<Timestamp>,
    pub timestamp: Timestamp,
}

pub enum ScanStatus {
    Pending,
    Planning,
    Running,
    Paused,
    Completed,
    Failed,
    Cancelled,
}

pub struct ScanProgress {
    pub current_stage: ScanStage,
    pub stages_completed: u32,
    pub total_stages: u32,
    pub percent_complete: f64,
    pub current_activity: String,
}

pub enum ScanStage {
    ScopeValidation,
    AssetDiscovery,
    Fingerprinting,
    Crawling,
    SecurityPlanning,
    Scanning,
    Detection,
    Verification,
    Correlation,
    Reporting,
}
```

### 5.6 Finding

```rust
pub struct Finding {
    pub id: Id<Finding>,
    pub scan_id: Option<Id<Scan>>,
    pub target_id: Id<Target>,
    pub asset_id: Option<Id<Asset>>,
    pub title: String,
    pub description: String,
    pub severity: FindingSeverity,
    pub confidence: f64,           // 0.0 to 1.0
    pub status: FindingStatus,
    pub finding_type: FindingType,
    pub location: FindingLocation,
    pub evidence: Vec<EvidenceRef>,
    pub detection_source: DetectionSource,
    pub verification: VerificationStatus,
    pub correlation_id: Option<Id<FindingGroup>>,
    pub recommendations: Vec<String>,
    pub references: Vec<String>,
    pub cwe_id: Option<String>,
    pub cvss_score: Option<f64>,
    pub timestamp: Timestamp,
}

pub enum FindingSeverity {
    Critical,
    High,
    Medium,
    Low,
    Informational,
}

pub enum FindingStatus {
    New,
    Confirmed,
    FalsePositive,
    Fixed,
    Accepted,
    Duplicate,
}

pub enum FindingType {
    Vulnerability,
    Misconfiguration,
    InformationDisclosure,
    SecurityWeakness,
    ComplianceViolation,
    Custom(String),
}
```

### 5.7 Evidence

```rust
pub struct Evidence {
    pub id: Id<Evidence>,
    pub finding_id: Id<Finding>,
    pub evidence_type: EvidenceType,
    pub content: EvidenceContent,
    pub redacted: bool,
    pub timestamp: Timestamp,
}

pub enum EvidenceType {
    HttpRequest,
    HttpResponse,
    Header,
    Timing,
    Fingerprint,
    ScannerOutput,
    VerificationResult,
    Screenshot,
    Custom(String),
}

pub enum EvidenceContent {
    Text(String),
    Binary(Vec<u8>),
    Json(Value),
    HttpRequest(HttpRequestEvidence),
    HttpResponse(HttpResponseEvidence),
}
```

### 5.8 Worker

```rust
pub struct Worker {
    pub id: Id<Worker>,
    pub hostname: String,
    pub version: String,
    pub capabilities: Vec<WorkerCapability>,
    pub status: WorkerStatus,
    pub resources: WorkerResources,
    pub current_job: Option<Id<Job>>,
    pub last_heartbeat: Timestamp,
    pub registered_at: Timestamp,
}

pub enum WorkerCapability {
    Scanning,
    Crawling,
    NetworkAnalysis,
    Fingerprinting,
    Verification,
    PluginExecution(String),
}

pub struct WorkerResources {
    pub cpu_cores: u32,
    pub memory_mb: u64,
    pub disk_gb: u64,
    pub network_mbps: u64,
}
```

### 5.9 Plugin

```rust
pub struct Plugin {
    pub id: Id<Plugin>,
    pub manifest: PluginManifest,
    pub status: PluginStatus,
    pub loaded_at: Option<Timestamp>,
    pub error: Option<String>,
}

pub struct PluginManifest {
    pub name: String,
    pub version: String,
    pub author: String,
    pub description: String,
    pub capabilities: Vec<PluginCapability>,
    pub permissions: PluginPermissions,
    pub runtime: PluginRuntime,
    pub requirements: PluginRequirements,
}

pub enum PluginCapability {
    Scanner,
    Detector,
    Reporter,
    Integration,
    AiModule,
}

pub enum PluginRuntime {
    Rust { crate_name: String },
    Python { entry_point: String },
    Wasm { module_path: String },
}
```

### 5.10 Job

```rust
pub struct Job {
    pub id: Id<Job>,
    pub job_type: JobType,
    pub priority: JobPriority,
    pub status: JobStatus,
    pub payload: Vec<u8>,           // Serialized job payload
    pub assigned_worker: Option<Id<Worker>>,
    pub result: Option<Vec<u8>>,    // Serialized result
    pub error: Option<String>,
    pub attempts: u32,
    pub max_attempts: u32,
    pub scheduled_at: Timestamp,
    pub started_at: Option<Timestamp>,
    pub completed_at: Option<Timestamp>,
    pub created_at: Timestamp,
}

pub enum JobType {
    Scan,
    Discovery,
    Crawl,
    Verification,
    Report,
    Maintenance,
    Custom(String),
}

pub enum JobStatus {
    Pending,
    Queued,
    Assigned,
    Running,
    Completed,
    Failed,
    Cancelled,
}
```

---

## 6. API Boundaries

### 6.1 API Structure

```
/api/v1/
├── /organizations
├── /projects
├── /targets
├── /scans
├── /findings
├── /evidence
├── /assets
├── /workers
├── /plugins
├── /reports
├── /system
│   ├── /health
│   ├── /metrics
│   └── /config
└── /events (WebSocket/SSE)
```

### 6.2 Authentication

- API key authentication
- JWT token authentication (enterprise)
- Session-based authentication (web UI)

### 6.3 Rate Limiting

- Per-API-key rate limits
- Per-organization rate limits
- Per-endpoint rate limits
- Configurable via `spectra.toml`

### 6.4 Response Format

```json
{
    "status": "success",
    "data": {},
    "meta": {
        "page": 1,
        "per_page": 25,
        "total": 100
    }
}
```

### 6.5 Error Format

```json
{
    "status": "error",
    "error": {
        "code": "NOT_FOUND",
        "message": "Target not found",
        "details": {}
    }
}
```

---

## 7. Event System

### 7.1 Event Envelope

```rust
pub struct Event {
    pub id: Id<Event>,
    pub event_type: EventType,
    pub source: EventSource,
    pub payload: EventPayload,
    pub metadata: HashMap<String, Value>,
    pub timestamp: Timestamp,
}

pub enum EventSource {
    System,
    User(Id<User>),
    Worker(Id<Worker>),
    Plugin(Id<Plugin>),
    Scheduler,
}

pub enum EventPayload {
    TargetCreated(Target),
    TargetUpdated(Target),
    TargetDeleted { target_id: Id<Target> },
    ScanStarted(Scan),
    ScanProgress { scan_id: Id<Scan>, progress: ScanProgress },
    ScanCompleted(Scan),
    ScanFailed { scan_id: Id<Scan>, error: String },
    FindingCreated(Finding),
    FindingUpdated(Finding),
    FindingVerified { finding_id: Id<Finding>, verified: bool },
    AssetDiscovered(Asset),
    AssetUpdated(Asset),
    WorkerRegistered(Worker),
    WorkerHeartbeat { worker_id: Id<Worker> },
    WorkerOffline { worker_id: Id<Worker> },
    PluginLoaded(Plugin),
    PluginUnloaded { plugin_id: Id<Plugin> },
    PluginError { plugin_id: Id<Plugin>, error: String },
    JobQueued(Job),
    JobAssigned { job_id: Id<Job>, worker_id: Id<Worker> },
    JobCompleted(Job),
    JobFailed { job_id: Id<Job>, error: String },
}
```

### 7.2 Event Delivery

- In-process event bus for single-machine operation
- Redis/NATS for distributed event delivery
- WebSocket/SSE for real-time UI updates
- Event persistence for audit trail

---

## 8. Plugin Contracts

### 8.1 Plugin Trait (Rust)

```rust
#[async_trait]
pub trait Plugin: Send + Sync {
    fn manifest(&self) -> &PluginManifest;
    
    async fn initialize(&self, context: PluginContext) -> Result<()>;
    
    async fn shutdown(&self) -> Result<()>;
    
    async fn health_check(&self) -> Result<PluginHealth>;
}

#[async_trait]
pub trait ScannerPlugin: Plugin {
    async fn scan(&self, request: ScanRequest) -> Result<ScanResult>;
}

#[async_trait]
pub trait DetectorPlugin: Plugin {
    async fn detect(&self, input: DetectionInput) -> Result<DetectionResult>;
}

#[async_trait]
pub trait ReporterPlugin: Plugin {
    async fn generate(&self, request: ReportRequest) -> Result<ReportOutput>;
}

#[async_trait]
pub trait IntegrationPlugin: Plugin {
    async fn execute(&self, action: IntegrationAction) -> Result<IntegrationResult>;
}
```

### 8.2 Plugin Context

```rust
pub struct PluginContext {
    pub plugin_id: Id<Plugin>,
    pub config: Value,
    pub storage: Box<dyn PluginStorage>,
    pub events: Box<dyn PluginEventEmitter>,
    pub http: Box<dyn PluginHttpClient>,
    pub logger: Box<dyn PluginLogger>,
}
```

### 8.3 Plugin Permissions

```rust
pub struct PluginPermissions {
    pub network: Vec<String>,        // Allowed network targets
    pub storage_access: StorageAccess,
    pub file_access: Vec<String>,    // Allowed file paths
    pub process_access: bool,
    pub max_memory_mb: u64,
    pub max_cpu_seconds: u64,
    pub max_wall_seconds: u64,
}
```

---

## 9. Worker Contracts

### 9.1 Worker Registration

```rust
pub struct RegisterWorker {
    pub hostname: String,
    pub version: String,
    pub capabilities: Vec<WorkerCapability>,
    pub resources: WorkerResources,
}
```

### 9.2 Job Assignment

```rust
pub struct AssignJob {
    pub job_id: Id<Job>,
    pub job_type: JobType,
    pub payload: Vec<u8>,
    pub timeout_seconds: u64,
}
```

### 9.3 Job Progress

```rust
pub struct JobProgress {
    pub job_id: Id<Job>,
    pub progress: f64,
    pub message: String,
    pub partial_result: Option<Vec<u8>>,
}
```

### 9.4 Job Completion

```rust
pub struct JobComplete {
    pub job_id: Id<Job>,
    pub result: Vec<u8>,
    pub duration_ms: u64,
    pub metrics: JobMetrics,
}
```

---

## 10. Storage Abstractions

### 10.1 Object Storage Trait

```rust
#[async_trait]
pub trait Storage: Send + Sync {
    async fn put(&self, key: &str, data: Vec<u8>, content_type: &str) -> Result<()>;
    async fn get(&self, key: &str) -> Result<Option<Vec<u8>>>;
    async fn delete(&self, key: &str) -> Result<()>;
    async fn list(&self, prefix: &str) -> Result<Vec<String>>;
    async fn exists(&self, key: &str) -> Result<bool>;
    async fn presign(&self, key: &str, expiry: Duration) -> Result<String>;
}
```

### 10.2 Database Trait

```rust
#[async_trait]
pub trait Database: Send + Sync {
    async fn execute(&self, query: &str, params: &[Value]) -> Result<u64>;
    async fn query(&self, query: &str, params: &[Value]) -> Result<Vec<Row>>;
    async fn query_one(&self, query: &str, params: &[Value]) -> Result<Option<Row>>;
    async fn transaction(&self) -> Result<Box<dyn Transaction>>;
}
```

### 10.3 Search Index Trait

```rust
#[async_trait]
pub trait SearchIndex: Send + Sync {
    async fn index(&self, index: &str, id: &str, document: Value) -> Result<()>;
    async fn search(&self, index: &str, query: &str, limit: usize) -> Result<Vec<SearchResult>>;
    async fn delete(&self, index: &str, id: &str) -> Result<()>;
    async fn bulk_index(&self, index: &str, documents: Vec<(String, Value)>) -> Result<()>;
}
```

### 10.4 Storage Backends

| Backend | Use Case |
|---------|----------|
| PostgreSQL | Structured data, relationships, transactions |
| Object Storage (S3/MinIO) | Large objects, evidence, reports, artifacts |
| OpenSearch | Full-text search, log analysis, audit search |
| Redis/NATS | Queues, caching, pub/sub, session state |

---

## 11. Security Boundaries

### 11.1 Scope Enforcement

Every active operation must validate scope before execution:

```rust
pub struct ScopeValidator {
    target: Target,
    scope: Scope,
}

impl ScopeValidator {
    pub fn validate(&self, operation: &Operation) -> Result<ScopeValidationResult> {
        // Check target is in scope
        // Check no exclusions match
        // Check rate limits
        // Check execution limits
        // Check protocol restrictions
    }
}
```

### 11.2 Plugin Isolation

- Plugins execute in isolated processes or WASM instances
- Resource limits enforced by sandbox
- Network access restricted to allowed targets
- Filesystem access restricted to designated paths
- All plugin I/O passes through context interfaces

### 11.3 API Security

- Authentication required for all endpoints
- Authorization checked per endpoint
- Input validation on all requests
- Rate limiting per client
- CSRF protection for web UI
- CORS configuration

### 11.4 Data Protection

- Credentials encrypted at rest
- Evidence redacted before storage/export
- Audit logging for all mutations
- PII detection and handling
- Secure secret rotation

### 11.5 Supply Chain Security

- Dependency auditing (`cargo audit`)
- Container image scanning
- Plugin signature verification
- SBOM generation
- Reproducible builds

---

## 12. Dependency Direction

### 12.1 Allowed Dependencies (Downward Only)

```
apps → crates → core
                  ↑
              crates (internal dependencies flow upward only)
```

### 12.2 Forbidden Dependencies

- `core` must never depend on any other crate
- `events` must never depend on `storage` or any specific implementation
- `plugins` must never depend on specific scanner implementations
- `scanner` must never depend on `api` or `web`
- No circular dependencies between crates

### 12.3 Dependency Rules

1. `core` depends on nothing (leaf crate)
2. Leaf crates (`events`, `config`, `storage`) depend only on `core`
3. Domain crates (`target`, `network`, `fingerprint`) depend on `core` + leaf crates
4. Service crates (`scanner`, `crawler`, `findings`) depend on `core` + leaf crates + domain crates
5. Orchestration crates (`engine`, `scheduler`) depend on service crates
6. Application crates (`api`, `cli`, `worker`) depend on orchestration crates

---

## 13. Error Handling Strategy

### 13.1 Error Type

```rust
#[derive(Debug, thiserror::Error)]
pub enum SpectraError {
    #[error("Not found: {0}")]
    NotFound(String),
    
    #[error("Validation error: {0}")]
    Validation(String),
    
    #[error("Authentication required")]
    Authentication,
    
    #[error("Authorization denied: {0}")]
    Authorization(String),
    
    #[error("Scope violation: {0}")]
    ScopeViolation(String),
    
    #[error("Database error: {0}")]
    Database(#[from] sqlx::Error),
    
    #[error("Storage error: {0}")]
    Storage(String),
    
    #[error("Network error: {0}")]
    Network(#[from] reqwest::Error),
    
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    
    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
    
    #[error("Plugin error: {plugin}: {error}")]
    Plugin { plugin: String, error: String },
    
    #[error("Worker error: {0}")]
    Worker(String),
    
    #[error("Configuration error: {0}")]
    Configuration(String),
    
    #[error("Internal error: {0}")]
    Internal(String),
    
    #[error("{0}")]
    Custom(String),
}
```

### 13.2 Error Context

Use `anyhow` for application-level error handling with context:
```rust
let config = load_config().context("Failed to load configuration")?;
```

Use `thiserror` for library-level error types with structured variants.

### 13.3 Error Propagation

- Errors propagate up the call stack
- Application layer catches and translates to API responses
- Worker errors reported back to scheduler
- Plugin errors isolated and reported without crashing core

---

## 14. Configuration Strategy

### 14.1 Configuration File (`spectra.toml`)

```toml
[server]
host = "0.0.0.0"
port = 8080
workers = 4

[database]
url = "postgresql://localhost/spectra"
max_connections = 20
min_connections = 5

[storage]
type = "local"
path = "./storage"

[storage.s3]
bucket = "spectra-storage"
region = "us-east-1"
endpoint = "http://localhost:9000"

[search]
url = "http://localhost:9200"

[queue]
type = "redis"
url = "redis://localhost:6379"

[scanner]
max_concurrent = 10
default_timeout = 300
rate_limit_per_second = 50

[crawler]
max_depth = 10
max_pages = 10000
concurrent_requests = 10
respect_robots = true

[ai]
provider = "openai"
model = "gpt-4"
api_key_env = "SPECTRA_AI_API_KEY"

[telemetry]
enabled = true
endpoint = "http://localhost:4317"

[worker]
heartbeat_interval = 10
job_timeout = 600
max_retries = 3
```

### 14.2 Environment Variables

All configuration can be overridden via environment variables:

```
SPECTRA_SERVER_HOST=0.0.0.0
SPECTRA_SERVER_PORT=8080
SPECTRA_DATABASE_URL=postgresql://localhost/spectra
SPECTRA_AI_API_KEY=sk-...
```

### 14.3 CLI Arguments

CLI arguments override both config file and environment variables:

```bash
spectra serve --port 9090 --database-url "postgresql://remote/spectra"
```

---

## 15. Testing Strategy

### 15.1 Test Pyramid

```
            ┌─────────┐
            │   E2E   │  Few, high-value
            ├─────────┤
            │Integration│  Service boundaries
            ├─────────┤
            │  Unit   │  Many, fast, isolated
            └─────────┘
```

### 15.2 Test Types

| Type | Scope | Speed | Quantity | Purpose |
|------|-------|-------|----------|---------|
| Unit | Single function/module | Fast | Many | Correctness |
| Integration | Service boundaries | Medium | Moderate | Interface correctness |
| E2E | Full system | Slow | Few | User workflows |
| Property | Algorithm correctness | Medium | Moderate | Edge cases |
| Fuzz | Parser/security | Medium | Few | Robustness |
| Performance | System throughput | Slow | Few | Performance baselines |
| Security | Attack surface | Slow | Few | Vulnerability detection |
| Plugin | Plugin contract | Medium | Moderate | Plugin compatibility |
| API | API contract | Medium | Moderate | API correctness |

### 15.3 Test Organization

```
tests/
├── unit/                   # Unit tests (co-located with source)
├── integration/            # Integration tests
│   ├── api/
│   ├── database/
│   ├── crawler/
│   └── scanner/
├── e2e/                    # End-to-end tests
│   ├── scan_lifecycle.rs
│   ├── target_management.rs
│   └── finding_management.rs
├── property/               # Property-based tests
├── fuzz/                   # Fuzz tests
├── performance/            # Performance benchmarks
└── security/               # Security tests
```

### 15.4 Test Commands

```bash
cargo fmt --check
cargo clippy -- -D warnings
cargo test
cargo audit
cargo bench
```

### 15.5 Frontend Testing

```bash
npm run lint
npm run typecheck
npm run test
npm run test:e2e
```

---

## 16. Versioning Strategy

### 16.1 Version Scheme

Use Semantic Versioning (SemVer): `MAJOR.MINOR.PATCH`

- **MAJOR**: Breaking changes to API or plugin contracts
- **MINOR**: New features, backwards compatible
- **PATCH**: Bug fixes, security patches

### 16.2 Crate Versioning

All crates in the workspace share the same version:

```toml
[workspace.package]
version = "0.1.0"
edition = "2021"
```

### 16.3 API Versioning

API endpoints are versioned via URL path:

```
/api/v1/...
/api/v2/...  (when breaking changes are needed)
```

### 16.4 Plugin Versioning

Plugins are independently versioned. Compatibility declared in manifest:

```toml
[plugin.compatibility]
spectra = ">=0.1.0 <1.0.0"
```

### 16.5 Database Migrations

Migrations are versioned sequentially and never modified after application:

```
migrations/
├── 001_initial_schema.sql
├── 002_add_findings_table.sql
├── 003_add_evidence_table.sql
└── ...
```

---

## 17. Deployment Architecture

### 17.1 Single Machine (Development)

```
┌─────────────────────────────────────┐
│            Development              │
│                                     │
│  ┌──────────┐  ┌──────────────┐    │
│  │ API      │  │ Web (Vite)   │    │
│  │ (Axum)   │  │              │    │
│  └────┬─────┘  └──────────────┘    │
│       │                             │
│  ┌────┴────────────────────┐       │
│  │       Engine            │       │
│  └────┬────────────────────┘       │
│       │                             │
│  ┌────┴────┐  ┌──────────────┐    │
│  │ Worker  │  │ PostgreSQL   │    │
│  └─────────┘  └──────────────┘    │
│                                     │
└─────────────────────────────────────┘
```

### 17.2 Distributed (Production)

```
┌─────────────────────────────────────────────────┐
│                  Load Balancer                   │
└────────────────────┬────────────────────────────┘
                     │
         ┌───────────┴───────────┐
         │                       │
    ┌────▼─────┐           ┌─────▼────┐
    │ API (1)  │           │ API (2)  │
    └────┬─────┘           └────┬─────┘
         │                       │
         └───────────┬───────────┘
                     │
    ┌────────────────┼────────────────┐
    │                │                │
┌───▼───┐      ┌────▼────┐     ┌────▼────┐
│Redis  │      │PostgreSQL│     │MinIO/S3 │
│Queue  │      │         │     │Storage  │
└───┬───┘      └─────────┘     └─────────┘
    │
    └────────────────┬────────────────┐
                     │                │
              ┌──────▼──────┐  ┌──────▼──────┐
              │  Worker (1) │  │  Worker (2) │
              └─────────────┘  └─────────────┘
```

### 17.3 Container Deployment

```dockerfile
# Dockerfile for API/Worker
FROM rust:1.75 as builder
WORKDIR /app
COPY . .
RUN cargo build --release

FROM debian:bookworm-slim
COPY --from=builder /app/target/release/spectra-api /usr/local/bin/
EXPOSE 8080
CMD ["spectra-api"]
```

### 17.4 Kubernetes Deployment

- Deployment for API servers (horizontal scaling)
- Deployment for Workers (horizontal scaling)
- StatefulSet for PostgreSQL
- Deployment for Redis/NATS
- PersistentVolumeClaim for object storage
- Ingress for external access
- ConfigMap and Secret for configuration

---

## 18. Architecture Decision Records

### ADR-001: Monorepo with Cargo Workspaces

**Status:** Accepted

**Context:** Spectra consists of multiple interconnected crates and applications.

**Decision:** Use a Cargo workspace monorepo structure.

**Consequences:**
- Unified dependency management
- Atomic cross-crate changes
- Shared configuration and tooling
- Single CI/CD pipeline
- Requires careful dependency management to avoid bloat

---

### ADR-002: Rust as Core Language

**Status:** Accepted

**Context:** Spectra needs high performance, memory safety, and strong typing for security-critical operations.

**Decision:** Use Rust for all core infrastructure, API, CLI, and workers.

**Consequences:**
- Memory safety without garbage collection
- Excellent performance characteristics
- Strong type system prevents many bugs
- Steeper learning curve
- Smaller ecosystem compared to Go/Node.js for web services
- Plugin system can support other languages (Python, WASM)

---

### ADR-003: Axum as HTTP Framework

**Status:** Accepted

**Context:** Need an async HTTP framework that integrates well with the Rust ecosystem.

**Decision:** Use Axum for the HTTP API server.

**Consequences:**
- Excellent Tokio integration
- Strong typing and compile-time guarantees
- Good middleware ecosystem via Tower
- Active community and maintenance
- Less mature than Actix-web but more ergonomic

---

### ADR-004: PostgreSQL as Primary Database

**Status:** Accepted

**Context:** Need a reliable, feature-rich relational database for structured data.

**Decision:** Use PostgreSQL as the primary database.

**Consequences:**
- ACID compliance
- Rich type system (JSON, arrays, full-text search)
- Excellent SQLx support in Rust
- Mature and battle-tested
- Requires separate search solution for complex queries

---

### ADR-005: Event-Driven Architecture

**Status:** Accepted

**Context:** Multiple subsystems need to react to state changes without tight coupling.

**Decision:** Implement an event bus for inter-system communication.

**Consequences:**
- Loose coupling between subsystems
- Easy to add new subscribers
- Supports audit logging
- Requires careful event schema management
- May add complexity for simple operations

---

### ADR-006: Plugin System Design

**Status:** Accepted

**Context:** Need to support third-party extensions without modifying core.

**Decision:** Implement a plugin system supporting Rust, Python, and WASM runtimes.

**Consequences:**
- Extensible without modifying core
- Different isolation levels for different trust levels
- Python support enables security research community
- WASM provides portable, sandboxed execution
- Requires maintaining multiple runtime interfaces

---

### ADR-007: Scope-First Design

**Status:** Accepted

**Context:** Security testing tools must never exceed authorized scope.

**Decision:** Every active operation must pass scope validation before execution.

**Consequences:**
- Prevents accidental scope creep
- Clear audit trail of scope compliance
- Adds overhead to every operation
- Must be impossible to bypass
- Central to Spectra's trust model

---

### ADR-008: Evidence-Based Findings

**Status:** Accepted

**Context:** Security findings must be verifiable and reviewable.

**Decision:** Every finding must include supporting evidence.

**Consequences:**
- Findings are independently reviewable
- Reduces false positives through verification
- Requires evidence storage and management
- Increases storage requirements
- Enables automated verification

---

### ADR-009: Provider-Agnostic AI

**Status:** Accepted

**Context:** AI capabilities should not be locked to a specific provider.

**Decision:** Abstract AI provider behind a trait interface.

**Consequences:**
- Can switch between OpenAI, Anthropic, Gemini, local models
- AI is optional and replaceable
- Requires maintaining provider adapters
- Prevents vendor lock-in

---

### ADR-010: Incremental Distribution

**Status:** Accepted

**Context:** Spectra should work on one machine before distributing.

**Decision:** Design for single-machine operation first, with distribution as an optional scaling path.

**Consequences:**
- Simpler initial development and testing
- Lower barrier to entry
- Same codebase for single and multi-machine
- Distribution adds complexity but is optional
- Worker protocol designed for both local and remote execution

---

## Appendix A: Glossary

| Term | Definition |
|------|------------|
| **Target** | An authorized entity to be tested |
| **Scope** | The boundaries of authorized testing |
| **Asset** | A discovered component of a target |
| **Observation** | Raw data collected by a scanner |
| **Finding** | A security issue identified from observations |
| **Evidence** | Data supporting a finding |
| **Verification** | Process of confirming or denying a finding |
| **Correlation** | Relationship analysis between findings |
| **Pipeline** | An ordered sequence of processing stages |
| **Worker** | A process that executes jobs |
| **Plugin** | An extension module that adds capabilities |
| **Sandbox** | An isolated execution environment |

---

## Appendix B: Technology Matrix

| Component | Technology | Version | Purpose |
|-----------|-----------|---------|---------|
| Core Language | Rust | 1.75+ | All core infrastructure |
| Async Runtime | Tokio | 1.x | Async execution |
| HTTP Framework | Axum | 0.7+ | API server |
| Database | PostgreSQL | 15+ | Primary data store |
| ORM/Query | SQLx | 0.7+ | Database access |
| Serialization | Serde | 1.x | JSON/TOML handling |
| CLI | Clap | 4.x | Command-line interface |
| HTTP Client | Reqwest | 0.11+ | Outbound HTTP |
| HTML Parsing | Scraper/Html5ever | - | Web crawling |
| DNS | Hickory-DNS | - | DNS resolution |
| Frontend | React | 18+ | Web UI |
| UI Framework | TypeScript | 5+ | Type-safe frontend |
| CSS | Tailwind CSS | 3+ | Styling |
| Bundler | Vite | 5+ | Frontend build |
| Message Queue | Redis | 7+ | Job queuing |
| Search | OpenSearch | 2+ | Full-text search |
| Object Storage | MinIO/S3 | - | File storage |
| Observability | OpenTelemetry | - | Metrics/traces/logs |

---

*End of Architecture Specification v1.0*
