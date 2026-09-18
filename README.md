# Spectra

**Modular, extensible, distributed security testing and analysis platform.**

[![CI](https://github.com/Hilbras/Spectra/actions/workflows/ci.yml/badge.svg)](https://github.com/Hilbras/Spectra/actions)
[![Crates.io](https://img.shields.io/crates/v/spectra-core)](https://crates.io/crates/spectra-core)
[![npm](https://img.shields.io/npm/v/@hilbras/spectra)](https://www.npmjs.com/package/@hilbras/spectra)
[![License: AGPL-3.0](https://img.shields.io/badge/license-AGPL--3.0-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-1.75+-orange.svg)](https://rustup.rs/)

Spectra is a security testing platform built in Rust for authorized penetration testing and security analysis. It combines target management, asset discovery, web crawling, technology fingerprinting, vulnerability scanning, evidence collection, finding verification, and reporting into a single extensible system.

```
UNDERSTAND → DISCOVER → OBSERVE → ANALYZE → DETECT → VERIFY → CORRELATE → EXPLAIN → REPORT
```

## Quick Start

### Install

```bash
# npm (recommended)
npm install -g @hilbras/spectra

# From source
git clone https://github.com/Hilbras/Spectra.git
cd Spectra
cargo build --release
```

### First Scan

```bash
# Create an organization
spectra organization create "My Org" --slug my-org

# Create a project
spectra project create "Web App" --organization <org-id> --slug webapp

# Add a target
spectra target add "Example" --target-type domain --value example.com --project <project-id>

# Run a scan
spectra scan run --target <target-id>

# View findings
spectra finding list
```

## Architecture

```
spectra/
├── apps/
│   ├── api/          # Axum HTTP API server
│   ├── cli/          # Clap CLI tool
│   └── worker/       # Distributed worker process
├── crates/
│   ├── core/         # Id<T>, errors, timestamps, security primitives
│   ├── events/       # Async event bus with typed payloads
│   ├── config/       # TOML config with env overrides
│   ├── storage/      # Database/Storage/SearchIndex traits + PostgreSQL
│   ├── telemetry/    # OpenTelemetry integration
│   ├── target/       # Organization → Project → Target hierarchy
│   ├── http/         # HTTP client with retry, proxy, sessions
│   ├── network/      # DNS resolution, port scanning, asset graphs
│   ├── fingerprint/  # 60+ technology fingerprinting rules
│   ├── crawler/      # BFS web crawler with robots.txt
│   ├── scanner/      # SQL injection, XSS, directory search
│   ├── findings/     # Finding lifecycle, observations, detection
│   ├── evidence/     # Evidence capture, redaction, integrity
│   ├── verification/ # Auto-verification with confidence scoring
│   ├── engine/       # Scan orchestration pipeline
│   ├── scheduler/    # Priority job queue with retry
│   ├── plugins/      # Plugin trait system with capabilities
│   └── sandbox/      # Process sandboxing with audit logging
├── migrations/       # PostgreSQL migrations (001–006)
├── npm/              # npm package wrapper
└── docs/             # Architecture, configuration, API docs
```

### Dependency Graph

```
core → config → target → network/fingerprint/crawler → scanner → findings → engine
                                ↓                                    ↓
                           evidence ←──────────────────────── verification
```

## Features

| Feature | Description |
|---------|-------------|
| **Target Management** | Organizations, projects, targets with scope enforcement |
| **Asset Discovery** | DNS resolution, port scanning, asset relationship graphs |
| **Web Crawling** | BFS frontier, HTML parsing, robots.txt, scope-aware filtering |
| **Fingerprinting** | 60+ rules across 9 categories (servers, frameworks, CMS, etc.) |
| **Vulnerability Scanning** | SQL injection, XSS, directory enumeration |
| **Evidence Engine** | Capture, redact, hash, and verify evidence integrity |
| **Observation Model** | 13 observation types with severity and confidence scoring |
| **Detection Engine** | Rule-based detection with AND/OR logic composition |
| **Verification** | Auto-verify by detection source and severity |
| **Plugin System** | Extensible with Scanner, Transformer, Enricher capabilities |
| **Sandbox** | Process isolation with resource limits and audit logging |
| **Security** | Input validation, rate limiting, constant-time comparison |

## CLI Reference

```bash
spectra <COMMAND> [SUBCOMMAND] [OPTIONS]

Commands:
  init              Initialize configuration
  organization      Manage organizations
  project           Manage projects
  target            Manage targets
  scan              Run and manage scans
  finding           List and manage findings
  observation       List observations
  evidence          List evidence
  verification      List verifications and summary
  stats             Show platform statistics
  config            Show configuration
  worker            Worker management
  plugin            Plugin management
  report            Generate reports
```

### Examples

```bash
# Organization management
spectra organization list
spectra organization create "Acme Corp" --slug acme

# Target management
spectra target add "API Server" --target-type domain --value api.acme.com --project <id>
spectra target scope --target <id> --value "https://api.acme.com/*"

# Scanning
spectra scan run --target <id> --scan-type full
spectra scan list
spectra scan cancel <id>

# Findings
spectra finding list --severity critical
spectra finding list --status new
spectra finding stats
spectra finding update-status <id> confirmed

# Observations & Evidence
spectra observation list <scan-id>
spectra evidence list <finding-id>
spectra verification summary

# Platform
spectra stats
spectra config show
```

## API Server

```bash
cargo run --bin spectra-api
# → http://localhost:8080
```

### Endpoints

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

See [docs/API.md](docs/API.md) for full API documentation.

## Configuration

Spectra uses TOML configuration with environment variable overrides.

```toml
[server]
host = "0.0.0.0"
port = 8080

[database]
url = "postgresql://localhost/spectra"

[crawler]
max_depth = 10
max_pages = 10000
respect_robots = true

[scanner]
max_concurrent = 10
rate_limit_per_second = 50
```

See [docs/CONFIGURATION.md](docs/CONFIGURATION.md) for the full reference.

## Development

```bash
# Build
cargo build --workspace

# Test
cargo test --workspace

# Lint
cargo fmt --all
cargo clippy --workspace --all-targets -- -D warnings
```

See [docs/DEVELOPMENT.md](docs/DEVELOPMENT.md) for the full development guide.

## Crate Versions

| Crate | Version | Description |
|-------|---------|-------------|
| spectra-core | 0.1.1 | Core primitives and error types |
| spectra-config | 0.1.1 | Configuration management |
| spectra-events | 0.1.1 | Event bus system |
| spectra-storage | 0.1.1 | Storage abstractions |
| spectra-target | 0.1.1 | Target management |
| spectra-http | 0.1.1 | HTTP client |
| spectra-network | 0.1.1 | Network discovery |
| spectra-fingerprint | 0.1.1 | Technology fingerprinting |
| spectra-crawler | 0.1.1 | Web crawler |
| spectra-scanner | 0.1.1 | Vulnerability scanners |
| spectra-findings | 0.1.1 | Finding lifecycle |
| spectra-evidence | 0.1.1 | Evidence engine |
| spectra-verification | 0.1.1 | Finding verification |
| spectra-engine | 0.1.1 | Scan orchestration |
| spectra-scheduler | 0.1.1 | Job scheduling |
| spectra-plugins | 0.1.1 | Plugin system |
| spectra-sandbox | 0.1.1 | Process sandboxing |
| spectra-telemetry | 0.1.1 | OpenTelemetry integration |

## Testing

387 tests across 21 crates. Run the full suite:

```bash
cargo test --workspace
```

Per-crate testing:

```bash
cargo test -p spectra-core
cargo test -p spectra-scanner
cargo test -p spectra-findings
```

## Security

See [SECURITY.md](SECURITY.md) for vulnerability reporting.

**Design guarantees:**
- `unsafe_code = "forbid"` — no unsafe Rust in any crate
- All external inputs validated through `InputValidator`
- Credentials never logged or committed
- Constant-time comparison for token verification
- Rate limiting on API endpoints
- Process sandboxing for plugin execution

## License

[AGPL-3.0](LICENSE)
