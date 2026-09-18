# Getting Started

## Prerequisites

| Requirement | Version | Install |
|-------------|---------|---------|
| Rust | 1.75+ | `curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \| sh` |
| PostgreSQL | 15+ | `apt install postgresql` (optional, for persistent storage) |
| Node.js | 18+ | For npm package installation |

## Installation

### Option 1: npm (Recommended)

```bash
npm install -g @hilbras/spectra
```

This downloads a pre-built binary for your platform and adds `spectra` to your PATH.

### Option 2: From Source

```bash
git clone https://github.com/Hilbras/Spectra.git
cd Spectra
cargo build --release
```

The binary will be at `target/release/spectra`. Add it to your PATH:

```bash
cp target/release/spectra /usr/local/bin/
```

### Option 3: Cargo Install (from crates.io, coming soon)

```bash
cargo install spectra-cli
```

## First Scan

### 1. Verify Installation

```bash
spectra --version
# spectra 0.1.0
```

### 2. Create an Organization

```bash
spectra organization create "My Company" --slug my-company
# Created organization: <org-id>
```

### 3. Create a Project

```bash
spectra project create "Web Application" --organization <org-id> --slug webapp
# Created project: <project-id>
```

### 4. Add a Target

```bash
spectra target add "Production Site" \
  --target-type domain \
  --value example.com \
  --project <project-id>
# Created target: <target-id>
```

Supported target types: `domain`, `url`, `ip`, `cidr`

### 5. Run a Scan

```bash
spectra scan run --target <target-id>
# Started scan: <scan-id>
```

Scan types: `full` (default), `quick`, `recon`

### 6. View Findings

```bash
spectra finding list
spectra finding list --severity critical
spectra finding list --status new
spectra finding stats
```

### 7. Check Verification

```bash
spectra verification summary
```

## Workflow Overview

```
1. Create Organization
2.    └── Create Project
3.          └── Add Target(s)
4.                └── Run Scan
5.                      ├── Discover (DNS, ports, assets)
6.                      ├── Crawl (URLs, forms, pages)
7.                      ├── Fingerprint (technologies, versions)
8.                      ├── Scan (SQLi, XSS, dir search)
9.                      ├── Observe (record observations)
10.                     ├── Detect (match detection rules)
11.                     ├── Verify (auto-verify findings)
12.                     └── Report (generate findings report)
13. Review Findings
14. Export Report
```

## API Quick Start

Start the API server:

```bash
cargo run --bin spectra-api
# Listening on 0.0.0.0:8080
```

### Create resources via API:

```bash
# Health check
curl http://localhost:8080/api/v1/health

# Create organization
curl -X POST http://localhost:8080/api/v1/organizations \
  -H "Content-Type: application/json" \
  -d '{"name": "My Org", "slug": "my-org"}'

# Create project
curl -X POST http://localhost:8080/api/v1/projects \
  -H "Content-Type: application/json" \
  -d '{"organization_id": "<org-id>", "name": "Web App", "slug": "webapp"}'

# Create target
curl -X POST http://localhost:8080/api/v1/targets \
  -H "Content-Type: application/json" \
  -d '{"project_id": "<project-id>", "name": "Example", "target_type": "domain", "value": "example.com"}'

# Run scan
curl -X POST http://localhost:8080/api/v1/scans \
  -H "Content-Type: application/json" \
  -d '{"target_id": "<target-id>"}'
```

See [API.md](API.md) for the full API reference.

## Worker Setup

Start a worker to process scan jobs:

```bash
cargo run --bin spectra-worker
# Worker <worker-id> started, polling for jobs...
```

The worker connects to the scheduler and processes jobs concurrently.

## Configuration

Spectra can be configured via file or environment variables:

```bash
# Set database URL
export SPECTRA_DATABASE__URL="postgresql://user:pass@localhost/spectra"

# Set log level
export SPECTRA_LOGGING__LEVEL=debug

# Start with custom config
spectra --config /path/to/spectra.toml scan list
```

See [CONFIGURATION.md](CONFIGURATION.md) for all options.

## Next Steps

- [Configuration Reference](CONFIGURATION.md) — all config options
- [API Documentation](API.md) — full REST API reference
- [Plugin Development](PLUGIN_DEVELOPMENT.md) — extend Spectra with plugins
- [Architecture](architecture/ARCHITECTURE.md) — system design deep dive
- [Development Guide](DEVELOPMENT.md) — contributing to Spectra
