# Getting Started with Spectra

## What is Spectra?

Spectra is a modular, extensible, distributed security testing and analysis platform for authorized targets. It helps security professionals discover, scan, and analyze web applications and infrastructure.

## Prerequisites

- **Rust** 1.75+ ([install](https://rustup.rs/))
- **PostgreSQL** 15+ (optional, for persistent storage)
- **Redis** 7+ (optional, for distributed workers)

## Quick Install

### From Source

```bash
git clone https://github.com/spectra/spectra.git
cd spectra
cargo build --release
```

The binary will be at `target/release/spectra`.

### From Binary

Download the latest release for your platform from [GitHub Releases](https://github.com/spectra/spectra/releases).

## First Run

### 1. Initialize a Project

```bash
spectra init
```

This creates a `spectra.toml` configuration file in the current directory.

### 2. Create an Organization

```bash
spectra organization create --name "My Org" --slug "my-org"
```

### 3. Create a Project

```bash
spectra project create --org "my-org" --name "My Project" --slug "my-project"
```

### 4. Add a Target

```bash
spectra target add --project "my-project" --name "Example" --type domain --value "example.com"
```

### 5. Run a Scan

```bash
spectra scan run --target <target-id>
```

### 6. View Findings

```bash
spectra finding list --target <target-id>
```

## Configuration

Spectra uses TOML configuration. The config file is searched in:

1. Current directory (`./spectra.toml`)
2. Home directory (`~/.config/spectra/spectra.toml`)
3. System directory (`/etc/spectra/spectra.toml`)

### Example Configuration

```toml
[api]
host = "127.0.0.1"
port = 8080

[database]
url = "postgres://localhost/spectra"

[redis]
url = "redis://localhost:6379"

[network]
dns_servers = ["8.8.8.8", "8.8.4.4"]
timeout_ms = 5000

[crawler]
max_depth = 3
max_pages = 100
delay_ms = 100

[scanner]
max_concurrent = 10
timeout_secs = 300
```

### Environment Variables

All config values can be overridden with environment variables:

```bash
SPECTRA_API__HOST=0.0.0.0
SPECTRA_API__PORT=9090
SPECTRA_DATABASE__URL=postgres://localhost/spectra
```

## Architecture

Spectra follows a layered architecture:

```
Core → Config → Target → Network/Fingerprint/Crawler → Scanner → Findings → Engine
```

Each layer has clear responsibilities and dependencies flow downward.

## CLI Commands

### Organization Management

```bash
spectra organization list
spectra organization create --name "Org" --slug "org"
spectra organization show <id>
spectra organization delete <id>
```

### Project Management

```bash
spectra project list --org <org-id>
spectra project create --org <org-id> --name "Project" --slug "project"
spectra project show <id>
spectra project delete <id>
```

### Target Management

```bash
spectra target list --project <project-id>
spectra target add --project <project-id> --name "Target" --type domain --value "example.com"
spectra target show <id>
spectra target delete <id>
spectra target scope <id>
```

### Scan Management

```bash
spectra scan run --target <target-id>
spectra scan list
spectra scan show <id>
spectra scan cancel <id>
```

## API Server

Start the API server:

```bash
cargo run --bin spectra-api
```

The API is available at `http://localhost:8080`.

### API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/v1/health` | Health check |
| POST | `/api/v1/organizations` | Create organization |
| GET | `/api/v1/organizations` | List organizations |
| GET | `/api/v1/targets` | List targets |
| POST | `/api/v1/scans` | Start scan |

## Worker

Start a worker process:

```bash
cargo run --bin spectra-worker
```

The worker connects to the scheduler and processes scan jobs.

## Next Steps

- Read the [Architecture Guide](ARCHITECTURE.md)
- Review [Configuration Reference](CONFIGURATION.md)
- Check the [API Documentation](API.md)
- Learn about [Plugin Development](PLUGIN_DEVELOPMENT.md)
