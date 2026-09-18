# Development Guide

## Prerequisites

| Tool | Version | Purpose |
|------|---------|---------|
| Rust | 1.75+ | Core language |
| cargo | Latest | Build system |
| PostgreSQL | 15+ | Database (optional) |
| Node.js | 18+ | npm package dev |

## Quick Start

```bash
git clone https://github.com/Hilbras/Spectra.git
cd Spectra
cargo build --workspace
cargo test --workspace
```

## Project Structure

```
spectra/
├── Cargo.toml              # Workspace root (21 members)
├── crates/                 # Library crates
│   ├── core/               # Id<T>, SpectraError, Timestamp, security
│   ├── config/             # TOML config with env overrides
│   ├── events/             # Async event bus
│   ├── storage/            # Database/Storage/Search traits + PostgreSQL
│   ├── telemetry/          # OpenTelemetry integration
│   ├── target/             # Organization → Project → Target
│   ├── http/               # HTTP client with retry/proxy/sessions
│   ├── network/            # DNS, port scanning, asset graphs
│   ├── fingerprint/        # 60+ technology detection rules
│   ├── crawler/            # BFS web crawler
│   ├── scanner/            # SQLi, XSS, directory search
│   ├── findings/           # Finding lifecycle, observations, detection
│   ├── evidence/           # Evidence capture, redaction, integrity
│   ├── verification/       # Auto-verification engine
│   ├── engine/             # Scan orchestration pipeline
│   ├── scheduler/          # Priority job queue
│   ├── plugins/            # Plugin trait system
│   └── sandbox/            # Process sandboxing
├── apps/                   # Binary applications
│   ├── api/                # Axum HTTP server
│   ├── cli/                # Clap CLI
│   └── worker/             # Worker process
├── migrations/             # PostgreSQL migrations
├── npm/                    # npm package wrapper
└── docs/                   # Documentation
```

## Architecture Rules

### Dependency Direction

```
core → config → target → network/fingerprint/crawler → scanner → findings → engine
```

**Never**:
- Create circular dependencies
- Make `core` depend on other crates
- Make crates depend on `apps/`
- Use `unsafe` code (`unsafe_code = "forbid"`)

### Adding a New Crate

1. Create `crates/my-crate/Cargo.toml`:
```toml
[package]
name = "spectra-my-crate"
version.workspace = true
edition.workspace = true
rust-version.workspace = true
license.workspace = true

[dependencies]
spectra-core = { workspace = true }

[lints]
workspace = true
```

2. Create `src/lib.rs`
3. Add `"crates/my-crate"` to workspace `Cargo.toml` members
4. Run `cargo build --workspace`

## Building

```bash
# Debug build
cargo build --workspace

# Release build
cargo build --release --workspace

# Specific crate
cargo build -p spectra-scanner

# Specific binary
cargo build --release --bin spectra
```

## Testing

```bash
# All tests (387+)
cargo test --workspace

# Specific crate
cargo test -p spectra-core
cargo test -p spectra-scanner

# Specific test
cargo test -p spectra-core -- security::tests::constant_time_eq

# With output
cargo test -- --nocapture

# Ignored tests
cargo test -- --ignored
```

### Test Structure

Each crate has `#[cfg(test)] mod tests` at the bottom of its source files. Tests use `#[tokio::test]` for async code.

## Code Quality

### Formatting

```bash
cargo fmt --all
cargo fmt --all -- --check  # Check only
```

### Linting

```bash
cargo clippy --workspace --all-targets -- -D warnings
```

### Safety Rules

- **No `unsafe`** — enforced via `unsafe_code = "forbid"` in workspace lints
- **All inputs validated** — use `InputValidator` from `spectra-core::security`
- **Credentials never logged** — use `#[instrument(skip(password))]` pattern
- **No secrets in code** — environment variables only

## Running Applications

### API Server

```bash
cargo run --bin spectra-api
# → http://localhost:8080
```

### CLI

```bash
cargo run --bin spectra -- --help
cargo run --bin spectra -- scan list
```

### Worker

```bash
cargo run --bin spectra-worker
```

## Database Setup

```bash
# Create database
createdb spectra

# Run migrations (in order)
psql spectra < migrations/001_initial.sql
psql spectra < migrations/002_target_management.sql
psql spectra < migrations/003_assets.sql
psql spectra < migrations/004_scanning.sql
psql spectra < migrations/005_findings.sql
psql spectra < migrations/006_operations.sql
```

## CI/CD

GitHub Actions runs on every push:

1. `cargo fmt --all -- --check`
2. `cargo clippy --workspace --all-targets -- -D warnings`
3. `cargo test --workspace`
4. `cargo build --release`

See `.github/workflows/ci.yml`.

## Common Patterns

### Typed Identifiers

```rust
use spectra_core::Id;

struct User;
let user_id: Id<User> = Id::new();
let id_string = user_id.to_string();
let parsed: Id<User> = Id::from_uuid(uuid::Uuid::parse_str(&id_string).unwrap());
```

### Error Handling

```rust
use spectra_core::{SpectraError, Result};

fn do_something() -> Result<()> {
    // Use ? for automatic conversion
    let data = std::fs::read_to_string("file.toml")
        .map_err(|e| SpectraError::Io(e.to_string()))?;
    Ok(())
}
```

### Event Bus

```rust
use spectra_events::{EventBus, Event, EventType, EventSource, EventPayload};

let bus = EventBus::new(100);
let mut rx = bus.subscribe();

bus.publish(Event::new(
    EventType::ScanStarted,
    EventSource::System,
    EventPayload::ScanStarted {
        scan_id: "s1".into(),
        target_id: "t1".into(),
    },
));

let event = rx.recv().await.unwrap();
```

## Release Process

See [RELEASE.md](RELEASE.md) for the release checklist.
