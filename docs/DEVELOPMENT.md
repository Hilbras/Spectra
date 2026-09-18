# Development Guide

## Prerequisites

- **Rust** 1.75+ (install via [rustup](https://rustup.rs/))
- **PostgreSQL** 15+ (for database features)
- **Redis** 7+ (for distributed scheduler)
- **Node.js** 18+ (for npm package development)

## Quick Start

```bash
# Clone the repository
git clone https://github.com/spectra/spectra.git
cd spectra

# Build the workspace
cargo build --workspace

# Run all tests
cargo test --workspace

# Run lints
cargo fmt --all
cargo clippy --workspace --all-targets -- -D warnings
```

## Project Structure

```
spectra/
├── apps/           # Binary applications
│   ├── api/        # Axum HTTP API server
│   ├── cli/        # Clap CLI tool
│   └── worker/     # Distributed worker
│
├── crates/         # Library crates
│   ├── core/       # Shared primitives
│   ├── events/     # Event bus
│   ├── config/     # Configuration
│   ├── storage/    # Storage abstractions
│   ├── telemetry/  # OpenTelemetry
│   ├── target/     # Target management
│   ├── http/       # HTTP client
│   ├── network/    # Network discovery
│   ├── fingerprint/# Technology detection
│   ├── crawler/    # Web crawler
│   ├── scanner/    # Vulnerability scanners
│   ├── findings/   # Finding lifecycle
│   ├── evidence/   # Evidence collection
│   ├── verification/# Finding verification
│   ├── engine/     # Scan orchestration
│   ├── scheduler/  # Job scheduling
│   ├── plugins/    # Plugin runtime
│   └── sandbox/    # Process sandboxing
│
├── migrations/     # SQL migrations
├── docs/           # Documentation
└── .github/        # CI/CD
```

## Architecture

See `docs/architecture/ARCHITECTURE.md` for the full specification.

### Dependency Rules

- No circular dependencies
- `core` has zero internal dependencies
- Dependencies flow downward: core → config/events → target → network/fingerprint/crawler → scanner → findings → engine
- Apps depend on crates, never the reverse

### Adding a New Crate

1. Create `crates/my-crate/` with `Cargo.toml` and `src/lib.rs`
2. Add to `[workspace] members` in root `Cargo.toml`
3. Add shared dependencies via `[workspace.dependencies]`
4. Add `[lints] workspace = true`
5. Implement with tests
6. Run `cargo fmt && cargo clippy -- -D warnings && cargo test`

## Running the Applications

### API Server

```bash
cargo run --bin spectra-api
# API available at http://localhost:8080
```

### CLI

```bash
cargo run --bin spectra -- --help
cargo run --bin spectra -- init
cargo run --bin spectra -- target list
```

### Worker

```bash
cargo run --bin spectra-worker
```

## Database Setup

```bash
# Create database
createdb spectra

# Run migrations
# (migrations are in migrations/ directory)
```

## Testing

### Unit Tests

```bash
cargo test --workspace
```

### Specific Crate Tests

```bash
cargo test -p spectra-scanner
cargo test -p spectra-findings
```

### Test Coverage

We aim for comprehensive test coverage. Every public API should have tests.

## Code Quality

### Formatting

```bash
cargo fmt --all
```

### Linting

```bash
cargo clippy --workspace --all-targets -- -D warnings
```

### Safety

- No `unsafe` code (`unsafe_code = "forbid"`)
- All external inputs validated
- Credentials never logged or committed

## Configuration

Spectra uses TOML configuration. See `docs/CONFIGURATION.md` for details.

### Environment Variables

All config values can be overridden via environment variables:

```bash
SPECTRA_API__HOST=0.0.0.0
SPECTRA_API__PORT=9090
SPECTRA_DATABASE__URL=postgres://localhost/spectra
```

## CI/CD

GitHub Actions runs on every push and PR:

1. `cargo check` — compilation
2. `cargo fmt` — formatting
3. `cargo clippy` — linting
4. `cargo test` — tests
5. `cargo audit` — security audit
6. `cargo build --release` — release build

## Release Process

See `docs/RELEASE.md` for the release checklist.
