# Spectra

A modular, extensible, distributed security testing and security analysis platform for authorized targets.

## Architecture

Spectra combines target management, asset discovery, reconnaissance, technology fingerprinting, web crawling, security scanning, network analysis, evidence collection, finding detection, finding verification, finding correlation, AI-assisted analysis, knowledge management, automation, distributed execution, a plugin ecosystem, reporting, integrations, and enterprise capabilities.

### Core Workflow

```
UNDERSTAND → DISCOVER → OBSERVE → ANALYZE → DETECT → VERIFY → CORRELATE → EXPLAIN → REPORT → AUTOMATE
```

## Project Structure

```
spectra/
├── apps/
│   ├── api/          # Axum HTTP API server
│   ├── cli/          # Command-line interface
│   └── worker/       # Distributed worker
├── crates/
│   ├── core/         # Shared primitives and error types
│   ├── events/       # Event bus system
│   ├── config/       # Configuration management
│   ├── storage/      # Storage abstractions
│   ├── telemetry/    # OpenTelemetry integration
│   ├── target/       # Target and scope management
│   ├── network/      # Network analysis
│   ├── fingerprint/  # Technology fingerprinting
│   ├── crawler/      # Web crawler
│   ├── scanner/      # Scanner framework
│   ├── findings/     # Finding management
│   ├── evidence/     # Evidence collection
│   ├── verification/ # Finding verification
│   ├── engine/       # Scan orchestration
│   ├── scheduler/    # Job scheduling
│   ├── plugins/      # Plugin runtime
│   └── sandbox/      # Plugin sandboxing
└── docs/
    └── architecture/ # Architecture specifications
```

## Prerequisites

- Rust 1.75+
- PostgreSQL 15+
- Redis 7+ (for job queue)
- Node.js 18+ (for web frontend)

## Development

### Setup

```bash
# Install Rust toolchain
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Clone the repository
git clone https://github.com/spectra/spectra.git
cd spectra

# Build the workspace
cargo build

# Run tests
cargo test

# Check code quality
cargo fmt --check
cargo clippy -- -D warnings
```

### Running

```bash
# Start the API server
cargo run --bin spectra-api

# Use the CLI
cargo run --bin spectra -- --help

# Start a worker
cargo run --bin spectra-worker
```

## Development Standards

- `cargo fmt` - Code formatting
- `cargo clippy` - Linting
- `cargo test` - Testing
- `cargo audit` - Security auditing

## License

MIT
