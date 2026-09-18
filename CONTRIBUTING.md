# Contributing to Spectra

Thank you for your interest in contributing to Spectra!

## Getting Started

1. Fork the repository on GitHub
2. Clone your fork:
   ```bash
   git clone https://github.com/YOUR_USERNAME/Spectra.git
   cd Spectra
   ```
3. Create a feature branch:
   ```bash
   git checkout -b feature/my-feature
   ```
4. Make your changes
5. Run the quality gates:
   ```bash
   cargo fmt --all
   cargo clippy --workspace --all-targets -- -D warnings
   cargo test --workspace
   ```
6. Commit and push
7. Open a Pull Request

## Development Setup

### Prerequisites

| Tool | Version | Install |
|------|---------|---------|
| Rust | 1.75+ | `curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \| sh` |
| PostgreSQL | 15+ | Optional, for database features |

### Build

```bash
cargo build --workspace
```

### Test

```bash
cargo test --workspace
```

## Code Standards

### Formatting

```bash
cargo fmt --all
```

### Linting

```bash
cargo clippy --workspace --all-targets -- -D warnings
```

### Safety

- **No `unsafe` code** — enforced via `unsafe_code = "forbid"` in workspace lints
- All external inputs must be validated
- Credentials must never be logged or committed
- Use `InputValidator` from `spectra-core::security` for input validation

### Testing

- Every public API should have tests
- Use `#[tokio::test]` for async tests
- Tests go in `#[cfg(test)] mod tests` at the bottom of source files
- Run `cargo test -p spectra-<crate>` to test a specific crate

## Architecture

See `docs/architecture/ARCHITECTURE.md` for the full specification.

### Key Principles

- **Modularity** — Each crate has a single responsibility
- **Extensibility** — Plugin system for custom scanners
- **Scope Safety** — All operations validated against target scope
- **Evidence-Based** — Every finding traceable to evidence
- **No Circular Dependencies** — Clean DAG structure
- **Dependencies Flow Downward** — core → config → target → network/fingerprint/crawler → scanner → findings → engine

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
4. Add tests
5. Run `cargo fmt && cargo clippy -- -D warnings && cargo test`

### Adding a New Scanner

1. Create `crates/scanner/src/my_scanner.rs`
2. Implement the `Scanner` trait:
   ```rust
   use spectra_scanner::Scanner;

   pub struct MyScanner;

   #[async_trait::async_trait]
   impl Scanner for MyScanner {
       fn name(&self) -> &str { "my-scanner" }

       async fn scan(&self, target: &str, client: &spectra_http::HttpClient)
           -> spectra_core::Result<Vec<spectra_findings::ManagedFinding>> {
           // Your scanning logic
           Ok(vec![])
       }
   }
   ```
3. Register in `crates/scanner/src/lib.rs`
4. Add tests

## Commit Messages

Use clear, descriptive commit messages:

```
feat: add new scanner module
fix: resolve scope matching edge case
docs: update API documentation
test: add integration tests for findings
refactor: simplify detection engine
```

## Pull Request Process

1. Ensure all tests pass
2. Ensure CI passes (fmt, clippy, test)
3. Update documentation if needed
4. Add CHANGELOG entry for user-facing changes
5. Request review from maintainers

## Reporting Issues

- Use GitHub Issues for bugs and feature requests
- Check existing issues before creating new ones
- Provide reproduction steps for bugs
- Include environment details (OS, Rust version, etc.)

## License

By contributing, you agree that your contributions will be licensed under the AGPL-3.0 License.
