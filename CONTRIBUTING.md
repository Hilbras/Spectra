# Contributing to Spectra

Thank you for your interest in contributing to Spectra!

## Getting Started

1. Fork the repository
2. Clone your fork
3. Create a feature branch: `git checkout -b feature/my-feature`
4. Make your changes
5. Run tests: `cargo test --workspace`
6. Run lints: `cargo fmt && cargo clippy -- -D warnings`
7. Commit your changes
8. Push to your fork
9. Open a Pull Request

## Development Setup

### Prerequisites

- Rust 1.75+
- PostgreSQL 15+ (for database features)
- Redis 7+ (for distributed scheduler)
- Node.js 18+ (for npm package)

### Building

```bash
cargo build --workspace
```

### Testing

```bash
cargo test --workspace
```

### Linting

```bash
cargo fmt --all
cargo clippy --workspace --all-targets -- -D warnings
```

## Code Style

- Follow Rust standard conventions
- Use `rustfmt` for formatting
- Use `clippy` for linting
- No `unsafe` code (`unsafe_code = "forbid"`)
- Write doc comments for public APIs
- Include tests for new functionality

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
2. Ensure CI passes
3. Update documentation if needed
4. Add CHANGELOG entry for user-facing changes
5. Request review from maintainers

## Architecture

See `docs/architecture/ARCHITECTURE.md` for the full architecture specification.

Key principles:
- **Modularity**: Each crate has a single responsibility
- **Extensibility**: Plugin system for custom scanners
- **Scope Safety**: All operations validated against target scope
- **Evidence-Based**: Every finding traceable to evidence
- **No Circular Dependencies**: Clean DAG structure

## Reporting Issues

- Use GitHub Issues for bugs and feature requests
- Check existing issues before creating new ones
- Provide reproduction steps for bugs
- Include environment details (OS, Rust version, etc.)

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
