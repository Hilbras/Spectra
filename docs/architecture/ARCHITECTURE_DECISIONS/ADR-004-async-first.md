# ADR-004: Async-First Architecture

## Status

Accepted

## Context

Spectra performs many I/O-bound operations (network requests, database queries, file operations). We need to decide on the concurrency model.

## Decision

Use async/await throughout the codebase with Tokio as the runtime. All I/O operations are async. CPU-bound work uses `tokio::task::spawn_blocking` when needed.

## Consequences

### Positive

- Efficient handling of concurrent operations
- Non-blocking I/O
- Good scalability
- Familiar async/await syntax

### Negative

- Async complexity (lifetimes, Send/Sync)
- Runtime dependency (Tokio)
- Some libraries don't support async

## Alternatives Considered

1. **Synchronous with threads**: Rejected due to scalability concerns
2. **Actor model**: Rejected due to complexity
3. **Async-std**: Rejected in favor of Tokio ecosystem

## References

- Tokio: https://tokio.rs/
- Async Book: https://rust-lang.github.io/async-book/
