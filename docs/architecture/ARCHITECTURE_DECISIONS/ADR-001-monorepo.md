# ADR-001: Monorepo Architecture

## Status

Accepted

## Context

Spectra needs to be organized as a single repository containing multiple crates and applications. We need to decide on the workspace structure.

## Decision

Use a Cargo workspace with:

- 18 library crates under `crates/`
- 3 binary applications under `apps/`
- Shared dependencies via `[workspace.dependencies]`
- Centralized lint configuration via `[lints] workspace`

## Consequences

### Positive

- Single repository for all code
- Shared dependencies reduce duplication
- Atomic commits across all components
- Easy dependency management
- Consistent tooling and CI

### Negative

- Larger repository size
- Longer build times for full workspace
- More complex CI configuration

## Alternatives Considered

1. **Multiple repositories**: Rejected due to coordination overhead
2. **Single crate with features**: Rejected due to dependency complexity
3. **Path dependencies without workspace**: Rejected due to lack of shared config

## References

- Cargo Workspaces: https://doc.rust-lang.org/cargo/reference/workspaces.html
