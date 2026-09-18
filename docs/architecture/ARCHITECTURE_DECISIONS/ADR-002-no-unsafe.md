# ADR-002: No Unsafe Code

## Status

Accepted

## Context

Spectra is a security tool. Using `unsafe` code introduces risks of memory safety bugs, undefined behavior, and potential vulnerabilities.

## Decision

Set `unsafe_code = "forbid"` in the workspace lints configuration. No `unsafe` code is allowed in any crate.

## Consequences

### Positive

- Memory safety guaranteed by the compiler
- No undefined behavior
- Easier auditing
- Safer plugin execution

### Negative

- Some performance optimizations not possible
- Some FFI integrations may require workarounds
- Must use safe abstractions for system calls

## Alternatives Considered

1. **Allow unsafe with audit**: Rejected due to security requirements
2. **Unsafe in specific crates only**: Rejected due to complexity
3. **Unsafe with strict review**: Rejected in favor of complete prohibition

## References

- Rustonomicon: https://doc.rust-lang.org/nomicon/
