# ADR-005: Trait-Based Abstractions

## Status

Accepted

## Context

Spectra needs to support multiple implementations for storage, scanning, verification, etc. We need to decide on the abstraction strategy.

## Decision

Use async traits for all major abstractions:

- `Scanner` trait for vulnerability scanners
- `Storage` trait for object storage
- `Database` trait for SQL databases
- `Sandbox` trait for plugin execution
- `Verifier` trait for finding verification
- `EvidenceCollector` trait for evidence collection

Concrete implementations are provided for each trait.

## Consequences

### Positive

- Clean separation of concerns
- Easy to add new implementations
- Testable with mock implementations
- Plugin-friendly architecture

### Negative

- Dynamic dispatch overhead
- More complex type signatures
- Async trait support still maturing

## Alternatives Considered

1. **Concrete types only**: Rejected due to lack of flexibility
2. **Generic parameters**: Rejected due to type complexity
3. **Enum dispatch**: Rejected due to limited extensibility

## References

- Async Traits: https://rust-lang.github.io/async-book/07_workarounds/03_send.html
