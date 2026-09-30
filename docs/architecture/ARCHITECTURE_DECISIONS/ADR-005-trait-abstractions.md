# ADR-005: Trait-Based Abstractions

## Status

Accepted — **partly unimplemented.** See "Audit note" below; two of the six traits
named in the decision do not exist.

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

## Audit note

Verified against the source during the architecture freeze. The decision was adopted
in principle and implemented in part:

| Trait named above | Exists | Concrete impl |
|---|---|---|
| `Scanner` | Yes, `crates/scanner/src/lib.rs:144` | Nine scanners |
| `Storage` | Yes, `crates/storage/src/lib.rs:15` | `LocalStorage` |
| `Database` | Yes, `crates/storage/src/lib.rs:37` | `PostgresDatabase` |
| `Sandbox` | Yes, `crates/sandbox/src/lib.rs:146` | `LocalSandbox` — **not a sandbox**, see ADR-013 |
| `Verifier` | **Absent.** No such trait | — |
| `EvidenceCollector` | **Absent.** Evidence has `EvidenceEngine`, not this trait | — |

Two claims in the original Consequences section do not hold:

- *"Concrete implementations are provided for each trait"* — true of the four that
  exist, and false of the two that do not.
- *"Plugin-friendly architecture"* — `spectra-plugins` and `spectra-sandbox` have no
  importers and `SandboxPolicy` enforces none of the limits its own type describes.
  See [ADR-013](ADR-013-hold-the-plugin-host-until-isolation-exists.md).

`Storage` and `Database` do have implementations, but both live in `spectra-storage`,
which nothing outside itself references. The abstractions are in place for
persistence; persistence is not. See [`../storage.md`](../storage.md).

The decision stands. The gap is implementation, not approach — the traits that the
Phase 2 work needs already exist and already accept `Arc<T>`.

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
