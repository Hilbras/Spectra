# ADR-003: Typed Identifiers

## Status

Accepted

## Context

The codebase uses UUIDs for identifiers. Using raw `String` or `Uuid` types can lead to mixing up IDs from different entities (e.g., passing a target ID where a project ID is expected).

## Decision

Use `Id<T>` generic typed identifiers with marker types:

```rust
pub struct Id<T> {
    value: Uuid,
    _marker: PhantomData<T>,
}
```

Each entity has a marker type:

```rust
pub struct TargetId;
pub struct ProjectId;
pub struct FindingId;
// etc.
```

## Consequences

### Positive

- Compile-time type safety
- Prevents ID confusion bugs
- Self-documenting code
- Zero runtime cost

### Negative

- More verbose code
- Must define marker types for each entity
- Generic complexity

## Alternatives Considered

1. **Raw `String` IDs**: Rejected due to type safety
2. **Raw `Uuid` IDs**: Rejected due to lack of differentiation
3. **Newtype per entity**: Rejected due to code duplication

## References

- Type-driven design: https://doc.rust-lang.org/book/ch19-03-pattern-types.html
