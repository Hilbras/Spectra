# ADR-006: In-Memory Implementations First

## Status

Accepted — **still in force. None of the "Future Work" below has been done.**

## Context

For v0.1.0, we need working implementations that can be tested without external dependencies (PostgreSQL, Redis, etc.).

## Decision

Provide in-memory implementations for all core components:

- `InMemoryFindingsManager` for findings storage
- `InMemoryJobQueue` for job scheduling
- `InMemoryVerificationStore` for verification records
- `LocalStorage` for object storage

These implementations are suitable for testing and single-instance deployments.

## Consequences

### Positive

- No external dependencies for basic usage
- Easy to test
- Fast execution
- Good for development

### Negative

- Not persistent (data lost on restart)
- Not distributed
- Limited scalability
- Memory constraints

## Alternatives Considered

1. **PostgreSQL only**: Rejected due to deployment complexity
2. **SQLite**: Rejected due to concurrency limitations
3. **File-based**: Rejected due to performance concerns

## Future Work

- Add PostgreSQL-backed implementations
- Add Redis-backed scheduler
- Add S3-compatible object storage

## Audit note

The decision was correct for a starting point and has not been revisited. It is worth
stating plainly what it currently costs: **0 of 12 stateful object types survive a
process restart.** Every finding, observation, evidence record, scan job, target,
user, token, audit entry, queued job, secret and rate-limit counter is in a `HashMap`
behind a lock inside the process that created it.

None of the three items under Future Work has been started, and each has a
prerequisite that is not yet done:

- **PostgreSQL** is blocked on fixing `spectra-storage` first — its migration runner
  is not idempotent, `pg_row_to_row` has eight silent `Value::Null` fallbacks, and ten
  struct fields have no matching column. Persistence that silently substitutes
  defaults converts visible absence into invisible corruption, which is worse than the
  in-memory state this ADR chose.
- **Redis-backed scheduler** is blocked on persistence, and on deciding failure
  semantics (idempotency keys, visibility timeout) before writing the queue.
- **Object storage** needs a decision on whether evidence bodies are inline or
  referenced; `EvidenceRecord.storage_path` already anticipates the latter.

The substitution itself is cheap: `FindingsManager` and `ObservationStore` exist, and
now accept `Arc<T>` via
[ADR-007](ADR-007-share-components-not-duplicate.md), so a persistent backend can be
dropped in without touching the engine.

Full state inventory: [`../storage.md`](../storage.md).

## References

- None
