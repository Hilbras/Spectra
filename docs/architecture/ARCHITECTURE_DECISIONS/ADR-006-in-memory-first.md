# ADR-006: In-Memory Implementations First

## Status

Accepted

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

## References

- None
