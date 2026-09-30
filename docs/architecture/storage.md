# Storage and State

**Status:** current behaviour is **entirely in-memory**. Nothing survives a restart.
The target design is specified but not built.

## The headline

**0 of 12 stateful object types survive a process restart.** Every finding,
observation, evidence record, scan job, target, user, token, audit entry, job,
secret and rate-limit counter lives in a `HashMap` behind a `tokio::sync::RwLock`
inside the process that created it.

This is a deliberate starting point (ADR-006) and the single largest gap in the
system. It is stated first because everything below is detail.

## Where state lives now

| State | Holder | Survives restart |
|---|---|---|
| `ScanJob` | `AppState.scan_jobs: Arc<RwLock<HashMap<String, ScanJob>>>` | No |
| `Finding` | `InMemoryFindingsManager` (`HashMap<String, ManagedFinding>`) | No |
| `Observation` | `InMemoryObservationStore` | No |
| `Evidence` | `InMemoryEvidenceStore` | No |
| `Target`, `Project`, `Organization` | `TargetService` | No |
| `User` | `UserStore` | No |
| Audit entries | `InMemoryAuditLog` via `AuditLogger::with_in_memory()` | No |
| Login failures | `LoginThrottle` | No |
| Governor counters | `ResourceGovernor` | No |
| Verification records | `VerificationEngine` | No — and never populated at all |
| Secrets | `EnvSecretProvider` (process environment) | Only if the environment does |
| Scheduler jobs | `InMemoryJobQueue` | No |

The API is constructed with `AuditLogger::with_in_memory()`. Audit records are
therefore never written to the log file — a known gap, and one reason the audit trail
cannot currently be used for forensics after a restart.

### The stores are now shared

`build_state` used to construct a findings manager, an observation store and an
evidence engine for the API, and then let `ScanEngine` construct a **second set**.
Nothing connected them, so `GET /scans/{id}/observations` and
`GET /findings/{id}/evidence` returned empty for every scan and `evidence_total` was
always `0`.

They are now built once and shared, via blanket `Arc<T>` implementations of
`FindingsManager` and `ObservationStore`. This is also what makes the persistence
target reachable: a database-backed store can satisfy the same trait and be
substituted without touching the engine.

## `spectra-storage` exists and is unreferenced

1,760 LOC across `lib.rs`, `repositories.rs`, `in_memory.rs`, `pg.rs` and
`search.rs`, with 5 tests. **Zero importers.** `migrations/001_initial.sql` through
`006_operations.sql` define 26 tables, none referenced by code.

It is retained and is load-bearing for the target design, but wiring it is not a
matter of calling it. It does not currently match the structs it is supposed to
persist.

### Known drift between structs and columns

Found by comparing `crates/storage/src/repositories.rs` against the migrations:

| Struct field | Problem |
|---|---|
| `ScanRecord.progress` | No matching column |
| `EvidenceRecord.content_type` | No matching column |
| `EvidenceRecord.size_bytes` | No matching column |
| `EvidenceRecord.storage_path` | No matching column |
| `ObservationRecord.title` | No matching column |
| `ObservationRecord.description` | No matching column |
| `WorkerRecord.capacity` | No matching column |
| `WorkerRecord.active_jobs` | No matching column |
| `AuditRecord.details` | No matching column |
| `MetricsRepository` | Targets a `metrics` table that does not exist in any migration |

### Other defects to fix before it is usable

- **The migration runner is not idempotent.** `pg.rs` executes migration SQL without
  recording what it has applied, so a second run re-runs every statement and fails on
  the first `CREATE TABLE`.
- **`pg_row_to_row` has eight silent `Value::Null` fallbacks.** A column that is
  `NULL` in the database becomes a default-constructed value in Rust rather than an
  error, so a query mismatch produces plausible wrong data instead of a failure. This
  is the same failure shape as the scan-status problem, one layer down.
- **Zero tests.** `pg.rs` has none, and there is no test database in CI.

## Target design

Not built. The intended shape:

1. Add the missing columns, or drop the fields that have no home.
2. Make the migration runner idempotent — record applied versions in a
   `schema_migrations` table and check before applying.
3. Replace the silent `Value::Null` fallbacks with typed extraction that errors on a
   shape mismatch.
4. Implement `FindingsManager` and `ObservationStore` against `sqlx` for
   `InMemoryFindingsManager` and `InMemoryObservationStore`. The traits already exist
   and already accept `Arc<T>`, so this is a substitution rather than a redesign.
5. Move `ScanJob` into a table so `GET /scans/{id}` survives a restart.
6. Point `AuditLogger` at a file or database log rather than the in-memory one.
7. Give CI a Postgres service and test `pg.rs` against it.

Steps 1–3 are prerequisites for step 4 and should not be skipped. Persistence that
silently produces default values is worse than no persistence, because it converts
visible absence into invisible corruption.

## A constraint on the design

`resource_path` is not a column, and evidence bodies are stored inline in the
in-memory store. Before persistence, decide whether evidence bodies go into object
storage with a reference in PostgreSQL or stay inline. `EvidenceRecord.storage_path`
already anticipates the former, which is why it is listed as drift above rather than
as a missing feature.
