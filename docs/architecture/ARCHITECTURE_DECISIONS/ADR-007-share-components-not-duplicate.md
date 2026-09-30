# ADR-007: Share Component Instances Rather Than Duplicating Them

## Status

Accepted

## Context

`build_state` in `apps/api/src/main.rs` constructed a findings manager, an observation
store and an evidence engine for the HTTP API. `ScanEngine::new_with` then constructed
a **second set of its own** and handed those to the engine. Nothing connected them.

The symptoms were user-visible and silent:

- `GET /scans/{id}/observations` returned an empty list for every scan.
- `GET /findings/{id}/evidence` returned an empty list for every finding.
- `stats.evidence_total` was always `0`; `stats.observations_total` was hardcoded `0`.

`create_scan` partially masked this with a loop that copied every finding out of the
engine's manager into the API's after each scan. That loop was worse than the symptom:
it iterated `ids()` rather than filtering by target, so it also re-copied findings
belonging to *other* scans on every completion, and discarded failures with `let _ =`.

## Decision

Build each shared component once and hand the same handle to both the engine and the
application state. `FindingsManager` and `ObservationStore` gain blanket
`impl<T: Trait + ?Sized> Trait for std::sync::Arc<T>`, so one store can have several
owners without a wrapper type. `ScanEngine`'s evidence engine became an
`Arc<EvidenceEngine>` so the API can read what the engine captures.

A shared handle is itself a trait implementor — the alternative, making every owner
hold `&dyn Trait`, would not survive the state being moved into an axum `State`.

## Consequences

- `GET /scans/{id}/observations` and `GET /findings/{id}/evidence` return real data.
- The manual copy loop is deleted, along with its cross-scan contamination.
- The traits already accept `Arc<T>`, so a database-backed store can be substituted
  later without touching the engine. See [ADR-006](ADR-006-in-memory-first.md).
- **A second defect was only visible at runtime.** After sharing was correct and
  compiling, the observations endpoint was still empty: the engine wrote
  `plan.target.id` into the field named `scan_id` while the endpoint queried by scan
  id. Neither the type system nor any unit test could see it. See
  [ADR-010](ADR-010-scan-plan-carries-its-scan-id.md).
- `stats.observations_total` needed a whole-inventory count. `ObservationStore::count`
  is per-scan, and adding `count_all` to the trait would force every implementor to
  provide it. It is an inherent method on `InMemoryObservationStore` for now, with a
  note that a persistent backend will need a real trait-level `count_all`.

## Verification

Five tests assert sharing works in both directions. The split-brain was reintroduced
deliberately as a mutation; five of them fail when it is present.
