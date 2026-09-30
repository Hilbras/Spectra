# ADR-010: A Scan Plan Carries Its Own Scan Id

## Status

Accepted

## Context

`ScanPlan` had a `target_id` and no scan identity. The engine obtained a scan id from
`job.id` and, separately, wrote an observation through:

```rust
observation_engine.record_with(..., &plan.target.id.to_string())
```

The field being written is named `scan_id`. The value written was a target id.

Nothing caught this. The types were `String`, so it compiled. The unit tests asserted
that a target id was recorded, because the test was written from the same reading of
the code as the bug. The result was that observations were stored under a target id
while `GET /scans/{id}/observations` queried by scan id, so the endpoint returned an
empty list for every scan.

The audit found this only after [ADR-007](ADR-007-share-components-not-duplicate.md)
had already fixed the split-brain stores. Sharing the store is what made the bug
observable: before that, the endpoint was empty because the engine's copy of the store
was a different map, and the id mismatch was hidden behind a larger fault.

ADR-003 commits to typed identifiers, and the scan id and the target id are both
`Id<…>` — the mechanism was there and the plan was not using it.

## Decision

`ScanPlan::new` takes the scan id as its first argument and makes it **required**. It
is stored as `Id<ScanId>`, not `String`.

The mismatch is now a compile error. There is no defaulting constructor, no
`impl Default for ScanPlan`, and no way to construct one without naming the scan it
belongs to. Every `ScanPlan` in the workspace is now built at the point where a scan
job exists, so the scan id is available and the id and the plan cannot drift apart
afterwards.

## Consequences

- `ScanPlan` gained a field it did not have. Callers in the API and the CLI construct
  it from the job they just created.
- The engine no longer needs `job.id` passed separately to correlate an observation
  with its scan; the plan carries it.
- `ScanPlan.scan_id` is the natural idempotency key for a distributed job queue — a
  worker that is redelivered the same job can recognise it. Recorded as a requirement
  in `distributed.md`.
- The blanket `impl<T: Trait + ?Sized> Trait for Arc<T>` on the store traits means a
  shared store is a store, so a persistent backend can be substituted without
  changing any of this.

## Verification

The two tests that assert observations are retrievable by scan id were failing at
runtime before this change while the suite was green. Writing `plan.target.id` into
`scan_id` now fails to compile rather than passing a test that agrees with it.
