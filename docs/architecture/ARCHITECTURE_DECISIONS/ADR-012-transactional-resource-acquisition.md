# ADR-012: Resource Acquisition Is Transactional, and Refusal Leaves No State

## Status

Accepted

## Context

Two separate faults, one in `ResourceGovernor` and one in the API handler.

**The governor burned resources on refusal.** `try_acquire` consumed from the token
bucket, then acquired a concurrency slot, then incremented queue depth — three
mutations in sequence, each after its own check. If a later check failed, the earlier
mutations were not undone. A caller rejected for exceeding queue depth kept the token
it had already spent.

That second case is latent rather than live: at the defaults `max_concurrent` is 10
and `max_queue_depth` is 1000, so the concurrency check always rejects first. But it
is a trap for anyone who configures the queue depth lower than the concurrency
ceiling, and it is exactly the kind of defect that is invisible until configuration
changes.

**The handler created the job before being governed.** `create_scan` built a
`ResourceGovernor` with `ResourceLimits::default()`, stored nothing, and never called
it. The configured limits were read by tests and by nothing else. The job was inserted
into `scan_jobs` and returned with a `202` and a scan id, and the scan ran whether or
not the server had capacity for it.

An authenticated user holding only the `scanner` role could therefore start
arbitrarily many concurrent crawls of a site of their choosing. Per-scan limits from
[ADR-008](ADR-008-caller-intent-vs-operator-ceilings.md) bound how much work one scan
does; they say nothing about how many scans run at once.

## Decision

**Check everything before mutating anything.** `TokenBucket` gained
`can_consume(&self)` and `consume(&mut self)` as separate methods, so every limit can
be evaluated against one consistent view before any of them is spent. `try_acquire`
takes all three locks up front, checks rate, concurrency and queue depth, and only
then mutates. A rejection changes nothing.

Refill is time-based, so `can_consume` recomputes availability from a clone of the
bucket rather than reading `self.tokens`, which may be stale.

**Bound the request before it exists.** `create_scan` calls the shared governor's
`try_acquire()` **before** inserting the job, and returns `429` with
`code: "RATE_LIMITED"` and the current occupancy on refusal. The governor's limits now
come from configuration — `SPECTRA_SCANNER_MAX_CONCURRENT` and
`SPECTRA_SCANNER_RATE_LIMIT_PER_SECOND` — rather than from `ResourceLimits::default()`.

The spawned task holds a clone of the governor and calls `release()` on every exit,
including when the engine returns an error.

## Consequences

- A refused submission leaves no job, no scan id and no way to poll a scan that will
  never run.
- The 429 message states what is running and what is permitted, so a caller can tell
  "try again shortly" from "you have asked for something the server will not do".
- **The limits are per process.** With two API instances, `max_concurrent = 10` means
  ten each. Making them global requires shared state and is a prerequisite of
  horizontal scaling — recorded in `distributed.md`.
- **There is no per-caller quota over time.** Only concurrency is bounded, so a caller
  can queue scans indefinitely as long as fewer than the ceiling run at once. The
  five-tier `HierarchicalGovernor` — organization, project, target, scan, api — exists
  and is never constructed outside its own tests. It is the natural home for this and
  is Phase 3 work.
- **A panic in the spawned task leaks its slot permanently.** `release` is awaited, and
  a `Drop` guard cannot await. The wedge is slow rather than fatal and `run_scan` is
  not expected to panic, but the failure mode exists and fixing it needs an abort-safe
  handle on the limiter.

## Verification

Four tests cover the leak directly: the default and a low rate limit are both
rejected, then a token is consumed and acquired-and-released pairs are checked against
the counters, asserting the bucket is full again afterwards. Two of those tests failed
on the first run — one asserted the wrong availability count, and one inferred the leak
only indirectly through a release — and were corrected to assert the invariant rather
than a consequence of it.

In the API: a test with `max_concurrent` set to 1 asserts the second submission is
`429` and that `scan_jobs` is still empty. A further test asserts the governor's
ceilings come from config rather than from the struct defaults.
