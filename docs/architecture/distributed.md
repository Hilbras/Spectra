# Distributed Operation

**Status:** target design. **The system runs in one process and there is no
distributed mode.** This document records the intended topology and, more usefully,
what stands between here and there.

## Current: one process

```
┌─────────────────────────────────────────────────┐
│  spectra-api                                    │
│                                                 │
│   scan_jobs, findings, observations, evidence   │
│   users, audit log, governor, throttle          │
│                                                 │
│   tokio::spawn ──▶ ScanEngine::run_scan         │
└─────────────────────────────────────────────────┘
```

Scans run in-process on the API's runtime. `POST /api/v1/scans` returns immediately
with a scan id and the work continues on a spawned task. Restarting the API loses every
job, including ones in progress.

`spectra-worker` exists and does not work. It binds `InMemoryJobQueue`, and nothing
anywhere calls `enqueue`, so `dequeue()` always returns `None` and it has nothing to
consume. Its Redis path is unreachable as well as unused, because the concrete queue
type is hardcoded to the in-memory one.

## Target

```
                    ┌──────────────┐
   browsers ───────▶│              │
   CLI ────────────▶│  spectra-api │──┐
                    │  (stateless) │  │
                    └──────────────┘  │  enqueue
                                     ▼
                            ┌──────────────────┐
                            │  job queue       │  Redis / NATS
                            └────────┬─────────┘
                                     │ claim
                    ┌────────────────┼────────────────┐
                    ▼                ▼                ▼
              ┌──────────┐     ┌──────────┐     ┌──────────┐
              │ worker 1 │     │ worker 2 │     │ worker N │
              └────┬─────┘     └────┬─────┘     └────┬─────┘
                   └────────────────┼────────────────┘
                                    ▼
                          ┌──────────────────┐
                          │  PostgreSQL      │  findings, jobs, users
                          │  object storage  │  evidence bodies
                          └──────────────────┘
                                    │
                            events ──▶ subscribers (UI, webhooks, SIEM)
```

## What each step requires

### 1. The API must become stateless

Every store in `AppState` is process-local. The API cannot run two instances until
findings, jobs, users and the audit log are in a database. This is
[`storage.md`](storage.md) and it is the prerequisite for everything else: the
governor and login throttle are also process-local and would need shared backing, or
each instance would enforce its own limit and `SPECTRA_SCANNER_MAX_CONCURRENT=10`
would mean 10 *per instance*.

### 2. A real queue

`spectra-scheduler` has a `JobQueue` trait, an `InMemoryJobQueue` and a scheduler with
`max_concurrent_jobs`. None of it is reachable from the API. Wiring it requires:

- A Redis or NATS implementation of `JobQueue`. The trait exists; the implementation
  does not.
- **Idempotency.** A worker that dies mid-scan and has its job redelivered must not
  double-report findings or double-charge the governor. There is no idempotency key
  today, and `ScanPlan.scan_id` is the obvious candidate — it was made a required
  field partly for this reason.
- **A visibility timeout.** A claimed job whose worker vanishes must become available
  again. Without it a single crash wedges a scan forever.
- **Heartbeats.** `EventType::WorkerRegistered` and `WorkerHeartbeat` exist and are
  never emitted.

### 3. Observability that survives a restart

`spectra-events` is in-process `broadcast`. Across a worker boundary that drops
everything on disconnect and delivers nothing to a late subscriber. Moving to Redis
pub/sub or NATS is the natural choice and would let the UI follow a scan started by
someone else.

This is also where `correlation_id` earns its place: today a finding can be tied to a
scan only within one process.

### 4. Failure semantics decided in advance

Each of these is currently undecided, and each is a correctness question rather than
an implementation detail:

- **Scan cancelled by its author while a worker holds it.** Does the worker observe
  the cancellation, or finish and have the result discarded?
- **Two workers claim the same scan.** The queue should prevent it; if it does not,
  which result wins?
- **API restarts mid-scan.** The job survives in the queue; the response the client
  polls does not.
- **Database unavailable mid-scan.** Does the scan fail, or buffer? Buffering implies
  unbounded memory growth in a process that has already lost its state.

Deciding these before writing the queue is cheaper than discovering them in
production, and each has a different correct answer.

## Honest assessment of the value

The distribution of value is not even, and the first two steps carry nearly all of
it.

| Step | Value | Cost |
|---|---|---|
| Persistence | **High** — results survive restart; the single largest gap | Migration fixes first, then repositories |
| Real queue | **High** — scan survives API restart; horizontal workers | Idempotency and visibility timeout are not optional |
| Distributed events | Medium — UI follows any worker's scans | Only once something consumes them |
| Redis governor/throttle | Medium — limits must be global, not per instance | Comes with persistence anyway |

Persistence first. It is a prerequisite for the others, it fixes the largest existing
problem, and it is the only one that improves the system as it is currently deployed —
which is a single process that loses everything on restart.
