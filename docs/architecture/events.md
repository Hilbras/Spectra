# Events

**Status:** wired. This is the one subsystem that went from fully dead to live during
the audit.

## What it is

`spectra-events` (636 LOC, 14 tests) is an in-process `tokio::sync::broadcast` bus
with a typed taxonomy, plus a handler registry for consumers that want filtered
delivery.

## What is emitted

`ScanEngine` publishes one event per scan transition:

| Event | When |
|---|---|
| `ScanStarted` | After the plan is clamped, before any work |
| `ScanCompleted` | Only for `ScanStatus::Completed` |
| `ScanPartial` | For `ScanStatus::Partial`, and for the timeout path |
| `ScanFailed` | For `ScanStatus::Failed`, for `Cancelled`, and for an engine error |

`spectra-api` attaches the bus and registers `ScanLifecycleAudit`, which writes each
transition to the audit trail with the scan id, the target id where known, and the
reason or error for partial and failed outcomes.

## Why `ScanPartial` had to be added

The taxonomy offered `ScanCompleted` and `ScanFailed`. A scan that found findings but
did not assess the target — a timeout, a crawl that got some pages, a scanner that
gave up — had to be reported as one or the other, and **the wrong choice is
`ScanCompleted`.**

That is the exact false-success shape that had already been removed from the scan API.
Publishing it on an event channel would have reintroduced it on a path that bypasses
the API entirely and that nothing was watching. Worse, a subscriber has no way to
check: the event carries no coverage information with which to contradict itself.

`ScanPartial` now exists as both an `EventType` and an `EventPayload`, and carries a
reason so a subscriber can act rather than reconstruct.

The mapping lives in one function, `terminal_event`, because it is the part that must
not drift. Three statuses in, three distinct events out, no lossy branch.

## Properties the wiring guarantees

- **Emitting cannot fail a scan.** `publish` is infallible and non-async. A subscriber
  that panics, or a channel that lags, loses events and leaves the scan untouched.
  Losing events is the correct failure mode here.
- **Exactly one terminal event per scan.** Asserted by test. Two would tell a
  subscriber a scan both finished and failed.
- **`ScanCompleted` means assessed.** Only `ScanStatus::Completed` produces it. A
  partial, failed or cancelled scan never does.
- **The bus is optional.** The CLI, the worker and the engine's own tests construct
  the engine with no bus and are unaffected.

## Known limits

- **Events are in-process only.** They do not cross a machine boundary. There is no
  Redis or NATS backend, so a restart loses anything in flight.
- **Delivery is lossy by design.** `broadcast` drops for slow subscribers rather than
  blocking. Correct for observability, wrong for anything transactional.
- **`Event` has no `correlation_id`, `causation_id` or `version`.** All three are
  required by `s.txt` Phase 22. `metadata: serde_json::Value` is a free-form escape
  hatch, not a substitute: nothing populates it, and it is untyped.
- **Only scan events are emitted.** The taxonomy defines target, asset, finding,
  evidence, verification, observation, job, worker and security events. None are
  produced. `EventType::PluginLoaded` and friends name a subsystem that does not exist.

## Target

`metadata` should become explicit `correlation_id` and `causation_id` fields so a
finding can be traced back to the scan that produced it and forward to the events it
caused. `version` lets a consumer tolerate a payload change rather than guess. Both
are additive to `Event` and do not require changing any publisher.

Emitting the remaining taxonomy is mechanical once something consumes it, and nothing
does beyond the audit handler. Building the full event surface before a UI or a
metrics pipeline exists would produce events no one reads.
