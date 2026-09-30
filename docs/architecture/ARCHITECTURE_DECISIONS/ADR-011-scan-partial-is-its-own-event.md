# ADR-011: A Partial Scan Is Its Own Event Type

## Status

Accepted

## Context

`spectra-events` existed with a typed taxonomy: `ScanStarted`, `ScanCompleted`,
`ScanFailed`, and a taxonomy for targets, assets, findings, evidence, verification,
observations, jobs, workers and security.

Nothing emitted any of them. The bus was constructed by the API and had no
subscribers, so the crate was 636 LOC of types that no publisher reached — and, per
the crate liveness rule, a type nobody produces is not a subsystem.

Wiring it was low-risk: the engine already knew every transition, and `publish` is
infallible and non-async, so a subscriber cannot slow down or fail a scan.

The design problem appeared immediately. The taxonomy offered `ScanCompleted` and
`ScanFailed`, and [ADR-009](ADR-009-three-scan-outcomes.md) added `ScanStatus::Partial`
as a third outcome. A partial scan had to map onto one of the two existing terminal
events.

**`ScanCompleted` is the wrong mapping and the tempting one.** A scan that hit its
timeout having found three findings would publish `ScanCompleted`, and a subscriber
would record a successful assessment of a target that was never fully examined.

That is precisely the false success ADR-009 removed from the API, reintroduced on a
path that bypasses the API entirely. It is worse here for two reasons. Nothing was
watching the channel, so it could not have been caught by observation. And an
`Event` carries no status field, no coverage information and no reason, so a
subscriber has nothing with which to contradict the event it received. It would have
to trust it.

## Decision

Add `ScanPartial` as both an `EventType` and an `EventPayload`, carrying a reason.

The status-to-event mapping lives in one function, `terminal_event`, because that is
the part that must not drift. Three statuses in, three distinct events out, with no
branch that loses information — which is what makes `ScanCompleted` mean *assessed*.

The API attaches the bus and registers `ScanLifecycleAudit`, which writes each
transition to the audit trail with the scan id, the target id where known, and the
reason or error for partial and failed outcomes. `Cancelled` and an engine error both
map to `ScanFailed`, because a caller needs to know the scan produced no usable
result and does not need those two distinguished to act on that.

## Consequences

- `ScanStatus::Partial` has no longer a lossy representation. Adding the status
  without the event would have made the lossy branch a compile-time requirement.
- The bus is **optional**. The CLI, the worker and the engine's own tests construct
  the engine with no bus. Emitting events is a consequence of having somewhere to emit
  them to, not a new requirement on every caller.
- Delivery is lossy by design: `broadcast` drops for a slow subscriber rather than
  blocking. That is correct for observability and wrong for anything transactional, so
  nothing may depend on an event arriving.
- Events are in-process. A restart loses anything in flight, and a subscriber that
  connects late sees nothing. Recorded in `events.md`.

## Known limits, unchanged by this ADR

- `Event` still has no `correlation_id`, `causation_id` or `version`. Free-form
  `metadata` is not a substitute; nothing populates it and it is untyped.
- Only the four scan events are emitted. The rest of the taxonomy names subsystems
  that do not execute.
- `EventType::PluginLoaded` and its siblings describe a plugin host that does not
  exist. See [ADR-013](ADR-013-hold-the-plugin-host-until-isolation-exists.md).

## Verification

A test asserts exactly one terminal event per scan, and that no
`ScanCompleted`-or-`ScanFailed` pair is emitted for a partial outcome. The original
attempt at the events test subscribed to the bus **after** publishing and so saw
nothing — it passed without observing anything. Every event test now subscribes
before the publish and asserts the received stream was non-empty.
