# Architecture Decision Records

Each ADR records a decision, the context that forced it, and what it cost. They are
numbered and immutable once accepted; a decision that turns out to be wrong is
superseded by a new record rather than edited.

## Index

| ADR | Decision | Status |
|---|---|---|
| [001](ARCHITECTURE_DECISIONS/ADR-001-monorepo.md) | Monorepo with independently publishable crates | Accepted |
| [002](ARCHITECTURE_DECISIONS/ADR-002-no-unsafe.md) | `unsafe_code = "forbid"` workspace-wide | Accepted |
| [003](ARCHITECTURE_DECISIONS/ADR-003-typed-identifiers.md) | Typed identifiers instead of `String` | Accepted |
| [004](ARCHITECTURE_DECISIONS/ADR-004-async-first.md) | Async-first API surface | Accepted |
| [005](ARCHITECTURE_DECISIONS/ADR-005-trait-abstractions.md) | Traits for storage, scanning, verification | Accepted, **partly unimplemented** |
| [006](ARCHITECTURE_DECISIONS/ADR-006-in-memory-first.md) | In-memory implementations before external dependencies | Accepted, **still in force** |
| [007](ARCHITECTURE_DECISIONS/ADR-007-share-components-not-duplicate.md) | Share component instances rather than duplicating them | Accepted |
| [008](ARCHITECTURE_DECISIONS/ADR-008-caller-intent-vs-operator-ceilings.md) | Separate caller intent from operator ceilings | Accepted |
| [009](ARCHITECTURE_DECISIONS/ADR-009-three-scan-outcomes.md) | Three scan outcomes, not one error count | Accepted |
| [010](ARCHITECTURE_DECISIONS/ADR-010-scan-plan-carries-its-scan-id.md) | A scan plan carries its own scan id | Accepted |
| [011](ARCHITECTURE_DECISIONS/ADR-011-scan-partial-is-its-own-event.md) | A partial scan is its own event type | Accepted |
| [012](ARCHITECTURE_DECISIONS/ADR-012-transactional-resource-acquisition.md) | Resource acquisition is transactional | Accepted |
| [013](ARCHITECTURE_DECISIONS/ADR-013-hold-the-plugin-host-until-isolation-exists.md) | Hold the plugin host until isolation exists | Accepted |

ADRs 001–006 predate the Phase 0 audit. 005 and 006 carry audit notes, because each
makes a claim that the source does not support: 005 names two traits that do not
exist, and 006's "Future Work" has not begun.

ADRs 007–013 were written during the remediation work and each corresponds to a
defect found in [`../audit/PHASE_0_AUDIT.md`](../audit/PHASE_0_AUDIT.md).

## Reading order

If you are new to the codebase, read these in order:

1. [002](ARCHITECTURE_DECISIONS/ADR-002-no-unsafe.md) — has a cost worth knowing
   about: `std::env::set_var` is untestable in process, which is why configuration
   overrides take an injected lookup function.
2. [003](ARCHITECTURE_DECISIONS/ADR-003-typed-identifiers.md) — why a scan id and a
   target id cannot be confused, and the bug that motivated it (ADR-010).
3. [008](ARCHITECTURE_DECISIONS/ADR-008-caller-intent-vs-operator-ceilings.md) and
   [009](ARCHITECTURE_DECISIONS/ADR-009-three-scan-outcomes.md) — the two decisions
   that determine what a scan is allowed to do and what it is allowed to claim.
4. [006](ARCHITECTURE_DECISIONS/ADR-006-in-memory-first.md) — what the system is
   allowed to forget, and why it currently forgets everything.

## Format

ADR-NNN-short-slug.md, with Status, Context, Decision, Consequences and References.
Consequences must include what was *not* chosen and what the decision costs. A record
whose Consequences section contains only benefits was written to persuade rather than
to inform, and should be treated with suspicion.
