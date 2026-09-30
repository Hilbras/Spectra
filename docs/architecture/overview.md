# Architecture Overview

**Status:** architecture freeze, Phase 1. Describes the system **as it is**. Where
the target differs, the difference is written down rather than described as if it
were built.

Every claim about current behaviour in this directory is checkable against the
source. Claims marked **Target** are not.

The previous single-file `ARCHITECTURE.md` in this directory describes a 12-stage
pipeline of which 5 stages do not execute. It is retained for background and
superseded by this set. See [`../audit/PHASE_0_AUDIT.md`](../audit/PHASE_0_AUDIT.md)
for the evidence behind that finding.

## Documents

| Document | Contents |
|---|---|
| [`overview.md`](overview.md) | This file: crate inventory and what actually runs |
| [`boundaries.md`](boundaries.md) | `s.txt` §4's required boundaries, verified one at a time |
| [`execution.md`](execution.md) | The scan pipeline, stage by stage, with verified arrows |
| [`runtime.md`](runtime.md) | Process lifecycle, configuration, resource bounds |
| [`security.md`](security.md) | Trust boundaries, authentication, SSRF, RBAC |
| [`storage.md`](storage.md) | Current all-in-memory state and the target persistence design |
| [`events.md`](events.md) | The event bus, what is emitted, what is missing |
| [`plugins.md`](plugins.md) | Why there is no plugin host |
| [`distributed.md`](distributed.md) | Target topology and the gap from one process |

## Crate inventory

LOC excludes nothing; tests are `#[test]` and `#[tokio::test]` attributes.
**Imported by** lists source files outside the crate that reference it, which is the
practical test of whether it participates in the system at all.

| Crate | LOC | Tests | Imported by | Role |
|---|---:|---:|---|---|
| `spectra-core` | 4,048 | 114 | 30 files | Primitives: `Id`, errors, audit, governance, SSRF, secrets, recovery |
| `spectra-findings` | 3,200 | 73 | 5 files | `Finding`, manager, observations, reports |
| `spectra-scanner` | 3,151 | 47 | 10 files | Nine vulnerability scanners |
| `spectra-engine` | 2,874 | 61 | 3 apps | Scan orchestration |
| `spectra-storage` | 1,760 | 5 | **nothing** | **Dead.** PostgreSQL repositories, unreferenced |
| `spectra-crawler` | 1,566 | 27 | `engine` | Bounded crawl with retained failures |
| `spectra-auth` | 1,166 | 28 | `api` | JWT, `Claims`, `Role`, `Permission`. Login throttle and CORS live in `main.rs`, not here |
| `spectra-http` | 1,207 | 21 | `crawler` | Client, retry, rate limiting |
| `spectra-fingerprint` | 1,161 | 17 | `engine` | Technology fingerprinting |
| `spectra-network` | 1,200 | 17 | 3 files | DNS, port scan, asset graph |
| `spectra-target` | 1,417 | 25 | 21 files | Targets, projects, scope enforcement |
| `spectra-config` | 771 | 30 | 6 files | Config, env overrides |
| `spectra-verification` | 755 | 20 | `api`, engine *tests* | **Constructed, never driven** — see below |
| `spectra-sandbox` | 735 | 26 | `plugins` only | **Not a sandbox** — transitively dead |
| `spectra-plugins` | 692 | 21 | **nothing** | **Dead.** Registry and three example plugins |
| `spectra-scheduler` | 821 | 25 | `worker` only | Reaches only the worker; nothing enqueues |
| `spectra-events` | 636 | 14 | `engine`, `api` | Event bus. **Wired** as of Remediation 14 |
| `spectra-evidence` | 960 | 20 | `engine`, `api` | Evidence capture, redaction, integrity |
| `spectra-telemetry` | 86 | 4 | 2 files | Tracing setup |

### Three kinds of "not running"

These are different problems and are not interchangeable:

1. **Referenced by nothing.** `spectra-plugins` and `spectra-storage` have zero
   importers. Nothing constructs them. They are candidates for deletion or for the
   work that would use them.
2. **Imported but never driven.** `spectra-verification` is imported by `main.rs`
   and by the engine's integration tests, and a `VerificationEngine` is constructed
   at startup — but no scan stage calls it, and nothing anywhere adds a verification
   record to it. The only `verify*` calls in the API are `verify_password`, for login.
   `GET /findings/{id}/verification` and `GET /verification/summary` therefore return
   empty for every finding, forever. This looks like a live subsystem and is not.
3. **Reachable only from a path that cannot start.** `spectra-scheduler` is imported
   by the worker, but no producer ever calls `enqueue`, so `dequeue()` always
   returns `None` and the worker has nothing to consume.

`spectra-sandbox` is a fourth case: imported by `spectra-plugins`, which is itself
unreferenced. It is transitively dead, and unsafe to wire — see
[`plugins.md`](plugins.md).

## Binaries

| Binary | Role | Status |
|---|---|---|
| `spectra-api` | HTTP API, also serves the dashboard | Complete for scans |
| `spectra-cli` | Local scan from the terminal | Works; prints the scan id so observations can be correlated |
| `spectra-worker` | Distributed worker | Cannot do useful work — nothing enqueues |

## What actually executes

A scan, end to end, runs in one process and touches these crates:

```
api ──▶ engine ──▶ network ──▶ crawler ──▶ fingerprint ──▶ scanner
           │                                                    │
           ├─▶ findings ─────────────────────────────────────────┤
           ├─▶ evidence ◀────────────────────────────────────────┘
           ├─▶ events  (scan lifecycle, to the API's audit handler)
           └─▶ core    (audit, governance, SSRF, secrets)
```

Four documented subsystems do not appear in that chain and are not merely
unreferenced from it: **verification**, **detection**, **correlation**, and
**persistence**. Each is examined in the document for its subject.

## Design commitments

These are recorded as ADRs in [`ARCHITECTURE_DECISIONS/`](ARCHITECTURE_DECISIONS/)
and are the reason the shape above is what it is:

- **ADR-002, no `unsafe`.** Enforced workspace-wide via `unsafe_code = "forbid"`.
  This has a cost worth stating: `std::env::set_var` is therefore untestable in
  process, which is why config overrides take an injected lookup function.
- **ADR-003, typed identifiers.** `Id<TargetId>` cannot be passed where
  `Id<FindingId>` is expected. A scan id and a target id are distinct types, and the
  bug where the engine wrote a target id into a field named `scan_id` was possible
  because both were `String`.
- **ADR-006, in-memory first.** Every finding, observation and evidence record lives
  in a `HashMap` behind a lock and is gone at restart. This is a deliberate starting
  point, not an oversight — but it is the single largest gap in the system and is
  specified in [`storage.md`](storage.md).
