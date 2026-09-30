# Architectural Boundaries

**Status:** verified against `Cargo.toml` and the source at the freeze commit.

This document checks `s.txt` §4's required boundaries one at a time. A boundary is
reported as **structural** when the dependency graph enforces it, **incidental** when
it holds only because no code happens to violate it, and **absent** when it does not
hold.

The distinction matters more than the verdict. A boundary that is incidental can be
broken by any contributor without touching an architecture document, and nothing will
report the break.

## The dependency graph

Internal dependencies only, after removing 35 declarations that were never imported.
Every edge below is a real `use` statement; this was not true before this commit.

```
                              core  (no internal deps, no sqlx/redis/axum/reqwest)
     ┌──────────┬───────────┬────┼────┬──────────┬──────────┬──────────┬───────┐
     │          │           │    │    │          │          │          │       │
  config     events      target  │  http     network   scanner  evidence  │    telemetry
     │          │           │    │    │          │          │     │    │       │
     │          │           │    │    └──────┬───┘          │     │    │       │
     │          │           │    │           │              │     │    │       │
     │       crawler ───────┘    │           │              │     │    │       │
     │          │                 │           │              │     │    │       │
     │       findings ◄──────────┘           │              │     │    │       │
     │       fingerprint                     │              │     │    │       │
     │          │                            │              │     │    │       │
     │     verification ◄────────────────────┴──────────────┘     │    │       │
     │                                                               │    │
     └──► engine ────────────────────────────────────────────────────┘    │
              │  ▲   │  ▲  ▲                                                    │
              │  │   │  │  └── evidence                                      │
              │  │   │  └───── verification                                  │
              │  │   └──────── findings                                      │
              │  └──────────── crawler                                       │
              └─────────────── core, config, target, fingerprint, network,    │
                              scanner, events                                 │
                                                                              │
  sandbox (no internal deps) ◄── plugins (held, ADR-013)                       │
                                                                              │
  scheduler (no internal deps) ◄──────────────────────────────┐               │
                                                                │              │
  storage ──► core (no consumers)                              │              │
                                                                ▼              ▼
                                                       worker            api ─► auth,
                                                                          config, engine,
                                                                          events, evidence,
                                                                          findings, scanner,
                                                                          target, telemetry,
                                                                          verification
```

Four crates have **no internal dependencies at all**: `core`, `auth`, `sandbox`,
`scheduler`. Three of those are self-contained for no good reason — `auth`,
`sandbox` and `scheduler` previously declared four dependencies between them and used
none.

`spectra-cli` depends on `config, core, engine, findings, target`.

## Core

> must not depend on Web · must not depend directly on PostgreSQL · must not depend
> directly on Redis · must remain reusable

**Structural. Satisfied.**

`core` declares **zero** internal dependencies. Its external dependencies are
`serde`, `serde_json`, `thiserror`, `uuid`, `chrono`, `async-trait`, `tokio`,
`tracing`, `toml`, `url`, `ipnet` — no `sqlx`, no `redis`, no `axum`, no `reqwest`,
no `tower`.

Nothing can be added here without a manifest change, which makes this the strongest
boundary in the codebase: 4,048 lines, the most depended-upon crate, and one of only
two that nothing depends on.

## Scanner

> must not manipulate DB directly · must communicate through contracts · must remain
> replaceable

| Rule | Status | Evidence |
|---|---|---|
| Not manipulate DB directly | **Structural** | `scanner -> core, target` only. The `spectra-storage` declaration was removed; it was never imported. |
| Communicate through contracts | Holds | `Scanner` trait at `crates/scanner/src/lib.rs:144`; the engine holds `Vec<Box<dyn Scanner>>`. |
| Remain replaceable | **Partial** | Any implementation of `Scanner` can be substituted — but see below. |

**The registration list is not extensible.** `create_scanners` is a `match` over nine
string literals naming concrete types (`crates/engine/src/lib.rs`). Adding a scanner
requires editing the *engine*. A scanner cannot be discovered, and a scanner from
outside the workspace cannot be registered at all.

So a scanner implementation is replaceable, but the set of scanners is fixed at
compile time by a different crate. That is a weaker guarantee than "replaceable"
usually implies, and it is worth knowing before Phase 7 adds stages.

An unrecognised name is no longer dropped in silence — the API returns `400` and the
engine records the coverage loss. See
[ADR-014](ARCHITECTURE_DECISIONS/ADR-014-unresolvable-scanner-is-a-coverage-claim.md).
That fixed a false negative; it did not make registration extensible.

## Plugin

> must use stable contracts · must not bypass authorization/scope · must execute inside
> controlled runtime

| Rule | Status |
|---|---|
| Stable contracts | `Plugin` trait exists and compiles |
| Not bypass authorization/scope | **No enforcement, and nothing to enforce** — no host exists |
| Controlled runtime | **Absent.** See [ADR-013](ARCHITECTURE_DECISIONS/ADR-013-hold-the-plugin-host-until-isolation-exists.md) |

The first rule is satisfied vacuously. The second and third are not satisfied and
cannot be, because there is no plugin host. This is the boundary most at odds with
the code, and the reason `s.txt` Phases 24–26 are recommended for removal rather than
implementation.

`spectra-plugins` now depends on `sandbox` alone, and `sandbox` on nothing.

## AI

> provider agnostic · optional · must not be required for deterministic scanning

**No AI code exists, and the requirement does not currently apply.**

Nothing in the workspace performs inference. All nine scanners are deterministic
pattern and probe logic. There is no AI SDK in any `Cargo.toml` — no `async-openai`,
no `anthropic`, no `ollama`.

**One caveat, and it is the opposite of provider agnostic.** `Config` carries an
`ai: AiConfig` field (`crates/config/src/config.rs:51`) whose defaults are:

```rust
provider: "openai".to_string(),
model: "gpt-4".to_string(),
api_key_env: "SPECTRA_AI_API_KEY".to_string(),
enabled: false,
```

**No code reads `config.ai`.** It is default-constructed, asserted by one test, and
otherwise inert. So the boundary holds by absence of implementation — but the
configuration surface names one specific vendor, and an operator who sets
`SPECTRA_AI_API_KEY` expecting AI-assisted triage will get silence rather than an
error.

Either implement provider selection or drop the field. Leaving a config block that
promises a feature is the same defect as `respect_robots` and the scan limits: an
input that looks like a control and is not.

If AI is added later, the three rules mean: no compile-time binding to one provider,
scanning works with it switched off, and no scan result may depend on a model having
been called. That last one is a design constraint on any AI-assisted triage, because
it would otherwise make findings non-reproducible — and reproducibility is the
property the rest of the pipeline is built to preserve.

## Storage

> abstract · PostgreSQL implementation · local development implementation · future
> distributed implementations

| Rule | Status |
|---|---|
| Abstract | `Storage` and `Database` traits exist |
| PostgreSQL implementation | `PostgresDatabase` exists in `pg.rs` |
| Local development implementation | `LocalStorage` exists |
| Future distributed | None |

**Structurally complete and entirely unused.** `spectra-storage` is depended upon by
**no crate**. It depends on `core` and nothing consumes it.

The traits also accept `Arc<T>` ([ADR-007](ARCHITECTURE_DECISIONS/ADR-007-share-components-not-duplicate.md)),
so substitution is cheap. It is not free: the migration runner is not idempotent,
`pg_row_to_row` has eight silent `Value::Null` fallbacks, and ten struct fields have
no matching column. See [`storage.md`](storage.md).

## Execution

> separable from orchestration · worker-compatible · retryable

| Rule | Status | Evidence |
|---|---|---|
| Separable from orchestration | **Now structural** | `engine -> scheduler` was removed; it was never imported. The engine cannot reach a job queue. |
| Worker-compatible | Manifest only | `worker -> engine, scheduler, target`, but nothing calls `enqueue`, so `dequeue()` always returns `None`. |
| Retryable | **Absent** | No scan-level retry exists anywhere. |

The first row is worth dwelling on. `engine` *declared* `spectra-scheduler` and never
used it, which is precisely why `Engine -> Scheduler` appeared as a real arrow in the
old architecture document and why the audit found it broken. The declaration made the
dependency graph lie. Removing it means the graph and the code now agree.

## Web

> consumer of API only

**Satisfied, and the rule is doing less work than it appears to.**

There is no web tier. `spectra-api` *is* the server: it depends on `engine`, `scanner`,
`findings`, `verification`, `evidence` and `target` and calls them directly, which is
correct for the tier that owns them.

The dashboard is a single committed `apps/api/static/index.html` (24 KB), served as a
static file and calling the HTTP API from the browser. It has no server-side path into
the engine, so the boundary holds where it matters. The Dockerfile copies it to
`/opt/spectra/static` and sets `SPECTRA_STATIC_DIR`.

If a second service is ever added, this boundary is the one that needs enforcing, and
it will need enforcing structurally — it is currently a consequence of there being only
one binary, not a rule.

## Summary

| Boundary | Verdict |
|---|---|
| Core | **Structural.** Zero internal deps, no DB or web crates. |
| Scanner | **Structural** for the DB rule; contracts hold; discovery is not extensible. |
| Plugin | **Absent.** Contracts exist, runtime is not controlled, nothing to enforce. |
| AI | **Not applicable in code.** No AI crate or SDK; but `Config.ai` names OpenAI and is inert |
| Storage | **Structural but unused.** All four required shapes exist; no consumer. |
| Execution | **Separation now structural**; worker-compatible in name only; not retryable. |
| Web | Holds, as a consequence of there being one binary rather than as a rule. |

Two boundaries — Plugin and Execution — cannot be closed without building the
subsystems they describe. Both are addressed by the recommendation to drop `s.txt`
Phases 24–26 and to treat persistence as the prerequisite for the queue rather than
the other way round.
