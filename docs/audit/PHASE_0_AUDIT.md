# Phase 0 — Repository & Release Audit

**Status:** Complete. P0 remediation pass applied — all eight hoisted P0 defects fixed and verified; see [Phase 0 remediation log](#phase-0-remediation-log).
**Date:** 2026-09-29
**Baseline commit:** `e53ee0e` + uncommitted working-tree changes
**Method:** Static analysis + compilation + test execution (toolchain installed for this audit)

This document answers the questions posed in `s.txt` §3 (Phase 0.1–0.5). It establishes ground truth before any architectural change is made, per the phase goal: *"Establish the actual state of the repository before modifying architecture or deleting/replacing anything."*

> **Reading note.** The findings below are the state at baseline `e53ee0e`. The
> P0 items have since been remediated; the tables still record the original
> observation, and the [remediation log](#phase-0-remediation-log) records what
> was changed and how it was verified. Findings not listed there are still open.

---

## Summary of findings

| # | Finding | Severity | Phase 0.1 item | Status |
|---|---|---|---|---|
| A1 | `spectra-storage`, `spectra-events`, `spectra-plugins` are 100% dead — zero references outside themselves | **Critical** | default in-memory components | Open |
| A2 | 35 declared internal dependencies are never imported | **High** | unused dependencies | Open |
| A3 | Declared MSRV `1.75` does not compile; fails on `edition2024` transitive deps | **High** | (new) | Open |
| A4 | 4 documented execution-graph stages never execute | **High** | test-only paths in production | Open |
| A5 | `CorrelationEngine` constructed, accessor never called | Medium | dead code | Open |
| A6 | All 26 migration tables unreferenced by any code | **High** | placeholder implementations | Open |
| A7 | `#[allow(dead_code)]` on 7 sites marks constructed-but-unreachable code | Medium | dead code | Open |
| A8 | No `todo!()`/`unimplemented!()`/placeholder macros found | ✅ Clean | — | — |
| A9 | Versions are already consistent at `0.1.1` (s.txt §0.5 claim is stale) | ✅ Clean | — | — |
| A10 | `spectra-api` and `spectra-cli` have **0 tests**; test density is inversely correlated with risk | **High** | (new) | Partly fixed (API: 0 → 42) |
| A11 | XSS detector reported findings not derived from the target's response | **Critical** | (new) | **Fixed** |
| A12 | SSRF guard was both unwired and bypassable | **Critical** | (new) | **Fixed** |
| A13 | RBAC existed with zero call sites; three disagreeing implementations of the authorisation decision | **Critical** | (new) | **Fixed** |
| A14 | A scan that reached nothing reported `Completed` with 0 findings — a false negative | **Critical** | (new) | **Fixed** |
| A15 | API and engine each built their own stores; 3 endpoints permanently empty | **Critical** | (new) | **Fixed** |
| A16 | `max_depth`/`max_pages`/`timeout_secs` accepted and ignored; scans unbounded | **High** | (new) | **Fixed** |
| A17 | `ResourceGovernor` never called; concurrent scans unbounded | **High** | (new) | **Fixed** |
| A18 | `spectra-sandbox` executes subprocesses with full server privileges | **Critical** | (new) | **Contained** |
| A19 | `spectra-events` fully implemented, nothing emitted or consumed | Medium | (new) | **Fixed** |

---

## 0.1 Repository inventory

### Actual workspace members

**22 members** (21 reported): 19 library crates + 3 binaries. `crates/auth` is present in the workspace but **absent from the README crate table** (lines 239–256).

```
crates/  auth config core crawler engine events evidence findings fingerprint
         http network plugins sandbox scanner scheduler storage target
         telemetry verification                                    (19 libraries)
apps/    api cli worker                                             (3 binaries)
```

### Unused dependencies — 35 internal crates declared but never imported

This is the most consequential inventory finding. It is the mechanism by which A1 stayed invisible: `spectra-storage` is declared in **8** `Cargo.toml` files and imported in **zero** of them.

| Crate | Declares but never imports |
|---|---|
| `api` | `spectra-storage`, `spectra-events` |
| `worker` | `spectra-findings` |
| `crawler` | `spectra-network`, `spectra-storage`, `spectra-events` |
| `engine` | `spectra-storage`, `spectra-events`, `spectra-config`, `spectra-scheduler` |
| `evidence` | `spectra-storage` |
| `findings` | `spectra-storage`, `spectra-events`, `spectra-evidence` |
| `fingerprint` | `spectra-storage` |
| `http` | `spectra-config` |
| `network` | `spectra-target`, `spectra-config`, `spectra-events` |
| `scanner` | `spectra-network`, `spectra-crawler`, `spectra-storage`, `spectra-events`, `spectra-config` |
| `scheduler` | `spectra-core`, `spectra-storage`, `spectra-events`, `spectra-config` |
| `target` | `spectra-storage`, `spectra-events` |
| `verification` | `spectra-core` |
| `telemetry` | `spectra-core` |
| `auth`, `plugins`, `sandbox` | `spectra-core` (+ `config`/`events`/`sandbox` variants) |

**Consequence:** the declared dependency graph is documentation, not architecture. Any dependency-conformance check written against these manifests will pass while the real coupling is invisible.

### Dead code markers

`s.txt` §0.1 asks for TODO/FIXME and placeholders. Result:

| Pattern | Count | Assessment |
|---|---|---|
| `todo!()` | **0** | ✅ Clean |
| `unimplemented!()` | **0** | ✅ Clean |
| `panic!("not implemented")` | **0** | ✅ Clean |
| `TODO` / `FIXME` | **0** | ✅ Clean |
| `unsafe` blocks | **0** | ✅ Clean (`unsafe_code = "forbid"`) |
| `#[allow(dead_code)]` | **7** | ⚠️ See A7 |
| `let _ = ` (discarded `Result`) | **6+** | ⚠️ Silent failure paths in API |
| `.unwrap_or_default()` on fallible ops | **4** | ⚠️ Converts errors into success |

**A7 — `#[allow(dead_code)]` sites:**

| Location | Symbol | Status |
|---|---|---|
| `apps/api/src/main.rs` ×4 | `config`, `recovery_manager`, `governor`, `secret_manager` | Constructed, never read |
| `apps/worker/src/main.rs` ×2 | `id()`, `hostname()` | Exist only for tests |
| `crates/core/src/ssrf.rs` | guard internals | **Unused by any production path** |

These are the only markers recording where the "built but unwired" boundary was crossed.

### Hardcoded values

Baseline observations. The first two were remediated in the P0 pass; see the
[remediation log](#phase-0-remediation-log).

| Value | Location | Risk | Status |
|---|---|---|---|
| `"spectra-default-secret-change-me"` | `api/main.rs:1259`, `auth/middleware.rs:58`, `auth/lib.rs:53` | **Critical** — forgeable admin tokens | **Fixed** — no fallback; server refuses to boot |
| `admin` / `admin` | `api/main.rs:52-69`, `static/index.html:167,171` | **Critical** — only possible account | **Fixed** in `main.rs`; dashboard placeholder text still to review |
| `postgresql://localhost/spectra` | `config/src/config.rs:104` | Default never overridden (no consumer) | Open |
| `0.0.0.0` | `config/src/config.rs:86` | Binds all interfaces by default | Open — deliberate, document it |

### Default in-memory components

Every stateful component in all three binaries is an in-memory default:

```
api/main.rs:1266-1277   4 separately-constructed in-memory stores (see A-split)
worker/main.rs:277      InMemoryJobQueue::with_defaults()
cli/main.rs:363         InMemoryFindingsManager::new()
```

---

## 0.2 Implementation audit

`s.txt` asks ten questions per subsystem. Answers are **exists / compiles / tested / wired / reachable / persists / survives restart / handles failure / observable / exposed**.

| Subsystem | Code exists | Compiles | Tested | Wired | Reachable from engine | Persists | Survives restart | Handles failure | Observable | Exposed |
|---|---|---|---|---|---|---|---|---|---|---|
| `core` | ✅ | ✅ | ✅ | ⚠️ `ssrf` guard unused | ✅ | n/a | n/a | ⚠️ | ✅ | n/a |
| `config` | ✅ | ✅ | ✅ | ⚠️ `unwrap_or_default` | ⚠️ | n/a | n/a | ❌ | ❌ | ✅ |
| `events` | ✅ | ✅ | ✅ | ❌ **0 refs** | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |
| `storage` | ✅ | ✅ | ✅ | ❌ **0 refs** | ❌ | ⚠️ pg real but unreachable | ❌ | ⚠️ 8× silent NULL | ❌ | ❌ |
| `telemetry` | ✅ | ✅ | ✅ | ⚠️ no exporter | ❌ | n/a | n/a | ❌ | ❌ | ❌ |
| `target` | ✅ | ✅ | ✅ | ✅ | ✅ | ❌ | ❌ | ⚠️ | ❌ | ✅ |
| `http` | ✅ | ✅ | ✅ | ✅ | ✅ | n/a | n/a | ⚠️ | ❌ | n/a |
| `network` | ✅ | ✅ | ✅ | ✅ | ✅ | ❌ | ❌ | ⚠️ | ❌ | ❌ |
| `fingerprint` | ✅ | ✅ | ✅ | ✅ | ✅ | ❌ | ❌ | ⚠️ | ❌ | ❌ |
| `crawler` | ✅ | ✅ | ⚠️ | ✅ | ✅ | ❌ | ❌ | ❌ **`total_crawled` = discovered** | ❌ | ❌ |
| `scanner` | ✅ | ✅ | ⚠️ false-positive-prone | ✅ | ✅ | ❌ | ❌ | ❌ **errors never read** | ❌ | ❌ |
| `findings` | ✅ | ✅ | ✅ | ✅ | ✅ | ❌ | ❌ | ⚠️ | ❌ | ✅ |
| `evidence` | ✅ | ✅ | ✅ | ✅ | ✅ | ❌ in-memory + `LocalStorage` | ❌ | ⚠️ | ❌ | ⚠️ always empty |
| `verification` | ✅ | ✅ | ✅ | ❌ **never invoked by engine** | ❌ | ❌ | ❌ | ❌ | ❌ | ⚠️ always empty |
| `engine` | ✅ | ✅ | ❌ **`integration_tests.rs` has no engine refs** | ✅ | ✅ | ❌ | ❌ | ❌ all-or-nothing `?` | ⚠️ | ✅ |
| `scheduler` | ✅ | ✅ | ⚠️ asserts the bug | ❌ **API doesn't depend on it** | ❌ | ❌ | ❌ **total loss** | ❌ `retry()` bypasses cap | ❌ | ❌ |
| `plugins` | ✅ | ✅ | ✅ | ❌ **0 refs** | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |
| `sandbox` | ✅ | ✅ | ✅ | ❌ only via dead `plugins` | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |
| `auth` | ✅ | ✅ | ✅ | ⚠️ **authentication only** | n/a | ❌ users in `HashMap` | ❌ | ❌ no lockout | ⚠️ success-only | ✅ |
| `api` | ✅ | ✅ | ❌ | ✅ | ✅ | ❌ | ❌ | ⚠️ | ⚠️ | ✅ |
| `cli` | ✅ | ✅ | ❌ | ⚠️ ~20 print-only stubs | ✅ | ❌ | ❌ | ❌ exits `0` on error | ❌ | ✅ |
| `worker` | ✅ | ✅ | ❌ | ❌ **no producer for its queue** | ❌ | ❌ | ❌ | ❌ discards results | ⚠️ local only | ❌ |

### Test density is inversely correlated with risk

| Crate | Tests | LOC | Tests/100 LOC |
|---|---|---|---|
| `storage` | **5** | **1,760** | **0.3** |
| `scanner` | 35 | 2,757 | **1.3** |
| `engine` | 29 | 1,675 | **1.7** |
| `network` | 17 | 1,200 | 1.4 |
| `fingerprint` | 17 | 1,161 | 1.5 |
| `crawler` | 23 | 1,362 | 1.7 |
| `auth` | 15 | 781 | 1.9 |
| `verification` | 20 | 755 | 2.6 |
| `findings` | 69 | 3,006 | 2.3 |
| `scheduler` | 25 | 821 | 3.0 |
| `sandbox` | 26 | 696 | 3.7 |
| `plugins` | 21 | 667 | 3.1 |
| `core` | 82 | 3,299 | 2.5 |
| `evidence` | 20 | 960 | 2.1 |
| `http` | 21 | 1,207 | 1.7 |
| `target` | 25 | 1,417 | 1.8 |
| `config` | 23 | 551 | 4.2 |
| `telemetry` | 4 | 86 | 4.7 |
| `events` | 14 | 616 | 2.3 |
| **crates subtotal** | **491** | — | — |

**Applications have 13 tests total, and they are in the wrong place:**

| App | LOC | Tests |
|---|---|---|
| `api` | **1,362** | **0** |
| `cli` | 806 | **0** |
| `worker` | 456 | 13 |
| **Total** | 2,624 | **13** (0.5 tests/100 LOC) |

`spectra-api` — the entire HTTP attack surface, containing authentication, the admin account, the CORS layer, and 20 endpoints — has **zero tests**. So does the CLI. Every test in the workspace targets library crates; none target the binaries an operator actually runs.

Full workspace total: **504** (491 crates + 13 apps) — versus the 387 claimed in `REPORT.md` and `README.md`.

The three least-tested crates are the three that carry the most risk: `storage` (holds all persistence logic, 1,760 LOC, 5 tests, and `pg_row_to_row` has **zero** tests), `scanner` (generates every user-facing security claim), and `engine` (orchestration, where `integration_tests.rs` contains no engine references at all).

By contrast `sandbox`, `plugins`, and `events` — three of the dead or unwired crates — have the *highest* test density. Effort is concentrated on code that does not run.

### Answering s.txt's explicit sub-questions

- **Is it reachable from the engine?** 5 of 19 subsystems are: `core`, `target`, `network`, `scanner`, `findings`. Plus `evidence` (via import) and `crawler`/`fingerprint` (constructed inline, not via engine fields).
- **Does it persist data?** Nothing. No subsystem persists.
- **Does it survive restart?** Nothing does. `s.txt` §0.4: *"No critical state may silently disappear after process restart."* **Currently every piece of state does.**
- **Is it observable?** Telemetry is a no-op exporter; no metrics, no tracing on scan internals; audit log is in-memory and records successes only.

### Test-only paths in production

| Path | Issue |
|---|---|
| `api/main.rs:797` | `tokio::spawn` with **discarded `JoinHandle`** — a panicking scan vanishes, leaving the job `Pending` forever |
| `dirsearch.rs:238` | `JoinError` discarded — panicking task reported as "no findings" |
| `worker/main.rs:201-209` | `id()`/`hostname()` exist only to satisfy tests |
| `engine/src/integration_tests.rs` | Named "integration tests"; contains **zero engine references** |

---

## 0.3 Integration audit

`s.txt` requires every arrow in the documented graph to correspond to executable code.

### Documented graph vs. actual

The documented chain is:

```
API → Engine → Scheduler → Worker → Execution → Events → Observation
    → Detection → Finding → Verification → Evidence → Correlation
    → Storage → API/CLI/Web
```

**Verified actual graph** — extracted from `ScanEngine::run_scan` (`crates/engine/src/lib.rs:259-474`):

```
API (api/main.rs:797)  ──spawn──▶  ScanEngine::run_scan
                                        │
     ┌──────────────────────────────────┤
     ▼                                  ▼
 network_engine.discover()        crawler.crawl()
     │  (spectra-network)          (spectra-crawler)
     ▼                                  ▼
 observations ────────────────▶  fingerprint (from crawled pages)
                                        │
                                        ▼
                                 scanner.scan()  (9 scanners)
                                        │
                                        ▼
                              findings + evidence
                                        │
                                        ▼
                                 generate_report()
```

### A4 — Four documented stages never execute

| Documented stage | Reality | Evidence |
|---|---|---|
| `Engine → Scheduler` | ❌ **Broken.** API does not depend on `spectra-scheduler`; scans run in-process via `tokio::spawn`. `engine` declares the dep but never imports it. | `api/Cargo.toml` has no `spectra-scheduler` |
| `Worker → Execution` | ❌ **Unreachable.** Nothing ever enqueues, so `dequeue()` always returns `None`. Worker binds concrete `InMemoryJobQueue`, so Redis is unreachable. | `worker/main.rs:277`, nothing calls `enqueue` |
| `Execution → Events` | ❌ **Dead crate.** `spectra-events` has 0 references outside itself. `run_scan` contains zero occurrences of "event". | grep, 0 hits |
| `→ Detection` | ❌ **Never invoked.** No `DetectionEngine` call in `run_scan`; findings are written directly by scanners. | `engine/src/lib.rs` |
| `→ Verification` | ❌ **Never invoked.** Zero `verification` references in `run_scan`. `VerificationEngine` is constructed in the API but nothing populates it. | grep, 0 hits in engine |
| `→ Correlation` | ❌ **A5.** `CorrelationEngine` is constructed at `lib.rs:227,239` and exposed via `correlation_engine()` — **the accessor is never called anywhere.** | grep, 0 call sites |
| `→ Storage` | ❌ **Broken.** `spectra-storage` has 0 references outside itself. The only SQL ever executed targets `search_documents`, in dead code. | grep, 0 hits |

**5 of 12 documented arrows are broken or dead. 4 of 19 subsystems execute.**

### A-split — the API reads from stores the engine never writes to

`apps/api/src/main.rs:1266-1277` constructs **four** separate in-memory stores:

```rust
let findings_manager = Arc::new(InMemoryFindingsManager::new());        // store A — API reads
let scan_engine = Arc::new(ScanEngine::new_with(
    InMemoryFindingsManager::new(),                                    // store B — engine writes
    InMemoryObservationStore::new(),                                   // store C — engine writes
));
// ...
observation_engine: Arc::new(ObservationEngine::new(
    InMemoryObservationStore::new())),                                  // store D — API reads
```

Consequences:
- `GET /scans/:id/observations` — reads D, engine writes C → **permanently empty**
- `GET /findings/:id/evidence` — reads a store the engine never populates → **permanently empty**
- `GET /verification/*` — nothing ever writes a verification → **permanently empty**
- `get_stats` hardcodes the symptom: `api/main.rs:1236` → `observations_total: 0`

Findings are partially papered over by a copy-back loop (`main.rs:800-807`) that re-copies the engine's *entire accumulated* manager on every scan completion — so findings from prior scans are re-saved each time, and `run_scan`'s own report includes all prior scans' findings.

---

## 0.4 Persistence audit

`s.txt` requires: *"No critical state may silently disappear after process restart."*

| Stateful object | Memory-only | DB-backed | Object-storage | Reconstructable | Survives restart |
|---|---|---|---|---|---|
| Organizations / Projects / Targets | ✅ | ❌ | ❌ | ❌ | ❌ |
| Scans / ScanJobs | ✅ | ❌ | ❌ | ❌ | ❌ |
| Findings | ✅ | ❌ | ❌ | ❌ | ❌ |
| Observations | ✅ | ❌ | ❌ | ❌ | ❌ |
| Evidence | ✅ | ❌ | ⚠️ `LocalStorage` (unwired, path-traversable) | ❌ | ❌ |
| Verifications | ✅ | ❌ | ❌ | ❌ | ❌ |
| Users / API keys | ✅ | ❌ | ❌ | ❌ | ❌ |
| Audit log | ✅ | ❌ | ❌ | ❌ | ❌ |
| Metrics | ✅ | ❌ | ❌ | ❌ | ❌ |
| Job queue (4 buckets) | ✅ | ❌ | ❌ | ❌ | ❌ **running jobs vanish mid-flight** |

**Verdict: 0 of 12 stateful objects survive restart. This is the central Phase 2 driver.**

### A6 — Migrations describe a database nothing creates

All **26 tables** across 6 migrations are unreferenced by any code. The only SQL statement executed anywhere in the workspace targets `search_documents` (`crates/storage/src/search.rs:67,156`) — and that table's DDL exists only in Rust code (`search.rs:22-59`), **not in `migrations/`**.

Additional migration defects relevant to Phase 2:

- **No version table.** `pg.rs:64-100` re-runs every file from 001 on each invocation.
- **Not idempotent.** `CREATE INDEX` at `002_target_management.sql:15` lacks `IF NOT EXISTS` (unlike the tables). A second run aborts mid-way, leaving a half-migrated schema.
- **`soft_delete()` and `update_updated_at_column()`** (`001_initial.sql:9-25`) are defined but **never attached to a trigger** — zero `CREATE TRIGGER` in any migration.
- **Struct ↔ column drift** (blocks Phase 2.2 repository work):
  | Struct | Field with no column |
  |---|---|
  | `ScanRecord` | `progress` |
  | `EvidenceRecord` | `content_type`, `size_bytes`, `storage_path` |
  | `ObservationRecord` | `title`, `description` |
  | `WorkerRecord` | `capacity`, `active_jobs` |
  | `AuditRecord` | `details` |
  | `JobRecord` | `error`→`error_message`, `max_attempts`→`max_retries`, `queued_at`→`created_at` |
  | `MetricsRepository` | targets a **`metrics` table that does not exist** |
- **`pg_row_to_row` has zero tests** and silently maps 8 decode failures plus all unhandled types (`inet`, `numeric`, arrays) to `Value::Null`.

### Env var name drift (blocks Phase 2.4)

| Source | Variable | Code actually reads |
|---|---|---|
| `docker-compose.production.yml:37` | `DATABASE_URL` | `SPECTRA_DATABASE_URL` (`config.rs:314`) |
| `docker-compose.production.yml:39` | `JWT_SECRET` | `SPECTRA_JWT_SECRET` (`main.rs:1258`) |
| `SECURITY.md:105` | `JWT_SECRET` | `SPECTRA_JWT_SECRET` |

Even `SPECTRA_DATABASE_URL` is read into config and then never consumed — `database_url()` has 1 call site, inside `#[cfg(test)]`.

---

## 0.5 Version normalization

**Finding A9 — `s.txt`'s conflict claim is stale. Versions are already consistent.**

| Artifact | Version | Source |
|---|---|---|
| `Cargo.toml` `[workspace.package]` | `0.1.1` | ✅ |
| All 22 member crates | `version.workspace = true` | ✅ no overrides |
| `npm/package.json` | `0.1.1` | ✅ |
| `CHANGELOG.md` | `0.1.1` | ✅ |
| `README.md` crate table (18 rows) | `0.1.1` | ✅ but **omits `spectra-auth`** |
| `REPORT.md` header | `0.1.1` | ✅ |
| GitHub release | *no release exists* | ⚠️ n/a |

**Action:** add `spectra-auth` to the README crate table. No version bump until Phase 2 lands.

### A3 — Declared MSRV does not compile

`Cargo.toml` declares `rust-version = "1.75"`. Building on 1.75.0 fails:

```
error: failed to download replaced source registry `crates-io`
  feature `edition2024` is required
  The package requires the Cargo feature called `edition2024`,
  but that feature is not stabilized in this version of Cargo (1.75.0)
```

Transitive dependencies have moved past the declared MSRV. CI uses `dtolnay/rust-toolchain@stable` so it does not surface this, but **any consumer building against the published MSRV fails**. This must be fixed before `crates.io` publication (Phase 0.5 / release).

**Action:** either pin transitive deps in `Cargo.lock` to 1.75-compatible versions, or raise `rust-version` to the true minimum. Recommend raising it and testing against it in CI.

---

## Phase 0 gate

`s.txt` §3 requires establishing actual state before modifying architecture. This document does that. Findings are recorded; no code was modified during this phase.

### Phase 0 remediation log

The P0 items scheduled for Phases 4, 6 and 11 were hoisted ahead of Phase 1 and
remediated, because each was a live vulnerability rather than a design question
and none of them is blocked on an architectural decision. Verification is
recorded per item below; all of it is reproducible from the commands in the
appendix.

**Gates, current state** — `cargo build --workspace`, `cargo test --workspace`
(573 passed / 0 failed), `cargo clippy --workspace --all-targets -- -D
warnings`, and `cargo fmt --all -- --check` all pass. This is the first time the
"all tests passing" claim has been verified; it was previously asserted without
a recorded run.

| P0 item | Status | Evidence |
|---|---|---|
| Fabricated XSS findings (`scanner/src/xss.rs`) | **Fixed** | Differential detection with a reflection sentinel + context classification. 12 regression tests. Was: a page containing its own `<script>` produced a finding. |
| Hardcoded JWT secret | **Fixed** | `JwtConfig::from_env` has no fallback; server exits non-zero when unset or under 32 bytes. Zero occurrences of the old string in code. |
| `admin` / `admin` default credentials | **Fixed** | `UserStore::bootstrap` takes `SPECTRA_ADMIN_PASSWORD` or generates a random 32-byte password into a `0600` file. |
| Unsalted SHA-256 password hashing | **Fixed** | argon2id with per-user random salt, constant-time verification. 3 hashing tests. |
| Wildcard CORS | **Fixed** | Explicit allowlist via `SPECTRA_CORS_ORIGINS`; unset permits no cross-origin access. 8 CORS tests, including 4 that drive real preflight requests. |
| No login rate limiting | **Fixed** | Per-client lockout after 5 failures in 5 min, 15 min lockout, `Retry-After` header. 6 throttle tests. |
| Unused SSRF guard | **Fixed + hardened** | Wired into `POST /api/v1/scans`; 7 bypasses closed (see below). Opt-out via `SPECTRA_ALLOW_INTERNAL_TARGETS`. |
| Docker/compose unreachable, static dir missing | **Fixed** | `EXPOSE 8080` matches config; static assets copied; env var names corrected. |

**Note on the SSRF guard.** The guard was not merely unwired — it was also
defective. `localhost`, `metadata.google.internal`, `host.docker.internal`,
`0.0.0.0` and hexadecimal IPv4-mapped addresses (`::ffff:7f00:1`) all passed.
Those are now blocked, and `validate_resolved_url` additionally resolves the
hostname so a public name pointing at an internal address is refused. Confirmed
at runtime: `localtest.me` → `::1` is refused. 24 new tests.

Two further defects were found by the new tests rather than by inspection, and
are recorded because they would have shipped:

- `AllowOrigin::list` **panics** on `*`, so `SPECTRA_CORS_ORIGINS=*` crashed the
  server at startup. Rejected explicitly now.
- `HeaderValue::from_str` accepts `"not a valid origin"` (spaces are legal in a
  header value), so a malformed entry was silently added to the allowlist.
  Origins are now validated against the shape a browser actually sends.

**Build environment.** The workspace could not link locally: `reqwest` used
default features, pulling in `native-tls` and requiring system OpenSSL. It now
uses `rustls-tls`, which matches `sqlx`'s existing `runtime-tokio-rustls`,
bundles `webpki-roots`, and removes the `libssl-dev` build requirement. This is
also why the `Dockerfile` no longer installs `libssl-dev`.

**Not remediated here** — these remain open and are tracked by their own phases:

| Blocker | Phase |
|---|---|
| `network_asset_count` counts the target without verifying reachability | Phase 7 (Engine) |
| No per-caller cap on scans over time, only on concurrency | Phase 7 (Engine) |
| `HierarchicalGovernor` (5 tiers) never constructed | Phase 3 (Orchestration) |
| MSRV 1.75 does not compile | Before publication |
| `spectra-storage` / `spectra-events` / plugins still dead | Phase 2 / 22 / 25–26 |

**Resolved here:** RBAC (Remediation 9), the swallowed-failure P0
(Remediation 10), the split-brain stores (Remediation 11), the unenforced scan
limits (Remediation 12), the unwired resource governor (Remediation 13), and the
dead-crate decision (Remediation 14). See below.

**Still split-brain:** the API's `verification_engine` is still a separate object
that nothing writes to — `ScanEngine` has no verification stage at all, so
`GET /findings/{id}/verification` and `GET /verification/summary` return empty.
That is a missing pipeline stage rather than a wiring fault, and is tracked under
Phase 7.

### Required before Phase 1 (Architecture Freeze)

Architecture documentation must describe the **actual** system. Writing docs against the 12-arrow documented graph would encode 5 broken arrows into the architecture record.

**Decided:** `spectra-storage` is to be **implemented**, not deleted. `s.txt` §5
treats persistence as a highest-priority phase, and 0 of 12 stateful objects
currently survive a restart, so the crate is load-bearing for the plan even
though nothing imports it yet.

**Now decided for all four** (Remediation 14 below), which unblocks Phase 1:

| Crate | LOC | Tests | Decision |
|---|---|---|---|
| `spectra-storage` | 1,760 | 5 | **Implement** — Phase 2 |
| `spectra-events` | 616 | 14 | **Wire** — done, Remediation 14 |
| `spectra-plugins` | 667 | 21 | **Hold** — no host until real isolation exists |
| `spectra-sandbox` | 696 | 26 | **Hold, and contained** — it does not sandbox |

### Carried-forward blockers

These are recorded here for traceability; each is remediated in its own phase:

| Blocker | Phase |
|---|---|
| `PlanTimeout`/`max_depth`/`max_pages` never read by `run_scan` | Phase 7 (Engine) |
| `network_asset_count` counts the target without verifying reachability | Phase 7 (Engine) |
| MSRV 1.75 does not compile | Before publication |

### Remediation 9 — Authorisation (RBAC)

`Permission`, `Role`, `Role::has_permission` and `require_permission_fn` existed
and were unit-tested, but had **no call sites outside their own tests**. Every
authenticated route was therefore available to every authenticated caller. This
was the last of the eight hoisted P0 defects.

**Roles are now the single source of truth.** The bootstrap admin previously
carried a hand-maintained permission list alongside `roles`, and the two had
already drifted: the list granted `scans:write` — a string this codebase does
not define as a permission, the real one being `scans:execute` — and omitted
`evidence`, `users`, `settings` and `api_keys` entirely. `UserEntry.permissions`
is removed; grants are derived from roles at token-issue time by
`expand_role_permissions`, so the two cannot diverge again.

**Three implementations of "may this caller?" existed**, and they disagreed:

1. `check_permission(&Claims, ..)` re-derived grants from `claims.roles`,
   ignoring `claims.permissions` entirely.
2. `require_permission_fn` did the same, in middleware form.
3. Nothing was actually called.

All three consulted the role claim rather than the granted list, which makes a
token self-escalating: a token claiming `admin` gains every permission whatever
the issuer granted. The surviving `check_permission(&AuthUser, ..)` reads the
grant list, and `roles_in_claims_do_not_grant_by_themselves` pins that.

**Per-method guards.** `MethodRouter::layer` applies to every method, but
`GET /scans` is a read while `POST /scans` makes the server fetch a
caller-chosen URL. The `guarded_route!` macro builds each method as its own
single-method router and merges them; each method's permission sits beside its
handler. `MethodRouter::merge` panics on a duplicate method, which is why the
router cannot be re-opened and re-layered per method after the fact.

**The route table was extracted** into `protected_routes()` so tests drive the
real table. A test against a hand-built copy proves only that the copy works;
the bug being guarded against is a route that was never wired.

**Third defect found by the new tests, not by inspection:** `Role::from_str`
never fails — it falls through to `Role::Custom` for any input — so
`is_known_name` built on parseability was vacuously `true` for every string. A
typo in a role name (`admn`) would resolve to `Custom("admn")`, grant nothing,
and log nothing. `is_known_name` now matches the four built-in names explicitly.

**Test discrimination was verified by mutation**, not assumed: forcing
`check_permission` to always return `Ok` fails 3 tests, and removing the guard
from `POST /scans` alone fails 4.

26 new tests.

### Remediation 10 — Swallowed failures (the false negative)

`ScanResult.errors` and `CrawlResult.errors` were written and never read. The
consequence is worse than a lost log line: **a scan that reached nothing reported
itself as `Completed` with zero findings**, which in a findings report is
indistinguishable from a clean target. For a security tool that is the worst
possible failure direction — a false negative reported as a clean bill of health.

Three separate defects combined to produce it:

1. `crawler/src/lib.rs:146` assigned `total_discovered` to `total_crawled`, so
   `success_rate()` was a constant 1.0 and `GET /scans/{id}` reported the count
   of URLs *attempted* as the count of pages *crawled*.
2. `CrawlResult.errors` was a bare `u32` and the individual reasons were dropped
   at `Err(_) => errors += 1`, so a dead target, a 404 and a crawler bug were
   indistinguishable.
3. `run_scan` set `ScanStatus::Completed` unconditionally on the `Ok` path,
   conflating "the orchestration finished" with "the target was analysed".

**Fixed:**

- `total_crawled` is now `pages.len()`. `success_rate()` follows, as does
  `crawl_page_count` in the API response.
- `CrawlResult.errors` is a `Vec<String>` retaining the URL and the reason;
  `error_count()` and `yielded_nothing()` were added.
- `ScanResult.errors` from every scanner now reaches `job.errors` and therefore
  `GET /scans/{id}`.
- A new `ScanStatus::Partial` distinguishes lost coverage from success. The
  decision lives in `ScanJob::resolve_status`, extracted so it is unit-testable
  without network access.
- `ReportGenerator::text_summary_with_coverage` renders the failures *above* the
  summary block, because the counts are what a reader quotes out of a report.
  `text_summary` is unchanged for callers with no failures to report.

**Three explicit severity levels, not one error count.** `record_error` (reported,
no status effect), `record_lost_coverage` → `Partial`, `record_coverage_gap` →
`Failed`. The first exists to avoid crying wolf: a few unreachable URLs in a
several-hundred-page crawl is routine, and if that flipped every scan to `Partial`
the status would stop carrying information.

**Verified at runtime,** not only by unit test. A scan of `http://127.0.0.1:1/`
(a loopback port with nothing listening) now returns `status: "Failed"`,
`crawl_page_count: 0`, three specific errors, and a `report_summary` beginning
`Scan status: Failed / WARNING: ... their absence is not evidence that the target
is clean`. Before the fix the same request returned `Completed`,
`crawl_page_count: 1` and an empty `errors` array.

**A test gap was caught by mutation testing, not inspection.** Reverting the
`total_crawled` assignment initially failed *zero* tests, because the crawler
tests only exercised a hand-built `CrawlResult` and never called `crawl()`. Two
tests now run a real crawl against a loopback socket — one serving a canned
response over `std::net`, one on a dead port — so the assignment itself is
covered. Reverting it now fails.

Also noted while verifying: `network_asset_count` reports `1` for the unreachable
target, because the network engine counts the target without verifying it is
reachable. Recorded as an open Phase 7 item.

16 new tests.

### Remediation 11 — Split-brain stores

`build_state` built a findings manager, an observation store and an evidence
engine for the HTTP API, and then `ScanEngine` built **a second set of its own**.
Nothing connected them. The consequences:

- `GET /scans/{id}/observations` returned an empty list for every scan.
- `GET /findings/{id}/evidence` returned an empty list for every finding.
- `stats.evidence_total` was always `0`; `stats.observations_total` was
  hardcoded `0`.
- `create_scan` papered over part of it with a manual loop that copied every
  finding out of the engine's manager into the API's after each scan — and
  because the engine's manager is not filtered per scan, that loop also copied
  findings belonging to *other* scans on every completion. Its failures were
  discarded with `let _ =`.

**Fixed by making the components shared rather than duplicated.** `FindingsManager`
and `ObservationStore` now have blanket impls for `Arc<T>`, so one store can be
handed to several owners. `ScanEngine::new_with_shared_components` takes the
caller's handles, and `ScanEngine.evidence_engine` is an `Arc` so the API can read
the evidence the engine captures. The manual copy loop is deleted.

**A second, independent bug surfaced only at runtime.** After sharing, the
observations endpoint was *still* empty. The engine recorded every observation's
`scan_id` as `plan.target.id`, while the endpoint queried by the *scan* id — a
field named for one thing, holding another, queried as a third. Neither the type
system nor any unit test could see it; only running a scan and reading the
response did.

`ScanPlan` now carries a required `scan_id`, and the engine attributes
observations to `plan.scan_id`. The field is required rather than derived
precisely so the mismatch becomes a compile error: all four call sites (API, CLI,
worker, engine tests) had to be updated, and the API now passes the scan id it had
already minted.

**Verified at runtime.** A scan against a local server now returns
`observations_total: 6`, `evidence_total: 2`, six observations from
`/scans/{id}/observations`, and one `ScannerOutput` evidence record per finding.
Before: `0`, `0`, empty list, empty list.

7 new tests, including that sharing works in **both** directions. The
split-brain was reintroduced deliberately as a mutation to confirm the tests fail
when it is present: 5 of them do.

`stats.observations_total` needed a whole-inventory count, which has no home on
the `ObservationStore` trait (`count` is per-scan). It is an inherent method on
`InMemoryObservationStore` for now, with a note that a persistent backend will need
a real trait-level `count_all`.

---

## Appendix — audit commands

All findings are reproducible:

```bash
# A1 — dead crates (expect 0 for each)
for c in storage events plugins; do
  echo -n "spectra-$c: "
  grep -rl "spectra_$c\b" --include=*.rs crates apps | grep -v "^crates/$c/" | wc -l
done

# A2 — unused internal deps
for c in crates/*/Cargo.toml apps/*/Cargo.toml; do d=$(dirname $c)
  grep -oP '^(spectra-[a-z]+) = ' $c | tr -d ' =' | while read dep; do
    grep -rq "\b$(echo $dep | tr - _)\b" $d/src/ || echo "  $d: $dep UNUSED"
  done; done

# A3 — MSRV
cargo +1.75.0 build --workspace   # fails: edition2024

# A5 — correlation never executed
grep -rn "correlation_engine\." --include=*.rs crates apps | grep -v "fn correlation_engine"

# A7 — dead code markers
grep -rn "allow(dead_code)" --include=*.rs crates apps

# A8 — placeholders (expect 0 for all)
grep -rn "todo!\|unimplemented!\|FIXME\|TODO" --include=*.rs crates apps

# observations_total hardcoded
grep -n "observations_total: 0" apps/api/src/main.rs
```


### Remediation 12 — Scan limits accepted, displayed, and ignored

`ScanPlan` carries `max_depth`, `max_pages` and `timeout_secs`. `POST /api/v1/scans`
accepts all three from the request body. A `scanner`-role user sees them echoed
back in `GET /scans/{id}`. **The engine never read any of them.** They were read
only by three assertions in a unit test.

What a scan actually did instead:

- Built `CrawlerConfig::default()` — depth 10, **10,000 pages**, 100ms delay.
- Never enforced `timeout_secs` at all.

So `max_pages: 1` crawled up to 10,000 pages, `max_depth: 1` crawled to depth 10,
and `timeout_secs: 5` ran indefinitely. Two distinct problems:

1. **A contract violation.** The fields are accepted, validated and echoed. A caller
   reading the scan back has no way to tell they were decorative.
2. **Resource exhaustion reachable by a non-admin.** `ScansExecute` is held by the
   `scanner` and `manager` roles, so any authenticated non-admin could launch
   unbounded crawls of a site of their choosing. `ResourceGovernor` is constructed
   in `AppState` and never called, so there was no concurrency bound either.

**Fixed by honouring the limits, with an operator ceiling above them.** The naive
fix — read `plan.max_pages` — would have converted a decorative field into a
caller-controlled one. So the two are kept separate:

- `ScanLimits` (engine) holds the **operator's** ceilings, built from config.
- `ScanPlan` holds the **caller's** request.
- `ScanEngine::run_scan` clamps: `min(caller, ceiling)`, with `0` meaning "no
  preference" and therefore taking the ceiling.

`0` matters. The API treats `max_pages: Some(0)` as a real request; honouring it
literally would produce a scan that crawls nothing and reports no findings — the
exact false-negative shape Remediation 10 removed, reintroduced through a different
door.

The ceilings are settable without a rebuild via `SPECTRA_CRAWLER_MAX_PAGES`,
`SPECTRA_CRAWLER_MAX_DEPTH` and `SPECTRA_SCANNER_DEFAULT_TIMEOUT`. A malformed value
logs and leaves the default: an operator typo should not take the scanner down.

**The timeout produces `Partial`, never `Completed`.** `run_scan` creates the job,
hands it to `run_scan_inner` inside `tokio::time::timeout`, and on expiry keeps the
partial job, records the reason, and returns `Partial`. Splitting the stages out
like this is what makes the timeout report *what it found* rather than discarding
it. A timed-out scan also carries a `report_summary` explaining itself, so the field
is not empty without a reason — every other `Partial` outcome populates it.

**Verified three ways.**

- *Mutation.* Reverting the clamp fails 4 of the new tests. Removing the timeout
  fails the timeout test. Reverting the crawler config to `CrawlerConfig::default()`
  fails 2 more. The env-override mutation fails its test.
- *Runtime, ceiling.* A server configured for 1 page / depth 1 / 3s, asked for
  1,000,000 pages at depth 99 for 86,400s, reports all three reductions to the
  caller and completes the 1-page scan.
- *Runtime, timeout.* Against a listener that accepts connections and never
  replies, the scan stops at the 3s budget, returns `status: "Partial"`, and the
  summary reads *"The target was NOT fully assessed… these are not exhaustive and
  the absence of further findings does not indicate their absence."* Before, this
  scan hung indefinitely.

**Not remediated:** `ResourceGovernor` is still constructed and never called, so
concurrent scans are still unbounded. Per-scan limits are now real, which bounds
each scan but not how many run at once. Tracked under Phase 7.

**A note on testability.** `CrawlerConfig` was previously constructed inline in
`run_scan_inner`, which made the plan-to-crawler mapping unverifiable — and it was
wrong. It is now a free function, `crawler_config_for`, tested directly. The env
overrides were likewise split into `apply_scan_limit_overrides`, parameterised on
the lookup, because reading the real environment from a test would mean either
`std::env::set_var` — which the workspace forbids via `unsafe_code = "forbid"` —
or asserting nothing.

15 new tests.


### Remediation 13 — The resource governor, constructed and never called

`ResourceGovernor` was built in `build_state` and held in `AppState`. Nothing ever
called it. A repository-wide search for `try_acquire` outside the governor's own
tests returned nothing.

This was the second half of the resource story Remediation 12 left open, and it was
worse than "not finished":

- `ScannerConfig.max_concurrent` and `ScannerConfig.rate_limit_per_second` were
  declared, given defaults, serialised, and asserted `> 0` by a test — and read by
  **nothing**. The two fields that would have configured this limiter were inert.
- `ResourceLimits::default()` was hardcoded at the construction site, so the values
  were unreachable by configuration even if something had called it.
- `SECURITY.md` claimed "multi-level rate limiting... token bucket, concurrency
  limiting, hierarchical governance". All three claims were false.

So an authenticated `scanner`-role user could start arbitrarily many scans
concurrently. Remediation 12's per-scan ceilings bound each scan individually and say
nothing about how many run at once.

**The governor had two leaks of its own, found before wiring it.** `try_acquire`
mutated as it went: it consumed a rate-limit token, *then* checked concurrency, and
returned `Err` without refunding. Every rejection against a saturated concurrency limit
burned a token permanently, so a burst of scans silently drained the bucket and began
rejecting callers for the wrong reason. It then took a concurrency slot, *then* checked
queue depth — so a queue-depth rejection permanently burned a slot, halving the
governor's capacity every time the queue filled. That second one is latent rather than
live at the defaults (`max_concurrent` 10 < `max_queue_depth` 1000, so the queue check
cannot fail before the concurrency check does), but it is a trap for anyone who
configures a queue depth below concurrency.

`try_acquire` is now transactional: all three limits are checked against a single
consistent view, and state is mutated only once all of them pass. `TokenBucket` gained
`can_consume`/`consume` for this, because checking and consuming in one step is what
allowed a rejected acquisition to keep what it had taken.

**Wired into scan submission.** The slot is acquired *before* the job is created, so a
refusal leaves nothing behind — a client retrying does not accumulate phantom scans in
`GET /scans`. Refusals are `429` with `code: "RATE_LIMITED"` and a message stating how
many of how many slots are in use. The slot is released when the scan finishes,
including on the engine-error path.

**Ceilings are configurable.** `SPECTRA_SCANNER_MAX_CONCURRENT` and
`SPECTRA_SCANNER_RATE_LIMIT_PER_SECOND` now drive the governor, alongside the three
limits from Remediation 12.

**Verified four ways.**

- *Mutation, the governor.* Restoring the original mutate-as-you-go `try_acquire`
  fails the token-leak and slot-leak tests. Both were rewritten after the first version
  failed to discriminate — one asserted the wrong availability count, the other inferred
  the leak indirectly through a release and so passed either way. Both now inspect the
  concurrency limiter directly.
- *Mutation, the wiring.* Removing the `try_acquire` call fails 3 API tests. Removing
  only the `release()` call fails exactly the release test, so acquire and release are
  covered independently rather than one masking the other.
- *Runtime.* With a ceiling of 2, four submissions give `200, 200, 429, 429` and
  `GET /scans` reports exactly 2. After a one-second per-scan budget elapses, the next
  submission returns `200` — the slots came back.
- *Config.* A test asserts the governor's ceilings come from config (3 / 17), not from
  `ResourceLimits::default()`.

**Known limits of this approach, stated rather than papered over.** A slot is released
on every non-panic exit. If the spawned task panics, the slot is leaked permanently,
because a `Drop` guard cannot await. `run_scan` is not expected to panic, and a
panic there is a bug in its own right, but the failure mode is a slow wedge rather than
a crash. A panic-safe version needs an abort-safe handle on the limiter.

Also still open: there is no per-caller cap on scans over time, only on concurrency, so
a caller can queue work indefinitely. `HierarchicalGovernor` — the 5-tier
org/project/target/scan/API limiter — is still never constructed.

14 new tests (7 governance, 2 config, 4 API, 1 elsewhere).


### Remediation 14 — The dead-crate decision

Three crates were fully implemented, tested, and referenced by nothing. This had
blocked Phase 1, because architecture documentation cannot describe a subsystem
whose relationship to the rest of the system is undefined. Rather than defer the
call a fourth time, it was made on evidence.

They are not one case, and treating them as one would have been the mistake.

#### `spectra-events` — wired

616 LOC, 14 tests, a working `broadcast` bus and a taxonomy that maps directly onto
what the engine already knows. The engine was the one component that knew every scan
transition and communicated none of it: the API read `ScanStatus` back out of the job
map after the fact, and nothing outside the process could observe a scan at all.
Emitting an event is a side effect that cannot break a scan if done wrong. Low risk,
clear value, and it is what `s.txt` Phase 22 wants as the backbone for observability.

**The taxonomy was missing a state, and adding it was the substantive part.**
`EventType` offered `ScanCompleted` and `ScanFailed`, so a scan that found findings
but did not assess the target had to be reported as one or the other — and the wrong
choice is `ScanCompleted`. That is the exact false-success shape Remediation 10
removed from the scan API, reappearing on a channel that bypasses the API and that
nobody was watching. `ScanPartial` now exists as both an `EventType` and an
`EventPayload`, carrying a reason so a subscriber can act rather than reconstruct.

The mapping is one function, `terminal_event`, because it is the part that must not
drift. Three statuses in, three distinct events out, and no path where an unassessed
scan is announced as complete. `ScanCompleted` is reserved for `ScanStatus::Completed`.

Wired into the API with a `ScanLifecycleAudit` handler that writes each transition to
the audit trail. Without a subscriber `publish` logs a warning on every event, so an
attached-but-unconsumed bus would be noisier than none.

**Verified.** Publishing `ScanCompleted` for a `Partial` job fails 4 tests. Removing
the terminal emit fails the one-terminal-event test. Mutating the audit handler to
record a partial as completed fails the scan-id test. At runtime the bus logs
`ScanStarted` then `ScanFailed` for a target that reaches nothing, with no
"no active subscribers" warning.

**Still missing for Phase 22:** `Event` has no `correlation_id`, `causation_id` or
`version`, all three of which Phase 22 lists explicitly. And only the four scan events
are emitted; target, asset, finding, evidence, verification and observation events are
still unemitted. Phase 22 is unblocked, not complete.

#### `spectra-plugins` and `spectra-sandbox` — held, and why that is not fence-sitting

This is the important half, and the reason it is not simply "wire them" is that
`spectra-sandbox` is actively dangerous under its own name.

`LocalSandbox` spawns a real subprocess with `tokio::process::Command` inside the
calling process. The child inherits the server's uid, filesystem access, network
access and environment. It is a process launcher with an audit log.

Of the six fields on `ResourceLimits`, how many are enforced while a subprocess runs:

| Field | Enforced? |
|---|---|
| `max_memory_bytes` | No — never read outside constructors and tests; `memory_used_bytes` is hardcoded `0` |
| `max_disk_bytes` | No — never read at all outside its definition |
| `max_network_connections` | No — never read outside constructors and tests |
| `allowed_hosts` / `blocked_hosts` | No — `is_host_allowed` is called only from tests |
| `max_cpu_time_ms` | Measured *after the fact* |

The CPU limit is the sharpest illustration. `execute` awaits `cmd.output()` to
completion and only then compares the elapsed duration, so a subprocess that runs
forever is reported as `Timeout` once it *eventually exits* — after having already
consumed everything it wanted, filled the disk, and exhausted memory.

`sandbox` is also not a Phase 25 implementation. Phase 25 asks for WASM with
capability-based permissions; this is a subprocess runner. And wiring `plugins` to it
would do precisely what `s.txt` Phase 26 forbids in its own words: "Never embed
arbitrary Python execution directly into the main API process." The type is called
`Sandbox`, so a reader would reasonably believe the opposite of what happens.

A plugin host built on this crate would execute third-party code with the server's
full privileges while the type names implied containment. That is strictly worse than
having no plugin system, because it looks protected.

**Contained rather than deleted.** Deleting 1,363 LOC and 47 tests is the maintainers'
call, not a mechanical one — and Phase 0's brief was explicitly to establish the
actual state *before* deleting or replacing anything. So the information is now at
the point of use instead of in an audit document nobody opens: both crates carry
module-level documentation stating what they do not enforce, in a table, with the
`max_cpu_time_ms` behaviour spelled out.

**Recommendation on `s.txt` Phases 24–26.** Drop or explicitly defer them. The
motivation is sound — running untrusted code safely does need a real sandbox — but a
WASM runtime with fuel and memory limits plus a Python runner behind an IPC boundary
is a large security-critical subsystem with no first-party consumers, because Spectra
has no third-party plugins. Building it now would mean building an isolation boundary
for hypothetical plugins, and the in-repo alternative (`sandbox`) is the one design
that looks right and is not.

If plugins are ever wanted, Phase 25 done properly is the entry point; Phase 24 and 26
follow from it. Phase 22 is now unblocked and should come first regardless, since
observability benefits every other phase.

14 new tests (5 engine events, 4 engine terminal-mapping, 3 API audit, plus the 2
config ones from Remediation 13).
