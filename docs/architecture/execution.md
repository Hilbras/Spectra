# The Scan Pipeline

**Status:** current behaviour, verified against `crates/engine/src/lib.rs`.

## The stages that execute

`ScanEngine::run_scan` clamps the plan, then `run_scan_inner` runs six stages. Line
numbers are from `crates/engine/src/lib.rs` at the commit that introduced the current
shape.

| # | Status set | Stage | Crate |
|---|---|---|---|
| 1 | `Discovering` (:564) | Resolve the target into an asset graph | `spectra-network` |
| 2 | `Crawling` (:706) | Fetch pages, bounded by the clamped plan | `spectra-crawler` |
| 3 | `Fingerprinting` (:771) | Identify technologies from crawled pages | `spectra-fingerprint` |
| 4 | `Scanning` (:809) | Run each requested scanner over the pages | `spectra-scanner` |
| 5 | (no status) | Save findings and capture evidence | `spectra-findings`, `spectra-evidence` |
| 6 | `Correlating` (:916) | `generate_report()` — **not** the correlation engine | `spectra-findings` |

Stage 6 is worth pausing on. The status is named `Correlating`, and a
`CorrelationEngine` exists in `ScanEngine` with a public `correlation_engine()`
accessor — **which is never called from anywhere in the workspace.** What runs at
that point is `FindingsManager::generate_report`, which lists the target's findings
and collects them into a `FindingsReport` (`crates/findings/src/manage.rs:156`).
No correlation between findings happens: nothing groups related findings, ranks them
against each other, or relates them to assets. The stage name describes an intent the
code does not implement.

## The verified graph

```
POST /api/v1/scans
        │
        ├─ ResourceGovernor.try_acquire()          429 if at the ceiling
        │   (rejected here creates no job)
        ▼
  ScanEngine::run_scan
        │
        ├─ ScanLimits::clamp(plan)                 caller ≤ operator ceiling
        ├─ record_error for each reduced limit
        ├─ emit ScanStarted
        │
        └─ tokio::time::timeout(budget, run_scan_inner)
                │
                ├─ 1 Discovering   network_engine.discover()
                ├─ 2 Crawling      crawler.crawl(CrawlerConfig from plan)
                ├─ 3 Fingerprinting
                ├─ 4 Scanning      9 scanners
                ├─ 5 save          findings_manager.save_finding()
                │                   evidence_engine.capture()
                │                   observation_engine.record_with()  → plan.scan_id
                ├─ 6 report        findings_manager.generate_report()
                ├─ resolve_status()            → Completed | Partial | Failed
                ├─ report_summary             rendered with the caveat
                └─ emit terminal event
                                                          │
   timeout fires ──▶ Partial + reason + summary ◀────────┘
                                                          │
                                                          ▼
                                          governor.release()
```

The released slot is why a scan that finishes — including one that fails inside the
engine — does not permanently consume capacity.

## Arrows that do not exist

The prior architecture document described this chain:

```
API → Engine → Scheduler → Worker → Execution → Events → Observation
    → Detection → Finding → Verification → Evidence → Correlation
    → Storage → API/CLI/Web
```

Five arrows in it are not executable code:

| Arrow | Reality |
|---|---|
| `Engine → Scheduler` | The API does not depend on `spectra-scheduler`. Scans run in-process via `tokio::spawn`. `engine` declares the dependency and never imports it. |
| `Worker → Execution` | Nothing calls `enqueue`, so `dequeue()` always returns `None`. The worker binds the in-memory queue, so Redis is unreachable regardless. |
| `→ Detection` | No `DetectionEngine` is constructed or called in the pipeline. `spectra-findings::detection` exists (including `default_rules()`) and is referenced only within its own file. Findings are written directly by scanners, tagged via `ScanEngine::detection_source_for`. |
| `→ Verification` | Zero calls. `VerificationEngine` is constructed at API startup and never populated, so the two verification endpoints are permanently empty. |
| `→ Correlation` | `correlation_engine()` has zero call sites. |
| `→ Storage` | Zero references to `spectra_storage` outside itself. |
| `→ Events` | **Now wired** as of Remediation 14. Was the fifth broken arrow. |

## The three coverage levels

A scan's outcome is decided by what it lost, not by whether it errored. This
distinction is the core of the pipeline's honesty guarantee.

| Level | Recorded by | Means | Status |
|---|---|---|---|
| Error | `record_error` | A step failed but coverage elsewhere survived | no effect |
| Lost coverage | `record_lost_coverage` | A stage gave up; results incomplete | `Partial` |
| Coverage gap | `record_coverage_gap` | Nothing usable was obtained | `Failed` |

A single unreachable URL is an *error*, deliberately: a crawl that loses one of three
hundred pages should not be reported as partial, or every real site would be. A crawl
that retrieves nothing at all is a *coverage gap*, because "0 findings" over an
unreached target is a claim the scan cannot support. A scanner that fails outright is
*lost coverage*, because the target was reachable and a stage gave up.

`resolve_status()` reads `coverage_gaps` first, then `lost_coverage`, so `Failed`
wins over `Partial`. The report summary is rendered **after** the status is resolved,
so the caveat appears above the counts rather than below them.

## Limits

`ScanLimits` is the operator's ceiling; `ScanPlan` is the caller's request;
`run_scan` clamps to `min(caller, ceiling)`. A request may narrow a scan, never widen
it. Each reduction is recorded as an error on the job and returned in
`GET /scans/{id}`, so a caller that asked for 1,000,000 pages learns it got fewer.

A zero is treated as "no preference" and takes the ceiling, because the API treats
`max_pages: 0` as a real request and honouring it literally would produce a scan that
crawls nothing and reports no findings.

See [`runtime.md`](runtime.md) for the configuration surface.

## Target: where the missing stages go

None of this is built. It is recorded so the gap is explicit rather than discovered
again.

- **Detection** should become a stage between scanning and finding, consuming
  scanner output through `DetectionEngine` so rules live in one place instead of
  being distributed across nine scanners.
- **Verification** should run after findings are saved and before the report is
  generated, so the report can state which findings were verified.
- **Correlation** should replace the current `generate_report` call under stage 6,
  which is what the stage name already implies.
- **Persistence** should replace every in-memory store. Until then a scan's results
  exist only in the process that produced them — see [`storage.md`](storage.md).
