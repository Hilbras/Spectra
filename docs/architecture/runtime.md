# Runtime

**Status:** current behaviour.

## Process lifecycle

`spectra-api` is the only binary that matters today. Startup order:

1. Load configuration, then apply environment overrides.
2. `JwtConfig::from_env()`. **If the signing key is absent or shorter than 32 bytes,
   the process exits.** It does not fall back to a default.
3. `UserStore::bootstrap()`. Uses `SPECTRA_ADMIN_PASSWORD`, or generates a 256-bit
   password and writes it to a `0600` file.
4. `build_state()` — builds the shared stores, the engine, the governor, the event bus
   and its audit handler.
5. `resolve_static_dir()` — `SPECTRA_STATIC_DIR` if set, else
   `$CARGO_MANIFEST_DIR/static` for local development. A missing directory is logged
   as an error and returned anyway, so the API starts and the dashboard 404s. The
   server does not refuse to boot over a missing dashboard, which is the right call
   for a missing frontend.

Steps 2 and 3 are deliberate refusals. A server that starts with a guessable signing
key or a known admin password is more dangerous than one that does not start, because
the failure is silent and the compromise is not. Step 5 is the opposite choice, and
deliberately so: a missing dashboard is a cosmetic failure, and failing to boot would
turn it into an outage.

### The dashboard path

`resolve_static_dir` used to use `env!("CARGO_MANIFEST_DIR")` **only**. That is a
*compile-time* constant — the build machine's directory, baked into the binary. In a
runtime container it does not exist, so every request to `/` returned 404 and the only
symptom was a blank page with no error anywhere.

`SPECTRA_STATIC_DIR` now takes priority, and the Dockerfile sets it to
`/opt/spectra/static`. The compile-time path remains as the development fallback,
which is what it is actually good for.

## Configuration

Configuration comes from a TOML file if present, then environment variables override
it. Overrides are applied by `apply_env_overrides`, which delegates the resource
ceilings to `apply_scan_limit_overrides`.

`apply_scan_limit_overrides` takes a lookup closure rather than reading the
environment directly. That is not stylistic: the workspace sets
`unsafe_code = "forbid"` (ADR-002), so `std::env::set_var` cannot be called from a
test, and it would race other tests in the same process if it could. Injecting the
lookup makes the precedence and the malformed-value behaviour directly testable.

A malformed value logs a warning and leaves the default. An operator typo should not
take the scanner down.

### Variables that change security posture

| Variable | Default | Effect if changed |
|---|---|---|
| `SPECTRA_JWT_SECRET` | none | Below 32 bytes the server will not start |
| `SPECTRA_ADMIN_PASSWORD` | generated | Fixed password at first boot |
| `SPECTRA_ALLOW_INTERNAL_TARGETS` | `false` | `true` re-opens SSRF against the scanner |
| `SPECTRA_CORS_ORIGINS` | unset | Unset means no cross-origin access; `*` is rejected |
| `SPECTRA_CRAWLER_MAX_PAGES` | 10,000 | Ceiling on one scan |
| `SPECTRA_CRAWLER_MAX_DEPTH` | 10 | Ceiling on one scan |
| `SPECTRA_SCANNER_DEFAULT_TIMEOUT` | 300 | Ceiling on one scan |
| `SPECTRA_SCANNER_MAX_CONCURRENT` | 10 | Concurrent scan ceiling |
| `SPECTRA_SCANNER_RATE_LIMIT_PER_SECOND` | 50 | Submission rate |
| `SPECTRA_STATIC_DIR` | `$CARGO_MANIFEST_DIR/static` | Where the dashboard is served from |

`SPECTRA_ALLOW_INTERNAL_TARGETS` is the one to be most careful with: `POST /api/v1/scans`
makes the server fetch a caller-chosen URL, so enabling this lets a caller reach
loopback, private networks and cloud metadata.

## Resource governance

`ResourceGovernor` bounds scan submission on two axes: a token bucket
(`rate_limit_per_second`) and a concurrency semaphore (`max_concurrent`). Both limits
are checked before any state is mutated, so a rejection changes nothing. This was not
always true — see `docs/audit/PHASE_0_AUDIT.md`, Remediation 13.

A scan's slot is released when the scan finishes, including when the engine returns an
error. A rejected submission is refused **before** the job is created.

One limit on this design: a slot is released on every non-panic exit. If the spawned
task panics, the slot leaks permanently, because a `Drop` guard cannot await. That is
a slow wedge rather than a crash, and `run_scan` is not expected to panic — but the
failure mode exists and fixing it needs an abort-safe handle on the limiter.

## What a scan costs

Defaults, for a target the scanner can reach:

| Resource | Bound |
|---|---|
| Pages fetched | 10,000 |
| Crawl depth | 10 |
| Wall clock | 300s |
| Concurrent scans | 10 |
| Delay between requests | 100ms (`CrawlerConfig::default`) |
| Concurrency within one crawl | 10 |
| Per-request timeout | 30s (`CrawlPolicy::default`) |
| Redirects followed | 10 |
| User agent | `Spectra/0.1.0` |

At the defaults a single scan is a polite crawler. The 100ms delay and `max_pages` are
`CrawlerConfig` fields the plan does not control, so an operator who needs a faster
scan edits `CrawlerConfig::default()` in source rather than configuration. That is a
real gap: **the inter-request delay and per-crawl concurrency are not operator
tunable.**

A scan that overruns its budget is stopped and reported `Partial` — not left running,
and not reported as `Completed`.

**`respect_robots` is not among these bounds, because it is not one.**
`CrawlerConfig.respect_robots` defaults to `true` and `Crawler::crawl` never reads it.
A complete `RobotsTxt` parser sits unused in `crates/crawler/src/robots.rs`. Spectra
fetches paths a site's `robots.txt` disallows while its configuration states that it
respects it. See [`security.md`](security.md) and A20 in the audit.

## Failure modes and what is reported

| Situation | Status | Reported |
|---|---|---|
| Target unreachable, no pages retrieved | `Failed` | Coverage gap naming the attempt count |
| Timeout | `Partial` | The budget, and that findings are not exhaustive |
| Some pages lost, others retrieved | `Partial` | Each lost URL's reason |
| One URL of many fails | `Completed` | Recorded as an error, no status effect |
| Engine returns `Err` | `Failed` | The engine error |
| Caller requests over a ceiling | — | `429 RATE_LIMITED` before any job exists |

The third and fourth rows are the distinction that matters: a crawl losing one page of
three hundred is routine and must not be reported as partial, while a crawl that
retrieved something but lost a stage is.

## Not implemented

- No graceful shutdown. In-flight scans are dropped when the process exits.
- **The health check reports the process, not the system.** `GET /api/v1/health`
  returns uptime and three component entries, of which `database` and `redis` are
  hardcoded to `status: "unknown", message: "Not configured"`. It cannot report a
  degraded system, because there is no system to degrade — nothing is connected.
- **The readiness check is unconditional.** `GET /api/v1/ready` returns
  `{ ready: true }` from a literal. It cannot become unready, so it is not a readiness
  signal for a load balancer; it is an endpoint that always says yes.
- No metrics endpoint. `spectra-telemetry` is 86 LOC and sets up tracing only.
