# ADR-008: Separate Caller Intent From Operator Ceilings

## Status

Accepted

## Context

`ScanPlan` carries `max_depth`, `max_pages` and `timeout_secs`. `POST /api/v1/scans`
accepts all three in the request body and `GET /scans/{id}` echoes them back. The
engine read none of them. They were read by three unit-test assertions and nothing
else.

What a scan actually did was build `CrawlerConfig::default()` — depth 10, 10,000
pages, 100ms delay — and enforce no timeout at all.

So `max_pages: 1` crawled up to 10,000 pages and `timeout_secs: 5` ran indefinitely.
Two distinct problems:

1. **Contract violation.** The fields are accepted, validated and echoed. A caller
   reading the scan back has no way to tell they were decorative.
2. **Resource exhaustion by a non-admin.** `ScansExecute` is held by the `scanner` and
   `manager` roles, so any authenticated non-admin could launch unbounded crawls of a
   site of their choosing.

The obvious fix — read `plan.max_pages` — would have converted a decorative field into
a caller-controlled one. A `scanner`-role user could then ask for ten million pages.

## Decision

Two types with two different owners, and a clamp between them.

- **`ScanLimits`** holds the **operator's** ceilings, built from configuration:
  `SPECTRA_CRAWLER_MAX_PAGES`, `SPECTRA_CRAWLER_MAX_DEPTH`,
  `SPECTRA_SCANNER_DEFAULT_TIMEOUT`.
- **`ScanPlan`** holds the **caller's** request.
- **`ScanEngine::run_scan` clamps to `min(caller, ceiling)`.** A caller may narrow a
  scan; only an operator may widen it.

Every reduction is recorded on the job via `record_error` and returned in
`GET /scans/{id}`, so a caller that asked for 1,000,000 pages learns it received
fewer rather than discovering it from a shorter crawl.

A zero is treated as **"no preference"** and takes the ceiling. The API treats
`max_pages: 0` as a real request, and honouring it literally would produce a scan
that crawls nothing and reports no findings — the same false-negative shape
[ADR-009](ADR-009-three-scan-outcomes.md) exists to prevent, re-entering through a
different door.

## Consequences

- A timeout yields `Partial` with the reason recorded, never a hang and never a
  `Completed`. `run_scan` creates the job and passes it into `run_scan_inner` inside
  `tokio::time::timeout`, so an overrunning scan reports what it found instead of
  discarding it.
- The crawl configuration is built from the clamped plan rather than from
  `CrawlerConfig::default()`, which is what actually connects these fields to
  anything.
- `CrawlerConfig`'s `delay_ms` and `concurrent_requests` are **not** controlled by the
  plan and are not operator-tunable. They still come from
  `CrawlerConfig::default()`. Recorded as a gap in `runtime.md`.
- A slot in the governor is released on every non-panic exit. A panic leaks it
  permanently, because a `Drop` guard cannot await.

## Verification

Reverting the clamp fails four tests. Removing the timeout fails the timeout test.
Reverting the crawler configuration to `CrawlerConfig::default()` fails two more. At
runtime a server configured for 1 page / depth 1 / 3s, asked for 1,000,000 pages at
depth 99 for 86,400s, reports all three reductions; and against a listener that accepts
connections and never replies, the scan stops at 3s with `Partial`.
