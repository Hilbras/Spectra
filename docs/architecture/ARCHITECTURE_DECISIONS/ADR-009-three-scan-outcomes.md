# ADR-009: Three Scan Outcomes, Not One Error Count

## Status

Accepted

## Context

`ScanJob` had a single `errors: Vec<String>`. At the end of a scan the engine chose
`Completed` or `Failed` from whether that list was empty.

The consequence was a false-success path with no obvious symptom. A scan whose
crawler reached two of one hundred pages, because the other ninety-eight timed out,
recorded ninety-eight errors and still completed. `GET /scans/{id}` returned
`status: "Completed"` with a report containing two pages' worth of findings. Any
reader — a person, a dashboard, a CI job — would conclude the target had been
assessed.

That is worse than reporting nothing. A partial assessment presented as complete is a
claim the scan cannot support, and it is indistinguishable from a clean result.

The API had a second, related defect. `text_summary` was rendered from findings
before the status was decided, so a caveat about incomplete coverage would have
appeared *below* the counts. The number of findings is the part readers take away;
the reason there were few of them needs to be above it.

## Decision

Coverage is recorded at three levels, and the level determines the status. The API is
`CrawlCoverage` in the engine, with three methods.

| Method | Meaning | Status effect |
|---|---|---|
| `record_error` | A step failed; coverage elsewhere survived | none |
| `record_lost_coverage` | A stage gave up; results are incomplete | `Partial` |
| `record_coverage_gap` | Nothing usable was obtained | `Failed` |

`resolve_status()` reads coverage gaps first, so `Failed` wins over `Partial`.

Two of these distinctions are deliberate and were the ones most likely to be got
wrong:

- **A single unreachable URL is `record_error`, not lost coverage.** A crawl that
  loses one page of three hundred should not be reported as partial, or every real
  site would be — most have a dead link somewhere. The scan still assessed the target
  as well as it could.
- **A scan that retrieved nothing is `record_coverage_gap`.** "0 findings" over an
  unreached target is a false negative, and the most damaging kind: it is a clean
  bill of health for a host that was never contacted.

Lost coverage comes from a scanner failing outright — the target was reachable and a
stage abandoned it — and from the timeout path.

The report summary is rendered **after** `resolve_status()`, so a partial scan's
explanation sits above its counts.

## Consequences

- `ScanStatus::Partial` exists as a distinct outcome. It is not a synonym for
  `Failed` and not a flavour of `Completed`.
- `CrawlResult.errors` is a `Vec<String>` that is never discarded. The earlier code
  dropped it entirely, so a crawl that failed to reach a page reported
  `total_crawled == 0` and no explanation.
- `total_crawled` is `pages.len()` — what was actually retrieved — not a count of
  attempted requests. A success that returned nothing and a request that never
  completed are different, and only the first is a page.
- `text_summary_with_coverage` states that a partial scan did **not** fully assess
  the target, and that the absence of further findings does not indicate their
  absence.
- `ScanStatus::Partial` needed a corresponding event, because an event channel has no
  status field to consult. See [ADR-011](ADR-011-scan-partial-is-its-own-event.md).

## Verification

Twelve tests over the three levels and their precedence. Mutating `record_error` to
`record_lost_coverage` fails the test asserting a one-URL failure completes — the
mutation that would reintroduce the original defect. Reordering `resolve_status` to
read lost coverage first fails the precedence test.

At runtime, against a server with `SPECTRA_ALLOW_INTERNAL_TARGETS=true` and a
`max_pages` of 1 with a one-page target that links to a dead port, the scan
completes; against loopback port 1 with no listener, it fails with a coverage gap.
