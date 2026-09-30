# ADR-014: An Unresolvable Scanner Name Is a Coverage Claim, Not a Silently Dropped String

## Status

Accepted

## Context

`POST /api/v1/scans` accepts `scanners: Option<Vec<String>>`. The API passed it
straight into `ScanPlan::with_scanners` with no validation, and the engine resolved
names with a `match` whose fallback arm was empty:

```rust
"cors" => scanners.push(Box::new(spectra_scanner::CorsScanner::new())),
_ => {}
```

A name that matched nothing therefore disappeared without a trace. The scan continued
to the report, `resolve_status()` found no coverage gaps and no lost coverage, and
returned `Completed` with a report rendering `Total: 0`.

**So `{"scanners": ["sqli"]}` produced a clean bill of health for a target that no
scanner had looked at.** `sqli` is not a typo invented for this argument — it is one
of the CLI's own documented short aliases, and the CLI translates it before the engine
sees it. The API has no such translation, so a caller copying a name from the CLI's
help text gets a scan that tests nothing.

This is the most damaging output a security tool can produce, because it is
indistinguishable from the output that means "I looked and found nothing".

There was also a test. `create_scanners_filters` asserted `scanners.len() == 2` for a
request naming three scanners, one of which was `"unknown_scanner"`. **That test
enshrined the silent drop as intended behaviour** — it read as a filter test, and it
would have failed if the engine had started reporting the unknown name. A test written
from the same reading of the code as the bug is worse than no test, because it
actively resists the fix.

## Decision

Three changes, because there are three distinct places the information was lost.

**1. `available_scanners()` is the single source of truth.** `ScanPlan::new` derives
its default list from it, and the API validates against it. Previously the nine names
were written out twice — once as the plan default, once as the `match` — which is
exactly the kind of duplication that drifts.

**2. The API refuses an unrecognised name** with `400`, `code: "UNKNOWN_SCANNER"`,
listing the valid names. A caller is better served by being told the valid set than by
discovering the problem in a report afterwards. A test asserts every name in
`available_scanners()` passes validation, so the validation cannot reject real
scanners.

**3. The engine records the consequence, using ADR-009's existing grammar.**

| Situation | Recorded | Status |
|---|---|---|
| All requested names resolved | nothing | `Completed` |
| Some resolved | `record_lost_coverage` | `Partial` |
| None resolved, or none requested | `record_coverage_gap` | `Failed` |

`create_scanners` now returns `(Vec<Box<dyn Scanner>>, Vec<String>)` instead of
dropping the tail of the match, and a free function
`record_scanner_selection_coverage(&mut ScanJob, requested, unresolved)` applies the
rule. It is a free function over `&mut ScanJob` so the decision is testable without a
network, a target or a running scan.

## Consequences

- `{"scanners": ["typo"]}` is a `400`, not a scan.
- `{"scanners": []}` runs the crawl and fingerprint stages and reports `Failed` with
  the reason. It is a legitimate request for reconnaissance, but it is not a
  vulnerability assessment and the report must not read as one.
- The engine alone, without the API in front of it, still records the coverage loss —
  so a CLI, worker or future caller that reaches the engine directly cannot
  reintroduce the false negative by skipping validation.
- `create_scanners_filters` was rewritten rather than supplemented. Its original
  assertion was wrong about intended behaviour, not merely incomplete.
- The API now needs `spectra_engine::available_scanners()`. It already depended on
  `spectra-engine`; this is a function, not a new dependency.

## Known limit, unchanged

The nine names are still a `match` inside the engine. Adding a scanner requires
editing `crates/engine/src/lib.rs`, and scanners cannot be discovered at runtime. The
scanner crate is replaceable behind `Box<dyn Scanner>`, but the set is fixed at
compile time by a different crate. Recorded in `execution.md`.

## Verification

The first attempt at testing this **passed a mutation**, which is why the coverage
decision was extracted into a pure function. A test that asserted only the length
returned by `create_scanners` stayed green while the engine still reported
`Completed` over an unscanned target — it was testing the plumbing, not the decision.

Five mutations were applied and each is caught by the intended test:

| Mutation | Caught by |
|---|---|
| Always treat an unresolvable selection as a total gap | `a_scan_where_some_scanners_ran_is_partial_not_failed` |
| Never treat it as a total gap | `a_scan_where_no_scanner_ran_is_failed_not_completed` |
| Drop the empty-request gap | `requesting_no_scanners_is_a_coverage_gap` |
| Downgrade the record to a plain error | `a_scan_where_some_scanners_ran_is_partial_not_failed` |
| Record the gap only when exactly one name was requested | `requesting_no_scanners_is_a_coverage_gap` |
| Skip the API validation | `an_unknown_scanner_name_is_rejected_rather_than_silently_dropped` |
| Return `unresolved` as empty | `an_unknown_scanner_name_is_reported_rather_than_dropped` |

The `a_fully_resolved_selection_records_no_coverage_loss` test guards the opposite
failure: if the normal path recorded anything, every ordinary scan would be reported
`Partial`.
