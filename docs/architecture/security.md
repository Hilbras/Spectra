# Security Boundaries

**Status:** current behaviour. Where a control is absent it is named as absent.

## Trust boundaries

```
                 ┌──────────────────────────────────────────┐
  untrusted      │  caller (browser, CLI, script)           │
                 └────────────────┬─────────────────────────┘
                                  │ bearer token
                 ┌────────────────▼─────────────────────────┐
  authenticated  │  axum middleware: authenticate, then     │
                 │  per-method permission check             │
                 └────────────────┬─────────────────────────┘
                                  │ validated plan
                 ┌────────────────▼─────────────────────────┐
  outbound       │  SSRF guard — after DNS resolution       │
                 └────────────────┬─────────────────────────┘
                                  │
                 ┌────────────────▼─────────────────────────┐
  target         │  the scanned host                        │
                 └──────────────────────────────────────────┘
```

The fourth boundary is the one with teeth. `POST /api/v1/scans` makes **the server**
fetch a URL the caller chose, which is a server-side request forgery primitive
regardless of how the caller is authenticated.

## Authentication

`JwtConfig::from_env()` reads `SPECTRA_JWT_SECRET` (or the deprecated `JWT_SECRET`)
and requires at least 32 bytes. **There is no default.** The server refuses to start
rather than fall back to a compiled-in key, because a shipped signing key means anyone
can mint an admin token.

The first administrator is created by `UserStore::bootstrap()` from
`SPECTRA_ADMIN_PASSWORD`, or by generating a 256-bit password and writing it to a
`0600` file. No account exists with a known password, and there is no code path that
creates one.

Passwords are hashed with **argon2id** with a per-user `SaltString`.

**Login throttling** — `LoginThrottle` allows five failures per **client address**
within five minutes, then locks that address for fifteen (`LOGIN_MAX_FAILURES`,
`LOGIN_WINDOW_SECS`, `LOGIN_LOCKOUT_SECS` in `apps/api/src/main.rs`).

Two consequences follow from keying on the address, and both are real weaknesses
rather than implementation details:

- **It is bypassable by distribution.** An attacker spreading requests across many
  source addresses gets no lockout, since each address accumulates its own count.
  Per-account throttling would resist this; per-address throttling does not.
- **It can be weaponised against a user.** Anyone who can make requests appear to
  originate from an address a victim uses — a shared NAT gateway, a corporate proxy,
  an office egress IP — can lock that victim out of the API for fifteen minutes per
  attempt, without ever knowing a valid credential.

Failures are audited whether or not the username exists, and every failure mode
returns the same generic message, so the endpoint does not reveal whether an account
exists and the throttle cannot be used to enumerate users.

## Authorisation

Roles are the single source of truth. `UserEntry.permissions` does not exist; a token's
grants are derived at issue time from its roles by `expand_role_permissions`.
`check_permission` reads the **token's grant list**, never the role claim — so a
forged role string cannot grant anything, because the signature check covers the roles
and the grants are computed from them server-side.

Guards are applied per method via `guarded_route!`, because `MethodRouter::merge`
panics if two routes register the same method. This is also the only way to express
the pairing that matters most: `POST /scans` and `GET /scans` need different
permissions, and `viewer` correctly holds the second but not the first.

## CORS

`cors_layer()` builds the policy from `SPECTRA_CORS_ORIGINS`. **An unset allowlist
means no cross-origin access**, not allow-all — which is what an absent configuration
previously produced. `*` is rejected outright: the API authenticates with a bearer
token, and a wildcard lets any origin read authenticated responses.

## SSRF

`validate_resolved_url()` validates **after DNS resolution**, so a hostname pointing at
`169.254.169.254` is refused. It handles decimal, octal and hex IPv4 forms, IPv4-mapped
IPv6 (`::ffff:127.0.0.1`), and the link-local and private ranges. 42 tests.

Scanning internal hosts requires `SPECTRA_ALLOW_INTERNAL_TARGETS=true`, **off by
default**. Enabling it re-opens SSRF by design, and `.env.example` says so at the
variable rather than leaving an operator to infer it.

## Resource bounds

Two independent bounds, both active. Neither substitutes for the other.

| Bound | Configuration | Default |
|---|---|---|
| Per-scan pages | `SPECTRA_CRAWLER_MAX_PAGES` | 10,000 |
| Per-scan depth | `SPECTRA_CRAWLER_MAX_DEPTH` | 10 |
| Per-scan duration | `SPECTRA_SCANNER_DEFAULT_TIMEOUT` | 300s |
| Concurrent scans | `SPECTRA_SCANNER_MAX_CONCURRENT` | 10 |
| Submissions/second | `SPECTRA_SCANNER_RATE_LIMIT_PER_SECOND` | 50 |

A request may **narrow** a scan below the ceiling but never raise it above it, and
every reduction is reported in `GET /scans/{id}` rather than applied silently. A
submission over the concurrency ceiling returns `429` with `code: "RATE_LIMITED"`
**before** the job is created, so a refused request leaves nothing behind.

**Not in effect:** there is no per-caller cap on scans over time — only on how many
run at once, so a caller can queue work indefinitely. The 5-tier
`HierarchicalGovernor` (organization, project, target, scan, API) is never
constructed.

## Reporting integrity

A finding exists to be acted on, so a scan must not imply conclusions it did not reach.

- A scan that retrieved no pages is `Failed`, never `Completed` with zero findings.
- A timed-out scan is `Partial` with the reason and a summary saying the target was
  **not** fully assessed, and that absence of further findings does not indicate their
  absence.
- Every `Partial` outcome carries an explanatory `report_summary`. The field is never
  empty for a scan that ended incomplete, because an empty field renders as a blank
  report with no reason on the field itself.
- Event publishing is not permitted to report a partial scan as `ScanCompleted`.
  `EventType::ScanPartial` exists precisely so that mapping has no lossy branch.

## Not implemented

Named so they are not mistaken for controls:

- **`respect_robots` does nothing.** It defaults to `true` and controls nothing —
  `Crawler::crawl` never reads it, and a working `RobotsTxt` parser in
  `crates/crawler/src/robots.rs` has no call sites. Spectra fetches paths listed under
  `Disallow` while its configuration claims otherwise. See
  [`../audit/PHASE_0_AUDIT.md`](../audit/PHASE_0_AUDIT.md), A20. The fix is a product
  decision: honouring the file would stop the scanner fetching exactly the paths worth
  scanning.
- **No encryption at rest.** Findings, observations and evidence are in memory. A
  previous revision of `SECURITY.md` claimed otherwise; that claim has been removed.
- **No plugin sandbox.** There is no plugin host. See [`plugins.md`](plugins.md).
- **No per-caller scan quota.** Only concurrency.
- **No per-account login throttle.** Throttling is per client address, which is
  bypassable by distribution and usable to lock out a victim behind a shared address.
- **No WAF, no IP allowlist, no mTLS** on the API.
- **Secrets are stored in process environment or an in-memory vault.** `SecretManager`
  wraps `SPECTRA_`-prefixed environment variables; it does not talk to Vault, AWS KMS
  or any external secret store.
