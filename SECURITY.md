# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 1.0.x   | Yes       |
| 0.1.x   | Yes       |

## Reporting a Vulnerability

If you discover a security vulnerability in Spectra, please report it responsibly.

**Do NOT open a public GitHub issue for security vulnerabilities.**

Instead, please email: security@spectra.dev (or the project maintainer's email)

Include:
- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

You should receive a response within 48 hours. We will work with you to understand and address the issue before any public disclosure.

## Scope

This security policy applies to:
- The Spectra Rust codebase
- The official npm package
- The API server
- The CLI tool
- The worker process

## Security Features

### Authentication & Authorization

Spectra has built-in authentication and authorization:

- JWT-based authentication with HMAC-SHA256
- Role-based access control (Admin, Manager, Scanner, Viewer)
- 26 granular permissions; the four roles grant 26, 14, 7 and 7 respectively
- Per-method permission checks, declared next to each handler in
  `protected_routes()` in `apps/api/src/main.rs`

Every protected route is declared through the `guarded_route!` macro, which
records the permission a method requires. A route with no guard is visible as
one in review rather than silently defaulting to "any authenticated caller" —
the state this codebase was in, since the permission types existed and were
never called.

Authorization is evaluated against the permissions embedded in the token, which
is the only information available at that point. Two consequences follow: a role
change does not take effect until the token is refreshed, and a token cannot be
revoked before it expires. Both are acceptable while the only account is the one
created at startup. Neither is acceptable once roles become user-assignable; at
that point authorization needs a store lookup rather than a claim.

A role name that is not one of the four built-ins resolves to no permissions and
is logged at login, rather than being treated as unrestricted. A token with an
empty permission list is refused every guarded route.

### Scope Enforcement

All scan targets must pass through scope validation. Spectra should never scan targets outside the authorized scope. Features include:

- Regex pattern matching
- Private IP detection (RFC 1918, loopback, link-local)
- Public IP validation

### SSRF Protection

Spectra includes comprehensive SSRF protection:

- Blocks loopback, private, link-local, and Class E IPs
- URL scheme validation (HTTP/HTTPS only)
- Bypass attempt detection (decimal IP, IPv6-mapped, null bytes)

### Input Validation

All user input is validated:

- Path traversal prevention
- SQL injection protection
- Command injection prevention
- Hostname validation
- Email validation
- JSON prototype pollution detection

### Secrets Management

Secrets are never hardcoded, logged, or returned in API responses:

- Environment-based secret providers
- Automatic redaction in logs and responses
- Constant-time comparison for tokens

### Rate Limiting

Two independent bounds, both active.

**Per-scan budgets.** `SPECTRA_CRAWLER_MAX_PAGES`, `SPECTRA_CRAWLER_MAX_DEPTH` and
`SPECTRA_SCANNER_DEFAULT_TIMEOUT` cap what one scan may consume. A request asking for
more has the excess clamped to the ceiling and the reduction reported in
`GET /scans/{id}` — never applied silently.

**Concurrency and submission rate.** `SPECTRA_SCANNER_MAX_CONCURRENT` (default 10) and
`SPECTRA_SCANNER_RATE_LIMIT_PER_SECOND` (default 50) drive a `ResourceGovernor` in the
scan submission path. `POST /api/v1/scans` acquires a slot before creating the job; a
refusal is `429` with `code: "RATE_LIMITED"` and creates nothing. The slot is released
when the scan finishes, including when the engine returns an error.

Both bounds matter and neither substitutes for the other: a per-scan budget says nothing
about how many scans are running, and a concurrency limit says nothing about how much
work each one does.

What is **not** in effect: `spectra-core` also contains a `HierarchicalGovernor` with
per-organization, per-project, per-target, per-scan and per-API levels. Nothing
constructs it outside its own tests, so those tiers do not exist as far as a request is
concerned. There is also no limit on the number of scans a single caller may start over
time — only on how many run at once.

### Plugin Execution

There is no plugin host. `spectra-plugins` is a registry — a `Plugin` trait, a map of
`Box<dyn Plugin>`, and three example plugins — and nothing in the workspace constructs
it. There is no manifest loading and no dynamic loading.

`spectra-sandbox` must not be used to run untrusted code, despite its name. It spawns
a real subprocess inside the server process, so the child inherits the server's uid,
filesystem access, network access and environment. Of its six `ResourceLimits` fields,
none is enforced during execution except `max_cpu_time_ms`, which is measured *after*
the process exits — so a subprocess that runs forever is reported as a `Timeout` once
it eventually returns, having already consumed whatever it wanted. `allowed_hosts` and
`blocked_hosts` are read only by tests.

Both crates carry module-level documentation stating this. Do not build a plugin host
on them. Running untrusted code needs either a WASM runtime with fuel and memory
limits and an explicit capability set, or a separate process under OS-level isolation
(namespaces, seccomp, cgroups) behind a protocol boundary.

### Evidence Security

Evidence is protected throughout its lifecycle:

- Automatic redaction of sensitive values
- Integrity hashing (SHA-256)
- Audit logging

### Reporting Integrity

A scan result is a security claim, so a scan that did not run is never reported as
a scan that found nothing. Three states are distinguished, and the distinction is
made on what each stage actually produced rather than on whether the run raised
an error:

| Status | Meaning |
|---|---|
| `Completed` | Every stage produced usable output |
| `Partial` | Usable output, but at least one stage lost coverage |
| `Failed` | A stage produced nothing — the findings are not evidence of absence |

Concretely:

- A crawl that retrieves no pages fails the scan, rather than producing an empty
  findings list.
- Crawler and scanner failures are retained with their reason (URL, message) and
  surfaced in `GET /api/v1/scans/{id}` under `errors`.
- `crawl_page_count` is the number of pages **retrieved**, not the number of URLs
  attempted.
- The rendered report carries the failures above the summary block, so the counts
  cannot be quoted without the caveat that qualifies them.

Treat `Completed` with zero findings as the only genuinely reassuring result.
For any other status, absence of a finding is uninformative.

## Credential Handling

Never commit credentials to version control. Spectra reads configuration from
the environment, and **there is no default for any secret** — the server refuses
to start rather than fall back to a shipped value, because a fallback signing
key lets anyone mint an admin token by HMAC-signing their own claims.

All variables are prefixed `SPECTRA_`:

```bash
# Required. The server exits non-zero with a named error if either is missing.
#
# SPECTRA_JWT_SECRET must be at least 32 bytes. Generate one with:
#   openssl rand -base64 48
SPECTRA_JWT_SECRET=<at least 32 bytes>

# Required unless SPECTRA_ADMIN_PASSWORD is set. Minimum 12 characters.
#
# If unset, the server generates a random 32-byte password and writes it once to
# SPECTRA_ADMIN_PASSWORD_FILE (default ~/.spectra/initial-admin-password) with
# 0600 permissions. The path is logged; the password is not.
SPECTRA_ADMIN_PASSWORD=<your password>
SPECTRA_ADMIN_PASSWORD_FILE=/run/spectra/initial-admin-password

# Optional
SPECTRA_DATABASE_URL=postgres://user:pass@host/db
SPECTRA_REDIS_URL=redis://host:6379
SPECTRA_CORS_ORIGINS=https://dashboard.example.com,https://admin.example.com
SPECTRA_STATIC_DIR=/opt/spectra/static
SPECTRA_ALLOW_INTERNAL_TARGETS=false
SPECTRA_JWT_TTL_SECS=3600
```

`JWT_SECRET` is accepted as a deprecated alias for `SPECTRA_JWT_SECRET` and logs
a warning. The unprefixed `DATABASE_URL` and `REDIS_URL` are **not** read.

### What is and is not protected at rest

Stated plainly, because the previous version of this file claimed encryption
that did not exist:

- The **JWT signing secret** lives only in the environment. It is never written
  to disk by Spectra.
- The **initial admin password** is stored as an argon2id hash with a per-user
  random salt, and verified in constant time.
- **User accounts** are held in memory. They do not survive a restart, and they
  are not encrypted at rest, because they are never written to disk. The same
  is true of findings, targets and audit records — see the persistence gap
  tracked in `docs/audit/PHASE_0_AUDIT.md`.

## Access Control

- Passwords are hashed with argon2id, never a bare digest.
- Login failures return one generic message, so the endpoint does not reveal
  whether a username exists.
- Repeated failures lock the client out for 15 minutes after 5 attempts in
  5 minutes. The lockout is per client address and returns `Retry-After`.
- All login outcomes, including failures, are written to the audit log.
- Cross-origin requests are refused unless the origin is in
  `SPECTRA_CORS_ORIGINS`. An unset allowlist permits **no** cross-origin
  browser access; it does not mean "allow all".

## Scanning Safety

A scan makes the server issue outbound requests to a target the caller chose, so
an unvalidated target is a server-side request forgery primitive. Before a scan
starts, the target is checked against a deny list covering loopback, private,
link-local, unspecified and cloud-metadata addresses, the hostnames that denote
them (`localhost`, `metadata.google.internal`, `host.docker.internal`, …), and
— after DNS resolution — every address the hostname actually points at, which
is what stops a public name from resolving to an internal address.

Set `SPECTRA_ALLOW_INTERNAL_TARGETS=true` to permit internal targets. That is
needed to scan internal hosts and it also re-opens SSRF against the scanner
itself, so it is opt-in.

## Plugin Security

There is no plugin sandbox. The `spectra-plugins` crate is not loaded by any
running component, so no plugin code executes and no sandbox is required.

Earlier versions of this file described process isolation, CPU and memory
limits, execution timeouts and syscall filtering for plugins. None of that was
implemented, and none of it is claimed here. If a plugin runtime is added, this
section must be written against the code that exists, not against intent.

## Dependencies

We use `cargo audit` to check for known vulnerabilities in Rust dependencies. Run regularly:

```bash
cargo install cargo-audit
cargo audit
```

## Docker Security

When deploying with Docker:

- The API runs as a non-root user
- Minimal base images (`debian:bookworm-slim`)
- No OpenSSL dependency: `reqwest` uses rustls, matching `sqlx`'s
  `runtime-tokio-rustls`, and CA roots are bundled via `webpki-roots`
- Secrets are supplied through the environment and never baked into the image
- `docker-compose.yml` defines health checks for the API's dependencies

The API exits non-zero with a named error if `SPECTRA_JWT_SECRET` is unset or
under 32 bytes, or if no administrator account can be established. That is
intentional: for a security scanner, starting with a guessable signing key or a
default administrator password is worse than not starting.

## Security Testing

We recommend running security tests regularly:

```bash
# Run all tests
cargo test --workspace

# Security audit
cargo audit

# Clippy with strict warnings
cargo clippy --workspace --all-targets -- -D warnings
```
