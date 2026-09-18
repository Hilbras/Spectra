# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
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

## Authentication & Authorization

Spectra v0.1.0 does not include built-in authentication. If deployed publicly, you must provide authentication at the network level (reverse proxy, firewall, etc.).

## Scope Enforcement

All scan targets must pass through scope validation. Spectra should never scan targets outside the authorized scope. If you find a scope bypass, report it immediately.

## Credential Handling

Credentials are stored encrypted at rest. Never commit credentials to version control. Use environment variables or encrypted configuration files.

## Dependencies

We use `cargo audit` to check for known vulnerabilities in Rust dependencies. Run regularly:

```bash
cargo install cargo-audit
cargo audit
```

## Plugin Security

Plugins run in a sandboxed environment with resource limits. If you discover a sandbox escape, report it immediately.
