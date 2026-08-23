# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.0.5   | ✅ Current         |
| < 0.0.5 | ❌ Unsupported     |

## Reporting a Vulnerability

We take the security of Spectra seriously. If you discover a security vulnerability, please report it responsibly.

**Do not open a public GitHub issue.**

Instead, report vulnerabilities through one of these channels:

- GitHub Security Advisories: https://github.com/Hilbras/spectra/security/advisories/new
- Email: [security contact — to be configured]

## What to Include

When reporting a vulnerability, please include:

1. A clear description of the issue
2. Steps to reproduce
3. Potential impact
4. Suggested fix (if any)

## Expected Response

- We aim to acknowledge receipt within 48 hours
- Initial assessment within 1 week
- We will work with you to develop a fix before public disclosure
- Credit will be given to reporters (unless anonymity is requested)

## Scope

This policy covers security issues in Spectra itself, including:

- Tool execution policy bypass
- Sandbox escape
- Secret leakage in reports or logs
- Prompt injection via repository content
- Cross-tenant data leakage (multi-tenant deployments)

Issues in projects analyzed by Spectra should be reported to the maintainers of those projects.
