# SQL Injection — Vulnerable Test Project

A minimal Express + SQLite project with intentional SQL injection vulnerabilities
for regression testing Hilbras Spectra's injection detection.

## What to Find

| Vulnerability | File | Line | CWE |
|---|---|---|---|
| SQLi in login query | `src/routes/auth.ts` | ~15 | CWE-89 |
| SQLi in user lookup | `src/routes/users.ts` | ~22 | CWE-89 |
| Unparameterized query in search | `src/routes/search.ts` | ~10 | CWE-89 |
| Missing input validation | `src/middleware/validation.ts` | — | CWE-20 |

## How to Run

```bash
npm install
npm run dev
```

## Security Issues

1. **Direct string concatenation in SQL** — user input concatenated directly into query strings
2. **No parameterized queries** — all database calls use raw string interpolation
3. **Missing input sanitization** — no validation middleware on auth routes
4. **Verbose error messages** — SQL errors exposed to clients reveal schema
