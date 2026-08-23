# Path Traversal — Vulnerable Test Project

A file-serving API with directory traversal vulnerabilities.

## What to Find

| Vulnerability | File | CWE |
|---|---|---|
| Filename from user input without sanitization | `src/server.js` | CWE-22 |
| No path canonicalization | `src/server.js` | CWE-22 |
| Directory listing exposed | `src/server.js` | CWE-548 |

## How to Run

```bash
node server.js
# Request: GET /files?name=../../../etc/passwd
```
