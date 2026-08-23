# IDOR / BOLA — Vulnerable Test Project

A mock API service with broken object-level authorization.

## What to Find

| Vulnerability | File | CWE |
|---|---|---|
| No ownership check on resource access | `server.js` | CWE-639 |
| Predictable sequential IDs | `server.js` | CWE-639 |
| No authorization middleware | `server.js` | CWE-862 |

## How to Run

```bash
node server.js
# As user A (token: token-a): GET /api/orders/2  → should be 403, returns order data
```
