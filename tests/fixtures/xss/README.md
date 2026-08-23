# XSS — Vulnerable Test Project

A minimal React-ish HTML template injection project with stored and reflected XSS.

## What to Find

| Vulnerability | File | Type | CWE |
|---|---|---|---|
| Reflected XSS in search | `index.html` | Reflected | CWE-79 |
| Stored XSS in comments | `server.js` | Stored | CWE-79 |
| InnerHTML assignment | `app.js` | DOM-based | CWE-79 |
| Unsafe JSONP callback | `server.js` | Reflected | CWE-79 |

## How to Run

```bash
node server.js
# Visit http://localhost:3457/search?q=<script>alert(1)</script>
```
