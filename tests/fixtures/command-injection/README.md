# Command Injection — Vulnerable Test Project

A minimal Node.js CLI tool with OS command injection vulnerabilities.

## What to Find

| Vulnerability | File | Line | CWE |
|---|---|---|---|
| execSync with user input | `src/generator.ts` | ~10 | CWE-78 |
| spawn with unsanitized args | `src/reporter.ts` | ~15 | CWE-78 |
| eval on config | `src/config-loader.ts` | ~5 | CWE-95 |

## How to Run

```bash
npm install
node dist/generator.js --name "<script>evil</script>"
```
