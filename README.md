# Hilbras Spectra

**AI Security Research & Validation Engine**

A single-agent autonomous security research engine that analyzes software projects, discovers security hypotheses, investigates them using deterministic tooling, safely validates findings in isolated environments, collects evidence, and produces traceable security reports.

[![npm version](https://img.shields.io/badge/npm-v0.0.6-blue)](https://www.npmjs.com/package/@hilbras/spectra)
[![TypeScript](https://img.shields.io/badge/typescript-%23007ACC.svg)](https://www.typescriptlang.org/)
[![Node.js](https://img.shields.io/badge/node-%3E%3D20-brightgreen)](https://nodejs.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

---

## Overview

Spectra is not a vulnerability scanner. It is an **AI security researcher** that understands your project, forms hypotheses about security weaknesses, investigates them with deterministic tools, validates findings in controlled sandboxes, and produces evidence-backed reports.

The core principle:

> **Discover → Reason → Investigate → Validate → Prove → Report**

---

## Installation

```bash
# Install globally for CLI access
npm install -g @hilbras/spectra

# Or use locally
npm install @hilbras/spectra
```

Requires Node.js ≥ 20 and TypeScript ≥ 5.

---

## Usage

### Interactive Terminal UI

Launch the full-screen TUI for guided investigations:

```bash
spectra ui
```

Navigate with keyboard:
- `↑` / `↓` — move between items
- `Enter` — confirm selection
- `Esc` / `q` — go back or quit

Screens available:
| Screen | What it does |
|--------|-------------|
| **Audit Project** | Select a project, choose depth (quick/full), watch live investigation |
| **View Findings** | Browse past audits with severity breakdowns |
| **Projects** | Add/remove saved project profiles, re-audit from list |
| **Settings** | Cycle report format, approval thresholds, model defaults |

### CLI Commands

```bash
# Run a security audit
spectra audit ./my-project

# Quick scan (20 iterations, faster)
spectra audit ./my-project -d quick

# Full scan (50 iterations, thorough)
spectra audit ./my-project -d full

# Dry-run — plan only, no tools executed
spectra audit ./my-project --dry-run

# Output formats
spectra audit ./my-project -f json    # JSON (default)
spectra audit ./my-project -f sarif   # SARIF 2.1 for CI/CD
spectra audit ./my-project -f markdown # Human-readable report

# Write report to file
spectra audit ./my-project -o report.sarif

# Quiet mode (CI-friendly, no progress output)
spectra audit ./my-project -q

# See all commands
spectra --help
```

### CLI Reference

| Command | Description |
|---------|-------------|
| `spectra audit <target> [options]` | Run security investigation |
| `spectra report <id> [options]` | Generate report from saved data |
| `spectra findings [options]` | List findings from recent audits |
| `spectra projects [action] [name] [path]` | Manage project profiles |
| `spectra config [action] [key] [value]` | View/edit configuration |
| `spectra init` | Initialize `~/.spectra/` directory |
| `spectra version` | Show version info |
| `spectra ui` | Launch interactive terminal UI |

### Configuration

Spectra persists settings in `~/.spectra/config.json`:

```json
{
  "defaultModel": "mock",
  "defaultFormat": "json",
  "autoApproveThreshold": "medium",
  "profiles": {
    "my-app": { "path": "/path/to/my-app", "lastAudit": "2026-08-24T..." }
  }
}
```

Add a project profile for one-command audits:
```bash
spectra projects add my-app /path/to/my-app
spectra audit my-app       # runs against saved profile
```

### CI Integration

Spectra exits with code `0` when no high/critical findings are found, and `1` otherwise — perfect for pipelines:

```yaml
# GitHub Actions example
- name: Security Audit
  run: spectra audit ./src -f sarif -o results.sarif || true
- uses: github/codeql-action/upload-sarif@v2
  with:
    sarif_file: results.sarif
```

---

## Programmatic API

```typescript
import {
  HilbrasSecurityRuntime,
  InvestigationController,
  DeterministicMockModel,
  ProjectIndex,
  buildSecurityModel,
  JsonReportFormatter,
} from "@hilbras/spectra";

// Build the runtime
const runtime = new HilbrasSecurityRuntime({
  targetPath: "./my-project",
  authorizationScope: {
    allowedHosts: [],
    allowedServices: [],
    allowedPorts: [],
    allowedEnvironments: ["local"],
    allowedOperations: ["read"],
    restrictions: ["no-host-execution", "no-credential-theft"],
    allowActiveTesting: false,
    allowNetworkAccess: false,
    allowFilesystemWrite: false,
  },
});

// Run autonomous investigation
const controller = new InvestigationController({
  runtime,
  model: new DeterministicMockModel([]), // swap for real AI model in production
  maxIterations: 50,
});

const result = await controller.run();
console.log(result.investigation.findings);
console.log(result.events);

// Generate reports
const jsonReport = new JsonReportFormatter().generate(result.investigation, result.investigation.findings);
```

---

## Architecture

```
                    Hilbras Spectra
                          │
                          ▼
              Security Investigation Runtime
                          │
           ┌──────────────┼──────────────┐
           ▼              ▼              ▼
     ProjectIndex       AI Engine    Investigation State
           │              │              │
           └──────────────┼──────────────┘
                          ▼
                    Policy Engine
                          │
                          ▼
                    Tool Dispatcher
                          │
         ┌────────────────┼────────────────┐
         ▼                ▼                ▼
   Code Analysis      Security Tools    Validation
           │              │                │
           └──────────────┼────────────────┘
                          ▼
                       Evidence
                          │
                          ▼
                       Findings
                          │
                          ▼
                     Reports
```

**One AI brain. Deterministic tools. Policy-gated execution.**

---

## Current Capabilities

### Project Intelligence
- Repository indexing (files, languages, frameworks)
- Symbol discovery (functions, classes, imports)
- Route discovery (Express, Fastify patterns)
- Dependency analysis with CVE classification
- Secret detection (pattern + entropy analysis)

### Security Analysis
- Taint analysis (source-to-sink tracing within files)
- Command injection sink detection
- Configuration analysis (Docker, CI, env, CORS, TLS)
- API endpoint inspection with auth annotation

### Investigation
- Single-agent AI investigation loop
- Structured decision schema (Zod-validated)
- Hypothesis tracking and prioritization
- Evidence collection and masking
- Finding correlation and severity scoring

### Validation & Reporting
- Isolated sandbox execution (Docker-first, process fallback)
- JSON, SARIF 2.1, and Markdown report generation
- Policy-controlled tool execution
- Secret value masking in all outputs

### Terminal UI (`spectra ui`)
- Full-screen interactive keyboard interface
- Live audit progress with phase indicators
- Findings browser with severity filtering
- Persistent project profiles and settings

---

## Security Model

Spectra enforces strict security boundaries:

- **Policy-controlled tools** — every tool call passes through a permission gate before execution
- **Authorized target scope** — active testing only against explicitly authorized hosts, ports, and services
- **Read-only repository analysis** — passive tools never modify the target project
- **Isolated validation** — active tests run inside disposable Docker containers (or sandboxed processes when Docker is unavailable)
- **Secret masking** — detected credentials are masked in all outputs (`sk_live_****`)
- **Evidence tracking** — every finding is linked to immutable evidence records
- **Untrusted repository content** — READMEs, comments, and source strings are treated as data, never as instructions to the AI

---

## Benchmarks

Five intentionally vulnerable fixture projects cover regression testing:

| Fixture | Vulnerability Type | CWE |
|---|---|---|
| `sql-injection` | SQL injection via string concatenation | CWE-89 |
| `xss` | Reflected/stored XSS via template literals | CWE-79 |
| `command-injection` | OS command injection via `execSync` | CWE-78 |
| `path-traversal` | Directory traversal via unsanitized paths | CWE-22 |
| `idor` | Broken object-level authorization | CWE-639 |

Run benchmarks:

```bash
npm test
```

---

## Known Limitations

- **AST analysis**: Regex-based parser; not a full TypeScript compiler API integration (in progress)
- **Taint analysis**: Intra-file only; cross-function data-flow tracing is not yet implemented
- **Dependency CVE database**: Embedded known-vulnerabilities list covers common packages; does not query live CVE feeds
- **Route discovery**: Detects Express/Fastify patterns; GraphQL, gRPC, and WebSocket routes require explicit configuration
- **Language support**: TypeScript and JavaScript analysis is primary; Python, Go, and Rust analysis is planned
- **Sandbox**: Requires Docker for production isolation; falls back to process-limited execution in development

---

## Roadmap

- [x] Investigation runtime
- [x] Project intelligence layer
- [x] Security tooling (taint, secrets, config, deps)
- [x] Evidence system
- [x] Finding correlation & severity engine
- [x] JSON / SARIF / Markdown reporting
- [x] Single-agent AI investigation controller
- [x] Deterministic mock model for testing
- [x] Benchmark fixtures
- [x] Production CLI (commander, profiles, CI exit codes)
- [x] Interactive Terminal UI (`spectra ui`)
- [ ] Advanced AST analysis (TS compiler API)
- [ ] Interprocedural data-flow analysis
- [ ] Expanded language support (Python, Go, Rust)
- [ ] Live CVE feed integration
- [ ] Checkpoint/persistence for long-running audits
- [ ] Real AI model adapters (OpenAI, Anthropic, Ollama)

---

## Development

```bash
npm install
npm run build       # Compile TypeScript
npm test            # Run test suite (85 tests)
npm run lint        # Lint source (oxlint)
npm run typecheck   # Type-check without emitting
npm run ui          # Launch interactive TUI
```

---

## Responsible Use

Spectra is intended for **authorized security research, defensive testing, and security validation** of software you own or have explicit permission to test.

Active validation (sandbox execution, HTTP requests) must only be performed against targets you are authorized to test. The policy engine enforces authorization scopes, but users are responsible for configuring them correctly.

---

## License

MIT © Hilbras
