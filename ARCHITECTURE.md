# Hilbras Spectra — Architecture

> Internal design reference for contributors. See [README.md](./README.md) for usage.

---

## System Overview

Spectra is a **single-agent** autonomous security investigation platform. One `InvestigationController` drives the entire loop — no multi-agent coordination. The agent observes project state, reasons about next steps, executes tools through a policy gate, and builds evidence-backed findings.

```
┌─────────────────────────────────────────────────────────┐
│                    Hilbras Spectra                       │
│                                                         │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────┐ │
│  │  ProjectIndex │    │SecurityModel │    │Policies  │ │
│  └──────┬───────┘    └──────┬───────┘    └────┬─────┘ │
│         │                   │                  │       │
│         └───────────────────┼──────────────────┘       │
│                             ▼                          │
│                  ┌─────────────────────┐               │
│                  │ InvestigationState  │               │
│                  │  (immutable, typed) │               │
│                  └──────────┬──────────┘               │
│                             ▼                          │
│                  ┌─────────────────────┐               │
│                  │ InvestigationController│             │
│                  │  observe → reason  │               │
│                  │  → act → update    │               │
│                  └──────────┬──────────┘               │
│                             ▼                          │
│                  ┌─────────────────────┐               │
│                  │  Tool Dispatcher    │               │
│                  │  (14 registered)    │               │
│                  └──────────┬──────────┘               │
│                             ▼                          │
│                  ┌─────────────────────┐               │
│                  │  Report Generators  │               │
│                  │  (JSON/SARIF/MD)    │               │
│                  └─────────────────────┘               │
└─────────────────────────────────────────────────────────┘
```

---

## Core Modules

### 1. Domain Layer (`src/domain/`)

Types and state machine. Immutable by design.

| File | Purpose |
|------|---------|
| `types.ts` | All domain types: Finding, Evidence, Hypothesis, Phase, ToolDefinition, Severity |
| `state.ts` | `InvestigationState` — immutable wrapper around investigation snapshot |
| `ids.ts` | UUID factories for all entity types |

**State machine:** 20 non-linear phases from `INITIALIZATION` to `COMPLETION`. State transitions are validated — invalid transitions throw.

```typescript
type Phase = 
  | "INITIALIZATION" | "RECONNAISSANCE" | "ARCHITECTURE_ANALYSIS" 
  | "ATTACK_SURFACE_MAPPING" | "SOURCE_ANALYSIS" | "DEPENDENCY_ANALYSIS"
  | "CONFIGURATION_ANALYSIS" | "SECRET_ANALYSIS" | "AUTHENTICATION_ANALYSIS"
  | "AUTHORIZATION_ANALYSIS" | "API_ANALYSIS" | "BUSINESS_LOGIC_ANALYSIS"
  | "HYPOTHESIS_GENERATION" | "INVESTIGATION" | "VALIDATION"
  | "EVIDENCE_COLLECTION" | "FINDING_CORRELATION" | "RISK_ASSESSMENT"
  | "REPORTING" | "COMPLETION";
```

### 2. Investigation (`src/investigation/`)

The autonomous brain.

| File | Purpose |
|------|---------|
| `controller.ts` | `InvestigationController` — main loop: observe → decide → execute → repeat |
| `decision-schema.ts` | Zod schemas for `InvestigationDecision` and `InvestigationOutput` |
| `model-adapter.ts` | `ModelAdapter` interface + `DeterministicMockModel` |
| `runtime.ts` | `HilbrasSecurityRuntime` — orchestrates phases, dispatches tools |
| `security-model.ts` | `buildSecurityModel(index)` — derives security context from ProjectIndex |
| `events.ts` | `InvestigationEventStream` — typed event bus for observability |
| `handlers.ts` | 20 phase handler classes (one per phase) |
| `ai-engine.ts` | AI reasoning engine (uses `HilbrasClient` stub for future integration) |

**Controller loop:**
```
while iterations < maxIterations:
  1. Build context (compact summary of current state)
  2. Call model.decide(context) → InvestigationOutput
  3. Validate output against Zod schema
  4. Select best decision (priority: complete > create_finding > validate > ...)
  5. Execute decision through runtime
  6. Emit event to stream
  7. Update state
```

### 3. Tools (`src/tools/`)

14 registered tools, each with a handler implementation.

| Tool | Handler | Risk | Phases |
|------|---------|------|--------|
| `filesystem.list` | `tools/filesystem/handlers.ts` | read_only | 6 phases |
| `filesystem.read` | `tools/filesystem/handlers.ts` | read_only | 6 phases |
| `search.code` | `tools/search/handlers.ts` | read_only | 7 phases |
| `search.regex` | `tools/search/handlers.ts` | read_only | 7 phases |
| `search.symbol` | `tools/search/handlers.ts` | read_only | 7 phases |
| `ast.parse` | `tools/ast/handlers.ts` | read_only | 2 phases |
| `ast.findCalls` | `tools/ast/handlers.ts` | read_only | 2 phases |
| `taint.analyze` | `tools/taint/handlers.ts` | read_only | 2 phases |
| `dependencies.analyze` | `tools/dependencies/handlers.ts` | read_only | 2 phases |
| `secrets.scan` | `tools/secrets/handlers.ts` | read_only | 2 phases |
| `configuration.analyze` | `tools/config/handlers.ts` | read_only | 2 phases |
| `api.inspect` | `tools/routes/handlers.ts` | read_only | 3 phases |
| `sandbox.execute` | `tools/sandbox/handlers.ts` | sandboxed | 2 phases |
| `repository.discover` | `tools/repository/handlers.ts` | read_only | 2 phases |

**Dispatcher:** Routes tool names to handler implementations. Falls back to handler map if dispatcher doesn't match.

### 4. Policies (`src/policies/`)

Every tool call passes through the policy engine.

| File | Purpose |
|------|---------|
| `engine.ts` | `evaluatePolicy(toolName, policyCtx)` — returns `{ allowed, reason }` |
| `index.ts` | Re-exports |

**4-layer check:**
1. Is tool `forbidden`? → deny
2. Is tool registered? → deny
3. Is tool available in current phase? → deny
4. Does authorization scope permit this operation? → deny

**Masking:** `maskSensitiveValues()` strips API keys, tokens, passwords from all input/output.

### 5. Findings (`src/findings/`)

Severity scoring and finding lifecycle.

| File | Purpose |
|------|---------|
| `engine.ts` | `computeSeverityScore()`, `createFinding()`, `correlateFindings()`, `groupCorrelated()` |
| `index.ts` | Re-exports |

**Severity formula (deterministic, weighted):**
```
score = exploitability * 0.25 + impact * 0.20 + reachability * 0.15
      + privilege_required * 0.15 + automation * 0.10 + code_access * 0.10 + user_interaction * 0.05
```
Mapped to: informational / low / medium / high / critical

**Correlation:** Groups findings by category, component, CWE, root-cause text similarity, and shared evidence. Deduplicates above threshold.

### 6. Reports (`src/reports/`)

Three output formats.

| Formatter | File | Output |
|-----------|------|--------|
| `JsonReportFormatter` | `formatters.ts` | Full structured payload |
| `SarifReportFormatter` | `formatters.ts` | SARIF 2.1 compliant |
| `MarkdownReportFormatter` | `formatters.ts` | Human-readable report |

### 7. Storage (`src/storage/`)

Database layer (PostgreSQL + Drizzle ORM, but with in-memory fallback).

| File | Purpose |
|------|---------|
| `schema.ts` | 8 tables: audits, findings, evidence, hypotheses, attackPaths, baselines, reports, toolExecutions |
| `repositories.ts` | 9 repository classes with factory `createRepositories(db)` |
| `evidence.ts` | `InMemoryEvidenceStore` with automatic secret masking on write |

### 8. Sandbox (`src/sandbox/`)

| File | Purpose |
|------|---------|
| `executor.ts` | `runInSandbox(command, config)` — Docker-first, process fallback with CPU/memory limits |

---

## CLI & UI (`src/cli/`)

| File | Purpose |
|------|---------|
| `index.ts` | Commander-based CLI: audit, report, findings, projects, config, init, version |
| `ui.tsx` | Interactive TUI (Ink + React): runs via `tsx src/cli/ui.tsx` |
| `progress.ts` | ANSI color utilities: severity badges, section headers, status indicators |
| `config.ts` | Persistent config: `~/.spectra/config.json` with profiles, defaults, API keys |
| `bootstrap.ts` | Entry point for `bin/spectra` |

**CLI exit codes:**
- `0` — clean (no high/critical findings)
- `1` — has high or critical findings
- `2` — usage/argument error
- `3` — runtime error

---

## Type Shims (`src/types/sdk-shims.ts`)

Local type definitions mirroring the subset of `@hilbras/sdk` used by Spectra:

- `Message`, `Role`, `ToolCall`, `ToolCallFunction`
- `Tool`, `ToolParameter`, `ToolParameters`, `ToolFunctionDef`
- `StreamChunk`, `TextChunk`, `ReasoningChunk`, `ToolCallChunk`, `UsageChunk`, `ErrorChunk`, `FinishChunk`
- `HilbrasClient`, `HilbrasClientConfig`

These allow Spectra to publish independently without requiring the SDK to be installed first.

---

## Test Structure

| Directory | Contents |
|-----------|----------|
| `tests/unit/` | Domain types, severity engine, state machine, tool registry, policy engine |
| `tests/integration/` | Runtime lifecycle, tool dispatch, dry-run mode, evidence linking |
| `tests/e2e/benchmark.test.ts` | Per-fixture indexing, search, taint, secrets, deps, config, reports, policy defense |
| `tests/e2e/autonomous.test.ts` | Controller loop, decision validation, event stream, mock model, prompt injection defense |
| `tests/fixtures/` | 5 vulnerable demo projects (SQLi, XSS, command injection, path traversal, IDOR) |

---

## Key Design Decisions

1. **Single agent, not multi-agent** — simpler reasoning chain, easier to audit, lower compute cost.
2. **Non-linear phase machine** — phases can be revisited based on AI decisions, not rigid linear progression.
3. **Policy gate before every tool call** — the AI cannot bypass permissions; the policy engine is the final authority.
4. **Deterministic severity scoring** — findings are scored with a weighted formula, not assigned by the LLM.
5. **Evidence-first findings** — every finding must link to at least one piece of collected evidence.
6. **Secret masking everywhere** — raw credentials never appear in logs, reports, or evidence stores.
7. **Immutable state** — `InvestigationState` is wrapped immutably; mutations return new instances.
