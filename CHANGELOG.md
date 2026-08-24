# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.0.6] — 2026-08-24

### Added

- **Interactive Terminal UI** (`spectra ui`)
  - Full keyboard-navigable TUI powered by Ink + React
  - Screens: Main Menu · Audit · Findings · Projects · Settings
  - Navigate with ↑/↓ arrows, Enter to select, Esc to go back
  - Run with: `spectra ui` or `npm run ui`

- **Production CLI** (full rewrite)
  - 7 commands: `audit`, `report`, `findings`, `projects`, `config`, `init`, `version`
  - Short flags: `-n/--dry-run`, `-f/--format`, `-d/--depth`, `-o/--output`, `-q/--quiet`, `-m/--model`
  - CI-friendly exit codes: `0` = no high/critical findings, `1` = findings present
  - SARIF 2.1, JSON, and Markdown report output to stdout or file

- **Persistent Configuration**
  - `~/.spectra/config.json` stores user preferences
  - Project profiles with last-audit tracking
  - Default model, report format, and approval threshold settings

- **SDK Type Shims**
  - Local type definitions for Message, Tool, StreamChunk, ToolParameters, HilbrasClient
  - Zero runtime dependency on @hilbras/sdk — fully standalone package

### Improved

- Phase handlers now strictly respect tool registry phase permissions
- Policy errors eliminated across all 20 investigation phases
- All 5 benchmark fixtures audit cleanly with zero errors
- Package ships as truly standalone (`@hilbras/sdk` removed from dependencies)

### Changed

- Package is now independently publishable — no monorepo build order required
- CLI entry point moved to `bin/spectra` (referenced in package.json `bin`)
- Report generation integrated into CLI audit command (no separate step needed)

### Fixed

- Tool dispatch now respects phase availability for every registered tool
- `filesystem.list` added to `ATTACK_SURFACE_MAPPING` allowed phases
- Fixed TypeScript strict mode errors in phase handlers (null-safe casts)

---

## [0.0.5] — 2026-08-23

### Added

- **Project Intelligence Layer**
  - `ProjectIndex` — single-pass indexer for file tree, language detection, symbol index, route discovery
  - `SecurityModel` — internal project security model built from indexed data (assets, trust boundaries, data flows, controls)

- **Investigation Controller**
  - `InvestigationController` — autonomous single-agent AI investigation loop
  - Structured decision schema with Zod validation (`InvestigationDecision`, `InvestigationOutput`)
  - AI context builder that assembles compact project state for each iteration
  - Decision prioritization (complete > create_finding > validate > investigate > analyze)

- **AI Model Abstraction**
  - `ModelAdapter` interface for provider-agnostic AI execution
  - `DeterministicMockModel` — reproducible test model with keyword-driven decision heuristics
  - Event stream (`InvestigationEventStream`) for observability and replay

- **Security Tooling**
  - Filesystem tools (`list`, `read`) with line-range support
  - Search tools (`text`, `regex`, `symbol`) across indexed project
  - AST/code analysis (`parse`, `findCalls`) via regex-based parser
  - Taint analysis (`analyze`) — source-to-sink path detection
  - Dependency analysis (`analyze`) — manifest parsing, CVE classification
  - Secret detection (`scan`) — multi-pattern + Shannon entropy, masked output
  - Configuration analysis (`analyze`) — Docker, CI, env, CORS, TLS, headers
  - Route/API inspection (`inspect`) with auth annotation

- **Reporting**
  - JSON, SARIF 2.1, and Markdown report formatters
  - Extensible formatter registry

- **Testing & Benchmarks**
  - 5 vulnerable benchmark fixtures: SQL Injection, XSS, Command Injection, Path Traversal, IDOR
  - 85 passing tests across unit, integration, E2E benchmark, and autonomous investigation suites
  - Prompt injection defense tests
  - Policy bypass resistance tests

- **Documentation**
  - Professional README with architecture diagram, capabilities, usage examples
  - CHANGELOG.md
  - .github/SECURITY.md
  - .github/CONTRIBUTING.md

### Improved

- Investigation runtime now supports iterative AI decision loops with phase flexibility
- Tool dispatcher routes through unified policy gate with phase-aware permissions
- Evidence store applies secret masking on write
- Finding creation uses deterministic severity scoring (not LLM-assigned)
- CLI displays product name as "Hilbras Spectra"

### Security

- Repository content treated as untrusted data — never overrides system policy
- All secret detection results are masked before exposure in logs or reports
- Policy engine gates every tool call against phase, authorization scope, and risk level
- Sandbox uses Docker containers with CPU/memory/network limits when available

### Changed

- **Renamed** package from `@hilbras/security` → `@hilbras/spectra`, CLI from `hilbras-security` → `spectra`
- Version set to 0.0.5
- All internal product-name references updated to "Hilbras Spectra"
