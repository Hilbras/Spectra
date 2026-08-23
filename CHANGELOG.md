# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
