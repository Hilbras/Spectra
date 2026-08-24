# Hilbras Spectra v0.1.0 — Feature Roadmap Specification

## Overview

This spec defines 10 improvements across 2 tiers that transform Spectra from a research prototype
into a production-grade security analysis platform. Each feature is designed to be implementable
independently while building toward a cohesive whole.

---

## Tier 1: High Impact, Medium Effort

### Feature 1: Real AI Model Adapters

**Problem:** The current `DeterministicMockModel` only runs keyword-based heuristics. Real audits
need actual LLM reasoning to form hypotheses, correlate findings, and make nuanced decisions.

**Solution:** Implement three model adapters that conform to the existing `ModelAdapter` interface:

```
src/investigation/adapters/
  openai.ts          — OpenAI GPT-4o / GPT-4-turbo / o1
  anthropic.ts       — Claude 3.5 Sonnet / Haiku
  ollama.ts          — Local models (llama3, mistral, etc.)
```

Each adapter:
- Reads config from `~/.spectra/config.json` (`apiKeys.openai`, `apiKeys.anthropic`, etc.)
- Accepts a `providerConfig` object with model ID, temperature, maxTokens
- Converts Spectra's `Message[]` to provider-specific format
- Streams responses back as structured JSON decisions
- Implements retry + circuit-breaker pattern (reuse SDK patterns from shims)

**Config schema change:**
```json
{
  "models": {
    "openai": { "model": "gpt-4o", "temperature": 0.1, "maxTokens": 4096 },
    "anthropic": { "model": "claude-3-5-sonnet-20241022" },
    "ollama": { "model": "llama3.2", "temperature": 0.1 }
  }
}
```

**Integration point:** `InvestigationController` already accepts any `ModelAdapter`. No controller changes needed — just swap in the real adapter.

**Tests:**
- Unit: Adapter creates correct HTTP requests for each provider
- Unit: Response parsing produces valid `InvestigationOutput`
- Integration: Mock HTTP server returns provider responses; verify decision quality
- E2E: Run mock model path (existing tests) + one real-adapter smoke test (skipped without API key)

---

### Feature 2: Live CVE Feed Integration

**Problem:** The embedded CVE database in `dependencies/handlers.ts` is static and stale.

**Solution:** Add optional live CVE fetching from NVD API (nvd.nist.gov):

```typescript
// src/tools/cve/fetcher.ts
export async function fetchCVEResponse(
  cpeMatch: string,
  options?: { since?: Date; until?: Date; maxResults?: number }
): Promise<CVERecord[]>

// src/tools/cve/cache.ts — localStorage-style cache with TTL
export class CVECache {
  get(key: string): CVERecord[] | null
  set(key: string, records: CVERecord[], ttlMs: number): void
  clear(): void
}
```

The `dependencies.analyze` tool gains a `--live` flag:
```bash
spectra audit ./my-app --live-cves   # fetch fresh CVE data
```

When `--live-cves` is used:
1. Check cache first (TTL: 24h)
2. Query NVD API for matching CVEs
3. Merge with embedded static DB (static = fallback, live = override)
4. Store result in `~/.spectra/data/cve-cache.json`

**Data source:** https://services.nvd.nist.gov/rest/json/cves/2.0?cpeName={cpe}&apiKey=${NVD_API_KEY}

Free tier: 5 requests/30s, 100K requests/day. No API key required for basic queries.

**Tests:**
- Unit: CVE cache get/set/clear/ttl expiration
- Unit: NVD response parser handles empty/filtered results
- Integration: Mock NVD API server, verify merge logic with static DB

---

### Feature 3: HTML Report Formatter

**Problem:** JSON/SARIF are machine-readable but not stakeholder-friendly. Executives need visual reports.

**Solution:** New `HtmlReportFormatter`:

```typescript
// src/reports/html-formatter.ts
export class HtmlReportFormatter implements ReportFormatter {
  readonly format = "html" as const;
  generate(investigation: SecurityInvestigation, findings: Finding[]): string
}
```

HTML report includes:
- Executive summary with security score gauge (SVG)
- Severity distribution pie chart (CSS-only, no JS dependency)
- Findings table with sortable columns and severity color coding
- Attack path diagrams (ASCII art fallback for simple chains)
- RemEDIATION recommendations section
- Print-optimized styles
- Dark/light theme support via CSS variables

**CLI usage:**
```bash
spectra audit ./app -f html -o report.html
spectra report my-audit-id -f html
```

**Tests:**
- Unit: HTML validates as well-formed document
- Unit: All findings render in table rows
- Unit: Score gauge shows correct percentage
- Snapshot: Compare rendered HTML against golden file

---

### Feature 4: JUnit XML Reporter

**Problem:** Enterprise CI/CD pipelines (Jenkins, GitLab CI, Azure DevOps) expect JUnit XML for
findings visualization in pipeline dashboards.

**Solution:** New `JUnitReportFormatter`:

```typescript
// src/reports/junit-formatter.ts
export class JUnitReportFormatter implements ReportFormatter {
  readonly format = "junit" as const;
  generate(investigation: SecurityInvestigation, findings: Finding[]): string
}
```

Output format:
```xml
<?xml version="1.0" encoding="UTF-8"?>
<testsuites name="Hilbras Spectra" tests="5" failures="2" errors="0">
  <testsuite name="sql-injection" tests="5" failures="2">
    <testcase name="SQLi in login query" classname="CWE-89" time="0.023">
      <failure message="Direct string concatenation in SQL query...">severity=critical</failure>
    </testcase>
  </testsuite>
</testsuites>
```

One `<testsuite>` per finding category. Each finding = one `<testcase>`. Critical/high findings
render as `<failure>`, medium/low as `<testcase>` (visible but not failures).

**CI integration:**
```yaml
# .gitlab-ci.yml example
security-audit:
  script:
    - spectra audit ./src -f junit -o junit.xml
  artifacts:
    reports:
      junit: junit.xml
```

**Tests:**
- Unit: XML validates against JUnit XSD
- Unit: Each finding becomes exactly one testcase
- Unit: Severity mapping correct (critical/high → failure element)

---

### Feature 5: Vulnerability Scan Tool

**Problem:** No tool wraps existing package-manager vulnerability scanners. Spectra can't leverage
npm audit, pip audit, cargo audit, etc.

**Solution:** New `vulnerability.scan` tool:

```typescript
// src/tools/vulnerability/handlers.ts
export async function scanVulnerabilities(input: {
  packageManager: "npm" | "pip" | "cargo" | "go";
  lockFile?: string;
  ignoreCVEs?: string[];
}, ctx: ToolExecutionContext): Promise<ToolOutput>
```

Implementation:
- Spawns subprocess: `npm audit --json`, `pip-audit --format json`, etc.
- Parses scanner output into Spectra's Finding format
- Maps scanner severities to Spectra severity levels
- Merges results with embedded CVE DB (Feature 2) for cross-reference

**Registry entry:**
```typescript
registerTool({
  name: "vulnerability.scan",
  description: "Run package manager vulnerability scanner (npm audit / pip-audit / cargo audit)",
  parameters: { /* ... */ },
  riskLevel: "read_only",
  allowedPhases: ["DEPENDENCY_ANALYSIS", "RECONNAISSANCE"],
  handlerRef: "tools/vulnerability/scan",
});
```

**Handler implementations:**
```
src/tools/vulnerability/
  handlers.ts        — Main dispatch: npm/pip/cargo/go
  npm-parser.ts      — Parse npm audit JSON
  pip-parser.ts      — Parse pip-audit JSON
  cargo-parser.ts    — Parse cargo-audit JSON
  go-parser.ts       — Parse go list -m all -json
```

**Tests:**
- Unit: Parser transforms raw scanner JSON → Spectra Finding[]
- Integration: Mock subprocess output for each package manager
- E2E: Run against fixture packages that have known vulnerabilities

---

## Tier 2: High Impact, Higher Effort

### Feature 6: Interprocedural Taint Analysis

**Problem:** Current taint analysis only traces within a single file. Real vulnerabilities cross
function boundaries (e.g., user input → function call → SQL query in another module).

**Solution:** Extend the taint engine to trace across function boundaries using AST call graphs:

```
src/tools/taint/
  flow-tracker.ts    — New: interprocedural data-flow engine
  call-graph.ts      — New: builds function call graph from AST
  intra-file.ts      — Existing: kept for simple cases
```

Flow tracker algorithm:
1. Build call graph from AST (who calls whom, with parameter mappings)
2. For each sink found in intra-file analysis, trace back through callers
3. Follow parameter aliases: if `f(x)` calls `g(x)`, taint flows from caller's arg to callee's param
4. Handle indirect calls via dispatch tables and dynamic imports
5. Mark taint paths with hop count; flag deep paths (>5 hops) as higher confidence

**New output format:**
```json
{
  "source": { "file": "routes/auth.ts", "line": 12, "expression": "req.body.username" },
  "sink": { "file": "db/queries.ts", "line": 8, "expression": `SELECT * FROM users WHERE name='${input}'` },
  "path": [
    { "step": 1, "call": "loginHandler(req)", "file": "routes/auth.ts", "line": 12 },
    { "step": 2, "call": "validateInput(username)", "file": "middleware/validation.ts", "line": 5 },
    { "step": 3, "call": "runQuery(sql)", "file": "db/queries.ts", "line": 8 }
  ],
  "hops": 3,
  "confidence": 0.92
}
```

**Tests:**
- Unit: Call graph builder correctly maps parameter aliases
- Unit: Taint flow tracks through 3+ hop chains
- Integration: Fixture with cross-module SQL injection (new fixture)
- Performance: Benchmark on large codebase (10K+ LOC)

---

### Feature 7: Python + Go Language Support

**Problem:** Current analyzers are TypeScript/JavaScript-only. Enterprise environments use
Python, Go, and other languages extensively.

**Solution:** Add language-specific analyzers:

```
src/index/
  language-analyzer.ts     — Base interface + dispatcher
  ts-analyzer.ts           — Existing (enhanced)
  python-analyzer.ts       — NEW: AST via tree-sitter or regex patterns
  go-analyzer.ts           — NEW: AST via astpackage + regex patterns
```

**Python analyzer** (regex-based, no external deps):
- Detect: `sqlalchemy`, `django`, `flask`, `fastapi` frameworks
- Patterns: `cursor.execute(f"...")`, `request.form[...]`, `subprocess.call(...)`
- Taint sources: `request.args`, `request.form`, `request.json`, `sys.argv`
- Taint sinks: `execute()`, `exec()`, `eval()`, `subprocess.*`, `os.system()`

**Go analyzer**:
- Detect: `gin`, `echo`, `fiber` frameworks
- Patterns: `c.Param("id")`, `fmt.Fprintf(w, ...)`, `exec.Command(...)`
- Taint sources: `c.Query()`, `c.PostForm()`, `c.Param()`
- Taint sinks: `Exec()`, `Query()`, `Command()`, `os/exec`

**Test fixtures added:**
```
tests/fixtures/
  python-flask-sqli/       — Flask app with SQL injection
  go-echo-xss/             — Echo framework with XSS
```

**Tests:**
- Unit: Python syntax detector recognizes common patterns
- Unit: Go route discovery finds Echo/Gin handlers
- E2E: Full audit of Python and Go fixtures

---

### Feature 8: Attack Path Visualization

**Problem:** Findings are listed but not connected. Users can't see exploit chains.

**Solution:** New attack-path correlation that links related findings into chains:

```typescript
// src/findings/attack-paths.ts
export function buildAttackPaths(findings: Finding[]): AttackPath[]

interface AttackPath {
  id: string;
  chain: Array<{ findingId: string; step: number; transition: string }>;
  totalSeverity: string;
  description: string;
  evidence: Evidence[];
}
```

Visualization output formats:
- **JSON**: Structured chain data for programmatic use
- **ASCII diagram**: Human-readable text representation
- **DOT/Graphviz**: Export for rendering as images

**ASCII example:**
```
┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
│  SQL Injection   │────▶│  Auth Bypass    │────▶│  Data Exfil    │
│  (Critical)      │     │  (High)         │     │  (Critical)    │
│  auth.ts:15      │     │  middleware.ts   │     │  db/queries.ts │
└─────────────────┘     └─────────────────┘     └─────────────────┘
```

**CLI usage:**
```bash
spectra audit ./app -f json -o audit.json
spectra paths audit.json --format ascii   # ASCII diagram
spectra paths audit.json --format dot     # Graphviz DOT
spectra paths audit.json --format json    # Structured data
```

**Tests:**
- Unit: Two findings with same CWE + overlapping component → correlated path
- Unit: Three+ finding chains built correctly
- Unit: Disconnected findings produce no false correlations

---

### Feature 9: Checkpoint/Persistence

**Problem:** Long-running audits on large projects can fail partway through with no recovery.

**Solution:** Automatic checkpoint saving at phase boundaries:

```
~/.spectra/checkpoints/
  <investigation-id>.checkpoint.json   — Saved state at each phase transition
```

Checkpoint contains:
```json
{
  "investigationId": "...",
  "phase": "SOURCE_ANALYSIS",
  "timestamp": "2026-08-24T...",
  "stateSnapshot": { /* full InvestigationState serialized */ },
  "evidenceStore": { /* serialized evidence records */ },
  "findings": [/* partial findings so far */],
  "iterationsCompleted": 23,
  "nextPhase": "DEPENDENCY_ANALYSIS"
}
```

Resume logic:
```bash
spectra audit ./app --resume            # Auto-resume most recent checkpoint
spectra audit ./app --resume-from inv-abc123  # Resume specific investigation
spectra checkpoints list                # Show available checkpoints
spectra checkpoints delete inv-abc123   # Clean up old checkpoints
```

**CLI commands added:**
- `spectra checkpoints list` — show active checkpoints
- `spectra checkpoints delete <id>` — remove a checkpoint

**Implementation:**
- After each phase completes in `runtime.ts`, call `checkpoint.save(state)`
- On `--resume`, load checkpoint and set runtime state to saved point
- Clean up checkpoint on successful completion

**Tests:**
- Unit: Checkpoint serializes/deserializes state correctly
- Unit: Resume skips completed phases and continues from save point
- Integration: Simulate crash mid-investigation, verify resume works

---

### Feature 10: Webhook Notifications

**Problem:** Users can't get notified about critical findings in real-time. No integration with
chat platforms used by security teams.

**Solution:** Configurable webhook delivery for critical/high findings:

```typescript
// src/notifications/webhook.ts
export class WebhookNotifier {
  async notify(config: WebhookConfig, findings: Finding[]): Promise<void>
}

interface WebhookConfig {
  url: string;                    // Incoming webhook URL
  type: "slack" | "discord" | "teams" | "custom";
  channel?: string;               // Slack channel or Discord channel
  mention?: string;              // @mention on Slack/Discord
}
```

**Payload examples:**

Slack:
```json
{
  "attachments": [{
    "color": "#ff0000",
    "title": "🚨 Critical Findings in Project",
    "fields": [
      { "title": "Project", "value": "my-app", "short": true },
      { "title": "Critical", "value": "2", "short": true },
      { "title": "High", "value": "3", "short": true },
      { "title": "Score", "value": "35/100", "short": true }
    ]
  }]
}
```

Discord (embed):
```json
{
  "embeds": [{
    "title": "🚨 Security Alert",
    "color": 16711680,
    "fields": [...]
  }]
}
```

Teams (card):
```json
{
  "@type": "MessageCard",
  "themeColor": "FF0000",
  "sections": [{ "activityTitle": "Security Alert", "facts": [...] }]
}
```

**Config:**
```json
{
  "webhooks": {
    "slack": { "url": "https://hooks.slack.com/...", "channel": "#security-alerts" },
    "discord": { "url": "https://discord.com/api/webhooks/..." }
  }
}
```

**Trigger logic:**
- Send notification when investigation completes with ≥1 critical OR ≥3 high findings
- Configurable thresholds: `--notify-threshold critical:1 high:3 medium:10`
- Batch notifications (one per investigation, not per finding)

**CLI:**
```bash
spectra audit ./app --notify slack      # Use configured Slack webhook
spectra audit ./app --notify-threshold critical:2  # Only notify on 2+ critical
```

**Tests:**
- Unit: Payload builder creates correct format for each provider
- Unit: Threshold evaluation correctly decides whether to send
- Integration: Mock webhook server receives and validates payload format
