#!/usr/bin/env node
/**
 * Hilbras Spectra — Full Production CLI
 * 
 * spectra audit <target> [options]      Run security investigation
 * spectra findings [options]            Browse past findings
 * spectra history [options]             List audit history
 * spectra report <id> [options]         Generate report from saved data
 * spectra benchmarks [--quiet]          Run all fixture benchmarks
 * spectra health                        Diagnose installation
 * spectra projects [action] [name] [path]  Manage project profiles
 * spectra config [action] [key] [value]   View/edit configuration
 * spectra login [provider] [options]      Configure AI provider keys
 * spectra init                            Initialize ~/.spectra/
 * spectra version                         Show version info
 */

import { Command } from "commander";
import { readFileSync, writeFileSync, mkdirSync, existsSync, readdirSync } from "fs";
import { join } from "path";
import { homedir } from "os";
import { spawnSync } from "child_process";

import { HilbrasSecurityRuntime } from "../investigation/runtime.js";
import { InvestigationController } from "../investigation/controller.js";
import { DeterministicMockModel } from "../investigation/model-adapter.js";
import { JsonReportFormatter, SarifReportFormatter, MarkdownReportFormatter } from "../reports/formatters.js";
import type { ReportFormatter } from "../reports/formatters.js";
import { loadConfig, saveConfig } from "./config.js";
import { appendAudit, findAudits, getAuditById } from "./store.js";  // eslint-disable-line
import type { StoredAudit } from "./types.js";

// ─── Color helpers ─────────────────────────────────────────────────────────────

const C = {
  reset: "\x1b[0m", bold: "\x1b[1m", dim: "\x1b[2m",
  red: "\x1b[31m", green: "\x1b[32m", yellow: "\x1b[33m",
  blue: "\x1b[34m", magenta: "\x1b[35m", cyan: "\x1b[36m", gray: "\x1b[90m", white: "\x1b[37m",
  bgRed: "\x1b[41m", bgYellow: "\x1b[43m",
} as const;

function c(text: string, color: string): string { return `${color}${text}${C.reset}`; }
function success(t: string) { return c(t, C.green); }
function error(t: string) { return c(t, C.red); }
function warn(t: string) { return c(t, C.yellow); }
function dim(t: string) { return c(t, C.gray); }

// ─── Dashboard helpers ─────────────────────────────────────────────────────────

function divider() { return c("  " + "─".repeat(70), C.gray); }
function section(title: string) { return `\n${c(title, C.bold + C.cyan)}\n${divider()}\n`; }

function scoreMeter(score: number, width = 40): string {
  const filled = Math.round((score / 100) * width);
  const bar = c("█".repeat(filled), score >= 80 ? C.green : score >= 50 ? C.yellow : C.red);
  const empty = c("░".repeat(width - filled), C.gray);
  return `${bar}${empty} ${c(`${score}/100`, score >= 80 ? C.green : score >= 50 ? C.yellow : C.red)}`;
}

function sevBadge(sev: string, compact = false): string {
  const map: Record<string, string> = {
    critical:    C.bgRed + C.white,
    high:        "\x1b[41m\x1b[37m",
    medium:      C.bgYellow + "\x1b[30m",
    low:         C.blue + C.white,
    informational: C.gray + C.white,
  };
  const code = map[sev] ?? (C.gray + C.white);
  const text = (sev ?? "?").toUpperCase().padEnd(compact ? 8 : 0);
  return `${code}${text}${C.reset}`;
}

function findingTable(findings: Array<{ title?: string; severity?: string; category?: string; component?: string; cwe?: string }>): string {
  if (!findings.length) return c("  No findings recorded.", C.dim);
  const rows = findings.map((f) => ({
    sev: f.severity ?? "unknown",
    cat: (f.category ?? "unknown").slice(0, 16),
    comp: (f.component ?? "—").slice(0, 22),
    title: (f.title ?? "").slice(0, 52),
  }));
  const header = c("  " + "SEVERITY".padEnd(10) + "CATEGORY".padEnd(18) + "COMPONENT".padEnd(24) + "TITLE", C.bold + C.cyan);
  const lines = [header, c("  " + "─".repeat(70), C.dim)];
  for (const r of rows) {
    lines.push(`  ${sevBadge(r.sev, true)} ${(r.cat).padEnd(18)} ${(r.comp).padEnd(24)} ${(r.title).length > 0 ? r.title : "—"}`);
  }
  return lines.join("\n");
}

function summaryPanel(target: string, result: any, meta: { durationMs: number; iterations: number; model: string; format: string }): string {
  const findings = result?.investigation?.findings ?? [];
  const hypotheses = result?.investigation?.hypotheses ?? [];
  const bySev: Record<string, number> = {};
  for (const f of findings) bySev[f.severity] = (bySev[f.severity] ?? 0) + 1;
  const score = Math.max(0, 100 - (bySev.critical ?? 0) * 25 - (bySev.high ?? 0) * 15 - (bySev.medium ?? 0) * 8 - (bySev.low ?? 0) * 3);
  const lines: string[] = [];
  lines.push(c(`\n  TARGET     ${target.split("/").pop() ?? target}`, C.green));
  lines.push(c("  STATUS     ", C.bold) + (result?.investigation?.status === "completed" ? success("✓ Completed") : warn(result?.investigation?.status ?? "?")));
  lines.push(c("  DURATION   ", C.bold) + `${(meta.durationMs / 1000).toFixed(2)}s`);
  lines.push(c("  ITERATIONS ", C.bold) + String(meta.iterations));
  lines.push(c("  MODEL      ", C.bold) + c(meta.model, C.cyan));
  lines.push("");
  lines.push(c("  SECURITY SCORE", C.bold));
  lines.push(`    ${scoreMeter(score)}`);
  lines.push("");
  lines.push(c("  FINDINGS", C.bold));
  if (bySev.critical) lines.push(`    ${c(`● ${bySev.critical} Critical`, C.red)}`);
  if (bySev.high) lines.push(`    ${c(`● ${bySev.high} High`, "\x1b[91m")}`);
  if (bySev.medium) lines.push(`    ${c(`● ${bySev.medium} Medium`, C.yellow)}`);
  if (bySev.low) lines.push(`    ${c(`● ${bySev.low} Low`, C.blue)}`);
  if (bySev.informational) lines.push(`    ${c(`● ${bySev.informational} Info`, C.gray)}`);
  if (!Object.keys(bySev).length) lines.push(`    ${success("None detected")}`);
  lines.push("");
  lines.push(c("  HYPOTHESES ", C.bold) + String(hypotheses.length));
  return lines.join("\n");
}

function auditList(audits: StoredAudit[]): string {
  if (!audits.length) return c("  No audits found. Run 'spectra audit' first.", C.dim);
  const h = c("  " + "DATE".padEnd(22) + "TARGET".padEnd(26) + "FINDINGS".padEnd(10) + "SCORE".padEnd(8) + "STATUS", C.bold + C.cyan);
  const sep = c("  " + "─".repeat(80), C.dim);
  const rows = [h, sep];
  for (const a of audits.slice(0, 15)) {
    const date = new Date(a.generatedAt).toLocaleString("en-US", { month: "short", day: "2-digit", hour: "2-digit", minute: "2-digit" });
    const target = (a.target.split("/").pop() ?? a.target).slice(0, 24);
    const f = a.investigation?.findings ?? [];
    const crit = f.filter((x: any) => x.severity === "critical").length;
    const high = f.filter((x: any) => x.severity === "high").length;
    const fStr = f.length > 0 ? c(String(f.length), crit > 0 || high > 0 ? C.red : C.yellow) : c("0", C.green);
    const score = a.summary?.overallScore ?? 100;
    const sStr = score >= 80 ? c(String(score), C.green) : score >= 50 ? c(String(score), C.yellow) : c(String(score), C.red);
    rows.push(`  ${date.padEnd(22)} ${target.padEnd(26)} ${fStr.padEnd(10)} ${sStr.padEnd(8)} ${dim(a.investigation?.status ?? "?")}`);
  }
  return rows.join("\n");
}

function benchmarkResults(results: Array<{ fixture: string; status: string; durationMs: number; findings: number; errors: number }>): string {
  const h = c("  " + "FIXTURE".padEnd(28) + "STATUS".padEnd(10) + "TIME".padEnd(8) + "FINDINGS".padEnd(10) + "ERRORS", C.bold + C.cyan);
  const sep = c("  " + "─".repeat(65), C.dim);
  const rows = [h, sep];
  let tf = 0, te = 0;
  for (const r of results) {
    tf += r.findings; te += r.errors;
    const st = r.errors > 0 ? warn("WARN") : r.findings > 0 ? c("OK", C.red) : success("OK");
    rows.push(`  ${(r.fixture ?? "").padEnd(28)} ${st.padEnd(10)} ${(r.durationMs / 1000).toFixed(2).padEnd(8)} ${String(r.findings).padEnd(10)} ${r.errors > 0 ? warn(String(r.errors)) : "0"}`);
  }
  rows.push("");
  rows.push(c("  TOTAL:", C.bold) + ` ${tf} findings, ${te} errors across ${results.length} fixtures`);
  return rows.join("\n");
}

function helpBanner(version: string): string {
  return [
    c("\n  ╔══════════════════════════════════════════════════════════════╗", C.cyan),
    c("  ║          🔍  HILBRAS SPECTRA v" + version.padEnd(30) + " ║", C.bold + C.cyan),
    c("  ║        Autonomous AI Security Research Platform              ║", C.cyan),
    c("  ╚══════════════════════════════════════════════════════════════╝\n", C.cyan),
    "",
    c("  QUICK START", C.bold),
    "    spectra audit ./my-app                   Run investigation",
    "    spectra audit ./my-app -d quick           Fast scan",
    "    spectra audit ./my-app -f sarif          SARIF for CI/CD",
    "    spectra benchmarks                       Run all fixtures",
    "",
    c("  COMMANDS", C.bold),
    "    audit <target> [opts]      Run security investigation",
    "    findings [opts]            Browse past findings",
    "    history [opts]             List audit history",
    "    report <id> [opts]         Generate report from saved data",
    "    benchmarks                 Run fixture benchmarks",
    "    health                     Diagnose installation",
    "    projects [act] [name] [p]  Manage project profiles",
    "    config [act] [k] [v]       View/edit configuration",
    "    login [provider] [opts]    Configure AI provider keys",
    "    init                       Initialize ~/.spectra/",
    "    version                    Show version info",
    "",
    c("  AUDIT OPTIONS", C.bold),
    "    -d, --depth <quick|full>   Investigation depth (default: full)",
    "    -f, --format <json|sarif|md> Output format (default: json)",
    "    -m, --model <id>           AI model: mock, openai, anthropic, groq, ollama",
    "    -n, --dry-run              Plan-only, no tools executed",
    "    -o, --output <path>        Write report to file",
    "    -q, --quiet                Suppress progress output",
    "",
    c("  EXAMPLES", C.bold),
    "    spectra audit ~/projects/my-webapp",
    "    spectra audit ~/projects/my-webapp -d quick -f sarif -o report.sarif",
    "    spectra findings --severity high",
    "    spectra history --last 5",
    "    spectra benchmarks",
    "    spectra health",
    "",
  ].join("\n");
}

// ─── Store helpers (local versions to avoid circular deps) ────────────────────

const DATA_DIR = join(homedir(), ".spectra", "data");
function ensureDir(): void {
  if (!existsSync(DATA_DIR)) mkdirSync(DATA_DIR, { recursive: true });
}
function loadHistory(): StoredAudit[] {
  ensureDir();
  try { return JSON.parse(readFileSync(join(DATA_DIR, "history.json"), "utf-8")) as StoredAudit[]; } catch { return []; }
}
function saveHistory(a: StoredAudit[]): void {
  ensureDir();
  writeFileSync(join(DATA_DIR, "history.json"), JSON.stringify(a.slice(0, 100), null, 2), "utf-8");
}
function appendAuditItem(a: StoredAudit): void {
  const h = loadHistory().filter((x) => x.target !== a.target || Math.abs(new Date(x.generatedAt).getTime() - new Date(a.generatedAt).getTime()) > 60000);
  h.unshift(a);
  saveHistory(h);
}
function findAuditsLocal(opts: { target?: string; severity?: string; last?: number; limit?: number }): StoredAudit[] {
  let a = loadHistory();
  if (opts.target) a = a.filter((x) => x.target.includes(opts.target!) || (x.investigation as any).projectId?.includes(opts.target!));
  if (opts.severity) a = a.filter((x) => (x.investigation?.findings ?? []).some((f: any) => f.severity === opts.severity));
  if (opts.last) a = a.slice(0, opts.last);
  if (opts.limit) a = a.slice(0, opts.limit);
  return a;
}
function getAuditByIdLocal(id: string): StoredAudit | null {
  return loadHistory().find((a) => (a.investigation as any).id === id) ?? null;
}

// Re-export for compatibility
const store = { appendAudit: appendAuditItem, findAudits: findAuditsLocal, getAuditById: getAuditByIdLocal };

// ─── Audit command ─────────────────────────────────────────────────────────────

async function runAudit(target: string, opts: { dryRun?: boolean; model?: string; format?: string; depth?: string; output?: string; quiet?: boolean }): Promise<void> {
  // Resolve target
  let resolved = target;
  if (!existsSync(target)) {
    const cfg = loadConfig();
    const p = cfg.profiles?.[target];
    if (p) resolved = p.path;
    else { console.error(error(`Target not found: ${target}`)); process.exit(1); }
  }

  const fmt = opts.format ?? loadConfig().defaultFormat ?? "json";
  const maxIter = opts.depth === "quick" ? 20 : 50;
  const modelId = opts.model ?? loadConfig().defaultModel ?? "mock";

  if (!opts.quiet) {
    console.log(section(`🔍 SPECTRA AUDIT — ${resolved}`));
    console.log(`  Target     ${resolved}`);
    console.log(`  Mode       ${opts.dryRun ? c("DRY-RUN", C.yellow) : "full"}`);
    console.log(`  Model      ${modelId}`);
    console.log(`  Depth      ${opts.depth ?? "full"}`);
    console.log(`  Format     ${fmt.toUpperCase()}`);
    console.log(divider());
  }

  const runtime = new HilbrasSecurityRuntime({
    targetPath: resolved,
    authorizationScope: {
      allowedHosts: [], allowedServices: [], allowedPorts: [],
      allowedEnvironments: ["local"], allowedOperations: ["read"],
      restrictions: ["no-host-execution", "no-credential-theft"],
      allowActiveTesting: !opts.dryRun,
      allowNetworkAccess: false, allowFilesystemWrite: false,
    },
    dryRun: opts.dryRun ?? false,
  });

  const model = modelId === "mock"
    ? new DeterministicMockModel([])
    : (() => { console.error(error(`Unsupported model "${modelId}". Use "mock"`)); process.exit(1); })();

  if (!opts.quiet) console.log("\n  Starting autonomous investigation...\n");

  const controller = new InvestigationController({ runtime, model, maxIterations: maxIter });
  const result = await controller.run();

  if (!opts.quiet) {
    console.log(divider());
    console.log(summaryPanel(resolved, result, { durationMs: result.durationMs, iterations: result.iterations, model: modelId, format: fmt }));
    if (result.errors.length > 0) {
      console.log(c("\n  POLICY NOTES:", C.yellow));
      for (const e of result.errors.slice(0, 5)) console.log(`    ${warn(e)}`);
    }
  }

  // Build summary
  const findings = result.investigation.findings ?? [];
  const hypotheses = result.investigation.hypotheses ?? [];
  const bySev: Record<string, number> = {};
  for (const f of findings) bySev[f.severity] = (bySev[f.severity] ?? 0) + 1;
  const score = Math.max(0, 100 - (bySev.critical ?? 0) * 25 - (bySev.high ?? 0) * 15 - (bySev.medium ?? 0) * 8 - (bySev.low ?? 0) * 3);

  // Save to history
  const meta: StoredAudit = {
    generatedAt: new Date().toISOString(), target: resolved, model: modelId,
    iterations: result.iterations, durationMs: result.durationMs,
    investigation: {
      ...(result.investigation as any),
      findings: findings.map((f: any) => ({
        id: f.id, title: f.title, severity: f.severity, category: f.category,
        cwe: f.cwe ?? undefined, owasp: f.owasp ?? undefined,
        confidence: f.confidence, status: f.status,
        component: f.affectedComponent ?? undefined,
        rootCause: f.rootCause ?? undefined,
        description: f.description ?? undefined,
      })),
      hypotheses: hypotheses.map((h: any) => ({
        id: h.id, category: h.category, claim: h.claim,
        confidence: h.confidence, status: h.status,
      })),
      evidence: [],
    } as any,
    summary: {
      overallScore: score,
      criticalCount: bySev.critical ?? 0,
      highCount: bySev.high ?? 0,
      mediumCount: bySev.medium ?? 0,
      lowCount: bySev.low ?? 0,
      informationalCount: bySev.informational ?? 0,
      confirmedCount: findings.filter((f: any) => f.status === "confirmed").length,
      potentialCount: findings.filter((f: any) => f.status === "potential").length,
      hypothesisCount: hypotheses.length,
      evidenceCount: 0,
      topRisks: findings.filter((f: any) => f.severity === "critical" || f.severity === "high").slice(0, 5).map((f: any) => ({ title: f.title, severity: f.severity, category: f.category })),
    },
  };
  store.appendAudit(meta);

  // Save raw per-project
  const sd = join(resolved, ".spectra");
  if (!existsSync(sd)) mkdirSync(sd, { recursive: true });
  writeFileSync(join(sd, `audit-${Date.now()}.json`), JSON.stringify(meta, null, 2), "utf-8");

  // Generate report
  const formatter: ReportFormatter = fmt === "sarif" ? new SarifReportFormatter() : fmt === "markdown" ? new MarkdownReportFormatter() : new JsonReportFormatter();
  const reportContent = formatter.generate(result.investigation, findings);
  if (opts.output) {
    const outDir = join(opts.output, "..");
    if (!existsSync(outDir)) mkdirSync(outDir, { recursive: true });
    writeFileSync(opts.output, reportContent, "utf-8");
    if (!opts.quiet) console.log(success(`  Report written to ${opts.output}`));
  } else if (!opts.quiet) {
    console.log(section("📄 REPORT"));
    process.stdout.write(reportContent + "\n");
  }

  if (!opts.quiet) console.log(success(`  Investigation saved to ${join(sd, "audit-" + Date.now() + ".json")}`));

  const hasHigh = findings.some((f: any) => f.severity === "high" || f.severity === "critical");
  process.exit(hasHigh ? 1 : 0);
}

// ─── Findings command ──────────────────────────────────────────────────────────

function runFindings(opts: { severity?: string; limit?: string; project?: string; recent?: string }): void {
  console.log(section("📋 FINDINGS BROWSER"));
  const audits = store.findAudits({
    ...(opts.project ? { target: opts.project } : {}),
    ...(opts.severity ? { severity: opts.severity } : {}),
    ...(opts.recent ? { last: parseInt(opts.recent) } : {}),
    ...(opts.limit ? { limit: parseInt(opts.limit) } : {}),
  });

  if (!audits.length) { console.log(warn("  No findings found. Run 'spectra audit <target>' first.")); return; }

  const all: Array<{ at: string; ad: string; f: any }> = [];
  for (const a of audits) {
    for (const f of a.investigation?.findings ?? []) all.push({ at: a.target, ad: new Date(a.generatedAt).toLocaleString(), f });
  }

  let display = all;
  if (opts.severity) {
    display = all.filter((x) => x.f.severity === opts.severity);
    console.log(dim(`  Showing ${display.length} ${opts.severity.toUpperCase()}+ findings`));
  }
  if (!display.length) { console.log(warn("  No matching findings.")); return; }

  console.log(findingTable(display.map((x) => x.f)));
  console.log(dim(`  ${all.length} total across ${audits.length} audits`));
}

// ─── History command ───────────────────────────────────────────────────────────

function runHistory(opts: { project?: string; limit?: string; last?: string; show?: string }): void {
  console.log(section("📜 AUDIT HISTORY"));
  let audits = store.findAudits({
    ...(opts.project ? { target: opts.project } : {}),
    ...(opts.last ? { last: parseInt(opts.last) } : {}),
    ...(opts.limit ? { limit: parseInt(opts.limit) } : {}),
  });

  if (opts.show) {
    const m = audits.find((a) => a.target.includes(opts.show!) || String((a.investigation as any).projectId)?.includes(opts.show!));
    if (!m) { console.error(error(`  No audit found matching "${opts.show}"`)); return; }
    printAuditDetail(m);
    return;
  }

  if (!audits.length) { console.log(warn("  No history found. Run 'spectra audit <target>' first.")); return; }
  console.log(auditList(audits));
  console.log(dim(`  ${audits.length} audit(s) stored  —  Options: --project <name>  --last <n>  --show <target>`));
}

function printAuditDetail(a: StoredAudit): void {
  const inv = a.investigation as any;
  const findings = inv?.findings ?? [];
  const hyps = inv?.hypotheses ?? [];
  console.log(c(`  Target:      ${a.target}`, C.green));
  console.log(`  Date:         ${new Date(a.generatedAt).toLocaleString()}`);
  console.log(`  Status:       ${inv?.status === "completed" ? success("✓ Completed") : warn(inv?.status ?? "?")}`);
  console.log(`  Iterations:   ${a.iterations}`);
  console.log(`  Duration:     ${(a.durationMs / 1000).toFixed(2)}s`);
  console.log(`  Model:        ${a.model}`);
  if (findings.length) {
    console.log(c("\n  FINDINGS:", C.bold));
    for (const f of findings) console.log(`    ${sevBadge(f.severity, true)} ${f.title?.slice(0, 60) ?? ""}`);
  } else console.log(success("  No findings detected."));
  if (hyps.length) {
    console.log(c("\n  HYPOTHESES:", C.bold));
    for (const h of hyps.slice(0, 5)) console.log(c(`    [${h.status}] ${h.category}: ${(h.claim ?? "").slice(0, 70)}`, C.cyan));
  }
}

// ─── Report command ─────────────────────────────────────────────────────────────

function runReport(idOrTarget: string, opts: { format?: string; output?: string }): void {
  console.log(section("📄 REPORT GENERATOR"));
  let audit: StoredAudit | null = store.getAuditById(idOrTarget);
  if (!audit) audit = store.findAudits({ target: idOrTarget, limit: 1 })[0] ?? null;
  if (!audit) audit = store.findAudits({ limit: 1 })[0] ?? null;
  if (!audit) { console.error(error("  No saved audits found. Run 'spectra audit <target>' first.")); process.exit(1); }

  const inv = audit.investigation as any;
  const fmt = opts.format ?? "json";
  const formatter: ReportFormatter = fmt === "sarif" ? new SarifReportFormatter() : fmt === "markdown" ? new MarkdownReportFormatter() : new JsonReportFormatter();
  const report = formatter.generate(inv, inv?.findings ?? []);

  if (opts.output) {
    const d = join(opts.output, "..");
    if (!existsSync(d)) mkdirSync(d, { recursive: true });
    writeFileSync(opts.output, report, "utf-8");
    console.log(success(`  Report written to ${opts.output}`));
  } else {
    process.stdout.write(report + "\n");
  }
}

// ─── Benchmarks command ─────────────────────────────────────────────────────────

async function runBenchmarks(opts: { quiet?: boolean }): Promise<void> {
  const cwd = process.cwd();
  const fd = join(cwd, "tests", "fixtures");
  if (!existsSync(fd)) {
    console.log(section("🧪 BENCHMARKS"));
    console.log(warn("  No tests/fixtures directory. Run from the Spectra source repo."));
    return;
  }

  const fixtures = readdirSync(fd).filter((f) => existsSync(join(fd, f, "README.md"))).sort();
  if (!fixtures.length) { console.log(warn("  No benchmark fixtures found.")); return; }

  console.log(section(`🧪 SPECTRA BENCHMARKS — ${fixtures.length} fixtures`));

  const results: Array<{ fixture: string; status: string; durationMs: number; findings: number; errors: number }> = [];
  const t0 = Date.now();

  for (const fixture of fixtures) {
    const fp = join(fd, fixture);
    if (!opts.quiet) process.stdout.write(`  ⟳ ${fixture}... `);
    try {
      const rt = new HilbrasSecurityRuntime({
        targetPath: fp,
        authorizationScope: {
          allowedHosts: [], allowedServices: [], allowedPorts: [],
          allowedEnvironments: ["local"], allowedOperations: ["read"],
          restrictions: ["no-host-execution", "no-credential-theft"],
          allowActiveTesting: false, allowNetworkAccess: false, allowFilesystemWrite: false,
        },
      });
      const ctl = new InvestigationController({ runtime: rt, model: new DeterministicMockModel([]), maxIterations: 20 });
      const res = await ctl.run();
      const elapsed = Date.now() - t0 - results.reduce((a, r) => a + r.durationMs, 0);
      const findings = res.investigation.findings ?? [];
      results.push({ fixture, status: res.errors.length > 0 ? "warn" : "pass", durationMs: elapsed, findings: findings.length, errors: res.errors.length });
      if (!opts.quiet) {
        const icon = res.errors.length > 0 ? warn("⚠") : success("✓");
        process.stdout.write(`${icon} ${findings.length} findings, ${res.errors.length} errors\n`);
      }
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      results.push({ fixture, status: "fail", durationMs: 0, findings: 0, errors: 1 });
      if (!opts.quiet) process.stdout.write(`${error("✗")} ${msg}\n`);
    }
  }

  console.log(divider());
  console.log(benchmarkResults(results));
  const te = results.reduce((a, r) => a + r.errors, 0);
  const _tf = results.reduce((a, r) => a + r.findings, 0);
  if (!te) console.log(success(`  All ${fixtures.length} fixtures passed cleanly.`));
  else console.log(warn(`  ${te} policy error(s) across ${fixtures.length} fixtures.`));
}

// ─── Health command ─────────────────────────────────────────────────────────────

async function runHealth(): Promise<void> {
  const home = homedir();
  const sd = join(home, ".spectra");
  const cfgOk = existsSync(join(sd, "config.json"));
  const binCandidates = [join(home, ".npm-global", "bin", "spectra"), "/usr/local/bin/spectra", "/usr/bin/spectra"];
  const bin = binCandidates.find((p) => existsSync(p)) ?? "";
  const dockerOk = spawnSync("docker", ["version"], { encoding: "utf-8", timeout: 3000 }).status === 0;

  console.log("\n  ╔══════════════════════════════════════════════════════════════╗");
  console.log("  ║         🔍  SPECTRA HEALTH CHECK                            ║");
  console.log("  ╚══════════════════════════════════════════════════════════════╝\n");

  console.log("  ENVIRONMENT");
  console.log(`    Node.js       ${process.version.slice(1)} ${parseInt(process.version.slice(1)) >= 20 ? success("") : error("REQUIRED >= 20")}`);
  const npmV = spawnSync("npm", ["--version"], { encoding: "utf-8" }).stdout.trim();
  console.log(`    npm           ${npmV}`);
  console.log(`    Home          ${home}`);
  console.log(`    Spectra dir   ${sd} ${cfgOk ? success("✓") : warn("○ run 'spectra init'")}`);
  console.log("");

  console.log("  INSTALLATION");
  if (bin && existsSync(bin)) {
    console.log(`    Binary        ✓ ${bin}`);
    const vOut = spawnSync(bin, ["--version"], { encoding: "utf-8", timeout: 5000 }).stdout.trim().split("\n")[0];
    console.log(`    Version       ${vOut || "?"}`);
  } else {
    console.log("    Binary        " + error("NOT FOUND"));
    console.log("    Hint:         export PATH=\"$HOME/.npm-global/bin:$PATH\"");
  }
  console.log("");

  console.log("  DEPENDENCIES");
  console.log(`    Docker        ${dockerOk ? success("available") : warn("not installed (fallback enabled)")}`);
  console.log(`    TypeScript    ${success("bundled")}`);
  console.log("");

  const issues: string[] = [];
  const warnings: string[] = [];
  if (parseInt(process.version.slice(1)) < 20) issues.push("Node.js < 20 (minimum required)");
  if (!bin || !existsSync(bin)) issues.push("spectra binary not in known paths — re-run 'NPM_CONFIG_PREFIX=$HOME/.npm-global npm install -g @hilbras/spectra'");
  if (!cfgOk) warnings.push("No config — run 'spectra init'");
  if (!dockerOk) warnings.push("Docker unavailable — sandbox uses process fallback");

  if (issues.length) { console.log("  ❌ ISSUES"); for (const i of issues) console.log(`    • ${i}`); console.log(""); }
  if (warnings.length) { console.log("  ⚠ WARNINGS"); for (const w of warnings) console.log(`    • ${w}`); console.log(""); }
  if (!issues.length && !warnings.length) console.log(success("  ✓ Everything looks good!"));
  else if (!issues.length) console.log(success("  ✓ Installation healthy (non-critical warnings above)."));
  else console.log(error("  ✗ Issues found — see above."));
  console.log("");
}

// ─── Projects command ───────────────────────────────────────────────────────────

function runProjects(action?: string, name?: string, path_?: string): void {
  if (action === "add") {
    if (!name || !path_) { console.error(error("Usage: spectra projects add <name> <path>")); process.exit(1); }
    const cfg = loadConfig(); cfg.profiles ??= {}; cfg.profiles[name] = { path: path_, tags: [], lastAudit: new Date().toISOString() };
    saveConfig(cfg); console.log(success(`  Project "${name}" added.`));
  } else if (action === "remove") {
    if (!name) { console.error(error("Usage: spectra projects remove <name>")); process.exit(1); }
    const cfg = loadConfig(); delete cfg.profiles?.[name]; saveConfig(cfg);
    console.log(success(`  Project "${name}" removed.`));
  } else {
    console.log(section("📁 PROJECTS"));
    const profiles = loadConfig().profiles ?? {};
    if (!Object.keys(profiles).length) { console.log(warn("  No profiles configured. Use: spectra projects add <name> <path>")); return; }
    for (const [n, p] of Object.entries(profiles)) {
      const la = p.lastAudit ? new Date(p.lastAudit).toLocaleString() : "never";
      console.log(`    ${c(n, C.cyan)}  ${p.path}`);
      console.log(`         Last audit: ${la}`);
    }
  }
}

// ─── Config command ─────────────────────────────────────────────────────────────

function runConfig(action?: string, key?: string, value?: string): void {
  const cfg = loadConfig();
  if (action === "set") {
    if (!key || value === undefined) { console.error(error("Usage: spectra config set <key> <value>")); process.exit(1); }
    (cfg as any)[key] = value; saveConfig(cfg);
    console.log(success(`  "${key}" = "${value}"`));
  } else if (action === "get") {
    if (!key) { console.error(error("Usage: spectra config get <key>")); process.exit(1); }
    console.log(JSON.stringify((cfg as any)[key], null, 2));
  } else {
    console.log(section("⚙️ CONFIGURATION"));
    console.log(JSON.stringify(cfg, null, 2));
  }
}

// ─── Login command ──────────────────────────────────────────────────────────────

async function runLogin(providerId?: string, opts: { key?: string; list?: boolean; remove?: string } = {}): Promise<void> {
  console.log(section("🔑 AUTH CONFIGURATION"));

  const PROVIDERS = [
    { id: "openai",   name: "OpenAI",        url: "https://platform.openai.com/api-keys" },
    { id: "anthropic",name: "Anthropic",     url: "https://console.anthropic.com/settings/keys" },
    { id: "groq",     name: "Groq",          url: "https://console.groq.com/keys" },
    { id: "ollama",   name: "Ollama (local)",url: "http://localhost:11434" },
  ] as const;

  if (opts.list) {
    const keys = loadConfig().apiKeys ?? {};
    if (!Object.keys(keys).length) { console.log(warn("  No API keys configured.\n  Set one: spectra login openai")); return; }
    for (const p of PROVIDERS) {
      const has = !!keys[p.id];
      const masked = has ? keys[p.id]!.slice(0, 4) + "..." + keys[p.id]!.slice(-4) : "—";
      console.log(`    ${has ? success("✓") : warn("○")} ${p.name.padEnd(22)} ${masked}`);
    }
    return;
  }

  if (opts.remove) {
    const cfg = loadConfig(); cfg.apiKeys ??= {}; delete cfg.apiKeys[opts.remove]; saveConfig(cfg);
    console.log(success(`  Removed ${opts.remove} credentials.`));
    return;
  }

  const pid = providerId ?? "openai";
  const prov = PROVIDERS.find((p) => p.id === pid);
  if (!prov) { console.error(error(`Unknown provider: ${pid}. Available: ${PROVIDERS.map((p) => p.id).join(", ")}`)); process.exit(1); }

  console.log(`  Provider: ${prov.name}`);
  console.log(`  Docs:     ${prov.url}`);

  let apiKey = opts.key;
  if (!apiKey) {
    if (process.stdin.isTTY) {
      process.stdout.write(`\n  Enter ${prov.name} API key: `);
      apiKey = await new Promise<string>((resolve) => {
        const h = (d: Buffer) => { process.stdin.removeListener("data", h); resolve(d.toString().trim()); };
        process.stdin.once("data", h);
      });
    } else {
      const chunks: string[] = [];
      await new Promise<void>((resolve) => {
        process.stdin.on("data", (d: Buffer) => chunks.push(d.toString()));
        process.stdin.on("end", () => resolve());
      });
      apiKey = chunks.join("").trim();
    }
  }

  if (!apiKey || apiKey.length < 8) { console.log(warn("  Invalid or empty key. Skipping.")); return; }

  const cfg = loadConfig(); cfg.apiKeys ??= {}; cfg.apiKeys[prov.id] = apiKey;
  if (prov.id === "openai") cfg.defaultModel = "openai";
  else if (prov.id === "anthropic") cfg.defaultModel = "anthropic";
  else if (prov.id === "groq") cfg.defaultModel = "groq";
  else if (prov.id === "ollama") cfg.defaultModel = "ollama";
  saveConfig(cfg);
  console.log(success(`  ✓ ${prov.name} key saved to ~/.spectra/config.json`));
}

// ─── Init command ───────────────────────────────────────────────────────────────

function runInit(): void {
  const dir = join(homedir(), ".spectra");
  mkdirSync(dir, { recursive: true });
  const cf = join(dir, "config.json");
  if (!existsSync(cf)) saveConfig({ defaultModel: "mock", defaultFormat: "json", autoApproveThreshold: "medium" });
  mkdirSync(join(dir, "data"), { recursive: true });
  console.log(success(`  Initialized ${dir}`));
  console.log("  Use 'spectra config show' to view settings.");
}

// ─── Version command ────────────────────────────────────────────────────────────

function runVersion(): void {
  console.log(`Hilbras Spectra v0.0.6`);
  console.log("Package: @hilbras/spectra@0.0.6");
  console.log("CLI: spectra");
}

// ─── Main ──────────────────────────────────────────────────────────────────────

async function main(): Promise<void> {
  const program = new Command();
  program.name("spectra").description("Hilbras Spectra — Autonomous AI Security Research Platform").version("0.0.6");

  program.addHelpText("beforeAll", () => helpBanner("0.0.6"));

  // audit
  program
    .command("audit")
    .description("Run security investigation against a target project")
    .argument("<target>", "Local path or project profile name")
    .option("-n, --dry-run", "Plan-only — no tools executed")
    .option("-m, --model <id>", "AI model (mock, openai, anthropic, groq, ollama)")
    .option("-f, --format <fmt>", "Output format: json, sarif, markdown", "json")
    .option("-d, --depth <level>", "Investigation depth: quick, full", "full")
    .option("-o, --output <path>", "Write report to file")
    .option("-q, --quiet", "Suppress progress output", false)
    .action(async (target: string, opts: any) => await runAudit(target, opts));

  // findings
  program
    .command("findings")
    .description("Browse findings from past audits")
    .option("--severity <level>", "Filter: low, medium, high, critical")
    .option("--limit <n>", "Max findings", "50")
    .option("--project <name>", "Filter by project")
    .option("--recent <n>", "Only last N audits")
    .action(runFindings);

  // history
  program
    .command("history")
    .description("List and inspect past audit results")
    .option("--project <name>", "Filter by project")
    .option("--last <n>", "Show last N audits")
    .option("--show <target>", "Show details for specific audit")
    .action(runHistory);

  // report
  program
    .command("report")
    .description("Generate report from saved investigation data")
    .argument("<id-or-target>", "Audit ID or project name")
    .option("-f, --format <fmt>", "Output format: json, sarif, markdown", "json")
    .option("-o, --output <path>", "Write report to file")
    .action(runReport);

  // benchmarks
  program
    .command("benchmarks")
    .description("Run all 5 benchmark fixtures and report results")
    .option("-q, --quiet", "Minimal output")
    .action(runBenchmarks);

  // health
  program
    .command("health")
    .description("Diagnose installation and environment")
    .action(runHealth);

  // projects
  program
    .command("projects")
    .description("Manage project profiles")
    .argument("[action]", "add, remove, or list")
    .argument("[name]", "Profile name")
    .argument("[path]", "Project path")
    .action(runProjects);

  // config
  program
    .command("config")
    .description("View and edit configuration")
    .argument("[action]", "show, set, get")
    .argument("[key]", "Config key")
    .argument("[value]", "Config value")
    .action(runConfig);

  // login
  program
    .command("login")
    .description("Configure AI provider API keys")
    .argument("[provider]", "openai, anthropic, groq, ollama")
    .option("-k, --key <key>", "API key value (or pipe via stdin)")
    .option("-l, --list", "Show configured keys")
    .option("-r, --remove <provider>", "Remove a provider's key")
    .action(async (provider: string, opts: any) => await runLogin(provider, opts));

  // init
  program
    .command("init")
    .description("Initialize ~/.spectra/ configuration directory")
    .action(runInit);

  // version
  program
    .command("version")
    .description("Show version information")
    .action(runVersion);

  try { await program.parseAsync(process.argv); }
  catch (err: unknown) {
    const msg = err instanceof Error ? err.message : String(err);
    console.error(error("Failed to run spectra:"), msg);
    process.exit(1);
  }
}

main().catch((err) => { console.error(error("Fatal error:"), err); process.exit(1); });
