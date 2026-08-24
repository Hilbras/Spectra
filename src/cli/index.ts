#!/usr/bin/env node
/**
 * Hilbras Spectra — Full Production CLI with Theming
 * 
 * spectra audit <target> [options]      Run security investigation
 * spectra findings [options]            Browse past findings
 * spectra history [options]             List audit history
 * spectra report <id> [options]         Generate report from saved data
 * spectra benchmarks [--quiet]          Run all fixture benchmarks
 * spectra health                        Diagnose installation
 * spectra projects [action] [name] [path] Manage project profiles
 * spectra config [action] [key] [value]   View/edit configuration
 * spectra login [provider] [options]      Configure AI provider keys
 * spectra init                            Initialize ~/.spectra/
 * spectra theme [dark|light]              Switch color theme
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
import { appendAudit, findAudits, getAuditById } from "./store.js";
import type { StoredAudit } from "./types.js";
import {
  t, bold, dim, goldBox, section, divider, endSection,
  scoreMeter, sevBadge, findingTable, auditList, benchmarkResults, helpBanner,
  setTheme, getActiveThemeName, ThemeName, getTheme,
} from "./themes.js";

const VERSION = "0.0.6";

// Theme color shorthand aliases
const ok  = (s: string) => t("success", s);
const fail= (s: string) => t("error", s);
const awarn = (s: string) => t("warning", s);
const ainfo = (s: string) => t("info", s);

// ─── Helpers ───────────────────────────────────────────────────────────────────

function getFormatter(format: string): ReportFormatter {
  switch (format) {
    case "sarif": return new SarifReportFormatter();
    case "markdown": return new MarkdownReportFormatter();
    default: return new JsonReportFormatter();
  }
}

function buildSummary(result: { investigation: any }): {
  overallScore: number; criticalCount: number; highCount: number;
  mediumCount: number; lowCount: number; informationalCount: number;
  confirmedCount: number; potentialCount: number; hypothesisCount: number; evidenceCount: number;
  topRisks: Array<{ title: string; severity: string; category: string }>;
} {
  const findings = result.investigation.findings ?? [];
  const hypotheses = result.investigation.hypotheses ?? [];
  const bySev: Record<string, number> = {};
  for (const f of findings) bySev[f.severity] = (bySev[f.severity] ?? 0) + 1;
  const score = Math.max(0, 100 - (bySev.critical ?? 0) * 25 - (bySev.high ?? 0) * 15 - (bySev.medium ?? 0) * 8 - (bySev.low ?? 0) * 3);
  const topRisks = findings
    .filter((f: any) => f.severity === "critical" || f.severity === "high")
    .slice(0, 5)
    .map((f: any) => ({ title: f.title, severity: f.severity, category: f.category }));
  return {
    overallScore: score, criticalCount: bySev.critical ?? 0, highCount: bySev.high ?? 0,
    mediumCount: bySev.medium ?? 0, lowCount: bySev.low ?? 0,
    informationalCount: bySev.informational ?? 0,
    confirmedCount: findings.filter((f: any) => f.status === "confirmed").length,
    potentialCount: findings.filter((f: any) => f.status === "potential").length,
    hypothesisCount: hypotheses.length, evidenceCount: 0, topRisks,
  };
}

function summaryPanel(target: string, result: any, meta: { durationMs: number; iterations: number; model: string; format: string }): string {
  const findings = result?.investigation?.findings ?? [];
  const hypotheses = result?.investigation?.hypotheses ?? [];
  const bySev: Record<string, number> = {};
  for (const f of findings) bySev[f.severity] = (bySev[f.severity] ?? 0) + 1;
  const score = Math.max(0, 100 - (bySev.critical ?? 0) * 25 - (bySev.high ?? 0) * 15 - (bySev.medium ?? 0) * 8 - (bySev.low ?? 0) * 3);
  const lines: string[] = [];
  lines.push(t("goldBright", `\n  TARGET     ${(target.split("/").pop() ?? target).padEnd(40)}`));
  lines.push(`${t("bold", "  STATUS")}    ${(result?.investigation?.status === "completed" ? t("success", "✓ Completed") : awarn(result?.investigation?.status ?? "?"))}`);
  lines.push(`${t("bold", "  DURATION")}  ${(meta.durationMs / 1000).toFixed(2)}s`);
  lines.push(`${t("bold", "  ITERATIONS")} ${String(meta.iterations)}`);
  lines.push(`${t("bold", "  MODEL")}     ${t("cyan", meta.model)}`);
  lines.push("");
  lines.push(t("bold", "  SECURITY SCORE"));
  const filled = Math.round((score / 100) * 40);
  lines.push(`    ${t("green", "█".repeat(filled))}${t("brightBlack", "░".repeat(40 - filled))} ${bold("green", `${score}/100`)}`);
  lines.push("");
  lines.push(t("bold", "  FINDINGS"));
  if (bySev.critical) lines.push(`    ${t("error", `● ${bySev.critical} Critical`)}`);
  if (bySev.high) lines.push(`    ${t("brightRed", `● ${bySev.high} High`)}`);
  if (bySev.medium) lines.push(`    ${t("warning", `● ${bySev.medium} Medium`)}`);
  if (bySev.low) lines.push(`    ${t("blue", `● ${bySev.low} Low`)}`);
  if (bySev.informational) lines.push(`    ${t("brightBlack", `● ${bySev.informational} Info`)}`);
  if (!Object.keys(bySev).length) lines.push(`    ${t("success", "None detected")}`);
  lines.push("");
  lines.push(`${t("bold", "  HYPOTHESES")} ${String(hypotheses.length)}`);
  return lines.join("\n");
}

// ─── Audit command ─────────────────────────────────────────────────────────────

async function runAudit(target: string, opts: { dryRun?: boolean; model?: string; format?: string; depth?: string; output?: string; quiet?: boolean }): Promise<void> {
  let resolved = target;
  if (!existsSync(target)) {
    const cfg = loadConfig();
    const p = cfg.profiles?.[target];
    if (p) resolved = p.path;
    else { console.error(fail(`Target not found: ${target}`)); process.exit(1); }
  }

  const fmt = opts.format ?? loadConfig().defaultFormat ?? "json";
  const maxIter = opts.depth === "quick" ? 20 : 50;
  const modelId = opts.model ?? loadConfig().defaultModel ?? "mock";

  if (!opts.quiet) {
    console.log(section(`🔍 SPECTRA AUDIT — ${resolved}`));
    console.log(`${t("bold", "  Target")}     ${resolved}`);
    console.log(`${t("bold", "  Mode")}       ${opts.dryRun ? t("yellow", "DRY-RUN") : "full"}`);
    console.log(`${t("bold", "  Model")}      ${t("cyan", modelId)}`);
    console.log(`${t("bold", "  Depth")}      ${opts.depth ?? "full"}`);
    console.log(`${t("bold", "  Format")}     ${t("magenta", fmt.toUpperCase())}`);
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

  const { createModelAdapter } = await import("../investigation/adapters/index.js");
  const model = modelId === "mock"
    ? new DeterministicMockModel([])
    : createModelAdapter();

  if (!opts.quiet) console.log("\n  Starting autonomous investigation...\n");

  const controller = new InvestigationController({ runtime, model, maxIterations: maxIter });
  const result = await controller.run();

  if (!opts.quiet) {
    console.log(divider());
    console.log(summaryPanel(resolved, result, { durationMs: result.durationMs, iterations: result.iterations, model: modelId, format: fmt }));
    if (result.errors.length > 0) {
      console.log(t("yellow", "\n  POLICY NOTES:"));
      for (const e of result.errors.slice(0, 5)) console.log(`    ${awarn(e)}`);
    }
  }

  const findings = result.investigation.findings ?? [];
  const hypotheses = result.investigation.hypotheses ?? [];
  const bySev: Record<string, number> = {};
  for (const f of findings) bySev[f.severity] = (bySev[f.severity] ?? 0) + 1;
  const score = Math.max(0, 100 - (bySev.critical ?? 0) * 25 - (bySev.high ?? 0) * 15 - (bySev.medium ?? 0) * 8 - (bySev.low ?? 0) * 3);

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
        rootCause: f.rootCause ?? undefined, description: f.description ?? undefined,
      })),
      hypotheses: hypotheses.map((h: any) => ({
        id: h.id, category: h.category, claim: h.claim,
        confidence: h.confidence, status: h.status,
      })),
      evidence: [],
    } as any,
    summary: {
      overallScore: score, criticalCount: bySev.critical ?? 0, highCount: bySev.high ?? 0,
      mediumCount: bySev.medium ?? 0, lowCount: bySev.low ?? 0,
      informationalCount: bySev.informational ?? 0,
      confirmedCount: findings.filter((f: any) => f.status === "confirmed").length,
      potentialCount: findings.filter((f: any) => f.status === "potential").length,
      hypothesisCount: hypotheses.length, evidenceCount: 0,
      topRisks: findings.filter((f: any) => f.severity === "critical" || f.severity === "high").slice(0, 5).map((f: any) => ({ title: f.title, severity: f.severity, category: f.category })),
    },
  };
  appendAudit(meta);

  const sd = join(resolved, ".spectra");
  if (!existsSync(sd)) mkdirSync(sd, { recursive: true });
  writeFileSync(join(sd, `audit-${Date.now()}.json`), JSON.stringify(meta, null, 2), "utf-8");

  const formatter = getFormatter(fmt);
  const reportContent = formatter.generate(result.investigation, findings);
  if (opts.output) {
    const outDir = join(opts.output, "..");
    if (!existsSync(outDir)) mkdirSync(outDir, { recursive: true });
    writeFileSync(opts.output, reportContent, "utf-8");
    if (!opts.quiet) console.log(ok(`  Report written to ${opts.output}`));
  } else if (!opts.quiet) {
    console.log(section("📄 REPORT"));
    process.stdout.write(reportContent + "\n");
  }

  if (!opts.quiet) console.log(ok(`  Investigation saved to ${join(sd, "audit-" + Date.now() + ".json")}`));

  const hasHigh = findings.some((f: any) => f.severity === "high" || f.severity === "critical");
  process.exit(hasHigh ? 1 : 0);
}

// ─── Findings ───────────────────────────────────────────────────────────────────

function runFindings(opts: { severity?: string; limit?: string; project?: string; recent?: string }): void {
  console.log(section("📋 FINDINGS BROWSER"));
  const audits = findAudits({
    ...(opts.project ? { target: opts.project } : {}),
    ...(opts.severity ? { severity: opts.severity } : {}),
    ...(opts.recent ? { last: parseInt(opts.recent) } : {}),
    ...(opts.limit ? { limit: parseInt(opts.limit) } : {}),
  });

  if (!audits.length) { console.log(awarn("  No findings found. Run 'spectra audit <target>' first.")); return; }

  const all: Array<{ at: string; ad: string; f: any }> = [];
  for (const a of audits) {
    for (const f of a.investigation?.findings ?? []) all.push({ at: a.target, ad: new Date(a.generatedAt).toLocaleString(), f });
  }

  let display = all;
  if (opts.severity) {
    display = all.filter((x) => x.f.severity === opts.severity);
    console.log(dim("brightBlack", `  Showing ${display.length} ${opts.severity.toUpperCase()}+ findings`));
  }
  if (!display.length) { console.log(awarn("  No matching findings.")); return; }

  console.log(findingTable(display.map((x) => x.f)));
  console.log(dim("brightBlack", `  ${all.length} total across ${audits.length} audits`));
}

// ─── History ────────────────────────────────────────────────────────────────────

function runHistory(opts: { project?: string; limit?: string; last?: string; show?: string }): void {
  console.log(section("📜 AUDIT HISTORY"));
  let audits = findAudits({
    ...(opts.project ? { target: opts.project } : {}),
    ...(opts.last ? { last: parseInt(opts.last) } : {}),
    ...(opts.limit ? { limit: parseInt(opts.limit) } : {}),
  });

  if (opts.show) {
    const m = audits.find((a) => a.target.includes(opts.show!) || String((a.investigation as any).projectId)?.includes(opts.show!));
    if (!m) { console.error(fail(`  No audit found matching "${opts.show}"`)); return; }
    printAuditDetail(m);
    return;
  }

  if (!audits.length) { console.log(awarn("  No history found. Run 'spectra audit <target>' first.")); return; }
  console.log(auditList(audits));
  console.log(dim("brightBlack", `  ${audits.length} audit(s) stored  —  Options: --project <name>  --last <n>  --show <target>`));
}

function printAuditDetail(a: StoredAudit): void {
  const inv = a.investigation as any;
  const findings = inv?.findings ?? [];
  const hyps = inv?.hypotheses ?? [];
  console.log(t("green", `  Target:      ${a.target}`));
  console.log(`  Date:         ${new Date(a.generatedAt).toLocaleString()}`);
  console.log(`  Status:       ${inv?.status === "completed" ? t("success", "✓ Completed") : awarn(inv?.status ?? "?")}`);
  console.log(`  Iterations:   ${a.iterations}`);
  console.log(`  Duration:     ${(a.durationMs / 1000).toFixed(2)}s`);
  console.log(`  Model:        ${a.model}`);
  if (findings.length) {
    console.log(t("bold", "\n  FINDINGS:"));
    for (const f of findings) console.log(`    ${sevBadge(f.severity, true)} ${(f.title ?? "").slice(0, 60)}`);
  } else console.log(t("success", "  No findings detected."));
  if (hyps.length) {
    console.log(t("bold", "\n  HYPOTHESES:"));
    for (const h of hyps.slice(0, 5)) console.log(t("cyan", `    [${h.status}] ${h.category}: ${(h.claim ?? "").slice(0, 70)}`));
  }
}

// ─── Report ─────────────────────────────────────────────────────────────────────

function runReport(idOrTarget: string, opts: { format?: string; output?: string }): void {
  console.log(section("📄 REPORT GENERATOR"));
  let audit = getAuditById(idOrTarget);
  if (!audit) audit = findAudits({ target: idOrTarget, limit: 1 })[0] ?? null;
  if (!audit) audit = findAudits({ limit: 1 })[0] ?? null;
  if (!audit) { console.error(fail("  No saved audits found. Run 'spectra audit <target>' first.")); process.exit(1); }

  const inv = audit.investigation as any;
  const fmt = opts.format ?? "json";
  const formatter = getFormatter(fmt);
  const report = formatter.generate(inv, inv?.findings ?? []);

  if (opts.output) {
    const d = join(opts.output, "..");
    if (!existsSync(d)) mkdirSync(d, { recursive: true });
    writeFileSync(opts.output, report, "utf-8");
    console.log(ok(`  Report written to ${opts.output}`));
  } else {
    process.stdout.write(report + "\n");
  }
}

// ─── Benchmarks ─────────────────────────────────────────────────────────────────

async function runBenchmarks(opts: { quiet?: boolean }): Promise<void> {
  const cwd = process.cwd();
  const fd = join(cwd, "tests", "fixtures");
  if (!existsSync(fd)) {
    console.log(section("🧪 BENCHMARKS"));
    console.log(awarn("  No tests/fixtures directory. Run from the Spectra source repo."));
    return;
  }

  const fixtures = readdirSync(fd).filter((f) => existsSync(join(fd, f, "README.md"))).sort();
  if (!fixtures.length) { console.log(awarn("  No benchmark fixtures found.")); return; }

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
        const icon = res.errors.length > 0 ? awarn("⚠") : t("success", "✓");
        process.stdout.write(`${icon} ${findings.length} findings, ${res.errors.length} errors\n`);
      }
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      results.push({ fixture, status: "fail", durationMs: 0, findings: 0, errors: 1 });
      if (!opts.quiet) process.stdout.write(`${fail("✗")} ${msg}\n`);
    }
  }

  console.log(divider());
  console.log(benchmarkResults(results));
  const te = results.reduce((a, r) => a + r.errors, 0);
  if (!te) console.log(ok(`  All ${fixtures.length} fixtures passed cleanly.`));
  else console.log(awarn(`  ${te} policy fail(s) across ${fixtures.length} fixtures.`));
}

// ─── Health ─────────────────────────────────────────────────────────────────────

async function runHealth(): Promise<void> {
  const home = homedir();
  const sd = join(home, ".spectra");
  const cfgOk = existsSync(join(sd, "config.json"));
  const binCandidates = [join(home, ".npm-global", "bin", "spectra"), "/usr/local/bin/spectra", "/usr/bin/spectra"];
  const bin = binCandidates.find((p) => existsSync(p)) ?? "";
  const dockerOk = spawnSync("docker", ["version"], { encoding: "utf-8", timeout: 3000 }).status === 0;
  const npmV = spawnSync("npm", ["--version"], { encoding: "utf-8" }).stdout.trim();
  const theme = getActiveThemeName();

  console.log(`\n  ${t("goldBright", "╔" + "══════════════════════════════════════════════════════════════".padEnd(68) + "╗")}`);
  console.log(`  ${t("goldBright", "║")}  ${bold("gold", "🔍  SPECTRA HEALTH CHECK")}${" ".repeat(36)}${t("goldBright", "║")}`);
  console.log(`  ${t("goldBright", "╚" + "══════════════════════════════════════════════════════════════".padEnd(68) + "╝")}\n`);

  console.log(t("bold", "  ENVIRONMENT"));
  console.log(`    Node.js       ${process.version.slice(1)} ${parseInt(process.version.slice(1)) >= 20 ? t("success", "✓") : fail("REQUIRED >= 20")}`);
  console.log(`    npm           ${npmV}`);
  console.log(`    Home          ${home}`);
  console.log(`    Spectra dir   ${sd} ${cfgOk ? t("success", "✓") : awarn("○ run 'spectra init'")}`);
  console.log(`    Theme         ${t("cyan", theme)}`);
  console.log("");

  console.log(t("bold", "  INSTALLATION"));
  if (bin && existsSync(bin)) {
    console.log(`    Binary        ✓ ${bin}`);
    const vOut = spawnSync(bin, ["--version"], { encoding: "utf-8", timeout: 5000 }).stdout.trim().split("\n")[0];
    console.log(`    Version       ${vOut || "?"}`);
  } else {
    console.log("    Binary        " + fail("NOT FOUND"));
    console.log("    Hint:         export PATH=\"$HOME/.npm-global/bin:$PATH\"");
  }
  console.log("");

  console.log(t("bold", "  DEPENDENCIES"));
  console.log(`    Docker        ${dockerOk ? t("success", "available") : awarn("not installed (fallback enabled)")}`);
  console.log(`    TypeScript    ${t("success", "bundled")}`);
  console.log("");

  const issues: string[] = [];
  const warnings: string[] = [];
  if (parseInt(process.version.slice(1)) < 20) issues.push("Node.js < 20 (minimum required)");
  if (!bin || !existsSync(bin)) issues.push("spectra binary not in known paths");
  if (!cfgOk) warnings.push("No config — run 'spectra init'");
  if (!dockerOk) warnings.push("Docker unavailable — sandbox uses process fallback");

  if (issues.length) { console.log(t("error", "  ❌ ISSUES")); for (const i of issues) console.log(`    • ${i}`); console.log(""); }
  if (warnings.length) { console.log(t("yellow", "  ⚠ WARNINGS")); for (const w of warnings) console.log(`    • ${w}`); console.log(""); }
  if (!issues.length && !warnings.length) console.log(t("success", "  ✓ Everything looks good!"));
  else if (!issues.length) console.log(t("success", "  ✓ Installation healthy (non-critical warnings above)."));
  else console.log(fail("  ✗ Issues found — see above."));
  console.log("");
}

// ─── Projects ───────────────────────────────────────────────────────────────────

function runProjects(action?: string, name?: string, path_?: string): void {
  if (action === "add") {
    if (!name || !path_) { console.error(fail("Usage: spectra projects add <name> <path>")); process.exit(1); }
    const cfg = loadConfig(); cfg.profiles ??= {}; cfg.profiles[name] = { path: path_, tags: [], lastAudit: new Date().toISOString() };
    saveConfig(cfg); console.log(ok(`  Project "${name}" added.`));
  } else if (action === "remove") {
    if (!name) { console.error(fail("Usage: spectra projects remove <name>")); process.exit(1); }
    const cfg = loadConfig(); delete cfg.profiles?.[name]; saveConfig(cfg);
    console.log(ok(`  Project "${name}" removed.`));
  } else {
    console.log(section("📁 PROJECTS"));
    const profiles = loadConfig().profiles ?? {};
    if (!Object.keys(profiles).length) { console.log(awarn("  No profiles configured. Use: spectra projects add <name> <path>")); return; }
    for (const [n, p] of Object.entries(profiles)) {
      const la = p.lastAudit ? new Date(p.lastAudit).toLocaleString() : "never";
      console.log(`    ${t("cyan", n)}  ${p.path}`);
      console.log(`         Last audit: ${la}`);
    }
  }
}

// ─── Config ─────────────────────────────────────────────────────────────────────

function runConfig(action?: string, key?: string, value?: string): void {
  const cfg = loadConfig();
  if (action === "set") {
    if (!key || value === undefined) { console.error(fail("Usage: spectra config set <key> <value>")); process.exit(1); }
    (cfg as any)[key] = value; saveConfig(cfg);
    console.log(ok(`  "${key}" = "${value}"`));
  } else if (action === "get") {
    if (!key) { console.error(fail("Usage: spectra config get <key>")); process.exit(1); }
    console.log(JSON.stringify((cfg as any)[key], null, 2));
  } else {
    console.log(section("⚙️ CONFIGURATION"));
    console.log(JSON.stringify(cfg, null, 2));
  }
}

// ─── Login ──────────────────────────────────────────────────────────────────────

async function runLogin(providerId?: string, o: { key?: string; list?: boolean; remove?: string } = {}): Promise<void> {
  console.log(section("🔑 AUTH CONFIGURATION"));

  const PROVIDERS = [
    { id: "openai",   name: "OpenAI",        url: "https://platform.openai.com/api-keys" },
    { id: "anthropic",name: "Anthropic",     url: "https://console.anthropic.com/settings/keys" },
    { id: "groq",     name: "Groq",          url: "https://console.groq.com/keys" },
    { id: "ollama",   name: "Ollama (local)",url: "http://localhost:11434" },
  ] as const;

  if (o.list) {
    const keys = loadConfig().apiKeys ?? {};
    if (!Object.keys(keys).length) { console.log(awarn("  No API keys configured.\n  Set one: spectra login openai")); return; }
    for (const p of PROVIDERS) {
      const has = !!keys[p.id];
      const masked = has ? keys[p.id]!.slice(0, 4) + "..." + keys[p.id]!.slice(-4) : "—";
      console.log(`    ${has ? t("success", "✓") : awarn("○")} ${p.name.padEnd(22)} ${masked}`);
    }
    return;
  }

  if (o.remove) {
    const cfg = loadConfig(); cfg.apiKeys ??= {}; delete cfg.apiKeys[o.remove]; saveConfig(cfg);
    console.log(ok(`  Removed ${o.remove} credentials.`));
    return;
  }

  const pid = providerId ?? "openai";
  const prov = PROVIDERS.find((p) => p.id === pid);
  if (!prov) { console.error(fail(`Unknown provider: ${pid}. Available: ${PROVIDERS.map((p) => p.id).join(", ")}`)); process.exit(1); }

  console.log(`  Provider: ${prov.name}`);
  console.log(`  Docs:     ${prov.url}`);

  let apiKey = o.key;
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

  if (!apiKey || apiKey.length < 8) { console.log(awarn("  Invalid or empty key. Skipping.")); return; }

  const cfg = loadConfig(); cfg.apiKeys ??= {}; cfg.apiKeys[prov.id] = apiKey;
  if (prov.id === "openai") cfg.defaultModel = "openai";
  else if (prov.id === "anthropic") cfg.defaultModel = "anthropic";
  else if (prov.id === "groq") cfg.defaultModel = "groq";
  else if (prov.id === "ollama") cfg.defaultModel = "ollama";
  saveConfig(cfg);
  console.log(ok(`  ✓ ${prov.name} key saved to ~/.spectra/config.json`));
}

// ─── Init ───────────────────────────────────────────────────────────────────────

function runInit(): void {
  const dir = join(homedir(), ".spectra");
  mkdirSync(dir, { recursive: true });
  const cf = join(dir, "config.json");
  if (!existsSync(cf)) saveConfig({ defaultModel: "mock", defaultFormat: "json", autoApproveThreshold: "medium" });
  mkdirSync(join(dir, "data"), { recursive: true });
  console.log(ok(`  Initialized ${dir}`));
  console.log("  Use 'spectra config show' to view settings.");
}

// ─── Theme command ──────────────────────────────────────────────────────────────

function runTheme(name?: string): void {
  if (!name) {
    console.log(section("🎨 THEME"));
    console.log(`  Current theme: ${t("goldBright", getActiveThemeName())}`);
    console.log(t("dim", "  Switch with: spectra theme dark | spectra theme light"));
    console.log(t("dim", "  Or set env: SPECTRA_THEME=dark spectra audit ./app"));
    return;
  }
  const normalized = name.toLowerCase();
  if (normalized !== "dark" && normalized !== "light") {
    console.error(fail(`  Unknown theme: ${name}. Use 'dark' or 'light'.`));
    process.exit(1);
  }
  setTheme(normalized as ThemeName);
  // Persist to config
  const cfg = loadConfig();
  (cfg as any).theme = normalized;
  saveConfig(cfg);
  console.log(ok(`  Theme switched to ${t("goldBright", normalized)}.`));
}

// ─── Version ────────────────────────────────────────────────────────────────────

function runVersion(): void {
  console.log(`${t("goldBright", "Hilbras Spectra v" + VERSION)}`);
  console.log(`Package: @hilbras/spectra@${VERSION}`);
  console.log(`CLI: spectra  |  Theme: ${t("cyan", getActiveThemeName())}`);
}

// ─── Main ───────────────────────────────────────────────────────────────────────

async function main(): Promise<void> {
  const program = new Command();
  program.name("spectra").description("Hilbras Spectra — Autonomous AI Security Research Platform").version(VERSION);
  program.addHelpText("beforeAll", () => helpBanner(VERSION));

  // audit
  program.command("audit")
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
  program.command("findings")
    .description("Browse findings from past audits")
    .option("--severity <level>", "Filter: low, medium, high, critical")
    .option("--limit <n>", "Max findings", "50")
    .option("--project <name>", "Filter by project")
    .option("--recent <n>", "Only last N audits")
    .action(runFindings);

  // history
  program.command("history")
    .description("List and inspect past audit results")
    .option("--project <name>", "Filter by project")
    .option("--last <n>", "Show last N audits")
    .option("--show <target>", "Show details for specific audit")
    .action(runHistory);

  // report
  program.command("report")
    .description("Generate report from saved investigation data")
    .argument("<id-or-target>", "Audit ID or project name")
    .option("-f, --format <fmt>", "Output format: json, sarif, markdown", "json")
    .option("-o, --output <path>", "Write report to file")
    .action(runReport);

  // benchmarks
  program.command("benchmarks")
    .description("Run all 5 benchmark fixtures and report results")
    .option("-q, --quiet", "Minimal output")
    .action(runBenchmarks);

  // health
  program.command("health")
    .description("Diagnose installation and environment")
    .action(runHealth);

  // projects
  program.command("projects")
    .description("Manage project profiles")
    .argument("[action]", "add, remove, or list")
    .argument("[name]", "Profile name")
    .argument("[path]", "Project path")
    .action(runProjects);

  // config
  program.command("config")
    .description("View and edit configuration")
    .argument("[action]", "show, set, get")
    .argument("[key]", "Config key")
    .argument("[value]", "Config value")
    .action(runConfig);

  // login
  program.command("login")
    .description("Configure AI provider API keys")
    .argument("[provider]", "openai, anthropic, groq, ollama")
    .option("-k, --key <key>", "API key value (or pipe via stdin)")
    .option("-l, --list", "Show configured keys")
    .option("-r, --remove <provider>", "Remove a provider's key")
    .action(async (provider: string, opts: any) => await runLogin(provider, opts));

  // init
  program.command("init")
    .description("Initialize ~/.spectra/ configuration directory")
    .action(runInit);

  // theme
  program.command("theme")
    .description("Switch color theme (dark or light)")
    .argument("[theme]", "dark or light (current: " + getActiveThemeName() + ")")
    .action(runTheme);

  // version
  program.command("version")
    .description("Show version information")
    .action(runVersion);

  try { await program.parseAsync(process.argv); }
  catch (err: unknown) {
    const msg = err instanceof Error ? err.message : String(err);
    console.error(fail("Failed to run spectra:"), msg);
    process.exit(1);
  }
}

main().catch((err) => { console.error(fail("Fatal error:"), err); process.exit(1); });
