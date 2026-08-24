/**
 * Hilbras Spectra — Dashboard Rendering
 * 
 * Pretty terminal tables, score bars, severity charts, and phased progress.
 */


import type { StoredAudit, AuditMeta, FindingRecord } from "./types.js";

const C = {
  reset: "\x1b[0m", bold: "\x1b[1m", dim: "\x1b[2m",
  red: "\x1b[31m", green: "\x1b[32m", yellow: "\x1b[33m",
  blue: "\x1b[34m", magenta: "\x1b[35m", cyan: "\x1b[36m",
  gray: "\x1b[90m", white: "\x1b[37m",
  bgRed: "\x1b[41m", bgGreen: "\x1b[42m", bgYellow: "\x1b[43m", black: "\x1b[30m",
} as const;

export function c(text: string, color: string): string {
  return `${color}${text}${C.reset}`;
}

// ─── Score meter ──────────────────────────────────────────────────────────────

export function scoreMeter(score: number, width: number = 40): string {
  const filled = Math.round((score / 100) * width);
  const empty = width - filled;
  const bar = C.green.repeat(Math.min(filled, width)) + C.gray.repeat(empty);
  const scoreColor = score >= 80 ? C.green : score >= 50 ? C.yellow : C.red;
  return `${c(bar, "")} ${c(`${score}/100`, scoreColor)}`;
}

// ─── Severity badges ───────────────────────────────────────────────────────────

export function sevBadge(sev: string, compact = false): string {
  const map: Record<string, { bg: string; fg: string; text: string }> = {
    critical:    { bg: C.bgRed, fg: C.white, text: "CRITICAL" },
    high:        { bg: C.bgRed, fg: C.white, text: "HIGH" },
    medium:      { bg: C.bgYellow, fg: C.black, text: "MEDIUM" },
    low:         { bg: C.blue, fg: C.white, text: "LOW" },
    informational: { bg: C.gray, fg: C.white, text: "INFO" },
  };
  const s = map[sev] ?? { bg: C.gray, fg: C.white, text: sev.toUpperCase() };
  if (compact) return c(s.text.padEnd(8), s.bg + s.fg);
  return `${c(s.text, s.bg + s.fg)}`;
}

// ─── Finding table ─────────────────────────────────────────────────────────────

export function findingTable(findings: FindingRecord[]): string {
  if (findings.length === 0) return c("  No findings recorded.", C.dim);
  
  const colW = { sev: 10, cat: 18, comp: 24, title: 0 };
  const rows = findings.map((f) => {
    const comp = f.component ?? "—";
    const title = (f.title ?? "").slice(0, 50);
    return { ...f, component: comp, displayTitle: title };
  });
  
  const titleMax = Math.max(...rows.map((r) => r.displayTitle.length));
  colW.title = Math.min(titleMax, 50);
  const totalWidth = colW.sev + colW.cat + colW.comp + colW.title + 12;
  
  const header = c("  " + "SEVERITY".padEnd(colW.sev) + "CATEGORY".padEnd(colW.cat) + "COMPONENT".padEnd(colW.comp) + "TITLE".padEnd(colW.title), C.bold + C.cyan);
  const sep = c("  " + "─".repeat(totalWidth - 4), C.dim);
  
  const lines = [header, sep];
  for (const f of rows) {
    const sev = sevBadge(f.severity, true);
    const cat = c((f.category ?? "unknown").padEnd(colW.cat), C.cyan);
    const comp = (f.component ?? "—").padEnd(colW.comp);
    const title = (f.displayTitle ?? "").padEnd(colW.title);
    lines.push(`  ${sev} ${cat} ${comp} ${title}`);
  }
  
  return lines.join("\n");
}

// ─── Summary panel ─────────────────────────────────────────────────────────────

export function summaryPanel(
  meta: Pick<AuditMeta, "target" | "durationMs" | "iterations" | "model" | "status"> & {
    summary?: AuditMeta["summary"];
  },
): string {
  const s = meta.summary ?? { overallScore: 100, criticalCount: 0, highCount: 0, mediumCount: 0, lowCount: 0, informationalCount: 0 };
  const sec = (meta.durationMs / 1000).toFixed(1);
  
  const lines: string[] = [];
  lines.push(c("\n  TARGET   ", C.bold) + c((meta.target || "").split("/").pop() ?? meta.target, C.green));
  lines.push(c("  STATUS   ", C.bold) + (meta.status === "completed" ? c("✓ Completed", C.green) : c(meta.status, C.yellow)));
  lines.push(c("  DURATION ", C.bold) + `${sec}s`);
  lines.push(c("  ITERATIONS", C.bold) + ` ${meta.iterations}`);
  lines.push(c("  MODEL    ", C.bold) + c(meta.model, C.cyan));
  lines.push("");
  lines.push(c("  SECURITY SCORE", C.bold));
  lines.push(`    ${scoreMeter(s.overallScore ?? 100)}`);
  lines.push("");
  lines.push(c("  FINDINGS BREAKDOWN", C.bold));
  if (s.criticalCount > 0) lines.push(`    ${c(`● ${s.criticalCount} Critical`, C.red)}`);
  if (s.highCount > 0) lines.push(`    ${c(`● ${s.highCount} High`, "\x1b[91m")}`);
  if (s.mediumCount > 0) lines.push(`    ${c(`● ${s.mediumCount} Medium`, C.yellow)}`);
  if (s.lowCount > 0) lines.push(`    ${c(`● ${s.lowCount} Low`, C.blue)}`);
  if (s.informationalCount > 0) lines.push(`    ${c(`● ${s.informationalCount} Info`, C.gray)}`);
  if (s.criticalCount === 0 && s.highCount === 0 && s.mediumCount === 0 && s.lowCount === 0) {
    lines.push(`    ${c("None detected", C.green)}`);
  }
  lines.push("");
  lines.push(c("  EVIDENCE  ", C.bold) + ` ${(s as any).evidenceCount ?? 0} records`);
  lines.push(c("  HYPOTHESES", C.bold) + ` ${(s as any).hypothesisCount ?? 0} generated`);
  
  return lines.join("\n");
}

// ─── Phase progress ────────────────────────────────────────────────────────────

const PHASES = [
  "INIT", "RECON", "ARCH", "SURFACE", "SOURCE", "DEPS", "CONFIG", "SECRETS",
  "AUTHN", "AUTHZ", "API", "LOGIC", "HYPOTHESIS", "INVESTIGATE", "VALIDATE",
  "EVIDENCE", "CORRELATE", "RISK", "REPORT", "DONE",
];

export function phaseProgress(current: string, completed: string[]): string {
  const currentIdx = PHASES.findIndex((p) => current.toUpperCase().includes(p.toUpperCase()) || p === current.toUpperCase());
  const arrows = PHASES.map((_, i) => {
    if (i < currentIdx || PHASES[i] && completed.includes(PHASES[i]!)) return c("●", C.green);
    if (i === currentIdx) return c("●", C.yellow);
    return c("○", C.gray);
  }).join(" ");
  return `  Phases: ${arrows}\n         Current: ${c(current, C.cyan)}`;
}

// ─── Audit list (for history) ──────────────────────────────────────────────────

export function auditList(audits: StoredAudit[]): string {
  if (audits.length === 0) return c("  No audits found. Run 'spectra audit' first.", C.dim);
  
  const header = c("  " + "DATE".padEnd(22) + "TARGET".padEnd(28) + "FINDINGS".padEnd(12) + "SCORE".padEnd(8) + "STATUS", C.bold + C.cyan);
  const sep = c("  " + "─".repeat(80), C.dim);
  const lines = [header, sep];
  
  for (const a of audits.slice(0, 15)) {
    const date = new Date(a.generatedAt).toLocaleString("en-US", { month: "short", day: "2-digit", hour: "2-digit", minute: "2-digit" });
    const target = ((a.target || "").split("/").pop() ?? a.target).slice(0, 26);
    const f = a.investigation?.findings ?? [];
    const critical = f.filter((x) => x.severity === "critical").length;
    const high = f.filter((x) => x.severity === "high").length;
    const findingsStr = f.length > 0 ? c(`${f.length}`, critical > 0 || high > 0 ? C.red : C.yellow) : c("0", C.green);
    const score = a.summary?.overallScore ?? 100;
    const scoreStr = score >= 80 ? c(`${score}`, C.green) : score >= 50 ? c(`${score}`, C.yellow) : c(`${score}`, C.red);
    lines.push(`  ${date.padEnd(22)} ${target.padEnd(28)} ${findingsStr.padEnd(12)} ${scoreStr.padEnd(8)} ${c(a.investigation?.status ?? "?", C.gray)}`);
  }
  
  return lines.join("\n");
}

// ─── Benchmark results ─────────────────────────────────────────────────────────

export function benchmarkResults(results: Array<{ fixture: string; status: string; durationMs: number; findings: number; errors: number }>): string {
  const header = c("  " + "FIXTURE".padEnd(28) + "STATUS".padEnd(10) + "TIME".padEnd(8) + "FINDINGS".padEnd(10) + "ERRORS", C.bold + C.cyan);
  const sep = c("  " + "─".repeat(65), C.dim);
  const lines = [header, sep];
  
  let totalFindings = 0;
  let totalErrors = 0;
  for (const r of results) {
    totalFindings += r.findings;
    totalErrors += r.errors;
    const status = r.errors > 0 ? c("WARN", C.yellow) : r.findings > 0 ? c("OK", C.red) : c("OK", C.green);
    const time = `${(r.durationMs / 1000).toFixed(2)}s`;
    lines.push(`  ${(r.fixture ?? "").padEnd(28)} ${status.padEnd(10)} ${time.padEnd(8)} ${r.findings.toString().padEnd(10)} ${r.errors > 0 ? c(`${r.errors}`, C.yellow) : "0"}`);
  }
  
  lines.push("");
  lines.push(c("  TOTAL:", C.bold) + ` ${totalFindings} findings, ${totalErrors} errors across ${results.length} fixtures`);
  return lines.join("\n");
}

// ─── Help banner ───────────────────────────────────────────────────────────────

export function helpBanner(version: string): string {
  return [
    c("\n  ╔══════════════════════════════════════════════════════════╗", C.cyan),
    c("  ║          🔍  HILBRAS SPECTRA v" + version.padEnd(24) + "   ║", C.bold + C.cyan),
    c("  ║        Autonomous AI Security Research Platform          ║", C.cyan),
    c("  ╚══════════════════════════════════════════════════════════╝\n", C.cyan),
    "",
    c("  QUICK START", C.bold),
    "    spectra audit ./my-app              Run security investigation",
    "    spectra audit ./my-app -d quick      Fast scan (20 iterations)",
    "    spectra audit ./my-app -f sarif     SARIF report for CI/CD",
    "    spectra benchmarks                  Run against all test fixtures",
    "",
    c("  COMMANDS", C.bold),
    "    audit <target> [options]             Run investigation",
    "    findings [options]                   Browse recent findings",
    "    history [options]                    List past audits",
    "    report <id> [options]               Generate report from saved data",
    "    benchmarks                           Run all 5 fixture benchmarks",
    "    health                               Check installation status",
    "    projects [action] [name] [path]      Manage project profiles",
    "    config [action] [key] [value]        View/edit configuration",
    "    login                                Configure AI provider keys",
    "    init                                 Initialize ~/.spectra/",
    "    version                              Show version info",
    "",
    c("  AUDIT OPTIONS", C.bold),
    "    -d, --depth <quick|full>    Investigation depth (default: full)",
    "    -f, --format <json|sarif|md> Output format (default: json)",
    "    -m, --model <id>            AI model (mock, openai, anthropic)",
    "    -n, --dry-run               Plan-only, no tools executed",
    "    -o, --output <path>         Write report to file",
    "    -q, --quiet                 Suppress progress output",
    "",
    c("  EXAMPLES", C.bold),
    "    spectra audit ~/projects/my-webapp",
    "    spectra audit ~/projects/my-webapp -d quick -f sarif -o report.sarif",
    "    spectra findings --severity high --limit 10",
    "    spectra history --project my-webapp --last 5",
    "    spectra benchmarks",
    "    spectra health",
    "",
  ].join("\n");
}

// ─── Loading spinner ───────────────────────────────────────────────────────────

const SPINNER = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];
let _spinIdx = 0;
let _spinTimer: ReturnType<typeof setInterval> | null = null;

export function startSpinner(msg: string): void {
  process.stdout.write(`  ${msg} `);
  _spinTimer = setInterval(() => {
    process.stdout.write(`\r  ${SPINNER[_spinIdx % SPINNER.length]} ${msg}  `);
    _spinIdx++;
  }, 80);
}

export function stopSpinner(success = true): void {
  if (_spinTimer) clearInterval(_spinTimer);
  const icon = success ? c("✓", C.green) : c("✗", C.red);
  process.stdout.write(`\r  ${icon} Done.\n\n`);
}

export function clearSpinner(): void {
  if (_spinTimer) clearInterval(_spinTimer);
  process.stdout.write("\r" + " ".repeat(60) + "\r");
}

// ─── Confirm prompt ────────────────────────────────────────────────────────────

export function confirm(prompt: string): Promise<boolean> {
  return new Promise((resolve) => {
    process.stdout.write(`\n${c(prompt + " ", C.yellow)}${c("[y/N]", C.dim)} `);
    const handler = (data: Buffer) => {
      const input = data.toString().trim().toLowerCase();
      process.stdin.removeListener("data", handler);
      resolve(input === "y" || input === "yes");
    };
    process.stdin.once("data", handler);
  });
}

// ─── Select prompt ─────────────────────────────────────────────────────────────

export function select(prompt: string, items: string[]): Promise<number> {
  return new Promise((resolve) => {
    let sel = 0;
    let input = "";
    
    function render() {
      process.stdout.write(`\n${c(prompt, C.bold)}\n\n`);
      items.forEach((item, i) => {
        const arrow = i === sel ? c("▶", C.green) : " ";
        const line = i === sel ? c(item, C.white) : item;
        process.stdout.write(`  ${arrow} ${line}\n`);
      });
      process.stdout.write(`\n  ${c("↑↓ navigate  •  Enter select  •  Esc cancel", C.dim)}\n`);
    }
    
    render();
    
    function handler(data: Buffer) {
      input = data.toString();
      if (input === "k" || input === "up" || input === "A") {
        sel = Math.max(0, sel - 1);
        render();
      } else if (input === "j" || input === "down" || input === "B") {
        sel = Math.min(items.length - 1, sel + 1);
        render();
      } else if (input === "\r" || input === " ") {
        process.stdin.removeListener("data", handler);
        resolve(sel);
      } else if (input === "u" || input === "escape" || input === "\x03") {
        process.stdin.removeListener("data", handler);
        resolve(-1);
      }
    }
    process.stdin.on("data", handler);
  });
}

// ─── Text prompt ───────────────────────────────────────────────────────────────

export function ask(prompt: string, defaultVal = ""): Promise<string> {
  return new Promise((resolve) => {
    process.stdout.write(`\n${c(prompt + " ", C.yellow)}${defaultVal ? c(`[${defaultVal}]`, C.dim) : ""} `);
    const handler = (data: Buffer) => {
      const val = data.toString().trim() || defaultVal;
      process.stdin.removeListener("data", handler);
      resolve(val);
    };
    process.stdin.once("data", handler);
  });
}

// ─── Divider ───────────────────────────────────────────────────────────────────

export function divider(): string {
  return c("  " + "─".repeat(68), C.dim);
}

export function section(title: string): string {
  return `\n${c(title, C.bold + C.cyan)}\n${divider()}\n`;
}

export function endSection(): string {
  return `\n${divider()}\n`;
}
