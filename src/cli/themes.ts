/**
 * Hilbras Spectra — Theme System
 * 
 * Supports dark and light terminal themes with gold accent colors.
 * Auto-detects terminal background or respects SPECTRA_THEME env var.
 */

export type ThemeName = "dark" | "light";

export interface ThemeColors {
  // Core
  reset: string;
  bold: string;
  dim: string;
  italic: string;
  
  // Standard palette
  black: string; red: string; green: string; yellow: string;
  blue: string; magenta: string; cyan: string; white: string;
  
  // Bright variants
  brightBlack: string; brightRed: string; brightGreen: string; brightYellow: string;
  brightBlue: string; brightMagenta: string; brightCyan: string; brightWhite: string;
  
  // Gold accent (signature Spectra color)
  gold: string; goldDim: string; goldBright: string; goldBg: string;
  
  // Semantic
  success: string; error: string; warning: string; info: string;
  
  // Background accents
  bgGold: string; bgDark: string; bgLight: string;
  bgRed: string; bgGreen: string; bgYellow: string; bgBlue: string;
  bgCyan: string;
  
  // Panel borders
  border: string; borderBright: string;
  
  // Text on colored backgrounds
  textOnGold: string; textOnDark: string; textOnLight: string;
}

// ─── Dark theme (default) ──────────────────────────────────────────────────────

const DARK: ThemeColors = {
  reset: "\x1b[0m",
  bold: "\x1b[1m",
  dim: "\x1b[2m",
  italic: "\x1b[3m",
  
  black: "\x1b[30m", red: "\x1b[31m", green: "\x1b[32m", yellow: "\x1b[33m",
  blue: "\x1b[34m", magenta: "\x1b[35m", cyan: "\x1b[36m", white: "\x1b[37m",
  
  brightBlack: "\x1b[90m", brightRed: "\x1b[91m", brightGreen: "\x1b[92m", brightYellow: "\x1b[93m",
  brightBlue: "\x1b[94m", brightMagenta: "\x1b[95m", brightCyan: "\x1b[96m", brightWhite: "\x1b[97m",
  
  // Gold accent — signature Spectra color
  gold: "\x1b[38;5;220m",        // ANSI 220 (warm gold)
  goldDim: "\x1b[38;5;178m",     // dimmer gold
  goldBright: "\x1b[38;5;220m\x1b[1m", // bright bold gold
  goldBg: "\x1b[48;5;220m",      // gold background
  
  success: "\x1b[38;5;82m",      // bright green
  error: "\x1b[38;5;203m",       // bright red/pink
  warning: "\x1b[38;5;214m",     // bright yellow
  info: "\x1b[38;5;147m",        // azure
  
  bgGold: "\x1b[48;5;220m",
  bgDark: "\x1b[48;5;236m",      // dark gray panel bg
  bgLight: "\x1b[48;5;240m",     // slightly lighter gray
  bgRed: "\x1b[48;5;196m",
  bgGreen: "\x1b[48;5;46m",
  bgYellow: "\x1b[48;5;226m",
  bgBlue: "\x1b[48;5;27m",
  bgCyan: "\x1b[48;5;51m",
  
  border: "\x1b[38;5;240m",      // muted gray border
  borderBright: "\x1b[38;5;220m", // gold border for active panels
  
  textOnGold: "\x1b[38;5;232m",  // near-black text on gold bg
  textOnDark: "\x1b[38;5;243m",  // light gray text on dark bg
  textOnLight: "\x1b[38;5;235m", // dark text on light bg
};

// ─── Light theme ───────────────────────────────────────────────────────────────

const LIGHT: ThemeColors = {
  reset: "\x1b[0m",
  bold: "\x1b[1m",
  dim: "\x1b[2m",
  italic: "\x1b[3m",
  
  black: "\x1b[30m", red: "\x1b[31m", green: "\x1b[32m", yellow: "\x1b[33m",
  blue: "\x1b[34m", magenta: "\x1b[35m", cyan: "\x1b[36m", white: "\x1b[37m",
  
  brightBlack: "\x1b[90m", brightRed: "\x1b[91m", brightGreen: "\x1b[92m", brightYellow: "\x1b[93m",
  brightBlue: "\x1b[94m", brightMagenta: "\x1b[95m", brightCyan: "\x1b[96m", brightWhite: "\x1b[37m",
  
  // Gold accent — slightly darker for light bg readability
  gold: "\x1b[38;5;166m",        // warm orange-gold on light
  goldDim: "\x1b[38;5;172m",
  goldBright: "\x1b[38;5;166m\x1b[1m",
  goldBg: "\x1b[48;5;166m",
  
  success: "\x1b[38;5;28m",      // dark green
  error: "\x1b[38;5;124m",       // dark red
  warning: "\x1b[38;5;94m",      // dark yellow/gold
  info: "\x1b[38;5;25m",         // dark blue
  
  bgGold: "\x1b[48;5;166m",
  bgDark: "\x1b[48;5;255m\x1b[38;5;236m",  // subtle gray
  bgLight: "\x1b[48;5;255m",      // white panel
  bgRed: "\x1b[48;5;203m",
  bgGreen: "\x1b[48;5;46m",
  bgYellow: "\x1b[48;5;226m",
  bgBlue: "\x1b[48;5;153m",
  bgCyan: "\x1b[48;5;159m",
  
  border: "\x1b[38;5;246m",
  borderBright: "\x1b[38;5;166m",
  
  textOnGold: "\x1b[38;5;232m",
  textOnDark: "\x1b[38;5;235m",
  textOnLight: "\x1b[38;5;235m",
};

// ─── Theme detection & selection ───────────────────────────────────────────────

function detectTheme(): ThemeName {
  // Explicit override takes priority
  const envOverride = process.env.SPECTRA_THEME?.toLowerCase();
  if (envOverride === "light" || envOverride === "dark") return envOverride;
  
  // Check if running in a known light-terminal emulator
  const termProgram = (process.env.TERM_PROGRAM ?? "").toLowerCase();
  if (termProgram.includes("liteui") || termProgram.includes("light")) return "light";
  
  // Check for forced light mode via environment
  if (process.env.FORCE_LIGHT === "1") return "light";
  
  // Default: dark
  return "dark";
}

let currentThemeName = detectTheme();
let currentTheme = currentThemeName === "dark" ? DARK : LIGHT;

export function getTheme(): ThemeColors {
  return currentTheme;
}

export function getThemeName(): ThemeName {
  return currentThemeName;
}

/** Switch theme programmatically (called by settings command) */
export function setTheme(name: ThemeName): void {
  currentThemeName = name;
  currentTheme = name === "dark" ? DARK : LIGHT;
}

/** Get theme as JSON for config persistence */
export function getActiveThemeName(): ThemeName {
  return currentThemeName;
}

// ─── Convenience colorizer ─────────────────────────────────────────────────────

/** Color text with the current theme's palette */
export function t(color: keyof ThemeColors, text: string): string {
  return `${currentTheme[color]}${text}${currentTheme.reset}`;
}

/** Bold text in a specific color */
export function bold(color: keyof ThemeColors, text: string): string {
  return `${currentTheme.bold}${currentTheme[color]}${text}${currentTheme.reset}`;
}

/** Dim text in a specific color */
export function dim(color: keyof ThemeColors, text: string): string {
  return `${currentTheme.dim}${currentTheme[color]}${text}${currentTheme.reset}`;
}

/** Text on a colored background */
export function on(bg: keyof ThemeColors, color: keyof ThemeColors, text: string): string {
  return `${currentTheme[bg]}${currentTheme[color]}${text}${currentTheme.reset}`;
}

// ─── Themed UI helpers ─────────────────────────────────────────────────────────

export function goldBox(title: string, content: string): string {
  const lines = content.split("\n");
  const innerW = Math.max(...lines.map((l) => l.length));
  const W = Math.min(innerW + 4, 68);
  
  const top = `${t("gold", "┌" + "─".repeat(W - 2) + "┐")}`;
  const titleLine = `│${t("goldBright", ` ${title.padEnd(W - 4)} `)}│`;
  const body = lines.map((l) => `│${t("goldDim", l.padEnd(W - 2))}│`).join("\n");
  const bot = `${t("gold", "└" + "─".repeat(W - 2) + "┘")}`;
  
  return `\n${top}\n${t("bold", titleLine)}\n${body}\n${bot}\n`;
}

export function section(title: string): string {
  const pad = " ".repeat(2);
  return `\n${pad}${t("goldBright", "━".repeat(66))}\n${pad}${t("bold", `  ${title}`)}\n${pad}${t("border", "─".repeat(66))}\n`;
}

export function divider(): string {
  return `\n${t("border", "  " + "─".repeat(68))}\n`;
}

export function endSection(): string {
  return `\n${t("border", "─".repeat(68))}\n`;
}

export function scoreMeter(score: number, width = 40): string {
  const filled = Math.round((score / 100) * width);
  const bar = t("green", "█".repeat(filled)) + t("brightBlack", "░".repeat(width - filled));
  const scoreColor = score >= 80 ? "green" : score >= 50 ? "yellow" : "red";
  return `${bar} ${bold(scoreColor as any, `${score}/100`)}`;
}

export function sevBadge(sev: string, compact = false): string {
  const map: Record<string, keyof ThemeColors> = {
    critical: "error", high: "brightRed", medium: "warning", low: "blue", informational: "brightBlack",
  };
  const color = map[sev] ?? "brightBlack";
  const text = (sev ?? "?").toUpperCase().padEnd(compact ? 8 : 0);
  return `${t(color, text)}`;
}

export function findingTable(findings: Array<{ title?: string; severity?: string; category?: string; component?: string; cwe?: string }>): string {
  if (!findings.length) return dim("brightBlack", "  No findings recorded.");
  const rows = findings.map((f) => ({
    sev: f.severity ?? "unknown",
    cat: (f.category ?? "unknown").slice(0, 16),
    comp: (f.component ?? "—").slice(0, 22),
    title: (f.title ?? "").slice(0, 52),
  }));
  const header = `${t("bold", "  " + "SEVERITY".padEnd(10) + "CATEGORY".padEnd(18) + "COMPONENT".padEnd(24) + "TITLE")}`;
  const lines = [header, t("border", "  " + "─".repeat(70))];
  for (const r of rows) {
    lines.push(`  ${sevBadge(r.sev, true)} ${r.cat.padEnd(18)} ${(r.comp).padEnd(24)} ${r.title || "—"}`);
  }
  return lines.join("\n");
}

export function auditList(audits: Array<{ generatedAt: string; target: string; investigation: any; summary?: any }>): string {
  if (!audits.length) return dim("brightBlack", "  No audits found. Run 'spectra audit' first.");
  const h = t("bold", "  " + "DATE".padEnd(22) + "TARGET".padEnd(26) + "FINDINGS".padEnd(10) + "SCORE".padEnd(8) + "STATUS");
  const sep = t("border", "  " + "─".repeat(80));
  const rows = [h, sep];
  for (const a of audits.slice(0, 15)) {
    const date = new Date(a.generatedAt).toLocaleString("en-US", { month: "short", day: "2-digit", hour: "2-digit", minute: "2-digit" });
    const target = (a.target.split("/").pop() ?? a.target).slice(0, 24);
    const f = a.investigation?.findings ?? [];
    const crit = f.filter((x: any) => x.severity === "critical").length;
    const high = f.filter((x: any) => x.severity === "high").length;
    const fStr = f.length > 0 ? t(crit > 0 || high > 0 ? "error" : "warning", String(f.length)) : t("green", "0");
    const score = a.summary?.overallScore ?? 100;
    const sStr = score >= 80 ? t("green", String(score)) : score >= 50 ? t("warning", String(score)) : t("error", String(score));
    rows.push(`  ${date.padEnd(22)} ${target.padEnd(26)} ${fStr.padEnd(10)} ${sStr.padEnd(8)} ${dim("brightBlack", a.investigation?.status ?? "?")}`);
  }
  return rows.join("\n");
}

export function benchmarkResults(results: Array<{ fixture: string; status: string; durationMs: number; findings: number; errors: number }>): string {
  const h = t("bold", "  " + "FIXTURE".padEnd(28) + "STATUS".padEnd(10) + "TIME".padEnd(8) + "FINDINGS".padEnd(10) + "ERRORS");
  const sep = t("border", "  " + "─".repeat(65));
  const rows = [h, sep];
  let tf = 0, te = 0;
  for (const r of results) {
    tf += r.findings; te += r.errors;
    const st = r.errors > 0 ? t("warning", "WARN") : r.findings > 0 ? t("error", "OK") : t("green", "OK");
    rows.push(`  ${(r.fixture ?? "").padEnd(28)} ${st.padEnd(10)} ${(r.durationMs / 1000).toFixed(2).padEnd(8)} ${String(r.findings).padEnd(10)} ${r.errors > 0 ? t("warning", String(r.errors)) : "0"}`);
  }
  rows.push("");
  rows.push(`${t("bold", "  TOTAL:")} ${tf} findings, ${te} errors across ${results.length} fixtures`);
  return rows.join("\n");
}

export function helpBanner(version: string): string {
  const g = (s: string) => t("goldBright", s);
  const d = (s: string) => t("brightBlack", s);
  const b = (s: string) => t("bold", s);
  return [
    `\n${g("╔" + "══════════════════════════════════════════════════════════════".padEnd(68) + "╗")}`,
    `${g("║")}  ${b(g("🔍  HILBRAS SPECTRA v" + version))}${" ".repeat(36 - version.length)}${g("║")}`,
    `${g("║")}  ${d("Autonomous AI Security Research Platform")}${" ".repeat(28)}${g("║")}`,
    `${g("╚" + "══════════════════════════════════════════════════════════════".padEnd(68) + "╝")}\n`,
    "",
    b(g("  QUICK START")),
    `    spectra audit ./my-app                   ${d("Run investigation")}`,
    `    spectra audit ./my-app -d quick          ${d("Fast scan (20 iterations)")}`,
    `    spectra audit ./my-app -f sarif         ${d("SARIF for CI/CD")}`,
    `    spectra benchmarks                       ${d("Run all fixture tests")}`,
    "",
    b(g("  COMMANDS")),
    `    audit <target> [opts]     ${d("Run security investigation")}`,
    `    findings [opts]           ${d("Browse past findings")}`,
    `    history [opts]            ${d("List audit history")}`,
    `    report <id> [opts]        ${d("Generate report from saved data")}`,
    `    benchmarks                ${d("Run fixture benchmarks")}`,
    `    health                    ${d("Diagnose installation")}`,
    `    projects [act] [name] [p] ${d("Manage project profiles")}`,
    `    config [act] [k] [v]      ${d("View/edit configuration")}`,
    `    login [provider] [opts]   ${d("Configure AI provider keys")}`,
    `    init                      ${d("Initialize ~/.spectra/")}`,
    `    theme [dark|light]        ${d("Switch color theme")}`,
    `    version                   ${d("Show version info")}`,
    "",
    b(g("  AUDIT OPTIONS")),
    `    -d, --depth <quick|full>   ${d("Investigation depth (default: full)")}`,
    `    -f, --format <json|sarif|md> ${d("Output format (default: json)")}`,
    `    -m, --model <id>           ${d("AI model: mock, openai, anthropic, groq, ollama")}`,
    `    -n, --dry-run              ${d("Plan-only, no tools executed")}`,
    `    -o, --output <path>        ${d("Write report to file")}`,
    `    -q, --quiet                ${d("Suppress progress output")}`,
    "",
    b(g("  EXAMPLES")),
    `    spectra audit ~/projects/my-webapp`,
    `    spectra audit ~/projects/my-webapp -d quick -f sarif -o report.sarif`,
    `    spectra findings --severity high`,
    `    spectra history --last 5`,
    `    spectra benchmarks`,
    `    spectra health`,
    `    spectra theme dark    # or 'spectra theme light'`,
    "",
  ].join("\n");
}
