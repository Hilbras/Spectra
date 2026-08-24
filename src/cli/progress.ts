/**
 * Hilbras Spectra — Colored Progress Output
 * 
 * Provides ANSI-colored terminal output with phase indicators,
 * status badges, and progress bars for audit workflow visibility.
 */

const COLORS = {
  reset: "\x1b[0m",
  bold: "\x1b[1m",
  dim: "\x1b[2m",
  red: "\x1b[31m",
  green: "\x1b[32m",
  yellow: "\x1b[33m",
  blue: "\x1b[34m",
  magenta: "\x1b[35m",
  cyan: "\x1b[36m",
  gray: "\x1b[90m",
  bgBlue: "\x1b[44m",
};

const SEVERITY_COLOR: Record<string, string> = {
  informational: COLORS.gray,
  low: COLORS.blue,
  medium: COLORS.yellow,
  high: COLORS.red,
  critical: "\x1b[35m\x1b[1m", // magenta bold
};

export function colorize(text: string, color: string): string {
  return `${color}${text}${COLORS.reset}`;
}

export function badge(text: string, color: string = COLORS.blue): string {
  return `${COLORS.bgBlue}${text.padEnd(8)}${COLORS.reset} ${color}${text}${COLORS.reset}`;
}

export function severityBadge(severity: string): string {
  const color = SEVERITY_COLOR[severity] ?? COLORS.gray;
  return colorize(`[${severity.toUpperCase()}]`, color);
}

export function statusBadge(status: string): string {
  const colors: Record<string, string> = {
    completed: COLORS.green,
    failed: COLORS.red,
    running: COLORS.yellow,
    pending: COLORS.gray,
  };
  const color = colors[status] ?? COLORS.gray;
  return colorize(`◉ ${status}`, color);
}

export function phaseLine(phase: string, done: boolean = false): string {
  const icon = done ? "✓" : "○";
  const color = done ? COLORS.green : COLORS.gray;
  return `  ${colorize(icon, color)} ${phase}`;
}

export function findLine(finding: { title: string; severity: string; category: string; component?: string }): string {
  const sevColor = SEVERITY_COLOR[finding.severity] ?? COLORS.gray;
  const prefix = colorize(finding.severity.toUpperCase().padEnd(10), sevColor);
  const title = finding.title.length > 60 ? finding.title.slice(0, 57) + "..." : finding.title;
  return `  ${prefix} ${colorize(finding.category, COLORS.cyan)} | ${title}`;
}

export function divider(): string {
  return colorize("────────────────────────────────────────", COLORS.dim);
}

export function section(title: string): string {
  return `\n${colorize(title, COLORS.bold)}\n${divider()}\n`;
}

export function success(msg: string): string {
  return colorize(`✓ ${msg}`, COLORS.green);
}

export function error(msg: string): string {
  return colorize(`✗ ${msg}`, COLORS.red);
}

export function warn(msg: string): string {
  return colorize(`⚠ ${msg}`, COLORS.yellow);
}

// Progress bar for long-running audits
export function progressBar(current: number, total: number, width: number = 40): string {
  const filled = Math.round((current / total) * width);
  const empty = width - filled;
  const bar = "█".repeat(filled) + "░".repeat(empty);
  const pct = Math.round((current / total) * 100);
  return `  ${colorize(bar, COLORS.blue)} ${pct}%`;
}

// Phase indicator for audit run
export function phaseIndicator(current: string, phases: string[]): string {
  const idx = phases.indexOf(current);
  const arrows = phases.map((_, i) => i <= idx ? colorize("▶", COLORS.green) : colorize("○", COLORS.gray)).join(" ");
  return `  Phases: ${arrows}\n        Current: ${colorize(current, COLORS.cyan)}`;
}
