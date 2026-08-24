/**
 * Hilbras Spectra — Interactive Terminal UI
 * 
 * Run with: spectra ui  (via tsx — handles JSX)
 */

import React, { useState, useCallback } from "react";
import { render, Text, Box, useInput, useApp } from "ink";
import { spawn } from "child_process";
import { readFileSync, readdirSync, statSync, existsSync, mkdirSync, writeFileSync } from "fs";
import { join, basename } from "path";
import { homedir } from "os";

// ─── Types ─────────────────────────────────────────────────────────────────────

interface AuditResult {
  target: string;
  durationMs: number;
  iterations: number;
  findings: Finding[];
  hypotheses: Hypothesis[];
  status: string;
}

interface Finding {
  id: string;
  title: string;
  severity: string;
  category: string;
}

interface Hypothesis {
  id: string;
  category: string;
  claim: string;
  confidence: number;
}

// ─── Colors ────────────────────────────────────────────────────────────────────

const C = {
  reset: "\x1b[0m",
  bold: "\x1b[1m",
  dim:  "\x1b[2m",
  red:   "\x1b[31m",
  green: "\x1b[32m",
  yellow:"\x1b[33m",
  blue:  "\x1b[34m",
  magenta:"\x1b[35m",
  cyan:  "\x1b[36m",
  gray:  "\x1b[90m",
  white: "\x1b[37m",
} as const;

function c(text: string, color: string): string {
  return `${color}${text}${C.reset}`;
}

function severityColor(s: string): string {
  const m: Record<string, string> = {
    critical:    c("CRITICAL", C.red),
    high:        c("HIGH",     "\x1b[91m"),
    medium:      c("MEDIUM",   C.yellow),
    low:         c("LOW",      C.blue),
    informational:c("INFO",    C.gray),
  };
  return m[s] ?? c(s.toUpperCase(), C.gray);
}

// ─── Storage ───────────────────────────────────────────────────────────────────

const CFG = join(homedir(), ".spectra");
const AUDITS = join(CFG, "audits");

function ensureDir(p: string): void {
  if (!existsSync(p)) mkdirSync(p, { recursive: true });
}

type AppConfig = {
  profiles?: Record<string, { name: string; path: string; lastAudit?: string }>;
  format?: "json" | "sarif" | "markdown";
  defaultModel?: string;
  autoApproveThreshold?: string;
};

function loadConfig(): AppConfig {
  try { return JSON.parse(readFileSync(join(CFG, "config.json"), "utf-8")); } catch { return {}; }
}
function saveConfig(cfg: AppConfig): void {
  ensureDir(CFG);
  writeFileSync(join(CFG, "config.json"), JSON.stringify(cfg, null, 2));
}

function listAudits(): Array<{ file: string; data: AuditResult }> {
  ensureDir(AUDITS);
  try {
    return readdirSync(AUDITS)
      .filter((f) => f.endsWith(".json"))
      .sort()
      .reverse()
      .map((file) => {
        try {
          const raw = JSON.parse(readFileSync(join(AUDITS, file), "utf-8")) as AuditResult & { investigation?: { findings?: Finding[]; hypotheses?: Hypothesis[]; status?: string; durationMs?: number; iterations?: number } };
          return {
            file,
            data: {
              target: raw.target ?? "",
              durationMs: raw.durationMs ?? 0,
              iterations: raw.iterations ?? 0,
              findings: raw.findings ?? raw.investigation?.findings ?? [],
              hypotheses: raw.hypotheses ?? raw.investigation?.hypotheses ?? [],
              status: raw.status ?? raw.investigation?.status ?? "unknown",
            },
          };
        } catch { return null; }
      })
      .filter((x): x is NonNullable<typeof x> => x !== null);
  } catch { return []; }
}

function discoverProjects(): Array<{ name: string; path: string }> {
  const out: Array<{ name: string; path: string }> = [];
  const cwd = process.cwd();
  // Demo fixtures
  const fixtures = join(cwd, "tests", "fixtures");
  if (existsSync(fixtures)) {
    for (const name of readdirSync(fixtures)) {
      const p = join(fixtures, name);
      if (statSync(p).isDirectory()) out.push({ name, path: p });
    }
  }
  // Sibling Hilbras product dir
  const sibling = join(cwd, "..", "Hilbras.product");
  if (existsSync(sibling)) {
    for (const item of readdirSync(sibling)) {
      const p = join(sibling, item);
      if (statSync(p).isDirectory() && existsSync(join(p, "package.json"))) {
        out.push({ name: item, path: p });
      }
    }
  }
  // Unique
  const seen = new Set<string>();
  return out.filter((p) => { if (seen.has(p.path)) return false; seen.add(p.path); return true; });
}

function runAudit(targetPath: string): Promise<AuditResult> {
  return new Promise((resolve, reject) => {
    const proc = spawn("node", ["dist/cli/index.js", "audit", targetPath, "--quiet"], {
      stdio: ["ignore", "pipe", "pipe"],
    });
    let stderr = "";
    proc.stderr.on("data", (d: Buffer) => (stderr += d.toString()));
    proc.on("close", (code) => {
      if (code !== 0) { reject(new Error(stderr || `Exit code ${code}`)); return; }
      const sd = join(targetPath, ".spectra");
      try {
        const files = readdirSync(sd).filter((f) => f.endsWith(".json")).sort();
        if (files.length > 0) {
          const raw = JSON.parse(readFileSync(join(sd, files[files.length - 1]), "utf-8"));
          resolve({
            target: targetPath,
            durationMs: raw.durationMs ?? 0,
            iterations: raw.iterations ?? 0,
            findings: raw.investigation?.findings ?? [],
            hypotheses: raw.investigation?.hypotheses ?? [],
            status: raw.investigation?.status ?? "completed",
          });
          return;
        }
      } catch { /* no saved data */ }
      resolve({ target: targetPath, durationMs: 0, iterations: 0, findings: [], hypotheses: [], status: "completed" });
    });
  });
}

// ─── Screens ───────────────────────────────────────────────────────────────────

function MainMenu({ onSelect }: { onSelect: (s: string) => void }) {
  const [sel, setSel] = useState(0);
  const items = [
    { k: "a", label: "Audit Project", desc: "Run security investigation" },
    { k: "f", label: "View Findings", desc: "Browse past audit results" },
    { k: "p", label: "Projects", desc: "Manage saved project profiles" },
    { k: "g", label: "Settings", desc: "Configure defaults" },
    { k: "q", label: "Quit", desc: "Exit Spectra" },
  ];

  useInput(
    useCallback((input: string) => {
      if (input === "k" || input === "up") setSel((i) => Math.max(0, i - 1));
      else if (input === "j" || input === "down") setSel((i) => Math.min(items.length - 1, i + 1));
      else if (input === "enter" || input === " ") onSelect(items[sel]!.label.toLowerCase());
    }, [sel, onSelect]),
  );

  return (
    <Box flexDirection="column" paddingX={2}>
      <Text bold>{c("╔══════════════════════════════════════════╗", C.cyan)}</Text>
      <Text bold>{c("║   🔍  HILBRAS SPECTRA v0.0.5            ║", C.bold + C.cyan)}</Text>
      <Text bold>{c("╚══════════════════════════════════════════╝", C.cyan)}</Text>
      <Text>{c("  Autonomous AI Security Research Platform", C.dim)}</Text>
      <Text></Text>
      {items.map((item, i) => (
        <Box key={item.k}>
          <Text>{i === sel ? c("▶", C.green) : " "}</Text>
          <Text bold={i === sel}>{c(item.label, i === sel ? C.white : C.gray)}</Text>
          <Text>{c("  " + item.desc, C.dim)}</Text>
        </Box>
      ))}
      <Text></Text>
      <Text>{c("↑↓ Navigate  •  Enter Select  •  q Quit", C.dim)}</Text>
    </Box>
  );
}

function AuditScreen({ onBack }: { onBack: () => void }) {
  const [step, setStep] = useState<"select" | "options" | "running" | "result">("select");
  const [projects] = useState(discoverProjects);
  const [selIdx, setSelIdx] = useState(0);
  const [depth, setDepth] = useState<"quick" | "full">("full");
  const [result, setResult] = useState<AuditResult | null>(null);
  const [error, setError] = useState<string>("");

  const targetPath = projects[selIdx]?.path ?? process.cwd();

  useInput(
    useCallback(
      (input: string) => {
        if (step === "select") {
          if (input === "k" || input === "up") setSelIdx((i) => Math.max(0, i - 1));
          else if (input === "j" || input === "down") setSelIdx((i) => Math.min(projects.length - 1, i + 1));
          else if (input === "enter") setStep("options");
        } else if (step === "options") {
          if (input === "k" || input === "up") setDepth((d) => (d === "full" ? "quick" : "full"));
          else if (input === "enter") {
            setStep("running");
            runAudit(targetPath)
              .then((r) => { setResult(r); setStep("result"); })
              .catch((e: Error) => { setError(e.message); setStep("result"); });
          }
        } else if (input === "esc" || input === "q") onBack();
      },
      [step, projects, selIdx, depth, targetPath],
    ),
  );

  if (step === "select") {
    return (
      <Box flexDirection="column" paddingX={2}>
        <Text bold>{c("◀ SELECT TARGET PROJECT", C.cyan)}</Text>
        <Text></Text>
        {projects.map((proj, i) => (
          <Box key={proj.name}>
            <Text>{i === selIdx ? c("▶", C.green) : " "}</Text>
            <Text bold={i === selIdx}>{c(proj.name, i === selIdx ? C.white : C.gray)}</Text>
            <Text>{c("  " + proj.path, C.dim)}</Text>
          </Box>
        ))}
        <Text></Text>
        <Text>{c("↑↓ Select  •  Enter Continue  •  Esc Back", C.dim)}</Text>
      </Box>
    );
  }

  if (step === "options") {
    return (
      <Box flexDirection="column" paddingX={2}>
        <Text bold>{c("◀ AUDIT OPTIONS", C.cyan)}</Text>
        <Text></Text>
        <Text>{c("Target:  ", C.gray)}{c(projects[selIdx]?.name ?? "", C.green)}</Text>
        <Text>{c("Depth:   ", C.gray)}{depth === "full" ? c("Full (50 iterations)", C.white) : c("Quick (20 iterations)", C.yellow)}</Text>
        <Text></Text>
        <Text>{c("↑ Toggle quick/full  •  Enter Launch  •  Esc Back", C.dim)}</Text>
      </Box>
    );
  }

  if (step === "running") {
    return (
      <Box flexDirection="column" paddingX={2}>
        <Text bold>{c("◀ RUNNING AUDIT", C.yellow)}</Text>
        <Text></Text>
        <Text>{c("Target:  " + (projects[selIdx]?.name ?? ""), C.gray)}</Text>
        <Text>{c("Status:  ⟳ Investigating...", C.yellow)}</Text>
        <Text></Text>
        <Text>{c("  This may take a moment.", C.dim)}</Text>
      </Box>
    );
  }

  if (error) {
    return (
      <Box flexDirection="column" paddingX={2}>
        <Text bold>{c("◀ AUDIT FAILED", C.red)}</Text>
        <Text></Text>
        <Text>{c(error, C.red)}</Text>
        <Text></Text>
        <Text>{c("Press any key to go back", C.dim)}</Text>
      </Box>
    );
  }

  if (!result) return null;

  return (
    <Box flexDirection="column" paddingX={2}>
      <Text bold>{c("◀ AUDIT COMPLETE", result.findings.length > 0 ? C.red : C.green)}</Text>
      <Text></Text>
      <Text>{c("Project:    ", C.gray)}{c(basename(result.target), C.green)}</Text>
      <Text>{c("Status:     ", C.gray)}{result.status === "completed" ? c("✓ Completed", C.green) : c(result.status, C.yellow)}</Text>
      <Text>{c("Duration:   ", C.gray)}{(result.durationMs / 1000).toFixed(2)}s</Text>
      <Text>{c("Iterations: ", C.gray)}{result.iterations}</Text>
      <Text></Text>
      <Text bold>{c("📊 Findings: " + result.findings.length, result.findings.length > 0 ? C.red : C.green)}</Text>
      {result.findings.slice(0, 5).map((f) => (
        <Text key={f.id}>{severityColor(f.severity) + "  " + f.title.slice(0, 65)}</Text>
      ))}
      {result.hypotheses.length > 0 && (
        <>
          <Text></Text>
          <Text bold>{c("🧠 Hypotheses: " + result.hypotheses.length, C.cyan)}</Text>
          {result.hypotheses.slice(0, 3).map((h) => (
            <Text key={h.id}>{c(`[( ${(h.confidence * 100).toFixed(0)}% ] ${h.category}: ${(h.claim ?? "").slice(0, 55)}`, C.dim)}</Text>
          ))}
        </>
      )}
      <Text></Text>
      <Text>{c("Press any key to go back", C.dim)}</Text>
    </Box>
  );
}

function FindingsScreen({ audits, onBack }: { audits: Array<{ file: string; data: AuditResult }>; onBack: () => void }) {
  const [sel, setSel] = useState(0);

  useInput(
    useCallback((input: string) => {
      if (input === "k" || input === "up") setSel((i) => Math.max(0, i - 1));
      else if (input === "j" || input === "down") setSel((i) => Math.min(audits.length - 1, i + 1));
      else if (input === "esc" || input === "q") onBack();
    }, [audits, sel]),
  );

  return (
    <Box flexDirection="column" paddingX={2}>
      <Text bold>{c("◀ RECENT FINDINGS", C.cyan)}</Text>
      <Text></Text>
      {audits.length === 0 && <Text>{c("No audits found. Run an audit first.", C.dim)}</Text>}
      {audits.map((a, i) => {
        const counts: Record<string, number> = {};
        for (const f of a.data.findings) counts[f.severity] = (counts[f.severity] ?? 0) + 1;
        const time = new Date(a.file.replace(".json", "")).toLocaleString();
        return (
          <Box key={a.file}>
            <Text>{i === sel ? c("▶", C.green) : " "}</Text>
            <Text bold={i === sel}>{c(basename(a.file), i === sel ? C.white : C.gray)}</Text>
            <Text>{c("  " + time, C.dim)}</Text>
            <Box>
              {Object.entries(counts).map(([sev, n]) => (
                <Text key={sev}>{severityColor(`${n}x ${sev}`) + "  "}</Text>
              ))}
              <Text>{c(`(${a.data.iterations} iters)`, C.dim)}</Text>
            </Box>
          </Box>
        );
      })}
      <Text></Text>
      <Text>{c("↑↓ Browse  •  Esc Quit", C.dim)}</Text>
    </Box>
  );
}

function ProjectsScreen({ onBack }: { onBack: () => void }) {
  const config = loadConfig();
  const profiles = Object.entries(config.profiles ?? {});
  const [sel, setSel] = useState(0);
  const [adding, setAdding] = useState(false);
  const [addStep, setAddStep] = useState<"name" | "path">("name");
  const [inputVal, setInputVal] = useState("");

  useInput(
    useCallback(
      (input: string) => {
        if (adding) {
          if (input === "enter") {
            if (addStep === "name") {
              setAddStep("path");
              setInputVal("");
            } else {
              const cfg = loadConfig();
              cfg.profiles ??= {};
              const normalizedPath = inputVal.startsWith("/") ? inputVal : join(process.cwd(), inputVal);
              cfg.profiles[inputVal] = { name: inputVal, path: normalizedPath };
              saveConfig(cfg);
              setAdding(false);
              setInputVal("");
              setAddStep("name");
            }
          } else if (input === "escape") {
            setAdding(false);
            setInputVal("");
          } else {
            setInputVal((v) => v + input);
          }
          return;
        }
        if (input === "k" || input === "up") setSel((i) => Math.max(0, i - 1));
        else if (input === "j" || input === "down") setSel((i) => Math.min(profiles.length - 1, i + 1));
        else if (input === "n") setAdding(true);
        else if (input === "d" && profiles.length > 0) {
          const [name] = profiles[sel]!;
          const cfg = loadConfig();
          delete cfg.profiles![name];
          saveConfig(cfg);
        } else if (input === "a" && profiles.length > 0) {
          const [, prof] = profiles[sel]!;
          if (prof) runAudit(prof.path).then(() => onBack());
        } else if (input === "esc" || input === "q") onBack();
      },
      [adding, addStep, profiles, sel],
    ),
  );

  return (
    <Box flexDirection="column" paddingX={2}>
      <Text bold>{c("◀ PROJECTS", C.cyan)}</Text>
      <Text></Text>
      {profiles.length === 0 && <Text>{c("No profiles configured. Press 'n' to add one.", C.dim)}</Text>}
      {profiles.map(([name, prof], i) => (
        <Box key={name}>
          <Text>{i === sel ? c("▶", C.green) : " "}</Text>
          <Text bold={i === sel}>{c(name, i === sel ? C.white : C.gray)}</Text>
          <Text>{c("  " + (prof?.path ?? ""), C.dim)}</Text>
        </Box>
      ))}
      <Text></Text>
      <Text>{c("↑↓ Navigate  •  n Add  •  d Delete  •  a Re-audit  •  Esc Quit", C.dim)}</Text>
      {adding && (
        <Box>
          <Text>{c(addStep === "name" ? "Name: " : "Path: ", C.green)}{inputVal}{c("_", C.green)}</Text>
          <Text>{c(" [Enter confirm, Esc cancel]", C.dim)}</Text>
        </Box>
      )}
    </Box>
  );
}

function SettingsScreen({ onBack }: { onBack: () => void }) {
  const config = loadConfig();
  const [sel, setSel] = useState(0);
  const fmt = (config.format as "json" | "sarif" | "markdown") ?? "json";
  const threshold = (config.autoApproveThreshold as "low" | "medium" | "high" | "critical") ?? "medium";

  const options = [
    { key: "model",    value: config.defaultModel ?? "mock", next: () => "mock" },
    { key: "format",   value: fmt, next: () => {
      const order: ("json" | "sarif" | "markdown")[] = ["json", "sarif", "markdown"];
      return order[(order.indexOf(fmt) + 1) % 3];
    }},
    { key: "threshold",value: threshold, next: () => {
      const order: ("low" | "medium" | "high" | "critical")[] = ["low", "medium", "high", "critical"];
      return order[(order.indexOf(threshold) + 1) % 4];
    }},
  ];

  useInput(
    useCallback((input: string) => {
      if (input === "k" || input === "up") setSel((i) => Math.max(0, i - 1));
      else if (input === "j" || input === "down") setSel((i) => Math.min(options.length - 1, i + 1));
      else if (input === "enter") {
        const opt = options[sel]!;
        const updated: AppConfig = { ...config, [opt.key]: opt.next() };
        saveConfig(updated);
      } else if (input === "esc" || input === "q") onBack();
    }, [sel, options, config]),
  );

  return (
    <Box flexDirection="column" paddingX={2}>
      <Text bold>{c("◀ SETTINGS", C.cyan)}</Text>
      <Text></Text>
      {options.map((opt, i) => (
        <Box key={opt.key}>
          <Text>{i === sel ? c("▶", C.green) : " "}</Text>
          <Text bold={i === sel}>{c(opt.key, i === sel ? C.white : C.gray)}</Text>
          <Text>{c(" = ", C.gray)}{c(String(opt.value), i === sel ? C.cyan : C.yellow)}</Text>
        </Box>
      ))}
      <Text></Text>
      <Text>{c("↑↓ Select  •  Enter Cycle value  •  Esc Quit", C.dim)}</Text>
    </Box>
  );
}

// ─── App ───────────────────────────────────────────────────────────────────────

type Screen = "main" | "audit" | "findings" | "projects" | "settings";

export default function App() {
  const [screen, setScreen] = useState<Screen>("main");
  const { exit } = useApp();

  const goTo = useCallback((s: Screen) => setScreen(s), []);
  const goBack = useCallback(() => setScreen("main"), []);

  return (
    <Box flexDirection="column" width={72} minHeight={15}>
      {screen === "main"     && <MainMenu onSelect={(label) => {
        switch (label) {
          case "audit project": goTo("audit"); break;
          case "view findings": goTo("findings"); break;
          case "projects":      goTo("projects"); break;
          case "settings":      goTo("settings"); break;
          case "quit":          exit(); break;
        }
      }} />}
      {screen === "audit"    && <AuditScreen onBack={goBack} />}
      {screen === "findings" && <FindingsScreen audits={listAudits()} onBack={goBack} />}
      {screen === "projects" && <ProjectsScreen onBack={goBack} />}
      {screen === "settings" && <SettingsScreen onBack={goBack} />}
    </Box>
  );
}

// ─── Entry ─────────────────────────────────────────────────────────────────────
render(<App />);
