#!/usr/bin/env node
/**
 * Hilbras Spectra — Production CLI
 *
 * Commands:
 *   spectra audit <target> [options]     Run security investigation
 *   spectra report <investigation-id>    Generate report from saved data
 *   spectra findings [options]           List findings
 *   spectra projects                     Manage project profiles
 *   spectra config                       Show/edit configuration
 *   spectra version                      Show version info
 *   spectra init                         Initialize config directory
 *
 * Examples:
 *   spectra audit ./my-app
 *   spectra audit ./my-app --model openai --format sarif --depth quick
 *   spectra audit https://github.com/user/repo --dry-run
 *   spectra findings --severity high --limit 10
 *   spectra report inv-123 --format markdown -o report.md
 */

import { program } from "commander";
import { writeFileSync, mkdirSync, existsSync } from "fs";
import { join } from "path";
import { homedir } from "os";

import { HilbrasSecurityRuntime } from "../investigation/runtime.js";
import { InvestigationController } from "../investigation/controller.js";
import { DeterministicMockModel } from "../investigation/model-adapter.js";
import { JsonReportFormatter, SarifReportFormatter, MarkdownReportFormatter } from "../reports/formatters.js";
import type { ReportFormatter } from "../reports/formatters.js";
import { loadConfig, saveConfig, addProfile, removeProfile, listProfiles } from "./config.js";
import { section, divider, success, error, warn, colorize, statusBadge } from "./progress.js";

const VERSION = "0.0.6";

// ─── Helpers ──────────────────────────────────────────────────────────────────

function resolveTarget(target: string): string {
  // Support git URLs, local paths, docker references
  if (target.startsWith("http://") || target.startsWith("https://")) {
    console.warn(warn("Git URL targets not yet supported — cloning would be needed"));
    process.exit(1);
  }
  if (target.startsWith("docker:")) {
    console.warn(warn("Docker image targets not yet supported"));
    process.exit(1);
  }
  if (!existsSync(target)) {
    console.error(error(`Target path does not exist: ${target}`));
    process.exit(1);
  }
  return target;
}

function getFormatter(format: string): ReportFormatter {
  switch (format) {
    case "sarif": return new SarifReportFormatter();
    case "markdown": return new MarkdownReportFormatter();
    case "json":
    default: return new JsonReportFormatter();
  }
}

function writeReport(content: string, outputPath?: string): void {
  if (outputPath) {
    const dir = join(outputPath, "..");
    if (!existsSync(dir)) mkdirSync(dir, { recursive: true });
    writeFileSync(outputPath, content, "utf-8");
    console.log(success(`Report written to ${outputPath}`));
  } else {
    process.stdout.write(content + "\n");
  }
}

// ─── Audit command ────────────────────────────────────────────────────────────

async function runAudit(
  target: string,
  options: {
    dryRun?: boolean;
    model?: string;
    format?: string;
    depth?: "quick" | "full";
    output?: string;
    quiet?: boolean;
  },
): Promise<void> {
  const resolved = resolveTarget(target);
  const format = options.format ?? loadConfig().defaultFormat ?? "json";
  const maxIterations = options.depth === "quick" ? 20 : 50;

  if (!options.quiet) {
    console.log(section(`🔍 Spectra Audit — ${resolved}`));
    console.log(`  Target:      ${resolved}`);
    console.log(`  Mode:        ${options.dryRun ? colorize("DRY-RUN", "yellow") : "full"}`);
    console.log(`  Model:       ${options.model ?? loadConfig().defaultModel ?? "mock"}`);
    console.log(`  Depth:       ${options.depth ?? "full"}`);
    console.log(`  Format:      ${format}`);
    console.log(divider());
  }

  const runtime = new HilbrasSecurityRuntime({
    targetPath: resolved,
    authorizationScope: {
      allowedHosts: [],
      allowedServices: [],
      allowedPorts: [],
      allowedEnvironments: ["local"],
      allowedOperations: options.dryRun ? ["read"] : ["read"],
      restrictions: ["no-host-execution", "no-credential-theft"],
      allowActiveTesting: !options.dryRun,
      allowNetworkAccess: false,
      allowFilesystemWrite: false,
    },
    dryRun: options.dryRun ?? false,
  });

  const modelId = options.model ?? loadConfig().defaultModel ?? "mock";
  const model = modelId === "mock"
    ? new DeterministicMockModel([])
    : (() => {
        // Future: resolve real AI model adapter from config
        console.error(error(`Unsupported model: ${modelId} — use "mock" for testing`));
        process.exit(1);
      })();

  if (!options.quiet) {
    console.log("\n  Running investigation...\n");
  }

  const controller = new InvestigationController({
    runtime,
    model,
    maxIterations,
  });

  const result = await controller.run();

  if (!options.quiet) {
    console.log(divider());
    console.log(section("📊 Investigation Result"));
    console.log(`  Status:    ${statusBadge(result.investigation.status)}`);
    console.log(`  Iterations: ${result.iterations}`);
    console.log(`  Duration:  ${(result.durationMs / 1000).toFixed(2)}s`);
    console.log(`  Findings:  ${result.investigation.findings.length}`);
    console.log(`  Hypotheses: ${result.investigation.hypotheses.length}`);
    console.log(`  Evidence:  ${(result as any).events?.filter((e: any) => e.type === "evidence.created").length ?? 0}`);
    
    if (result.errors.length > 0) {
      console.log(colorize("\n  Errors:", "red"));
      for (const err of result.errors.slice(0, 5)) {
        console.log(`    ${warn(err)}`);
      }
    }
  }

  // Generate report
  const formatter = getFormatter(format);
  const report = formatter.generate(result.investigation, result.investigation.findings);

  if (options.output) {
    writeReport(report, options.output);
  } else if (!options.quiet) {
    console.log(section("📄 Report (JSON)"));
    process.stdout.write(report + "\n");
  }

  // Save investigation data for later analysis
  const dataDir = join(resolved, ".spectra");
  if (!existsSync(dataDir)) mkdirSync(dataDir, { recursive: true });
  const dataFile = join(dataDir, `audit-${Date.now()}.json`);
  writeFileSync(dataFile, JSON.stringify({
    generatedAt: new Date().toISOString(),
    target: resolved,
    model: modelId,
    iterations: result.iterations,
    durationMs: result.durationMs,
    investigation: result.investigation,
  }, null, 2), "utf-8");

  if (!options.quiet) {
    console.log(success(`Investigation data saved to ${dataFile}`));
  }

  // Exit code: 0 = no high/critical findings, 1 = has findings
  const hasHighSeverity = result.investigation.findings.some(
    f => f.severity === "high" || f.severity === "critical",
  );
  process.exit(hasHighSeverity ? 1 : 0);
}

// ─── Findings command ─────────────────────────────────────────────────────────

function runFindings(_options: { severity?: string; limit?: number }): void {
  console.log(section("📋 Findings"));
  console.log(warn("No saved investigations found. Run 'spectra audit' first."));
  process.exit(0);
}

// ─── Report command ───────────────────────────────────────────────────────────

function runReport(investigationId: string, options: { format?: string; output?: string }): void {
  const dataDir = join(process.cwd(), ".spectra");
  const files = existsSync(dataDir)
    ? require("fs").readdirSync(dataDir).filter((f: string) => f.includes(investigationId))
    : [];
  
  if (files.length === 0) {
    console.error(error(`No investigation data found for ID: ${investigationId}`));
    process.exit(1);
  }

  const rawData = JSON.parse(require("fs").readFileSync(join(dataDir, files[0]), "utf-8"));
  const formatter = getFormatter(options.format ?? "json");
  const report = formatter.generate(rawData.investigation, rawData.investigation.findings);
  
  if (options.output) {
    writeReport(report, options.output);
  } else {
    process.stdout.write(report + "\n");
  }
}

// ─── Projects command ─────────────────────────────────────────────────────────

function runProjects(action?: string, name?: string, path?: string): void {
  switch (action) {
    case "add":
      if (!name || !path) {
        console.error(error("Usage: spectra projects add <name> <path>"));
        process.exit(1);
      }
      addProfile(name, path);
      console.log(success(`Project "${name}" added to profile`));
      break;
    case "remove":
      if (!name) {
        console.error(error("Usage: spectra projects remove <name>"));
        process.exit(1);
      }
      removeProfile(name);
      console.log(success(`Project "${name}" removed`));
      break;
    case "list":
    case undefined:
    default:
      const profiles = listProfiles();
      console.log(section("📁 Project Profiles"));
      if (Object.keys(profiles).length === 0) {
        console.log(warn("No profiles configured. Use: spectra projects add <name> <path>"));
      } else {
        for (const [projName, proj] of Object.entries(profiles)) {
          const lastAudit = proj.lastAudit
            ? new Date(proj.lastAudit).toLocaleString()
            : "never";
          console.log(`  ${colorize(projName, "cyan")}  ${proj.path}`);
          console.log(`         Last audit: ${lastAudit}`);
        }
      }
      break;
  }
}

// ─── Config command ───────────────────────────────────────────────────────────

function runConfig(action?: string, key?: string, value?: string): void {
  const cfg = loadConfig();
  switch (action) {
    case "set":
      if (!key || !value) {
        console.error(error("Usage: spectra config set <key> <value>"));
        process.exit(1);
      }
      (cfg as any)[key ?? "defaultModel"] = value;
      saveConfig(cfg);
      console.log(success(`Config "${key}" set to "${value}"`));
      break;
    case "get":
      console.log(JSON.stringify((cfg as any)[key ?? "defaultModel"] ?? "not set", null, 2));
      break;
    case "show":
    default:
      console.log(section("⚙️ Spectra Configuration"));
      console.log(JSON.stringify(cfg, null, 2));
      break;
  }
}

// ─── Init command ─────────────────────────────────────────────────────────────

function runInit(): void {
  mkdirSync(join(homedir(), ".spectra"), { recursive: true });
  console.log(success("Initialized ~/.spectra directory"));
  console.log("Use 'spectra config' to configure settings.");
}

// ─── Version command ──────────────────────────────────────────────────────────

function runVersion(): void {
  console.log(`Hilbras Spectra v${VERSION}`);
  console.log(`Package: @hilbras/spectra@${VERSION}`);
  console.log(`CLI: spectra`);
}

// ─── Main ─────────────────────────────────────────────────────────────────────

const _app = program
  .name("spectra")
  .description("Hilbras Spectra — Autonomous AI Security Research Platform")
  .version(VERSION);

// Audit command
program
  .command("audit")
  .description("Run security investigation against a target project")
  .argument("<target>", "Local path, git URL, or docker reference")
  .option("-n, --dry-run", "Plan-only mode — no tools executed")
  .option("-m, --model <id>", "AI model to use (mock, openai, anthropic)")
  .option("-f, --format <fmt>", "Output format: json, sarif, markdown", "json")
  .option("-d, --depth <level>", "Investigation depth: quick, full", "full")
  .option("-o, --output <path>", "Write report to file instead of stdout")
  .option("-q, --quiet", "Suppress progress output", false)
  .action(async (target: string, opts: any) => {
    await runAudit(target, opts);
  });

// Report command
program
  .command("report")
  .description("Generate report from saved investigation data")
  .argument("<investigation-id>", "ID or filename prefix of saved audit")
  .option("-f, --format <fmt>", "Output format: json, sarif, markdown", "json")
  .option("-o, --output <path>", "Write report to file")
  .action(runReport);

// Findings command
program
  .command("findings")
  .description("List findings from recent audits")
  .option("--severity <level>", "Filter by severity: low, medium, high, critical")
  .option("--limit <n>", "Max findings to show", "20")
  .action(runFindings);

// Projects command
program
  .command("projects")
  .description("Manage project profiles")
  .argument("[action]", "add, remove, list")
  .argument("[name]", "Project name")
  .argument("[path]", "Project path")
  .action(runProjects);

// Config command
program
  .command("config")
  .description("View and edit configuration")
  .argument("[action]", "show, set, get")
  .argument("[key]", "Config key")
  .argument("[value]", "Config value")
  .action(runConfig);

// Init command
program
  .command("init")
  .description("Initialize config directory (~/.spectra)")
  .action(runInit);

// Version command
program
  .command("version")
  .description("Show version information")
  .action(runVersion);

// Parse and run
program.parseAsync().catch((err) => {
  console.error(error("Failed to run spectra:"), err);
  process.exit(1);
});
