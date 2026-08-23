/**
 * Hilbras Spectra — CLI Entry Point
 *
 * spectra audit <target>
 * spectra projects
 * spectra findings
 * spectra report
 */

import { HilbrasSecurityRuntime } from "../investigation/runtime.js";

const args = process.argv.slice(2);
const command = args[0];

if (!command) {
  printUsage();
  process.exit(1);
}

switch (command) {
  case "audit":
    await runAudit(args.slice(1));
    break;
  case "projects":
    console.log("No projects configured yet.");
    break;
  case "findings":
    console.log("No findings to display.");
    break;
  case "report":
    console.log("No reports generated yet.");
    break;
  case "--help":
  case "-h":
    printUsage();
    break;
  default:
    console.error(`Unknown command: ${command}`);
    printUsage();
    process.exit(1);
}

async function runAudit(targetArgs: string[]): Promise<void> {
  if (targetArgs.length === 0) {
    console.error("Usage: spectra audit <target-path-or-url>");
    process.exit(1);
  }

  const target = targetArgs[0]!;
  const dryRun = targetArgs.includes("--dry-run");

  console.log(`\n🔍 Hilbras Spectra — Audit Starting`);
  console.log(`Target:    ${target}`);
  console.log(`Dry run:   ${dryRun}`);
  console.log(`─────────────────────────────\n`);

  const runtime = new HilbrasSecurityRuntime({
    targetPath: target,
    authorizationScope: {
      allowedHosts: [],
      allowedServices: [],
      allowedPorts: [],
      allowedEnvironments: ["local"],
      allowedOperations: ["read"],
      restrictions: ["no-host-execution", "no-credential-theft"],
      allowActiveTesting: !dryRun,
      allowNetworkAccess: false,
      allowFilesystemWrite: false,
    },
    dryRun,
  });

  // Phase-specific handlers would be registered here in the full implementation.
  // For now, the runtime advances through phases automatically.

  const result = await runtime.run();

  console.log(`\n✅ Audit Complete`);
  console.log(`Status:        ${result.status}`);
  console.log(`Duration:      ${result.durationMs}ms`);
  console.log(`Findings:      ${result.findings.length}`);
  console.log(`Hypotheses:    ${result.hypotheses.length}`);
  console.log(`Evidence:      ${result.evidenceCount}`);
  if (result.errors.length > 0) {
    console.log(`Errors:        ${result.errors.length}`);
    for (const err of result.errors) {
      console.log(`  ⚠️  ${err}`);
    }
  }
}

function printUsage(): void {
  console.log(`
Hilbras Spectra — Autonomous Security Research Platform

Usage:
  spectra audit <target>        Run a security audit against a target
  spectra audit <target> --dry-run   Plan-only mode (no tools executed)
  spectra projects              List configured projects
  spectra findings              Show findings for current project
  spectra report                Generate a security report
  spectra --help                Show this help

Targets:
  Local path:    spectra audit /path/to/project
  Git repo:      spectra audit https://github.com/user/repo
  Docker:        spectra audit docker:my-app:latest
`);
}
