import { execSync, spawnSync } from "node:child_process";
import { join } from "node:path";

// VULNERABLE: command injection via unsanitized filename parameter
export function generateReport(filename: string, outputDir: string): string {
  // Direct shell interpolation — classic command injection
  const cmd = `cat "${filename}" | wc -l`;
  const result = execSync(cmd, { encoding: "utf-8" });
  return result.trim();
}

// VULNERABLE: spawn with user-controlled argument array
export function listFiles(pattern: string, directory: string): string[] {
  // pattern can contain shell metacharacters
  const result = spawnSync("find", [directory, "-name", pattern], {
    encoding: "utf-8",
    timeout: 5000,
  });
  return result.stdout.split("\n").filter(Boolean);
}

// VULNERABLE: loading config via eval
export function loadConfig(configPath: string): Record<string, unknown> {
  const fs = await import("node:fs/promises");
  const content = await fs.readFile(configPath, "utf-8");
  // eval on external input — arbitrary code execution
  // eslint-disable-next-line no-eval
  return eval(`(${content})`);
}
