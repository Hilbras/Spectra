/**
 * Hilbras Spectra — Configuration Analysis Tool
 *
 * Analyzes Dockerfiles, docker-compose, .env, CI/CD configs, nginx, and security headers.
 * Each finding includes the exact configuration source location.
 */

import { readFile } from "node:fs/promises";
import { join } from "node:path";
import type { ToolExecutionContext, ToolOutput } from "../../investigation/runtime.js";

interface ConfigIssue {
  file: string;
  line?: number;
  category: string;
  severity: "high" | "medium" | "low" | "info";
  rule: string;
  description: string;
  recommendation: string;
}

export async function analyzeConfig(
  input: Record<string, unknown>,
  ctx: ToolExecutionContext,
): Promise<ToolOutput> {
  const start = Date.now();
  const issues: ConfigIssue[] = [];
  const _fileTypes = (input.fileTypes as string[]) ?? ["Dockerfile*", ".env*", "*.yml", "*.yaml", "*.json", "nginx*.conf", ".github/**/*"];

  // Collect config files
  const configFiles: string[] = [];
  try {
    const walk = (dir: string, prefix: string) => {
      try {
        for (const entry of require("node:fs").readdirSync(dir, { withFileTypes: true }) as any[]) {
          if (entry.isDirectory()) {
            if (entry.name === "node_modules" || entry.name === ".git") continue;
            walk(join(dir, entry.name), `${prefix}/${entry.name}`);
          } else {
            const rel = `${prefix}/${entry.name}`;
            if (/\.(env|yml|yaml|json|tf|hcl|conf|cfg|ini|dockerfile|Dockerfile)$/i.test(rel) || rel.includes("Dockerfile") || rel.includes(".github/")) {
              configFiles.push(rel);
            }
          }
        }
      } catch { /* skip */ }
    };
    walk(ctx.rootPath, "");
  } catch { /* no root */ }

  for (const file of configFiles.slice(0, 50)) {
    const abs = join(ctx.rootPath, file);
    try {
      const content = await readFile(abs, "utf-8");
      const lines = content.split("\n");
      for (let i = 0; i < lines.length; i++) {
        const line = lines[i]!;
        // Docker: running as root
        if (/^USER\s+root/i.test(line)) issues.push({ file, line: i + 1, category: "docker", severity: "high", rule: "no-root-user", description: "Container runs as root", recommendation: "Add USER <non-root>" });
        // Docker: privileged
        if (/--privileged/.test(line)) issues.push({ file, line: i + 1, category: "docker", severity: "high", rule: "no-privileged", description: "Privileged container", recommendation: "Use specific cap-add instead" });
        // Docker: host network
        if (/network_mode:\s*host/i.test(line) || /--network\s*host/i.test(line)) issues.push({ file, line: i + 1, category: "docker", severity: "high", rule: "no-host-network", description: "Host network mode exposes all interfaces", recommendation: "Use bridge with explicit port mapping" });
        // Env: hardcoded secrets
        if (/^(API_KEY|SECRET|PASSWORD|TOKEN|PRIVATE_KEY)\s*=\s*\S/i.test(line)) issues.push({ file, line: i + 1, category: "secret_exposure", severity: "high", rule: "hardcoded-secret", description: "Hardcoded credential in config file", recommendation: "Move to environment variable or secret manager" });
        // .env: check for git inclusion
        if (file.endsWith(".env") && !file.includes(".env.example")) issues.push({ file, line: i + 1, category: "secret_exposure", severity: "medium", rule: "env-in-repo", description: ".env file present in repository", recommendation: "Add .env to .gitignore; use .env.example" });
        // YAML: bind to 0.0.0.0
        if (/bind:\s*0\.0\.0\.0|host:\s*0\.0\.0\.0/i.test(line)) issues.push({ file, line: i + 1, category: "network", severity: "medium", rule: "bind-all", description: "Service bound to all interfaces", recommendation: "Bind to 127.0.0.1 or internal network" });
        // CORS wildcard
        if (/Access-Control-Allow-Origin:\s*\*/i.test(line) || /"origin"\s*:\s*"\*"/i.test(line)) issues.push({ file, line: i + 1, category: "cors", severity: "high", rule: "cors-wildcard", description: "CORS allows all origins", recommendation: "Restrict to specific trusted origins" });
        // TLS disabled
        if (/ssl\s*off|disable_ssl|insecure/i.test(line)) issues.push({ file, line: i + 1, category: "tls", severity: "high", rule: "tls-disabled", description: "TLS/SSL appears disabled", recommendation: "Enable TLS for all external communication" });
        // Missing security headers
        if (file.includes("nginx") && /X-Frame-Options|X-Content-Type-Options|Strict-Transport-Security/.test(content)) {
          for (const header of ["X-Frame-Options", "X-Content-Type-Options", "Strict-Transport-Security", "Content-Security-Policy"]) {
            if (!new RegExp(header, "i").test(content)) {
              issues.push({ file, category: "headers", severity: "medium", rule: `missing-${header.replace(/-/g, "_").toLowerCase()}`, description: `Missing security header: ${header}`, recommendation: `Add ${header} header` });
            }
          }
        }
      }
    } catch { /* skip unreadable */ }
  }

  return {
    success: true,
    data: { filesAnalyzed: configFiles.length, totalIssues: issues.length, highSeverity: issues.filter((i) => i.severity === "high").length, issues },
    resultSize: JSON.stringify(issues).length,
    durationMs: Date.now() - start,
  };
}
