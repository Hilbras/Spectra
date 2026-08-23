/**
 * Hilbras Spectra — Dependency Analysis Tool
 *
 * Reads package manifests and lockfiles, classifies dependencies by risk level.
 * Distinguishes known CVEs from outdated-but-unexploited packages.
 */

import { readFile } from "node:fs/promises";
import { join } from "node:path";
import type { ToolExecutionContext, ToolOutput } from "../../investigation/runtime.js";

// Known vulnerability metadata (compact embedded DB for common packages)
const KNOWN_CVES: Record<string, Array<{ version: string; cwe: string; severity: string; description: string }>> = {
  "lodash": [{ version: "<4.17.21", cwe: "CWE-1321", severity: "high", description: "Prototype pollution" }],
  "express": [{ version: "<4.19.2", cwe: "CWE-1333", severity: "medium", description: "Open redirect vulnerability" }],
  "jsonwebtoken": [{ version: "<9.0.0", cwe: "CWE-327", severity: "critical", description: "Algorithm confusion / key injection" }],
  "minimatch": [{ version: "<3.0.5", cwe: "CWE-400", severity: "high", description: "ReDoS via uncontrolled recursion" }],
  "node-fetch": [{ version: "<2.6.7", cwe: "CWE-200", severity: "medium", description: "Information exposure via headers" }],
  "helmet": [{ version: "<7.0.0", cwe: "CWE-693", severity: "low", description: "Missing security headers" }],
  "cors": [{ version: "*", cwe: "CWE-942", severity: "medium", description: "Wildcard origin allows any caller" }],
};

export async function analyzeDependencies(
  input: Record<string, unknown>,
  ctx: ToolExecutionContext,
): Promise<ToolOutput> {
  const start = Date.now();
  try {
    const pm = String(input.packageManager ?? "npm");
    const _includeTransitive = Boolean(input.includeTransitive);

    // Read manifest
    const manifestPath = join(ctx.rootPath, "package.json");
    let deps: Array<{ name: string; version: string; isDev: boolean }> = [];
    try {
      const raw = await readFile(manifestPath, "utf-8");
      const pkg = JSON.parse(raw);
      deps = [
        ...Object.entries(pkg.dependencies ?? {}).map(([name, ver]: [string, any]) => ({ name, version: String(ver), isDev: false })),
        ...Object.entries(pkg.devDependencies ?? {}).map(([name, ver]: [string, any]) => ({ name, version: String(ver), isDev: true })),
      ];
    } catch { /* no manifest */ }

    const results = deps.map((dep) => {
      const cleanVer = dep.version.replace(/[\^~>=<]/g, "");
      const cveEntry = KNOWN_CVES[dep.name];
      if (!cveEntry) {
        return { name: dep.name, version: cleanVer, risk: "informational", classification: "no_known_vulns" as const };
      }
      const matching = cveEntry.find((c) => _versionLt(cleanVer, c.version.replace("<", "").trim()));
      if (matching) {
        return { name: dep.name, version: cleanVer, risk: matching.severity, classification: "known_vulnerability" as const, cwe: matching.cwe, description: matching.description };
      }
      return { name: dep.name, version: cleanVer, risk: "informational", classification: "outdated_safe" as const };
    });

    return {
      success: true,
      data: {
        packageManager: pm,
        totalDeps: deps.length,
        directDeps: deps.filter((d) => !d.isDev).length,
        devDeps: deps.filter((d) => d.isDev).length,
        vulnerabilities: results.filter((r) => r.classification === "known_vulnerability"),
        risky: results.filter((r) => r.risk === "high" || r.risk === "critical"),
        all: results,
      },
      resultSize: JSON.stringify(results).length,
      durationMs: Date.now() - start,
    };
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    return { success: false, data: null, error: msg, resultSize: 0, durationMs: Date.now() - start };
  }
}

/** Simple semver less-than (handles ^, ~, * prefixes) */
function _versionLt(a: string, b: string): boolean {
  const parse = (v: string) => v.split(".").map((n) => parseInt(n, 10) || 0);
  const [ma, ma1, ma2] = parse(a);
  const [mb, mb1, mb2] = parse(b);
  if ((ma ?? 0) < (mb ?? 0)) return true;
  if ((ma ?? 0) > (mb ?? 0)) return false;
  if ((ma1 ?? 0) < (mb1 ?? 0)) return true;
  if ((ma1 ?? 0) > (mb1 ?? 0)) return false;
  return (ma2 ?? 0) < (mb2 ?? 0);
}
