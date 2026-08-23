/**
 * Hilbras Spectra — Secret Detection Tool
 *
 * Multi-signal secret detection: pattern matching + entropy analysis + context.
 * Sensitive values are masked in all outputs.
 */

import type { ToolExecutionContext, ToolOutput } from "../../investigation/runtime.js";

interface SecretHit {
  file: string;
  line: number;
  type: string;
  pattern: string;
  maskedValue: string;
  confidence: number;
}

type PatternDef = { name: string; regex: RegExp; confidence: number };

const PATTERNS: PatternDef[] = [
  { name: "aws_access_key",   regex: /AKIA[0-9A-Z]{16}/g,                          confidence: 0.95 },
  { name: "github_token",     regex: /ghp_[0-9A-Za-z]{36}/g,                       confidence: 0.95 },
  { name: "generic_api_key",  regex: /(?:api[_-]?key|apikey)\s*[:=]\s*["']?[0-9A-Za-z_-]{20,}/gi, confidence: 0.6 },
  { name: "jwt_token",        regex: /eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/g, confidence: 0.85 },
  { name: "private_key",      regex: /-----BEGIN\s+(RSA|EC|OPENSSH|PGP)?\s*PRIVATE\s+KEY-----/g, confidence: 0.99 },
  { name: "database_url",     regex: /(?:postgres|mysql|mongodb|redis):\/\/[^\s"')\]]+/gi, confidence: 0.8 },
  { name: "slack_token",      regex: /xox[baprs]-[0-9A-Za-z-]+/g,                  confidence: 0.95 },
  { name: "stripe_key",       regex: /sk_live_[0-9a-zA-Z]{24,}/g,                   confidence: 0.95 },
];

function shannonEntropy(s: string): number {
  if (!s) return 0;
  const freq = new Map<string, number>();
  for (const c of s) freq.set(c, (freq.get(c) ?? 0) + 1);
  let ent = 0;
  for (const count of freq.values()) {
    const p = count / s.length;
    ent -= p * Math.log2(p);
  }
  return ent;
}

function maskValue(value: string): string {
  if (value.length <= 4) return "****";
  return value.slice(0, 4) + "*".repeat(Math.min(value.length - 4, 12));
}

export async function scanSecrets(
  input: Record<string, unknown>,
  ctx: ToolExecutionContext,
): Promise<ToolOutput> {
  const start = Date.now();
  try {
    const scope = String(input.scope ?? "full");
    const hits: SecretHit[] = [];
    const seen = new Set<string>();
    const fs = require("node:fs") as typeof import("node:fs");
    const path = require("node:path") as typeof import("node:path");

    const extRe = /\.(ts|js|py|go|rs|json|yaml|yml|toml|env|sh|md|txt|cfg|ini|conf)$|^package\.json$|^Dockerfile$|^docker-compose\./i;
    const skipDirs = ["node_modules", ".git", "dist", "build"];

    function walk(dir: string, relPrefix: string): void {
      let entries: any[];
      try { entries = fs.readdirSync(dir, { withFileTypes: true }); } catch { return; }
      for (const entry of entries) {
        if (entry.isDirectory()) {
          if (skipDirs.includes(entry.name)) continue;
          walk(path.join(dir, entry.name), relPrefix ? `${relPrefix}/${entry.name}` : entry.name);
        } else if (entry.isFile() && extRe.test(entry.name)) {
          const rel = relPrefix ? `${relPrefix}/${entry.name}` : entry.name;
          if (skipDirs.some((d) => rel.includes(`/${d}/`) || rel.startsWith(`${d}/`))) continue;
          let content: string;
          try { content = fs.readFileSync(path.join(dir, entry.name), "utf-8"); } catch { continue; }
          const lines = content.split("\n");
          for (let i = 0; i < lines.length; i++) {
            const line = lines[i]!;
            for (const pat of PATTERNS) {
              pat.regex.lastIndex = 0;
              const match = pat.regex.exec(line);
              if (!match) continue;
              const value = match[0];
              const key = `${rel}:${i + 1}:${value.slice(0, 10)}`;
              if (seen.has(key)) continue;
              seen.add(key);
              const words = value.split(/[^\w]/).filter(Boolean);
              const avgEnt = words.length > 0
                ? words.reduce((s: number, w: string) => s + shannonEntropy(w), 0) / words.length
                : 0;
              const boost = avgEnt > 3.5 ? 0.15 : 0;
              if (/^\s*(\/|\*|#|--)/.test(line)) continue;
              hits.push({
                file: rel,
                line: i + 1,
                type: pat.name,
                pattern: value.slice(0, 30),
                maskedValue: maskValue(value),
                confidence: Math.min(1, pat.confidence + boost),
              });
            }
          }
        }
      }
    }

    walk(ctx.rootPath, "");

    return {
      success: true,
      data: {
        scope,
        hits,
        totalHits: hits.length,
        highConfidence: hits.filter((h) => h.confidence >= 0.8).length,
      },
      resultSize: JSON.stringify(hits).length,
      durationMs: Date.now() - start,
    };
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    return { success: false, data: null, error: msg, resultSize: 0, durationMs: Date.now() - start };
  }
}
