/**
 * Hilbras Spectra — Audit History Store
 * 
 * Manages persisted audit metadata for history browsing,
 * reporting, and cross-audit comparison.
 */

import { readFileSync, writeFileSync, mkdirSync, existsSync, readdirSync } from "fs";
import { join } from "path";
import { homedir } from "os";
import type { StoredAudit } from "./types.js";

const DATA_DIR = join(homedir(), ".spectra", "data");
const HISTORY_FILE = join(DATA_DIR, "history.json");

function ensureDir(): void {
  if (!existsSync(DATA_DIR)) mkdirSync(DATA_DIR, { recursive: true });
}

export function loadHistory(): StoredAudit[] {
  ensureDir();
  try {
    const raw = readFileSync(HISTORY_FILE, "utf-8");
    return JSON.parse(raw) as StoredAudit[];
  } catch {
    return [];
  }
}

export function saveHistory(audits: StoredAudit[]): void {
  ensureDir();
  // Keep max 100 entries
  const trimmed = audits.slice(0, 100);
  writeFileSync(HISTORY_FILE, JSON.stringify(trimmed, null, 2), "utf-8");
}

export function appendAudit(audit: StoredAudit): void {
  const history = loadHistory();
  // Avoid duplicate by target + timestamp proximity
  const recent = history.filter(
    (a) => a.target !== audit.target || Math.abs(new Date(a.generatedAt).getTime() - new Date(audit.generatedAt).getTime()) > 60_000
  );
  recent.unshift(audit);
  saveHistory(recent.slice(0, 100));
}

export function findAudits(options: {
  target?: string;
  severity?: string;
  limit?: number;
  last?: number;
}): StoredAudit[] {
  let audits = loadHistory();
  
  if (options.target) {
    audits = audits.filter((a) => a.target.includes(options.target!) || a.investigation.projectId?.includes(options.target!));
  }
  if (options.severity) {
    const level = options.severity;
    audits = audits.filter((a) => {
      const f = a.investigation?.findings ?? [];
      return f.some((fin) => fin.severity === level);
    });
  }
  if (options.last) {
    audits = audits.slice(0, options.last);
  }
  if (options.limit) {
    audits = audits.slice(0, options.limit);
  }
  return audits;
}

export function getAuditById(id: string): StoredAudit | null {
  const audits = loadHistory();
  return audits.find((a) => a.investigation?.id === id) ?? null;
}

// Also scan per-project .spectra directories for older audits not in central history
export function discoverProjectAudits(targetPath: string): StoredAudit[] {
  const dir = join(targetPath, ".spectra");
  if (!existsSync(dir)) return [];
  try {
    return readdirSync(dir)
      .filter((f) => f.endsWith(".json"))
      .map((file) => {
        try {
          return JSON.parse(readFileSync(join(dir, file), "utf-8")) as StoredAudit;
        } catch { return null; }
      })
      .filter((a): a is StoredAudit => a !== null);
  } catch { return []; }
}
