/**
 * Hilbras Spectra — CLI Configuration Manager
 * 
 * Persists user preferences and API keys to ~/.spectra/config.json.
 * Supports: default model, output format, auto-approve, project profiles.
 */

import { readFileSync, writeFileSync, mkdirSync, existsSync } from "fs";
import { join } from "path";
import { homedir } from "os";

const CONFIG_DIR = join(homedir(), ".spectra");
const CONFIG_FILE = join(CONFIG_DIR, "config.json");

export interface SpectraConfig {
  /** Default AI model provider (e.g., "mock", "openai", "anthropic") */
  defaultModel?: string;
  /** Default output format for reports (json | sarif | markdown) */
  defaultFormat?: "json" | "sarif" | "markdown";
  /** Auto-confirm findings above this severity (low | medium | high | critical) */
  autoApproveThreshold?: "low" | "medium" | "high" | "critical";
  /** Saved project profiles */
  profiles?: Record<string, { path: string; tags?: string[]; lastAudit?: string }>;
  /** API keys per provider */
  apiKeys?: { [provider: string]: string };
}

const DEFAULT_CONFIG: SpectraConfig = {
  defaultModel: "mock",
  defaultFormat: "json",
  autoApproveThreshold: "medium",
  profiles: {},
  apiKeys: {},
};

export function loadConfig(): SpectraConfig {
  if (!existsSync(CONFIG_FILE)) {
    mkdirSync(CONFIG_DIR, { recursive: true });
    return { ...DEFAULT_CONFIG };
  }
  try {
    const raw = readFileSync(CONFIG_FILE, "utf-8");
    return { ...DEFAULT_CONFIG, ...JSON.parse(raw) };
  } catch {
    return { ...DEFAULT_CONFIG };
  }
}

export function saveConfig(cfg: SpectraConfig): void {
  mkdirSync(CONFIG_DIR, { recursive: true });
  writeFileSync(CONFIG_FILE, JSON.stringify(cfg, null, 2), "utf-8");
}

export function addProfile(name: string, path: string, tags: string[] = []): void {
  const cfg = loadConfig();
  cfg.profiles ??= {};
  cfg.profiles[name] = {
    path,
    tags,
    lastAudit: new Date().toISOString(),
  };
  saveConfig(cfg);
}

export function removeProfile(name: string): void {
  const cfg = loadConfig();
  if (cfg.profiles) delete cfg.profiles[name];
  saveConfig(cfg);
}

export function listProfiles(): Record<string, { path: string; tags?: string[]; lastAudit?: string }> {
  return loadConfig().profiles ?? {};
}
