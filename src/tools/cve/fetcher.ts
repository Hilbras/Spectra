/**
 * Hilbras Spectra — CVE Fetcher
 * 
 * Queries the NVD API for current CVE data and caches results locally.
 */

import { readFileSync, writeFileSync, existsSync } from "fs";
import { join } from "path";
import { homedir } from "os";

const CACHE_DIR = join(homedir(), ".spectra", "data");
const CACHE_FILE = join(CACHE_DIR, "cve-cache.json");
const TTL_MS = 24 * 60 * 60 * 1000; // 24 hours

export interface CVERecord {
  cveId: string;
  description: string;
  severity: "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
  publishDate: string;
  lastModified: string;
  references: Array<{ url: string; name: string }>;
  metrics?: Record<string, unknown>;
  cweId?: string;
}

export class CVEFetcher {
  private cache: Map<string, { data: CVERecord[]; timestamp: number }> = new Map();

  constructor() {
    this.loadCache();
  }

  private loadCache(): void {
    if (!existsSync(CACHE_FILE)) return;
    try {
      const raw = JSON.parse(readFileSync(CACHE_FILE, "utf-8")) as Record<string, { data: CVERecord[]; timestamp: number }>;
      this.cache = new Map(Object.entries(raw));
    } catch { /* ignore corrupt cache */ }
  }

  private saveCache(): void {
    const obj = Object.fromEntries(this.cache);
    writeFileSync(CACHE_FILE, JSON.stringify(obj), "utf-8");
  }

  /** Check if cached result is still fresh */
  private isFresh(key: string): boolean {
    const entry = this.cache.get(key);
    if (!entry) return false;
    return Date.now() - entry.timestamp < TTL_MS;
  }

  /** Query NVD API for CVEs matching a CPE, with caching */
  async fetchForCPE(cpe: string, options?: { maxResults?: number }): Promise<CVERecord[]> {
    const cacheKey = `cpe:${cpe}`;
    if (this.isFresh(cacheKey)) {
      return this.cache.get(cacheKey)!.data;
    }

    const maxResults = options?.maxResults ?? 20;
    const apiKey = process.env.NVD_API_KEY ?? "";
    const url = apiKey
      ? `https://services.nvd.nist.gov/rest/json/cves/2.0?cpeName=${encodeURIComponent(cpe)}&apiKey=${apiKey}&resultsPerPage=${maxResults}`
      : `https://services.nvd.nist.gov/rest/json/cves/2.0?cpeName=${encodeURIComponent(cpe)}&resultsPerPage=${maxResults}`;

    try {
      const res = await fetch(url, { signal: AbortSignal.timeout(10000) });
      if (!res.ok) throw new Error(`NVD API HTTP ${res.status}`);
      const json = await res.json() as { vulnerabilities?: Array<{ cve: Record<string, unknown> }> };
      
      const rawRecords = (json.vulnerabilities ?? [])
        .map((v) => this.parseCVE(v.cve))
        .filter((r): r is CVERecord => r !== null);
      const records: CVERecord[] = rawRecords.slice(0, maxResults);

      this.cache.set(cacheKey, { data: records, timestamp: Date.now() });
      this.saveCache();
      return records;
    } catch {
      // Network error or timeout — return empty, don't crash
      return [];
    }
  }

  /** Query by CVE ID directly */
  async fetchByCVEId(cveId: string): Promise<CVERecord | null> {
    const cacheKey = `cve:${cveId}`;
    if (this.isFresh(cacheKey)) {
      const data = this.cache.get(cacheKey)!;
      return data.data[0] ?? null;
    }

    const apiKey = process.env.NVD_API_KEY ?? "";
    const url = apiKey
      ? `https://services.nvd.nist.gov/rest/json/cves/${cveId}?apiKey=${apiKey}`
      : `https://services.nvd.nist.gov/rest/json/cves/${cveId}`;

    try {
      const res = await fetch(url, { signal: AbortSignal.timeout(10000) });
      if (!res.ok) return null;
      const json = await res.json() as { vulnerabilities?: Array<{ cve: Record<string, unknown> }> };
      const rawCve = json.vulnerabilities?.[0]?.cve;
      const record = rawCve ? this.parseCVE(rawCve) : null;
      if (record) {
        this.cache.set(cacheKey, { data: [record], timestamp: Date.now() });
        this.saveCache();
      }
      return record ?? null;
    } catch {
      return null;
    }
  }

  clearCache(): void {
    this.cache.clear();
    try { if (existsSync(CACHE_FILE)) require("fs").unlinkSync(CACHE_FILE); } catch { /* ignore */ }
  }

  getCacheStats(): { entries: number; sizeBytes: number } {
    return { entries: this.cache.size, sizeBytes: require("fs").existsSync(CACHE_FILE) ? require("fs").statSync(CACHE_FILE).size : 0 };
  }

  // ─── Parsing ────────────────────────────────────────────────────────────────

  private parseCVE(raw: Record<string, unknown>): CVERecord | null {
    const id = String(raw.id ?? "");
    if (!id || !id.startsWith("CVE-")) return null;

    const descs = (raw.description ?? []) as Array<{ value: string }>;
    const primaryDesc = descs.find((d) => d.value.includes("cpe:2.3") === false) ?? descs[0];
    const description = primaryDesc?.value ?? "";

    const metrics = raw.metrics as Record<string, unknown> | undefined;
    const severity = this.extractSeverity(metrics);
    const refs = ((raw.references ?? []) as Array<{ url?: string; name?: string }>).filter((r) => r.url);
    const cweIds = ((raw.problemTypes ?? []) as Array<{ descriptions?: Array<{ type?: string; description?: string[] }> }>)
      .flatMap((p) => p.descriptions ?? [])
      .flatMap((d) => d.description ?? [])
      .filter((d) => d.startsWith("CWE-"));

    return {
      cveId: id,
      description: description.slice(0, 500),
      severity,
      publishDate: String(raw.pubDate ?? ""),
      lastModified: String(raw.lastModified ?? ""),
      references: refs.map((r) => ({ url: r.url ?? "", name: r.name ?? "" })),
      metrics: metrics ?? {},
      ...(cweIds[0] ? { cweId: cweIds[0] } : {}),
    };
  }

  private extractSeverity(metrics: Record<string, unknown> | undefined): CVERecord["severity"] {
    if (!metrics) return "MEDIUM";
    const cvssV3 = metrics["cvssMetricV31"] ?? metrics["cvssMetricV3"];
    if (!cvssV3) return "MEDIUM";
    const arr = Array.isArray(cvssV3) ? cvssV3 : [cvssV3];
    for (const m of arr) {
      const cvssData = (m as Record<string, unknown>)?.cvssData as Record<string, unknown> | undefined;
      const base = cvssData?.baseScore;
      if (typeof base === "number") {
        if (base >= 9) return "CRITICAL";
        if (base >= 7) return "HIGH";
        if (base >= 4) return "MEDIUM";
        return "LOW";
      }
    }
    return "MEDIUM";
  }
}
