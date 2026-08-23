/**
 * Hilbras Spectra — SecurityModel
 *
 * Internal representation of a project's security-relevant structure.
 * Built from ProjectIndex + tool results; queried by the AI investigation loop.
 */

import type { ProjectIndex } from "../index/index.js";

export interface Asset {
  id: string;
  type: "user" | "account" | "credential" | "token" | "personal_data" | "financial_data"
    | "admin_function" | "database" | "file" | "internal_service" | "external_service"
    | "api_endpoint" | "queue" | "cache" | "storage";
  name: string;
  location: string;
  sensitivity: "public" | "internal" | "confidential" | "restricted";
  evidence: string[]; // source evidence IDs
}

export interface TrustBoundary {
  id: string;
  from: string;
  to: string;
  controls: string[];
  weaknesses: string[];
}

export interface DataFlow {
  id: string;
  fromAsset: string;
  toAsset: string;
  protocol: string;
  sensitivity: string;
  validated: boolean;
}

export interface AuthFlow {
  id: string;
  steps: string[];
  entryPoint: string;
  tokenType?: string;
  weakness?: string;
}

export interface SecurityControl {
  id: string;
  type: "authentication" | "authorization" | "input_validation" | "output_encoding"
    | "csrf_protection" | "rate_limiting" | "security_headers" | "encryption"
    | "logging" | "session_management" | "tenant_isolation";
  present: boolean;
  location?: string;
  weakness?: string;
}

export interface SecurityModel {
  assets: Asset[];
  trustBoundaries: TrustBoundary[];
  dataFlows: DataFlow[];
  authFlows: AuthFlow[];
  controls: SecurityControl[];
  sources: Array<{ name: string; location: string; category: string }>;
  sinks: Array<{ name: string; location: string; category: string }>;
  endpoints: Array<{ method: string; path: string; authRequired: boolean; sensitivity: string }>;
}

/** Build a SecurityModel from a ProjectIndex and tool results */
export function buildSecurityModel(index: ProjectIndex): SecurityModel {
  const assets: Asset[] = [];
  const trustBoundaries: TrustBoundary[] = [];
  const dataFlows: DataFlow[] = [];
  const authFlows: AuthFlow[] = [];
  const controls: SecurityControl[] = [];
  const srcList: Array<{ name: string; location: string; category: string }> = [];
  const snkList: Array<{ name: string; location: string; category: string }> = [];
  const endpoints: Array<{ method: string; path: string; authRequired: boolean; sensitivity: string }> = [];

  // Discover assets from file contents and index
  for (const [rel, file] of index.files) {
    if (!["typescript", "javascript"].includes(file.language)) continue;
    try {
      const content = require("node:fs").readFileSync(file.absolute, "utf-8");
      // Detect database connections
      if (/createPool|new\s+Database|mongoose\.connect|pg\.createClient/i.test(content)) {
        assets.push({ id: `asset_db_${assets.length}`, type: "database", name: "Database connection", location: rel, sensitivity: "restricted", evidence: [] });
      }
      // Detect auth handlers
      if (/jwt|jsonwebtoken|passport|session|cookie.*auth|bearer/i.test(content)) {
        assets.push({ id: `asset_cred_${assets.length}`, type: "credential", name: "Authentication credentials", location: rel, sensitivity: "confidential", evidence: [] });
      }
      // Detect user-facing routes
      if (/\.(get|post|put|delete)\s*\(/.test(content)) {
        assets.push({ id: `asset_api_${assets.length}`, type: "api_endpoint", name: "HTTP endpoint handler", location: rel, sensitivity: "internal", evidence: [] });
      }
    } catch { /* skip */ }
  }

  // Trust boundaries from architecture
  if (assets.some((a) => a.type === "api_endpoint") && assets.some((a) => a.type === "database")) {
    trustBoundaries.push({
      id: "tb_net_to_db",
      from: "Internet/API Layer",
      to: "Database",
      controls: ["authentication", "authorization", "input validation"],
      weaknesses: [],
    });
  }

  // Data flows from routes
  for (const route of index.routes) {
    endpoints.push({
      method: route.method,
      path: route.path,
      authRequired: route.middleware?.length > 0,
      sensitivity: /admin|payment|refund|user/i.test(route.path) ? "high" : "medium",
    });
    if (route.handler) {
      dataFlows.push({
        id: `df_${dataFlows.length}`,
        fromAsset: "HTTP Client",
        toAsset: route.handler,
        protocol: route.method,
        sensitivity: "internal",
        validated: false,
      });
    }
  }

  // Sources and sinks from taint analysis
  const sqlSinks = index.findTaintPaths("request", ["query(", "execute(", "prepare("]);
  for (const p of sqlSinks.slice(0, 10)) {
    snkList.push({ name: "SQL query construction", location: p.sink.file, category: "sql" });
    srcList.push({ name: "User request input", location: p.source.file, category: "http" });
  }

  const cmdSinks = index.findCommandSinks();
  for (const s of cmdSinks) {
    snkList.push({ name: s.code.slice(0, 40), location: s.file, category: "command" });
  }

  // Auth control assessment
  const authLibraries = new Set(["jsonwebtoken", "jose", "passport", "firebase-admin", "auth0"]);
  const depNames = new Set(index.dependencies.map((d) => d.name));
  const hasAuth = [...depNames].some((d) => authLibraries.has(d));
  if (hasAuth) {
    controls.push({ id: "ctrl_auth", type: "authentication", present: true, location: "dependencies" });
  } else {
    controls.push({ id: "ctrl_auth", type: "authentication", present: false, weakness: "No authentication library detected in dependencies" });
  }

  // CORS check
  const corsFiles = index.searchText("cors", 5);
  if (corsFiles.some((r) => r.text.toLowerCase().includes("*"))) {
    controls.push({ id: "ctrl_cors", type: "security_headers", present: true, weakness: "Wildcard CORS origin detected" });
  }

  return { assets, trustBoundaries, dataFlows, authFlows, controls, sources: srcList, sinks: snkList, endpoints };
}
