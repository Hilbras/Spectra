/**
 * Hilbras Spectra — CLI Shared Types
 */

export interface AuditMeta {
  id: string;
  timestamp: string;
  target: string;
  durationMs: number;
  iterations: number;
  model: string;
  depth: string;
  status: string;
  summary: AuditSummary;
}

export interface AuditSummary {
  overallScore: number;
  criticalCount: number;
  highCount: number;
  mediumCount: number;
  lowCount: number;
  informationalCount: number;
  confirmedCount: number;
  potentialCount: number;
  hypothesisCount: number;
  evidenceCount: number;
  topRisks: Array<{ title: string; severity: string; category: string }>;
}

export interface FindingRecord {
  id: string;
  title: string;
  severity: string;
  category: string;
  cwe?: string;
  owasp?: string;
  confidence: number;
  status: string;
  component?: string;
  rootCause?: string;
}

export interface StoredAudit {
  generatedAt: string;
  target: string;
  model: string;
  iterations: number;
  durationMs: number;
  investigation: {
    id: string;
    projectId: string;
    status: string;
    phase: string;
    findings: FindingRecord[];
    hypotheses: Array<{ id: string; category: string; claim: string; confidence: number; status: string }>;
    evidence: unknown[];
  };
  summary?: AuditSummary;
}

export interface ConfigData {
  defaultModel: string;
  defaultFormat: string;
  autoApproveThreshold: string;
  profiles: Record<string, { path: string; tags?: string[]; lastAudit?: string }>;
  apiKeys?: Record<string, string>;
}

export interface HealthCheck {
  nodeVersion: string;
  npmVersion: string;
  nodePath: string;
  spectralBin: string;
  spectralVersion: string;
  homeDir: string;
  spectraDir: string;
  spectraConfigExists: boolean;
  fixturesAvailable: boolean;
  nodeModulesOk: boolean;
  issues: string[];
  warnings: string[];
}
