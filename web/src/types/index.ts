export interface AuditMeta {
  id: string;
  generatedAt: string;
  target: string;
  durationMs: number;
  iterations: number;
  model: string;
  status: string;
}

export interface Finding {
  id: string;
  title: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'informational';
  category: string;
  cwe?: string;
  component?: string;
  confidence: number;
  status: string;
  description?: string;
}

export interface Hypothesis {
  id: string;
  category: string;
  claim: string;
  confidence: number;
  status: string;
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
    findings: Finding[];
    hypotheses: Hypothesis[];
    evidence: unknown[];
  };
  summary?: {
    overallScore: number;
    criticalCount: number;
    highCount: number;
    mediumCount: number;
    lowCount: number;
    informationalCount: number;
  };
}

export interface ApiConfig {
  defaultModel: string;
  defaultFormat: string;
  autoApproveThreshold: string;
  profiles: Record<string, { path: string; lastAudit?: string }>;
  apiKeys?: Record<string, string>;
  theme?: 'dark' | 'light';
}

export interface HealthCheck {
  nodeVersion: string;
  npmVersion: string;
  binPath: string;
  version: string;
  theme: 'dark' | 'light';
  configExists: boolean;
  dockerAvailable: boolean;
  issues: string[];
  warnings: string[];
}

export interface AuditProgress {
  phase: string;
  iteration: number;
  maxIterations: number;
  status: 'running' | 'completed' | 'failed';
  currentFinding?: Finding;
}
