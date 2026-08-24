/**
 * Hilbras Spectra — Domain Types
 *
 * Canonical types for investigations, findings, evidence, hypotheses,
 * tools, policies, and reports.
 */

import type { ToolParameters } from "../types/sdk-shims.js";

// ─── IDs ────────────────────────────────────────────────────────────────────

export type InvestigationId = string;
export type FindingId = string;
export type EvidenceId = string;
export type HypothesisId = string;
export type ToolName = string;

// ─── Phases ──────────────────────────────────────────────────────────────────

/** Ordered phases the AI traverses during an investigation */
export const PHASES = [
  "INITIALIZATION",
  "RECONNAISSANCE",
  "ARCHITECTURE_ANALYSIS",
  "ATTACK_SURFACE_MAPPING",
  "SOURCE_ANALYSIS",
  "DEPENDENCY_ANALYSIS",
  "CONFIGURATION_ANALYSIS",
  "SECRET_ANALYSIS",
  "AUTHENTICATION_ANALYSIS",
  "AUTHORIZATION_ANALYSIS",
  "API_ANALYSIS",
  "BUSINESS_LOGIC_ANALYSIS",
  "HYPOTHESIS_GENERATION",
  "INVESTIGATION",
  "VALIDATION",
  "EVIDENCE_COLLECTION",
  "FINDING_CORRELATION",
  "RISK_ASSESSMENT",
  "REPORTING",
  "COMPLETION",
] as const;

export type Phase = (typeof PHASES)[number];

// ─── Status enums ────────────────────────────────────────────────────────────

export const AUDIT_STATUS = {
  PENDING: "pending",
  RUNNING: "running",
  PAUSED: "paused",
  CANCELLED: "cancelled",
  COMPLETED: "completed",
  FAILED: "failed",
} as const;

export type AuditStatus = (typeof AUDIT_STATUS)[keyof typeof AUDIT_STATUS];

export const FINDING_STATUS = {
  POTENTIAL: "potential",
  VALIDATED: "validated",
  CONFIRMED: "confirmed",
  FALSE_POSITIVE: "false_positive",
  ACCEPTED_RISK: "accepted_risk",
  RESOLVED: "resolved",
  REGRESSION: "regression",
} as const;

export type FindingStatus = (typeof FINDING_STATUS)[keyof typeof FINDING_STATUS];

export const HYPOTHESIS_STATUS = {
  OPEN: "open",
  INVESTIGATING: "investigating",
  VALIDATED: "validated",
  REJECTED: "rejected",
  INCONCLUSIVE: "inconclusive",
} as const;

export type HypothesisStatus = (typeof HYPOTHESIS_STATUS)[keyof typeof HYPOTHESIS_STATUS];

// ─── Severity & Confidence ───────────────────────────────────────────────────

export const SEVERITY = {
  INFORMATIONAL: "informational",
  LOW: "low",
  MEDIUM: "medium",
  HIGH: "high",
  CRITICAL: "critical",
} as const;

export type Severity = (typeof SEVERITY)[keyof typeof SEVERITY];

export const CONFIDENCE = {
  LOW: "low",
  MEDIUM: "medium",
  HIGH: "high",
} as const;

export type Confidence = (typeof CONFIDENCE)[keyof typeof CONFIDENCE];

// ─── Risk level for hypothesis prioritization ────────────────────────────────

export const RISK_LEVEL = {
  LOW: "low",
  MEDIUM: "medium",
  HIGH: "high",
  CRITICAL: "critical",
} as const;

export type RiskLevel = (typeof RISK_LEVEL)[keyof typeof RISK_LEVEL];

// ─── Target ──────────────────────────────────────────────────────────────────

export const TARGET_TYPE = {
  LOCAL_REPO: "local_repo",
  GIT_REPO: "git_repo",
  GITHUB: "github",
  GITLAB: "gitlab",
  ARCHIVE: "archive",
  DOCKER: "docker",
  LOCAL_APP: "local_app",
  STAGING_ENV: "staging_env",
  API: "api",
} as const;

export type TargetType = (typeof TARGET_TYPE)[keyof typeof TARGET_TYPE];

// ─── SecurityProject ─────────────────────────────────────────────────────────

/** The project being analyzed — metadata plus target configuration */
export interface SecurityProject {
  id: string;
  name: string;
  description?: string;
  createdAt: Date;
  updatedAt: Date;
  /** Organization ID (multi-tenant) */
  organizationId: string;
  /** Target type */
  targetType: TargetType;
  /** Target location (path, URL, image reference) */
  targetLocation: string;
  /** Authorization scope for active testing */
  authorizationScope: AuthorizationScope;
  /** Tags for categorization */
  tags: string[];
}

// ─── AuthorizationScope ──────────────────────────────────────────────────────

/** What the AI is explicitly authorized to touch */
export interface AuthorizationScope {
  allowedHosts: string[];
  allowedServices: string[];
  allowedPorts: number[];
  allowedEnvironments: string[];
  allowedOperations: string[];
  restrictions: string[];
  allowActiveTesting: boolean;
  allowNetworkAccess: boolean;
  allowFilesystemWrite: boolean;
}

// ─── SecurityInvestigation ───────────────────────────────────────────────────

/**
 * Persistent structured state for every security audit.
 * The AI must never rely solely on conversational context —
 * this state survives restarts and powers replay.
 */
export interface SecurityInvestigation {
  id: InvestigationId;
  projectId: string;
  status: AuditStatus;
  phase: Phase;
  currentObjective: string;

  // Project model
  architecture?: ArchitectureModel;
  attackSurface?: AttackSurface;
  technologies?: Technology[];
  entrypoints?: EntryPoint[];
  securityBoundaries?: SecurityBoundary[];
  discoveredAssets?: DiscoveredAsset[];

  // Investigation state
  findings: Finding[];
  hypotheses: Hypothesis[];
  evidence: Evidence[];
  executedActions: ExecutedAction[];

  // Knowns and unknowns
  assumptions: string[];
  unknowns: string[];

  // Tracking
  riskAssessment?: RiskSummary;
  timeline: TimelineEntry[];
  phaseProgress: Record<Phase, PhaseProgress>;

  // Metadata
  startedAt: Date;
  lastActivityAt: Date;
  completedAt?: Date;
  error?: string;
  metadata: Record<string, unknown>;
}

// ─── ArchitectureModel ───────────────────────────────────────────────────────

/** Conceptual architecture the AI constructs during analysis */
export interface ArchitectureModel {
  layers: ArchitectureLayer[];
  trustBoundaries: TrustBoundary[];
  dataFlows: DataFlow[];
  externalDependencies: ExternalDependency[];
}

export interface ArchitectureLayer {
  name: string;
  components: string[];
  position: "frontend" | "backend" | "infrastructure" | "data";
}

export interface TrustBoundary {
  id: string;
  between: [string, string];
  controls: string[];
}

export interface DataFlow {
  id: string;
  from: string;
  to: string;
  protocol: string;
  sensitivity: "public" | "internal" | "confidential" | "restricted";
}

export interface ExternalDependency {
  name: string;
  type: "api" | "service" | "library" | "database" | "queue" | "storage";
  trustLevel: "trusted" | "semi-trusted" | "untrusted";
  criticality: string;
}

// ─── AttackSurface ────────────────────────────────────────────────────────────

/**
 * Modeled attack surface built from recon.
 * Covers application, API, auth, infra layers.
 */
export interface AttackSurface {
  totalEndpoints: number;
  totalRoutes: number;
  entryPoints: EntryPoint[];
  categorized: Record<string, EndpointCategory[]>;
}

export interface EndpointCategory {
  method?: string;
  path: string;
  authentication?: string;
  authorization?: string;
  sensitivity: "low" | "medium" | "high" | "critical";
  notes?: string;
}

export interface EntryPoint {
  id: string;
  type: "http" | "graphql" | "websocket" | "grpc" | "file_upload" | "command" | "queue" | "admin_panel";
  location: string;
  description: string;
  requiresAuth: boolean;
  requiresPrivilege: boolean;
}

export interface Technology {
  name: string;
  version?: string;
  category: "language" | "framework" | "database" | "cache" | "queue" | "auth" | "infra" | "package_manager";
  purpose: string;
}

// ─── SecurityBoundary ────────────────────────────────────────────────────────

export interface SecurityBoundary {
  id: string;
  name: string;
  type: "network" | "application" | "data" | "privilege";
  description: string;
  controls: string[];
  weaknesses?: string[];
}

// ─── DiscoveredAsset ─────────────────────────────────────────────────────────

export interface DiscoveredAsset {
  id: string;
  type:
    | "route"
    | "api_endpoint"
    | "database_table"
    | "config_file"
    | "secret_store"
    | "environment_variable"
    | "external_service"
    | "container"
    | "worker"
    | "job_queue";
  name: string;
  location: string;
  relevance: "direct" | "indirect" | "background";
  securityNotes?: string;
}

// ─── Finding ─────────────────────────────────────────────────────────────────

/** Normalized finding produced after investigation + validation */
export interface Finding {
  id: FindingId;
  title: string;
  category: string; // e.g. "sql_injection", "xss", "idor", "business_logic"
  cwe?: string; // CWE ID
  owasp?: string; // OWASP Top 10 mapping
  severity: Severity;
  confidence: Confidence;
  status: FindingStatus;
  affectedComponent: string;
  affectedLocation: LocationReference;
  rootCause: string;
  description: string;
  impact: string;
  evidenceIds: EvidenceId[];
  validation?: ValidationRecord;
  remediation?: Remediation;
  references: string[]; // CVEs, docs, etc.
  attackPath?: AttackPath;
  firstSeenAt: Date;
  lastSeenAt: Date;
  correlationGroupId?: string; // for deduplication
  tags: string[];
}

export interface LocationReference {
  file?: string;
  lineStart?: number;
  lineEnd?: number;
  function?: string;
  route?: string;
  endpoint?: string;
  module?: string;
}

export interface ValidationRecord {
  method: string;
  timestamp: Date;
  result: string;
  proof: string;
  environment: string;
  validatedBy: "automated" | "manual" | "ai";
}

export interface Remediation {
  rootCause: string;
  whyItHappens: string;
  recommendedFix: string;
  securePattern: string;
  affectedFiles: string[];
  testsNeeded: string[];
  proposedPatch?: string;
  patchApplied?: boolean;
}

// ─── Evidence ────────────────────────────────────────────────────────────────

export const EVIDENCE_TYPES = {
  SOURCE: "source",
  RUNTIME: "runtime",
  HTTP: "http",
  CONFIGURATION: "configuration",
  DEPENDENCY: "dependency",
  EXECUTION: "execution",
} as const;

export type EvidenceType = (typeof EVIDENCE_TYPES)[keyof typeof EVIDENCE_TYPES];

export interface Evidence {
  id: EvidenceId;
  findingId: FindingId | null; // null during collection, linked when finding created
  type: EvidenceType;
  timestamp: Date;
  environment: string;
  action: string;
  input: unknown;
  observedResult: unknown;
  expectedResult?: unknown;
  artifact?: string; // file path or remote URI
  hash?: string; // content hash for immutability
  raw: unknown;
  sanitized: SanitizedEvidence;
  metadata?: Record<string, unknown>;
}

/** Sanitized copy safe for UI / reports — secrets masked */
export interface SanitizedEvidence {
  input?: string;
  observedResult?: string;
  action?: string;
  type?: string;
}

// ─── SeverityScore ────────────────────────────────────────────────────────────

/** Deterministic severity score before mapping to severity label */
export interface SeverityScore {
  exploitability: number;
  impact: number;
  reachability: number;
  privilegesRequired: number;
  userInteraction: number;
  dataSensitivity: number;
  businessCriticality: number;
  confidence: number;
  total: number;
  mappedSeverity: Severity;
}

// ─── Hypothesis ───────────────────────────────────────────────────────────────

/**
 * Every serious security suspicion becomes a structured hypothesis.
 * The AI creates, updates, merges, and discards them over time.
 */
export interface Hypothesis {
  id: HypothesisId;
  category: string;
  target: string; // what it targets (component, endpoint, flow)
  claim: string; // the security claim being tested
  reasoning: string; // why this hypothesis exists
  preconditions: string[];
  expectedBehavior: string;
  suspectedBehavior: string;
  evidenceIds: EvidenceId[];
  confidence: number; // 0–1
  riskLevel: RiskLevel;
  validationPlan: ValidationStep[];
  status: HypothesisStatus;
  createdAt: Date;
  updatedAt: Date;
  resolvedAt?: Date;
  relatedFindingId?: FindingId;
}

export interface ValidationStep {
  step: number;
  description: string;
  tool: string;
  expectedOutcome: string;
  criteriaForPass: string;
}

// ─── ExecutedAction ──────────────────────────────────────────────────────────

export interface ExecutedAction {
  timestamp: Date;
  phase: Phase;
  toolName: string;
  toolInput: Record<string, unknown>;
  toolOutputSize: number; // bytes or item count
  durationMs: number;
  success: boolean;
  resultSummary: string;
}

// ─── Timeline ────────────────────────────────────────────────────────────────

export interface TimelineEntry {
  timestamp: Date;
  phase: Phase;
  eventType: "phase_start" | "phase_end" | "finding_created" | "hypothesis_created" | "evidence_collected" | "action_executed" | "status_change";
  summary: string;
  details?: Record<string, unknown>;
}

// ─── PhaseProgress ────────────────────────────────────────────────────────────

export interface PhaseProgress {
  phase: Phase;
  status: "not_started" | "in_progress" | "completed" | "skipped";
  startedAt?: Date;
  completedAt?: Date;
  keyFindings: number;
  notes: string;
}

// ─── RiskSummary ─────────────────────────────────────────────────────────────

export interface RiskSummary {
  overallScore: number; // 0–100, lower is worse
  criticalCount: number;
  highCount: number;
  mediumCount: number;
  lowCount: number;
  informationalCount: number;
  confirmedCount: number;
  potentialCount: number;
  topRisks: string[];
}

// ─── Report ──────────────────────────────────────────────────────────────────

export const REPORT_FORMATS = {
  JSON: "json",
  SARIF: "sarif",
  MARKDOWN: "markdown",
} as const;

export type ReportFormat = (typeof REPORT_FORMATS)[keyof typeof REPORT_FORMATS];

export interface Report {
  id: string;
  investigationId: InvestigationId;
  format: ReportFormat;
  generatedAt: Date;
  executiveSummary: ExecutiveSummary;
  technicalFindings: TechnicalFinding[];
  raw: unknown; // format-specific output
}

export interface ExecutiveSummary {
  securityScore: number;
  riskSummary: RiskSummary;
  criticalFindings: string[];
  majorRisks: string[];
  businessImpact: string;
  recommendedPriorities: string[];
  trend?: string;
}

export interface TechnicalFinding {
  findingId: FindingId;
  title: string;
  category: string;
  severity: Severity;
  rootCause: string;
  location: LocationReference;
  attackPath?: AttackPath;
  impact: string;
  remediation: Remediation;
}

// ─── AttackPath ───────────────────────────────────────────────────────────────

export interface AttackPath {
  id: string;
  description: string;
  nodes: AttackPathNode[];
  prerequisites: string[];
  impact: string;
  mitigations: string[];
}

export interface AttackPathNode {
  id: string;
  type: "entry" | "vulnerability" | "access" | "action" | "impact";
  description: string;
  linkedFindingId?: FindingId;
}

// ─── AuditBaseline ───────────────────────────────────────────────────────────

/**
 * Snapshot of findings at a point in time for regression tracking.
 * Each new audit creates a baseline that can be compared against later.
 */
export interface AuditBaseline {
  id: string;
  investigationId: InvestigationId;
  createdAt: Date;
  severityCounts: Record<Severity, number>;
  totalFindings: number;
  findingIds: FindingId[];
  metadata: Record<string, unknown>;
}

// ─── ToolDefinition ───────────────────────────────────────────────────────────

/**
 * A tool in the controlled tool registry.
 * Every tool has schema, permissions, and risk level.
 */
export interface ToolDefinition {
  /** Tool identifier used by the policy engine and runtime */
  name: ToolName;
  /** Human-readable description shown to the AI */
  description: string;
  /** Structured schema for tool input validation */
  parameters: ToolParameters;
  /** Risk classification — gates execution policy */
  riskLevel: ToolRiskLevel;
  /** Which phases may invoke this tool */
  allowedPhases: Phase[];
  /** Permission gate: who must approve execution */
  permission: ToolPermission;
  /** Handler module reference for dispatch */
  handlerRef: string;
  /** Max result size (bytes) to prevent memory issues */
  maxResultSizeBytes: number;
  /** Whether the tool requires sandbox isolation */
  requiresSandbox: boolean;
}

export const TOOL_RISK_LEVEL = {
  READ_ONLY: "read_only",
  SANDBOXED: "sandboxed",
  RESTRICTED: "restricted",
  FORBIDDEN: "forbidden",
} as const;

export type ToolRiskLevel = (typeof TOOL_RISK_LEVEL)[keyof typeof TOOL_RISK_LEVEL];

export const TOOL_PERMISSION = {
  AUTOMATED: "automated",
  REQUEST_APPROVAL: "request_approval",
  MANUAL_OVERRIDE: "manual_override",
} as const;

export type ToolPermission = (typeof TOOL_PERMISSION)[keyof typeof TOOL_PERMISSION];
