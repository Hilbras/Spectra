/**
 * Hilbras Spectra — Database Schema (Drizzle + PostgreSQL)
 *
 * Multi-tenant schema scoped under Keystone organizations.
 * All tables have organization_id for tenant isolation.
 */

import {
  pgTable,
  text,
  boolean,
  timestamp,
  jsonb,
  integer,
  uuid,
  pgEnum,
} from "drizzle-orm/pg-core";

// ─── Enums ────────────────────────────────────────────────────────────────────

export const auditStatusEnum = pgEnum("audit_status", [
  "pending",
  "running",
  "paused",
  "cancelled",
  "completed",
  "failed",
]);

export const findingStatusEnum = pgEnum("finding_status", [
  "potential",
  "validated",
  "confirmed",
  "false_positive",
  "accepted_risk",
  "resolved",
  "regression",
]);

export const hypothesisStatusEnum = pgEnum("hypothesis_status", [
  "open",
  "investigating",
  "validated",
  "rejected",
  "inconclusive",
]);

export const severityEnum = pgEnum("severity", [
  "informational",
  "low",
  "medium",
  "high",
  "critical",
]);

export const confidenceEnum = pgEnum("confidence", [
  "low",
  "medium",
  "high",
]);

export const evidenceTypeEnum = pgEnum("evidence_type", [
  "source",
  "runtime",
  "http",
  "configuration",
  "dependency",
  "execution",
]);

export const targetTypeEnum = pgEnum("target_type", [
  "local_repo",
  "git_repo",
  "github",
  "gitlab",
  "archive",
  "docker",
  "local_app",
  "staging_env",
  "api",
]);

// ─── Tables ───────────────────────────────────────────────────────────────────

/** Security projects — each project belongs to an org */
export const projects = pgTable("security_projects", {
  id: uuid("id").primaryKey().defaultRandom(),
  organizationId: text("organization_id").notNull(),
  name: text("name").notNull(),
  description: text("description"),
  targetType: targetTypeEnum("target_type").notNull(),
  targetLocation: text("target_location").notNull(),
  tags: text("tags").array(),
  createdAt: timestamp("created_at").notNull().defaultNow(),
  updatedAt: timestamp("updated_at").notNull().defaultNow(),
});

/** Active and historical audits/investigations */
export const audits = pgTable("audits", {
  id: uuid("id").primaryKey().defaultRandom(),
  projectId: uuid("project_id")
    .references(() => projects.id, { onDelete: "cascade" })
    .notNull(),
  organizationId: text("organization_id").notNull(),
  status: auditStatusEnum("status").notNull().default("pending"),
  currentPhase: text("current_phase").notNull(),
  currentObjective: text("current_objective"),
  startedAt: timestamp("started_at").notNull().defaultNow(),
  completedAt: timestamp("completed_at"),
  error: text("error"),
  metadata: jsonb("metadata").default({}),
});

/** Findings tied to an audit */
export const findings = pgTable("findings", {
  id: uuid("id").primaryKey().defaultRandom(),
  auditId: uuid("audit_id")
    .references(() => audits.id, { onDelete: "cascade" })
    .notNull(),
  organizationId: text("organization_id").notNull(),
  title: text("title").notNull(),
  category: text("category").notNull(),
  cwe: text("cwe"),
  owasp: text("owasp"),
  severity: severityEnum("severity").notNull(),
  confidence: confidenceEnum("confidence").notNull(),
  status: findingStatusEnum("status").notNull().default("potential"),
  affectedComponent: text("affected_component").notNull(),
  affectedFile: text("affected_file"),
  affectedLineStart: integer("affected_line_start"),
  affectedLineEnd: integer("affected_line_end"),
  rootCause: text("root_cause").notNull(),
  description: text("description").notNull(),
  impact: text("impact").notNull(),
  correlationGroupId: text("correlation_group_id"),
  tags: text("tags").array(),
  firstSeenAt: timestamp("first_seen_at").notNull().defaultNow(),
  lastSeenAt: timestamp("last_seen_at").notNull().defaultNow(),
  // Severity score breakdown (for auditability)
  scoreExploitability: integer("score_exploitability"),
  scoreImpact: integer("score_impact"),
  scoreReachability: integer("score_reachability"),
  scorePrivilegesRequired: integer("score_privileges_required"),
  scoreUserInteraction: integer("score_user_interaction"),
  scoreDataSensitivity: integer("score_data_sensitivity"),
  scoreBusinessCriticality: integer("score_business_criticality"),
  scoreConfidence: integer("score_confidence"),
  scoreTotal: integer("score_total"),
});

/** Remediation guidance per finding */
export const remediations = pgTable("remediations", {
  id: uuid("id").primaryKey().defaultRandom(),
  findingId: uuid("finding_id")
    .references(() => findings.id, { onDelete: "cascade" })
    .notNull(),
  whyItHappens: text("why_it_happens"),
  recommendedFix: text("recommended_fix"),
  securePattern: text("secure_pattern"),
  affectedFiles: text("affected_files").array(),
  testsNeeded: text("tests_needed").array(),
  proposedPatch: text("proposed_patch"),
  patchApplied: boolean("patch_applied").default(false),
});

/** Evidence records linked to findings (or unlinked during collection) */
export const evidence = pgTable("evidence", {
  id: uuid("id").primaryKey().defaultRandom(),
  auditId: uuid("audit_id").references(() => audits.id, { onDelete: "set null" }),
  findingId: uuid("finding_id").references(() => findings.id, { onDelete: "set null" }),
  organizationId: text("organization_id").notNull(),
  type: evidenceTypeEnum("type").notNull(),
  action: text("action").notNull(),
  input: jsonb("input"),
  observedResult: jsonb("observed_result"),
  expectedResult: jsonb("expected_result"),
  artifact: text("artifact"),
  hash: text("hash"),
  environment: text("environment").notNull(),
  createdAt: timestamp("created_at").notNull().defaultNow(),
});

/** Hypotheses formed during investigation */
export const hypotheses = pgTable("hypotheses", {
  id: uuid("id").primaryKey().defaultRandom(),
  auditId: uuid("audit_id")
    .references(() => audits.id, { onDelete: "cascade" })
    .notNull(),
  organizationId: text("organization_id").notNull(),
  category: text("category").notNull(),
  target: text("target").notNull(),
  claim: text("claim").notNull(),
  reasoning: text("reasoning").notNull(),
  preconditions: text("preconditions").array(),
  expectedBehavior: text("expected_behavior"),
  suspectedBehavior: text("suspected_behavior"),
  confidence: integer("confidence"), // stored as 0-100 integer (percentage)
  riskLevel: text("risk_level").notNull(),
  status: hypothesisStatusEnum("status").notNull().default("open"),
  validationPlan: jsonb("validation_plan"),
  createdAt: timestamp("created_at").notNull().defaultNow(),
  updatedAt: timestamp("updated_at").notNull().defaultNow(),
  resolvedAt: timestamp("resolved_at"),
  relatedFindingId: uuid("related_finding_id").references(() => findings.id, { onDelete: "set null" }),
});

/** Attack paths linking multiple findings */
export const attackPaths = pgTable("attack_paths", {
  id: uuid("id").primaryKey().defaultRandom(),
  auditId: uuid("audit_id")
    .references(() => audits.id, { onDelete: "cascade" })
    .notNull(),
  organizationId: text("organization_id").notNull(),
  description: text("description").notNull(),
  nodes: jsonb("nodes").notNull(), // Array of { id, type, description, linkedFindingId }
  prerequisites: text("prerequisites").array(),
  impact: text("impact"),
  mitigations: text("mitigations").array(),
  createdAt: timestamp("created_at").notNull().defaultNow(),
});

/** Audit baselines for regression tracking */
export const baselines = pgTable("baselines", {
  id: uuid("id").primaryKey().defaultRandom(),
  auditId: uuid("audit_id")
    .references(() => audits.id, { onDelete: "cascade" })
    .notNull(),
  organizationId: text("organization_id").notNull(),
  createdAt: timestamp("created_at").notNull().defaultNow(),
  severityCounts: jsonb("severity_counts").notNull(), // { critical: N, high: N, ... }
  totalFindings: integer("total_findings").notNull(),
  findingIds: uuid("finding_ids").array(),
  metadata: jsonb("metadata").default({}),
});

/** Reports generated from an audit */
export const reports = pgTable("reports", {
  id: uuid("id").primaryKey().defaultRandom(),
  auditId: uuid("audit_id")
    .references(() => audits.id, { onDelete: "cascade" })
    .notNull(),
  organizationId: text("organization_id").notNull(),
  format: text("format").notNull(), // json | sarif | markdown
  executiveSummary: jsonb("executive_summary"),
  raw: jsonb("raw"),
  generatedAt: timestamp("generated_at").notNull().defaultNow(),
});

/** Tool execution log — auditable record of every tool call */
export const toolExecutions = pgTable("tool_executions", {
  id: uuid("id").primaryKey().defaultRandom(),
  auditId: uuid("audit_id")
    .references(() => audits.id, { onDelete: "cascade" })
    .notNull(),
  toolName: text("tool_name").notNull(),
  phase: text("phase").notNull(),
  input: jsonb("input"),
  success: boolean("success").notNull(),
  resultSize: integer("result_size"),
  durationMs: integer("duration_ms"),
  error: text("error"),
  createdAt: timestamp("created_at").notNull().defaultNow(),
});
