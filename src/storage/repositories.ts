/**
 * Hilbras Spectra — Storage Repositories
 *
 * Data access layer over PostgreSQL via Drizzle ORM.
 * Each repository is scoped to an organization for tenant isolation.
 */

import { eq, desc, asc, and } from "drizzle-orm";
import type { PgDatabase } from "drizzle-orm/pg-core";
import {
  audits,
  findings,
  evidence as evidenceTable,
  hypotheses,
  attackPaths,
  baselines,
  reports,
  toolExecutions,
  projects,
} from "./schema.js";
import type { Evidence } from "../domain/types.js";

export type Db = PgDatabase<any, any>;

// ─── Project repository ────────────────────────────────────────────────────────

export class ProjectRepository {
  constructor(private readonly db: Db) {}

  async create(input: {
    organizationId: string; name: string; description?: string;
    targetType: string; targetLocation: string; tags?: string[];
  }): Promise<string> {
    const rows = await (this.db.insert(projects) as any).values({
      organizationId: input.organizationId,
      name: input.name,
      description: input.description ?? null,
      targetType: input.targetType,
      targetLocation: input.targetLocation,
      tags: input.tags ?? [],
    }).returning({ id: projects.id });
    if (!rows[0]) throw new Error("Failed to create project");
    return rows[0]!.id;
  }

  async findById(id: string): Promise<(typeof projects.$inferSelect) | null> {
    const [row] = await this.db.select().from(projects).where(eq(projects.id, id));
    return row ?? null;
  }

  async listByOrganization(organizationId: string): Promise<(typeof projects.$inferSelect)[]> {
    return this.db.select().from(projects).where(eq(projects.organizationId, organizationId)).orderBy(desc(projects.updatedAt));
  }
}

// ─── Audit repository ──────────────────────────────────────────────────────────

export class AuditRepository {
  constructor(private readonly db: Db) {}

  async create(input: { projectId: string; organizationId: string; currentPhase: string; currentObjective?: string }): Promise<string> {
    const rows = await (this.db.insert(audits) as any).values({
      projectId: input.projectId,
      organizationId: input.organizationId,
      status: "pending",
      currentPhase: input.currentPhase,
      currentObjective: input.currentObjective ?? null,
    }).returning({ id: audits.id });
    if (!rows[0]) throw new Error("Failed to create audit");
    return rows[0]!.id;
  }

  async updateStatus(id: string, status: string, completedAt?: Date): Promise<void> {
    await this.db.update(audits).set({ status: status as any, ...(completedAt ? { completedAt } : {}) }).where(eq(audits.id, id));
  }

  async updatePhase(id: string, phase: string, objective?: string): Promise<void> {
    await this.db.update(audits).set({ currentPhase: phase, ...(objective ? { currentObjective: objective } : {}) }).where(eq(audits.id, id));
  }

  async findById(id: string): Promise<(typeof audits.$inferSelect) | null> {
    const [row] = await this.db.select().from(audits).where(eq(audits.id, id));
    return row ?? null;
  }

  async listByProject(projectId: string, limit = 20): Promise<(typeof audits.$inferSelect)[]> {
    return this.db.select().from(audits).where(eq(audits.projectId, projectId)).orderBy(desc(audits.startedAt)).limit(limit);
  }
}

// ─── Finding repository ────────────────────────────────────────────────────────

export class FindingRepository {
  constructor(private readonly db: Db) {}

  async insert(finding: {
    auditId: string; organizationId: string; title: string; category: string;
    cwe?: string; owasp?: string; severity: string; confidence: string; status: string;
    affectedComponent: string; affectedFile?: string | null; affectedLineStart?: number | null; affectedLineEnd?: number | null;
    rootCause: string; description: string; impact: string; correlationGroupId?: string;
    tags?: string[]; scoreExploitability?: number; scoreImpact?: number; scoreReachability?: number;
    scorePrivilegesRequired?: number; scoreUserInteraction?: number; scoreDataSensitivity?: number;
    scoreBusinessCriticality?: number; scoreConfidence?: number; scoreTotal?: number;
  }): Promise<string> {
    const rows = await (this.db.insert(findings) as any).values({
      auditId: finding.auditId,
      organizationId: finding.organizationId,
      title: finding.title,
      category: finding.category,
      cwe: finding.cwe ?? null,
      owasp: finding.owasp ?? null,
      severity: finding.severity,
      confidence: finding.confidence,
      status: finding.status,
      affectedComponent: finding.affectedComponent,
      affectedFile: finding.affectedFile ?? null,
      affectedLineStart: finding.affectedLineStart ?? null,
      affectedLineEnd: finding.affectedLineEnd ?? null,
      rootCause: finding.rootCause,
      description: finding.description,
      impact: finding.impact,
      correlationGroupId: finding.correlationGroupId ?? null,
      tags: finding.tags ?? [],
      scoreExploitability: finding.scoreExploitability ?? null,
      scoreImpact: finding.scoreImpact ?? null,
      scoreReachability: finding.scoreReachability ?? null,
      scorePrivilegesRequired: finding.scorePrivilegesRequired ?? null,
      scoreUserInteraction: finding.scoreUserInteraction ?? null,
      scoreDataSensitivity: finding.scoreDataSensitivity ?? null,
      scoreBusinessCriticality: finding.scoreBusinessCriticality ?? null,
      scoreConfidence: finding.scoreConfidence ?? null,
      scoreTotal: finding.scoreTotal ?? null,
    }).returning({ id: findings.id });
    if (!rows[0]) throw new Error("Failed to insert finding");
    return rows[0]!.id;
  }

  async findById(id: string): Promise<(typeof findings.$inferSelect) | null> {
    const [row] = await this.db.select().from(findings).where(eq(findings.id, id));
    return row ?? null;
  }

  async listByAudit(auditId: string): Promise<(typeof findings.$inferSelect)[]> {
    return this.db.select().from(findings).where(eq(findings.auditId, auditId)).orderBy(desc(findings.scoreTotal ?? 0));
  }

  async updateStatus(id: string, status: string): Promise<void> {
    await this.db.update(findings).set({ status: status as any, lastSeenAt: new Date() }).where(eq(findings.id, id));
  }

  async countByAuditAndSeverity(auditId: string, severity: string): Promise<number> {
    const [row] = await this.db.select({ count: this.db.$count(findings) }).from(findings).where(and(eq(findings.auditId, auditId), eq(findings.severity, severity as any)));
    return row ? Number(row.count) : 0;
  }
}

// ─── Evidence repository ───────────────────────────────────────────────────────

export class EvidenceRepository {
  constructor(private readonly db: Db) {}

  async insert(evidence: Omit<Evidence, "id"> & { auditId?: string; organizationId: string }): Promise<string> {
    const rows = await (this.db.insert(evidenceTable) as any).values({
      auditId: evidence.auditId ?? null,
      findingId: evidence.findingId ?? null,
      organizationId: evidence.organizationId,
      type: evidence.type,
      action: evidence.action,
      input: evidence.input ?? null,
      observedResult: evidence.observedResult ?? null,
      expectedResult: evidence.expectedResult ?? null,
      artifact: evidence.artifact ?? null,
      hash: evidence.hash ?? null,
      environment: evidence.environment,
    }).returning({ id: evidenceTable.id });
    if (!rows[0]) throw new Error("Failed to insert evidence");
    return rows[0]!.id;
  }

  async linkToFinding(evidenceId: string, findingId: string): Promise<void> {
    await this.db.update(evidenceTable).set({ findingId }).where(eq(evidenceTable.id, evidenceId));
  }

  async listByAudit(auditId: string): Promise<(typeof evidenceTable.$inferSelect)[]> {
    return this.db.select().from(evidenceTable).where(eq(evidenceTable.auditId, auditId)).orderBy(asc(evidenceTable.createdAt));
  }

  async listByFinding(findingId: string): Promise<(typeof evidenceTable.$inferSelect)[]> {
    return this.db.select().from(evidenceTable).where(eq(evidenceTable.findingId, findingId)).orderBy(asc(evidenceTable.createdAt));
  }
}

// ─── Hypothesis repository ─────────────────────────────────────────────────────

export class HypothesisRepository {
  constructor(private readonly db: Db) {}

  async insert(hyp: {
    auditId: string; organizationId: string; category: string; target: string; claim: string;
    reasoning: string; preconditions?: string[]; expectedBehavior?: string; suspectedBehavior?: string;
    confidence?: number; riskLevel: string; status: string; validationPlan?: unknown;
  }): Promise<string> {
    const now = new Date();
    const rows = await (this.db.insert(hypotheses) as any).values({
      auditId: hyp.auditId,
      organizationId: hyp.organizationId,
      category: hyp.category,
      target: hyp.target,
      claim: hyp.claim,
      reasoning: hyp.reasoning,
      preconditions: hyp.preconditions ?? [],
      expectedBehavior: hyp.expectedBehavior ?? null,
      suspectedBehavior: hyp.suspectedBehavior ?? null,
      confidence: hyp.confidence ?? null,
      riskLevel: hyp.riskLevel,
      status: hyp.status,
      validationPlan: hyp.validationPlan ?? null,
      createdAt: now,
      updatedAt: now,
    }).returning({ id: hypotheses.id });
    if (!rows[0]) throw new Error("Failed to insert hypothesis");
    return rows[0]!.id;
  }

  async updateStatus(id: string, status: string, resolvedAt?: Date): Promise<void> {
    await this.db.update(hypotheses).set({ status: status as any, updatedAt: new Date(), ...(resolvedAt ? { resolvedAt } : {}) }).where(eq(hypotheses.id, id));
  }
}

// ─── Baseline repository ───────────────────────────────────────────────────────

export class BaselineRepository {
  constructor(private readonly db: Db) {}

  async create(input: { auditId: string; organizationId: string; severityCounts: Record<string, number>; totalFindings: number; findingIds: string[] }): Promise<string> {
    const rows = await (this.db.insert(baselines) as any).values({
      auditId: input.auditId,
      organizationId: input.organizationId,
      createdAt: new Date(),
      severityCounts: input.severityCounts,
      totalFindings: input.totalFindings,
      findingIds: input.findingIds,
      metadata: {},
    }).returning({ id: baselines.id });
    if (!rows[0]) throw new Error("Failed to create baseline");
    return rows[0]!.id;
  }
}

// ─── Report repository ─────────────────────────────────────────────────────────

export class ReportRepository {
  constructor(private readonly db: Db) {}

  async insert(report: { auditId: string; organizationId: string; format: string; executiveSummary?: unknown; raw?: unknown }): Promise<string> {
    const rows = await (this.db.insert(reports) as any).values({
      auditId: report.auditId,
      organizationId: report.organizationId,
      format: report.format,
      executiveSummary: report.executiveSummary ?? null,
      raw: report.raw ?? null,
      generatedAt: new Date(),
    }).returning({ id: reports.id });
    if (!rows[0]) throw new Error("Failed to insert report");
    return rows[0]!.id;
  }
}

// ─── Attack path repository ────────────────────────────────────────────────────

export class AttackPathRepository {
  constructor(private readonly db: Db) {}

  async insert(path: { auditId: string; organizationId: string; description: string; nodes: unknown[]; prerequisites?: string[]; impact?: string; mitigations?: string[] }): Promise<string> {
    const rows = await (this.db.insert(attackPaths) as any).values({
      auditId: path.auditId,
      organizationId: path.organizationId,
      createdAt: new Date(),
      description: path.description,
      nodes: path.nodes,
      prerequisites: path.prerequisites ?? [],
      impact: path.impact ?? null,
      mitigations: path.mitigations ?? [],
    }).returning({ id: attackPaths.id });
    if (!rows[0]) throw new Error("Failed to insert attack path");
    return rows[0]!.id;
  }
}

// ─── Tool execution log repository ─────────────────────────────────────────────

export class ToolExecutionRepository {
  constructor(private readonly db: Db) {}

  async insert(execution: { auditId: string; toolName: string; phase: string; input: unknown; success: boolean; resultSize?: number; durationMs: number; error?: string }): Promise<void> {
    await (this.db.insert(toolExecutions) as any).values({
      auditId: execution.auditId,
      toolName: execution.toolName,
      phase: execution.phase,
      input: execution.input,
      success: execution.success,
      resultSize: execution.resultSize ?? null,
      durationMs: execution.durationMs,
      error: execution.error ?? null,
      createdAt: new Date(),
    });
  }
}

// ─── Factory ───────────────────────────────────────────────────────────────────

export function createRepositories(db: Db) {
  return {
    projects: new ProjectRepository(db),
    audits: new AuditRepository(db),
    findings: new FindingRepository(db),
    evidence: new EvidenceRepository(db),
    hypotheses: new HypothesisRepository(db),
    baselines: new BaselineRepository(db),
    reports: new ReportRepository(db),
    attackPaths: new AttackPathRepository(db),
    toolExecutions: new ToolExecutionRepository(db),
  };
}
