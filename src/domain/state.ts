/**
 * Hilbras Spectra — InvestigationState
 *
 * Immutable-first state machine for the investigation lifecycle.
 * Provides typed transitions and invariant checks between phases.
 */

import type {
  AuditStatus,
  Phase,
  SecurityInvestigation,
} from "./types.js";

/**
 * Phase transition graph.
 * The AI is not constrained to a rigid pipeline — it may move backward
 * and forward between analysis phases as evidence demands.
 * Only INITIALIZATION → RECONNAISSANCE and final convergence are ordered.
 */
const ALLOWED_PHASE_TRANSITIONS: Record<Phase, Phase[]> = {
  INITIALIZATION: ["RECONNAISSANCE", "COMPLETION"],
  RECONNAISSANCE: [
    "ARCHITECTURE_ANALYSIS",
    "ATTACK_SURFACE_MAPPING",
    "HYPOTHESIS_GENERATION",
    "COMPLETION",
  ],
  ARCHITECTURE_ANALYSIS: [
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
    "RECONNAISSANCE",
  ],
  ATTACK_SURFACE_MAPPING: [
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
    "RECONNAISSANCE",
  ],
  SOURCE_ANALYSIS: [
    "DEPENDENCY_ANALYSIS",
    "CONFIGURATION_ANALYSIS",
    "SECRET_ANALYSIS",
    "AUTHENTICATION_ANALYSIS",
    "AUTHORIZATION_ANALYSIS",
    "API_ANALYSIS",
    "BUSINESS_LOGIC_ANALYSIS",
    "HYPOTHESIS_GENERATION",
    "INVESTIGATION",
    "RECONNAISSANCE",
    "ATTACK_SURFACE_MAPPING",
    "ARCHITECTURE_ANALYSIS",
  ],
  // All analysis sub-phases are mutually reachable — the AI circles back
  // as new evidence reveals gaps in prior work.
  DEPENDENCY_ANALYSIS: [
    "SOURCE_ANALYSIS",
    "CONFIGURATION_ANALYSIS",
    "SECRET_ANALYSIS",
    "AUTHENTICATION_ANALYSIS",
    "AUTHORIZATION_ANALYSIS",
    "API_ANALYSIS",
    "BUSINESS_LOGIC_ANALYSIS",
    "HYPOTHESIS_GENERATION",
    "INVESTIGATION",
    "RECONNAISSANCE",
    "ATTACK_SURFACE_MAPPING",
    "ARCHITECTURE_ANALYSIS",
  ],
  CONFIGURATION_ANALYSIS: [
    "SOURCE_ANALYSIS",
    "DEPENDENCY_ANALYSIS",
    "SECRET_ANALYSIS",
    "AUTHENTICATION_ANALYSIS",
    "AUTHORIZATION_ANALYSIS",
    "API_ANALYSIS",
    "BUSINESS_LOGIC_ANALYSIS",
    "HYPOTHESIS_GENERATION",
    "INVESTIGATION",
    "RECONNAISSANCE",
    "ATTACK_SURFACE_MAPPING",
    "ARCHITECTURE_ANALYSIS",
  ],
  SECRET_ANALYSIS: [
    "SOURCE_ANALYSIS",
    "DEPENDENCY_ANALYSIS",
    "CONFIGURATION_ANALYSIS",
    "AUTHENTICATION_ANALYSIS",
    "AUTHORIZATION_ANALYSIS",
    "API_ANALYSIS",
    "BUSINESS_LOGIC_ANALYSIS",
    "HYPOTHESIS_GENERATION",
    "INVESTIGATION",
    "RECONNAISSANCE",
    "ATTACK_SURFACE_MAPPING",
    "ARCHITECTURE_ANALYSIS",
  ],
  AUTHENTICATION_ANALYSIS: [
    "SOURCE_ANALYSIS",
    "DEPENDENCY_ANALYSIS",
    "CONFIGURATION_ANALYSIS",
    "SECRET_ANALYSIS",
    "AUTHORIZATION_ANALYSIS",
    "API_ANALYSIS",
    "BUSINESS_LOGIC_ANALYSIS",
    "HYPOTHESIS_GENERATION",
    "INVESTIGATION",
    "RECONNAISSANCE",
    "ATTACK_SURFACE_MAPPING",
    "ARCHITECTURE_ANALYSIS",
  ],
  AUTHORIZATION_ANALYSIS: [
    "SOURCE_ANALYSIS",
    "DEPENDENCY_ANALYSIS",
    "CONFIGURATION_ANALYSIS",
    "SECRET_ANALYSIS",
    "AUTHENTICATION_ANALYSIS",
    "API_ANALYSIS",
    "BUSINESS_LOGIC_ANALYSIS",
    "HYPOTHESIS_GENERATION",
    "INVESTIGATION",
    "RECONNAISSANCE",
    "ATTACK_SURFACE_MAPPING",
    "ARCHITECTURE_ANALYSIS",
  ],
  API_ANALYSIS: [
    "SOURCE_ANALYSIS",
    "DEPENDENCY_ANALYSIS",
    "CONFIGURATION_ANALYSIS",
    "SECRET_ANALYSIS",
    "AUTHENTICATION_ANALYSIS",
    "AUTHORIZATION_ANALYSIS",
    "BUSINESS_LOGIC_ANALYSIS",
    "HYPOTHESIS_GENERATION",
    "INVESTIGATION",
    "RECONNAISSANCE",
    "ATTACK_SURFACE_MAPPING",
    "ARCHITECTURE_ANALYSIS",
  ],
  BUSINESS_LOGIC_ANALYSIS: [
    "SOURCE_ANALYSIS",
    "DEPENDENCY_ANALYSIS",
    "CONFIGURATION_ANALYSIS",
    "SECRET_ANALYSIS",
    "AUTHENTICATION_ANALYSIS",
    "AUTHORIZATION_ANALYSIS",
    "API_ANALYSIS",
    "HYPOTHESIS_GENERATION",
    "INVESTIGATION",
    "RECONNAISSANCE",
    "ATTACK_SURFACE_MAPPING",
    "ARCHITECTURE_ANALYSIS",
  ],
  HYPOTHESIS_GENERATION: [
    "INVESTIGATION",
    "VALIDATION",
    "RECONNAISSANCE",
    "ATTACK_SURFACE_MAPPING",
    "SOURCE_ANALYSIS",
    "DEPENDENCY_ANALYSIS",
    "CONFIGURATION_ANALYSIS",
    "SECRET_ANALYSIS",
    "AUTHENTICATION_ANALYSIS",
    "AUTHORIZATION_ANALYSIS",
    "API_ANALYSIS",
    "BUSINESS_LOGIC_ANALYSIS",
  ],
  INVESTIGATION: [
    "VALIDATION",
    "EVIDENCE_COLLECTION",
    "HYPOTHESIS_GENERATION",
    "RECONNAISSANCE",
    "ATTACK_SURFACE_MAPPING",
    "SOURCE_ANALYSIS",
    "DEPENDENCY_ANALYSIS",
    "CONFIGURATION_ANALYSIS",
    "SECRET_ANALYSIS",
    "AUTHENTICATION_ANALYSIS",
    "AUTHORIZATION_ANALYSIS",
    "API_ANALYSIS",
    "BUSINESS_LOGIC_ANALYSIS",
  ],
  VALIDATION: [
    "EVIDENCE_COLLECTION",
    "INVESTIGATION",
    "HYPOTHESIS_GENERATION",
  ],
  EVIDENCE_COLLECTION: ["FINDING_CORRELATION", "VALIDATION", "INVESTIGATION"],
  FINDING_CORRELATION: ["RISK_ASSESSMENT", "EVIDENCE_COLLECTION"],
  RISK_ASSESSMENT: ["REPORTING", "FINDING_CORRELATION"],
  REPORTING: ["COMPLETION", "RISK_ASSESSMENT"],
  COMPLETION: [],
};

export class InvestigationState {
  private constructor(
    readonly investigation: SecurityInvestigation,
  ) {}

  static create(projectId: string, initialPhase: Phase): InvestigationState {
    const now = new Date();
    const investigation: SecurityInvestigation = {
      id: crypto.randomUUID(),
      projectId,
      status: "pending",
      phase: initialPhase,
      currentObjective: `Starting ${initialPhase.toLowerCase()} phase`,
      findings: [],
      hypotheses: [],
      evidence: [],
      executedActions: [],
      assumptions: [],
      unknowns: [],
      timeline: [
        {
          timestamp: now,
          phase: initialPhase,
          eventType: "status_change",
          summary: `Investigation initialized in ${initialPhase} phase`,
          details: { projectId },
        },
      ],
      phaseProgress: Object.fromEntries(
        (Object.keys(ALLOWED_PHASE_TRANSITIONS) as Phase[]).map((p) => [
          p,
          { phase: p, status: "not_started" } as const,
        ]),
      ) as Record<Phase, import("./types.js").PhaseProgress>,
      startedAt: now,
      lastActivityAt: now,
      metadata: {},
    };
    return new InvestigationState(investigation);
  }

  get() {
    return this.investigation;
  }

  withCurrentObjective(objective: string): InvestigationState {
    return new InvestigationState({
      ...this.investigation,
      currentObjective: objective,
      lastActivityAt: new Date(),
      timeline: [
        ...this.investigation.timeline,
        {
          timestamp: new Date(),
          phase: this.investigation.phase,
          eventType: "status_change",
          summary: objective,
        },
      ],
    });
  }

  advanceTo(nextPhase: Phase): InvestigationState {
    const current = this.investigation.phase;
    const allowed = ALLOWED_PHASE_TRANSITIONS[current];
    if (!allowed?.includes(nextPhase)) {
      throw new Error(
        `Invalid phase transition: ${current} → ${nextPhase}. Allowed: ${allowed?.join(", ") || "none"}`,
      );
    }

    const now = new Date();
    const progress = { ...this.investigation.phaseProgress };
    progress[current] = {
      ...progress[current],
      status: "completed",
      completedAt: now,
    };
    progress[nextPhase] = {
      ...progress[nextPhase],
      status: "in_progress",
      startedAt: now,
    };

    return new InvestigationState({
      ...this.investigation,
      phase: nextPhase,
      currentObjective: `Entered ${nextPhase.toLowerCase()} phase`,
      lastActivityAt: now,
      phaseProgress: progress,
      timeline: [
        ...this.investigation.timeline,
        {
          timestamp: now,
          phase: nextPhase,
          eventType: "phase_start",
          summary: `Advancing from ${current} to ${nextPhase}`,
        },
      ],
    });
  }

  setStatus(status: AuditStatus): InvestigationState {
    const now = new Date();
    return new InvestigationState({
      ...this.investigation,
      status,
      lastActivityAt: now,
      ...(status === "completed" ? { completedAt: now } : {}),
      ...(status === "cancelled" ? { completedAt: now } : {}),
      timeline: [
        ...this.investigation.timeline,
        {
          timestamp: now,
          phase: this.investigation.phase,
          eventType: "status_change",
          summary: `Status changed to ${status}`,
        },
      ],
    });
  }

  addFinding(finding: import("./types.js").Finding): InvestigationState {
    const progress = { ...this.investigation.phaseProgress };
    progress[this.investigation.phase] = {
      ...progress[this.investigation.phase],
      keyFindings: (progress[this.investigation.phase].keyFindings ?? 0) + 1,
    };
    return new InvestigationState({
      ...this.investigation,
      findings: [...this.investigation.findings, finding],
      lastActivityAt: new Date(),
      phaseProgress: progress,
      timeline: [
        ...this.investigation.timeline,
        {
          timestamp: new Date(),
          phase: this.investigation.phase,
          eventType: "finding_created",
          summary: finding.title,
          details: { findingId: finding.id, severity: finding.severity },
        },
      ],
    });
  }

  addHypothesis(hypothesis: import("./types.js").Hypothesis): InvestigationState {
    return new InvestigationState({
      ...this.investigation,
      hypotheses: [...this.investigation.hypotheses, hypothesis],
      lastActivityAt: new Date(),
      timeline: [
        ...this.investigation.timeline,
        {
          timestamp: new Date(),
          phase: this.investigation.phase,
          eventType: "hypothesis_created",
          summary: hypothesis.claim,
          details: { hypothesisId: hypothesis.id, category: hypothesis.category },
        },
      ],
    });
  }

  addEvidence(evidence: import("./types.js").Evidence): InvestigationState {
    return new InvestigationState({
      ...this.investigation,
      evidence: [...this.investigation.evidence, evidence],
      lastActivityAt: new Date(),
      timeline: [
        ...this.investigation.timeline,
        {
          timestamp: new Date(),
          phase: this.investigation.phase,
          eventType: "evidence_collected",
          summary: `Collected ${evidence.type} evidence`,
          details: { evidenceId: evidence.id },
        },
      ],
    });
  }

  recordAction(action: import("./types.js").ExecutedAction): InvestigationState {
    return new InvestigationState({
      ...this.investigation,
      executedActions: [...this.investigation.executedActions, action],
      lastActivityAt: new Date(),
    });
  }

  markUnknown(unknown: string): InvestigationState {
    return new InvestigationState({
      ...this.investigation,
      unknowns: [...this.investigation.unknowns, unknown],
    });
  }

  markAssumption(assumption: string): InvestigationState {
    return new InvestigationState({
      ...this.investigation,
      assumptions: [...this.investigation.assumptions, assumption],
    });
  }

  withError(error: string): InvestigationState {
    return new InvestigationState({
      ...this.investigation,
      error,
      lastActivityAt: new Date(),
    });
  }
}
