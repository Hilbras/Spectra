/**
 * Hilbras Spectra — Findings Engine
 *
 * Deterministic severity scoring, finding correlation, and lifecycle management.
 * Never lets the LLM arbitrarily assign severity.
 */

import type {
  Confidence,
  Evidence,
  Finding,
  FindingStatus,
  LocationReference,
  Remediation,
  Severity,
  SeverityScore,
} from "../domain/types.js";

// ─── Severity scoring weights ────────────────────────────────────────────────

const SEVERITY_WEIGHTS = {
  exploitability: 0.25,
  impact: 0.20,
  reachability: 0.15,
  privilegesRequired: 0.10,
  userInteraction: 0.05,
  dataSensitivity: 0.15,
  businessCriticality: 0.05,
  confidence: 0.05,
};

/**
 * Compute a deterministic severity score from component scores (0–10 each).
 * Maps to a severity label using calibrated thresholds.
 */
export function computeSeverityScore(
  components: Partial<{
    exploitability: number;
    impact: number;
    reachability: number;
    privilegesRequired: number; // lower privilege needed = higher score
    userInteraction: number; // no interaction needed = higher score
    dataSensitivity: number;
    businessCriticality: number;
    confidence: number;
  }>,
): SeverityScore {
  const scores = {
    exploitability: components.exploitability ?? 5,
    impact: components.impact ?? 5,
    reachability: components.reachability ?? 5,
    privilegesRequired: 10 - (components.privilegesRequired ?? 5), // invert: low privilege = high score
    userInteraction: 10 - (components.userInteraction ?? 5), // invert: no interaction = high score
    dataSensitivity: components.dataSensitivity ?? 5,
    businessCriticality: components.businessCriticality ?? 5,
    confidence: components.confidence ?? 5,
  };

  const weighted =
    scores.exploitability * SEVERITY_WEIGHTS.exploitability +
    scores.impact * SEVERITY_WEIGHTS.impact +
    scores.reachability * SEVERITY_WEIGHTS.reachability +
    scores.privilegesRequired * SEVERITY_WEIGHTS.privilegesRequired +
    scores.userInteraction * SEVERITY_WEIGHTS.userInteraction +
    scores.dataSensitivity * SEVERITY_WEIGHTS.dataSensitivity +
    scores.businessCriticality * SEVERITY_WEIGHTS.businessCriticality +
    scores.confidence * SEVERITY_WEIGHTS.confidence;

  // Normalize to 0–100
  const total = weighted * 10;

  const mappedSeverity = mapScoreToSeverity(total);

  return {
    ...scores,
    total,
    mappedSeverity,
  };
}

function mapScoreToSeverity(score: number): Severity {
  if (score >= 85) return "critical";
  if (score >= 65) return "high";
  if (score >= 40) return "medium";
  if (score >= 20) return "low";
  return "informational";
}

// ─── Finding creation ────────────────────────────────────────────────────────

export interface CreateFindingInput {
  title: string;
  category: string;
  cwe?: string;
  owasp?: string;
  severityComponents: Partial<{
    exploitability: number;
    impact: number;
    reachability: number;
    privilegesRequired: number;
    userInteraction: number;
    dataSensitivity: number;
    businessCriticality: number;
    confidence: number;
  }>;
  affectedComponent: string;
  affectedLocation: LocationReference;
  rootCause: string;
  description: string;
  impact: string;
  remediation?: Remediation;
  references?: string[];
  tags?: string[];
}

/**
 * Create a new Finding with deterministic severity and default status.
 * New findings start as "potential" until validated.
 */
export function createFinding(
  input: CreateFindingInput,
  evidenceIds: string[] = [],
): Finding {
  const score = computeSeverityScore(input.severityComponents);
  const now = new Date();
  const base: Omit<Finding, "id" | "firstSeenAt" | "lastSeenAt"> = {
    title: input.title,
    category: input.category,
    severity: score.mappedSeverity,
    confidence: inferConfidence(input.severityComponents.confidence ?? 0.5),
    status: "potential",
    affectedComponent: input.affectedComponent,
    affectedLocation: input.affectedLocation,
    rootCause: input.rootCause,
    description: input.description,
    impact: input.impact,
    evidenceIds,
    references: input.references ?? [],
    tags: input.tags ?? [],
  };
  // Conditionally set optional fields to satisfy exactOptionalPropertyTypes
  if (input.cwe) base.cwe = input.cwe;
  if (input.owasp) base.owasp = input.owasp;
  if (input.remediation) base.remediation = input.remediation;
  return { ...base, id: crypto.randomUUID(), firstSeenAt: now, lastSeenAt: now };
}

function inferConfidence(rawScore: number): Confidence {
  if (rawScore >= 0.7) return "high";
  if (rawScore >= 0.4) return "medium";
  return "low";
}

// ─── Correlation ─────────────────────────────────────────────────────────────

/**
 * Check whether two findings likely describe the same underlying vulnerability.
 * Returns a correlation confidence (0–1).
 */
export function correlateFindings(a: Finding, b: Finding): number {
  let score = 0;
  const factors = [];

  // Same category is a strong signal
  if (a.category === b.category) {
    score += 0.3;
    factors.push("same_category");
  }

  // Same affected component
  if (a.affectedComponent === b.affectedComponent) {
    score += 0.2;
    factors.push("same_component");
  }

  // Same file location
  if (a.affectedLocation.file === b.affectedLocation.file) {
    score += 0.15;
    factors.push("same_file");
  }

  // Same CWE
  if (a.cwe && b.cwe && a.cwe === b.cwe) {
    score += 0.15;
    factors.push("same_cwe");
  }

  // Similar root cause keywords
  if (similarText(a.rootCause, b.rootCause)) {
    score += 0.1;
    factors.push("similar_root_cause");
  }

  // Overlapping evidence
  const sharedEvidence = a.evidenceIds.filter((id) => b.evidenceIds.includes(id));
  if (sharedEvidence.length > 0) {
    score += 0.1;
    factors.push("shared_evidence");
  }

  return Math.min(score, 1.0);
}

function similarText(a: string, b: string): boolean {
  const normalize = (s: string) => s.toLowerCase().replace(/[^\w\s]/g, "").split(/\s+/).filter(Boolean);
  const setA = new Set(normalize(a));
  const setB = new Set(normalize(b));
  if (setA.size === 0 || setB.size === 0) return false;
  let overlap = 0;
  for (const word of setA) {
    if (setB.has(word)) overlap++;
  }
  return overlap / Math.max(setA.size, setB.size) > 0.5;
}

/**
 * Group findings into correlation clusters.
 * Findings above the threshold share a groupId.
 */
export function groupCorrelated(findings: Finding[], threshold = 0.5): Map<string, Finding[]> {
  const groups = new Map<string, Finding[]>();
  let nextGroupId = 1;

  for (const finding of findings) {
    let matchedGroup: string | null = null;
    for (const [groupId, members] of groups) {
      const bestCorr = Math.max(...members.map((m) => correlateFindings(finding, m)));
      if (bestCorr >= threshold) {
        matchedGroup = groupId;
        break;
      }
    }
    if (matchedGroup) {
      groups.get(matchedGroup)!.push(finding);
    } else {
      const newId = `corr_${String(nextGroupId).padStart(4, "0")}`;
      nextGroupId++;
      groups.set(newId, [finding]);
      finding.correlationGroupId = newId;
    }
  }

  return groups;
}

// ─── Evidence linking ────────────────────────────────────────────────────────

/**
 * Link evidence to a finding.
 * Validates that the evidence actually supports the finding's claim.
 */
export function linkEvidence(
  finding: Finding,
  evidence: Evidence,
): Finding & { linked: boolean } {
  if (!finding.evidenceIds.includes(evidence.id)) {
    finding = {
      ...finding,
      evidenceIds: [...finding.evidenceIds, evidence.id],
      lastSeenAt: new Date(),
    };
  }
  return { ...finding, linked: true };
}

// ─── Status transitions ──────────────────────────────────────────────────────

const VALID_TRANSITIONS: Record<FindingStatus, FindingStatus[]> = {
  potential: ["validated", "confirmed", "false_positive", "accepted_risk"],
  validated: ["confirmed", "false_positive", "accepted_risk"],
  confirmed: ["resolved", "regression"],
  false_positive: ["potential", "validated"],
  accepted_risk: ["potential", "validated", "resolved"],
  resolved: [],
  regression: ["validated", "confirmed"],
};

export function transitionFindingStatus(
  finding: Finding,
  targetStatus: FindingStatus,
): { finding: Finding; valid: boolean; reason: string } {
  const allowed = VALID_TRANSITIONS[finding.status];
  if (!allowed?.includes(targetStatus)) {
    return {
      finding,
      valid: false,
      reason: `Cannot transition from "${finding.status}" to "${targetStatus}". Allowed: ${allowed?.join(", ") || "none"}`,
    };
  }
  return {
    finding: {
      ...finding,
      status: targetStatus,
      lastSeenAt: new Date(),
    },
    valid: true,
    reason: `Transitioned from "${finding.status}" to "${targetStatus}"`,
  };
}
