/**
 * Hilbras Spectra — Domain Model
 *
 * Core types for the single-agent autonomous security research platform.
 * All state is persisted structurally; no reliance on conversational context.
 */

export {
  type InvestigationId,
  type FindingId,
  type EvidenceId,
  type HypothesisId,
  type ToolName,
  type Phase,
  type AuditStatus,
  type FindingStatus,
  type Severity,
  type Confidence,
  type HypothesisStatus,
  type RiskLevel,
  type TargetType,
  type ToolRiskLevel,
  type ReportFormat,
  type SecurityProject,
  type AuthorizationScope,
  type SecurityInvestigation,
  type PhaseProgress,
  type AttackSurface,
  type EntryPoint,
  type Technology,
  type SecurityBoundary,
  type DiscoveredAsset,
  type Finding,
  type Evidence,
  type EvidenceType,
  type SeverityScore,
  type Remediation,
  type Hypothesis,
  type AuditBaseline,
  type Report,
  type ToolDefinition,
  type ToolPermission,
  type AttackPathNode,
  type AttackPath,
  type LocationReference,
  type ValidationRecord,
  type ExecutiveSummary,
  type TechnicalFinding,
  type ExecutedAction,
  type TimelineEntry,
  type ArchitectureModel,
  type ArchitectureLayer,
  type TrustBoundary,
  type DataFlow,
  type ExternalDependency,
  type EndpointCategory,
} from "./types.js";
export { InvestigationState } from "./state.js";
export { createFindingId, createHypothesisId, createEvidenceId } from "./ids.js";
