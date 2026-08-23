/**
 * Hilbras Spectra — Main Entry Point
 *
 * Single-agent autonomous security research platform.
 */

export * from "./domain/index.js";
export * from "./investigation/index.js";
export * from "./findings/index.js";
export * from "./policies/index.js";
export * from "./tools/index.js";
export * from "./storage/index.js";
export * from "./reports/index.js";
export * from "./sandbox/executor.js";
export { ProjectIndex } from "./index/index.js";

// Autonomous investigation brain
export { InvestigationController } from "./investigation/controller.js";
export type { InvestigationControllerConfig, InvestigationControllerResult } from "./investigation/controller.js";
export { DeterministicMockModel } from "./investigation/model-adapter.js";
export type { ModelAdapter } from "./investigation/model-adapter.js";
export type { InvestigationDecision, InvestigationOutput } from "./investigation/decision-schema.js";
export { buildSecurityModel } from "./investigation/security-model.js";
export type { SecurityModel } from "./investigation/security-model.js";
export { InvestigationEventStream } from "./investigation/events.js";
export type { InvestigationEvent, InvestigationEventType } from "./investigation/events.js";

// Re-export key types for convenience
export type { ToolHandler, ToolExecutionContext, ToolOutput, SecurityRuntimeConfig, InvestigationResult } from "./investigation/runtime.js";
export type { PhaseHandler, PhaseHandlerContext, PhaseResult } from "./investigation/handlers.js";
export type { AIEngineConfig, AIObservation, AIAction } from "./investigation/ai-engine.js";
export type { SandboxConfig, SandboxResult } from "./sandbox/executor.js";
export type { ReportFormatter } from "./reports/formatters.js";
