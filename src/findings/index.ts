/**
 * Hilbras Spectra — Findings Module
 */

export {
  computeSeverityScore,
  createFinding,
  correlateFindings,
  groupCorrelated,
  linkEvidence,
  transitionFindingStatus,
} from "./engine.js";
export type { CreateFindingInput } from "./engine.js";
