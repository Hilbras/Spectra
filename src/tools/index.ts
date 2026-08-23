/**
 * Hilbras Spectra — Tools Module
 *
 * Re-exports the tool registry so consumers can import from a single path.
 */

export {
  TOOL_REGISTRY,
  registerTool,
  getTool,
  isToolAvailableForPhase,
  listTools,
} from "./registry.js";
export type { ToolDefinition, ToolName, ToolRiskLevel, ToolPermission } from "../domain/types.js";
