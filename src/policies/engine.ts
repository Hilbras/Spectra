/**
 * Hilbras Spectra — Policy Engine
 *
 * GATE: AI tool request → Policy check → Allowed / Denied.
 *
 * Repository content (README, comments, AGENTS.md, source strings) is NEVER
 * treated as authority. The policy layer is the final arbiter.
 */

import type { AuthorizationScope, Phase, ToolName, ToolPermission, ToolRiskLevel } from "../domain/types.js";
import { getTool, isToolAvailableForPhase, listTools } from "../tools/registry.js";

export interface PolicyDecision {
  allowed: boolean;
  reason: string;
  toolName: ToolName;
  riskLevel: ToolRiskLevel | null;
  permissionRequirement: ToolPermission | null;
  restrictedDetails?: RestrictedDetail;
}

export interface RestrictedDetail {
  /** What is restricted and why */
  restriction: string;
  /** What would be needed to allow this */
  requiredApproval?: string;
}

export interface PolicyContext {
  phase: Phase;
  scope: AuthorizationScope;
  /** Whether active testing is authorized */
  allowActiveTesting: boolean;
  /** Whether network access is authorized */
  allowNetworkAccess: boolean;
}

/**
 * Check whether a tool invocation is allowed under the current policy.
 * This is the gate between the AI and every tool execution.
 */
export function evaluatePolicy(
  toolName: ToolName,
  ctx: PolicyContext,
): PolicyDecision {
  const tool = getTool(toolName);

  if (!tool) {
    return {
      allowed: false,
      reason: `Tool "${toolName}" is not registered in the registry`,
      toolName,
      riskLevel: null,
      permissionRequirement: null,
      restrictedDetails: { restriction: "Tool not found" },
    };
  }

  // 1. Forbidden tools are always denied
  if (tool.riskLevel === "forbidden") {
    return {
      allowed: false,
      reason: `Tool "${toolName}" is forbidden by policy`,
      toolName,
      riskLevel: tool.riskLevel,
      permissionRequirement: null,
      restrictedDetails: {
        restriction: "Forbidden tool",
        requiredApproval: "Cannot be overridden",
      },
    };
  }

  // 2. Phase gate: tool must be available in the current phase
  if (!isToolAvailableForPhase(toolName, ctx.phase)) {
    return {
      allowed: false,
      reason: `Tool "${toolName}" is not available in phase "${ctx.phase}"`,
      toolName,
      riskLevel: tool.riskLevel,
      permissionRequirement: tool.permission,
      restrictedDetails: {
        restriction: `Not available in ${ctx.phase}`,
        requiredApproval: `Advance to a phase where ${toolName} is permitted`,
      },
    };
  }

  // 3. Sandbox-required tools need active testing authorization
  if (tool.requiresSandbox && !ctx.allowActiveTesting) {
    return {
      allowed: false,
      reason: `Tool "${toolName}" requires sandbox execution, but active testing is not authorized`,
      toolName,
      riskLevel: tool.riskLevel,
      permissionRequirement: tool.permission,
      restrictedDetails: {
        restriction: "Active testing not authorized",
        requiredApproval: "Enable authorizationScope.allowActiveTesting",
      },
    };
  }

  // 4. Network-restricted tools need network authorization
  if (
    toolName.startsWith("http.") &&
    !ctx.allowNetworkAccess &&
    !ctx.allowActiveTesting
  ) {
    return {
      allowed: false,
      reason: `Tool "${toolName}" requires network access, which is not authorized`,
      toolName,
      riskLevel: tool.riskLevel,
      permissionRequirement: tool.permission,
      restrictedDetails: {
        restriction: "Network access not authorized",
        requiredApproval: "Enable authorizationScope.allowNetworkAccess",
      },
    };
  }

  // 5. Permission gate check
  switch (tool.permission) {
    case "automated":
      // Always allowed once phase + sandbox checks pass
      return {
        allowed: true,
        reason: `Tool "${toolName}" allowed (automated)`,
        toolName,
        riskLevel: tool.riskLevel,
        permissionRequirement: tool.permission,
      };

    case "request_approval":
      // Allowed only when active testing is authorized
      if (!ctx.allowActiveTesting) {
        return {
          allowed: false,
          reason: `Tool "${toolName}" requires approval: active testing not enabled`,
          toolName,
          riskLevel: tool.riskLevel,
          permissionRequirement: tool.permission,
          restrictedDetails: {
            restriction: "Requires manual or auto-approval",
            requiredApproval: "Enable allowActiveTesting in authorization scope",
          },
        };
      }
      return {
        allowed: true,
        reason: `Tool "${toolName}" approved for sandboxed validation`,
        toolName,
        riskLevel: tool.riskLevel,
        permissionRequirement: tool.permission,
      };

    case "manual_override":
      return {
        allowed: false,
        reason: `Tool "${toolName}" requires manual override — cannot be invoked automatically`,
        toolName,
        riskLevel: tool.riskLevel,
        permissionRequirement: tool.permission,
        restrictedDetails: {
          restriction: "Manual override required",
          requiredApproval: "Administrator must approve this tool call",
        },
      };

    default:
      return {
        allowed: false,
        reason: `Unknown permission type for tool "${toolName}"`,
        toolName,
        riskLevel: tool.riskLevel,
        permissionRequirement: tool.permission,
      };
  }
}

/**
 * Determine which tools are available for the current investigation state.
 * Used to populate the tool prompt context for the AI.
 */
export function getAvailableTools(phase: Phase, scope: AuthorizationScope): ToolName[] {
  const policyCtx: PolicyContext = {
    phase,
    scope,
    allowActiveTesting: scope.allowActiveTesting,
    allowNetworkAccess: scope.allowNetworkAccess,
  };
  // Iterate over registered tools
  const available: ToolName[] = [];
  for (const tool of listTools()) {
    const decision = evaluatePolicy(tool.name, policyCtx);
    if (decision.allowed) {
      available.push(tool.name);
    }
  }
  return available;
}

/**
 * Mask sensitive values in evidence/output before returning to the AI or storing.
 */
export function maskSensitiveValues(input: unknown): unknown {
  if (typeof input !== "string") return input;
  // Regex patterns for common secret formats — masks in-place
  const patterns: Array<[RegExp, string]> = [
    [/\b[A-Z0-9]{20,}\b/g, "[MASKED_KEY]"],
    [/(password|passwd|pwd)\s*[:=]\s*\S+/gi, "$1=[REDACTED]"],
    [/(api[_-]?key|apikey)\s*[:=]\s*\S+/gi, "$1=[REDACTED]"],
    [/(Bearer\s+)[A-Za-z0-9._-]+/gi, "$1[REDACTED_TOKEN]"],
    [/"(access_token|token)"\s*:\s*"(.*?)"/g, '"$1":"[REDACTED]"'],
  ];
  let result = input;
  for (const [regex, replacement] of patterns) {
    result = result.replace(regex, replacement);
  }
  return result;
}
