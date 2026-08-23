/**
 * Hilbras Spectra — AI Reasoning Engine
 *
 * The single AI brain that drives the investigation loop.
 * It observes tool results, updates its mental model, forms hypotheses,
 * and decides the next highest-value action.
 *
 * Uses @hilbras/sdk for model/provider abstraction.
 */

import type { HilbrasClient } from "@hilbras/sdk";
import type { Message } from "@hilbras/sdk";
import type { StreamChunk } from "@hilbras/sdk";
import type { Tool } from "@hilbras/sdk";
import type {
  Phase,
  Hypothesis,
  Finding,
} from "../domain/types.js";
import type { InvestigationState } from "../domain/state.js";
import type { PolicyContext } from "../policies/engine.js";

export interface AIObservation {
  toolName: string;
  result: unknown;
  success: boolean;
  summary: string;
}

export interface AIAction {
  nextPhase?: Phase;
  toolCall?: { name: string; input: Record<string, unknown> };
  newHypothesis?: Omit<Hypothesis, "id" | "createdAt" | "updatedAt" | "evidenceIds">;
  newFinding?: Omit<Finding, "id" | "firstSeenAt" | "lastSeenAt">;
  objective?: string;
  unknown?: string;
  assumption?: string;
  continue: boolean;
}

export interface AIEngineConfig {
  client: HilbrasClient;
  systemPrompt: string;
  maxTokens: number;
  temperature: number;
  organizationId: string;
  /** Provider name to use for the security AI */
  provider: string;
  /** Model ID to use */
  model: string;
}

/**
 * The AI engine wraps the HilbrasClient and manages conversation history
 * for a single investigation.
 */
export class AIEngine {
  private messages: Message[] = [];
  private readonly config: AIEngineConfig;

  constructor(config: AIEngineConfig) {
    this.config = config;
    this.messages.push({
      role: "system",
      content: config.systemPrompt,
    });
  }

  /**
   * Process an observation and return the next AI action.
   */
  async decide(
    observation: AIObservation | null,
    state: InvestigationState,
    _policyCtx: PolicyContext,
    availableTools: Tool[],
  ): Promise<AIAction> {
    const inv = state.get();

    if (observation) {
      this.messages.push({
        role: "user",
        content: `[OBSERVATION: ${observation.toolName}] ${observation.summary}`,
      });
    } else {
      this.messages.push({
        role: "user",
        content: this.buildInitialPrompt(inv),
      });
    }

    try {
      const params: Parameters<typeof this.config.client.stream>[0] = {
        provider: this.config.provider,
        model: this.config.model,
        messages: this.messages as Parameters<typeof this.config.client.stream>[0]["messages"],
        maxTokens: this.config.maxTokens,
        temperature: this.config.temperature,
      };
      if (availableTools.length > 0) {
        // Cast to bypass exactOptionalPropertyTypes on tools field
        (params as Record<string, unknown>).tools = availableTools;
      }
      const stream = this.config.client.stream(params);

      let fullText = "";
      const collectedToolCalls: Array<{ id: string; name: string; args: string }> = [];
      let currentToolCall: { id: string; name: string; argsParts: string[] } | null = null;

      for await (const chunk of stream as AsyncIterable<StreamChunk>) {
        switch (chunk.type) {
          case "text":
            fullText += chunk.text;
            break;
          case "reasoning":
            // Store reasoning but don't add to visible history
            break;
          case "tool_call":
            if (chunk.id) {
              if (!currentToolCall) {
                currentToolCall = { id: chunk.id, name: chunk.name ?? "unknown", argsParts: [] };
              } else {
                currentToolCall.id = chunk.id;
                if (chunk.name) currentToolCall.name = chunk.name;
              }
              if (chunk.argumentsDelta) {
                currentToolCall.argsParts.push(chunk.argumentsDelta);
              }
              if (chunk.done && currentToolCall) {
                collectedToolCalls.push({
                  id: currentToolCall.id,
                  name: currentToolCall.name,
                  args: currentToolCall.argsParts.join(""),
                });
                currentToolCall = null;
              }
            }
            break;
          case "error":
            throw new Error(chunk.message);
          default:
            break;
        }
      }

      // Add assistant message to history
      this.messages.push({
        role: "assistant",
        content: fullText || null,
        tool_calls: collectedToolCalls.map((tc) => ({
          id: tc.id,
          type: "function" as const,
          function: { name: tc.name, arguments: tc.args },
        })),
      });

      return this.parseResponse(fullText, collectedToolCalls, inv);
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      return { continue: false, objective: `AI error: ${message}` };
    }
  }

  reset(_state: InvestigationState): void {
    this.messages.length = 0;
    this.messages.push({
      role: "system",
      content: this.config.systemPrompt,
    });
  }

  get messageCount(): number {
    return this.messages.length;
  }

  // ─── Private ──────────────────────────────────────────────────────────────

  private buildInitialPrompt(inv: import("../domain/types.js").SecurityInvestigation): string {
    const parts = [
      `You are investigating project "${inv.projectId}".`,
      `Current phase: ${inv.phase}.`,
      `Objective: ${inv.currentObjective}.`,
      inv.findings.length > 0 ? `Findings so far: ${inv.findings.length}` : "No findings yet.",
      inv.hypotheses.length > 0 ? `Active hypotheses: ${inv.hypotheses.length}` : "No hypotheses formed.",
      inv.unknowns.length > 0 ? `Unknowns: ${inv.unknowns.slice(0, 5).join(", ")}` : "",
    ].filter(Boolean);
    return parts.join("\n");
  }

  private parseResponse(
    content: string,
    toolCalls: Array<{ id: string; name: string; args: string }>,
    _inv: import("../domain/types.js").SecurityInvestigation,
  ): AIAction {
    // Try structured JSON output first
    if (content.trim().startsWith("{")) {
      try {
        const parsed = JSON.parse(content) as Partial<AIAction>;
        return { continue: true, ...parsed };
      } catch {
        // Fall through to text parsing
      }
    }

    if (toolCalls.length > 0) {
      const tc = toolCalls[0]!;
      try {
        const args = JSON.parse(tc.args) as Record<string, unknown>;
        return { continue: true, toolCall: { name: tc.name, input: args } };
      } catch {
        return { continue: true };
      }
    }

    return { continue: true };
  }
}
