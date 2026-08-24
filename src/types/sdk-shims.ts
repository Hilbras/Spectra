/**
 * Hilbras Spectra — SDK Type Shims
 * 
 * Mirrors the minimal subset of @hilbras/sdk types used by Spectra.
 * These exist solely to remove the npm publish-time dependency on @hilbras/sdk.
 * The actual types live in the SDK monorepo package.
 */

// ─── Messages (from @hilbras/sdk/types/messages) ──────────────────────────────

export type Role = "system" | "user" | "assistant" | "tool";

export interface ToolCallFunction {
  name: string;
  arguments: string;
}

export interface ToolCall {
  id: string;
  type: "function";
  function: ToolCallFunction;
}

export interface Message {
  role: Role;
  content: string | null;
  tool_calls?: ToolCall[];
  tool_call_id?: string;
  name?: string;
}

// ─── Tools (from @hilbras/sdk/types/tools) ────────────────────────────────────

export interface ToolParameter {
  type: string;
  description?: string;
  enum?: string[];
  properties?: Record<string, ToolParameter>;
  required?: string[];
}

export interface ToolParameters {
  type: "object";
  properties: Record<string, ToolParameter>;
  required: string[];
}

export interface ToolFunctionDef {
  name: string;
  description: string;
  parameters: ToolParameters;
}

export interface Tool {
  type: "function";
  function: ToolFunctionDef;
}

// ─── Streams (from @hilbras/sdk/types/streams) ────────────────────────────────

export interface TextChunk {
  type: "text";
  text: string;
}

export interface ReasoningChunk {
  type: "reasoning";
  text: string;
}

export interface ToolCallChunk {
  type: "tool_call";
  id: string;
  name?: string;
  argumentsDelta?: string;
  index?: number;
  done?: boolean;
}

export interface UsageChunk {
  type: "usage";
  inputTokens: number;
  outputTokens: number;
  totalTokens: number;
}

export interface ErrorChunk {
  type: "error";
  message: string;
  retryable: boolean;
}

export interface FinishChunk {
  type: "finish";
  reason: string;
}

export type StreamChunk =
  | TextChunk
  | ReasoningChunk
  | ToolCallChunk
  | UsageChunk
  | ErrorChunk
  | FinishChunk;

// ─── HilbrasClient stub (mirrors SDK signature, no runtime impl) ──────────────
// Used only as a type in AI engine config. Replaced by DeterministicMockModel
// in testing and by real integration at runtime via the ModelAdapter interface.

export interface HilbrasClientConfig {
  policy?: unknown;
  budget?: unknown;
}

export class HilbrasClient {
  addProvider(_config: unknown): void {}
  stream(_params: {
    provider?: string;
    model?: string;
    messages: Message[];
    maxTokens?: number;
    temperature?: number;
    tools?: Tool[];
  }): AsyncIterable<StreamChunk> {
    return (async function* () {})();
  }
}
