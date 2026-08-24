/**
 * Hilbras Spectra — Anthropic Model Adapter
 * Uses Claude 3.5 Sonnet, Haiku, Opus, and other Anthropic models.
 */

import { BaseAdapter, type ChatMessage, } from "./base.js";
import type { InvestigationOutput } from "../decision-schema.js";

export interface AnthropicAdapterConfig {
  model?: string;
  apiKey?: string;
  baseUrl?: string;
}

export class AnthropicAdapter extends BaseAdapter {
  readonly id = "anthropic";
  private readonly apiKey: string;
  private readonly baseUrl: string;

  constructor(config: AnthropicAdapterConfig = {}) {
    super({
      model: { provider: "anthropic", model: config.model ?? "claude-3-5-sonnet-20241022", baseUrl: config.baseUrl ?? "https://api.anthropic.com" },
    });
    this.apiKey = config.apiKey ?? process.env.ANTHROPIC_API_KEY ?? "";
    this.baseUrl = config.baseUrl ?? "https://api.anthropic.com";
  }

  async decide(messages: ChatMessage[], context: string): Promise<InvestigationOutput> {
    const systemPrompt = this.buildSystemPrompt(context);
    const apiMessages = messages
      .filter((m) => m.role !== "system")
      .map((m) => ({ role: m.role === "assistant" ? "assistant" as const : "user" as const, content: m.content }));

    const body = {
      model: this.model.model,
      max_tokens: this.maxTokens,
      system: systemPrompt,
      messages: apiMessages.length > 0 ? apiMessages : [{ role: "user" as const, content: "Provide your security investigation decisions as structured JSON." }],
      temperature: this.temperature,
    };

    const res = await this.httpRequest(`${this.baseUrl}/v1/messages`, body, {
      "Content-Type": "application/json",
      "x-api-key": this.apiKey,
      "anthropic-version": "2023-06-01",
    });

    const json = await res.json() as { content?: Array<{ type?: string; text?: string }> };
    const textBlock = json.content?.find((c) => c.type === "text");
    const text = textBlock?.text ?? "";
    const output = this.extractJsonResponse(text);
    if (!output) throw new Error(`Anthropic returned invalid decision format: ${text.slice(0, 200)}`);
    return output;
  }

  requiresNetwork(): boolean { return true; }
}
