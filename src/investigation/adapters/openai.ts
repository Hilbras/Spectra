/**
 * Hilbras Spectra — OpenAI Model Adapter
 * Uses GPT-4o, GPT-4-turbo, o1, and other OpenAI models.
 */

import { BaseAdapter, type ChatMessage, } from "./base.js";
import type { InvestigationOutput } from "../decision-schema.js";

export interface OpenAIAdapterConfig {
  model?: string;
  apiKey?: string;
  baseUrl?: string;
}

export class OpenAIAdapter extends BaseAdapter {
  readonly id = "openai";
  private readonly apiKey: string;
  private readonly baseUrl: string;

  constructor(config: OpenAIAdapterConfig = {}) {
    super({
      model: { provider: "openai", model: config.model ?? "gpt-4o", baseUrl: config.baseUrl ?? "https://api.openai.com/v1" },
    });
    this.apiKey = config.apiKey ?? process.env.OPENAI_API_KEY ?? "";
    this.baseUrl = config.baseUrl ?? "https://api.openai.com/v1";
  }

  async decide(messages: ChatMessage[], context: string): Promise<InvestigationOutput> {
    const systemPrompt = this.buildSystemPrompt(context);
    const apiMessages = [
      { role: "system" as const, content: systemPrompt },
      ...messages.map((m) => ({ role: m.role as "system" | "user" | "assistant", content: m.content })),
      { role: "user" as const, content: "Analyze the project context above and provide your security investigation decisions as JSON." },
    ];

    const body = {
      model: this.model.model,
      messages: apiMessages,
      temperature: this.temperature,
      max_tokens: this.maxTokens,
      response_format: { type: "json_object" },
    };

    const res = await this.httpRequest(`${this.baseUrl}/chat/completions`, body, {
      "Content-Type": "application/json",
      Authorization: `Bearer ${this.apiKey}`,
    });

    const json = await res.json() as { choices?: Array<{ message?: { content?: string } }> };
    const content = json.choices?.[0]?.message?.content ?? "";
    const output = this.extractJsonResponse(content);
    if (!output) throw new Error(`OpenAI returned invalid decision format: ${content.slice(0, 200)}`);
    return output;
  }

  requiresNetwork(): boolean { return true; }
}
