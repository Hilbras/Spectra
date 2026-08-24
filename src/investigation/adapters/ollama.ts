/**
 * Hilbras Spectra — Ollama Adapter
 * Uses local Ollama instances (llama3, mistral, codellama, etc.).
 * No API key required. Runs entirely offline.
 */

import { BaseAdapter, type ChatMessage, } from "./base.js";
import type { InvestigationOutput } from "../decision-schema.js";

export interface OllamaAdapterConfig {
  model?: string;
  baseUrl?: string;
}

export class OllamaAdapter extends BaseAdapter {
  readonly id = "ollama";
  private readonly baseUrl: string;

  constructor(config: OllamaAdapterConfig = {}) {
    super({
      model: { provider: "ollama", model: config.model ?? "llama3.2", baseUrl: config.baseUrl ?? "http://localhost:11434" },
    });
    this.baseUrl = config.baseUrl ?? "http://localhost:11434";
  }

  async decide(messages: ChatMessage[], context: string): Promise<InvestigationOutput> {
    const systemPrompt = this.buildSystemPrompt(context);
    const apiMessages = [
      { role: "system" as const, content: systemPrompt },
      ...messages.filter((m) => m.role !== "system"),
      { role: "user" as const, content: "Provide your security analysis as structured JSON." },
    ];

    const body = {
      model: this.model.model,
      messages: apiMessages,
      options: { temperature: this.temperature, num_predict: this.maxTokens },
      stream: false,
    };

    const res = await this.httpRequest(`${this.baseUrl}/api/chat`, body, { "Content-Type": "application/json" });
    const json = await res.json() as { message?: { content?: string } };
    const text = json.message?.content ?? "";
    const output = this.extractJsonResponse(text);
    if (!output) throw new Error(`Ollama returned invalid decision format: ${text.slice(0, 200)}`);
    return output;
  }

  requiresNetwork(): boolean { return false; }
}
