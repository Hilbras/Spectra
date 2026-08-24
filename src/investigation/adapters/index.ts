/**
 * Hilbras Spectra — AI Model Adapter Factory
 * 
 * Creates the appropriate ModelAdapter based on configuration.
 * Falls back to DeterministicMockModel when no real provider is configured.
 */

export { BaseAdapter, type ModelConfig, type ChatMessage, type AdapterOptions } from "./base.js";
export { OpenAIAdapter } from "./openai.js";
export { AnthropicAdapter } from "./anthropic.js";
export { OllamaAdapter } from "./ollama.js";

import type { ModelAdapter } from "../model-adapter.js";
import { loadConfig } from "../../cli/config.js";
import { DeterministicMockModel } from "../model-adapter.js";
import { OpenAIAdapter } from "./openai.js";
import { AnthropicAdapter } from "./anthropic.js";
import { OllamaAdapter } from "./ollama.js";

/**
 * Create a ModelAdapter from configuration.
 * Returns DeterministicMockModel if no real provider is configured.
 */
export function createModelAdapter(): ModelAdapter {
  const cfg = loadConfig();
  const modelId = cfg.defaultModel ?? "mock";

  if (modelId === "mock") {
    return new DeterministicMockModel([]);
  }

  const keys = cfg.apiKeys ?? {};

  switch (modelId) {
    case "openai": {
      const apiKey = keys.openai ?? process.env.OPENAI_API_KEY;
      if (!apiKey) {
        console.error("[Spectra] OpenAI API key not found. Set SPECTRA_OPENAI_API_KEY or run 'spectra login openai'");
        process.exit(1);
      }
      return new OpenAIAdapter({ apiKey, model: "gpt-4o" });
    }

    case "anthropic": {
      const apiKey = keys.anthropic ?? process.env.ANTHROPIC_API_KEY;
      if (!apiKey) {
        console.error("[Spectra] Anthropic API key not found. Set SPECTRA_ANTHROPIC_API_KEY or run 'spectra login anthropic'");
        process.exit(1);
      }
      return new AnthropicAdapter({ apiKey, model: "claude-3-5-sonnet-20241022" });
    }

    case "groq": {
      // Groq uses OpenAI-compatible API
      const apiKey = keys.groq ?? process.env.GROQ_API_KEY;
      if (!apiKey) {
        console.error("[Spectra] Groq API key not found. Set SPECTRA_GROQ_API_KEY or run 'spectra login groq'");
        process.exit(1);
      }
      return new OpenAIAdapter({ apiKey, model: "llama-3.1-70b-versatile", baseUrl: "https://api.groq.com/openai/v1" });
    }

    case "ollama": {
      return new OllamaAdapter({ model: "llama3.2" });
    }

    default:
      console.error(`[Spectra] Unknown model: ${modelId}. Use: mock, openai, anthropic, groq, ollama`);
      process.exit(1);
  }
}
