import type { InvestigationOutput } from "../decision-schema.js";
/**
 * Hilbras Spectra — Base AI Model Adapter
 * 
 * Abstract base class for all model adapters.
 * Handles HTTP communication, retry logic, JSON extraction.
 * Concrete subclasses implement provider-specific API calls.
 */


export interface ModelConfig {
  provider: string;
  model: string;
  temperature?: number;
  maxTokens?: number;
  baseUrl?: string;
}

export interface ChatMessage {
  role: "system" | "user" | "assistant";
  content: string;
}

export interface AdapterOptions {
  model: ModelConfig;
  maxRetries?: number;
  timeoutMs?: number;
}

const DEFAULTS = { maxRetries: 3, timeoutMs: 60_000, temperature: 0.1, maxTokens: 4096 };

export abstract class BaseAdapter {
  protected readonly model: ModelConfig;
  protected readonly maxRetries: number;
  protected readonly timeoutMs: number;
  protected readonly temperature: number;
  protected readonly maxTokens: number;

  constructor(opts: AdapterOptions) {
    this.model = opts.model;
    this.maxRetries = opts.maxRetries ?? DEFAULTS.maxRetries;
    this.timeoutMs = opts.timeoutMs ?? DEFAULTS.timeoutMs;
    this.temperature = opts.model.temperature ?? DEFAULTS.temperature;
    this.maxTokens = opts.model.maxTokens ?? DEFAULTS.maxTokens;
  }

  /**
   * Core method: send context to LLM and return structured investigation output.
   * Subclasses implement the provider-specific API call.
   */
  abstract decide(messages: ChatMessage[], context: string): Promise<InvestigationOutput>;

  /** Whether this adapter requires external network access */
  abstract requiresNetwork(): boolean;

  // ─── Shared helpers ────────────────────────────────────────────────────────

  buildSystemPrompt(context: string): string {
    return `You are Hilbras Spectra, an autonomous AI security researcher. Analyze this software project and identify security vulnerabilities.

PROJECT CONTEXT:
${context}

YOUR OUTPUT: Respond with ONLY a valid JSON object — no markdown, no explanation, no text outside the JSON.

{
  "decisions": [
    {
      "type": "analyze|investigate|validate|collect_evidence|create_finding|reject_hypothesis|change_phase|complete",
      "objective": "specific action (3-200 chars)",
      "reasoningSummary": "why this decision (optional)",
      "tool": "tool name like 'taint.analyze' (optional)",
      "toolInput": { /* tool parameters (optional) */ },
      "expectedInformation": "what you expect to learn (optional)",
      "successCriteria": ["verifiable condition"]
    }
  ],
  "continueInvestigation": true|false,
  "currentObjective": "string (optional)",
  "unknowns": ["remaining questions"]
}

RULES:
1. Always include at least one decision
2. Use create_finding when you have sufficient evidence of a vulnerability
3. Use complete only when the investigation has exhausted all leads
4. Keep objectives specific and actionable
5. Prioritize high-severity findings`;
  }

  extractJsonResponse(text: string): InvestigationOutput | null {
    // Direct parse
    try {
      const obj = JSON.parse(text.trim());
      if (obj && Array.isArray(obj.decisions)) return obj as InvestigationOutput;
    } catch { /* fall through */ }

    // Strip code fences
    const cleaned = text.replace(/```json\s*/g, "").replace(/```\s*/g, "").trim();
    const start = cleaned.indexOf("{");
    const end = cleaned.lastIndexOf("}");
    if (start === -1 || end <= start) return null;

    try {
      const obj = JSON.parse(cleaned.slice(start, end + 1));
      if (obj && Array.isArray(obj.decisions)) return obj as InvestigationOutput;
    } catch { /* fall through */ }

    // Fallback: find first JSON object with decisions key
    const match = cleaned.match(/\{[\s\S]*"decisions"[\s\S]*\}/);
    if (match) {
      try { return JSON.parse(match[0]) as InvestigationOutput; } catch { /* fall through */ }
    }

    return null;
  }

  protected async httpRequest(
    url: string, body: unknown, headers: Record<string, string>,
  ): Promise<Response> {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeoutMs);

    let lastErr: Error | null = null;
    for (let i = 0; i <= this.maxRetries; i++) {
      try {
        const res = await fetch(url, { method: "POST", headers, body: JSON.stringify(body), signal: controller.signal });
        clearTimeout(timer);
        if (!res.ok) throw new Error(`HTTP ${res.status}: ${(await res.text()).slice(0, 200)}`);
        return res;
      } catch (e) {
        lastErr = e instanceof Error ? e : new Error(String(e));
        if (i < this.maxRetries) await new Promise((r) => setTimeout(r, 1000 * Math.pow(2, i)));
      }
    }
    throw new Error(`Request failed after ${this.maxRetries + 1} attempts: ${lastErr?.message}`);
  }
}
