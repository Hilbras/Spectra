/**
 * Hilbras Spectra — AI Model Adapter Interface
 *
 * Abstraction over @hilbras/sdk providers.
 * Allows swapping production LLM for deterministic test models.
 */

import type { Message } from "@hilbras/sdk";
import type { InvestigationOutput } from "./decision-schema.js";

export interface ModelAdapter {
  /** Unique identifier for this adapter (e.g. "mock", "openai-gpt4o") */
  readonly id: string;

  /** Produce an investigation output given messages and context */
  decide(messages: Message[], context: string): Promise<InvestigationOutput>;

  /** Whether this adapter requires network access */
  requiresNetwork(): boolean;
}

/**
 * Deterministic mock adapter for CI/testing.
 * Returns pre-programmed decisions based on phase and input keywords.
 * Simulates a real investigation without hitting any LLM API.
 */
export class DeterministicMockModel implements ModelAdapter {
  readonly id = "mock-deterministic";

  constructor(
    private readonly decisionTable: Array<{
      matchPhase?: string;
      matchKeyword?: string;
      output: Partial<InvestigationOutput>;
    }>,
  ) {}

  async decide(
    _messages: Message[],
    context: string,
  ): Promise<InvestigationOutput> {
    // Fall through to default behavior based on context content
    const lower = context.toLowerCase();

    // If context mentions known vulnerabilities, steer toward hypothesis creation
    const _hasTaintPaths = lower.includes("taintedpaths") && !lower.includes("totalpaths: 0");
    const hasSqlPatterns = lower.includes("prepare") || lower.includes("query(");
    const hasXssPatterns = lower.includes("innerhtml") || lower.includes("script");
    const hasCommandSinks = lower.includes("execsync") || lower.includes("spawn");
    const hasSecrets = lower.includes("hit") && !lower.includes("totalhits: 0");
    const _hasRoutes = lower.includes("endpoint") && !lower.includes("totalendpoints: 0");
    const hasConfigIssues = lower.includes("issue") && !lower.includes("totalissues: 0");

    const decisions: Array<import("./decision-schema.js").InvestigationDecision> = [];

    // Phase-gated hypothesis generation
    if (hasSqlPatterns && !context.includes("hypothesis")) {
      decisions.push({
        type: "analyze",
        objective: "Trace SQL injection source-to-sink path",
        reasoningSummary: "Raw SQL queries found with template literals",
        tool: "taint.analyze",
        toolInput: { source: "request", sink: "sql", language: "typescript" },
        expectedInformation: "Data flow from user input to database query",
        successCriteria: ["Source and sink identified in same file", "Direct concatenation confirmed"],
      });
    }

    if (hasXssPatterns && !context.includes("hypothesis")) {
      decisions.push({
        type: "analyze",
        objective: "Confirm XSS via unescaped template literal in HTML response",
        reasoningSummary: "User input rendered directly in HTML via template literal",
        tool: "search.code",
        toolInput: { query: "innerHTML|document.write|innerHTML", scope: "project", resultLimit: 10 },
        expectedInformation: "Confirmation of unsafe DOM manipulation",
        successCriteria: ["At least one unescaped rendering pattern found"],
      });
    }

    if (hasCommandSinks && !context.includes("command_hypothesis")) {
      decisions.push({
        type: "investigate",
        objective: "Verify command injection reachability from user input",
        reasoningSummary: "Subprocess execution found; checking if input flows to sink",
        tool: "filesystem.read",
        toolInput: { path: "src/generator.ts", lineStart: 1, lineEnd: 30 },
        expectedInformation: "Whether user input reaches execSync/spawn",
        successCriteria: ["Input parameter traced to command argument"],
      });
    }

    if (hasSecrets && !context.includes("secret_hypothesis")) {
      decisions.push({
        type: "analyze",
        objective: "Classify detected secrets by confidence and mask values",
        reasoningSummary: "Potential credentials found during scan",
        tool: "secrets.scan",
        toolInput: { scope: "full" },
        expectedInformation: "Secret types, locations, and masking status",
        successCriteria: ["All hits have masked values", "High-confidence secrets categorized"],
      });
    }

    if (hasConfigIssues && !context.includes("config_hypothesis")) {
      decisions.push({
        type: "analyze",
        objective: "Document configuration security issues by severity",
        reasoningSummary: "Security misconfigurations detected in project config files",
        tool: "configuration.analyze",
        toolInput: {},
        expectedInformation: "List of config issues with exact file locations",
        successCriteria: ["Each issue has file, line, and recommendation"],
      });
    }

    // After enough analysis, generate hypotheses
    if (decisions.length > 0) {
      return {
        decisions,
        currentObjective: decisions[0]!.objective,
        continueInvestigation: true,
        unknowns: [],
      };
    }

    // Default: advance or complete
    if (context.includes("phase:") && context.includes("COMPLETION")) {
      return {
        decisions: [{ type: "complete", objective: "Investigation complete" }],
        continueInvestigation: false,
      };
    }

    // Explore: discover more about the project
    if (!context.includes("frameworks") && !context.includes("dependency")) {
      return {
        decisions: [{
          type: "analyze",
          objective: "Build project intelligence model",
          reasoningSummary: "Initial project scan needed before targeted analysis",
          tool: "repository.discover",
          toolInput: { depth: 3 },
          expectedInformation: "Language distribution, frameworks, dependencies, route count",
          successCriteria: ["Project structure mapped", "Technology stack identified"],
        }],
        continueInvestigation: true,
      };
    }

    // If we have findings, correlate and report
    if (context.includes("finding") && context.includes("count")) {
      return {
        decisions: [{ type: "complete", objective: "Finalize report with all findings" }],
        continueInvestigation: false,
      };
    }

    // Generic exploration step
    return {
      decisions: [{
        type: "analyze",
        objective: "Continue systematic security analysis",
        reasoningSummary: "No immediate high-value targets identified; expanding coverage",
        tool: "search.code",
        toolInput: { query: "auth|authorize|permission|middleware", scope: "project", resultLimit: 20 },
        expectedInformation: "Authentication and authorization patterns in codebase",
        successCriteria: ["Auth flow mapped", "Authorization gaps identified"],
      }],
      continueInvestigation: true,
      unknowns: ["Exact threat model not yet defined"],
    };
  }

  requiresNetwork(): boolean {
    return false;
  }
}
