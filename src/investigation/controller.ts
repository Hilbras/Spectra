/**
 * Hilbras Spectra — Investigation Controller
 *
 * The single autonomous AI security researcher.
 * Runs the iterative investigation loop:
 *   observe → reason → act → interpret → update state → repeat
 */

import type { Phase, SecurityInvestigation } from "../domain/types.js";
import { getTool } from "../tools/registry.js";
import { ProjectIndex } from "../index/index.js";
import { buildSecurityModel } from "./security-model.js";
import type { ModelAdapter } from "./model-adapter.js";
import { InvestigationEventStream, evt } from "./events.js";
import { HilbrasSecurityRuntime } from "./runtime.js";

export interface InvestigationControllerConfig {
  runtime: HilbrasSecurityRuntime;
  model: ModelAdapter;
  /** Max iterations before forced completion */
  maxIterations?: number;
  /** Token budget (tokens consumed); null = unlimited */
  tokenBudget?: number;
}

export interface InvestigationControllerResult {
  investigation: SecurityInvestigation;
  events: Array<{ type: string; summary: string }>;
  iterations: number;
  durationMs: number;
  errors: string[];
}

export class InvestigationController {
  private readonly runtime: HilbrasSecurityRuntime;
  private readonly model: ModelAdapter;
  private readonly index: ProjectIndex;
  private readonly events: InvestigationEventStream;
  private readonly maxIterations: number;
  private readonly tokenBudget: number | null;
  private readonly errors: string[] = [];
  private iterationCount = 0;
  private tokensUsed = 0;

  constructor(config: InvestigationControllerConfig) {
    this.runtime = config.runtime;
    this.model = config.model;
    this.index = config.runtime.getIndex()!;
    this.events = new InvestigationEventStream();
    this.maxIterations = config.maxIterations ?? 50;
    this.tokenBudget = config.tokenBudget ?? null;
  }

  async run(): Promise<InvestigationControllerResult> {
    const startTime = Date.now();
    this.events.emit(evt("investigation.started", "Investigation started"));

    try {
      // Build security model once at start
      const securityModel = buildSecurityModel(this.index);
      this.events.emit(evt("phase.changed", "Project analyzed", {
        assets: securityModel.assets.length,
        endpoints: securityModel.endpoints.length,
        controls: securityModel.controls.filter((c) => c.present).length,
      }));

      let phase: Phase = "INITIALIZATION";
      let objective = "Analyze project structure and identify attack surface";

      while (this.iterationCount < this.maxIterations) {
        if (this.runtime.isComplete()) break;
        if (this.tokenBudget !== null && this.tokensUsed >= this.tokenBudget) {
          this.events.emit(evt("investigation.completed", "Budget exhausted"));
          break;
        }

        this.iterationCount++;
        const state = this.runtime.getState();

        // Build compact context for AI
        const context = this.buildContext(phase, objective, securityModel, state);
        this.events.emit(evt("tool.requested", `AI iteration ${this.iterationCount}: deciding next action`, {
          phase, iteration: this.iterationCount,
        }));

        // Get AI decision
        const output = await this.model.decide([], context);

        // Validate output schema
        if (!output.decisions || output.decisions.length === 0) {
          this.errors.push("AI returned no decisions");
          break;
        }

        // Process each decision (pick highest-value one)
        const bestDecision = this.selectBestDecision(output.decisions, state);
        if (!bestDecision) continue;

        // Update objective
        if (output.currentObjective) objective = output.currentObjective;

        this.events.emit(evt("investigation.paused", bestDecision.objective, {
          type: bestDecision.type, iteration: this.iterationCount,
        }));

        await this.executeDecision(bestDecision, state, securityModel);
      }

      this.runtime.complete("completed");
      this.events.emit(evt("investigation.completed", `Completed in ${this.iterationCount} iterations`));
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      this.errors.push(`Controller error: ${msg}`);
      this.runtime.complete("failed");
      this.events.emit(evt("investigation.failed", msg));
    }

    return {
      investigation: this.runtime.getState(),
      events: this.events.getHistory().map((e) => ({ type: e.type, summary: e.summary })),
      iterations: this.iterationCount,
      durationMs: Date.now() - startTime,
      errors: this.errors,
    };
  }

  /** Select the highest-priority decision from AI output */
  private selectBestDecision(
    decisions: import("./decision-schema.js").InvestigationDecision[],
    _state: SecurityInvestigation,
  ): import("./decision-schema.js").InvestigationDecision | null {
    // Prioritize: complete > create_finding > validate > investigate > analyze
    const priority: Record<string, number> = {
      complete: 100,
      create_finding: 90,
      validate: 80,
      investigate: 70,
      analyze: 60,
      reject_hypothesis: 50,
      change_phase: 40,
      collect_evidence: 30,
    };
    return decisions.reduce((best, d) => {
      const score = (priority[d.type] ?? 0) + (d.expectedInformation ? 5 : 0);
      return !best || score > (best as any)._score ? { ...d, _score: score } : best;
    }, null as any);
  }

  /** Execute a single validated decision */
  private async executeDecision(
    decision: import("./decision-schema.js").InvestigationDecision,
    _state: SecurityInvestigation,
    _securityModel: any,
  ): Promise<void> {
    switch (decision.type) {
      case "complete":
        this.runtime.complete("completed");
        this.events.emit(evt("investigation.completed", decision.objective));
        break;

      case "analyze":
      case "investigate":
        await this.executeToolAnalysis(decision);
        break;

      case "validate":
        await this.executeValidation(decision);
        break;

      case "collect_evidence":
        if (decision.evidence) {
          const eid = this.runtime.collectEvidence(
            "manual", decision.evidence.input, decision.evidence.observedResult,
            decision.hypothesisId,
          );
          if (eid) this.events.emit(evt("evidence.created", `Evidence collected: ${decision.evidence.action}`, { evidenceId: eid }));
        }
        break;

      case "create_finding":
        if (decision.newFinding) {
          const finding = this.runtime.createFinding({
            title: decision.newFinding.title,
            category: decision.newFinding.category,
            affectedComponent: decision.newFinding.affectedComponent,
            affectedLocation: (() => {
            const loc = decision.newFinding.affectedLocation;
            const out: any = {};
            if (loc.file) out.file = loc.file;
            if (loc.lineStart != null) out.lineStart = loc.lineStart;
            if (loc.lineEnd != null) out.lineEnd = loc.lineEnd;
            if (loc.function) out.function = loc.function;
            return out;
          })(),
            rootCause: decision.newFinding.rootCause,
            description: decision.newFinding.description,
            impact: decision.newFinding.impact,
            severityComponents: decision.newFinding.severityComponents,
            remediation: (() => {
            const r = decision.newFinding.remediation;
            if (!r) return undefined;
            const out: any = {};
            if (r.whyItHappens) out.whyItHappens = r.whyItHappens;
            if (r.recommendedFix) out.recommendedFix = r.recommendedFix;
            if (r.securePattern) out.securePattern = r.securePattern;
            if (r.affectedFiles) out.affectedFiles = r.affectedFiles;
            if (r.testsNeeded) out.testsNeeded = r.testsNeeded;
            return Object.keys(out).length > 0 ? out : undefined;
          })(),
          });
          this.events.emit(evt("finding.created", `Finding created: ${finding.title}`, { findingId: finding.id, severity: finding.severity }));
        }
        break;

      case "reject_hypothesis":
        if (decision.hypothesisId) {
          // In full impl: transition hypothesis to rejected status
          this.events.emit(evt("hypothesis.rejected", `Hypothesis rejected: ${decision.hypothesisId}`));
        }
        break;

      case "change_phase":
        // In full impl: advance to next phase
        this.events.emit(evt("phase.changed", `Phase change: ${decision.objective}`));
        break;
    }
  }

  /** Execute a tool call through the policy gate */
  private async executeToolAnalysis(decision: import("./decision-schema.js").InvestigationDecision): Promise<void> {
    if (!decision.tool) return;
    const toolName = decision.tool;

    // Validate: tool must exist in registry
    const toolDef = getTool(toolName);
    if (!toolDef) {
      this.errors.push(`Unknown tool requested by AI: ${toolName}`);
      this.events.emit(evt("tool.denied", `Tool not in registry: ${toolName}`));
      return;
    }

    // Validate: tool available in current phase
    const phase = this.runtime.getPhase();
    if (!toolDef.allowedPhases.includes(phase)) {
      this.errors.push(`AI requested ${toolName} but not allowed in phase ${phase}`);
      this.events.emit(evt("tool.denied", `Tool denied: phase mismatch ${toolName} @ ${phase}`));
      return;
    }

    // Validate: tool input matches schema (rough check)
    if (decision.toolInput) {
      // In full impl: validate against ToolDefinition.parameters
    }

    // Execute through runtime (which applies policy gate)
    const result = await this.runtime.executeTool(toolName, decision.toolInput ?? {});
    if (result === null) {
      this.events.emit(evt("tool.denied", `${toolName} denied by policy`));
      return;
    }
    if (!result.success) {
      this.events.emit(evt("tool.failed", `${toolName} failed: ${result.error}`));
      return;
    }

    // Record event
    const summary = typeof result.data === "string"
      ? result.data.slice(0, 100)
      : JSON.stringify(result.data).slice(0, 200);
    this.events.emit(evt("tool.executed", `${toolName}: ${summary}`, {
      tool: toolName, phase, success: true,
    }));

    // If decision expected information, log it
    if (decision.expectedInformation) {
      this.events.emit(evt("investigation.paused", `Expected: ${decision.expectedInformation}`));
    }
  }

  /** Execute a validation plan for a hypothesis */
  private async executeValidation(decision: import("./decision-schema.js").InvestigationDecision): Promise<void> {
    if (!decision.hypothesisId || !decision.tool) return;
    const result = await this.runtime.executeTool(decision.tool, decision.toolInput ?? {});
    if (result?.success) {
      this.events.emit(evt("tool.executed", `Validation ${decision.hypothesisId}: ${decision.tool}`, {
        hypothesisId: decision.hypothesisId,
      }));
    }
  }

  /** Build compact context string for the AI */
  private buildContext(
    phase: Phase,
    objective: string,
    securityModel: ReturnType<typeof buildSecurityModel>,
    _state: SecurityInvestigation,
  ): string {
    const availableTools = ["filesystem.list", "filesystem.read", "search.code", "ast.parse", "taint.analyze",
      "dependencies.analyze", "secrets.scan", "configuration.analyze", "api.inspect"];

    return [
      `=== PHASE: ${phase} ===`,
      `OBJECTIVE: ${objective}`,
      ``,
      `=== PROJECT MODEL ===`,
      `Assets: ${securityModel.assets.length}`,
      `Endpoints: ${securityModel.endpoints.length}`,
      `Trust Boundaries: ${securityModel.trustBoundaries.length}`,
      `Sources: ${securityModel.sources.length}`,
      `Sinks: ${securityModel.sinks.length}`,
      ``,
      `=== ENDPOINTS ===`,
      securityModel.endpoints.length === 0 ? "  None discovered"
        : securityModel.endpoints.slice(0, 20).map((e) =>
          `  ${e.method} ${e.path} [auth:${e.authRequired}] sens:${e.sensitivity}`,
        ).join("\n"),
      ``,
      `=== SECURITY CONTROLS ===`,
      ...securityModel.controls.map((c) =>
        `  [${c.present ? "✓" : "✗"}] ${c.type}${c.location ? ` @ ${c.location}` : ""}${c.weakness ? ` — ${c.weakness}` : ""}`,
      ),
      ``,
      `=== SOURCES & SINKS ===`,
      `Sources: ${securityModel.sources.map((s) => s.name).join(", ") || "None"}`,
      `Sinks: ${securityModel.sinks.map((s) => s.name).join(", ") || "None"}`,
      ``,
      `=== ACTIVE HYPOTHESES (${_state.hypotheses.length}) ===`,
      _state.hypotheses.length === 0 ? "  None yet."
        : _state.hypotheses.map((h) =>
          `  [${h.status}] ${h.category}: ${(h.claim).slice(0, 80)} (conf: ${(h.confidence * 100).toFixed(0)}%)`,
        ).join("\n"),
      ``,
      `=== CONFIRMED FINDINGS (${_state.findings.length}) ===`,
      _state.findings.length === 0 ? "  None yet."
        : _state.findings.map((f) =>
          `  [${f.severity.toUpperCase()}] ${f.title} — ${f.status}`,
        ).join("\n"),
      ``,
      `=== UNKNOWNs (${_state.unknowns.length}) ===`,
      _state.unknowns.length === 0 ? "  None recorded." : _state.unknowns.join("\n"),
      ``,
      `Available tools: ${availableTools.join(", ")}`,
    ].join("\n");
  }
}
