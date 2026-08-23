/**
 * Hilbras Spectra — Investigation Runtime
 *
 * Single-agent autonomous security researcher.
 *
 * The AI moves through phases, forms hypotheses, executes tools (through the
 * policy gate), validates findings in controlled environments, collects evidence,
 * and produces structured reports. Never multiple agents — one reasoning loop.
 */

import type {
  AuditStatus,
  Evidence,
  EvidenceId,
  Finding,
  Hypothesis,
  Phase,
  RiskLevel,
  SecurityInvestigation,
} from "../domain/types.js";
import { InvestigationState } from "../domain/state.js";
import { evaluatePolicy, type PolicyContext } from "../policies/engine.js";
import { InMemoryEvidenceStore } from "../storage/evidence.js";
import { createFinding } from "../findings/engine.js";
import type { CreateFindingInput } from "../findings/engine.js";
import { getPhaseHandler } from "./handlers.js";
import { ToolDispatcher } from "../tools/dispatcher.js";
import { ProjectIndex } from "../index/index.js";




// ─── Tool executor interface ─────────────────────────────────────────────────

export interface ToolHandler {
  name: string;
  execute(input: Record<string, unknown>, ctx: ToolExecutionContext): Promise<ToolOutput>;
}

export interface ToolExecutionContext {
  investigationId: string;
  phase: Phase;
  projectId: string;
  rootPath: string;
}

export interface ToolOutput {
  success: boolean;
  data: unknown;
  error?: string;
  resultSize: number;
  durationMs: number;
}

// ─── Config ────────────────────────────────────────────────────────────────────

export interface SecurityRuntimeConfig {
  targetPath: string;
  authorizationScope: import("../domain/types.js").AuthorizationScope;
  validationThreshold?: number;
  maxConcurrentTools?: number;
  dryRun?: boolean;
  organizationId?: string;
}

// ─── Result ───────────────────────────────────────────────────────────────────

export interface InvestigationResult {
  investigation: SecurityInvestigation;
  findings: Finding[];
  hypotheses: Hypothesis[];
  evidenceCount: number;
  durationMs: number;
  status: AuditStatus;
  errors: string[];
}

export interface ToolExecutionLog {
  auditId: string;
  toolName: string;
  phase: string;
  input: unknown;
  success: boolean;
  resultSize: number;
  durationMs: number;
  error: string;
}

// ─── Runtime ──────────────────────────────────────────────────────────────────

export class HilbrasSecurityRuntime {
  private state: InvestigationState;
  private readonly config: SecurityRuntimeConfig;
  private readonly handlers = new Map<string, ToolHandler>();
  private readonly evidenceStore = new InMemoryEvidenceStore();
  private readonly startTime = new Date();
  private readonly errors: string[] = [];
  private readonly toolLogs: ToolExecutionLog[] = [];
  private _index: ProjectIndex | null = null;
  private _dispatcher: ToolDispatcher | null = null;

  constructor(config: SecurityRuntimeConfig) {
    this.config = config;
    this.state = InvestigationState.create(
      config.targetPath,
      "INITIALIZATION",
    );
    // Build project index and dispatcher once at construction
    this._index = new ProjectIndex(config.targetPath);
    this._dispatcher = new ToolDispatcher(this._index);
  }

  /** Access the project index (built during INITIALIZATION) */
  getIndex(): ProjectIndex | null {
    return this._index;
  }

  registerHandler(handler: ToolHandler): void {
    this.handlers.set(handler.name, handler);
  }

  getState(): SecurityInvestigation {
    return this.state.get();
  }

  getPhase(): Phase {
    return this.state.get().phase;
  }

  isComplete(): boolean {
    const s = this.state.get().status;
    return s === "completed" || s === "cancelled";
  }

  async executeTool(
    toolName: string,
    input: Record<string, unknown>,
  ): Promise<ToolOutput | null> {
    const phase = this.state.get().phase;
    const policyCtx: PolicyContext = {
      phase,
      scope: this.config.authorizationScope,
      allowActiveTesting: this.config.authorizationScope.allowActiveTesting,
      allowNetworkAccess: this.config.authorizationScope.allowNetworkAccess,
    };

    const decision = evaluatePolicy(toolName, policyCtx);
    if (!decision.allowed) {
      this.errors.push(`Tool "${toolName}" denied by policy: ${decision.reason}`);
      return null;
    }

    // Dry-run: plan but don't execute
    if (this.config.dryRun) {
      const log: ToolExecutionLog = {
        auditId: this.state.get().id,
        toolName,
        phase,
        input,
        success: true,
        resultSize: 0,
        durationMs: 0,
        error: "",
      };
      this.toolLogs.push(log);
      return {
        success: true,
        data: { planned: true, tool: toolName, input },
        resultSize: 0,
        durationMs: 0,
      };
    }

    const handler = this.handlers.get(toolName);
    if (handler) {
      // Custom handler takes priority
      const start = Date.now();
      try {
        const output = await handler.execute(input, {
          investigationId: this.state.get().id,
          phase,
          projectId: this.state.get().projectId,
          rootPath: this.config.targetPath,
        });
        this.toolLogs.push({
          auditId: this.state.get().id,
          toolName,
          phase,
          input,
          success: output.success,
          resultSize: output.resultSize,
          durationMs: output.durationMs,
          error: output.error ?? "",
        });
        return output;
      } catch (err) {
        const message = err instanceof Error ? err.message : String(err);
        this.errors.push(`Tool "${toolName}" failed: ${message}`);
        this.toolLogs.push({
          auditId: this.state.get().id,
          toolName,
          phase,
          input,
          success: false,
          resultSize: 0,
          durationMs: Date.now() - start,
          error: message,
        });
        return { success: false, data: null, error: message, resultSize: 0, durationMs: Date.now() - start };
      }
    }

    // Fall back to dispatcher (registered real tool implementations)
    if (this._dispatcher) {
      const start = Date.now();
      try {
        const output = await this._dispatcher.dispatch(toolName, input, {
          investigationId: this.state.get().id,
          phase,
          projectId: this.state.get().projectId,
          rootPath: this.config.targetPath,
        });
        this.toolLogs.push({
          auditId: this.state.get().id,
          toolName,
          phase,
          input,
          success: output.success,
          resultSize: output.resultSize,
          durationMs: output.durationMs,
          error: output.error ?? "",
        });
        return output;
      } catch (err) {
        const message = err instanceof Error ? err.message : String(err);
        this.errors.push(`Tool "${toolName}" failed: ${message}`);
        this.toolLogs.push({
          auditId: this.state.get().id,
          toolName,
          phase,
          input,
          success: false,
          resultSize: 0,
          durationMs: Date.now() - start,
          error: message,
        });
        return { success: false, data: null, error: message, resultSize: 0, durationMs: Date.now() - start };
      }
    }

    return null;
  }

  /** Log a tool execution externally (called by phase handlers) */
  async logToolExecution(exec: ToolExecutionLog): Promise<void> {
    this.toolLogs.push(exec);
  }

  collectEvidence(
    toolName: string,
    input: unknown,
    result: unknown,
    findingId?: string,
  ): EvidenceId | null {
    const evidence: Omit<Evidence, "id" | "sanitized"> = {
      findingId: findingId ?? null,
      type: "execution",
      timestamp: new Date(),
      environment: this.config.targetPath,
      action: `Tool execution: ${toolName}`,
      input,
      observedResult: result,
      raw: result,
    };
    const record = this.evidenceStore.create(evidence);
    this.state = this.state.addEvidence(record);
    return record.id;
  }

  createFinding(input: CreateFindingInput, evidenceIds: string[] = []): Finding {
    const finding = createFinding(input, evidenceIds);
    this.state = this.state.addFinding(finding);
    for (const eid of evidenceIds) {
      this.evidenceStore.linkToFinding(eid, finding.id);
    }
    return finding;
  }

  formHypothesis(params: {
    category: string;
    target: string;
    claim: string;
    reasoning: string;
    preconditions: string[];
    expectedBehavior: string;
    suspectedBehavior: string;
    confidence: number;
    riskLevel: RiskLevel;
    validationPlan: import("../domain/types.js").ValidationStep[];
  }): Hypothesis {
    const hyp: Hypothesis = {
      id: crypto.randomUUID(),
      ...params,
      evidenceIds: [],
      status: "open",
      createdAt: new Date(),
      updatedAt: new Date(),
    };
    this.state = this.state.addHypothesis(hyp);
    return hyp;
  }

  advancePhase(nextPhase: Phase): void {
    this.state = this.state.advanceTo(nextPhase);
  }

  complete(status: AuditStatus = "completed"): void {
    this.state = this.state.setStatus(status);
  }

  /** Run the full investigation — dispatches to phase handlers */
  async run(): Promise<InvestigationResult> {
    const phases: Phase[] = [
      "INITIALIZATION",
      "RECONNAISSANCE",
      "ARCHITECTURE_ANALYSIS",
      "ATTACK_SURFACE_MAPPING",
      "SOURCE_ANALYSIS",
      "DEPENDENCY_ANALYSIS",
      "CONFIGURATION_ANALYSIS",
      "SECRET_ANALYSIS",
      "AUTHENTICATION_ANALYSIS",
      "AUTHORIZATION_ANALYSIS",
      "API_ANALYSIS",
      "BUSINESS_LOGIC_ANALYSIS",
      "HYPOTHESIS_GENERATION",
      "INVESTIGATION",
      "VALIDATION",
      "EVIDENCE_COLLECTION",
      "FINDING_CORRELATION",
      "RISK_ASSESSMENT",
      "REPORTING",
      "COMPLETION",
    ];

    this.state = this.state.setStatus("running");

    // Skip the initial phase on first run — it's already set as the starting phase
    const currentPhase = this.state.get().phase;
    const phasesToRun = phases.slice(phases.indexOf(currentPhase) + 1);

    for (const phase of phasesToRun) {
      if (this.isComplete()) break;
      this.advancePhase(phase);

      const handler = getPhaseHandler(phase);
      if (handler) {
        const policyCtx: PolicyContext = {
          phase,
          scope: this.config.authorizationScope,
          allowActiveTesting: this.config.authorizationScope.allowActiveTesting,
          allowNetworkAccess: this.config.authorizationScope.allowNetworkAccess,
        };
        const result = await handler.execute({
          runtime: this,
          state: this.state,
          policyCtx,
          rootPath: this.config.targetPath,
          signal: new AbortController().signal,
        });
        this.state = this.state.withCurrentObjective(result.summary);
        if (!result.completed && result.errors?.length) {
          this.errors.push(...result.errors);
        }
      }
    }

    this.complete("completed");

    return {
      investigation: this.state.get(),
      findings: this.state.get().findings,
      hypotheses: this.state.get().hypotheses,
      evidenceCount: this.evidenceStore.list().length,
      durationMs: Date.now() - this.startTime.getTime(),
      status: this.state.get().status,
      errors: this.errors,
    };
  }
}
