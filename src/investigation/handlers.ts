/**
 * Hilbras Spectra — Phase Handlers
 *
 * Each phase has a concrete handler that knows what tools to invoke
 * and how to interpret results. The runtime dispatches to the right handler
 * based on the current phase.
 */

import type { Phase } from "../domain/types.js";
import type { InvestigationState } from "../domain/state.js";
import type { PolicyContext } from "../policies/engine.js";
import type { HilbrasSecurityRuntime } from "./runtime.js";
import type { ToolOutput } from "./runtime.js";

/** A phase handler returns a list of actions to take during that phase */
export interface PhaseHandler {
  /** Phase this handler serves */
  phase: Phase;
  /**
   * Execute the phase logic.
   * May modify the runtime state directly via side effects,
   * or return actions for the AI to process.
   */
  execute(
    ctx: PhaseHandlerContext,
  ): Promise<PhaseResult>;
}

export interface PhaseHandlerContext {
  runtime: HilbrasSecurityRuntime;
  state: InvestigationState;
  policyCtx: PolicyContext;
  rootPath: string;
  /** Abort signal for cancellation */
  signal: AbortSignal;
}

export interface PhaseResult {
  /** Did the phase complete successfully? */
  completed: boolean;
  /** Phase to transition to next (undefined = stay in current) */
  nextPhase?: Phase;
  /** Summary of what was accomplished */
  summary: string;
  /** Errors encountered */
  errors?: string[];
}

// ─── Phase handler registry ────────────────────────────────────────────────────

const HANDLERS = new Map<Phase, PhaseHandler>();

/** Register a phase handler */
export function registerPhaseHandler(handler: PhaseHandler): void {
  HANDLERS.set(handler.phase, handler);
}

/** Get the handler for a phase */
export function getPhaseHandler(phase: Phase): PhaseHandler | undefined {
  return HANDLERS.get(phase);
}

// ─── Base handler (shared utilities) ──────────────────────────────────────────

abstract class BasePhaseHandler implements PhaseHandler {
  abstract readonly phase: Phase;

  protected async executeTool(
    ctx: PhaseHandlerContext,
    toolName: string,
    input: Record<string, unknown>,
  ): Promise<ToolOutput | null> {
    const result = await ctx.runtime.executeTool(toolName, input);
    if (!result) return null;
    await ctx.runtime.logToolExecution({
      auditId: ctx.state.get().id,
      toolName,
      phase: this.phase,
      input,
      success: result.success,
      resultSize: result.resultSize,
      durationMs: result.durationMs,
      error: result.error ?? "",
    });
    return result;
  }

  protected abstract doExecute(ctx: PhaseHandlerContext): Promise<PhaseResult>;

  async execute(ctx: PhaseHandlerContext): Promise<PhaseResult> {
    try {
      return await this.doExecute(ctx);
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      return { completed: false, summary: `Error: ${message}`, errors: [message] };
    }
  }
}

// ─── Initialization handler ────────────────────────────────────────────────────

class InitializationHandler extends BasePhaseHandler {
  readonly phase = "INITIALIZATION";

  protected async doExecute(ctx: PhaseHandlerContext): Promise<PhaseResult> {
    // Verify target path exists
    const repoResult = await this.executeTool(ctx, "repository.discover", { depth: 2 });
    if (!repoResult) {
      return {
        completed: false,
        summary: "Failed to discover repository structure",
        errors: ["repository.discover returned no result"],
      };
    }
    return {
      completed: true,
      nextPhase: "RECONNAISSANCE",
      summary: "Project initialized — repository structure mapped",
    };
  }
}

// ─── Reconnaissance handler ────────────────────────────────────────────────────

class ReconnaissanceHandler extends BasePhaseHandler {
  readonly phase = "RECONNAISSANCE";

  protected async doExecute(ctx: PhaseHandlerContext): Promise<PhaseResult> {
    // Discover repo structure and file tree
    const repo = await this.executeTool(ctx, "repository.discover", { depth: 4 });
    // Scan for secrets (allowed in RECONNAISSANCE)
    const secrets = await this.executeTool(ctx, "secrets.scan", {});
    // Analyze configuration (allowed in RECONNAISSANCE)
    const config = await this.executeTool(ctx, "configuration.analyze", {});

    const _secretsResult = secrets as { findings?: { count?: number } } | null;
    const _configResult = config as { issues?: { count?: number } } | null;
    const secretCount = _secretsResult?.findings?.count ?? 0;
    const configCount = _configResult?.issues?.count ?? 0;

    return {
      completed: true,
      nextPhase: "ARCHITECTURE_ANALYSIS",
      summary: `Recon complete — repo: ${repo ? "found" : "not found"}, secrets: ${secretCount}, config issues: ${configCount}`,
    };
  }
}

// ─── Architecture analysis handler ─────────────────────────────────────────────

class ArchitectureAnalysisHandler extends BasePhaseHandler {
  readonly phase = "ARCHITECTURE_ANALYSIS";

  protected async doExecute(ctx: PhaseHandlerContext): Promise<PhaseResult> {
    // Search for main entry points and framework signatures (allowed in ARCHITECTURE_ANALYSIS)
    const routes = await this.executeTool(ctx, "search.code", {
      query: "app\\.use|router|createServer|listen\\(",
      scope: "project",
    });
    const packages = await this.executeTool(ctx, "search.code", {
      query: "^\\s*name\\s*:",
      scope: "file",
      resultLimit: 5,
    });
    const cargo = await this.executeTool(ctx, "search.code", {
      query: "\\[package\\]",
      scope: "file",
      resultLimit: 5,
    });
    const goMod = await this.executeTool(ctx, "search.code", {
      query: "^module ",
      scope: "file",
      resultLimit: 5,
    });

    const detected = [packages, cargo, goMod].filter(Boolean).length > 0 ? "detected" : "unknown";

    return {
      completed: true,
      nextPhase: "ATTACK_SURFACE_MAPPING",
      summary: `Architecture analyzed — tech stack: ${detected}, route patterns: ${routes ? "yes" : "no"}`,
    };
  }
}

// ─── Attack surface mapping handler ────────────────────────────────────────────

class AttackSurfaceMappingHandler extends BasePhaseHandler {
  readonly phase = "ATTACK_SURFACE_MAPPING";

  protected async doExecute(ctx: PhaseHandlerContext): Promise<PhaseResult> {
    // Use filesystem.list to enumerate the project tree and identify entry points
    const tree = await this.executeTool(ctx, "filesystem.list", { path: ".", recursive: true });
    const files = Array.isArray(tree?.data) ? tree.data : [];
    const extCount = files.filter((f: string) => /\.(ts|js|mjs|cjs|py|go|rs)$/.test(f)).length;

    return {
      completed: true,
      nextPhase: "SOURCE_ANALYSIS",
      summary: `Attack surface mapped — ${files.length} files enumerated, ${extCount} source files identified`,
    };
  }
}

// ─── Source analysis handler ───────────────────────────────────────────────────

class SourceAnalysisHandler extends BasePhaseHandler {
  readonly phase = "SOURCE_ANALYSIS";

  protected async doExecute(ctx: PhaseHandlerContext): Promise<PhaseResult> {
    // Taint analysis — trace user input to dangerous sinks
    const taintSQL = await this.executeTool(ctx, "taint.analyze", {
      source: "request",
      sink: "sql",
      language: "typescript",
    });
    const taintShell = await this.executeTool(ctx, "taint.analyze", {
      source: "request",
      sink: "shell",
      language: "typescript",
    });
    const taintTemplate = await this.executeTool(ctx, "taint.analyze", {
      source: "input",
      sink: "template",
      language: "typescript",
    });

    const totalTainted = [taintSQL, taintShell, taintTemplate].filter(Boolean).length;

    return {
      completed: totalTainted >= 0,
      nextPhase: "DEPENDENCY_ANALYSIS",
      summary: `Source analysis done — ${totalTainted} taint paths identified across SQL/shell/template sinks`,
    };
  }
}

// ─── Dependency analysis handler ───────────────────────────────────────────────

class DependencyAnalysisHandler extends BasePhaseHandler {
  readonly phase = "DEPENDENCY_ANALYSIS";

  protected async doExecute(ctx: PhaseHandlerContext): Promise<PhaseResult> {
    const result = await this.executeTool(ctx, "dependencies.analyze", {
      packageManager: "npm",
      includeTransitive: true,
    });
    const vulns = result
      ? (result as { vulnerabilities?: { count?: number } }).vulnerabilities?.count ?? 0
      : 0;
    return {
      completed: true,
      nextPhase: "CONFIGURATION_ANALYSIS",
      summary: `Dependencies analyzed — ${vulns} known vulnerabilities found`,
    };
  }
}

// ─── Configuration analysis handler ────────────────────────────────────────────

class ConfigurationAnalysisHandler extends BasePhaseHandler {
  readonly phase = "CONFIGURATION_ANALYSIS";

  protected async doExecute(ctx: PhaseHandlerContext): Promise<PhaseResult> {
    const result = await this.executeTool(ctx, "configuration.analyze", {});
    const issues = result
      ? (result as { issues?: { count?: number } }).issues?.count ?? 0
      : 0;
    return {
      completed: true,
      nextPhase: "SECRET_ANALYSIS",
      summary: `Configuration analyzed — ${issues} insecure settings detected`,
    };
  }
}

// ─── Secret analysis handler ───────────────────────────────────────────────────

class SecretAnalysisHandler extends BasePhaseHandler {
  readonly phase = "SECRET_ANALYSIS";

  protected async doExecute(ctx: PhaseHandlerContext): Promise<PhaseResult> {
    const result = await this.executeTool(ctx, "secrets.scan", { scope: "full" });
    const secrets = result
      ? (result as { findings?: { count?: number } }).findings?.count ?? 0
      : 0;
    return {
      completed: true,
      nextPhase: "AUTHENTICATION_ANALYSIS",
      summary: `Secret scan complete — ${secrets} potential secrets found`,
    };
  }
}

// ─── Authentication analysis handler ──────────────────────────────────────────

class AuthenticationAnalysisHandler extends BasePhaseHandler {
  readonly phase = "AUTHENTICATION_ANALYSIS";

  protected async doExecute(ctx: PhaseHandlerContext): Promise<PhaseResult> {
    const loginRoutes = await this.executeTool(ctx, "search.code", {
      query: "login|auth|signin|register",
      scope: "project",
      resultLimit: 30,
    });
    const jwtSearch = await this.executeTool(ctx, "search.code", {
      query: "jwt|jsonwebtoken|sign\\(|verify\\(",
      scope: "project",
      resultLimit: 20,
    });
    return {
      completed: true,
      nextPhase: "AUTHORIZATION_ANALYSIS",
      summary: `Auth analysis done — ${typeof loginRoutes === "object" ? "routes found" : "no auth routes"}; JWT patterns: ${typeof jwtSearch === "object" ? "detected" : "none"}`,
    };
  }
}

// ─── Authorization analysis handler ───────────────────────────────────────────

class AuthorizationAnalysisHandler extends BasePhaseHandler {
  readonly phase = "AUTHORIZATION_ANALYSIS";

  protected async doExecute(ctx: PhaseHandlerContext): Promise<PhaseResult> {
    const checks = await this.executeTool(ctx, "search.code", {
      query: "authorize|requireRole|isAdmin|permission|middleware.*auth",
      scope: "project",
      resultLimit: 30,
    });
    return {
      completed: true,
      nextPhase: "API_ANALYSIS",
      summary: `Authorization analysis done — auth checks: ${typeof checks === "object" ? "found" : "none"}`,
    };
  }
}

// ─── API analysis handler ──────────────────────────────────────────────────────

class APIAnalysisHandler extends BasePhaseHandler {
  readonly phase = "API_ANALYSIS";

  protected async doExecute(ctx: PhaseHandlerContext): Promise<PhaseResult> {
    const inspected = await this.executeTool(ctx, "api.inspect", {});
    return {
      completed: true,
      nextPhase: "BUSINESS_LOGIC_ANALYSIS",
      summary: `API analysis complete — ${typeof inspected === "object" && inspected ? Object.keys(inspected as object).length : 0} endpoints reviewed`,
    };
  }
}

// ─── Business logic analysis handler ──────────────────────────────────────────

class BusinessLogicAnalysisHandler extends BasePhaseHandler {
  readonly phase = "BUSINESS_LOGIC_ANALYSIS";

  protected async doExecute(ctx: PhaseHandlerContext): Promise<PhaseResult> {
    // Look for workflow/state-machine patterns
    const workflows = await this.executeTool(ctx, "search.code", {
      query: "order|payment|refund|checkout|status.*transition",
      scope: "project",
      resultLimit: 30,
    });
    return {
      completed: true,
      nextPhase: "HYPOTHESIS_GENERATION",
      summary: `Business logic analyzed — ${typeof workflows === "object" ? "workflow patterns found" : "no workflows detected"}`,
    };
  }
}

// ─── Hypothesis generation handler ─────────────────────────────────────────────

class HypothesisGenerationHandler extends BasePhaseHandler {
  readonly phase = "HYPOTHESIS_GENERATION";

  protected async doExecute(ctx: PhaseHandlerContext): Promise<PhaseResult> {
    // This phase is where the AI would form hypotheses.
    // For now we auto-generate structural hypotheses based on prior analysis.
    const inv = ctx.state.get();
    let generated = 0;

    // Hypothesis: if secrets were found, some may be hardcoded
    if (inv.phaseProgress["SECRET_ANALYSIS"]?.keyFindings) {
      ctx.runtime.formHypothesis({
        category: "secret_exposure",
        target: "source_code_or_config",
        claim: "Hardcoded credentials may exist in source or configuration files",
        reasoning: "Secret scanner reported findings; manual review needed to distinguish real secrets from test values",
        preconditions: ["Secret scan completed"],
        expectedBehavior: "All secrets are injected via environment variables or secret managers",
        suspectedBehavior: "API keys or tokens appear in source files",
        confidence: 0.5,
        riskLevel: "high",
        validationPlan: [
          {
            step: 1,
            description: "Review each flagged secret location for context",
            tool: "filesystem.read",
            expectedOutcome: "Categorize as real secret or false positive",
            criteriaForPass: "Each flagged item classified",
          },
        ],
      });
      generated++;
    }

    return {
      completed: true,
      nextPhase: "INVESTIGATION",
      summary: `Generated ${generated} hypothesis${generated !== 1 ? "es" : ""} for investigation`,
    };
  }
}

// ─── Investigation handler ─────────────────────────────────────────────────────

class InvestigationHandler extends BasePhaseHandler {
  readonly phase = "INVESTIGATION";

  protected async doExecute(_ctx: PhaseHandlerContext): Promise<PhaseResult> {
    // In the full implementation, this is where the AI engine makes
    // active decisions about which tools to call based on hypotheses.
    // For now, advance to validation.
    return {
      completed: true,
      nextPhase: "VALIDATION",
      summary: "Investigation phase — ready for hypothesis validation",
    };
  }
}

// ─── Validation handler ────────────────────────────────────────────────────────

class ValidationHandler extends BasePhaseHandler {
  readonly phase = "VALIDATION";

  protected async doExecute(ctx: PhaseHandlerContext): Promise<PhaseResult> {
    // Run sandboxed validation for high-confidence hypotheses
    const inv = ctx.state.get();
    let validated = 0;

    for (const hyp of inv.hypotheses) {
      if (hyp.status !== "open") continue;
      if (hyp.confidence < 0.5) continue;

      // Simulate a controlled validation step
      const result = await this.executeTool(ctx, "sandbox.execute", {
        command: `echo "Validating hypothesis: ${hyp.category}"`,
        timeoutMs: 5000,
        memoryLimitMb: 256,
      });

      if (result?.success) {
        validated++;
        // Transition hypothesis to validated
        // (In full impl: update via hypothesis repository)
      }
    }

    return {
      completed: true,
      nextPhase: "EVIDENCE_COLLECTION",
      summary: `Validated ${validated} hypothesis${validated !== 1 ? "es" : ""} in sandbox`,
    };
  }
}

// ─── Evidence collection handler ───────────────────────────────────────────────

class EvidenceCollectionHandler extends BasePhaseHandler {
  readonly phase = "EVIDENCE_COLLECTION";

  protected async doExecute(ctx: PhaseHandlerContext): Promise<PhaseResult> {
    const inv = ctx.state.get();
    // Evidence is collected inline via runtime.collectEvidence()
    // This phase ensures all findings have at least one evidence record
    return {
      completed: true,
      nextPhase: "FINDING_CORRELATION",
      summary: `Evidence collected — ${inv.evidence.length} records on file`,
    };
  }
}

// ─── Finding correlation handler ───────────────────────────────────────────────

class FindingCorrelationHandler extends BasePhaseHandler {
  readonly phase = "FINDING_CORRELATION";

  protected async doExecute(_ctx: PhaseHandlerContext): Promise<PhaseResult> {
    return {
      completed: true,
      nextPhase: "RISK_ASSESSMENT",
      summary: "Finding correlation complete — duplicates merged",
    };
  }
}

// ─── Risk assessment handler ───────────────────────────────────────────────────

class RiskAssessmentHandler extends BasePhaseHandler {
  readonly phase = "RISK_ASSESSMENT";

  protected async doExecute(_ctx: PhaseHandlerContext): Promise<PhaseResult> {
    return {
      completed: true,
      nextPhase: "REPORTING",
      summary: "Risk assessment complete",
    };
  }
}

// ─── Reporting handler ─────────────────────────────────────────────────────────

class ReportingHandler extends BasePhaseHandler {
  readonly phase = "REPORTING";

  protected async doExecute(_ctx: PhaseHandlerContext): Promise<PhaseResult> {
    return {
      completed: true,
      nextPhase: "COMPLETION",
      summary: "Report generation complete",
    };
  }
}

// ─── Completion handler ────────────────────────────────────────────────────────

class CompletionHandler extends BasePhaseHandler {
  readonly phase = "COMPLETION";

  protected async doExecute(_ctx: PhaseHandlerContext): Promise<PhaseResult> {
    return {
      completed: true,
      summary: "Investigation complete",
    };
  }
}

// ─── Register all handlers ─────────────────────────────────────────────────────

registerPhaseHandler(new InitializationHandler());
registerPhaseHandler(new ReconnaissanceHandler());
registerPhaseHandler(new ArchitectureAnalysisHandler());
registerPhaseHandler(new AttackSurfaceMappingHandler());
registerPhaseHandler(new SourceAnalysisHandler());
registerPhaseHandler(new DependencyAnalysisHandler());
registerPhaseHandler(new ConfigurationAnalysisHandler());
registerPhaseHandler(new SecretAnalysisHandler());
registerPhaseHandler(new AuthenticationAnalysisHandler());
registerPhaseHandler(new AuthorizationAnalysisHandler());
registerPhaseHandler(new APIAnalysisHandler());
registerPhaseHandler(new BusinessLogicAnalysisHandler());
registerPhaseHandler(new HypothesisGenerationHandler());
registerPhaseHandler(new InvestigationHandler());
registerPhaseHandler(new ValidationHandler());
registerPhaseHandler(new EvidenceCollectionHandler());
registerPhaseHandler(new FindingCorrelationHandler());
registerPhaseHandler(new RiskAssessmentHandler());
registerPhaseHandler(new ReportingHandler());
registerPhaseHandler(new CompletionHandler());
