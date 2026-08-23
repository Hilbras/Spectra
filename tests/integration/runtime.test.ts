import { describe, expect, it } from "vitest";
import { HilbrasSecurityRuntime } from "../../src/investigation/runtime.js";
import type { ToolHandler, ToolOutput } from "../../src/investigation/runtime.js";
import { registerTool } from "../../src/tools/registry.js";

/** A no-op handler that records calls for testing */
class RecordingHandler implements ToolHandler {
  calls: Array<{ name: string; input: Record<string, unknown> }> = [];

  constructor(private readonly _name: string) {}

  get name() {
    return this._name;
  }

  async execute(
    input: Record<string, unknown>,
  ): Promise<ToolOutput> {
    this.calls.push({ name: this._name, input });
    return {
      success: true,
      data: { processed: true, echo: input },
      resultSize: JSON.stringify(input).length,
      durationMs: 1,
    };
  }
}

describe("HilbrasSecurityRuntime", () => {
  it("starts with INITIALIZATION phase and pending status", async () => {
    const runtime = new HilbrasSecurityRuntime({
      targetPath: "/tmp/test-project",
      authorizationScope: {
        allowedHosts: [],
        allowedServices: [],
        allowedPorts: [],
        allowedEnvironments: ["local"],
        allowedOperations: ["read"],
        restrictions: [],
        allowActiveTesting: false,
        allowNetworkAccess: false,
        allowFilesystemWrite: false,
      },
    });

    expect(runtime.getPhase()).toBe("INITIALIZATION");
    expect(runtime.getState().status).toBe("pending");
    expect(runtime.isComplete()).toBe(false);
  });

  it("rejects tools when active testing is not authorized", async () => {
    const runtime = new HilbrasSecurityRuntime({
      targetPath: "/tmp/test-project",
      authorizationScope: {
        allowedHosts: [],
        allowedServices: [],
        allowedPorts: [],
        allowedEnvironments: ["local"],
        allowedOperations: ["read"],
        restrictions: [],
        allowActiveTesting: false,
        allowNetworkAccess: false,
        allowFilesystemWrite: false,
      },
    });

    const result = await runtime.executeTool("http.request", {
      url: "http://example.com",
      method: "GET",
    });
    expect(result).toBeNull();
  });

  it("allows read-only tools in RECONNAISSANCE", async () => {
    const runtime = new HilbrasSecurityRuntime({
      targetPath: "/tmp/test-project",
      authorizationScope: {
        allowedHosts: [],
        allowedServices: [],
        allowedPorts: [],
        allowedEnvironments: ["local"],
        allowedOperations: ["read"],
        restrictions: [],
        allowActiveTesting: false,
        allowNetworkAccess: false,
        allowFilesystemWrite: false,
      },
    });

    const result = await runtime.executeTool("repository.discover", {});
    // Policy passes and dispatcher provides the implementation
    expect(result).not.toBeNull();
    expect(result!.success).toBe(true);
  });

  it("executes registered tool handlers through the policy gate", async () => {
    const runtime = new HilbrasSecurityRuntime({
      targetPath: "/tmp/test-project",
      authorizationScope: {
        allowedHosts: [],
        allowedServices: [],
        allowedPorts: [],
        allowedEnvironments: ["local"],
        allowedOperations: ["read"],
        restrictions: [],
        allowActiveTesting: true,
        allowNetworkAccess: false,
        allowFilesystemWrite: false,
      },
    });

    // Register a test handler and its tool definition so the policy gate passes
    registerTool({
      name: "integration.test.tool",
      description: "Test tool",
      parameters: { type: "object", properties: {}, required: [] },
      riskLevel: "read_only",
      allowedPhases: ["INITIALIZATION", "INVESTIGATION", "VALIDATION"],
      permission: "automated",
      handlerRef: "test-tool",
      maxResultSizeBytes: 10_000,
      requiresSandbox: false,
    });
    const handler = new RecordingHandler("integration.test.tool");
    runtime.registerHandler(handler);

    const result = await runtime.executeTool("integration.test.tool", { query: "SELECT *" });
    expect(result).not.toBeNull();
    expect(result!.success).toBe(true);
    expect(handler.calls).toHaveLength(1);
    expect(handler.calls[0]!.input.query).toBe("SELECT *");
  });

  it("does not execute in dry-run mode but still passes policy", async () => {
    const runtime = new HilbrasSecurityRuntime({
      targetPath: "/tmp/test-project",
      authorizationScope: {
        allowedHosts: [],
        allowedServices: [],
        allowedPorts: [],
        allowedEnvironments: ["local"],
        allowedOperations: ["read"],
        restrictions: [],
        allowActiveTesting: true,
        allowNetworkAccess: false,
        allowFilesystemWrite: false,
      },
      dryRun: true,
    });

    // Register tool and handler for dry-run test
    registerTool({
      name: "integration.test.tool2",
      description: "Dry-run test tool",
      parameters: { type: "object", properties: {}, required: [] },
      riskLevel: "read_only",
      allowedPhases: ["INITIALIZATION", "INVESTIGATION", "VALIDATION"],
      permission: "automated",
      handlerRef: "test-tool-2",
      maxResultSizeBytes: 10_000,
      requiresSandbox: false,
    });
    const handler = new RecordingHandler("integration.test.tool2");
    runtime.registerHandler(handler);

    const result = await runtime.executeTool("integration.test.tool2", { a: 1 });
    expect(result).not.toBeNull();
    expect(result!.data).toEqual({ planned: true, tool: "integration.test.tool2", input: { a: 1 } });
    // Handler should NOT have been called in dry-run
    expect(handler.calls).toHaveLength(0);
  });

  it("records evidence and links findings", async () => {
    const runtime = new HilbrasSecurityRuntime({
      targetPath: "/tmp/test-project",
      authorizationScope: {
        allowedHosts: [],
        allowedServices: [],
        allowedPorts: [],
        allowedEnvironments: ["local"],
        allowedOperations: ["read"],
        restrictions: [],
        allowActiveTesting: false,
        allowNetworkAccess: false,
        allowFilesystemWrite: false,
      },
    });

    const eid = runtime.collectEvidence(
      "filesystem.read",
      { path: "package.json" },
      { name: "test-project", version: "1.0.0" },
    );
    expect(eid).toBeTruthy();

    const finding = runtime.createFinding({
      title: "Insecure dependency",
      category: "dependency_risk",
      affectedComponent: "lodash",
      affectedLocation: { file: "package.json" },
      rootCause: "Outdated lodash version with known prototype pollution",
      description: "lodash < 4.17.21 allows prototype pollution.",
      impact: "Potential remote code execution via crafted input.",
      severityComponents: { exploitability: 7, impact: 8, confidence: 0.8 },
    });

    expect(finding.id).toBeTruthy();
    expect(finding.severity).toBeTruthy();
    expect(finding.status).toBe("potential");
    expect(runtime.getState().findings.length).toBeGreaterThan(0);
  });

  it("forms and tracks hypotheses", async () => {
    const runtime = new HilbrasSecurityRuntime({
      targetPath: "/tmp/test-project",
      authorizationScope: {
        allowedHosts: [],
        allowedServices: [],
        allowedPorts: [],
        allowedEnvironments: ["local"],
        allowedOperations: ["read"],
        restrictions: [],
        allowActiveTesting: false,
        allowNetworkAccess: false,
        allowFilesystemWrite: false,
      },
    });

    const hyp = runtime.formHypothesis({
      category: "idor",
      target: "API /api/users/:id",
      claim: "User ID in URL path is not validated against session ownership",
      reasoning: "No ownership check observed in route handler.",
      preconditions: ["Authenticated as low-privilege user"],
      expectedBehavior: "Server returns 403 for foreign IDs",
      suspectedBehavior: "Server returns user data regardless of ID ownership",
      confidence: 0.65,
      riskLevel: "high",
      validationPlan: [
        {
          step: 1,
          description: "Login as user A, fetch /api/users/:id where id=B",
          tool: "http.request",
          expectedOutcome: "403 Forbidden",
          criteriaForPass: "Response status 403 and empty body",
        },
      ],
    });

    expect(hyp.id).toBeTruthy();
    expect(hyp.status).toBe("open");
    expect(runtime.getState().hypotheses.length).toBe(1);
  });

  it("advances through phases and completes", async () => {
    const runtime = new HilbrasSecurityRuntime({
      targetPath: "/tmp/test-project",
      authorizationScope: {
        allowedHosts: [],
        allowedServices: [],
        allowedPorts: [],
        allowedEnvironments: ["local"],
        allowedOperations: ["read"],
        restrictions: [],
        allowActiveTesting: false,
        allowNetworkAccess: false,
        allowFilesystemWrite: false,
      },
    });

    // Simulate progression
    runtime.advancePhase("RECONNAISSANCE");
    expect(runtime.getPhase()).toBe("RECONNAISSANCE");

    runtime.advancePhase("ARCHITECTURE_ANALYSIS");
    expect(runtime.getPhase()).toBe("ARCHITECTURE_ANALYSIS");

    runtime.complete("completed");
    expect(runtime.isComplete()).toBe(true);
    expect(runtime.getState().status).toBe("completed");
  });
});
