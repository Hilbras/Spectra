import { describe, expect, it } from "vitest";
import {
  computeSeverityScore,
  createFinding,
  correlateFindings,
  groupCorrelated,
  transitionFindingStatus,
} from "../../src/findings/engine.js";
import type { Finding } from "../../src/domain/types.js";
import { InvestigationState } from "../../src/domain/state.js";
import { registerTool, getTool, listTools } from "../../src/tools/registry.js";
import { evaluatePolicy } from "../../src/policies/engine.js";

describe("severity engine", () => {
  it("maps high scores to critical severity", () => {
    const score = computeSeverityScore({
      exploitability: 9,
      impact: 10,
      reachability: 9,
      privilegesRequired: 2, // easy to exploit
      userInteraction: 1, // none needed
      dataSensitivity: 10,
      businessCriticality: 9,
      confidence: 10,
    });
    expect(score.mappedSeverity).toBe("critical");
    expect(score.total).toBeGreaterThan(80);
  });

  it("maps medium scores to medium severity", () => {
    const score = computeSeverityScore({
      exploitability: 5,
      impact: 5,
      reachability: 5,
      confidence: 0.5,
    });
    expect(score.mappedSeverity).toBe("medium");
  });

  it("inverts privilege requirement (lower privilege needed = higher score)", () => {
    // privilegesRequired=2 (low privilege = easy) → inverted to 8
    const score = computeSeverityScore({
      privilegesRequired: 2,
      userInteraction: 1,
      confidence: 0.3,
    });
    expect(score.privilegesRequired).toBe(8);
    expect(score.userInteraction).toBe(9);
  });
});

describe("finding creation", () => {
  it("creates a finding with deterministic severity", () => {
    const finding = createFinding({
      title: "Potential SQL injection",
      category: "sql_injection",
      affectedComponent: "UserRepository.query()",
      affectedLocation: { file: "src/user.ts", lineStart: 42 },
      rootCause: "Unparameterized query with user input",
      description: "User-controlled input reaches a raw SQL query.",
      impact: "Database compromise possible.",
      severityComponents: { exploitability: 9, impact: 10, privilegesRequired: 1, userInteraction: 1, dataSensitivity: 10, businessCriticality: 9, confidence: 10 },
    });

    expect(finding.severity).toBe("critical");
    expect(finding.confidence).toBe("high");
    expect(finding.status).toBe("potential");
    expect(finding.evidenceIds).toEqual([]);
    expect(finding.references).toEqual([]);
    expect(finding.tags).toEqual([]);
  });

  it("omits optional fields when not provided", () => {
    const f = createFinding({
      title: "Test",
      category: "test",
      affectedComponent: "x",
      affectedLocation: { file: "a.ts" },
      rootCause: "r",
      description: "d",
      impact: "i",
      severityComponents: {},
    });
    expect(f.cwe).toBeUndefined();
    expect(f.owasp).toBeUndefined();
    expect(f.remediation).toBeUndefined();
    expect(f.attackPath).toBeUndefined();
    expect(f.correlationGroupId).toBeUndefined();
  });
});

describe("finding correlation", () => {
  const makeFinding = (overrides: Partial<Finding> & { category: string; affectedComponent: string }): Finding =>
    createFinding({
      title: overrides.title ?? "Finding",
      category: overrides.category,
      affectedComponent: overrides.affectedComponent,
      affectedLocation: overrides.affectedLocation ?? { file: "x" },
      rootCause: "root cause",
      description: "desc",
      impact: "impact",
      severityComponents: {},
    });

  it("returns high correlation for identical findings", () => {
    const a = makeFinding({ category: "sql_injection", affectedComponent: "UserRepo", title: "SQLi in UserRepo" });
    const b = makeFinding({ category: "sql_injection", affectedComponent: "UserRepo", title: "Another SQLi" });
    a.cwe = "CWE-89";
    b.cwe = "CWE-89";
    expect(correlateFindings(a, b)).toBeGreaterThanOrEqual(0.6);
  });

  it("returns low correlation for unrelated findings", () => {
    const a = makeFinding({ category: "xss", affectedComponent: "LoginForm" });
    const b = makeFinding({ category: "idor", affectedComponent: "OrderService" });
    expect(correlateFindings(a, b)).toBeLessThan(0.3);
  });
});

describe("finding status transitions", () => {
  it("allows potential → validated", () => {
    const f = createFinding({
      title: "t",
      category: "c",
      affectedComponent: "x",
      affectedLocation: { file: "f" },
      rootCause: "r",
      description: "d",
      impact: "i",
      severityComponents: {},
    });
    const result = transitionFindingStatus(f, "validated");
    expect(result.valid).toBe(true);
    expect(result.finding.status).toBe("validated");
  });

  it("rejects invalid transition confirmed → potential", () => {
    const f = createFinding({
      title: "t",
      category: "c",
      affectedComponent: "x",
      affectedLocation: { file: "f" },
      rootCause: "r",
      description: "d",
      impact: "i",
      severityComponents: {},
    });
    // First move to confirmed
    const afterValidated = transitionFindingStatus(f, "validated").finding;
    const afterConfirmed = transitionFindingStatus(afterValidated, "confirmed").finding;
    // confirmed → potential is not allowed
    const result = transitionFindingStatus(afterConfirmed, "potential");
    expect(result.valid).toBe(false);
    expect(result.reason).toContain("Cannot transition");
  });

  it("allows validated → confirmed", () => {
    const f = createFinding({
      title: "t",
      category: "c",
      affectedComponent: "x",
      affectedLocation: { file: "f" },
      rootCause: "r",
      description: "d",
      impact: "i",
      severityComponents: {},
    });
    const afterValidated = transitionFindingStatus(f, "validated").finding;
    const result = transitionFindingStatus(afterValidated, "confirmed");
    expect(result.valid).toBe(true);
    expect(result.finding.status).toBe("confirmed");
  });
});

describe("investigation state machine", () => {
  it("starts in INITIALIZATION with pending status", () => {
    const state = InvestigationState.create("proj-1", "INITIALIZATION");
    const inv = state.get();
    expect(inv.id).toBeTruthy();
    expect(inv.projectId).toBe("proj-1");
    expect(inv.status).toBe("pending");
    expect(inv.phase).toBe("INITIALIZATION");
    expect(inv.findings).toEqual([]);
    expect(inv.hypotheses).toEqual([]);
    expect(inv.timeline.length).toBeGreaterThan(0);
  });

  it("transitions INITIALIZATION → RECONNAISSANCE", () => {
    const state = InvestigationState.create("proj-1", "INITIALIZATION");
    const next = state.advanceTo("RECONNAISSANCE");
    expect(next.get().phase).toBe("RECONNAISSANCE");
    expect(next.get().phaseProgress["INITIALIZATION"].status).toBe("completed");
    expect(next.get().phaseProgress["RECONNAISSANCE"].status).toBe("in_progress");
  });

  it("rejects invalid phase transition", () => {
    const state = InvestigationState.create("proj-1", "RECONNAISSANCE");
    expect(() => state.advanceTo("SOURCE_ANALYSIS")).toThrow("Invalid phase transition");
  });

  it("records a finding and updates timeline", () => {
    const state = InvestigationState.create("proj-1", "RECONNAISSANCE");
    const finding = createFinding({
      title: "XSS found",
      category: "xss",
      affectedComponent: "TemplateEngine",
      affectedLocation: { file: "render.ts" },
      rootCause: "No escaping",
      description: "User input rendered unsanitized",
      impact: "Client-side script execution",
      severityComponents: {},
    });
    const next = state.addFinding(finding);
    expect(next.get().findings).toHaveLength(1);
    expect(next.get().timeline.some((e) => e.eventType === "finding_created")).toBe(true);
  });

  it("sets status to completed", () => {
    const state = InvestigationState.create("proj-1", "INITIALIZATION");
    const next = state.setStatus("completed");
    expect(next.get().status).toBe("completed");
    expect(next.get().completedAt).toBeDefined();
  });
});

describe("tool registry", () => {
  it("registers and retrieves tools", () => {
    const existing = listTools().length;
    expect(getTool("filesystem.list")).toBeDefined();
    expect(listTools().length).toBeGreaterThan(0);
  });

  it("rejects duplicate registration", () => {
    expect(() =>
      registerTool({
        name: "filesystem.list",
        description: "dup",
        parameters: { type: "object", properties: {}, required: [] },
        riskLevel: "read_only",
        allowedPhases: ["RECONNAISSANCE"],
        permission: "automated",
        handlerRef: "dup",
        maxResultSizeBytes: 100,
        requiresSandbox: false,
      }),
    ).toThrow("already registered");
  });

  it("prevents registering forbidden tools", () => {
    expect(() =>
      registerTool({
        name: "forbidden-tool",
        description: "bad",
        parameters: { type: "object", properties: {}, required: [] },
        riskLevel: "forbidden",
        allowedPhases: [],
        permission: "manual_override",
        handlerRef: "x",
        maxResultSizeBytes: 0,
        requiresSandbox: false,
      }),
    ).toThrow("forbidden");
  });
});

describe("policy engine", () => {
  const scope = {
    allowedHosts: [],
    allowedServices: [],
    allowedPorts: [],
    allowedEnvironments: ["local"],
    allowedOperations: ["read"],
    restrictions: [],
    allowActiveTesting: false,
    allowNetworkAccess: false,
    allowFilesystemWrite: false,
  };

  it("allows filesystem.list in RECONNAISSANCE with automated permission", () => {
    const decision = evaluatePolicy("filesystem.list", {
      phase: "RECONNAISSANCE",
      scope,
      allowActiveTesting: false,
      allowNetworkAccess: false,
    });
    expect(decision.allowed).toBe(true);
  });

  it("denies http.request without active testing authorization", () => {
    const decision = evaluatePolicy("http.request", {
      phase: "VALIDATION",
      scope,
      allowActiveTesting: false,
      allowNetworkAccess: false,
    });
    expect(decision.allowed).toBe(false);
    expect(decision.reason).toContain("active testing");
  });

  it("allows http.request when active testing is authorized", () => {
    const decision = evaluatePolicy("http.request", {
      phase: "VALIDATION",
      scope: { ...scope, allowActiveTesting: true },
      allowActiveTesting: true,
      allowNetworkAccess: false,
    });
    expect(decision.allowed).toBe(true);
  });

  it("denies tool unavailable in current phase", () => {
    const decision = evaluatePolicy("dependencies.analyze", {
      phase: "INITIALIZATION",
      scope,
      allowActiveTesting: false,
      allowNetworkAccess: false,
    });
    expect(decision.allowed).toBe(false);
    expect(decision.reason).toContain("not available in phase");
  });

  it("denies unregistered tools", () => {
    const decision = evaluatePolicy("nonexistent.tool", {
      phase: "RECONNAISSANCE",
      scope,
      allowActiveTesting: false,
      allowNetworkAccess: false,
    });
    expect(decision.allowed).toBe(false);
    expect(decision.reason).toContain("not registered");
  });
});

describe("evidence store", () => {
  it("stores and retrieves evidence", async () => {
    // This tests InMemoryEvidenceStore indirectly via the public API
    const { InMemoryEvidenceStore } = await import("../../src/storage/evidence.js");
    const store = new InMemoryEvidenceStore();
    const record = store.create({
      findingId: null,
      type: "source",
      timestamp: new Date(),
      environment: "test",
      action: "scan",
      input: "test input",
      observedResult: { match: true },
      raw: { match: true },
    });
    expect(record.id).toBeTruthy();
    const retrieved = store.get(record.id);
    expect(retrieved).not.toBeNull();
    expect(retrieved!.id).toBe(record.id);
  });
});
