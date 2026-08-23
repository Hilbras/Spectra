/**
 * Hilbras Spectra — Tool Registry
 *
 * Controlled tool registry: every tool has a name, schema, risk level,
 * permission gate, and execution policy. The policy engine gates every
 * AI tool request before it reaches the handler.
 */

import type { ToolParameters } from "@hilbras/sdk";
import type { ToolDefinition } from "../domain/types.js";

export const TOOL_REGISTRY = new Map<string, ToolDefinition>();

/**
 * Register a tool into the controlled registry.
 * Tools not registered cannot be invoked by the AI.
 */
export function registerTool(tool: ToolDefinition): void {
  if (TOOL_REGISTRY.has(tool.name)) {
    throw new Error(`Tool "${tool.name}" is already registered`);
  }
  if (tool.riskLevel === "forbidden") {
    throw new Error(`Cannot register a forbidden tool: ${tool.name}`);
  }
  TOOL_REGISTRY.set(tool.name, tool);
}

/** Get a registered tool definition */
export function getTool(name: string): ToolDefinition | undefined {
  return TOOL_REGISTRY.get(name);
}

/** Check whether a tool is available for the given phase */
export function isToolAvailableForPhase(
  toolName: string,
  phase: string,
): boolean {
  const tool = TOOL_REGISTRY.get(toolName);
  if (!tool) return false;
  return tool.allowedPhases.includes(phase as import("../domain/types.js").Phase);
}

/** List all registered tools */
export function listTools(): readonly ToolDefinition[] {
  return Array.from(TOOL_REGISTRY.values());
}

// ─── Built-in tool definitions ───────────────────────────────────────────────

function makeParams(properties: Record<string, { type: string; description?: string; enum?: string[] }>, required: string[]): ToolParameters {
  return { type: "object", properties, required };
}

/**
 * filesystem.list — read-only access to the target repository tree
 */
registerTool({
  name: "filesystem.list",
  description:
    "List files and directories in the target project. Read-only. Supports path filtering and glob patterns.",
  parameters: makeParams(
    {
      path: { type: "string", description: "Directory path to list (relative to project root)" },
      recursive: { type: "boolean", description: "Recursively list subdirectories" },
      includeHidden: { type: "boolean", description: "Include hidden files (.git, .env, etc.)" },
      filter: { type: "string", description: "Glob pattern to filter results" },
    },
    ["path"],
  ),
  riskLevel: "read_only",
  allowedPhases: [
    "RECONNAISSANCE",
    "ARCHITECTURE_ANALYSIS",
    "SOURCE_ANALYSIS",
    "DEPENDENCY_ANALYSIS",
    "CONFIGURATION_ANALYSIS",
    "SECRET_ANALYSIS",
  ],
  permission: "automated",
  handlerRef: "tools/filesystem/list",
  maxResultSizeBytes: 10_000_000,
  requiresSandbox: false,
});

/**
 * filesystem.read — read file contents
 */
registerTool({
  name: "filesystem.read",
  description:
    "Read the contents of a file in the target project. Read-only. Line ranges supported.",
  parameters: makeParams(
    {
      path: { type: "string", description: "File path relative to project root" },
      lineStart: { type: "number", description: "Starting line (1-based)" },
      lineEnd: { type: "number", description: "Ending line (inclusive)" },
    },
    ["path"],
  ),
  riskLevel: "read_only",
  allowedPhases: [
    "RECONNAISSANCE",
    "SOURCE_ANALYSIS",
    "SECRET_ANALYSIS",
    "CONFIGURATION_ANALYSIS",
  ],
  permission: "automated",
  handlerRef: "tools/filesystem/read",
  maxResultSizeBytes: 500_000,
  requiresSandbox: false,
});

/**
 * search.code — symbol, pattern, and content search across the repository
 */
registerTool({
  name: "search.code",
  description:
    "Search source code for symbols, patterns, imports, functions, and call sites. Uses indexed search where available.",
  parameters: makeParams(
    {
      query: { type: "string", description: "Search query (symbol name, regex, or keyword)" },
      language: { type: "string", description: "Filter by programming language" },
      scope: { type: "string", description: "Search scope", enum: ["file", "directory", "project"] },
      resultLimit: { type: "number", description: "Maximum results to return" },
    },
    ["query"],
  ),
  riskLevel: "read_only",
  allowedPhases: [
    "RECONNAISSANCE",
    "ARCHITECTURE_ANALYSIS",
    "SOURCE_ANALYSIS",
    "AUTHENTICATION_ANALYSIS",
    "AUTHORIZATION_ANALYSIS",
    "API_ANALYSIS",
    "BUSINESS_LOGIC_ANALYSIS",
  ],
  permission: "automated",
  handlerRef: "tools/search/code",
  maxResultSizeBytes: 2_000_000,
  requiresSandbox: false,
});

/**
 * ast.parse — parse a source file into an AST
 */
registerTool({
  name: "ast.parse",
  description:
    "Parse a source file into an Abstract Syntax Tree for deterministic analysis.",
  parameters: makeParams(
    {
      path: { type: "string", description: "Source file path" },
      language: { type: "string", description: "Programming language" },
    },
    ["path", "language"],
  ),
  riskLevel: "read_only",
  allowedPhases: ["SOURCE_ANALYSIS", "INVESTIGATION"],
  permission: "automated",
  handlerRef: "tools/ast/parse",
  maxResultSizeBytes: 1_000_000,
  requiresSandbox: false,
});

/**
 * callgraph.build — build a call graph from source code
 */
registerTool({
  name: "callgraph.build",
  description:
    "Build a call graph for a given function or entry point to trace data flow through the codebase.",
  parameters: makeParams(
    {
      entryPoint: { type: "string", description: "Function name, route handler, or class method" },
      language: { type: "string", description: "Programming language" },
      depth: { type: "number", description: "Max call depth to traverse" },
    },
    ["entryPoint", "language"],
  ),
  riskLevel: "read_only",
  allowedPhases: ["SOURCE_ANALYSIS", "INVESTIGATION", "VALIDATION"],
  permission: "automated",
  handlerRef: "tools/callgraph/build",
  maxResultSizeBytes: 5_000_000,
  requiresSandbox: false,
});

/**
 * taint.analyze — trace user input to sensitive operations
 */
registerTool({
  name: "taint.analyze",
  description:
    "Perform taint analysis: trace untrusted input (source) to dangerous sinks (DB queries, shell exec, template rendering).",
  parameters: makeParams(
    {
      source: { type: "string", description: "Input source (e.g., 'request.body', 'user.input')" },
      sink: { type: "string", description: "Sink category (e.g., 'sql', 'shell', 'template', 'filesystem')" },
      language: { type: "string", description: "Programming language" },
    },
    ["language"],
  ),
  riskLevel: "read_only",
  allowedPhases: ["SOURCE_ANALYSIS", "INVESTIGATION"],
  permission: "automated",
  handlerRef: "tools/taint/analyze",
  maxResultSizeBytes: 3_000_000,
  requiresSandbox: false,
});

/**
 * dependencies.analyze — analyze direct and transitive dependencies
 */
registerTool({
  name: "dependencies.analyze",
  description:
    "Analyze project dependencies: lockfiles, known CVEs, vulnerable versions, suspicious behavior, abandoned packages.",
  parameters: makeParams(
    {
      packageManager: {
        type: "string",
        description: "Package manager to analyze",
        enum: ["npm", "yarn", "pnpm", "pip", "cargo", "gomod", "maven", "gradle"],
      },
      includeTransitive: { type: "boolean", description: "Include transitive dependencies" },
    },
    ["packageManager"],
  ),
  riskLevel: "read_only",
  allowedPhases: ["DEPENDENCY_ANALYSIS", "SOURCE_ANALYSIS"],
  permission: "automated",
  handlerRef: "tools/dependencies/analyze",
  maxResultSizeBytes: 5_000_000,
  requiresSandbox: false,
});

/**
 * secrets.scan — detect exposed secrets in the repository
 */
registerTool({
  name: "secrets.scan",
  description:
    "Scan repository for API keys, tokens, passwords, private keys, and credentials using pattern detection, entropy analysis, and context analysis. Results are sanitized in output.",
  parameters: makeParams(
    {
      scope: {
        type: "string",
        description: "Scan scope",
        enum: ["full", "config_only", "source_only"],
      },
      includeGitHistory: { type: "boolean", description: "Also scan git history" },
    },
    [],
  ),
  riskLevel: "read_only",
  allowedPhases: ["SECRET_ANALYSIS", "RECONNAISSANCE"],
  permission: "automated",
  handlerRef: "tools/secrets/scan",
  maxResultSizeBytes: 1_000_000,
  requiresSandbox: false,
});

/**
 * config.analyze — analyze configuration files for security issues
 */
registerTool({
  name: "configuration.analyze",
  description:
    "Analyze configuration files (Docker, Kubernetes, Nginx, .env, CI/CD) for insecure settings, hardcoded credentials, and misconfigurations.",
  parameters: makeParams(
    {
      fileTypes: {
        type: "array",
        description: "Configuration file extensions to analyze",
      },
    },
    [],
  ),
  riskLevel: "read_only",
  allowedPhases: ["CONFIGURATION_ANALYSIS", "RECONNAISSANCE"],
  permission: "automated",
  handlerRef: "tools/configuration/analyze",
  maxResultSizeBytes: 2_000_000,
  requiresSandbox: false,
});

/**
 * api.inspect — inspect discovered API endpoints (passive only)
 */
registerTool({
  name: "api.inspect",
  description:
    "Inspect API endpoints: routes, authentication requirements, authorization checks, parameter schemas, response shapes. Passive only — no requests sent.",
  parameters: makeParams(
    {
      protocol: {
        type: "string",
        description: "Protocol to inspect",
        enum: ["rest", "graphql", "grpc", "websocket"],
      },
      pathFilter: { type: "string", description: "Path prefix to filter" },
    },
    [],
  ),
  riskLevel: "read_only",
  allowedPhases: ["API_ANALYSIS", "AUTHENTICATION_ANALYSIS", "AUTHORIZATION_ANALYSIS"],
  permission: "automated",
  handlerRef: "tools/api/inspect",
  maxResultSizeBytes: 3_000_000,
  requiresSandbox: false,
});

/**
 * http.request — make HTTP requests for active testing (sandboxed, restricted)
 */
registerTool({
  name: "http.request",
  description:
    "Make HTTP requests to authorized targets for validation. Restricted: only allows hosts, ports, and methods defined in the authorization scope. Requires sandbox isolation.",
  parameters: makeParams(
    {
      url: { type: "string", description: "Target URL" },
      method: {
        type: "string",
        description: "HTTP method",
        enum: ["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"],
      },
      headers: { type: "object", description: "Request headers" },
      body: { type: "string", description: "Request body" },
      timeoutMs: { type: "number", description: "Request timeout in milliseconds" },
    },
    ["url", "method"],
  ),
  riskLevel: "restricted",
  allowedPhases: ["INVESTIGATION", "VALIDATION"],
  permission: "request_approval",
  handlerRef: "tools/http/request",
  maxResultSizeBytes: 1_000_000,
  requiresSandbox: true,
});

/**
 * sandbox.execute — run code in an isolated disposable environment
 */
registerTool({
  name: "sandbox.execute",
  description:
    "Execute code or commands inside an isolated, disposable sandbox with filesystem/network/CPU/memory limits. Never runs on the host.",
  parameters: makeParams(
    {
      command: { type: "string", description: "Command to execute" },
      script: { type: "string", description: "Inline script to run" },
      language: { type: "string", description: "Scripting language" },
      timeoutMs: { type: "number", description: "Execution timeout" },
      memoryLimitMb: { type: "number", description: "Memory limit in MB" },
    },
    [],
  ),
  riskLevel: "sandboxed",
  allowedPhases: ["VALIDATION", "EVIDENCE_COLLECTION"],
  permission: "request_approval",
  handlerRef: "tools/sandbox/execute",
  maxResultSizeBytes: 10_000_000,
  requiresSandbox: true,
});

/**
 * diff.compare — compare two versions of a file or code section
 */
registerTool({
  name: "diff.compare",
  description:
    "Compare two versions of source code, configuration, or any text content. Useful for regression analysis and patch verification.",
  parameters: makeParams(
    {
      oldContent: { type: "string", description: "Original content" },
      newContent: { type: "string", description: "Modified content" },
      contextLines: { type: "number", description: "Context lines around changes" },
    },
    ["oldContent", "newContent"],
  ),
  riskLevel: "read_only",
  allowedPhases: ["VALIDATION", "FINDING_CORRELATION"],
  permission: "automated",
  handlerRef: "tools/diff/compare",
  maxResultSizeBytes: 1_000_000,
  requiresSandbox: false,
});

/**
 * repository.discover — discover repository structure and metadata
 */
registerTool({
  name: "repository.discover",
  description:
    "Discover repository structure: file tree, branch info, commit history, package manifests, language distribution.",
  parameters: makeParams(
    {
      depth: { type: "number", description: "How deep to traverse" },
      ignorePatterns: {
        type: "array",
        description: "Glob patterns to ignore",
      },
    },
    [],
  ),
  riskLevel: "read_only",
  allowedPhases: ["INITIALIZATION", "RECONNAISSANCE"],
  permission: "automated",
  handlerRef: "tools/repository/discover",
  maxResultSizeBytes: 5_000_000,
  requiresSandbox: false,
});
