/**
 * Hilbras Spectra — Route/API Discovery Tool
 *
 * Discovers HTTP routes from framework code patterns.
 * Builds an endpoint model with auth and privilege info.
 */

import type { ProjectIndex } from "../../index/index.js";
import type { ToolOutput } from "../../investigation/runtime.js";

export function inspectApi(
  input: Record<string, unknown>,
  index: ProjectIndex,
): ToolOutput {
  const start = Date.now();
  try {
    const protocol = String(input.protocol ?? "all");
    const pathFilter = String(input.pathFilter ?? "");

    let routes = index.routes;
    if (protocol !== "all") {
      // Filter by protocol hint (REST vs GraphQL vs WebSocket)
      if (protocol === "graphql") routes = routes.filter((r) => r.path.includes("graphql") || r.handler.toLowerCase().includes("graphql"));
    }
    if (pathFilter) {
      const regex = new RegExp(pathFilter.replace(/\*/g, ".*"));
      routes = routes.filter((r) => regex.test(r.path));
    }

    // Annotate each route with security metadata
    const endpoints = routes.map((r) => {
      // Check if handler references auth/role middleware
      const refLines = index.findReferences(r.handler, 5);
      const hasAuthCheck = refLines.some((l) =>
        /auth|authorize|permission|role|middleware|isAdmin|requireAuth/i.test(l.text),
      );
      // Check if path contains admin/sensitive keywords
      const sensitivity: "low" | "medium" | "high" | "critical" =
        /admin|internal|config|user.*delete|payment|refund/i.test(r.path) ? "high"
        : /api|v[0-9]/i.test(r.path) ? "medium"
        : "low";

      return {
        method: r.method,
        path: r.path,
        handler: r.handler,
        file: r.file,
        line: r.line,
        authentication: hasAuthCheck ? "likely_present" : "unknown",
        authorization: hasAuthCheck ? "present" : "missing",
        sensitivity,
        notes: r.middleware?.join(", ") || undefined,
      };
    });

    return {
      success: true,
      data: { totalEndpoints: endpoints.length, protocol, pathFilter, endpoints },
      resultSize: JSON.stringify(endpoints).length,
      durationMs: Date.now() - start,
    };
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    return { success: false, data: null, error: msg, resultSize: 0, durationMs: Date.now() - start };
  }
}
