/**
 * Hilbras Spectra — Tool Dispatcher
 *
 * Routes registered tool names to their handler implementations.
 * Every tool goes through this dispatcher after passing the policy gate.
 */

import type { ToolExecutionContext, ToolOutput } from "../investigation/runtime.js";
import { ProjectIndex } from "../index/index.js";
import * as fsHandlers from "./filesystem/handlers.js";
import * as searchHandlers from "./search/handlers.js";
import * as astHandlers from "./ast/handlers.js";
import * as taintHandlers from "./taint/handlers.js";
import * as depHandlers from "./dependencies/handlers.js";
import * as secretHandlers from "./secrets/handlers.js";
import * as configHandlers from "./config/handlers.js";
import * as routeHandlers from "./routes/handlers.js";
import { runInSandbox } from "../sandbox/executor.js";

export class ToolDispatcher {
  constructor(private readonly index: ProjectIndex) {}

  async dispatch(
    toolName: string,
    input: Record<string, unknown>,
    ctx: ToolExecutionContext,
  ): Promise<ToolOutput> {
    const root = ctx.rootPath;

    switch (toolName) {
      // ── Filesystem ────────────────────────────────────────────────────
      case "filesystem.list":
        return fsHandlers.listFiles(input, ctx);
      case "filesystem.read":
        return fsHandlers.readFileContent(input, ctx);

      // ── Search ────────────────────────────────────────────────────────
      case "search.code":
        return searchHandlers.searchText(input, this.index);

      // ── AST ───────────────────────────────────────────────────────────
      case "ast.parse":
        return astHandlers.parseAST(input, ctx);
      case "callgraph.build":
        return astHandlers.findCalls(input, ctx);

      // ── Taint ─────────────────────────────────────────────────────────
      case "taint.analyze":
        return taintHandlers.analyzeTaint(input, this.index);

      // ── Dependencies ──────────────────────────────────────────────────
      case "dependencies.analyze":
        return depHandlers.analyzeDependencies(input, ctx);

      // ── Secrets ───────────────────────────────────────────────────────
      case "secrets.scan":
        return secretHandlers.scanSecrets(input, ctx);

      // ── Configuration ─────────────────────────────────────────────────
      case "configuration.analyze":
        return configHandlers.analyzeConfig(input, ctx);

      // ── API/Routes ────────────────────────────────────────────────────
      case "api.inspect":
        return routeHandlers.inspectApi(input, this.index);

      // ── Sandbox ───────────────────────────────────────────────────────
      case "sandbox.execute": {
        const result = await runInSandbox(
          String(input.command ?? input.script ?? ""),
          {
            timeoutMs: Number(input.timeoutMs) || 10_000,
            memoryLimitMb: Number(input.memoryLimitMb) || 256,
            cpuLimit: Number(input.cpuLimit) || 0.5,
            image: String(input.image ?? "node:20-alpine"),
          },
        );
        if (result === null) {
          return { success: false, data: null, error: "Sandbox unavailable — Docker not found", resultSize: 0, durationMs: 0 };
        }
        return { success: result.success, data: result, resultSize: (result.stdout + result.stderr).length, durationMs: result.durationMs };
      }

      // ── HTTP ──────────────────────────────────────────────────────────
      case "http.request": {
        const url = String(input.url);
        const method = String(input.method ?? "GET").toUpperCase();
        const timeout = Number(input.timeoutMs) || 10_000;
        try {
          const controller = new AbortController();
          const timer = setTimeout(() => controller.abort(), timeout);
          const init: RequestInit = { method, signal: controller.signal };
          if (input.headers) (init as Record<string, unknown>).headers = input.headers as Record<string, string>;
          if (input.body) init.body = input.body as string;
          const res = await fetch(url, init);
          clearTimeout(timer);
          const body = await res.text();
          return {
            success: res.ok,
            data: { status: res.status, statusText: res.statusText, headers: Object.fromEntries(res.headers.entries()), body: body.slice(0, 5000) },
            resultSize: body.length,
            durationMs: timeout,
          };
        } catch (err) {
          const msg = err instanceof Error ? err.message : String(err);
          return { success: false, data: null, error: msg, resultSize: 0, durationMs: timeout };
        }
      }

      // ── Diff ──────────────────────────────────────────────────────────
      case "diff.compare": {
        const oldContent = String(input.oldContent ?? "");
        const newContent = String(input.newContent ?? "");
        const _ctxLines = Number(input.contextLines) || 3;
        const oldLines = oldContent.split("\n");
        const newLines = newContent.split("\n");
        const diffs: Array<{ line: number; type: "added" | "removed" | "changed"; text: string }> = [];
        const maxLen = Math.max(oldLines.length, newLines.length);
        for (let i = 0; i < maxLen; i++) {
          const old = oldLines[i] ?? "";
          const nw = newLines[i] ?? "";
          if (old !== nw) {
            if (old) diffs.push({ line: i + 1, type: "removed", text: old });
            if (nw) diffs.push({ line: i + 1, type: "added", text: nw });
          }
        }
        return { success: true, data: { diffs: diffs.slice(0, 100), totalChanges: diffs.length }, resultSize: JSON.stringify(diffs).length, durationMs: 1 };
      }

      // ── Repository ────────────────────────────────────────────────────
      case "repository.discover": {
        const _depth = Number(input.depth) || 2;
        return {
          success: true,
          data: { root: root, languages: this.index.summary.byLanguage, frameworks: this.index.frameworks, totalFiles: this.index.summary.totalFiles, totalRoutes: this.index.summary.totalRoutes },
          resultSize: 0,
          durationMs: 0,
        };
      }

      default:
        return { success: false, data: null, error: `Unknown tool: ${toolName}`, resultSize: 0, durationMs: 0 };
    }
  }
}
