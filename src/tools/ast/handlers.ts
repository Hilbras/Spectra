/**
 * Hilbras Spectra — AST Analysis Tools (regex-based)
 */

import type { ToolExecutionContext, ToolOutput } from "../../investigation/runtime.js";

export function parseAST(
  input: Record<string, unknown>,
  ctx: ToolExecutionContext,
): ToolOutput {
  const start = Date.now();
  try {
    const filePath = ctx.rootPath + "/" + String(input.path);
    const language = String(input.language ?? "typescript");
    let content: string;
    try {
      content = require("node:fs").readFileSync(filePath, "utf-8");
    } catch {
      return { success: false, data: null, error: `Cannot read file: ${filePath}`, resultSize: 0, durationMs: Date.now() - start };
    }
    const lines = content.split("\n");
    const functions: Array<{ name: string; line: number; params: string[] }> = [];
    const classes: Array<{ name: string; line: number; methods: string[] }> = [];
    const imports: Array<{ source: string }> = [];
    const calls: Array<{ name: string; line: number; args: string }> = [];

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i]!;
      const fnMatch = line.match(/^\s*(?:export\s+)?(?:async\s+)?function\s+(\w+)\s*\(([^)]*)\)/);
      if (fnMatch) {
        functions.push({ name: fnMatch[1]!, line: i + 1, params: fnMatch[2]!.split(",").map((p) => p.trim()).filter(Boolean) });
        continue;
      }
      const assignFn = line.match(/^\s*(?:export\s+)?(?:const|let)\s+(\w+)\s*=\s*(?:async\s*)?(?:\([^)]*\)|\w+)\s*=>/);
      if (assignFn) {
        functions.push({ name: assignFn[1]!, line: i + 1, params: [] });
        continue;
      }
      const classMatch = line.match(/^\s*(?:export\s+)?class\s+(\w+)/);
      if (classMatch) {
        const methods: string[] = [];
        for (let j = i + 1; j < Math.min(i + 30, lines.length); j++) {
          const m = lines[j]?.match(/^\s+(\w+)\s*\(/);
          if (m && !/if|for|while|return|new|throw|class|function|constructor/.test(m[1]!)) methods.push(m[1]!);
          if (lines[j]?.trim() === "}") break;
        }
        classes.push({ name: classMatch[1]!, line: i + 1, methods });
        continue;
      }
      const importMatch = line.match(/^\s*import\s+(?:.*?\s+from\s+)?['"]([^'"]+)['"]/);
      if (importMatch) imports.push({ source: importMatch[1]! });
      const callMatch = line.match(/\b(\w+)\s*\(/);
      if (callMatch && !/if|for|while|switch|return|throw|new|class|function|const|let|var|import|export|require/.test(callMatch[1]!)) {
        calls.push({ name: callMatch[1]!, line: i + 1, args: line.slice(0, 120) });
      }
    }

    return {
      success: true,
      data: { file: String(input.path), language, totalLines: lines.length, functions, classes, imports, calls },
      resultSize: JSON.stringify({ functions, classes }).length,
      durationMs: Date.now() - start,
    };
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    return { success: false, data: null, error: msg, resultSize: 0, durationMs: Date.now() - start };
  }
}

export function findCalls(
  input: Record<string, unknown>,
  ctx: ToolExecutionContext,
): ToolOutput {
  const start = Date.now();
  try {
    const funcName = String(input.function);
    const results: Array<{ caller: string; callee: string; file: string; line: number }> = [];
    const allFiles: any[] = require("node:fs").readdirSync(ctx.rootPath, { recursive: true, withFileTypes: true });
    const files = allFiles
      .filter((d: any) => d.isFile() && /\.(ts|js)$/.test(d.name))
      .map((d: any) => d.path);

    for (const file of files.slice(0, 80)) {
      try {
        const src = require("node:fs").readFileSync(ctx.rootPath + "/" + file, "utf-8");
        const lines = src.split("\n");
        for (let i = 0; i < lines.length; i++) {
          const escaped = funcName.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
          if (new RegExp("\\b" + escaped + "\\b").test(lines[i]!)) {
            const callMatch = lines[i]!.match(/\b(\w+(?:\.\w+)*)\s*\(/);
            if (callMatch) {
              results.push({ caller: funcName, callee: callMatch[1]!, file, line: i + 1 });
            }
          }
        }
      } catch { /* skip */ }
    }

    return {
      success: true,
      data: { functionName: funcName, calls: results.slice(0, 50), total: results.length },
      resultSize: JSON.stringify(results).length,
      durationMs: Date.now() - start,
    };
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    return { success: false, data: null, error: msg, resultSize: 0, durationMs: Date.now() - start };
  }
}
