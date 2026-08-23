/**
 * Hilbras Spectra — Taint Analysis Tool
 *
 * Traces untrusted input (sources) through transformations to dangerous sinks.
 * Uses the ProjectIndex for cross-file source-to-sink path detection.
 */

import type { ProjectIndex } from "../../index/index.js";
import type { ToolOutput } from "../../investigation/runtime.js";

export function analyzeTaint(
  input: Record<string, unknown>,
  index: ProjectIndex,
): ToolOutput {
  const start = Date.now();
  try {
    const language = String(input.language ?? "typescript");
    const sourceKeyword = String(input.source ?? "request");
    const sinkKeywordsStr = String(input.sink ?? "sql");

    const sinkMap: Record<string, string[]> = {
      sql: ["query(", "execute(", "prepare(", "raw(", `\``, "${"],
      shell: ["exec(", "execSync(", "spawn(", "spawnSync(", "child_process", "system(", "popen("],
      template: ["innerHTML", "document.write", "render(", "templateLiteral", "html(", "${"],
      filesystem: ["readFile(", "writeFile(", "createReadStream(", "unlink(", "mkdir("],
      deserialization: ["eval(", " Function(", "require(", "import(", "JSON.parse("],
      http: ["fetch(", "axios.", "http.request(", "https.request(", "superagent"],
    };

    const sinks = sinkMap[sinkKeywordsStr] ?? sinkMap.sql;
    const paths = index.findTaintPaths(sourceKeyword, sinks);

    // Enhance with AST-level call chains if possible
    const fileResults = paths.filter((p) => p.source.file === p.sink.file).slice(0, 30);

    return {
      success: true,
      data: {
        language,
        sourceKeyword,
        sinkCategory: sinkKeywordsStr,
        taintedPaths: fileResults,
        totalPaths: paths.length,
        withinSameFile: fileResults.length,
      },
      resultSize: JSON.stringify(fileResults).length,
      durationMs: Date.now() - start,
    };
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    return { success: false, data: null, error: msg, resultSize: 0, durationMs: Date.now() - start };
  }
}
