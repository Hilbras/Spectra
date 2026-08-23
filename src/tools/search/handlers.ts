/**
 * Hilbras Spectra — Search Tools
 *
 * Text, regex, and symbol search across the indexed project.
 */

import type { ProjectIndex } from "../../index/index.js";
import type { ToolOutput } from "../../investigation/runtime.js";

export function searchText(
  input: Record<string, unknown>,
  index: ProjectIndex,
): ToolOutput {
  const start = Date.now();
  try {
    const query = String(input.query);
    const limit = Number(input.resultLimit) || 30;
    const results = index.searchText(query, limit);
    return {
      success: true,
      data: { query, matches: results, total: results.length },
      resultSize: JSON.stringify(results).length,
      durationMs: Date.now() - start,
    };
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    return { success: false, data: null, error: msg, resultSize: 0, durationMs: Date.now() - start };
  }
}

export function searchRegex(
  input: Record<string, unknown>,
  index: ProjectIndex,
): ToolOutput {
  const start = Date.now();
  try {
    const pattern = String(input.query);
    const limit = Number(input.resultLimit) || 30;
    const results = index.searchRegex(pattern, limit);
    return {
      success: true,
      data: { pattern, matches: results, total: results.length },
      resultSize: JSON.stringify(results).length,
      durationMs: Date.now() - start,
    };
  } catch {
    return { success: false, data: null, error: "Invalid regex pattern", resultSize: 0, durationMs: Date.now() - start };
  }
}

export function searchSymbol(
  input: Record<string, unknown>,
  index: ProjectIndex,
): ToolOutput {
  const start = Date.now();
  try {
    const name = String(input.query);
    const symbols = index.findSymbol(name);
    const references = index.findReferences(name, 30);
    return {
      success: true,
      data: { symbol: name, definitions: symbols, references: references.slice(0, 20), totalDefs: symbols.length },
      resultSize: JSON.stringify(symbols).length + JSON.stringify(references).length,
      durationMs: Date.now() - start,
    };
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    return { success: false, data: null, error: msg, resultSize: 0, durationMs: Date.now() - start };
  }
}
