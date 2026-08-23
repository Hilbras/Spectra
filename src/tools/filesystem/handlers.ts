/**
 * Hilbras Spectra — Filesystem Tools
 *
 * Read-only file system operations on the target project.
 * No write access; used in RECONNAISSANCE and SOURCE_ANALYSIS phases.
 */

import { readdir, stat, readFile } from "node:fs/promises";
import { join } from "node:path";
import type { ToolExecutionContext, ToolOutput } from "../../investigation/runtime.js";

export async function listFiles(
  input: Record<string, unknown>,
  ctx: ToolExecutionContext,
): Promise<ToolOutput> {
  const start = Date.now();
  try {
    const baseDir = join(ctx.rootPath, String(input.path ?? "."));
    const recursive = Boolean(input.recursive);
    const includeHidden = Boolean(input.includeHidden);
    const filter = input.filter ? String(input.filter) : undefined;

    const results: Array<{ path: string; type: "file" | "dir"; size?: number }> = [];
    await _walk(baseDir, "", recursive, includeHidden, filter, results);

    return {
      success: true,
      data: { files: results, total: results.length, directory: baseDir },
      resultSize: JSON.stringify(results).length,
      durationMs: Date.now() - start,
    };
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    return { success: false, data: null, error: msg, resultSize: 0, durationMs: Date.now() - start };
  }
}

async function _walk(
  dir: string, prefix: string, recursive: boolean, includeHidden: boolean,
  filter: string | undefined, results: Array<{ path: string; type: "file" | "dir"; size?: number }>,
): Promise<void> {
  let entries;
  try { entries = await readdir(dir, { withFileTypes: true }); } catch { return; }
  for (const entry of entries) {
    if (!includeHidden && entry.name.startsWith(".")) continue;
    if (entry.name === "node_modules" || entry.name === ".git" || entry.name === "dist" || entry.name === "build") continue;
    const rel = prefix ? `${prefix}/${entry.name}` : entry.name;
    if (filter && !new RegExp(filter.replace(/\*/g, ".*")).test(rel)) continue;
    const abs = join(dir, entry.name);
    if (entry.isDirectory()) {
      results.push({ path: rel, type: "dir" });
      if (recursive) await _walk(abs, rel, true, includeHidden, filter, results);
    } else {
      const st = await stat(abs).catch(() => ({ size: 0 }));
      results.push({ path: rel, type: "file", size: st.size });
    }
  }
}

export async function readFileContent(
  input: Record<string, unknown>,
  ctx: ToolExecutionContext,
): Promise<ToolOutput> {
  const start = Date.now();
  try {
    const filePath = join(ctx.rootPath, String(input.path));
    let content = await readFile(filePath, "utf-8");
    const lineStart = Number(input.lineStart) || 1;
    const lineEnd = Number(input.lineEnd) || 0;
    const lines = content.split("\n");
    if (lineStart > 1 || lineEnd > 0) {
      const s = Math.max(1, lineStart);
      const e = lineEnd > 0 ? Math.min(lines.length, lineEnd) : lines.length;
      content = lines.slice(s - 1, e).join("\n");
    }
    return {
      success: true,
      data: { path: String(input.path), content, lineCount: lines.length, truncated: lineEnd > 0 },
      resultSize: content.length,
      durationMs: Date.now() - start,
    };
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    return { success: false, data: null, error: msg, resultSize: 0, durationMs: Date.now() - start };
  }
}
