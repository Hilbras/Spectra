/**
 * Hilbras Spectra — Project Index
 *
 * Single-pass indexed representation of a project's structure, language,
 * framework, symbols, routes, imports, and security-relevant metadata.
 * Built once at INITIALIZATION/RECONNAISSANCE; queried by all subsequent tools.
 */

import { readdir, stat, readFile } from "node:fs/promises";
import { join, extname } from "node:path";
import { createHash } from "node:crypto";

// ─── Core types ────────────────────────────────────────────────────────────────

export interface ProjectFile {
  path: string;          // relative to project root
  absolute: string;      // absolute filesystem path
  size: number;
  mtime: Date;
  language: Language;
  hash: string;          // content hash for change detection
}

export type Language =
  | "typescript"
  | "javascript"
  | "python"
  | "go"
  | "java"
  | "rust"
  | "docker"
  | "yaml"
  | "json"
  | "toml"
  | "sh"
  | "markdown"
  | "html"
  | "css"
  | "unknown";

export interface ProjectSymbol {
  name: string;
  kind: "function" | "class" | "interface" | "const" | "let" | "var" | "type" | "enum" | "method" | "import" | "export" | "middleware" | "route" | "hook" | "validator";
  file: string;
  line: number;
  column?: number;
  references?: string[]; // names referenced in body
}

export interface ProjectRoute {
  method: string;
  path: string;
  handler: string;
  file: string;
  line: number;
  authRequired?: boolean;
  middleware: string[];
}

export interface Dependency {
  name: string;
  version: string;
  resolved?: string;
  path?: string; // where declared (package.json path)
  isDev?: boolean;
}

export interface FrameworkDetection {
  name?: string;       // e.g. "express", "fastify", "next"
  version?: string;
  authLibrary?: string; // e.g. "jsonwebtoken", "passport"
  dbLibrary?: string;   // e.g. "mongoose", "prisma", "typeorm"
  testFramework?: string;
}

// ─── ProjectIndex class ───────────────────────────────────────────────────────

export class ProjectIndex {
  readonly rootPath: string;
  readonly files = new Map<string, ProjectFile>();
  readonly symbols: ProjectSymbol[] = [];
  readonly routes: ProjectRoute[] = [];
  readonly dependencies: Dependency[] = [];
  readonly frameworks: FrameworkDetection = {};
  readonly ignoredPatterns = new Set<string>([
    "node_modules", "dist", "build", ".git", ".next", ".nuxt", "coverage",
    ".turbo", ".cache", "vendor", "__pycache__", ".DS_Store", "*.log",
    "pnpm-lock.yaml", "package-lock.json", "yarn.lock", "bun.lockb",
  ]);

  constructor(rootPath: string) {
    this.rootPath = rootPath.replace(/\/$/, "");
  }

  /** Scan the entire project tree once — call this at project intake */
  async scan(): Promise<this> {
    await this._walkDir(this.rootPath, "");
    this._detectFrameworks();
    this._scanPackageFiles();
    this._parseSymbols();
    return this;
  }

  // ─── File discovery ──────────────────────────────────────────────────────

  async _walkDir(dir: string, relPrefix: string): Promise<void> {
    let entries: Array<{ name: string; isDir: boolean }>;
    try {
      const raw = await readdir(dir, { withFileTypes: true });
      entries = raw.map((e) => ({ name: e.name, isDir: e.isDirectory() }));
    } catch {
      return; // permission denied or doesn't exist
    }

    for (const entry of entries) {
      const rel = relPrefix ? `${relPrefix}/${entry.name}` : entry.name;
      const abs = join(dir, entry.name);

      if (entry.isDir) {
        if (this._isIgnored(entry.name)) continue;
        await this._walkDir(abs, rel);
        continue;
      }

      const lang = this._detectLanguage(rel);
      if (lang === "unknown") continue; // skip non-code files for symbol analysis

      let content: string;
      try {
        content = await readFile(abs, "utf-8");
      } catch {
        continue;
      }

      const hash = createHash("sha256").update(content).digest("hex").slice(0, 16);
      const statResult = await stat(abs).catch(() => ({ size: 0, mtime: new Date() }));

      this.files.set(rel, {
        path: rel,
        absolute: abs,
        size: statResult.size,
        mtime: statResult.mtime,
        language: lang,
        hash,
      });
    }
  }

  _isIgnored(name: string): boolean {
    for (const pat of this.ignoredPatterns) {
      if (pat === name) return true;
      if (pat.startsWith("*") && name.endsWith(pat.slice(1))) return true;
    }
    return false;
  }

  _detectLanguage(path: string): Language {
    const ext = extname(path).toLowerCase();
    const base = path.split("/").pop()?.toLowerCase() ?? "";
    if (ext === ".ts" || ext === ".tsx") return "typescript";
    if (ext === ".js" || ext === ".jsx") return "javascript";
    if (ext === ".py") return "python";
    if (ext === ".go") return "go";
    if (ext === ".java") return "java";
    if (ext === ".rs") return "rust";
    if (base === "dockerfile") return "docker";
    if (ext === ".yml" || ext === ".yaml") return "yaml";
    if (ext === ".json") return "json";
    if (ext === ".toml") return "toml";
    if (ext === ".sh") return "sh";
    if (ext === ".md") return "markdown";
    if (ext === ".html") return "html";
    if (ext === ".css" || ext === ".scss" || ext === ".less") return "css";
    return "unknown";
  }

  // ─── Framework / package detection ────────────────────────────────────────

  _scanPackageFiles(): void {
    for (const [rel, file] of this.files) {
      if (!rel.endsWith("package.json") && !rel.endsWith("go.mod") && !rel.endsWith("Cargo.toml")) continue;
      try {
        const content = file.path.endsWith("package.json")
          ? JSON.parse(require("node:fs").readFileSync(file.absolute, "utf-8"))
          : null;
        if (!content) continue;
        const allDeps = { ...content.dependencies, ...content.devDependencies };
        for (const [name, ver] of Object.entries(allDeps)) {
          this.dependencies.push({
            name,
            version: typeof ver === "string" ? ver : String(ver),
            isDev: !!(content.devDependencies?.[name]),
            path: rel,
          });
        }
      } catch { /* malformed manifest, ignore */ }
    }
  }

  _detectFrameworks(): void {
    const depNames = new Set(this.dependencies.map((d) => d.name));
    const fileContents = new Map<string, string>();
    for (const [, file] of this.files) {
      try { fileContents.set(file.path, require("node:fs").readFileSync(file.absolute, "utf-8")); } catch { /* skip */ }
    }

    if (depNames.has("express") || depNames.has("@fastify/fastify")) {
      this.frameworks.name = depNames.has("@fastify/fastify") ? "fastify" : "express";
      this.frameworks.version = this.dependencies.find((d) => d.name === "express" || d.name === "@fastify/fastify")?.version ?? "";
    }
    if (depNames.has("next")) { this.frameworks.name = "next"; this.frameworks.version = this.dependencies.find((d) => d.name === "next")?.version ?? ""; }
    if (depNames.has("nestjs")) { this.frameworks.name = "nestjs"; this.frameworks.version = this.dependencies.find((d) => d.name === "@nestjs/core")?.version ?? ""; }
    if (depNames.has("koa")) { this.frameworks.name = "koa"; }
    if (depNames.has("hono")) { this.frameworks.name = "hono"; }

    // Auth libraries
    for (const name of ["jsonwebtoken", "jose", "passports", "auth0", "firebase-admin", "aws-sdk", "aws-cdk"]) {
      if (depNames.has(name) || [...depNames].some((d) => d.includes(name))) {
        this.frameworks.authLibrary = name; break;
      }
    }
    // DB libraries
    for (const name of ["mongoose", "sequelize", "prisma", "typeorm", "drizzle-orm", "better-sqlite3", "pg", "mysql2"]) {
      if (depNames.has(name)) { this.frameworks.dbLibrary = name; break; }
    }
    // Test frameworks
    for (const name of ["vitest", "jest", "mocha", "playwright", "cypress"]) {
      if (depNames.has(name)) { this.frameworks.testFramework = name; break; }
    }
  }

  // ─── Symbol & route parsing (regex-based for speed; AST fallback below) ──

  _parseSymbols(): void {
    for (const [rel, file] of this.files) {
      if (!["typescript", "javascript"].includes(file.language)) continue;
      const content = require("node:fs").readFileSync(file.absolute, "utf-8");
      this._parseJsSymbols(rel, content, file.language === "typescript" ? "ts" : "js");
      this._parseRoutes(rel, content);
    }
  }

  _parseJsSymbols(fileRel: string, content: string, _ext: "ts" | "js"): void {
    const lines = content.split("\n");
    // Functions
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i]!;
      // function declarations
      const fnMatch = line.match(/^\s*(?:export\s+)?(?:async\s+)?function\s+(\w+)/);
      if (fnMatch) {
        this.symbols.push({ name: fnMatch[1]!, kind: "function", file: fileRel, line: i + 1, references: [] });
        continue;
      }
      // arrow/function expressions assigned to const/let
      const assignFn = line.match(/^\s*(?:export\s+)?(?:const|let)\s+(\w+)\s*=\s*(?:async\s*)?(?:\([^)]*\)|\w+)\s*=>/);
      if (assignFn) {
        this.symbols.push({ name: assignFn[1]!, kind: "function", file: fileRel, line: i + 1, references: [] });
        continue;
      }
      // class declarations
      const classMatch = line.match(/^\s*(?:export\s+)?class\s+(\w+)/);
      if (classMatch) {
        this.symbols.push({ name: classMatch[1]!, kind: "class", file: fileRel, line: i + 1, references: [] });
        continue;
      }
      // imports
      const importMatch = line.match(/^\s*import\s+.*?\s+from\s+['"]([^'"]+)['"]/);
      if (importMatch) {
        this.symbols.push({ name: `import:${importMatch[1]!}`, kind: "import", file: fileRel, line: i + 1, references: [] });
      }
      // middleware registration
      const mwMatch = line.match(/\.(get|post|put|delete|patch|use)\s*\(\s*["']/);
      if (mwMatch) {
        this.symbols.push({ name: `middleware:${mwMatch[1]!}`, kind: "middleware", file: fileRel, line: i + 1, references: [] });
      }
    }
  }

  _parseRoutes(fileRel: string, content: string): void {
    const lines = content.split("\n");
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i]!;
      // Express/Fastify style: app.get('/path', ...)  or router.post('/path', ...)
      const routeMatch = line.match(/\.(get|post|put|delete|patch|head|options|use)\s*\(\s*['"]([^'"]+)['"]/);
      if (routeMatch) {
        const method = routeMatch[1]!.toUpperCase();
        const path = routeMatch[2]!;
        // Find the handler name on the same or nearby lines
        const nearby = lines.slice(Math.max(0, i - 2), Math.min(lines.length, i + 5)).join("\n");
        const handlerMatch = nearby.match(/(?:function\s+(\w+)|(\w+)\s*=>|(\w+)\s*\()/) ?? [];
        const handler = handlerMatch[1] ?? handlerMatch[2] ?? handlerMatch[3] ?? "anonymous";
        this.routes.push({ method, path, handler, file: fileRel, line: i + 1, middleware: [] });
      }
    }
  }

  // ─── Query APIs ────────────────────────────────────────────────────────────

  /** Files matching a glob-like pattern (supports *, ? prefixes) */
  findFiles(pattern: string): ProjectFile[] {
    const regex = this._globToRegex(pattern);
    return Array.from(this.files.values()).filter((f) => regex.test(f.path));
  }

  /** Exact file lookup */
  getFile(path: string): ProjectFile | null {
    return this.files.get(path) ?? null;
  }

  /** Get file content by relative path */
  async readFileContent(path: string): Promise<string | null> {
    const file = this.files.get(path);
    if (!file) return null;
    try { return await readFile(file.absolute, "utf-8"); } catch { return null; }
  }

  /** Search text across all files */
  searchText(query: string, limit = 50): Array<{ file: string; line: number; text: string }> {
    const results: Array<{ file: string; line: number; text: string }> = [];
    const lowerQuery = query.toLowerCase();
    for (const [rel, file] of this.files) {
      try {
        const content = require("node:fs").readFileSync(file.absolute, "utf-8");
        const lines = content.split("\n");
        for (let i = 0; i < lines.length; i++) {
          if (lines[i]!.toLowerCase().includes(lowerQuery)) {
            results.push({ file: rel, line: i + 1, text: lines[i]!.trim() });
            if (results.length >= limit) return results;
          }
        }
      } catch { /* skip unreadable */ }
    }
    return results;
  }

  /** Regex search across all files */
  searchRegex(pattern: string, limit = 50): Array<{ file: string; line: number; text: string }> {
    const results: Array<{ file: string; line: number; text: string }> = [];
    let re: RegExp;
    try { re = new RegExp(pattern, "i"); } catch { return []; }
    for (const [rel, file] of this.files) {
      try {
        const content = require("node:fs").readFileSync(file.absolute, "utf-8");
        const lines = content.split("\n");
        for (let i = 0; i < lines.length; i++) {
          if (re.test(lines[i]!)) {
            results.push({ file: rel, line: i + 1, text: lines[i]!.trim() });
            if (results.length >= limit) return results;
          }
        }
      } catch { /* skip */ }
    }
    return results;
  }

  /** Find symbols by name */
  findSymbol(name: string): ProjectSymbol[] {
    const lower = name.toLowerCase();
    return this.symbols.filter((s) => s.name.toLowerCase().includes(lower));
  }

  /** Find all references to a symbol name (imports, usages) */
  findReferences(symbolName: string, limit = 20): Array<{ file: string; line: number; text: string }> {
    const results: Array<{ file: string; line: number; text: string }> = [];
    for (const [rel, file] of this.files) {
      try {
        const content = require("node:fs").readFileSync(file.absolute, "utf-8");
        const lines = content.split("\n");
        const regex = new RegExp(`\\b${this._escapeRegex(symbolName)}\\b`);
        for (let i = 0; i < lines.length; i++) {
          if (regex.test(lines[i]!)) {
            results.push({ file: rel, line: i + 1, text: lines[i]!.trim() });
            if (results.length >= limit) return results;
          }
        }
      } catch { /* skip */ }
    }
    return results;
  }

  /** SQL injection source→sink pairs: find user input reaching database calls */
  findTaintPaths(
    sourceKeyword: string = "request",
    sinkKeywords: string[] = ["query(", "execute(", "prepare(", "`", "${"],
  ): Array<{ source: { file: string; line: number }; sink: { file: string; line: number }; link: string }> {
    const paths: Array<{ source: { file: string; line: number }; sink: { file: string; line: number }; link: string }> = [];
    for (const [rel, file] of this.files) {
      if (!["typescript", "javascript", "python", "go"].includes(file.language)) continue;
      try {
        const content = require("node:fs").readFileSync(file.absolute, "utf-8");
        const lines = content.split("\n");
        let sourceLine = -1;
        for (let i = 0; i < lines.length; i++) {
          if (new RegExp(sourceKeyword, "i").test(lines[i]!)) sourceLine = i + 1;
          for (const sink of sinkKeywords) {
            if (lines[i]?.includes(sink) && sourceLine > 0) {
              paths.push({
                source: { file: rel, line: sourceLine },
                sink: { file: rel, line: i + 1 },
                link: lines[i]?.trim().slice(0, 120) ?? "",
              });
            }
          }
        }
      } catch { /* skip */ }
    }
    return paths;
  }

  /** Commands with subprocess execution */
  findCommandSinks(): Array<{ file: string; line: number; code: string }> {
    const results: Array<{ file: string; line: number; code: string }> = [];
    const patterns = [/execSync|exec\(|spawnSync|spawn\(|system\(|popen|os\.system|subprocess\./i];
    for (const [rel, file] of this.files) {
      try {
        const content = require("node:fs").readFileSync(file.absolute, "utf-8");
        const lines = content.split("\n");
        for (let i = 0; i < lines.length; i++) {
          if (patterns.some((p) => p.test(lines[i]!))) {
            results.push({ file: rel, line: i + 1, code: lines[i]!.trim().slice(0, 200) });
          }
        }
      } catch { /* skip */ }
    }
    return results;
  }

  /** Files containing potential secrets (high-entropy strings, known patterns) */
  findPotentialSecrets(): Array<{ file: string; line: number; pattern: string }> {
    const results: Array<{ file: string; line: number; pattern: string }> = [];
    const patterns = [
      { name: "api_key", regex: /(?:api[_-]?key|apikey)\s*[:=]\s*["']?[A-Za-z0-9]{16,}/i },
      { name: "secret", regex: /(?:secret|passwd|password|pwd)\s*[:=]\s*["']?[^\s"{']{8,}/i },
      { name: "token", regex: /(?:token|access_token|auth_token)\s*[:=]\s*["']?[A-Za-z0-9._-]{20,}/i },
      { name: "private_key", regex: /-----BEGIN\s+(RSA\s+)?PRIVATE\s+KEY-----/ },
      { name: "aws_key", regex: /(?:AKIA|ASIA)[A-Z0-9]{16}/ },
      { name: "db_conn", regex: /(?:mongodb|postgres|mysql|redis):\/\/[^\s"']+/i },
    ];
    for (const [rel, file] of this.files) {
      if (file.path.includes("node_modules") || file.path.includes(".git")) continue;
      try {
        const content = require("node:fs").readFileSync(file.absolute, "utf-8");
        const lines = content.split("\n");
        for (let i = 0; i < lines.length; i++) {
          for (const pat of patterns) {
            if (pat.regex.test(lines[i]!)) {
              results.push({ file: rel, line: i + 1, pattern: pat.name });
              break;
            }
          }
        }
      } catch { /* skip */ }
    }
    return results;
  }

  // ─── Utilities ─────────────────────────────────────────────────────────────

  _globToRegex(pattern: string): RegExp {
    const esc = pattern.replace(/[.+?^${}()|[\]\\]/g, "\\$&");
    const regex = esc.replace(/\\\*/g, ".*").replace(/\\\?/g, ".");
    return new RegExp(`^${regex}$`);
  }

  _escapeRegex(str: string): string {
    return str.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  }

  /** Summary stats for the AI context */
  get summary(): {
    totalFiles: number;
    byLanguage: Record<Language, number>;
    totalRoutes: number;
    totalSymbols: number;
    totalDeps: number;
    frameworks: FrameworkDetection;
  } {
    const byLang: Record<Language, number> = {
      typescript: 0, javascript: 0, python: 0, go: 0, java: 0, rust: 0,
      docker: 0, yaml: 0, json: 0, toml: 0, sh: 0, markdown: 0, html: 0, css: 0, unknown: 0,
    };
    for (const f of this.files.values()) byLang[f.language]++;
    return {
      totalFiles: this.files.size,
      byLanguage: byLang,
      totalRoutes: this.routes.length,
      totalSymbols: this.symbols.length,
      totalDeps: this.dependencies.length,
      frameworks: { ...this.frameworks },
    };
  }
}
