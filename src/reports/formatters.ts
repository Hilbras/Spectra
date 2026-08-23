/**
 * Hilbras Spectra — Report Generators
 *
 * Generate professional security reports in JSON, SARIF, and Markdown formats.
 * Extensible design: add new formats by implementing the ReportFormatter interface.
 */

import type {
  Finding,

  ReportFormat,
  SecurityInvestigation,
} from "../domain/types.js";

export interface ReportFormatter {
  format: ReportFormat;
  generate(investigation: SecurityInvestigation, findings: Finding[]): string;
}

// ─── JSON Formatter ───────────────────────────────────────────────────────────

export class JsonReportFormatter implements ReportFormatter {
  readonly format = "json" as const;

  generate(investigation: SecurityInvestigation, findings: Finding[]): string {
    const payload = {
      schemaVersion: "1.0.0",
      product: "Hilbras Spectra",
      generatedAt: new Date().toISOString(),
      investigation: {
        id: investigation.id,
        projectId: investigation.projectId,
        status: investigation.status,
        phase: investigation.phase,
        startedAt: investigation.startedAt.toISOString(),
        completedAt: investigation.completedAt?.toISOString(),
        durationMs: Date.now() - investigation.startedAt.getTime(),
      },
      summary: buildExecutiveSummary(findings),
      findings: findings.map((f) => ({
        id: f.id,
        title: f.title,
        category: f.category,
        cwe: f.cwe,
        owasp: f.owasp,
        severity: f.severity,
        confidence: f.confidence,
        status: f.status,
        affectedComponent: f.affectedComponent,
        affectedLocation: f.affectedLocation,
        rootCause: f.rootCause,
        description: f.description,
        impact: f.impact,
        evidenceCount: f.evidenceIds.length,
        remediation: f.remediation,
        attackPath: f.attackPath,
        firstSeenAt: f.firstSeenAt.toISOString(),
        lastSeenAt: f.lastSeenAt.toISOString(),
      })),
      hypotheses: investigation.hypotheses.map((h) => ({
        id: h.id,
        category: h.category,
        target: h.target,
        claim: h.claim,
        status: h.status,
        confidence: h.confidence,
        riskLevel: h.riskLevel,
      })),
      metadata: investigation.metadata,
    };
    return JSON.stringify(payload, null, 2);
  }
}

// ─── SARIF Formatter ──────────────────────────────────────────────────────────

export class SarifReportFormatter implements ReportFormatter {
  readonly format = "sarif" as const;

  generate(_investigation: SecurityInvestigation, findings: Finding[]): string {
    const sarif: Record<string, unknown> = {
      $schema: "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
      version: "2.1.0",
      runs: [
        {
          tool: {
            driver: {
              name: "Hilbras Spectra",
              version: "0.1.0",
              rules: findings.map((f) => ({
                id: f.id,
                name: f.title,
                shortDescription: { text: f.category },
                defaultConfiguration: {
                  level: sarifLevel(f.severity),
                },
              })),
            },
          },
          results: findings.map((f) => ({
            ruleId: f.id,
            level: sarifLevel(f.severity),
            message: {
              text: `${f.description}\n\nRoot cause: ${f.rootCause}`,
            },
            locations: f.affectedLocation.file
              ? [
                  {
                    physicalLocation: {
                      artifactLocation: {
                        uri: f.affectedLocation.file,
                      },
                      region: f.affectedLocation.lineStart
                        ? {
                            startLine: f.affectedLocation.lineStart,
                            endLine: f.affectedLocation.lineEnd,
                          }
                        : undefined,
                    },
                  },
                ]
              : undefined,
            fixes: f.remediation
              ? [
                  {
                    description: { text: f.remediation.recommendedFix },
                    artifactChanges: f.remediation.affectedFiles?.map((file) => ({
                      artifactLocation: { uri: file },
                      replacements: [
                        {
                          deletedRegion: {
                            endColumn: 1,
                            endLine: 9999,
                            startColumn: 1,
                            startLine: 1,
                          },
                          insertedContent: {
                            text: (f.remediation?.proposedPatch ?? "[Apply proposed fix]") as string,
                          },
                        },
                      ],
                    })),
                  },
                ]
              : undefined,
          })),
        },
      ],
    };
    return JSON.stringify(sarif, null, 2);
  }
}

function sarifLevel(severity: string): string {
  switch (severity) {
    case "critical": return "error";
    case "high": return "error";
    case "medium": return "warning";
    case "low": return "note";
    default: return "none";
  }
}

// ─── Markdown Formatter ───────────────────────────────────────────────────────

export class MarkdownReportFormatter implements ReportFormatter {
  readonly format = "markdown" as const;

  generate(investigation: SecurityInvestigation, findings: Finding[]): string {
    const summary = buildExecutiveSummary(findings);
    const lines: string[] = [
      "# Security Audit Report",
      "",
      `**Product:** Hilbras Spectra`,
      `**Generated:** ${new Date().toISOString()}`,
      `**Project:** ${investigation.projectId}`,
      `**Status:** ${investigation.status}`,
      `**Duration:** ${investigation.completedAt ? Math.round((investigation.completedAt.getTime() - investigation.startedAt.getTime()) / 1000) : "?"}s`,
      "",
      "---",
      "",
      "## Executive Summary",
      "",
      `**Security Score:** ${summary.overallScore}/100`,
      "",
      "| Severity | Count |",
      "|----------|-------|",
      `| 🔴 Critical | ${summary.criticalCount} |`,
      `| 🟠 High | ${summary.highCount} |`,
      `| 🟡 Medium | ${summary.mediumCount} |`,
      `| 🟢 Low | ${summary.lowCount} |`,
      `| ℹ️ Informational | ${summary.informationalCount} |`,
      "",
      "### Top Risks",
      "",
      ...(summary.topRisks.map((r) => `- ${r}`).slice(0, 5)),
      "",
      "---",
      "",
      "## Findings",
      "",
    ];

    if (findings.length === 0) {
      lines.push("*No findings were identified.*\n");
    } else {
      for (const f of findings) {
        lines.push(
          `### ${severityEmoji(f.severity)} ${f.title}`,
          "",
          `- **Category:** ${f.category}`,
          `- **Severity:** ${f.severity.toUpperCase()}`,
          `- **Confidence:** ${f.confidence}`,
          `- **Status:** ${f.status}`,
          ...(f.cwe != null ? [`- **CWE:** ${f.cwe}`] : []),
          ...(f.owasp != null ? [`- **OWASP:** ${f.owasp}`] : []),
          `- **Component:** \`${f.affectedComponent}\``,
          ...(f.affectedLocation.file ? [
            `- **Location:** \`${f.affectedLocation.file}${f.affectedLocation.lineStart ? `:${f.affectedLocation.lineStart}` : ""}\``,
          ] : []),
          "",
          `**Description:** ${f.description}`,
          "",
          `**Root Cause:** ${f.rootCause}`,
          "",
          `**Impact:** ${f.impact}`,
          "",
          `**Evidence:** ${f.evidenceIds.length} record${f.evidenceIds.length !== 1 ? "s" : ""}`,
          "",
        );
        if (f.remediation) {
          lines.push(
            "#### Remediation",
            "",
            `- **Why:** ${f.remediation.whyItHappens ?? f.remediation.rootCause}`,
            `- **Fix:** ${f.remediation.recommendedFix}`,
            `- **Pattern:** ${f.remediation.securePattern}`,
            "",
          );
        }
        lines.push("---", "");
      }
    }

    if (investigation.hypotheses.length > 0) {
      lines.push(
        "## Active Hypotheses",
        "",
        ...investigation.hypotheses.map(
          (h) =>
            `- **[${h.status}]** ${h.claim} (confidence: ${(h.confidence * 100).toFixed(0)}%)`,
        ),
        "",
      );
    }

    lines.push(
      "---",
      "",
      "*Report generated by Hilbras Spectra*",
    );

    return lines.filter((l) => l !== undefined).join("\n");
  }
}

function severityEmoji(severity: string): string {
  switch (severity) {
    case "critical": return "🔴";
    case "high": return "🟠";
    case "medium": return "🟡";
    case "low": return "🟢";
    default: return "ℹ️";
  }
}

// ─── Helper ───────────────────────────────────────────────────────────────────

function buildExecutiveSummary(findings: Finding[]): {
  overallScore: number;
  criticalCount: number;
  highCount: number;
  mediumCount: number;
  lowCount: number;
  informationalCount: number;
  confirmedCount: number;
  potentialCount: number;
  topRisks: string[];
} {
  const counts = { critical: 0, high: 0, medium: 0, low: 0, informational: 0 };
  const confirmed: Finding[] = [];
  const topRisks: string[] = [];

  for (const f of findings) {
    counts[f.severity as keyof typeof counts] = (counts[f.severity as keyof typeof counts] ?? 0) + 1;
    if (f.status === "confirmed") confirmed.push(f);
    if (f.severity === "critical" || f.severity === "high") {
      topRisks.push(`${f.title} (${f.category})`);
    }
  }

  const penalty =
    counts.critical * 25 +
    counts.high * 15 +
    counts.medium * 8 +
    counts.low * 3;
  const overallScore = Math.max(0, 100 - penalty);

  return {
    overallScore,
    criticalCount: counts.critical,
    highCount: counts.high,
    mediumCount: counts.medium,
    lowCount: counts.low,
    informationalCount: counts.informational,
    confirmedCount: confirmed.length,
    potentialCount: findings.length - confirmed.length,
    topRisks: topRisks.slice(0, 5),
  };
}

// ─── Registry ─────────────────────────────────────────────────────────────────

const FORMATTERS: Record<ReportFormat, ReportFormatter> = {
  json: new JsonReportFormatter(),
  sarif: new SarifReportFormatter(),
  markdown: new MarkdownReportFormatter(),
};

/** Generate a report in the requested format */
export function generateReport(
  investigation: SecurityInvestigation,
  findings: Finding[],
  format: ReportFormat,
): string {
  const formatter = FORMATTERS[format];
  if (!formatter) {
    throw new Error(`Unknown report format: ${format}`);
  }
  return formatter.generate(investigation, findings);
}

/** List all supported report formats */
export function listFormats(): ReportFormat[] {
  return (Object.keys(FORMATTERS) as unknown as ReportFormat[]);
}
