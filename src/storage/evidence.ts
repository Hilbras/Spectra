/**
 * Hilbras Spectra — Evidence System
 *
 * Collect, store, and retrieve evidence with immutability guarantees.
 * Sensitive values are masked before storage or display.
 */

import type { Evidence, EvidenceId, FindingId } from "../domain/types.js";
import { maskSensitiveValues } from "../policies/engine.js";

export interface EvidenceStore {
  get(id: EvidenceId): Evidence | null;
  list(filter?: EvidenceFilter): Evidence[];
  create(evidence: Omit<Evidence, "id" | "sanitized">): Evidence;
  linkToFinding(evidenceId: EvidenceId, findingId: FindingId): boolean;
  hash(content: string): Promise<string>;
}

export interface EvidenceFilter {
  findingId?: FindingId;
  type?: string;
  since?: Date;
  environment?: string;
}

export class InMemoryEvidenceStore implements EvidenceStore {
  private readonly store = new Map<EvidenceId, Evidence>();

  get(id: EvidenceId): Evidence | null {
    return this.store.get(id) ?? null;
  }

  list(filter?: EvidenceFilter): Evidence[] {
    let results = Array.from(this.store.values());
    if (filter) {
      if (filter.findingId) {
        results = results.filter((e) => e.findingId === filter.findingId);
      }
      if (filter.type) {
        results = results.filter((e) => e.type === filter.type);
      }
      if (filter.since) {
        results = results.filter((e) => e.timestamp >= filter.since!);
      }
      if (filter.environment) {
        results = results.filter((e) => e.environment === filter.environment);
      }
    }
    return results;
  }

  create(evidence: Omit<Evidence, "id" | "sanitized">): Evidence {
    const id = crypto.randomUUID() as EvidenceId;
    const sanitized = sanitizeForStorage(evidence);
    const record: Evidence = {
      ...evidence,
      id,
      sanitized,
    };
    this.store.set(id, record);
    return record;
  }

  linkToFinding(evidenceId: EvidenceId, findingId: FindingId): boolean {
    const record = this.store.get(evidenceId);
    if (!record) return false;
    record.findingId = findingId;
    this.store.set(evidenceId, record);
    return true;
  }

  async hash(content: string): Promise<string> {
    const encoder = new TextEncoder();
    const data = encoder.encode(content);
    const buf = await crypto.subtle.digest("SHA-256", data);
    return Array.from(new Uint8Array(buf))
      .map((b) => b.toString(16).padStart(2, "0"))
      .join("");
  }
}

/**
 * Sanitize evidence before storage/display.
 * Masks secrets, truncates large fields, preserves structure.
 */
function sanitizeForStorage(evidence: Omit<Evidence, "id" | "sanitized">): import("../domain/types.js").SanitizedEvidence {
  return {
    input: truncate(toSafeString(evidence.input), 5000),
    observedResult: truncate(toSafeString(evidence.observedResult), 5000),
    action: evidence.action,
    type: evidence.type,
  };
}

function toSafeString(value: unknown): string {
  if (typeof value === "string") return maskSensitiveValues(value) as string;
  if (value == null) return "";
  return JSON.stringify(maskSensitiveValues(value));
}

function truncate(text: string, maxLen: number): string {
  if (!text) return text;
  if (text.length <= maxLen) return text;
  return text.slice(0, maxLen) + `\n… (truncated, original ${text.length} chars)`;
}
