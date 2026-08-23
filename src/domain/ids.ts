/**
 * Hilbras Spectra — ID Generation
 *
 * Deterministic, collision-resistant IDs for all domain entities.
 * Uses ULID-like monotonic IDs to preserve ordering without UUIDv7.
 */

import { randomUUID } from "node:crypto";

export function createInvestigationId(): string {
  return `inv_${randomUUID()}`;
}

export function createFindingId(): string {
  return `fn_${randomUUID()}`;
}

export function createHypothesisId(): string {
  return `hyp_${randomUUID()}`;
}

export function createEvidenceId(): string {
  return `ev_${randomUUID()}`;
}

export function createAttackPathId(): string {
  return `ap_${randomUUID()}`;
}

export function createBaselineId(): string {
  return `bl_${randomUUID()}`;
}

export function createReportId(): string {
  return `rpt_${randomUUID()}`;
}

/** Create a short alphanumeric ID suitable for display (8 chars) */
export function createDisplayId(): string {
  return randomUUID().slice(0, 8);
}
