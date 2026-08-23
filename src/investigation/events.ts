/**
 * Hilbras Spectra — Investigation Event Stream
 *
 * Structured observability for every investigation step.
 * UI and CI consume these events for live progress and replay.
 */

export type InvestigationEventType =
  | "investigation.started"
  | "investigation.paused"
  | "investigation.resumed"
  | "investigation.completed"
  | "investigation.failed"
  | "phase.changed"
  | "hypothesis.created"
  | "hypothesis.updated"
  | "hypothesis.rejected"
  | "tool.requested"
  | "tool.denied"
  | "tool.executed"
  | "tool.failed"
  | "evidence.created"
  | "finding.created"
  | "finding.confirmed"
  | "finding.promoted"
  | "checkpoint.saved";

export interface InvestigationEvent {
  timestamp: Date;
  type: InvestigationEventType;
  /** Human-readable summary (for UI display) */
  summary: string;
  /** Structured payload (for programmatic consumption) */
  payload: Record<string, unknown>;
}

export class InvestigationEventStream {
  private readonly listeners = new Map<string, Set<(event: InvestigationEvent) => void>>();
  private readonly history: InvestigationEvent[] = [];

  /** Subscribe to events of a specific type (or all if no type given) */
  on(eventType: string, listener: (event: InvestigationEvent) => void): () => void {
    const key = eventType ?? "*";
    if (!this.listeners.has(key)) this.listeners.set(key, new Set());
    this.listeners.get(key)!.add(listener);
    return () => this.off(key, listener);
  }

  /** Unsubscribe */
  off(eventType: string, listener: (event: InvestigationEvent) => void): void {
    const set = this.listeners.get(eventType);
    set?.delete(listener);
  }

  /** Emit an event and broadcast to subscribers */
  emit(event: InvestigationEvent): void {
    this.history.push(event);
    for (const listener of this.listeners.get("*") ?? []) {
      try { listener(event); } catch { /* isolated listeners */ }
    }
    for (const listener of this.listeners.get(event.type) ?? []) {
      try { listener(event); } catch { /* isolated listeners */ }
    }
  }

  /** Get the full event history (for replay/debugging) */
  getHistory(): ReadonlyArray<InvestigationEvent> {
    return this.history;
  }

  /** Get events since a given index */
  getSince(index: number): InvestigationEvent[] {
    return this.history.slice(index);
  }

  /** Number of events emitted so far */
  get length(): number {
    return this.history.length;
  }
}

/** Factory for creating structured investigation events */
export function evt(
  type: InvestigationEventType,
  summary: string,
  payload: Record<string, unknown> = {},
): InvestigationEvent {
  return { timestamp: new Date(), type, summary, payload };
}
