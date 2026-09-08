import { canonicalize, taggedSha256Hex } from "./hash.js";
import type { Core } from "./core.js";

/**
 * The append-only event log: what happened, in order, hash-chained.
 *
 * Whitepaper Section 6, "Seal": everything gets sealed, drafts and rejections
 * included, and the log is append-only. Whitepaper Section 6, "Validate":
 * anyone can verify offline that an event existed and has not changed, so each
 * event carries a hash over its own fields plus the hash of the event before
 * it. Rewriting any earlier event breaks every hash after it.
 *
 * This module is pure: no I/O, no storage, and no clock. The caller supplies
 * `at` from the injected clock. Status and every derived field are recomputed
 * from these events elsewhere (src/derive.ts); nothing here is ever set
 * directly on an entry.
 */

/**
 * Domain-separation tag for the event hash. A format constant, not a policy
 * number: it names the hash construction, so an event hash can never be
 * replayed as an entry hash.
 */
export const HASH_TAG_EVENT = "nomankind-event-v1";

/** Approver record exactly as the schema's approvers[] item (M3 treats it as opaque). */
export type ApproverRecord = {
  agent: string;
  operator: string;
  decision: "approve" | "reject";
  reason?: string | null;
  snapshot_hash?: string | null;
  assigned_random: boolean;
  test_accepted?: boolean | null;
  reproduction?: Record<string, unknown> | null;
  observation?: Record<string, unknown> | null;
  signed_at: string;
};

/** Reconfirmation record exactly as the schema's reconfirmations[] item. */
export type ReconfirmationRecord = {
  agent: string;
  operator: string;
  snapshot_hash: string;
  reproduction: Record<string, unknown> | null;
  observation: Record<string, unknown> | null;
  signed_at: string;
};

/**
 * The provider-independence attestation an operator signs to register.
 *
 * Whitepaper Section 10, Governance and legal posture: "registration requires a
 * signed attestation that no model provider holds control or a beneficial
 * stake". Section 11 names signing it as the third joining step. The text and
 * the signing bytes are src/registry.ts's; the event carries only what was
 * signed, so an offline reader can recheck it years later.
 */
export type Attestation = {
  version: string;
  signed_at: string;
  signature: string;
};

/** The payload shape carried by each event type. */
export type EventPayloads = {
  operator_registered: { operator: string; maintainer: boolean };
  operator_trusted: { operator: string };
  operator_untrusted: { operator: string };
  /**
   * An agent key bound to the operator that answers for it. Section 5: "Every
   * agent belongs to an operator", and Section 11: "The binding is then sealed
   * into nomankind's log and you can validate."
   */
  agent_bound: { operator: string; agent: string; attestation: Attestation };
  /** Sorted trusted pool at this position in the log (M4 draws assignments from it). */
  pool_snapshot: { operators: string[] };
  /** The sealed submission: the immutable core and the author's signature over it. */
  entry_submitted: { core: Core; signature: string };
  assignment: {
    agent: string;
    operator: string;
    beacon_round: number;
    deadline: string;
    replacement: boolean;
  };
  assignment_missed: { agent: string; operator: string };
  /**
   * A validator's decision. The signature travels on the event, not inside the
   * record, because the schema's approvers[] item has no field for it.
   */
  validation: { record: ApproverRecord; signature: string };
  reconfirmation: { record: ReconfirmationRecord; signature: string };
  /** Recorded on the overturned entry; M20 refines the dispute rules. */
  dispute_upheld: { correction_entry_id: string };
};

export type EventType = keyof EventPayloads;

/** Every event type, in the declared order. */
export const EVENT_TYPES: readonly EventType[] = [
  "operator_registered",
  "operator_trusted",
  "operator_untrusted",
  "agent_bound",
  "pool_snapshot",
  "entry_submitted",
  "assignment",
  "assignment_missed",
  "validation",
  "reconfirmation",
  "dispute_upheld",
] as const;

/**
 * Events scoped to an entry carry entry_id; the operator and pool events carry
 * null. Whitepaper Section 6: an entry's lifecycle is the sub-sequence of the
 * log bearing its id, so the scope must be unambiguous for every event.
 */
export const ENTRY_SCOPED_TYPES: readonly EventType[] = [
  "entry_submitted",
  "assignment",
  "assignment_missed",
  "validation",
  "reconfirmation",
  "dispute_upheld",
] as const;

export type Event<T extends EventType = EventType> = {
  /** 0 for the first event, then previous + 1. */
  seq: number;
  /** ISO 8601 date-time supplied by the caller from the injected clock. */
  at: string;
  type: T;
  entry_id: string | null;
  payload: EventPayloads[T];
  /** null for seq 0, else the previous event's hash. */
  prev_hash: string | null;
  /** "sha256:" + hex of the tagged digest over the canonical form of the fields above. */
  hash: string;
};

export type EventInput<T extends EventType = EventType> = {
  at: string;
  type: T;
  entry_id: string | null;
  payload: EventPayloads[T];
};

const EVENT_TYPE_SET = new Set<string>(EVENT_TYPES);
const ENTRY_SCOPED_SET = new Set<string>(ENTRY_SCOPED_TYPES);

/**
 * The event hash: the tagged SHA-256 over the JCS canonical form of the
 * event's fields without the hash itself, prefixed "sha256:" to match the
 * schema's hash pattern (^sha256:[0-9a-f]{64}$). Canonical JSON makes the hash
 * independent of key order, so an offline verifier reaches the same digest.
 */
export async function eventHash(fields: Omit<Event, "hash">): Promise<string> {
  const canonical = canonicalize({
    seq: fields.seq,
    at: fields.at,
    type: fields.type,
    entry_id: fields.entry_id,
    payload: fields.payload,
    prev_hash: fields.prev_hash,
  });
  const digest = await taggedSha256Hex(HASH_TAG_EVENT, canonical);
  return `sha256:${digest}`;
}

/**
 * Structural checks only: the type is known, the entry_id scope rule holds,
 * and a submission's entry_id names the core it seals. Payload internals
 * belong to derivation (src/derive.ts) and M4, not here.
 */
function checkInput(input: EventInput): void {
  if (typeof input.at !== "string" || input.at.length === 0) {
    throw new Error("appendEvent: at must be a non-empty ISO 8601 string");
  }
  if (!EVENT_TYPE_SET.has(input.type)) {
    throw new Error(`appendEvent: unknown event type: ${String(input.type)}`);
  }
  const scoped = ENTRY_SCOPED_SET.has(input.type);
  if (scoped && input.entry_id === null) {
    throw new Error(`appendEvent: ${input.type} requires an entry_id`);
  }
  if (!scoped && input.entry_id !== null) {
    throw new Error(`appendEvent: ${input.type} must have a null entry_id`);
  }
  if (input.type === "entry_submitted") {
    const { core } = input.payload as EventPayloads["entry_submitted"];
    if (core?.id !== input.entry_id) {
      throw new Error(
        "appendEvent: entry_submitted entry_id must equal payload.core.id",
      );
    }
  }
}

/**
 * Seal one more event onto the log.
 *
 * Whitepaper Section 6, "Seal": the log is append-only, so this returns a new
 * array and never mutates the input; existing events are carried through
 * untouched and only the new event is hashed.
 */
export async function appendEvent(
  events: readonly Event[],
  input: EventInput,
): Promise<Event[]> {
  checkInput(input);
  const previous = events.length > 0 ? events[events.length - 1] : undefined;
  const fields: Omit<Event, "hash"> = {
    seq: previous === undefined ? 0 : previous.seq + 1,
    at: input.at,
    type: input.type,
    entry_id: input.entry_id,
    payload: input.payload,
    prev_hash: previous === undefined ? null : previous.hash,
  };
  const hash = await eventHash(fields);
  return [...events, { ...fields, hash }];
}

export type ChainResult =
  | { ok: true; length: number }
  | { ok: false; seq: number; reason: "bad_seq" | "bad_prev_hash" | "bad_hash" };

/**
 * Verify the chain offline.
 *
 * Whitepaper Section 6, "Validate": anyone can check that an event existed and
 * has not changed. Recomputes every hash, requires seq to run from 0 without a
 * gap, and requires each prev_hash to be the previous event's hash (null at
 * seq 0). Reports the first failure, by its position in the list.
 */
export async function verifyChain(
  events: readonly Event[],
): Promise<ChainResult> {
  for (let index = 0; index < events.length; index += 1) {
    const event = events[index]!;
    if (event.seq !== index) {
      return { ok: false, seq: index, reason: "bad_seq" };
    }
    const expectedPrev = index === 0 ? null : events[index - 1]!.hash;
    if (event.prev_hash !== expectedPrev) {
      return { ok: false, seq: index, reason: "bad_prev_hash" };
    }
    const { hash, ...fields } = event;
    if ((await eventHash(fields)) !== hash) {
      return { ok: false, seq: index, reason: "bad_hash" };
    }
  }
  return { ok: true, length: events.length };
}
