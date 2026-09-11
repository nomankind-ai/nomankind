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
  /**
   * The domain this attestation is about (decision D-071). Absent on every
   * attestation sealed before schema v0.7, which reads as the ai-ecosystem
   * attestation under its existing version -- the only domain there was.
   */
  domain?: string;
  signed_at: string;
  signature: string;
};

/**
 * One probe in an attestation's set: the entry it was drawn from, and the hash
 * of that entry as it stood when the set was drawn.
 *
 * The training path, "Drift attestation": "the score and the probe hash are
 * sealed with a date". The entry hash travels beside the id because the probe
 * is a question about a fact at a moment: an entry reconfirmed or superseded
 * after the draw is a different fact, and a score recomputed years later has to
 * know which one was asked about.
 */
export interface Probe {
  readonly entry_id: string;
  readonly entry_hash: string;
}

/** One drawn scorer: the operator the draw picked, and the agent it answers with. */
export interface AttestationScorer {
  readonly operator: string;
  readonly agent: string;
}

/**
 * A scorer's signed verdict.
 *
 * `agreed` is how many of the probes the model's answers matched the log on,
 * out of the attestation's probe_count; `probe_hash` and `answers_hash` pin
 * exactly which questions and which answers were scored, so a score can never be
 * moved onto a different probe set or a different set of answers. The signature
 * travels beside the record in the event payload, exactly as a validation's
 * does (src/records.ts).
 */
export interface AttestationScoreRecord {
  readonly agent: string;
  readonly operator: string;
  readonly agreed: number;
  readonly probe_hash: string;
  readonly answers_hash: string;
  readonly signed_at: string;
}

/** The payload shape carried by each event type. */
export type EventPayloads = {
  /**
   * An operator joined the registry. `domain` is the first domain it is
   * attested in -- the one its registration attestation was signed for
   * (decision D-071) -- and is absent on every registration sealed before
   * schema v0.7, which reads as ai-ecosystem.
   */
  operator_registered: {
    operator: string;
    maintainer: boolean;
    domain?: string;
  };
  operator_trusted: { operator: string };
  operator_untrusted: { operator: string };
  /**
   * An agent key bound to the operator that answers for it. Section 5: "Every
   * agent belongs to an operator", and Section 11: "The binding is then sealed
   * into nomankind's log and you can validate."
   */
  agent_bound: { operator: string; agent: string; attestation: Attestation };
  /**
   * An operator took on a second domain.
   *
   * Decision D-071: registration binds an operator to its first domain's
   * independence attestation, and working in another domain means signing that
   * domain's attestation too. The join is a public event for the same reason
   * the registration is: eligibility per domain has to be recomputable from the
   * log alone (src/derive.ts, `operatorDomainsAt`).
   *
   * `agent` is the key that signed the attestation, which must be one of the
   * operator's own; the attestation carries the domain it is for.
   */
  operator_joined_domain: {
    operator: string;
    agent: string;
    domain: string;
    attestation: Attestation;
  };
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
  /** Recorded on the overturned entry: the correction that overturned it. */
  dispute_upheld: { correction_entry_id: string };
  /**
   * A challenge filed against a verified entry.
   *
   * Whitepaper Section 6, "Dispute": "A challenge is itself an entry, in the
   * correction category, and it requires a citation." So there are two entries
   * in play, and this event is scoped to the DISPUTED one — the target — never
   * to the correction. `correction_entry_id` names the correction, and every
   * later dispute event on the target names it too, so the target's own
   * sub-sequence of the log tells the whole story of what was challenged and
   * how it ended.
   *
   * `citation` and `snapshot_hash` are copied from the correction entry's core
   * rather than looked up. A reader folding the target's events alone must be
   * able to fill the schema's disputes[] item, which requires both, and a
   * derivation that had to fetch another entry's core to do it would not be a
   * fold at all.
   *
   * `operator` is null for a bare-key challenger, which is what decides the
   * stake: Section 6, "A verified operator stakes standing, a bare key stakes a
   * refundable filing fee, and the amounts are published policy" (src/stake.ts,
   * src/policy.ts).
   *
   * `from_report_seq` names the `failure_report` event this dispute was
   * upgraded from, and `from_revalidation_seq` the `revalidation_requested`
   * event it was upgraded from; both null for a dispute filed on its own.
   * Section 8: "a report that carries a citation or a reproducible observation
   * is upgraded into a dispute", and Section 6: "A request that turns up a
   * citation can be upgraded into a dispute."
   */
  dispute_filed: {
    correction_entry_id: string;
    challenger: string;
    operator: string | null;
    citation: string;
    snapshot_hash: string;
    from_report_seq: number | null;
    from_revalidation_seq: number | null;
  };
  /**
   * The challenge did not stand: the correction entry was rejected by its own
   * validators. Section 6: "A failed challenge forfeits the stake and costs the
   * challenger standing, so disputes are for evidence."
   *
   * `reason` is the first rejection's reason, carried so the target's world
   * says why the challenge failed without reading the correction's approvers.
   * Null when no rejection carried one.
   */
  dispute_failed: { correction_entry_id: string; reason: string | null };
  /**
   * Section 6, "Revalidate": "Any operator can also request revalidation of an
   * entry inside its window by staking a small amount of standing. No citation
   * is needed; the request only asks for a check."
   *
   * `requester` and `operator` are both null when the request was opened by
   * nomankind itself, which Section 8 says happens when failure reports from a
   * published threshold of distinct verified operators arrive: the check is "at
   * nomankind's expense", so nobody staked and nobody is refunded.
   */
  revalidation_requested: {
    requester: string | null;
    operator: string | null;
    source: "operator" | "failure_reports";
  };
  /**
   * Section 6: the request "is assigned at random to a trusted operator". The
   * draw is src/assign.ts's, unchanged; `request_seq` is the position of the
   * `revalidation_requested` event being answered, which is what ties the
   * assignment to its request.
   */
  revalidation_assigned: {
    request_seq: number;
    agent: string;
    operator: string;
    beacon_round: number;
    deadline: string;
  };
  /** The assigned checker let the window run out, exactly as `assignment_missed`. */
  revalidation_missed: { request_seq: number; agent: string; operator: string };
  /**
   * How the check ended. Section 6: "If the check finds the fact changed, the
   * requester gets the stake back plus a challenger-style reward. If the entry
   * holds, the requester loses the stake." And: "A request that turns up a
   * citation can be upgraded into a dispute", which is `upgraded` — the stake
   * comes back and the dispute's own stake takes over from there.
   *
   * `checker`, `operator` and `snapshot_hash` are null for an upgrade that the
   * requester made without a check having landed; `correction_entry_id` names
   * the dispute's correction entry and is null unless the outcome is upgraded.
   */
  revalidation_resolved: {
    request_seq: number;
    outcome: "held" | "changed" | "upgraded";
    checker: string | null;
    operator: string | null;
    snapshot_hash: string | null;
    correction_entry_id: string | null;
  };
  /**
   * Section 8, "Failure reports": "A reader that acts on a verified entry and
   * fails ... files a signed failure report against the entry, with its
   * transcript frozen and hashed like any artifact."
   *
   * `artifact_hash` is that frozen transcript or receipt, in the schema's own
   * field name. `operator` is null for a bare-key reporter, and Section 12
   * ("Failure reports can be flooded") is why the field matters: "The threshold
   * that auto-opens revalidation counts distinct verified operators only", so a
   * flood of bare-key reports opens nothing (src/dispute.ts).
   *
   * `citation` is optional evidence; the schema says "its presence makes the
   * report eligible for upgrade to a dispute".
   */
  failure_report: {
    reporter: string;
    operator: string | null;
    observed: string;
    artifact_hash: string;
    citation: string | null;
  };
  /**
   * One UTC day's read counts, published to the log.
   *
   * Whitepaper Section 9, Money: "Read counts are published to the sealed log
   * daily", so "any reader can compare the receipts they hold against the
   * published counts". The event is the publication, and the receipts
   * (src/receipt.ts) are what a reader holds against it.
   *
   * Not entry-scoped: one event covers every entry read that day, so a single
   * entry_id would be a lie about what it says. The per-entry counts are in
   * `reads`, sorted by entry_id so the canonical form — and therefore the event
   * hash — does not depend on what order the rows came back in.
   *
   * `counter_first` and `counter_last` are the smallest and largest receipt
   * counter issued that day, both null when the day counted nothing. They are
   * what makes the day's slice of the running counter checkable: a reader
   * holding a receipt whose counter falls inside the range knows which day's
   * count should have contained it.
   */
  read_count: {
    date: string;
    reads: readonly ReadCountRow[];
    total: number;
    counter_first: number | null;
    counter_last: number | null;
    /**
     * The half of the day that was paid for (M24): the same rows over keyed
     * receipts only, the same reads per key, and their common total.
     *
     * Section 9, Money: "A read is one verified entry returned by the paid API,
     * or one verified entry delivered in a paid sync", and the contributor pool
     * is a share of what those reads were billed at. So this is what the ledger
     * prices, while `reads` above stays the whole day's traffic — the number a
     * free reader's receipt is checked against.
     *
     * `keys` is what makes a bill checkable without trusting us: a key holder
     * adds up the receipts they hold for a day and finds that number here,
     * published in the sealed log where nobody can edit it afterwards.
     *
     * Optional, and absent on every event published before M24: a payload that
     * never carried the block is priced from `reads`, which is what it meant.
     */
    paid?: {
      reads: readonly ReadCountRow[];
      total: number;
      keys: Readonly<Record<string, number>>;
    };
    /**
     * The reads this day was not paid for, and why (decision D-085).
     *
     * A sync hands a trainer the whole delta, so when two verified entries
     * assert the same fact the trainer was delivered one fact twice; the log is
     * owed one read for it, and the one it is owed is the newest of the group.
     * The publish step drops the older entry's sync reads, and this is the drop
     * said out loud: which entry lost them, which live entry the group's reads
     * went to instead, and how many there were.
     *
     * Section 9 asks readers to check the published counts against the receipts
     * they hold, and a reader holding a sync receipt for an entry that is not in
     * `reads` could not tell an under-count from the rule working. Sorted by
     * entry_id, and empty on a day that dropped nothing.
     *
     * The ledger never reads it: the money follows `paid`, and nothing here was
     * paid for. Optional, and absent on every event published before M24b.
     */
    duplicates?: readonly ReadCountDuplicate[];
  };
  /**
   * An attestation opened: the probes drawn, the scorers drawn, and everything
   * either draw was computed from.
   *
   * The training path, "Drift attestation": "A probe set is drawn from verified,
   * observed, fresh entries by public randomness, the same beacon-and-snapshot
   * construction as validator assignment (Section 6), so neither the model's
   * operator nor the maintainer picks the questions."
   *
   * Which is why the payload carries the snapshot's position, the beacon round
   * and the round's randomness rather than only the outcome: both draws are
   * deterministic functions of exactly those, so anyone holding the log and the
   * beacon can recompute the probe set and the three scorers and check that
   * nobody picked either (src/probe.ts, src/attest.ts).
   *
   * `model` is the model's own agent id, and `model_operator` the operator that
   * answers for it, null for an agent bound to nobody. `probes` is sorted by
   * entry_id, so the canonical form the probe hash is taken over does not depend
   * on the order the draw happened to produce; `scorers` stays in draw order,
   * because the order the beacon picked them in is part of what is checkable.
   *
   * The event is not entry-scoped, though every probe names an entry: an
   * attestation is about a model and not about any one of the ten entries it
   * asks about, and a single entry_id would be a lie about which entry's
   * lifecycle it belongs to.
   */
  attestation_requested: {
    attestation: string;
    /** The domain the probes are drawn from and the scorers are attested in. */
    domain: string;
    model: string;
    model_operator: string | null;
    probes: readonly Probe[];
    probe_hash: string;
    probe_count: number;
    pool_snapshot_seq: number;
    beacon_round: number;
    beacon_randomness: string;
    scorers: readonly AttestationScorer[];
    deadline: string;
  };
  /**
   * The model answered. "The model answers the probes."
   *
   * Only the hash is in the log: the answers themselves are the model's output
   * and can be long, and what the scorers must agree about is that they all
   * scored the same answers, which the hash settles (src/probe.ts,
   * `answersHash`). The answers are stored beside the attestation and served
   * from there. `at` is the answered time.
   */
  attestation_answered: { attestation: string; answers_hash: string };
  /**
   * One scorer's signed verdict. "Three operators from the trusted pool ...
   * score its answers against the log and sign the result."
   *
   * The signature travels beside the record rather than inside it, exactly as a
   * validation's does (decision D-034, src/records.ts), and it is over the
   * `attestation_score` kind with the attestation id in the entry_id slot of the
   * signing bytes — so a score signed for one attestation can never be replayed
   * onto another, and a validation can never be replayed as a score.
   */
  attestation_scored: {
    attestation: string;
    record: AttestationScoreRecord;
    signature: string;
  };
  /**
   * The window ran out. `missing` is the scorer operators that never scored,
   * which is what makes an expiry say who did not answer rather than only that
   * nobody finished.
   *
   * An attestation that expires is not a failing score: it is no score at all,
   * and the model's operator asks for a new one. Nothing about drift is claimed
   * by an expiry.
   */
  attestation_expired: { attestation: string; missing: readonly string[] };
};

/** One entry's reads on a published day. */
export interface ReadCountRow {
  entry_id: string;
  count: number;
}

/**
 * One duplicate drop on a published day: the entry whose sync reads were not
 * counted, the live entry of its group the reads were counted for instead, and
 * how many reads were dropped.
 */
export interface ReadCountDuplicate {
  entry_id: string;
  newest: string;
  sync_reads: number;
}

export type EventType = keyof EventPayloads;

/** Every event type, in the declared order. */
export const EVENT_TYPES: readonly EventType[] = [
  "operator_registered",
  "operator_trusted",
  "operator_untrusted",
  "operator_joined_domain",
  "agent_bound",
  "pool_snapshot",
  "entry_submitted",
  "assignment",
  "assignment_missed",
  "validation",
  "reconfirmation",
  "dispute_upheld",
  "dispute_filed",
  "dispute_failed",
  "revalidation_requested",
  "revalidation_assigned",
  "revalidation_missed",
  "revalidation_resolved",
  "failure_report",
  "read_count",
  "attestation_requested",
  "attestation_answered",
  "attestation_scored",
  "attestation_expired",
] as const;

/**
 * Events scoped to an entry carry entry_id; the operator, pool, read-count and
 * attestation events carry null. Whitepaper Section 6: an entry's lifecycle is
 * the sub-sequence of the log bearing its id, so the scope must be unambiguous
 * for every event — and a day's read counts, like an attestation's ten probes,
 * belong to no single entry.
 */
export const ENTRY_SCOPED_TYPES: readonly EventType[] = [
  "entry_submitted",
  "assignment",
  "assignment_missed",
  "validation",
  "reconfirmation",
  "dispute_upheld",
  "dispute_filed",
  "dispute_failed",
  "revalidation_requested",
  "revalidation_assigned",
  "revalidation_missed",
  "revalidation_resolved",
  "failure_report",
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
