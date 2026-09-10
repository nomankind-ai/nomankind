/**
 * Derivation: every derived field and the status, recomputed from the event log.
 *
 * Pure and synchronous. Nothing here reads a wall clock: the only time input is
 * the injected `clock.now`, so the same events and the same clock always give
 * the same answer, on Node and on a Worker alike.
 *
 * Nothing here is ever written directly onto an entry. The schema says so of
 * every field this module computes ("DERIVED ... never written directly"), and
 * the consensus rules come from the whitepaper's Lifecycle of an entry and
 * Freshness and decay sections, cited on each rule below.
 */

import { CORE_KEYS, type Core } from "./core.js";
import {
  evidenceGate,
  type EvidenceTier,
  type TestVerdict,
} from "./evidence.js";
import {
  APPROVALS_TO_VERIFY_LARGE_POOL,
  APPROVALS_TO_VERIFY_SMALL_POOL,
  REJECTIONS_TO_REJECT,
  SLOT_COUNT,
  STALENESS_WINDOW_DAYS,
  TRUSTED_POOL_SWITCH,
  VERIFICATION_MIN_OUTSIDE_OPERATORS,
  type Category,
} from "./policy.js";
import type { Entry } from "./schema.js";
import type { EntrySeal } from "./seal.js";
import { checkSupersedes } from "./supersede.js";
import type {
  ApproverRecord,
  Event,
  EventType,
  ReconfirmationRecord,
} from "./events.js";

/** The injected clock: an ISO 8601 date-time, and the only time input. */
export interface Clock {
  readonly now: string;
}

/** The schema's status enum. */
export type EntryStatus =
  | "draft"
  | "rejected"
  | "verified"
  | "superseded"
  | "overturned";

/** Every derived field on an entry, in the schema's names and shapes. */
export interface DerivedFields {
  readonly status: EntryStatus;
  readonly staleness_window_days: number | null;
  readonly verified_at: string | null;
  readonly last_confirmed: string;
  readonly expires_at: string | null;
  readonly stale: boolean;
  readonly superseded_by: string | null;
  readonly overturned_by: string | null;
  /**
   * The confidence field. conf-v1 is not published, so the field is null for
   * every entry and every input to it stays exposed raw.
   */
  readonly confidence: null;
}

/**
 * One of the entry's read-share slots: who holds it, and the position of the
 * event that seated them. Incentives / Money: the read share is split among the
 * submitter and three current slot holders, so a slot is a claim on future
 * revenue and the seq is what makes "the oldest slot" a fact of the log rather
 * than a matter of opinion.
 */
export interface ReadShareSlot {
  readonly operator: string;
  /** seq of the event that seated the holder. */
  readonly seq: number;
}

/**
 * State the application keeps beside the entry, never in the signed record and
 * never in the schema.
 */
export interface Sidecar {
  /**
   * Lifecycle of an entry: two approvals against one rejection in the large
   * pool draw one beacon-chosen replacement validator. The draw itself is M4's;
   * this only says one is owed.
   */
  readonly needs_replacement: boolean;
  /**
   * Two tiers of evidence: the tier the entry actually verified at, which is
   * not always the tier its core claims. An observed entry whose test a
   * majority rejected verifies as a document, and its effective tier falls to
   * stated. Null while the entry is draft or rejected; once it has verified the
   * value is the one the gate gave at that decision's position and it stays
   * there, superseded and overturned included.
   */
  readonly effective_tier: EvidenceTier | null;
  /**
   * What the validators decided about the proposed test itself, at the
   * verifying decision's position. Null for a stated entry, which has no test
   * to judge, and null while the entry is draft or rejected.
   */
  readonly test_verdict: TestVerdict | null;
  /** Size of the trusted pool at the promoting decision's position. */
  readonly trusted_count_at_decision: number | null;
  /**
   * Incentives / Money: "Reconfirming a stale entry ... rotates the reconfirmer
   * into one of the three validator read-share slots ... replacing the holder
   * of the oldest slot rather than adding to the pool. A reconfirmation by an
   * operator already holding a slot refreshes the entry but rotates nothing."
   *
   * Null until the entry verifies: there is no read share to split before
   * then. The slots are seeded by the approvals that promoted it and then
   * rotated by every later reconfirmation, and once seeded they are never reset
   * to null, superseded and overturned included — the entry still earns.
   */
  readonly read_share_slots: readonly ReadShareSlot[] | null;
  /**
   * Whitepaper Section 6, "Revalidate": "Any operator can also request
   * revalidation of an entry inside its window ... It is assigned at random to a
   * trusted operator", and Section 8: a threshold of failure reports "auto-opens
   * a revalidation at nomankind's expense".
   *
   * The schema has no field for these — a request is not a claim about the world
   * and the signed record says nothing about it — so they live in the sidecar,
   * exactly as the read-share slots do. Empty when nobody has ever asked for a
   * check of this entry.
   */
  readonly revalidations: readonly RevalidationView[];
}

/**
 * One revalidation request, folded from the target's own events.
 *
 * `request_seq` is the `revalidation_requested` event's position, which is what
 * every later event about it names. `requester` and `operator` are both null
 * when the check was auto-opened by failure reports at nomankind's expense
 * (Section 8), which is also what `source` says.
 *
 * `assigned` is the draw currently in force, or null when none is: a missed
 * assignment closes the assignment and not the request, so the field goes back
 * to null and the next draw fills it again.
 */
export interface RevalidationView {
  readonly request_seq: number;
  readonly requester: string | null;
  readonly operator: string | null;
  readonly source: "operator" | "failure_reports";
  readonly requested_at: string;
  readonly assigned: {
    readonly agent: string;
    readonly operator: string;
    readonly deadline: string;
  } | null;
  readonly outcome: "open" | "held" | "changed" | "upgraded";
  readonly resolved_at: string | null;
  readonly checker: string | null;
  readonly correction_entry_id: string | null;
}

/** An entry, its derived fields, and the sidecar the schema cannot hold. */
export interface DerivedEntry {
  readonly entry: Entry;
  readonly derived: DerivedFields;
  readonly sidecar: Sidecar;
}

/** The payload of an event of a given type. */
type PayloadOf<T extends EventType> = Event<T>["payload"];

/**
 * The approver fields derivation reads. Declared here so this module reads the
 * record through the schema's own field names rather than depending on how
 * `ApproverRecord` happens to be spelled.
 */
interface DecisionFields {
  readonly operator: string;
  readonly decision: "approve" | "reject";
  readonly assigned_random: boolean;
  readonly signed_at: string;
}

interface ReconfirmationFields {
  readonly signed_at: string;
}

const MILLISECONDS_PER_DAY = 86_400_000;

/** Events in seq order, without mutating the caller's array. */
function inSeqOrder(events: readonly Event[]): readonly Event[] {
  return [...events].sort((left, right) => left.seq - right.seq);
}

function isType<T extends EventType>(
  event: Event,
  type: T,
): event is Event<T> {
  return event.type === type;
}

/**
 * Registered operators, and which of them are maintainers, as of `position`.
 * Only events with seq <= position are folded, so a later registration can
 * never change what a past decision saw (retrospective M8).
 */
export function registeredOperatorsAt(
  events: readonly Event[],
  position: number,
): { operators: Set<string>; maintainers: Set<string> } {
  const operators = new Set<string>();
  const maintainers = new Set<string>();
  for (const event of inSeqOrder(events)) {
    if (event.seq > position) break;
    if (!isType(event, "operator_registered")) continue;
    const payload: PayloadOf<"operator_registered"> = event.payload;
    operators.add(payload.operator);
    if (payload.maintainer) maintainers.add(payload.operator);
  }
  return { operators, maintainers };
}

/**
 * The trusted pool as of `position`: every operator trusted at or before it,
 * minus every operator untrusted at or before it.
 *
 * Retrospective M8: the trusted count is evaluated at the decision's position,
 * never over the whole log, so an entry can neither verify retroactively when
 * the pool grows nor flip back to draft when it shrinks.
 */
export function trustedOperatorsAt(
  events: readonly Event[],
  position: number,
): Set<string> {
  const trusted = new Set<string>();
  for (const event of inSeqOrder(events)) {
    if (event.seq > position) break;
    if (isType(event, "operator_trusted")) {
      trusted.add(event.payload.operator);
      continue;
    }
    if (isType(event, "operator_untrusted")) {
      trusted.delete(event.payload.operator);
    }
  }
  return trusted;
}

/**
 * Which operator answers for each agent, as of `position`.
 *
 * Whitepaper Section 5: "Every agent belongs to an operator, the human or
 * company that runs it", and every rule that says "a distinct operator"
 * resolves an agent through this. Only events with seq <= position are folded,
 * so a binding sealed later can never change what a past decision saw
 * (retrospective M8), and a later binding of the same agent replaces the
 * earlier one because the fold runs in seq order.
 */
export function agentOperatorsAt(
  events: readonly Event[],
  position: number,
): Map<string, string> {
  const operators = new Map<string, string>();
  for (const event of inSeqOrder(events)) {
    if (event.seq > position) break;
    if (!isType(event, "agent_bound")) continue;
    operators.set(event.payload.agent, event.payload.operator);
  }
  return operators;
}

/** The outcome of folding an entry's validation events, and nothing else. */
interface Consensus {
  readonly status: "draft" | "rejected" | "verified";
  readonly verifiedAt: string | null;
  readonly trustedCountAtDecision: number | null;
  readonly effectiveTier: EvidenceTier | null;
  readonly testVerdict: TestVerdict | null;
  readonly needsReplacement: boolean;
  readonly approvers: readonly ApproverRecord[];
  /** seq of the decision that promoted the entry; null unless it verified. */
  readonly promotingSeq: number | null;
  /** The slots the promoting approvals seated; null unless it verified. */
  readonly seededSlots: readonly ReadShareSlot[] | null;
}

/**
 * Fold an entry's validation events into a verdict.
 *
 * Lifecycle of an entry, Validate: "Once the pool holds ten operators, three
 * approvals promote the entry to verified, two rejections mark it rejected ...
 * and two approvals against one rejection draw one replacement validator ...
 * Until the pool holds ten operators, two approvals verify, two rejections
 * reject, and there is no replacement draw."
 *
 * And: "Verification has two preconditions: three verified operators outside
 * the submitter's own, and a non-empty trusted pool to draw the random
 * validator from. At genesis, entries stay in draft until both exist."
 *
 * Both the pool size and the two preconditions are read at the position of the
 * decision being folded, never at the end of the log (retrospective M8), so a
 * decision taken under one pool keeps its verdict when the pool later moves,
 * and a later decision is judged afresh at its own position.
 *
 * The count is not the only condition. Two tiers of evidence: an entry also has
 * to have the evidence its tier asks for, which is src/evidence.ts's rule and
 * is asked there, never restated here. The gate is consulted at exactly the
 * moment the count would promote, over exactly the decisions counted so far, so
 * an entry the gate turns away does not verify and is asked again at the next
 * counted decision. It stays draft only while the rejections are short of the
 * threshold: the rejection rule is unconditional, and a gate refusal never
 * shields an entry from it.
 */
function consensusFor(
  events: readonly Event[],
  entryId: string,
  authorOperator: string | null,
  core: Core,
): Consensus {
  const approvers: ApproverRecord[] = [];
  const approvingOperators = new Set<string>();
  const rejectingOperators = new Set<string>();
  // The counted decisions themselves, one per distinct eligible operator and in
  // seq order: the same records the counts above are built from, kept so the
  // evidence gate reads exactly what consensus counted.
  const countedRecords: ApproverRecord[] = [];
  // The seq each counted record arrived at, parallel to countedRecords: a
  // read-share slot is identified by the position that seated it.
  const countedSeqs: number[] = [];
  const countedOperators = new Set<string>();
  let hasRandomApproval = false;
  let status: "draft" | "rejected" | "verified" = "draft";
  let verifiedAt: string | null = null;
  let trustedCountAtDecision: number | null = null;
  let effectiveTier: EvidenceTier | null = null;
  let testVerdictAtDecision: TestVerdict | null = null;
  let needsReplacement = false;
  let promotingSeq: number | null = null;
  let seededSlots: readonly ReadShareSlot[] | null = null;

  for (const event of inSeqOrder(events)) {
    if (!isType(event, "validation")) continue;
    if (event.entry_id !== entryId) continue;

    const record = stripSignature(event.payload.record);
    approvers.push(record);

    // Once verified or rejected the verdict stands: later decisions still land
    // in approvers[], but change nothing.
    if (status !== "draft") continue;

    const position = event.seq;
    const decision = record as unknown as DecisionFields;

    // Who may validate at all. Lifecycle of an entry, Validate: "Three other
    // agents, each from a distinct operator and none under the submitter's
    // own"; Section 5: "Only verified operators can validate"; the schema's
    // approvers[] $comment adds "none under the submitter's or maintainer's".
    // A record from anyone else stays in approvers[] (the log is append-only,
    // and M4's check-validation refuses such a write at the door), but it is
    // counted by nobody here: derivation stays safe against a log that holds
    // one anyway. Eligibility is read at the record's own position, like every
    // other rule here.
    if (!mayValidate(events, position, authorOperator, decision.operator)) {
      continue;
    }

    // The first record from an operator is the one that counts, here as in the
    // distinct-operator sets below.
    if (!countedOperators.has(decision.operator)) {
      countedOperators.add(decision.operator);
      countedRecords.push(record);
      countedSeqs.push(position);
    }

    if (decision.decision === "approve") {
      // Distinct operators: a second record from the same operator is kept but
      // adds no count.
      approvingOperators.add(decision.operator);
      if (decision.assigned_random) hasRandomApproval = true;
    } else {
      rejectingOperators.add(decision.operator);
    }

    const trustedCount = trustedOperatorsAt(events, position).size;
    const largePool = trustedCount >= TRUSTED_POOL_SWITCH;
    const approvals = approvingOperators.size;
    const rejections = rejectingOperators.size;

    if (preconditionsMet(events, position, authorOperator, trustedCount)) {
      const approvalsToVerify = largePool
        ? APPROVALS_TO_VERIFY_LARGE_POOL
        : APPROVALS_TO_VERIFY_SMALL_POOL;
      // The large pool also wants the beacon-drawn validator among the
      // approvals. The paper says exactly one; "at least one" is what the
      // replacement-draw path can satisfy (retrospective GAPS M9).
      const randomSatisfied = largePool ? hasRandomApproval : true;
      // Two tiers of evidence: the count says the validators agree, the gate
      // says whether what they brought is enough, and at which tier. The gate is
      // asked only where the count would promote, over exactly the decisions
      // counted so far.
      const countMet = approvals >= approvalsToVerify && randomSatisfied;
      const gate = countMet ? evidenceGate(core, countedRecords) : null;
      // A gate refusal is never itself a rejection: it only means the approvals
      // do not promote at this position, so this decision is judged as any
      // unpromoted one is. Lifecycle of an entry: two rejections mark the entry
      // rejected, unconditionally — an entry the gate keeps turning away is
      // still rejected once the rejections arrive, and is otherwise asked again
      // at the next counted decision.
      if (countMet && gate !== null && gate.verifiable) {
        status = "verified";
        verifiedAt = decision.signed_at;
        trustedCountAtDecision = trustedCount;
        effectiveTier = gate.effective_tier;
        testVerdictAtDecision = gate.test_verdict;
        promotingSeq = position;
        seededSlots = seatsFrom(countedRecords, countedSeqs);
      } else if (rejections >= REJECTIONS_TO_REJECT) {
        status = "rejected";
        trustedCountAtDecision = trustedCount;
      }
    }

    if (status !== "draft") {
      needsReplacement = false;
      continue;
    }
    // A 2-1 split in the large pool owes a replacement draw; the small pool
    // makes no draw at all.
    needsReplacement =
      largePool &&
      approvals >= APPROVALS_TO_VERIFY_LARGE_POOL - 1 &&
      rejections >= 1;
  }

  return {
    status,
    verifiedAt,
    trustedCountAtDecision,
    effectiveTier,
    testVerdict: testVerdictAtDecision,
    needsReplacement,
    approvers,
    promotingSeq,
    seededSlots,
  };
}

/**
 * The slots the promoting approvals seat.
 *
 * Incentives / Money: the read share goes to "the submitter and the three
 * validators", so the seats are the approvals consensus counted — approve
 * decisions only, one per eligible operator, the same set the evidence gate
 * read — each at the position of its own validation event, earliest first.
 * Never more than SLOT_COUNT: the split is over exactly that many slots, and a
 * rejection buys no share of an entry it argued against.
 */
function seatsFrom(
  countedRecords: readonly ApproverRecord[],
  countedSeqs: readonly number[],
): readonly ReadShareSlot[] {
  const seats: ReadShareSlot[] = [];
  for (let index = 0; index < countedRecords.length; index += 1) {
    const decision = countedRecords[index] as unknown as DecisionFields;
    if (decision.decision !== "approve") continue;
    seats.push({ operator: decision.operator, seq: countedSeqs[index]! });
  }
  seats.sort((left, right) => left.seq - right.seq);
  return seats.slice(0, SLOT_COUNT);
}

/**
 * Fold the reconfirmations after the promoting decision into the read-share
 * slots.
 *
 * Incentives / Money: "Reconfirming a stale entry ... rotates the reconfirmer
 * into one of the three validator read-share slots ... replacing the holder of
 * the oldest slot rather than adding to the pool. A reconfirmation by an
 * operator already holding a slot refreshes the entry but rotates nothing."
 *
 * So: a holder rotates nothing; an outsider takes an empty slot while the entry
 * holds fewer than SLOT_COUNT (a small pool verifies on two approvals and seats
 * two, and filling the third adds to the pool only until it is full); otherwise
 * the outsider replaces the oldest holder. The slots keep folding whatever the
 * entry's later status: refusing a reconfirmation on a non-verified entry is the
 * door's job (M6's reconfirmation check), and derivation trusts the sealed log
 * here exactly as it does for validations.
 */
function readShareSlotsFor(
  events: readonly Event[],
  entryId: string,
  consensus: Consensus,
): readonly ReadShareSlot[] | null {
  if (consensus.promotingSeq === null || consensus.seededSlots === null) {
    return null;
  }
  const slots: ReadShareSlot[] = [...consensus.seededSlots];
  for (const event of inSeqOrder(events)) {
    if (!isType(event, "reconfirmation")) continue;
    if (event.entry_id !== entryId) continue;
    // Approvals arriving after verification take no slot, and neither does a
    // reconfirmation sealed at or before the decision that seated the slots.
    if (event.seq <= consensus.promotingSeq) continue;

    const { operator } = event.payload.record;
    if (slots.some((slot) => slot.operator === operator)) continue;

    if (slots.length < SLOT_COUNT) {
      slots.push({ operator, seq: event.seq });
    } else {
      // Sorted ascending, so the oldest slot is the first one.
      slots.splice(0, 1, { operator, seq: event.seq });
    }
    slots.sort((left, right) => left.seq - right.seq);
  }
  return slots;
}

/**
 * Whether one operator's decision on this entry counts, as of `position`.
 *
 * Lifecycle of an entry, Validate, and Section 5: the validators are "three
 * other agents, each from a distinct operator and none under the submitter's
 * own", and "only verified operators can validate". The maintainer is not an
 * outside operator either, so its own operator never counts.
 */
function mayValidate(
  events: readonly Event[],
  position: number,
  authorOperator: string | null,
  operator: string,
): boolean {
  const registered = registeredOperatorsAt(events, position);
  if (!registered.operators.has(operator)) return false;
  if (registered.maintainers.has(operator)) return false;
  if (authorOperator !== null && operator === authorOperator) return false;
  return true;
}

/**
 * Lifecycle of an entry: "Verification has two preconditions: three verified
 * operators outside the submitter's own, and a non-empty trusted pool to draw
 * the random validator from."
 *
 * Maintainers are not outside operators: the paper excludes the maintainer's
 * own agents from validating an entry.
 */
function preconditionsMet(
  events: readonly Event[],
  position: number,
  authorOperator: string | null,
  trustedCount: number,
): boolean {
  if (trustedCount === 0) return false;
  const registered = registeredOperatorsAt(events, position);
  let outside = 0;
  for (const operator of registered.operators) {
    if (registered.maintainers.has(operator)) continue;
    if (authorOperator !== null && operator === authorOperator) continue;
    outside += 1;
  }
  return outside >= VERIFICATION_MIN_OUTSIDE_OPERATORS;
}

/**
 * The entry carries the decision, never the envelope signature that delivered
 * it: `approvers[]` items are exactly the schema's approver shape.
 */
function stripSignature<T>(record: T): T {
  const copy = { ...(record as Record<string, unknown>) };
  delete copy["signature"];
  return copy as T;
}

/** The date part of an ISO 8601 date-time; `last_confirmed` is a date. */
function dateOf(timestamp: string): string {
  return timestamp.slice(0, 10);
}

/**
 * The UTC calendar date an instant falls on, whatever offset it was written
 * with. `expires_at` is a date (schema format `date`), so comparing it to the
 * clock is a comparison of calendar days, never of instants.
 */
function utcDateOf(timestamp: string): string {
  return new Date(Date.parse(timestamp)).toISOString().slice(0, 10);
}

function startOfDayMs(date: string): number {
  return Date.parse(`${date}T00:00:00.000Z`);
}

/** A UTC date, `days` after `date`. Milliseconds arithmetic, no wall clock. */
function datePlusDays(date: string, days: number): string {
  const shifted = startOfDayMs(date) + days * MILLISECONDS_PER_DAY;
  return new Date(shifted).toISOString().slice(0, 10);
}

/** The submitted core and author signature for an entry, or null if unknown. */
function submissionOf(
  events: readonly Event[],
  entryId: string,
): PayloadOf<"entry_submitted"> | null {
  for (const event of inSeqOrder(events)) {
    if (!isType(event, "entry_submitted")) continue;
    if (event.payload.core["id"] !== entryId) continue;
    return event.payload;
  }
  return null;
}

/**
 * Freshness and decay: "Every entry carries a last-confirmed date. Volatile
 * facts carry a staleness window from that date ... Event categories carry no
 * window, because once they happened they stay true." A reconfirmation
 * "advances the derived last-confirmed date, reopens the freshness window".
 */
function freshnessOf(
  events: readonly Event[],
  entryId: string,
  core: Core,
  clock: Clock,
): {
  staleness_window_days: number | null;
  last_confirmed: string;
  expires_at: string | null;
  stale: boolean;
  reconfirmations: readonly ReconfirmationRecord[];
} {
  const reconfirmations: ReconfirmationRecord[] = [];
  for (const event of inSeqOrder(events)) {
    if (!isType(event, "reconfirmation")) continue;
    if (event.entry_id !== entryId) continue;
    reconfirmations.push(stripSignature(event.payload.record));
  }

  // The latest reconfirmation is the last one in log order, not the one with
  // the greatest signed_at: append position is the sealed truth, so a
  // reconfirmer cannot extend its window by forward-dating signed_at.
  const latest = reconfirmations[reconfirmations.length - 1];
  const lastConfirmed =
    latest === undefined
      ? dateOf(core["submitted_at"] as string)
      : dateOf((latest as unknown as ReconfirmationFields).signed_at);

  const window = STALENESS_WINDOW_DAYS[core["category"] as Category] ?? null;
  const expiresAt = window === null ? null : datePlusDays(lastConfirmed, window);
  // The schema: stale is "True when expires_at is in the past". `expires_at` is
  // a calendar date, so the expiry date itself is still fresh (day 90) and the
  // day after it is stale (day 91), whatever time of day the clock reads.
  const stale = expiresAt !== null && utcDateOf(clock.now) > expiresAt;

  return {
    staleness_window_days: window,
    last_confirmed: lastConfirmed,
    expires_at: expiresAt,
    stale,
    reconfirmations,
  };
}

/**
 * Freshness and decay: the superseding entry "names the superseded entry inside
 * the new entry's frozen, signed core ... and the old entry's superseded-by
 * pointer is derived from it". The approvals are the check, so a superseding
 * entry that never verified changes nothing. Earliest such entry by position
 * wins.
 *
 * And: "A superseding entry must share its target's subject and category".
 * That rule lives in src/supersede.ts and is asked there, never restated here:
 * a candidate the link check refuses is not a superseder at all, however its own
 * validators voted. The lookup answers for this entry alone, because this entry
 * is the only target in question.
 */
function supersededBy(
  events: readonly Event[],
  entryId: string,
  target: Core,
): string | null {
  const lookup = (id: string): Core | null => (id === entryId ? target : null);
  for (const event of inSeqOrder(events)) {
    if (!isType(event, "entry_submitted")) continue;
    const core = event.payload.core;
    if (core["supersedes"] !== entryId) continue;
    const candidateId = core["id"] as string;
    if (candidateId === entryId) continue;
    if (!checkSupersedes(core, lookup).ok) continue;
    const candidate = consensusFor(
      events,
      candidateId,
      (core["author_operator"] as string | null) ?? null,
      core,
    );
    if (candidate.status === "verified") return candidateId;
  }
  return null;
}

/**
 * The schema's `disputes[]` array, folded from the target's own events.
 *
 * Lifecycle of an entry, Dispute: "A challenge is itself an entry, in the
 * correction category, and it requires a citation ... The original stays in the
 * log, marked overturned, linked to its correction." The array is the record of
 * every challenge against this entry, upheld, failed or still open, in the order
 * they were filed.
 *
 * `citation` and `snapshot_hash` come off the `dispute_filed` event, which
 * copied them from the correction's core: the fold reads this entry's events and
 * nothing else, so a reader holding only the target's sub-sequence of the log
 * can rebuild the array exactly.
 *
 * A `dispute_upheld` with no `dispute_filed` before it produces no row. The
 * event still overturns the entry (`overturnedBy` below reads it on its own),
 * because it always has; but a disputes[] item needs a challenger, a citation
 * and a snapshot hash, and inventing them would be a lie.
 */
function disputesFor(
  events: readonly Event[],
  entryId: string,
): readonly Record<string, unknown>[] {
  const outcomes = new Map<
    string,
    { outcome: "upheld" | "failed"; reason: string | null; at: string }
  >();
  for (const event of inSeqOrder(events)) {
    if (event.entry_id !== entryId) continue;
    if (isType(event, "dispute_upheld")) {
      const id = event.payload.correction_entry_id;
      if (!outcomes.has(id)) {
        outcomes.set(id, { outcome: "upheld", reason: null, at: event.at });
      }
    } else if (isType(event, "dispute_failed")) {
      const id = event.payload.correction_entry_id;
      if (!outcomes.has(id)) {
        outcomes.set(id, {
          outcome: "failed",
          reason: event.payload.reason,
          at: event.at,
        });
      }
    }
  }

  const disputes: Record<string, unknown>[] = [];
  for (const event of inSeqOrder(events)) {
    if (!isType(event, "dispute_filed")) continue;
    if (event.entry_id !== entryId) continue;
    const settled = outcomes.get(event.payload.correction_entry_id) ?? null;
    disputes.push({
      id: event.payload.correction_entry_id,
      challenger: event.payload.challenger,
      operator: event.payload.operator,
      citation: event.payload.citation,
      snapshot_hash: event.payload.snapshot_hash,
      outcome: settled === null ? "open" : settled.outcome,
      reason: settled === null ? null : settled.reason,
      filed_at: event.at,
      resolved_at: settled === null ? null : settled.at,
    });
  }
  return disputes;
}

/**
 * The schema's `failure_reports[]` array, folded from the target's own events.
 *
 * Whitepaper Section 8: "A reader that acts on a verified entry and fails ...
 * files a signed failure report against the entry, with its transcript frozen
 * and hashed like any artifact." Reports "never change the core or the status by
 * themselves", so nothing here touches the status: the array is what the reports
 * say, and the threshold that acts on them is src/dispute.ts's.
 *
 * `upgraded_to` is filled from the other direction: a `dispute_filed` naming
 * this report's position in `from_report_seq` is what upgraded it, so the link
 * is the log's and never a second field somebody had to remember to set.
 */
function failureReportsFor(
  events: readonly Event[],
  entryId: string,
): readonly Record<string, unknown>[] {
  const upgrades = new Map<number, string>();
  for (const event of inSeqOrder(events)) {
    if (!isType(event, "dispute_filed")) continue;
    if (event.entry_id !== entryId) continue;
    const from = event.payload.from_report_seq;
    if (from === null || upgrades.has(from)) continue;
    upgrades.set(from, event.payload.correction_entry_id);
  }

  const reports: Record<string, unknown>[] = [];
  for (const event of inSeqOrder(events)) {
    if (!isType(event, "failure_report")) continue;
    if (event.entry_id !== entryId) continue;
    reports.push({
      reporter: event.payload.reporter,
      operator: event.payload.operator,
      observed: event.payload.observed,
      artifact_hash: event.payload.artifact_hash,
      citation: event.payload.citation,
      upgraded_to: upgrades.get(event.seq) ?? null,
      filed_at: event.at,
    });
  }
  return reports;
}

/**
 * The sidecar's `revalidations`, folded from the target's own events.
 *
 * One view per `revalidation_requested`, in the order they were made, each
 * carrying the draw currently in force and the outcome if the check has landed.
 * A `revalidation_missed` clears the draw rather than the request: Section 6's
 * check is still owed, and the next draw answers it, exactly as a missed
 * validation assignment leaves the entry still needing one.
 */
function revalidationsFor(
  events: readonly Event[],
  entryId: string,
): readonly RevalidationView[] {
  const views = new Map<number, RevalidationView>();
  for (const event of inSeqOrder(events)) {
    if (event.entry_id !== entryId) continue;

    if (isType(event, "revalidation_requested")) {
      views.set(event.seq, {
        request_seq: event.seq,
        requester: event.payload.requester,
        operator: event.payload.operator,
        source: event.payload.source,
        requested_at: event.at,
        assigned: null,
        outcome: "open",
        resolved_at: null,
        checker: null,
        correction_entry_id: null,
      });
      continue;
    }

    if (isType(event, "revalidation_assigned")) {
      const view = views.get(event.payload.request_seq);
      if (view === undefined) continue;
      views.set(view.request_seq, {
        ...view,
        assigned: {
          agent: event.payload.agent,
          operator: event.payload.operator,
          deadline: event.payload.deadline,
        },
      });
      continue;
    }

    if (isType(event, "revalidation_missed")) {
      const view = views.get(event.payload.request_seq);
      if (view === undefined) continue;
      views.set(view.request_seq, { ...view, assigned: null });
      continue;
    }

    if (isType(event, "revalidation_resolved")) {
      const view = views.get(event.payload.request_seq);
      if (view === undefined) continue;
      // The first resolution is the one that counts, as the first verdict on an
      // entry is: a check answered twice is still one check.
      if (view.outcome !== "open") continue;
      views.set(view.request_seq, {
        ...view,
        assigned: null,
        outcome: event.payload.outcome,
        resolved_at: event.at,
        checker: event.payload.checker,
        correction_entry_id: event.payload.correction_entry_id,
      });
    }
  }
  return [...views.values()].sort(
    (left, right) => left.request_seq - right.request_seq,
  );
}

/**
 * Lifecycle of an entry, Dispute: "An upheld challenge ... overturns the entry
 * ... The original stays in the log, marked overturned, linked to its
 * correction."
 */
function overturnedBy(events: readonly Event[], entryId: string): string | null {
  for (const event of inSeqOrder(events)) {
    if (!isType(event, "dispute_upheld")) continue;
    if (event.entry_id !== entryId) continue;
    return event.payload.correction_entry_id;
  }
  return null;
}

/** Every entry id in the log, in submission order. */
function submittedEntryIds(events: readonly Event[]): readonly string[] {
  const ids: string[] = [];
  for (const event of inSeqOrder(events)) {
    if (!isType(event, "entry_submitted")) continue;
    ids.push(event.payload.core["id"] as string);
  }
  return ids;
}

/**
 * Derive one entry from the log.
 *
 * Throws when the log holds no `entry_submitted` event for `entryId`: there is
 * nothing to derive, and a made-up empty entry would be a lie.
 */
export function deriveEntry(
  events: readonly Event[],
  entryId: string,
  clock: Clock,
  entrySeals: ReadonlyMap<string, EntrySeal> = new Map(),
): DerivedEntry {
  const submission = submissionOf(events, entryId);
  if (submission === null) {
    throw new Error(`deriveEntry: no entry_submitted event for ${entryId}`);
  }
  const core = submission.core;
  const authorOperator = (core["author_operator"] as string | null) ?? null;

  const consensus = consensusFor(events, entryId, authorOperator, core);
  const freshness = freshnessOf(events, entryId, core, clock);
  const overturned = overturnedBy(events, entryId);
  const superseded =
    consensus.status === "verified"
      ? supersededBy(events, entryId, core)
      : null;

  let status: EntryStatus = consensus.status;
  if (superseded !== null) status = "superseded";
  // An upheld dispute is the stronger verdict: it says the entry was never
  // true, where supersession only says it stopped being current.
  if (overturned !== null) status = "overturned";

  const derived: DerivedFields = {
    status,
    staleness_window_days: freshness.staleness_window_days,
    verified_at: consensus.verifiedAt,
    last_confirmed: freshness.last_confirmed,
    expires_at: freshness.expires_at,
    stale: freshness.stale,
    superseded_by: superseded,
    overturned_by: overturned,
    confidence: null,
  };

  const sidecar: Sidecar = {
    needs_replacement: consensus.needsReplacement,
    effective_tier: consensus.effectiveTier,
    test_verdict: consensus.testVerdict,
    trusted_count_at_decision: consensus.trustedCountAtDecision,
    read_share_slots: readShareSlotsFor(events, entryId, consensus),
    revalidations: revalidationsFor(events, entryId),
  };

  const entry: Record<string, unknown> = {};
  for (const key of CORE_KEYS) entry[key] = core[key];
  entry["signature"] = submission.signature;
  entry["approvers"] = consensus.approvers;
  entry["reconfirmations"] = freshness.reconfirmations;
  entry["disputes"] = disputesFor(events, entryId);
  entry["failure_reports"] = failureReportsFor(events, entryId);
  entry["seal"] = entrySeals.get(entryId) ?? null;
  entry["staleness_window_days"] = derived.staleness_window_days;
  entry["verified_at"] = derived.verified_at;
  entry["last_confirmed"] = derived.last_confirmed;
  entry["expires_at"] = derived.expires_at;
  entry["stale"] = derived.stale;
  entry["superseded_by"] = derived.superseded_by;
  entry["overturned_by"] = derived.overturned_by;
  entry["status"] = derived.status;
  entry["confidence"] = derived.confidence;

  return { entry: entry as Entry, derived, sidecar };
}

/** Derive every entry in the log, keyed by entry id. */
export function deriveAll(
  events: readonly Event[],
  clock: Clock,
  entrySeals: ReadonlyMap<string, EntrySeal> = new Map(),
): Map<string, DerivedEntry> {
  const derived = new Map<string, DerivedEntry>();
  for (const entryId of submittedEntryIds(events)) {
    derived.set(entryId, deriveEntry(events, entryId, clock, entrySeals));
  }
  return derived;
}
