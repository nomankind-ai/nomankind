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
  APPROVALS_TO_VERIFY_LARGE_POOL,
  APPROVALS_TO_VERIFY_SMALL_POOL,
  REJECTIONS_TO_REJECT,
  STALENESS_WINDOW_DAYS,
  TRUSTED_POOL_SWITCH,
  VERIFICATION_MIN_OUTSIDE_OPERATORS,
  type Category,
} from "./policy.js";
import type { Entry } from "./schema.js";
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
  /** The derived effective tier. M5's; always null here. */
  readonly effective_tier: null;
  /** Size of the trusted pool at the promoting decision's position. */
  readonly trusted_count_at_decision: number | null;
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

/** The outcome of folding an entry's validation events, and nothing else. */
interface Consensus {
  readonly status: "draft" | "rejected" | "verified";
  readonly verifiedAt: string | null;
  readonly trustedCountAtDecision: number | null;
  readonly needsReplacement: boolean;
  readonly approvers: readonly ApproverRecord[];
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
 */
function consensusFor(
  events: readonly Event[],
  entryId: string,
  authorOperator: string | null,
): Consensus {
  const approvers: ApproverRecord[] = [];
  const approvingOperators = new Set<string>();
  const rejectingOperators = new Set<string>();
  let hasRandomApproval = false;
  let status: "draft" | "rejected" | "verified" = "draft";
  let verifiedAt: string | null = null;
  let trustedCountAtDecision: number | null = null;
  let needsReplacement = false;

  for (const event of inSeqOrder(events)) {
    if (!isType(event, "validation")) continue;
    if (event.entry_id !== entryId) continue;

    const record = event.payload.record;
    approvers.push(stripSignature(record));

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
      if (approvals >= approvalsToVerify && randomSatisfied) {
        status = "verified";
        verifiedAt = decision.signed_at;
        trustedCountAtDecision = trustedCount;
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
    needsReplacement,
    approvers,
  };
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
 */
function supersededBy(events: readonly Event[], entryId: string): string | null {
  for (const event of inSeqOrder(events)) {
    if (!isType(event, "entry_submitted")) continue;
    const core = event.payload.core;
    if (core["supersedes"] !== entryId) continue;
    const candidateId = core["id"] as string;
    if (candidateId === entryId) continue;
    const candidate = consensusFor(
      events,
      candidateId,
      (core["author_operator"] as string | null) ?? null,
    );
    if (candidate.status === "verified") return candidateId;
  }
  return null;
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
): DerivedEntry {
  const submission = submissionOf(events, entryId);
  if (submission === null) {
    throw new Error(`deriveEntry: no entry_submitted event for ${entryId}`);
  }
  const core = submission.core;
  const authorOperator = (core["author_operator"] as string | null) ?? null;

  const consensus = consensusFor(events, entryId, authorOperator);
  const freshness = freshnessOf(events, entryId, core, clock);
  const overturned = overturnedBy(events, entryId);
  const superseded =
    consensus.status === "verified" ? supersededBy(events, entryId) : null;

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
    effective_tier: null,
    trusted_count_at_decision: consensus.trustedCountAtDecision,
  };

  const entry: Record<string, unknown> = {};
  for (const key of CORE_KEYS) entry[key] = core[key];
  entry["signature"] = submission.signature;
  entry["approvers"] = consensus.approvers;
  entry["reconfirmations"] = freshness.reconfirmations;
  entry["disputes"] = [];
  entry["failure_reports"] = [];
  entry["seal"] = null;
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
): Map<string, DerivedEntry> {
  const derived = new Map<string, DerivedEntry>();
  for (const entryId of submittedEntryIds(events)) {
    derived.set(entryId, deriveEntry(events, entryId, clock));
  }
  return derived;
}
