/**
 * Assignment: the beacon draw, the seventy-two-hour window, and the miss.
 *
 * Lifecycle of an entry, Validate: "Two of the three volunteer. The third is
 * assigned from the trusted pool by public randomness. The draw is a
 * deterministic function of a public randomness beacon's output, the entry id,
 * and a published snapshot of the eligible pool. The pool snapshot is committed
 * to the sealed log before the beacon round it uses, so neither can be chosen
 * with the outcome in view, anyone can recompute who should have been drawn,
 * and neither the submitter nor the maintainer can steer it. An assigned
 * validator has seventy-two hours to respond. A miss costs standing, and the
 * next beacon round draws a replacement."
 *
 * Identity and operators: "Every agent under an operator counts as one for
 * validation." The operator is therefore the unit of assignment; an assignment
 * names the operator and the agent the caller resolved for it, and a validation
 * record satisfies an assignment when its `operator` matches.
 *
 * Pure, and no wall clock: time arrives as ISO 8601 strings and through the
 * injected `Clock`. Hashing is WebCrypto via src/hash.ts, so this runs
 * unchanged on a Worker. Every policy number comes from src/policy.ts.
 */

import { canonicalize, taggedSha256Hex } from "./hash.js";
import { ASSIGNMENT_WINDOW_HOURS, TRUSTED_POOL_SWITCH } from "./policy.js";
import { trustedOperatorsAt, type Clock, type EntryStatus } from "./derive.js";
import type { Event, EventInput, EventType } from "./events.js";

/**
 * Domain-separation tag for the draw digest. A format constant, not a policy
 * number: it names the hash construction, so a draw digest can never be
 * replayed as an entry or event hash.
 */
export const HASH_TAG_DRAW = "nomankind-draw-v1";

/** A unit constant, not a policy number. */
const MILLISECONDS_PER_HOUR = 3_600_000;

/** One round of a public randomness beacon (a beacon like drand). */
export interface Beacon {
  readonly round: number;
  /** The round's randomness, as hex. */
  readonly randomness: string;
  /** ISO 8601 time of the round. */
  readonly at: string;
}

/** A published snapshot of the eligible pool, as sealed into the log. */
export interface PoolSnapshot {
  /** Position of the `pool_snapshot` event in the log. */
  readonly seq: number;
  readonly at: string;
  readonly operators: readonly string[];
}

export type DrawRefusal =
  | "snapshot_after_beacon"
  | "empty_pool"
  | "pool_below_switch"
  | "no_eligible_operator";

export type DrawResult =
  | {
      ok: true;
      operator: string;
      index: number;
      digest: string;
      eligible: readonly string[];
    }
  | { ok: false; reason: DrawRefusal };

/** Sorted, de-duplicated, default string order: the pool's canonical form. */
function canonicalPool(operators: readonly string[]): string[] {
  return [...new Set(operators)].sort();
}

/**
 * Draw the assigned validator.
 *
 * A rule refusal is a verdict, never a throw: the caller gets a reason it can
 * record. The digest is over the entry id, the whole canonical pool, and the
 * beacon round and its randomness, so anyone holding the log and the beacon can
 * recompute who should have been drawn.
 *
 * The pool inside the digest is the full snapshot, not the eligible subset: it
 * is the published commitment, and folding the exclusions into it would let a
 * caller move the digest by claiming a different exclusion set.
 *
 * Below the switch there is no draw at all. The schema says of
 * `approvers[].assigned_random` that it is "Always false while the pool is
 * under ten operators", because "before then two approvals verify and no draw
 * is made"; derivation counts no assigned approval under a small pool either.
 * A caller that asks for one anyway gets `pool_below_switch` rather than an
 * operator it could never legitimately assign.
 */
export async function drawValidator(input: {
  entryId: string;
  snapshot: PoolSnapshot;
  beacon: Beacon;
  exclude: readonly string[];
}): Promise<DrawResult> {
  // The snapshot is committed before the beacon round it uses; equal times are
  // not before, so they are refused too.
  if (!(Date.parse(input.snapshot.at) < Date.parse(input.beacon.at))) {
    return { ok: false, reason: "snapshot_after_beacon" };
  }

  const pool = canonicalPool(input.snapshot.operators);
  if (pool.length === 0) return { ok: false, reason: "empty_pool" };
  if (pool.length < TRUSTED_POOL_SWITCH) {
    return { ok: false, reason: "pool_below_switch" };
  }

  const excluded = new Set(input.exclude);
  const eligible = pool.filter((operator) => !excluded.has(operator));
  if (eligible.length === 0) {
    return { ok: false, reason: "no_eligible_operator" };
  }

  const canonical = canonicalize({
    entry_id: input.entryId,
    pool,
    beacon_round: input.beacon.round,
    beacon_randomness: input.beacon.randomness,
  });
  const hex = await taggedSha256Hex(HASH_TAG_DRAW, canonical);
  const index = Number(BigInt(`0x${hex}`) % BigInt(eligible.length));

  return {
    ok: true,
    operator: eligible[index] as string,
    index,
    // "sha256:" + hex, matching the schema's hash pattern.
    digest: `sha256:${hex}`,
    eligible,
  };
}

/** Events in seq order, without mutating the caller's array (as derive.ts). */
function inSeqOrder(events: readonly Event[]): readonly Event[] {
  return [...events].sort((left, right) => left.seq - right.seq);
}

function isType<T extends EventType>(event: Event, type: T): event is Event<T> {
  return event.type === type;
}

/**
 * The newest `pool_snapshot` at or before `position`.
 *
 * Read at a position, never at the end of the log: a draw is recomputed against
 * the pool as it stood when the draw was made, so a later snapshot can never
 * change who should have been drawn.
 */
export function latestPoolSnapshot(
  events: readonly Event[],
  position: number,
): PoolSnapshot | null {
  let snapshot: PoolSnapshot | null = null;
  for (const event of inSeqOrder(events)) {
    if (event.seq > position) break;
    if (!isType(event, "pool_snapshot")) continue;
    snapshot = {
      seq: event.seq,
      at: event.at,
      operators: [...event.payload.operators],
    };
  }
  return snapshot;
}

/**
 * The deadline for an assignment made at `at`: ASSIGNMENT_WINDOW_HOURS later,
 * as an ISO 8601 date-time with milliseconds.
 */
export function assignmentDeadline(at: string): string {
  const deadline =
    Date.parse(at) + ASSIGNMENT_WINDOW_HOURS * MILLISECONDS_PER_HOUR;
  return new Date(deadline).toISOString();
}

/** An assignment still awaiting its validator, and where it sits in the log. */
export interface OpenAssignment {
  readonly seq: number;
  readonly agent: string;
  readonly operator: string;
  readonly beacon_round: number;
  readonly deadline: string;
  readonly replacement: boolean;
}

/**
 * The entry's open assignment, or null.
 *
 * The newest `assignment` for the entry is the one in force: a later assignment
 * supersedes an earlier one, so an earlier one never reopens. It is open unless
 * something after it closed it, which is either an `assignment_missed` for the
 * same entry and operator or a `validation` on the entry whose record carries
 * that operator (Identity and operators: the operator is the unit, so any agent
 * under it answers the assignment).
 */
export function openAssignment(
  events: readonly Event[],
  entryId: string,
): OpenAssignment | null {
  const ordered = inSeqOrder(events);

  let assignment: OpenAssignment | null = null;
  for (const event of ordered) {
    if (!isType(event, "assignment")) continue;
    if (event.entry_id !== entryId) continue;
    assignment = {
      seq: event.seq,
      agent: event.payload.agent,
      operator: event.payload.operator,
      beacon_round: event.payload.beacon_round,
      deadline: event.payload.deadline,
      replacement: event.payload.replacement,
    };
  }
  if (assignment === null) return null;

  for (const event of ordered) {
    if (event.seq <= assignment.seq) continue;
    if (event.entry_id !== entryId) continue;
    if (
      isType(event, "assignment_missed") &&
      event.payload.operator === assignment.operator
    ) {
      return null;
    }
    if (
      isType(event, "validation") &&
      event.payload.record.operator === assignment.operator
    ) {
      return null;
    }
  }
  return assignment;
}

/**
 * Whether the window has run out. Strictly past the deadline: the deadline
 * instant itself is still inside the seventy-two hours.
 */
export function isAssignmentMissed(
  assignment: OpenAssignment,
  clock: Clock,
): boolean {
  return Date.parse(clock.now) > Date.parse(assignment.deadline);
}

/**
 * Every operator the draw must skip for this entry.
 *
 * Identity and operators: "No agent under the submitter's operator may validate
 * that submitter's entry." Lifecycle of an entry, Validate: the validators are
 * "each from a distinct operator", so an operator that already signed cannot be
 * drawn again; and a missed assignment draws a replacement, which means the
 * operator that missed is not redrawn for the same entry.
 */
export function exclusionsFor(
  events: readonly Event[],
  entryId: string,
): string[] {
  const excluded = new Set<string>();
  for (const event of inSeqOrder(events)) {
    if (isType(event, "entry_submitted")) {
      if (event.payload.core["id"] !== entryId) continue;
      const author = event.payload.core["author_operator"];
      if (typeof author === "string") excluded.add(author);
      continue;
    }
    if (event.entry_id !== entryId) continue;
    if (isType(event, "validation")) {
      excluded.add(event.payload.record.operator);
      continue;
    }
    if (isType(event, "assignment_missed")) {
      excluded.add(event.payload.operator);
    }
  }
  return [...excluded].sort();
}

/** The `assignment` event for a drawn operator and the agent resolved for it. */
export function buildAssignment(input: {
  entryId: string;
  at: string;
  agent: string;
  operator: string;
  beaconRound: number;
  replacement: boolean;
}): EventInput<"assignment"> {
  return {
    at: input.at,
    type: "assignment",
    entry_id: input.entryId,
    payload: {
      agent: input.agent,
      operator: input.operator,
      beacon_round: input.beaconRound,
      deadline: assignmentDeadline(input.at),
      replacement: input.replacement,
    },
  };
}

/**
 * The `assignment_missed` event. It names the agent and operator that were
 * assigned, so the miss lands on the identity that owes the standing.
 */
export function buildAssignmentMissed(input: {
  entryId: string;
  at: string;
  assignment: OpenAssignment;
}): EventInput<"assignment_missed"> {
  return {
    at: input.at,
    type: "assignment_missed",
    entry_id: input.entryId,
    payload: {
      agent: input.assignment.agent,
      operator: input.assignment.operator,
    },
  };
}

/**
 * The head of the log the caller handed in.
 *
 * The event list arrives in any order and holds the registry events beside the
 * entry's own, so the head is the largest seq present rather than the last
 * element. -1 on an empty list: every real position is at or above 0, so
 * reading "at the head" of nothing folds no events at all.
 */
function headPosition(events: readonly Event[]): number {
  let head = -1;
  for (const event of events) {
    if (event.seq > head) head = event.seq;
  }
  return head;
}

/** The trusted pool at the head of the log, in the pool's canonical form. */
function trustedPoolAtHead(events: readonly Event[]): string[] {
  return canonicalPool([...trustedOperatorsAt(events, headPosition(events))]);
}

/** The newest `pool_snapshot` anywhere in the log, or null. */
function newestPoolSnapshot(events: readonly Event[]): PoolSnapshot | null {
  return latestPoolSnapshot(events, headPosition(events));
}

/** Whether two canonical pools name the same operators. */
function samePool(left: readonly string[], right: readonly string[]): boolean {
  if (left.length !== right.length) return false;
  return left.every((operator, index) => operator === right[index]);
}

/**
 * The pool snapshot that is owed, or null when the log already holds it.
 *
 * Lifecycle of an entry, Validate: "The pool snapshot is committed to the sealed
 * log before the beacon round it uses, so neither can be chosen with the outcome
 * in view." A snapshot is therefore owed whenever the sealed one no longer says
 * what the trusted pool is: the sweep commits this one first and draws against
 * it only on a later round.
 *
 * The answer is the pool in canonical form — sorted and de-duplicated, exactly
 * what `drawValidator` digests — so committing what this returns and drawing
 * against it cannot disagree about the pool.
 *
 * An empty pool that differs from the last snapshot is still owed: an operator
 * leaving the pool is as much a change as one joining, and a log whose snapshot
 * still names them would let a draw pick an operator the registry has untrusted.
 *
 * Pure, and never throws: a verdict, never an exception.
 */
export function poolSnapshotDue(
  events: readonly Event[],
): readonly string[] | null {
  const pool = trustedPoolAtHead(events);
  const snapshot = newestPoolSnapshot(events);
  if (snapshot === null) return pool;
  return samePool(canonicalPool(snapshot.operators), pool) ? null : pool;
}

/** Why no draw is owed for the entry right now. */
export type DrawDueReason =
  | "not_draft"
  | "pool_below_switch"
  | "assignment_open"
  | "awaiting_volunteers";

/** Whether a draw is owed, and whether it is a replacement when it is. */
export type DrawDueVerdict =
  | { due: false; reason: DrawDueReason }
  | { due: true; replacement: boolean };

/** The newest `assignment` for the entry, or null. */
function newestAssignment(
  events: readonly Event[],
  entryId: string,
): Event<"assignment"> | null {
  let newest: Event<"assignment"> | null = null;
  for (const event of inSeqOrder(events)) {
    if (!isType(event, "assignment")) continue;
    if (event.entry_id !== entryId) continue;
    newest = event;
  }
  return newest;
}

/** The newest `validation` on the entry, or null. */
function newestValidation(
  events: readonly Event[],
  entryId: string,
): Event<"validation"> | null {
  let newest: Event<"validation"> | null = null;
  for (const event of inSeqOrder(events)) {
    if (!isType(event, "validation")) continue;
    if (event.entry_id !== entryId) continue;
    newest = event;
  }
  return newest;
}

/** Whether an `assignment_missed` after `assignment` closed it. */
function wasMissed(
  events: readonly Event[],
  entryId: string,
  assignment: Event<"assignment">,
): boolean {
  return inSeqOrder(events).some(
    (event) =>
      event.seq > assignment.seq &&
      event.entry_id === entryId &&
      isType(event, "assignment_missed") &&
      event.payload.operator === assignment.payload.operator,
  );
}

/** Whether the assigned operator answered `assignment` with a validation. */
function wasAnswered(
  events: readonly Event[],
  entryId: string,
  assignment: Event<"assignment">,
): boolean {
  return inSeqOrder(events).some(
    (event) =>
      event.seq > assignment.seq &&
      event.entry_id === entryId &&
      isType(event, "validation") &&
      event.payload.record.operator === assignment.payload.operator,
  );
}

/**
 * Whether the entry is owed a beacon draw, and whether the one it is owed is a
 * replacement.
 *
 * Lifecycle of an entry, Validate: "Two of the three volunteer. The third is
 * assigned from the trusted pool by public randomness", "A miss costs standing,
 * and the next beacon round draws a replacement", and "two approvals against one
 * rejection draw one replacement validator by the same public randomness". Below
 * the switch "there is no replacement draw" and no draw at all, because "two
 * approvals verify" without the drawn third.
 *
 * The verdict is read from the log alone, so the sweep that calls it can be run
 * twice on the same events and reach the same answer both times. `status` and
 * `needsReplacement` come from derivation (src/derive.ts) rather than being
 * recomputed here: nothing in this module derives a field.
 *
 * The order of the checks is the order of the rules. A draft that has run out of
 * lifecycle is not owed a draw; below the switch no draw is legitimate; an
 * assignment already standing is the draw, so a second would supersede a
 * validator still inside their seventy-two hours. Only then does the log say
 * which draw is owed: the first one, the replacement for a miss, or the
 * replacement the 2-1 split calls for. Anything else is an entry waiting on its
 * volunteers, which no draw fixes.
 *
 * Pure, and never throws.
 */
export function drawDue(input: {
  events: readonly Event[];
  entryId: string;
  status: EntryStatus;
  needsReplacement: boolean;
}): DrawDueVerdict {
  if (input.status !== "draft") return { due: false, reason: "not_draft" };
  if (trustedPoolAtHead(input.events).length < TRUSTED_POOL_SWITCH) {
    return { due: false, reason: "pool_below_switch" };
  }
  if (openAssignment(input.events, input.entryId) !== null) {
    return { due: false, reason: "assignment_open" };
  }

  const assignment = newestAssignment(input.events, input.entryId);
  if (assignment === null) return { due: true, replacement: false };

  if (wasMissed(input.events, input.entryId, assignment)) {
    return { due: true, replacement: true };
  }

  if (input.needsReplacement && wasAnswered(input.events, input.entryId, assignment)) {
    // The split is read at the head, so the replacement is owed only while no
    // assignment has been made since the decision that opened it; one already
    // made is the draw this verdict would otherwise ask for a second time.
    const validation = newestValidation(input.events, input.entryId);
    if (validation !== null && assignment.seq < validation.seq) {
      return { due: true, replacement: true };
    }
  }

  return { due: false, reason: "awaiting_volunteers" };
}
