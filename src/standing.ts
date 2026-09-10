/**
 * Standing: the non-monetary record of being right, recomputed from the log.
 *
 * Whitepaper Section 9, "Standing": "Standing is not a score nomankind assigns.
 * It is derived from the sealed public events by a published formula, so anyone
 * can recompute anyone's standing from the log and get the same number." That
 * sentence is this module's whole specification, and everything below follows
 * from it: the fold is pure, it takes the events and a position and nothing
 * else, it reads every amount out of src/policy.ts, and it never stores what it
 * computed. Drop every standing column in the database and the same numbers come
 * back by replaying the log; a column that disagrees with the log is wrong, and
 * the log is right.
 *
 * "It is earned by approved submissions, completed validations (assigned work
 * weighted highest), rejections that hold, and upheld challenges. It is burned
 * by overturned entries you signed, failed challenges, wrong reconfirmations,
 * and missed assignments." Each of those is one case of the fold below, and
 * nothing else in the log moves standing.
 *
 * "It decays when the work it came from stops being read or was never used ...
 * Decay is paused until the paid loop starts." So there is no decay term here at
 * all while `STANDING_DECAY_PAUSED` holds: not a rate of zero, which would be a
 * number nobody published, but no term.
 *
 * `position` is the log position the answer is as of. Only events with
 * seq <= position are folded, for the same reason every other retrospective
 * question in this system is asked at a position (M8): what an operator's
 * standing was when a decision was made must not change because the log grew
 * afterwards.
 */

import type { ApproverRecord, Event, EventType } from "./events.js";
import {
  deriveEntry,
  registeredOperatorsAt,
  trustedOperatorsAt,
} from "./derive.js";
import { isProviderDomain } from "./registry.js";
import {
  DISPUTE_STAKE_STANDING,
  REVALIDATION_REQUEST_STAKE_STANDING,
  STANDING_ASSIGNMENT_MISSED,
  STANDING_DISPUTE_UPHELD,
  STANDING_OVERTURNED_SIGNER,
  STANDING_SUBMISSION_VERIFIED,
  STANDING_TRUSTED_ENTRY,
  STANDING_TRUSTED_STAY,
  STANDING_VALIDATION_ASSIGNED,
  STANDING_VALIDATION_VOLUNTEERED,
} from "./policy.js";

/**
 * What an operator did, counted. The numbers beside `standing` are what make an
 * operator page checkable: a reader who disagrees with the total can see which
 * of the seven kinds of move it came from.
 */
export interface StandingCounts {
  readonly validations_volunteered: number;
  readonly validations_assigned: number;
  readonly submissions_verified: number;
  readonly disputes_upheld: number;
  readonly overturned: number;
  readonly missed: number;
  readonly forfeits: number;
}

/**
 * One operator's standing at a position.
 *
 * `locked` is what open stakes are holding: a filed dispute and an open
 * revalidation request each lock their stake until the outcome lands
 * (src/stake.ts writes the ledger rows; this is the standing side of the same
 * fact). `available` is what is left to stake with, which is the number every
 * cap and every stake is checked against.
 */
export interface Standing {
  readonly operator: string;
  readonly earned: number;
  readonly burned: number;
  readonly locked: number;
  /** earned - burned. */
  readonly standing: number;
  /** standing - locked. */
  readonly available: number;
  readonly counts: StandingCounts;
  /** The log position this answer is as of. */
  readonly position: number;
}

/** The mutable accumulator the fold works on. */
interface Accumulator {
  operator: string;
  earned: number;
  burned: number;
  locked: number;
  validations_volunteered: number;
  validations_assigned: number;
  submissions_verified: number;
  disputes_upheld: number;
  overturned: number;
  missed: number;
  forfeits: number;
}

/**
 * The policy names the fold reads, in the order the formula applies them.
 *
 * Published beside the numbers themselves, because Section 9 promises a
 * published formula and a formula whose terms are not named is not published.
 * Every string here is a key of POLICY (test/policy.test.ts holds that), so the
 * endpoint that serves this can serve the amounts beside the names without a
 * second list that could drift.
 */
export const STANDING_FORMULA: readonly string[] = Object.freeze([
  "STANDING_VALIDATION_VOLUNTEERED",
  "STANDING_VALIDATION_ASSIGNED",
  "STANDING_SUBMISSION_VERIFIED",
  "STANDING_DISPUTE_UPHELD",
  "STANDING_OVERTURNED_SIGNER",
  "STANDING_ASSIGNMENT_MISSED",
  "DISPUTE_STAKE_STANDING",
  "REVALIDATION_REQUEST_STAKE_STANDING",
  "STANDING_DECAY_PAUSED",
]);

function isType<T extends EventType>(event: Event, type: T): event is Event<T> {
  return event.type === type;
}

/** Events with seq <= position, in seq order, without mutating the input. */
function folded(events: readonly Event[], position: number): readonly Event[] {
  return [...events]
    .filter((event) => event.seq <= position)
    .sort((left, right) => left.seq - right.seq);
}

function empty(operator: string): Accumulator {
  return {
    operator,
    earned: 0,
    burned: 0,
    locked: 0,
    validations_volunteered: 0,
    validations_assigned: 0,
    submissions_verified: 0,
    disputes_upheld: 0,
    overturned: 0,
    missed: 0,
    forfeits: 0,
  };
}

function freeze(accumulator: Accumulator, position: number): Standing {
  const standing = accumulator.earned - accumulator.burned;
  return {
    operator: accumulator.operator,
    earned: accumulator.earned,
    burned: accumulator.burned,
    locked: accumulator.locked,
    standing,
    available: standing - accumulator.locked,
    counts: {
      validations_volunteered: accumulator.validations_volunteered,
      validations_assigned: accumulator.validations_assigned,
      submissions_verified: accumulator.submissions_verified,
      disputes_upheld: accumulator.disputes_upheld,
      overturned: accumulator.overturned,
      missed: accumulator.missed,
      forfeits: accumulator.forfeits,
    },
    position,
  };
}

/** The zero record: an operator the log has never mentioned owns nothing. */
export function zeroStanding(operator: string, position: number): Standing {
  return freeze(empty(operator), position);
}

/**
 * Every operator that signed the entry, once each, as of `through`.
 *
 * Section 6: an upheld challenge "overturns the entry ... and claws back what
 * the approvers earned on it", and Section 9 burns "overturned entries you
 * signed". Who signed is the core's author operator, every approver that
 * approved — a rejection argued against the entry and is not a signature on it —
 * and every reconfirmer, because Section 9 says a wrong reconfirmation is
 * "clawed back exactly like a wrong approval".
 */
function signersOf(
  events: readonly Event[],
  entryId: string,
  through: number,
): Set<string> {
  const signers = new Set<string>();
  for (const event of events) {
    if (event.seq > through) break;
    if (event.entry_id !== entryId) continue;
    if (isType(event, "entry_submitted")) {
      const author = event.payload.core["author_operator"];
      if (typeof author === "string") signers.add(author);
      continue;
    }
    if (isType(event, "validation")) {
      const record = event.payload.record as ApproverRecord;
      if (record.decision === "approve") signers.add(record.operator);
      continue;
    }
    if (isType(event, "reconfirmation")) {
      signers.add(event.payload.record.operator);
    }
  }
  return signers;
}

/**
 * The dispute filing an outcome resolves: the newest `dispute_filed` on the same
 * entry naming the same correction, at or before the outcome.
 *
 * Newest rather than first because Section 6 lets a target be challenged more
 * than once; the correction entry is what ties an outcome to its filing, and two
 * open filings naming one correction would be the same challenge filed twice.
 */
function filingFor(
  events: readonly Event[],
  outcome: Event,
  correctionEntryId: string,
): Event<"dispute_filed"> | null {
  let found: Event<"dispute_filed"> | null = null;
  for (const event of events) {
    if (event.seq > outcome.seq) break;
    if (!isType(event, "dispute_filed")) continue;
    if (event.entry_id !== outcome.entry_id) continue;
    if (event.payload.correction_entry_id !== correctionEntryId) continue;
    found = event;
  }
  return found;
}

/** The `revalidation_requested` event at `requestSeq`, or null. */
function requestAt(
  events: readonly Event[],
  requestSeq: number,
): Event<"revalidation_requested"> | null {
  for (const event of events) {
    if (event.seq > requestSeq) break;
    if (event.seq !== requestSeq) continue;
    if (isType(event, "revalidation_requested")) return event;
  }
  return null;
}

/**
 * Every operator's standing as of `position`, by the published formula.
 *
 * The fold runs once over the events in seq order. Every registered operator has
 * a record whether or not it has ever moved, so an operator page never has to
 * tell "nothing yet" from "unknown", and so does every operator the fold touches
 * — a challenger, a checker, a signer of an overturned entry.
 */
export function standingAt(
  events: readonly Event[],
  position: number,
): Map<string, Standing> {
  const ordered = folded(events, position);
  const records = new Map<string, Accumulator>();

  const of = (operator: string): Accumulator => {
    const existing = records.get(operator);
    if (existing !== undefined) return existing;
    const created = empty(operator);
    records.set(operator, created);
    return created;
  };

  // Registered but idle is a real answer, and a different one from unknown.
  for (const operator of registeredOperatorsAt(events, position).operators) {
    of(operator);
  }

  /** Entries whose submission credit has already been paid, once each. */
  const credited = new Set<string>();
  /** Entry -> the operators already burned for signing it, once each. */
  const burnedSigners = new Map<string, Set<string>>();

  for (const event of ordered) {
    if (isType(event, "validation")) {
      const record = event.payload.record as ApproverRecord;
      const validator = of(record.operator);
      if (record.assigned_random) {
        validator.earned += STANDING_VALIDATION_ASSIGNED;
        validator.validations_assigned += 1;
      } else {
        validator.earned += STANDING_VALIDATION_VOLUNTEERED;
        validator.validations_volunteered += 1;
      }

      // "Earned by approved submissions": the submitter's operator is paid the
      // first time the entry actually derives verified, which is a question
      // about the whole log up to here and not about this one decision. The
      // clock is the event's own instant, so the answer cannot depend on when
      // anyone asked.
      const entryId = event.entry_id;
      if (entryId === null || credited.has(entryId)) continue;
      const derived = deriveEntry(
        ordered.filter((candidate) => candidate.seq <= event.seq),
        entryId,
        { now: event.at },
      );
      if (derived.derived.status !== "verified") continue;
      credited.add(entryId);
      const author = derived.entry["author_operator"];
      if (typeof author !== "string") continue;
      const submitter = of(author);
      submitter.earned += STANDING_SUBMISSION_VERIFIED;
      submitter.submissions_verified += 1;
      continue;
    }

    if (isType(event, "reconfirmation")) {
      // A reconfirmation is a volunteered check: nobody was drawn for it.
      const reconfirmer = of(event.payload.record.operator);
      reconfirmer.earned += STANDING_VALIDATION_VOLUNTEERED;
      reconfirmer.validations_volunteered += 1;
      continue;
    }

    if (isType(event, "assignment_missed") || isType(event, "revalidation_missed")) {
      const missed = of(event.payload.operator);
      missed.burned += STANDING_ASSIGNMENT_MISSED;
      missed.missed += 1;
      continue;
    }

    if (isType(event, "dispute_filed")) {
      // A bare key stakes a filing fee and no standing (Section 6), so there is
      // nothing to lock and no operator to lock it against.
      const operator = event.payload.operator;
      if (operator === null) continue;
      of(operator).locked += DISPUTE_STAKE_STANDING;
      continue;
    }

    if (isType(event, "dispute_upheld")) {
      const filing = filingFor(
        ordered,
        event,
        event.payload.correction_entry_id,
      );
      const challenger = filing?.payload.operator ?? null;
      if (challenger !== null) {
        const record = of(challenger);
        record.locked -= DISPUTE_STAKE_STANDING;
        record.earned += STANDING_DISPUTE_UPHELD;
        record.disputes_upheld += 1;
      }

      const entryId = event.entry_id;
      if (entryId === null) continue;
      let burned = burnedSigners.get(entryId);
      if (burned === undefined) {
        burned = new Set<string>();
        burnedSigners.set(entryId, burned);
      }
      for (const signer of signersOf(ordered, entryId, event.seq)) {
        if (burned.has(signer)) continue;
        burned.add(signer);
        const record = of(signer);
        record.burned += STANDING_OVERTURNED_SIGNER;
        record.overturned += 1;
      }
      continue;
    }

    if (isType(event, "dispute_failed")) {
      const filing = filingFor(
        ordered,
        event,
        event.payload.correction_entry_id,
      );
      const challenger = filing?.payload.operator ?? null;
      if (challenger === null) continue;
      const record = of(challenger);
      record.locked -= DISPUTE_STAKE_STANDING;
      record.burned += DISPUTE_STAKE_STANDING;
      record.forfeits += 1;
      continue;
    }

    if (isType(event, "revalidation_requested")) {
      // Section 8: a check auto-opened by failure reports is at nomankind's
      // expense, so nobody staked and nothing is locked.
      if (event.payload.source !== "operator") continue;
      const operator = event.payload.operator;
      if (operator === null) continue;
      of(operator).locked += REVALIDATION_REQUEST_STAKE_STANDING;
      continue;
    }

    if (isType(event, "revalidation_resolved")) {
      const request = requestAt(ordered, event.payload.request_seq);
      const requester =
        request === null || request.payload.source !== "operator"
          ? null
          : request.payload.operator;
      if (requester !== null) {
        const record = of(requester);
        record.locked -= REVALIDATION_REQUEST_STAKE_STANDING;
        if (event.payload.outcome === "held") {
          // "If the entry holds, the requester loses the stake."
          record.burned += REVALIDATION_REQUEST_STAKE_STANDING;
          record.forfeits += 1;
        }
      }

      // The drawn checker did assigned work, and is paid for it whatever the
      // outcome was: Section 9 pays completed validations, not agreeable ones.
      const checker = event.payload.operator;
      if (checker === null) continue;
      const record = of(checker);
      record.earned += STANDING_VALIDATION_ASSIGNED;
      record.validations_assigned += 1;
      continue;
    }
  }

  const standings = new Map<string, Standing>();
  for (const [operator, accumulator] of records) {
    standings.set(operator, freeze(accumulator, position));
  }
  return standings;
}

/** One operator's standing as of `position`; the zero record when unknown. */
export function standingOf(
  events: readonly Event[],
  operator: string,
  position: number,
): Standing {
  return standingAt(events, position).get(operator) ?? zeroStanding(operator, position);
}

/** What the sweep should change about the trusted pool at a position. */
export interface TrustChanges {
  readonly trust: string[];
  readonly untrust: string[];
}

/**
 * Who standing says should enter the trusted pool, and who should leave it.
 *
 * Section 9: standing "gates everything discretionary, from entry to and stay in
 * the trusted pool". Section 10: "No lab or model provider may be a maintainer,
 * funder, or trusted operator", and the maintainer's own operator is never an
 * outside operator either (src/derive.ts asks the same of a validator), so
 * neither is ever trusted however much standing it has.
 *
 * Pure and idempotent: an operator already trusted is not in `trust`, and the
 * answer at a position never changes as the log grows past it. Applying it — the
 * events, the rows — is the sweep's job and not this module's.
 */
export function trustChangesAt(
  events: readonly Event[],
  position: number,
): TrustChanges {
  const standings = standingAt(events, position);
  const registered = registeredOperatorsAt(events, position);
  const trusted = trustedOperatorsAt(events, position);

  const standingOfOperator = (operator: string): number =>
    standings.get(operator)?.standing ?? 0;

  const trust: string[] = [];
  for (const operator of registered.operators) {
    if (trusted.has(operator)) continue;
    if (registered.maintainers.has(operator)) continue;
    if (isProviderDomain(operator)) continue;
    if (standingOfOperator(operator) < STANDING_TRUSTED_ENTRY) continue;
    trust.push(operator);
  }

  const untrust: string[] = [];
  for (const operator of trusted) {
    if (standingOfOperator(operator) >= STANDING_TRUSTED_STAY) continue;
    untrust.push(operator);
  }

  trust.sort();
  untrust.sort();
  return { trust, untrust };
}
