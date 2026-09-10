/**
 * Who may dispute an entry, who may ask for it to be rechecked, and who may
 * report that it failed them.
 *
 * Whitepaper Section 6, "Dispute": "Verified entries stay open to challenge ...
 * A challenge is itself an entry, in the correction category, and it requires a
 * citation. It passes through the same validation process with one extra
 * exclusion: no operator that signed the original, submitter or validator, may
 * validate the challenge against it."
 *
 * Whitepaper Section 6, "Revalidate": "Any operator can also request
 * revalidation of an entry inside its window by staking a small amount of
 * standing. No citation is needed; the request only asks for a check. It is
 * assigned at random to a trusted operator, the entry keeps earning while the
 * check is pending, and requests are capped per operator per window."
 *
 * Whitepaper Section 8, "Failure reports": "A single report is a signal. A
 * published threshold of reports from distinct operators auto-opens a
 * revalidation at nomankind's expense", and Section 12, "Failure reports can be
 * flooded": "The threshold that auto-opens revalidation counts distinct
 * verified operators only, and revalidation confirms rather than overturns, so
 * the cost of a flood is a wasted check and never a wrong record."
 *
 * This module is a pure check, like src/reconfirm.ts and src/validate.ts. It
 * never throws for a rule refusal, never reads a clock, and holds no policy
 * number of its own: the threshold and the cap reach it from src/policy.ts. A
 * refusal is a value, so a caller can report the reason to the challenger,
 * requester or reporter unchanged. Everything a dispute or a report does to an
 * entry — the disputes[] and failure_reports[] arrays, `overturned_by`, the
 * status — stays derivation's job (src/derive.ts), recomputed from the events.
 *
 * The exclusion the paper names is not enforced here either: it is a validation
 * rule, so it lives with the other validation rules (src/validate.ts's
 * `original_signer`). `disputeExclusions` below only says who the excluded
 * operators are.
 */

import type { Core } from "./core.js";
import type { EntryStatus } from "./derive.js";
import type { ApproverRecord, Event } from "./events.js";
import {
  DEFAULT_DOMAIN,
  FAILURE_REPORT_THRESHOLD,
  REVALIDATION_REQUESTS_PER_OPERATOR_PER_WINDOW,
} from "./policy.js";
import type { StakeRecord } from "./stake.js";

// ---------------------------------------------------------------------------
// Filing a dispute
// ---------------------------------------------------------------------------

/** Every reason a dispute filing can be refused. One string per rule, in check order. */
export type DisputeRefusal =
  | "entry_not_verified"
  | "not_correction"
  | "missing_citation"
  | "subject_mismatch"
  | "self_dispute"
  | "dispute_open";

/** Every refusal, in check order. */
export const DISPUTE_REFUSALS: readonly DisputeRefusal[] = Object.freeze([
  "entry_not_verified",
  "not_correction",
  "missing_citation",
  "subject_mismatch",
  "self_dispute",
  "dispute_open",
] as const);

/** The target as the check reads it: the derived entry, narrowed to what a rule asks. */
export interface DisputeTarget {
  readonly id: string;
  readonly subject: string;
  readonly status: EntryStatus;
}

/** Everything the check needs, gathered by the caller at the filing's position. */
export interface DisputeFilingContext {
  /** The agent filing the challenge. */
  readonly challenger: string;
  /** Its operator, or null for a bare key (which decides the stake, src/stake.ts). */
  readonly challengerOperator: string | null;
  /** Disputes already open on this target. */
  readonly openDisputes: number;
}

/** Accepted, or refused with the reason. */
export type DisputeVerdict =
  | { ok: true }
  | { ok: false; reason: DisputeRefusal };

/**
 * Check one dispute filing against the entry it challenges.
 *
 * Synchronous and pure. Rules are checked in a fixed order and the first
 * refusal wins, so a filing that breaks several rules always reports the same
 * one and a client can fix them one at a time.
 *
 * `correctionCore` is the challenge's own frozen core; `target` is the derived
 * entry it challenges. Nothing here judges the challenge's evidence: it "passes
 * through the same validation process", so its own validators decide, and this
 * only says whether it may be filed at all.
 */
export function checkDisputeFiling(
  correctionCore: Core,
  target: DisputeTarget,
  context: DisputeFilingContext,
): DisputeVerdict {
  // 1. Section 6: "Verified entries stay open to challenge." A draft has not
  // been decided yet, a rejected one was already refused, and an overturned one
  // has already been corrected. A stale entry is still verified (Section 7:
  // past its window an entry stays verified but shows as stale) and may be
  // challenged, which is why staleness is not a gate here.
  if (target.status !== "verified") return refuseDispute("entry_not_verified");

  // 2-3. Section 6: "A challenge is itself an entry, in the correction
  // category, and it requires a citation." Both are facts about the challenge's
  // own signed core, so they are read out of it and never supplied beside it.
  if (correctionCore["category"] !== "correction") {
    return refuseDispute("not_correction");
  }
  const citation = correctionCore["citation"];
  if (typeof citation !== "string" || citation.trim().length === 0) {
    return refuseDispute("missing_citation");
  }

  // 4. A challenge is a claim about the same fact, so it has to be about the
  // same subject; a correction filed against an unrelated entry is a mislink,
  // and the disputes[] row it would produce would say the wrong thing about
  // both entries.
  if (correctionCore["subject"] !== target.subject) {
    return refuseDispute("subject_mismatch");
  }

  // 5. The challenger is the author of the challenge. Filing under someone
  // else's correction would put another agent's stake and standing at risk on a
  // dispute they did not choose to file, and would credit the reward to the
  // wrong key when it is upheld.
  if (correctionCore["author"] !== context.challenger) {
    return refuseDispute("self_dispute");
  }

  // 6. One open dispute at a time. Section 6 gives an upheld challenge the
  // power to overturn the entry outright, so two open challenges could reach
  // opposite verdicts against the same entry with nothing to say which one the
  // log means; and a queue of open filings would be the flooding Section 12
  // warns about, paid for in stakes but wasting the same checks.
  if (context.openDisputes > 0) return refuseDispute("dispute_open");

  return { ok: true };
}

function refuseDispute(reason: DisputeRefusal): DisputeVerdict {
  return { ok: false, reason };
}

// ---------------------------------------------------------------------------
// Standing enough to stake
// ---------------------------------------------------------------------------

/**
 * The one refusal a filing gets for having nothing to put up.
 *
 * Section 9, Standing: it "gates everything discretionary, from entry to and
 * stay in the trusted pool to revalidation-request caps and dispute stakes". A
 * stake that an operator cannot cover is not a stake: the filing would cost
 * nothing to make and nothing to lose, which is exactly the free challenge
 * Section 6 says the stake exists to prevent.
 */
export type StakeCoverRefusal = "insufficient_standing";

/**
 * What the check needs: the operator's standing, what its open stakes already
 * hold, and what this filing would put up. All three in the same unit, standing,
 * and all three the caller's to gather.
 */
export interface StakeCover {
  /** The operator's standing at the position the caller read it at. */
  readonly standing: number;
  /** What its still-open stakes hold: no refund and no forfeit has settled them. */
  readonly locked: number;
  /** What this filing stakes, from src/policy.ts through the caller. */
  readonly stake: number;
}

/** Accepted, or refused with the reason. */
export type StakeCoverVerdict =
  | { ok: true }
  | { ok: false; reason: StakeCoverRefusal };

/**
 * Whether an operator can cover one more stake.
 *
 * Available standing is what it has less what its open stakes already hold: an
 * operator with ten standing and a ten-standing dispute in flight has nothing
 * available, because the standing in flight is already promised to the outcome
 * of that dispute. Without the subtraction one balance could back any number of
 * simultaneous filings, and a challenger could lose more than it ever had.
 *
 * Pure, like every other check here: no clock, no storage, and no policy number
 * of its own — the amount reaches it as `stake`.
 */
export function checkStakeCover(cover: StakeCover): StakeCoverVerdict {
  const available = cover.standing - cover.locked;
  if (available < cover.stake) return { ok: false, reason: "insufficient_standing" };
  return { ok: true };
}

/**
 * What a set of open stake rows holds, in standing.
 *
 * Only the rows whose unit is standing: a bare key's dispute stake is a filing
 * fee in cents (Section 6), it is nobody's standing, and adding it to this total
 * would be adding two units together. A row with no amount is not a stake — a
 * reward carries none — and counts as nothing.
 */
export function lockedStanding(rows: readonly StakeRecord[]): number {
  let locked = 0;
  for (const row of rows) {
    if (row.unit !== "standing" || row.amount === null) continue;
    locked += row.amount;
  }
  return locked;
}

// ---------------------------------------------------------------------------
// Requesting a revalidation
// ---------------------------------------------------------------------------

/** Every reason a revalidation request can be refused, in check order. */
export type RevalidationRefusal =
  | "entry_not_verified"
  | "entry_stale"
  | "bare_key"
  | "operator_not_in_domain"
  | "cap_exceeded"
  | "request_open";

/** Every refusal, in check order. */
export const REVALIDATION_REFUSALS: readonly RevalidationRefusal[] = Object.freeze([
  "entry_not_verified",
  "entry_stale",
  "bare_key",
  "operator_not_in_domain",
  "cap_exceeded",
  "request_open",
] as const);

/** The target as the check reads it. */
export interface RevalidationTarget {
  readonly status: EntryStatus;
  readonly stale: boolean;
  /**
   * The entry's domain, from its signed core (`domainOf`). Absent reads as the
   * default domain, exactly as a legacy v0.6 core does.
   */
  readonly domain?: string;
}

/** Everything the check needs, gathered by the caller at the request's position. */
export interface RevalidationRequestContext {
  /** The requester's operator, or null for a bare key. */
  readonly requesterOperator: string | null;
  /** This operator's requests against this entry inside the current freshness window. */
  readonly requestsThisWindow: number;
  /** Whether a request on this entry is still open. */
  readonly openRequest: boolean;
  /**
   * The domains the requester's operator is attested in (src/derive.ts,
   * `operatorDomainsAt`). Absent reads as the default domain.
   */
  readonly operatorDomains?: readonly string[];
}

/** Accepted, or refused with the reason. */
export type RevalidationVerdict =
  | { ok: true }
  | { ok: false; reason: RevalidationRefusal };

/**
 * Check one revalidation request against the entry it asks about.
 *
 * Synchronous and pure; first refusal wins, in a fixed order.
 */
export function checkRevalidationRequest(
  target: RevalidationTarget,
  context: RevalidationRequestContext,
): RevalidationVerdict {
  // 1. Only a verified entry has anything to recheck.
  if (target.status !== "verified") return refuseRevalidation("entry_not_verified");

  // 2. Section 6 scopes the request to "an entry inside its window". A stale
  // entry is not rechecked, it is reconfirmed: src/reconfirm.ts already lets any
  // trusted operator refresh it, and the bounty (src/bounty.ts) already pays for
  // that. Staking standing to ask for a check of something anyone may refresh
  // for free would be a second, worse door onto the same act.
  if (target.stale) return refuseRevalidation("entry_stale");

  // 3. Section 6: "Any OPERATOR can also request revalidation ... by staking a
  // small amount of standing." A bare key has no standing to stake, so it has no
  // way to make the request cost anything, and a free check is exactly the
  // flood Section 12 names. A bare key that has evidence files a dispute (which
  // it can, on a refundable fee) or a failure report.
  if (context.requesterOperator === null) return refuseRevalidation("bare_key");

  // 3a. Decision D-071: eligibility is per domain, because the independence
  // attestation is. An operator asks for a check of an entry only in a domain
  // it has attested in; standing staked in one domain buys nothing in another.
  const entryDomain = target.domain ?? DEFAULT_DOMAIN;
  const attestedIn = context.operatorDomains ?? [DEFAULT_DOMAIN];
  if (!attestedIn.includes(entryDomain)) {
    return refuseRevalidation("operator_not_in_domain");
  }

  // 4. Section 6: "requests are capped per operator per window." The cap is
  // per operator, per entry, per freshness window (src/policy.ts), so one
  // operator cannot keep one entry permanently under review.
  if (context.requestsThisWindow >= REVALIDATION_REQUESTS_PER_OPERATOR_PER_WINDOW) {
    return refuseRevalidation("cap_exceeded");
  }

  // 5. One open request at a time, for the same reason one dispute is: a second
  // request buys a second check of a question already being checked.
  if (context.openRequest) return refuseRevalidation("request_open");

  return { ok: true };
}

function refuseRevalidation(reason: RevalidationRefusal): RevalidationVerdict {
  return { ok: false, reason };
}

// ---------------------------------------------------------------------------
// Filing a failure report
// ---------------------------------------------------------------------------

/** Every reason a failure report can be refused, in check order. */
export type FailureReportRefusal =
  | "entry_not_verified"
  | "empty_observed"
  | "bad_artifact_hash"
  | "duplicate_reporter";

/** Every refusal, in check order. */
export const FAILURE_REPORT_REFUSALS: readonly FailureReportRefusal[] =
  Object.freeze([
    "entry_not_verified",
    "empty_observed",
    "bad_artifact_hash",
    "duplicate_reporter",
  ] as const);

/** Everything the check needs, gathered by the caller at the report's position. */
export interface FailureReportContext {
  /** The agents that have already reported this entry, in log order. */
  readonly priorReporters: readonly string[];
  readonly reporter: string;
  readonly observed: string;
  readonly artifactHash: string;
}

/** Accepted, or refused with the reason. */
export type FailureReportVerdict =
  | { ok: true }
  | { ok: false; reason: FailureReportRefusal };

/** The schema's artifact_hash pattern, as the failure_reports[] item states it. */
const ARTIFACT_HASH = /^sha256:[0-9a-f]{64}$/;

/**
 * Check one failure report against the entry it is filed against.
 *
 * Synchronous and pure; first refusal wins, in a fixed order. Bare keys may
 * file: Section 8 says readers are "the largest verification pool the log has",
 * and Section 12 accepts the flood risk explicitly, answering it at the
 * threshold (`failureReportThresholdReached`) rather than at the door.
 */
export function checkFailureReport(
  target: { readonly status: EntryStatus },
  context: FailureReportContext,
): FailureReportVerdict {
  // 1. Section 8: a report is filed by "a reader that acts on a VERIFIED entry
  // and fails". Nothing else is being relied on, so nothing else can fail a
  // reader in the way the section means.
  if (target.status !== "verified") return refuseReport("entry_not_verified");

  // 2. The schema: `observed` is "what the reader actually saw, in plain
  // language". An empty one is a vote, not a report, and a vote is what the
  // threshold must not be made of.
  if (context.observed.trim().length === 0) return refuseReport("empty_observed");

  // 3. Section 8: the report carries the failing interaction "with its
  // transcript frozen and hashed like any artifact". The hash is the whole
  // difference between a report and a complaint.
  if (!ARTIFACT_HASH.test(context.artifactHash)) {
    return refuseReport("bad_artifact_hash");
  }

  // 4. One report per agent per entry. Without it, one key could carry the
  // threshold on its own by filing the same observation repeatedly; the
  // threshold counts distinct verified operators, and this keeps the array it
  // counts over honest as well.
  if (context.priorReporters.includes(context.reporter)) {
    return refuseReport("duplicate_reporter");
  }

  return { ok: true };
}

function refuseReport(reason: FailureReportRefusal): FailureReportVerdict {
  return { ok: false, reason };
}

/**
 * Whether the reports on an entry have reached the threshold that auto-opens a
 * revalidation.
 *
 * Section 12, "Failure reports can be flooded": "Bare keys can file them, so a
 * campaign can manufacture volume against a true entry. The threshold that
 * auto-opens revalidation counts distinct VERIFIED OPERATORS only." So a report
 * with a null operator never counts, a report naming an operator the registry
 * does not hold never counts, and several reports under one operator count once.
 * Three bare keys open nothing; three registered operators open a check.
 *
 * `registeredOperators` is the registry as of the newest report's position,
 * gathered by the caller (src/derive.ts's `registeredOperatorsAt`), so the count
 * is judged at the log position it is asked at and never against a registry that
 * moved later.
 */
export function failureReportThresholdReached(
  reports: readonly Event<"failure_report">[],
  registeredOperators: ReadonlySet<string>,
): boolean {
  const counted = new Set<string>();
  for (const report of reports) {
    const { operator } = report.payload;
    if (operator === null) continue;
    if (!registeredOperators.has(operator)) continue;
    counted.add(operator);
  }
  return counted.size >= FAILURE_REPORT_THRESHOLD;
}

// ---------------------------------------------------------------------------
// Exclusions
// ---------------------------------------------------------------------------

/**
 * The operators barred from validating a challenge against this entry.
 *
 * Section 6: "no operator that signed the original, submitter or validator, may
 * validate the challenge against it." So: the submitter's operator when it has
 * one — a bare-key submitter bars nobody, having no operator to bar — and every
 * operator that signed a decision on the original, approve or reject alike. A
 * validator that rejected the entry still signed it, and letting it judge the
 * challenge would be letting it re-argue its own vote.
 *
 * In order, without repeats, so the list reads the same every time.
 */
export function disputeExclusions(target: {
  readonly author_operator: string | null;
  readonly approvers: readonly ApproverRecord[];
}): string[] {
  const excluded: string[] = [];
  const seen = new Set<string>();
  const add = (operator: string | null): void => {
    if (operator === null || seen.has(operator)) return;
    seen.add(operator);
    excluded.push(operator);
  };
  add(target.author_operator);
  for (const approver of target.approvers) add(approver.operator);
  return excluded;
}

/**
 * The operators barred from the random draw for a revalidation check.
 *
 * Section 6, "Revalidate": the request "is assigned at random to a trusted
 * operator", and the exception that mirrors validation bars the submitter's
 * own. The requester's operator is barred too: an operator that paid for a
 * check and then drew itself as the checker would be answering its own
 * question, and either outcome — the stake back plus a reward, or the stake
 * forfeited — would be its own to decide.
 *
 * The original's other signers are NOT barred here. A revalidation is a
 * recheck, not a challenge: Section 12 says "revalidation confirms rather than
 * overturns", so it does not carry the dispute's extra exclusion.
 */
export function revalidationDrawExclusions(
  authorOperator: string | null,
  requesterOperator: string | null,
): string[] {
  const excluded: string[] = [];
  if (authorOperator !== null) excluded.push(authorOperator);
  if (requesterOperator !== null && requesterOperator !== authorOperator) {
    excluded.push(requesterOperator);
  }
  return excluded;
}

// ---------------------------------------------------------------------------
// Reading the target's own events
// ---------------------------------------------------------------------------

/** The events in seq order, without mutating the caller's array. */
function inSeqOrder(events: readonly Event[]): readonly Event[] {
  return [...events].sort((left, right) => left.seq - right.seq);
}

/**
 * The entry's open revalidation request, or null.
 *
 * Open means requested and not yet resolved. `events` is the target's own
 * sub-sequence of the log; a request is closed by a `revalidation_resolved`
 * naming its position, and a missed assignment closes the assignment, never the
 * request — Section 6's check is still owed, and the next draw answers it.
 */
export function openRevalidation(
  events: readonly Event[],
): Event<"revalidation_requested"> | null {
  const resolved = new Set<number>();
  for (const event of events) {
    if (event.type !== "revalidation_resolved") continue;
    resolved.add((event as Event<"revalidation_resolved">).payload.request_seq);
  }
  let open: Event<"revalidation_requested"> | null = null;
  for (const event of inSeqOrder(events)) {
    if (event.type !== "revalidation_requested") continue;
    if (resolved.has(event.seq)) continue;
    open = event as Event<"revalidation_requested">;
  }
  return open;
}

/**
 * The entry's open dispute, or null.
 *
 * Open means filed and neither upheld nor failed, matched by the correction
 * entry the outcome names: the target may have been disputed before, and an old
 * resolved challenge must not read as the open one.
 */
export function openDispute(
  events: readonly Event[],
): Event<"dispute_filed"> | null {
  const settled = new Set<string>();
  for (const event of events) {
    if (event.type === "dispute_upheld") {
      settled.add((event as Event<"dispute_upheld">).payload.correction_entry_id);
    } else if (event.type === "dispute_failed") {
      settled.add((event as Event<"dispute_failed">).payload.correction_entry_id);
    }
  }
  let open: Event<"dispute_filed"> | null = null;
  for (const event of inSeqOrder(events)) {
    if (event.type !== "dispute_filed") continue;
    const filed = event as Event<"dispute_filed">;
    if (settled.has(filed.payload.correction_entry_id)) continue;
    open = filed;
  }
  return open;
}

/**
 * How many revalidation requests one operator has made against this entry
 * inside the current freshness window: the count `cap_exceeded` is measured
 * against.
 *
 * `windowStartAt` is the instant the current window opened — the entry's
 * `last_confirmed`, which derivation already computes — so the cap resets when
 * the window does, exactly as Section 6's "per operator per window" says. The
 * comparison is on the event's own sealed `at`, so a request cannot be dated out
 * of the window it was made in.
 */
export function requestsByOperatorInWindow(
  events: readonly Event[],
  operator: string,
  windowStartAt: string,
): number {
  let count = 0;
  for (const event of events) {
    if (event.type !== "revalidation_requested") continue;
    const request = event as Event<"revalidation_requested">;
    if (request.payload.operator !== operator) continue;
    if (request.at < windowStartAt) continue;
    count += 1;
  }
  return count;
}
