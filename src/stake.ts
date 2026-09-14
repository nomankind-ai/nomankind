/**
 * The stakes a dispute and a revalidation request put up, and what became of
 * them.
 *
 * Whitepaper Section 6, "Dispute": "Filing takes a stake, so burner keys cannot
 * dispute for free. A verified operator stakes standing ... An upheld
 * challenge returns the stake, pays the challenger, overturns the entry ... A
 * failed challenge forfeits the stake and costs the challenger standing, so
 * disputes are for evidence."
 *
 * Section 6, "Revalidate": "Any operator can also request revalidation of an
 * entry inside its window by staking a small amount of standing ... If the entry
 * holds, the requester loses the stake." A request puts up a stake and wins no
 * reward of its own: a check that turns up a citation "can be upgraded into a
 * dispute", and the reward on that is the dispute's, priced from what the
 * overturned entry lost.
 *
 * This module is pure, exactly as src/bounty.ts is: no I/O, no clock, and no
 * policy number of its own beyond the four it reads from src/policy.ts. Every
 * field of every record is read out of a sealed event, so the ledger rows are
 * DERIVABLE FROM THE LOG and are never a second source of truth. Drop every
 * stake row and the same records come back by replaying the log; a row that
 * disagrees with the log is wrong, and the log is right.
 *
 * One row here is priced elsewhere. `dispute_reward` is written at the outcome
 * with no amount — the fact that a reward is owed, at the position it became
 * owed — and the sweep's ledger step prices it when it writes the overturned
 * entry's clawbacks, because the price IS those clawbacks (src/ledger.ts's
 * `disputeRewardRow`). This module never sees them: the clawbacks are a fact
 * about the money side of the same event, and a number invented here would be a
 * second answer to a question src/ledger.ts already answers.
 */

import type { Event } from "./events.js";
import {
  DISPUTE_STAKE_STANDING,
  REVALIDATION_REQUEST_STAKE_STANDING,
} from "./policy.js";

/**
 * What a row says happened to a stake.
 *
 * The stake goes up, and then it comes back (refund) or is lost (forfeit). A
 * dispute has a fourth move, the reward an upheld challenge is paid, and it is
 * its own row rather than a larger refund so the ledger never has to be read
 * backwards to see what was staked and what was won.
 *
 * A revalidation request has no reward of its own: Section 6 upgrades a check
 * that turns up a citation into a dispute, and the reward on that is the
 * dispute's — one reward per doubt, priced from the entry it overturned.
 */
export type StakeKind =
  | "dispute_stake"
  | "dispute_refund"
  | "dispute_forfeit"
  | "dispute_reward"
  | "revalidation_stake"
  | "revalidation_refund"
  | "revalidation_forfeit";

/**
 * One ledger row.
 *
 * `entry_id` is always the DISPUTED or REQUESTED entry — the target — because
 * that is what every dispute and revalidation event is scoped to;
 * `correction_entry_id` names the correction entry when there is one, and
 * `request_seq` the `revalidation_requested` event when there is one.
 *
 * `unit` and `amount` are null together on a reward as this module writes one: a
 * reward is a fact with no number attached until the ledger step reaches the
 * position it was owed at and prices it from the clawbacks, in `micros`. They
 * are never null on a stake, a refund or a forfeit, which are all the same
 * amount as what was put up, and on all three the unit is `standing`: since
 * D-127 there is no fee and no second currency to put up. `cents` stays in the
 * union because a row read back out of a mirror sealed before that decision
 * still says so, and a reader has to be able to name what it says.
 *
 * `seq` and `at` are the position and instant of the event that produced the
 * row, so a reader can find the event a row came from without searching.
 */
export interface StakeRecord {
  readonly kind: StakeKind;
  readonly entry_id: string;
  readonly correction_entry_id: string | null;
  readonly request_seq: number | null;
  /** The agent that staked: the challenger, or the requester. Null when nomankind opened the check itself. */
  readonly agent: string | null;
  /** The operator that staked, or null for a bare key (and for nomankind's own check). */
  readonly operator: string | null;
  readonly unit: "standing" | "cents" | "micros" | null;
  readonly amount: number | null;
  readonly seq: number;
  readonly at: string;
}

/** The entry_id of an entry-scoped event, which `appendEvent` guarantees is there. */
function targetOf(event: Event): string {
  if (event.entry_id === null) {
    throw new TypeError(`${event.type}: expected an entry_id`);
  }
  return event.entry_id;
}

/**
 * What a challenger put up to file: standing, and only ever standing.
 *
 * Section 6 has a bare key stake "a refundable filing fee" instead, and D-127
 * supersedes that half of the sentence: there is no money anywhere in this
 * record, so there is no fee to stake and contribution is the only currency a
 * filing can put up. A bare key holds none of it and so cannot file at all —
 * the dispute door refuses the filing before it reaches here, with the refusal
 * it already had for a challenger who cannot cover the stake,
 * `insufficient_standing` (src/dispute.ts, `checkStakeCover`: available
 * standing zero against a stake of DISPUTE_STAKE_STANDING).
 *
 * So the row is one shape now. `operator` is still read out of the log and
 * still carried, because the log is what a row is derived from and a legacy
 * filing must keep replaying to the same position it occupied; what it no
 * longer does is choose a unit.
 */
export function disputeStake(event: Event<"dispute_filed">): StakeRecord {
  return {
    kind: "dispute_stake",
    entry_id: targetOf(event),
    correction_entry_id: event.payload.correction_entry_id,
    request_seq: null,
    agent: event.payload.challenger,
    operator: event.payload.operator,
    unit: "standing",
    amount: DISPUTE_STAKE_STANDING,
    seq: event.seq,
    at: event.at,
  };
}

/**
 * What the dispute's outcome does to that stake.
 *
 * Section 6: an upheld challenge "returns the stake, pays the challenger", so
 * two rows — the refund of exactly what was staked, and the reward, which the
 * ledger step prices from the clawbacks of the same event. A failed challenge
 * "forfeits the stake", so one row, for exactly what was staked. The standing a
 * failed challenge also costs is not a ledger amount and is not invented here.
 *
 * The rows carry the OUTCOME event's seq and instant, not the filing's: they
 * happened when the dispute resolved.
 */
export function disputeOutcomeStakes(
  filed: Event<"dispute_filed">,
  outcome: Event<"dispute_upheld"> | Event<"dispute_failed">,
): StakeRecord[] {
  const staked = disputeStake(filed);
  const base = {
    entry_id: staked.entry_id,
    correction_entry_id: staked.correction_entry_id,
    request_seq: null,
    agent: staked.agent,
    operator: staked.operator,
    seq: outcome.seq,
    at: outcome.at,
  } as const;

  if (outcome.type === "dispute_failed") {
    return [
      { ...base, kind: "dispute_forfeit", unit: staked.unit, amount: staked.amount },
    ];
  }
  return [
    { ...base, kind: "dispute_refund", unit: staked.unit, amount: staked.amount },
    // What the reward is worth is what the overturned entry lost, and that is
    // not known until the clawbacks are written. The row records that one is
    // owed, at the position it became owed; src/ledger.ts prices it there.
    { ...base, kind: "dispute_reward", unit: null, amount: null },
  ];
}

/**
 * What a requester put up to ask for a check, or null when nobody put anything
 * up.
 *
 * Section 8: a threshold of failure reports auto-opens a revalidation "at
 * nomankind's expense". Nomankind stakes nothing against itself, so a request
 * whose source is `failure_reports` produces no row at all, and its resolution
 * produces none either.
 */
export function revalidationStake(
  event: Event<"revalidation_requested">,
): StakeRecord | null {
  if (event.payload.source === "failure_reports") return null;
  return {
    kind: "revalidation_stake",
    entry_id: targetOf(event),
    correction_entry_id: null,
    request_seq: event.seq,
    agent: event.payload.requester,
    operator: event.payload.operator,
    unit: "standing",
    amount: REVALIDATION_REQUEST_STAKE_STANDING,
    seq: event.seq,
    at: event.at,
  };
}

/**
 * What the check's outcome does to that stake.
 *
 * Section 6: "If the entry holds, the requester loses the stake", so one forfeit
 * row for exactly what was put up. A check that found the fact changed gets the
 * stake back and no more: the request staked for a check and got one, and the
 * reward Section 6 pays is the dispute's — "a request that turns up a citation
 * can be upgraded into a dispute", and that dispute files its own stake and
 * earns its own reward, priced from the entry it overturns.
 *
 * An upgrade is the same refund for the same reason: the request becomes a
 * dispute, so the request's own stake comes back and the dispute's stake
 * (`disputeStake`) takes over from there — the requester is never made to stake
 * twice for one doubt.
 *
 * Empty when the request was auto-opened by failure reports: nothing was staked,
 * so nothing is refunded and nothing is forfeited.
 */
export function revalidationOutcomeStakes(
  requested: Event<"revalidation_requested">,
  resolved: Event<"revalidation_resolved">,
): StakeRecord[] {
  const staked = revalidationStake(requested);
  if (staked === null) return [];

  const base = {
    entry_id: staked.entry_id,
    correction_entry_id: resolved.payload.correction_entry_id,
    request_seq: requested.seq,
    agent: staked.agent,
    operator: staked.operator,
    seq: resolved.seq,
    at: resolved.at,
  } as const;

  if (resolved.payload.outcome === "held") {
    return [
      {
        ...base,
        kind: "revalidation_forfeit",
        unit: staked.unit,
        amount: staked.amount,
      },
    ];
  }
  // "changed" and "upgraded" alike: the stake back, and nothing beside it.
  return [
    {
      ...base,
      kind: "revalidation_refund",
      unit: staked.unit,
      amount: staked.amount,
    },
  ];
}
