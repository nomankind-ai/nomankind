/**
 * The stakes a dispute and a revalidation request put up, and what became of
 * them.
 *
 * Whitepaper Section 6, "Dispute": "Filing takes a stake, so burner keys cannot
 * dispute for free. A verified operator stakes standing, a bare key stakes a
 * refundable filing fee, and the amounts are published policy. An upheld
 * challenge returns the stake, pays the challenger, overturns the entry ... A
 * failed challenge forfeits the stake and costs the challenger standing, so
 * disputes are for evidence."
 *
 * Section 6, "Revalidate": "Any operator can also request revalidation of an
 * entry inside its window by staking a small amount of standing ... If the check
 * finds the fact changed, the requester gets the stake back plus a
 * challenger-style reward. If the entry holds, the requester loses the stake."
 *
 * This module is pure, exactly as src/bounty.ts is: no I/O, no clock, and no
 * policy number of its own beyond the four it reads from src/policy.ts. Every
 * field of every record is read out of a sealed event, so the ledger rows are
 * DERIVABLE FROM THE LOG and are never a second source of truth. Drop every
 * stake row and the same records come back by replaying the log; a row that
 * disagrees with the log is wrong, and the log is right.
 *
 * Nothing here moves money. Decision D-064: a stake is a ledger row and nothing
 * else until M21 builds the money side, and the amounts in src/policy.ts are
 * placeholders the maintainer sets. A reward's `amount` is null for the same
 * reason src/bounty.ts leaves `amount_cents` null: Section 9's pricing is M21's,
 * and freezing a number into a stored record a milestone early would be
 * inventing a policy that does not exist yet.
 */

import type { Event } from "./events.js";
import {
  DISPUTE_FILING_FEE_CENTS,
  DISPUTE_STAKE_STANDING,
  REVALIDATION_REQUEST_STAKE_STANDING,
} from "./policy.js";

/**
 * What a row says happened to a stake.
 *
 * Four moves per mechanism, and the same four for both: the stake goes up, and
 * then it comes back (refund), is lost (forfeit), or comes back with a reward
 * beside it. A reward is its own row rather than a larger refund so the ledger
 * never has to be read backwards to see what was staked and what was won.
 */
export type StakeKind =
  | "dispute_stake"
  | "dispute_refund"
  | "dispute_forfeit"
  | "dispute_reward"
  | "revalidation_stake"
  | "revalidation_refund"
  | "revalidation_forfeit"
  | "revalidation_reward";

/**
 * One ledger row.
 *
 * `entry_id` is always the DISPUTED or REQUESTED entry — the target — because
 * that is what every dispute and revalidation event is scoped to;
 * `correction_entry_id` names the correction entry when there is one, and
 * `request_seq` the `revalidation_requested` event when there is one.
 *
 * `unit` and `amount` are null together on a reward: Section 9's pricing is
 * M21's, and until it exists a reward is a fact with no number attached. They
 * are never null on a stake, a refund or a forfeit, which are all the same
 * amount as what was put up.
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
  readonly unit: "standing" | "cents" | null;
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
 * What a challenger put up to file.
 *
 * Section 6: "A verified operator stakes standing, a bare key stakes a
 * refundable filing fee." The event's `operator` is what tells the two apart —
 * null is a bare key — so the unit is read out of the log and never guessed.
 */
export function disputeStake(event: Event<"dispute_filed">): StakeRecord {
  const bareKey = event.payload.operator === null;
  return {
    kind: "dispute_stake",
    entry_id: targetOf(event),
    correction_entry_id: event.payload.correction_entry_id,
    request_seq: null,
    agent: event.payload.challenger,
    operator: event.payload.operator,
    unit: bareKey ? "cents" : "standing",
    amount: bareKey ? DISPUTE_FILING_FEE_CENTS : DISPUTE_STAKE_STANDING,
    seq: event.seq,
    at: event.at,
  };
}

/**
 * What the dispute's outcome does to that stake.
 *
 * Section 6: an upheld challenge "returns the stake, pays the challenger", so
 * two rows — the refund of exactly what was staked, and the reward, whose amount
 * M21 prices. A failed challenge "forfeits the stake", so one row, for exactly
 * what was staked. The standing a failed challenge also costs is not a ledger
 * amount and is not invented here.
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
    // Section 9's pricing is M21's. A reward with a made-up number would be a
    // policy nobody decided, so the row records that one is owed and no more.
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
 * Section 6: "If the check finds the fact changed, the requester gets the stake
 * back plus a challenger-style reward. If the entry holds, the requester loses
 * the stake." An upgrade is neither: the request becomes a dispute, so the
 * request's own stake comes back and the dispute's stake (`disputeStake`) takes
 * over from there — the requester is never made to stake twice for one doubt.
 *
 * Empty when the request was auto-opened by failure reports: nothing was staked,
 * so nothing is refunded, forfeited or rewarded.
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
  const refund: StakeRecord = {
    ...base,
    kind: "revalidation_refund",
    unit: staked.unit,
    amount: staked.amount,
  };
  if (resolved.payload.outcome === "upgraded") return [refund];
  // "changed": the stake back plus a challenger-style reward, priced by M21.
  return [refund, { ...base, kind: "revalidation_reward", unit: null, amount: null }];
}
