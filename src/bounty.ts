/**
 * The reconfirmation bounty an entry accrued while it was stale.
 *
 * Whitepaper Section 7, "Freshness and decay": "Past its window an entry stays
 * verified but shows as stale ... Stale entries earn half rate, and the withheld
 * half builds up on the entry as a reconfirmation bounty, paid to whoever makes
 * it fresh again." Section 9, Incentives / Money, says the same from the money
 * side: "Reconfirming a stale entry pays the accrued bounty and rotates the
 * reconfirmer into one of the three validator read-share slots for the window it
 * reopened."
 *
 * This module records that a bounty came due and to whom, and nothing else. It
 * is pure: no I/O, no clock, no policy number. Every field is read out of the
 * derived entry as it stood before the reconfirmation and out of the sealed
 * reconfirmation event, so the record is DERIVABLE FROM THE LOG and the derived
 * entry and is never a second source of truth. Drop every bounty row and the
 * same records come back by replaying the log; a row that disagrees with the log
 * is wrong, and the log is right.
 *
 * `amount_micros` is null at the door on purpose. The accrual says that a
 * bounty came due and over what window; what it is worth is the sum of the
 * halves the entry withheld while it was stale, which is a question about the
 * entry's `bounty_pool` rows and not about this event. src/ledger.ts prices it
 * (`bountyAccrualRow`), in the integer micro-USD every read-revenue amount is
 * counted in. Policy numbers live in src/policy.ts and nowhere else.
 */

import type { Event } from "./events.js";

/**
 * One accrual: the entry that went stale, the operator that made it fresh
 * again, the window it was stale for, and the position in the log where the
 * bounty came due.
 */
export interface BountyAccrual {
  readonly kind: "bounty_accrual";
  readonly entry_id: string;
  /** The reconfirming operator, read out of the record it signed. */
  readonly operator: string;
  /**
   * The last date the entry was fresh: the `expires_at` it carried before the
   * reconfirmation, a date in the schema's `date` format. Accrual runs from
   * here.
   */
  readonly stale_from: string;
  /** The reconfirmation's own `at`: the instant the entry became fresh again. */
  readonly stale_until: string;
  /** The reconfirmation event's position in the log. */
  readonly seq: number;
  /**
   * The bounty in micro-USD, or null when it has not been priced yet. Null at
   * the door: src/ledger.ts sums the entry's withheld pool rows over exactly
   * the window above and fills it.
   */
  readonly amount_micros: number | null;
}

/**
 * The bounty a reconfirmation collects, or null when there is none.
 *
 * Null when the entry was not stale at the moment the reconfirmation landed: a
 * reconfirmation inside the window is welcome — Section 6 lets any trusted
 * operator refresh a verified entry — but nothing accrued, so there is nothing
 * to pay. An entry with no `expires_at` is an event-category entry with no
 * window at all, which can never go stale and so can never build a bounty.
 *
 * `before` is the entry as derivation left it *before* this reconfirmation was
 * folded in; deriving after the fact would find the window already reopened and
 * `stale` already false, and would never see a bounty at all.
 */
export function bountyAccrual(
  before: { expires_at: string | null; stale: boolean },
  reconfirmation: Event<"reconfirmation">,
): BountyAccrual | null {
  if (!before.stale || before.expires_at === null) return null;
  if (reconfirmation.entry_id === null) {
    throw new TypeError("bountyAccrual: reconfirmation has no entry_id");
  }
  return {
    kind: "bounty_accrual",
    entry_id: reconfirmation.entry_id,
    operator: reconfirmation.payload.record.operator,
    stale_from: before.expires_at,
    stale_until: reconfirmation.at,
    seq: reconfirmation.seq,
    amount_micros: null,
  };
}
