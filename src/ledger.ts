/**
 * The money side of the log: read shares, the stale bounty pool, clawbacks,
 * payouts and the daily reconciliation.
 *
 * Whitepaper Section 9, Money: "Thirty percent of paid-read revenue goes to the
 * contributor pool at launch, fifteen to the submitter and five to each
 * validator, paid to their operators ... Accrued fees are held for thirty days
 * before payout so an upheld dispute can claw them back before they leave."
 * Section 7: "Stale entries earn half rate, and the withheld half builds up on
 * the entry as a reconfirmation bounty, paid to whoever makes it fresh again."
 * And: "Read counts are published to the sealed log daily ... Each day's
 * published count is the number the seal commits to and payouts are computed
 * from."
 *
 * Every row this module builds except a payout is a PURE FUNCTION OF THE LOG:
 * given the sealed `read_count`, `dispute_upheld` and `reconfirmation` events
 * and the entry state derivation already computes, the same rows come back with
 * the same ids and the same amounts, on any machine, years later. That is what
 * makes Section 9's promise — "any operator can reconcile their payout against
 * the log" — a fact about the code rather than a hope. A payout is the one row
 * that is not derivable, because it records something that happened outside the
 * log: money left, through a provider, under a reference.
 *
 * Units. Read revenue is counted in integer micro-USD, a millionth of a dollar,
 * because one read's submitter share is 75 micros and a ledger that rounded to
 * cents would pay the long tail nothing at all. The price and the split are
 * src/policy.ts's and are read from there; no number is written down here.
 *
 * Pure: no I/O, no clock, no storage. `now` is always the caller's, from the
 * injected clock.
 */

import type { ReadShareSlot } from "./derive.js";
import type { Event, ReadCountRow } from "./events.js";
import type { BountyAccrual } from "./bounty.js";
import type { StakeKind } from "./stake.js";
import {
  HOLDBACK_DAYS,
  PAYOUT_MINIMUM_MICROS,
  READ_PRICE_MICROS_PER_READ,
  READ_SHARE_SPLIT,
} from "./policy.js";

/**
 * Every kind of ledger row. The stake kinds are src/stake.ts's, unchanged: a
 * stake was already a ledger row before there was any money (decision D-064),
 * and this milestone adds the rows that carry amounts rather than replacing the
 * ones that carry standing.
 */
export type LedgerKind =
  | StakeKind
  | "bounty_accrual"
  | "read_share"
  | "bounty_pool"
  | "clawback"
  | "payout"
  | "reconciliation";

/** Which share of an entry's read revenue a row pays. */
export type ShareRole = "submitter" | "validator" | "reconfirmer";

/**
 * One ledger row.
 *
 * `amount` is signed: a clawback is the negative of the row it claws back, so a
 * balance is a sum and never a subtraction someone might forget to make.
 *
 * `available_at` is when the row may leave: the read's day plus the thirty-day
 * holdback for a read share, the reconfirmation's instant plus the same for a
 * bounty accrual, and null for every row that is not waiting on the holdback —
 * a withheld pool row, a clawback, a payout, a reconciliation.
 *
 * `seq` and `at` are the position and instant of the event that produced the
 * row, so a reader can find the event a row came from without searching, exactly
 * as a stake row does.
 */
export interface LedgerRow {
  readonly id: string;
  readonly kind: LedgerKind;
  readonly entry_id: string | null;
  readonly operator: string | null;
  readonly role: ShareRole | null;
  /** The UTC day the row is about, YYYY-MM-DD; null when it is about no day. */
  readonly date: string | null;
  readonly reads: number | null;
  readonly unit: "micros" | "standing" | "cents";
  readonly amount: number;
  readonly available_at: string | null;
  readonly seq: number;
  readonly at: string;
  readonly ref: Record<string, unknown>;
}

/**
 * What pricing needs to know about an entry, and nothing more: who submitted it,
 * who holds its read-share slots, whether it was stale on the day being priced,
 * and whether it is payable at all.
 *
 * Every field is derivation's (src/derive.ts): `author_operator` off the core,
 * `read_share_slots` off the sidecar, `stale` and `verified` off the derived
 * fields. The caller passes them in rather than this module deriving them,
 * because pricing a day means asking about the entry as it stood on that day and
 * a fold that rederived here would answer about today.
 */
export interface EntryShareState {
  readonly author_operator: string | null;
  readonly read_share_slots: readonly ReadShareSlot[] | null;
  readonly stale: boolean;
  readonly verified: boolean;
}

const MILLISECONDS_PER_DAY = 86_400_000;

/** A UTC date, `days` after `date`. Milliseconds arithmetic, no wall clock. */
function datePlusDays(date: string, days: number): string {
  const shifted = Date.parse(`${date}T00:00:00.000Z`) + days * MILLISECONDS_PER_DAY;
  return new Date(shifted).toISOString().slice(0, 10);
}

/** The instant a row accrued on `date` may leave: the holdback, in full. */
function releaseFromDate(date: string): string {
  return `${datePlusDays(date, HOLDBACK_DAYS)}T00:00:00.000Z`;
}

/** The instant a row accrued at `at` may leave. */
function releaseFromInstant(at: string): string {
  return new Date(Date.parse(at) + HOLDBACK_DAYS * MILLISECONDS_PER_DAY).toISOString();
}

/** The UTC calendar day an instant falls on. */
function utcDateOf(timestamp: string): string {
  return new Date(Date.parse(timestamp)).toISOString().slice(0, 10);
}

/**
 * One share of one day's reads of one entry, in micros.
 *
 * The multiplication runs before the division so the arithmetic is exact at the
 * paper's own example: ten thousand reads at 500 micros, fifteen percent, is
 * 750,000 micros — seventy-five cents. The floor is the only rounding in the
 * system and it always rounds toward nomankind's share, never toward its own.
 */
function shareMicros(count: number, percent: number): number {
  return Math.floor((count * READ_PRICE_MICROS_PER_READ * percent) / 100);
}

/** Who is owed a share of an entry's reads, and at what percent. */
interface ShareHolder {
  readonly operator: string;
  readonly role: ShareRole;
  readonly percent: number;
}

function holdersOf(state: EntryShareState): ShareHolder[] {
  const holders: ShareHolder[] = [];
  if (state.author_operator !== null) {
    holders.push({
      operator: state.author_operator,
      role: "submitter",
      percent: READ_SHARE_SPLIT.submitter,
    });
  }
  for (const slot of state.read_share_slots ?? []) {
    holders.push({
      operator: slot.operator,
      role: "validator",
      percent: READ_SHARE_SPLIT.validator,
    });
  }
  return holders;
}

/**
 * Price one published day of reads.
 *
 * One `read_share` row per share holder of every verified entry read that day,
 * plus one `bounty_pool` row per entry that was stale on that day carrying the
 * halves the stale rule withheld.
 *
 * Nothing is priced for an entry the caller cannot state (`stateOf` returns
 * null) or that is not verified: Section 9 pays for verified entries and a draft
 * earns nothing however often it is read. An entry whose author operator is null
 * — a bare-key submission — pays its slot holders and nobody else, exactly as a
 * bare-key challenger's reward has no operator to land on.
 *
 * The ids are deterministic and carry the event's position, so replaying a day
 * writes the same rows over the same ids rather than a second set beside them.
 */
export function readShareRows(
  event: Event<"read_count">,
  stateOf: (entryId: string) => EntryShareState | null,
): LedgerRow[] {
  const { date } = event.payload;
  const availableAt = releaseFromDate(date);
  const rows: LedgerRow[] = [];

  for (const read of event.payload.reads as readonly ReadCountRow[]) {
    if (read.count <= 0) continue;
    const state = stateOf(read.entry_id);
    if (state === null || !state.verified) continue;

    const holders = holdersOf(state);
    if (holders.length === 0) continue;

    let withheld = 0;
    const withheldFrom: string[] = [];
    for (const holder of holders) {
      const full = shareMicros(read.count, holder.percent);
      // Section 7: "Stale entries earn half rate, and the withheld half builds
      // up on the entry as a reconfirmation bounty." The half that is paid is
      // rounded down, so the odd micro is withheld rather than invented.
      const paid = state.stale ? Math.floor(full / 2) : full;
      if (state.stale) withheld += full - paid;
      const id = `read_share:${event.seq}:${read.entry_id}:${holder.role}:${holder.operator}`;
      if (state.stale) withheldFrom.push(id);
      rows.push({
        id,
        kind: "read_share",
        entry_id: read.entry_id,
        operator: holder.operator,
        role: holder.role,
        date,
        reads: read.count,
        unit: "micros",
        amount: paid,
        available_at: availableAt,
        seq: event.seq,
        at: event.at,
        ref: {
          price_micros_per_read: READ_PRICE_MICROS_PER_READ,
          share_percent: holder.percent,
          stale: state.stale,
        },
      });
    }

    if (!state.stale) continue;
    rows.push({
      id: `bounty_pool:${event.seq}:${read.entry_id}`,
      kind: "bounty_pool",
      entry_id: read.entry_id,
      // The pool belongs to the entry and not to a person: whoever makes it
      // fresh again collects it, and until then nobody holds it.
      operator: null,
      role: null,
      date,
      reads: read.count,
      unit: "micros",
      amount: withheld,
      // Not waiting on the holdback: it is not owed to anyone yet.
      available_at: null,
      seq: event.seq,
      at: event.at,
      ref: {
        price_micros_per_read: READ_PRICE_MICROS_PER_READ,
        stale: true,
        withheld_from: withheldFrom,
      },
    });
  }

  return rows;
}

/**
 * Claw back what an overturned entry earned but has not yet paid out.
 *
 * Section 9: "Accrued fees are held for thirty days before payout so an upheld
 * dispute can claw them back before they leave ... A dispute upheld later claws
 * back nothing and burns standing only, so thirty days is the reader's real
 * protection window." So the test is exactly the holdback: a row whose
 * `available_at` is still in the future at the instant the dispute was upheld is
 * clawed back, and a row already released is not touched however wrong the entry
 * turned out to be. The standing side of the same sentence is src/standing.ts's.
 *
 * `held` is what the caller read back for the entry; this filters it again
 * rather than trusting the query, because the rule is the one thing here that
 * must not depend on how the rows were fetched.
 */
export function clawbackRows(
  event: Event<"dispute_upheld">,
  held: readonly LedgerRow[],
): LedgerRow[] {
  const rows: LedgerRow[] = [];
  for (const row of held) {
    if (row.kind !== "read_share") continue;
    if (row.available_at === null || row.available_at <= event.at) continue;
    rows.push({
      id: `clawback:${event.seq}:${row.id}`,
      kind: "clawback",
      entry_id: row.entry_id,
      operator: row.operator,
      role: row.role,
      date: row.date,
      reads: row.reads,
      unit: "micros",
      amount: -row.amount,
      // A clawback is never held: it takes effect the instant it is written.
      available_at: null,
      seq: event.seq,
      at: event.at,
      ref: { claws_back: row.id },
    });
  }
  return rows;
}

/**
 * Price a reconfirmation's bounty: the halves the entry withheld while it was
 * stale, paid to whoever made it fresh again.
 *
 * Section 7: the withheld half "builds up on the entry as a reconfirmation
 * bounty, paid to whoever makes it fresh again", and Section 9: "Reconfirming a
 * stale entry pays the accrued bounty and rotates the reconfirmer into one of
 * the three validator read-share slots for the window it reopened."
 *
 * `accrual` is src/bounty.ts's record of the window — null when the entry was
 * not stale, and then there is nothing to pay. `pool` is the entry's withheld
 * rows; only those dated inside the stale window count, because a pool row from
 * an earlier stale spell was already collected by the reconfirmation that ended
 * it.
 */
export function bountyAccrualRow(
  event: Event<"reconfirmation">,
  accrual: BountyAccrual | null,
  pool: readonly LedgerRow[],
): LedgerRow | null {
  if (accrual === null) return null;
  const from = accrual.stale_from;
  const until = utcDateOf(accrual.stale_until);

  let amount = 0;
  const pooled: string[] = [];
  for (const row of pool) {
    if (row.kind !== "bounty_pool") continue;
    if (row.entry_id !== accrual.entry_id) continue;
    if (row.date === null || row.date < from || row.date > until) continue;
    amount += row.amount;
    pooled.push(row.id);
  }

  return {
    id: `bounty_accrual:${event.seq}`,
    kind: "bounty_accrual",
    entry_id: accrual.entry_id,
    operator: accrual.operator,
    role: "reconfirmer",
    date: utcDateOf(event.at),
    reads: null,
    unit: "micros",
    amount,
    // Held like any other accrual: a wrong reconfirmation is "clawed back
    // exactly like a wrong approval".
    available_at: releaseFromInstant(event.at),
    seq: event.seq,
    at: event.at,
    ref: { stale_from: from, stale_until: accrual.stale_until, pooled },
  };
}

/** What one operator is owed this cycle, and what carries to the next. */
export interface PayoutPlan {
  readonly operator: string;
  /** What is being paid now: zero when the total sat below the minimum. */
  readonly amount: number;
  /** The ids the payout covers, empty when nothing is being paid. */
  readonly rows: string[];
  /** What carries forward: zero when paid, else the whole released total. */
  readonly carried_forward: number;
}

/** Whether a row is released — payable now — at `now`. */
function isReleased(row: LedgerRow, now: string): boolean {
  // A clawback is always released: it is money that has to come back before
  // anything else leaves, so it can never wait behind a holdback.
  if (row.kind === "clawback") return true;
  if (row.kind !== "read_share" && row.kind !== "bounty_accrual") return false;
  return row.available_at !== null && row.available_at <= now;
}

/**
 * What to pay one operator this cycle (decision D-053).
 *
 * The cycle is monthly and the floor is published (`PAYOUT_MINIMUM_MICROS`): an
 * operator whose released accruals sit below it is not paid, and the whole
 * amount carries forward to the next cycle rather than being written off. That
 * is why nothing is paid and no row is claimed when the total falls short —
 * a plan that named its rows without paying them would let the next cycle think
 * they had already left.
 *
 * `released` is what the caller read back as unpaid for this operator; the rule
 * is applied again here rather than trusted from the query, and a clawback
 * always counts however recently it was written, so an operator can never be
 * paid out from under a clawback by a query that missed it.
 */
export function payoutPlan(
  operator: string,
  released: readonly LedgerRow[],
  now: string,
): PayoutPlan {
  let amount = 0;
  const rows: string[] = [];
  for (const row of released) {
    if (row.operator !== operator) continue;
    if (!isReleased(row, now)) continue;
    amount += row.amount;
    rows.push(row.id);
  }

  if (amount < PAYOUT_MINIMUM_MICROS) {
    return { operator, amount: 0, rows: [], carried_forward: amount };
  }
  return { operator, amount, rows, carried_forward: 0 };
}

/**
 * The row that records money leaving.
 *
 * The one row in this module that is NOT a function of the log: it names a
 * transfer that happened at a payment provider, under a reference the provider
 * gave back, and no amount of replaying events can reproduce it. Everything
 * around it can be recomputed and checked against it, which is the point of
 * Section 9's "any operator can reconcile their payout against the log".
 *
 * One payout per operator per day at most, which is what the id says: the cycle
 * is monthly, so a second payout on the same day is the same payout retried.
 */
export function payoutRow(
  plan: PayoutPlan,
  seq: number,
  at: string,
  reference: string,
): LedgerRow {
  return {
    id: `payout:${plan.operator}:${utcDateOf(at)}`,
    kind: "payout",
    entry_id: null,
    operator: plan.operator,
    role: null,
    date: utcDateOf(at),
    reads: null,
    unit: "micros",
    amount: plan.amount,
    available_at: null,
    seq,
    at,
    ref: { reference, rows: plan.rows },
  };
}

/**
 * The daily reconciliation: does what the ledger accrued agree with what the log
 * published?
 *
 * Section 9: "Read counts are published to the sealed log daily, so nomankind
 * cannot quietly change the numbers later, and any operator can reconcile their
 * payout against the log ... Each day's published count is the number the seal
 * commits to and payouts are computed from." This is nomankind reconciling
 * against itself, every day, and writing the answer where the same public can
 * read it.
 *
 * `accrued` maps an entry to the read count its `read_share` rows for that day
 * carry. Every share row of one entry carries the same count — they are shares
 * of one number — so the map holds that count once, not once per holder.
 *
 * An entry that accrued nothing is not a mismatch: it had no share holder to pay
 * (a bare-key submission with no slots yet, or an entry that was not verified
 * when the day was priced). Those are named under `unpriced`, because silence
 * about them would be exactly the under-reporting this row exists to catch.
 */
export function reconciliationRow(
  event: Event<"read_count">,
  accrued: ReadonlyMap<string, number>,
): LedgerRow {
  const mismatches: Array<{ entry_id: string; published: number; accrued: number }> = [];
  const unpriced: string[] = [];
  let publishedTotal = 0;
  let accruedTotal = 0;

  for (const read of event.payload.reads as readonly ReadCountRow[]) {
    publishedTotal += read.count;
    const priced = accrued.get(read.entry_id);
    if (priced === undefined) {
      unpriced.push(read.entry_id);
      continue;
    }
    accruedTotal += priced;
    if (priced !== read.count) {
      mismatches.push({
        entry_id: read.entry_id,
        published: read.count,
        accrued: priced,
      });
    }
  }

  const ok = mismatches.length === 0;
  return {
    id: `reconciliation:${event.payload.date}`,
    kind: "reconciliation",
    entry_id: null,
    operator: null,
    role: null,
    date: event.payload.date,
    reads: publishedTotal,
    unit: "micros",
    // A reconciliation moves no money: it is a statement about rows that do.
    amount: 0,
    available_at: null,
    seq: event.seq,
    at: event.at,
    ref: {
      ok,
      published_total: publishedTotal,
      accrued_total: accruedTotal,
      mismatches,
      unpriced,
    },
  };
}

/** What a set of rows adds up to, in micros. */
export interface LedgerBalance {
  /** Everything ever accrued: read shares and bounties, clawbacks aside. */
  readonly accrued: number;
  /** Accrued and still inside the holdback at `now`. */
  readonly held: number;
  /** Accrued and past the holdback at `now`. */
  readonly released: number;
  /** The clawbacks, as they are written: negative. */
  readonly clawed_back: number;
  /** What has left, through payouts. */
  readonly paid: number;
  /** Released, less clawbacks, less what has been paid. */
  readonly carried_forward: number;
}

/**
 * Add up a set of ledger rows.
 *
 * `bounty_pool` rows are deliberately not accrued to anyone: they are the halves
 * an entry withheld while stale, owed to whoever reconfirms it next and to
 * nobody until then. They enter the accounting as the `bounty_accrual` row that
 * collects them.
 */
export function ledgerBalance(
  rows: readonly LedgerRow[],
  now: string,
): LedgerBalance {
  let accrued = 0;
  let held = 0;
  let releasedTotal = 0;
  let clawedBack = 0;
  let paid = 0;

  for (const row of rows) {
    if (row.kind === "read_share" || row.kind === "bounty_accrual") {
      accrued += row.amount;
      if (row.available_at !== null && row.available_at > now) {
        held += row.amount;
      } else {
        releasedTotal += row.amount;
      }
      continue;
    }
    if (row.kind === "clawback") {
      clawedBack += row.amount;
      continue;
    }
    if (row.kind === "payout") paid += row.amount;
  }

  return {
    accrued,
    held,
    released: releasedTotal,
    clawed_back: clawedBack,
    paid,
    carried_forward: releasedTotal + clawedBack - paid,
  };
}
