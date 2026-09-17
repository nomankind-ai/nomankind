/**
 * The ledger rows the log still writes: the stakes, the dispute reward, the
 * reconfirmation bounty and the daily reconciliation.
 *
 * Decision D-127, "the record is free, no money anywhere": nothing is priced.
 * The pricing this module used to hold — the read shares, the stale bounty
 * pool, the clawbacks and what left through a provider — is gone with the money
 * it counted
 * (D-127 item 2). What is left is what a NEW event still produces, and every
 * amount it produces is zero.
 *
 * Every row here is a PURE FUNCTION OF THE LOG: given the sealed `read_count`,
 * `dispute_upheld` and `reconfirmation` events, the same rows come back with
 * the same ids and the same amounts, on any machine, years later — which is
 * what lets the mirror's `ledger.jsonl` be recomputed from the mirror's own
 * events and held against what the ledger holds.
 *
 * The old rows are history and stay: months of sealed rows the ledger doors go
 * on serving, in the integer micro-USD a read share was counted in.
 *
 * Pure: no I/O, no clock, no storage. `now` is always the caller's, from the
 * injected clock.
 */

import type { Event, ReadCountRow } from "./events.js";
import type { BountyAccrual } from "./bounty.js";
import type { StakeKind, StakeRecord } from "./stake.js";
import { HOLDBACK_DAYS } from "./policy.js";

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
 * bounty accrual, the negated row's own instant for a clawback — so a clawback
 * releases with the share it cancels and the two net to zero at one moment
 * rather than at two — and null for every row that is not waiting on the
 * holdback: a withheld pool row or a reconciliation.
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

const MILLISECONDS_PER_DAY = 86_400_000;

/** The instant a row accrued at `at` may leave. */
function releaseFromInstant(at: string): string {
  return new Date(Date.parse(at) + HOLDBACK_DAYS * MILLISECONDS_PER_DAY).toISOString();
}

/** The UTC calendar day an instant falls on. */
function utcDateOf(timestamp: string): string {
  return new Date(Date.parse(timestamp)).toISOString().slice(0, 10);
}

/**
 * The rows of a published day the reconciliation is over.
 *
 * The day's paid half — `payload.paid.reads` — and never the free reads beside
 * it. A payload with no `paid` block at all is an event published before M24,
 * when every read the log served went through the same door and the whole day
 * was that half; those days are read from `reads`, which is what they meant
 * when they were sealed. Exported because the mirror recomputes the same fold
 * off the same events and two readings of one day would be two answers.
 */
export function pricedReads(
  event: Event<"read_count">,
): readonly ReadCountRow[] {
  const paid = event.payload.paid;
  return paid === undefined ? event.payload.reads : paid.reads;
}

/**
 * Price the reward an upheld challenge is paid: what the entry it overturned
 * lost.
 *
 * Section 6: an upheld challenge "returns the stake, pays the challenger,
 * overturns the entry, and claws back what the approvers earned on it (Section
 * 9)". One sentence, and the last clause is the amount of the second: the
 * reward is exactly the sum of the clawbacks that same event wrote — the shares
 * the signers had accrued inside the holdback and lost. So it is a function of
 * the log like every other row here, and nobody has to decide a number.
 *
 * `owed` is the row src/stake.ts wrote at the outcome — the fact that a reward
 * was owed, at the position it became owed — and it keeps that position, that
 * instant and that id: this prices the row, it does not write a second one. Its
 * operator is the challenger's, or null for a bare key, and the record goes
 * under `ref` unchanged, so `ref.agent` still names the key a bare-key
 * challenger's reward accrues to and holds for.
 *
 * `available_at` is the latest release instant among those clawbacks: the reward
 * leaves when the last clawed-back share would have, because it is that money
 * and is owed no earlier than the moment the money would have left.
 *
 * An entry that had accrued nothing inside the holdback prices at zero,
 * explicitly, and not at null: Section 9 pays nothing back out of a share that
 * had already released ("a dispute upheld later claws back nothing and burns
 * standing only"), and a row left unpriced after the step has passed its
 * position would read as an amount still to come.
 */
export function disputeRewardRow(
  owed: StakeRecord,
  clawbacks: readonly LedgerRow[],
): LedgerRow {
  let clawedBack = 0;
  let availableAt: string | null = null;
  const claws: string[] = [];
  for (const row of clawbacks) {
    if (row.kind !== "clawback") continue;
    clawedBack += row.amount;
    claws.push(row.id);
    if (row.available_at !== null && (availableAt === null || row.available_at > availableAt)) {
      availableAt = row.available_at;
    }
  }
  return {
    id: `${owed.kind}:${owed.seq}`,
    kind: "dispute_reward",
    entry_id: owed.entry_id,
    operator: owed.operator,
    role: null,
    date: null,
    reads: null,
    unit: "micros",
    // The clawbacks are written negative, because they negate the shares they
    // claw back. What the challenger is paid is the positive of that sum,
    // subtracted rather than negated so a reward of nothing is zero and never
    // the negative zero a negation would write into a stored row.
    amount: 0 - clawedBack,
    available_at: availableAt,
    seq: owed.seq,
    at: owed.at,
    // The record the row was written as, and the rows the price was read off:
    // the arithmetic is checkable from the row without rederiving the entry.
    ref: { ...owed, clawed_back: clawedBack, clawbacks: claws },
  };
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

/**
 * The daily reconciliation: does what the ledger accrued agree with what the log
 * published?
 *
 * Section 9: "Read counts are published to the sealed log daily, so nomankind
 * cannot quietly change the numbers later ... Each day's published count is the
 * number the seal commits to." This is nomankind reconciling against itself,
 * every day, and writing the answer where the same public can read it.
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

  // The paid half of the day: a reconciliation of the whole day's traffic
  // against rows that only ever covered that half would report a mismatch on
  // every free read.
  for (const read of pricedReads(event)) {
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

/**
 * The kinds that carry an amount to or from an operator and wait out the
 * holdback.
 *
 * `dispute_reward` is one of them. Section 6's upheld challenge "returns the
 * stake, pays the challenger", and what it paid was money in micros, held until
 * the last clawed-back share would have left. The other stake kinds are not
 * here — standing is its own unit, and no query ever sums two units together.
 *
 * Nothing is priced above zero in any of these kinds now (D-127). They are read
 * because the rows are still in the table.
 */
function isBalanceKind(kind: LedgerKind): boolean {
  return (
    kind === "read_share" ||
    kind === "bounty_accrual" ||
    kind === "clawback" ||
    kind === "dispute_reward"
  );
}

/**
 * Whether a row counts toward a balance at all: a balance kind, and priced.
 *
 * A `dispute_reward` is written at the outcome as a fact with no number — unit
 * and amount null together (src/stake.ts) — and was priced when the sweep's
 * ledger step reached that position. Unpriced it counts for nothing: such a row
 * reads back through the columns as zero in `standing`
 * (src/storage/repository.ts, `toLedgerRow`) and the mirror recomputes it the
 * same way, so `micros` is what says a step has passed it and the amount is a
 * real number. Every other balance kind was written priced and always counts.
 */
function countsTowardBalance(row: LedgerRow): boolean {
  if (!isBalanceKind(row.kind)) return false;
  return row.kind !== "dispute_reward" || row.unit === "micros";
}

/** What a set of rows adds up to, in micros. */
export interface LedgerBalance {
  /** Everything ever accrued: read shares and bounties, clawbacks aside. */
  readonly accrued: number;
  /** Still inside the holdback at `now`, clawbacks netted against what they cancel. */
  readonly held: number;
  /** Past the holdback at `now`, clawbacks netted against what they cancel. */
  readonly released: number;
  /** The clawbacks, as they are written: negative, held or not. */
  readonly clawed_back: number;
}

/**
 * Add up a set of ledger rows.
 *
 * `bounty_pool` rows are deliberately not accrued to anyone: they are the halves
 * an entry withheld while stale, owed to whoever reconfirms it next and to
 * nobody until then. They enter the accounting as the `bounty_accrual` row that
 * collects them.
 *
 * A clawback is placed by its own `available_at`, exactly as the row it negates
 * is: a held share and its clawback are both held, so `held` reads zero rather
 * than a debt that is not owed yet. `clawed_back` is the clawbacks as written,
 * held or released, because it answers what came back and not when.
 *
 * A priced `dispute_reward` accrues to the challenger like any other accrual and
 * is placed by its own release, which is the last of those clawbacks': the same
 * money, leaving at the same instant, on the other side of the dispute. An
 * unpriced one is not counted at all (`countsTowardBalance`).
 */
export function ledgerBalance(
  rows: readonly LedgerRow[],
  now: string,
): LedgerBalance {
  let accrued = 0;
  let held = 0;
  let releasedTotal = 0;
  let clawedBack = 0;

  for (const row of rows) {
    if (!countsTowardBalance(row)) continue;
    if (row.kind === "clawback") clawedBack += row.amount;
    else accrued += row.amount;
    if (row.available_at !== null && row.available_at > now) {
      held += row.amount;
    } else {
      releasedTotal += row.amount;
    }
  }

  return {
    accrued,
    held,
    released: releasedTotal,
    clawed_back: clawedBack,
  };
}
