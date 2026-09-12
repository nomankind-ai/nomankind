/**
 * The ledger step's work, cut to what one run can finish.
 *
 * Whitepaper Section 9: "Read counts are published to the sealed log daily ...
 * Each day's published count is the number the seal commits to and payouts are
 * computed from." Pricing one entry of a published day costs a read of the
 * entry and a read per read-share slot it seated, so a day on which a thousand
 * entries were read is thousands of statements — more than one alarm has, and a
 * run that tried them all would be killed part-way through a day rather than
 * finish it.
 *
 * So a run prices LEDGER_ENTRIES_PER_RUN entries, the next run resumes the same
 * day where it stopped, and the day's reconciliation — which is about the whole
 * day — is written only on the run that reaches the end of it. The rows reach
 * D1 in batches of at most SWEEP_BATCH_STATEMENTS. These tests measure exactly
 * that: how far each run gets, how big each batch is, and that the day's rows
 * and its one reconciliation are the same rows one unbounded run would have
 * written.
 *
 * The payout step is here for the other half of the same question: its work is
 * due at most once a month, on a step that runs every few minutes, so a run
 * inside a cycle that has already paid must cost one statement and not two per
 * operator in the directory.
 *
 * The database is miniflare's D1 with every migration applied, wrapped in a
 * counter that records every statement and the size of every batch. The log is
 * the real one: `appendEvent` chains and hashes every event.
 */

import { afterAll, beforeAll, describe, expect, it } from "vitest";

import {
  MockPayoutAdapter,
  MOCK_VERIFIED_PREFIX,
} from "../src/adapters/payout.js";
import type { Core } from "../src/core.js";
import type { Sidecar } from "../src/derive.js";
import { appendEvent, type Event } from "../src/events.js";
import type { LedgerRow } from "../src/ledger.js";
import {
  DEFAULT_DOMAIN,
  LEDGER_ENTRIES_PER_RUN,
  PAYOUT_MINIMUM_MICROS,
  SWEEP_BATCH_STATEMENTS,
} from "../src/policy.js";
import type { Entry } from "../src/schema.js";
import type {
  D1Like,
  D1LikeResult,
  D1LikeStatement,
} from "../src/storage/d1.js";
import {
  appendEvents,
  ledgerCursor,
  ledgerRowsForOperator,
  payoutRows,
  putEntry,
  putLedgerRows,
  putOperator,
  reconciliationRows,
} from "../src/storage/repository.js";
import {
  LEDGER_CURSOR,
  LEDGER_DAY_CURSOR,
  ledgerStep,
  payoutStep,
} from "../src/worker/sweep.js";
import { openTestDatabase, type TestDatabase } from "./helpers/d1.js";

/** The injected clock: nothing here reads a wall clock. */
const NOW = new Date("2026-09-12T00:05:00.000Z");
const AT = NOW.toISOString();

/** The published day these tests price, which is the day before the run's. */
const DAY = "2026-09-11";

/** How many entries that day was read on: three runs' worth and no more. */
const ENTRIES = LEDGER_ENTRIES_PER_RUN * 3;

/** How many times each of them was read. */
const READS = 10;

const AUTHOR = "1F916:YXV0aG9yQWdlbnRJZGVudGl0eUFBQUFBQUE";
const OPERATOR = "kestrel";
const SLOT_OPERATORS = ["heron", "merlin", "osprey"];

/** The id of the nth entry, wide enough to keep log order and text order one. */
function entryId(index: number): string {
  return `nmk_price_${String(index).padStart(5, "0")}`;
}

/** One entry's signed core, as the log carries it. */
function core(index: number): Core {
  return {
    id: entryId(index),
    domain: DEFAULT_DOMAIN,
    subject: `kestrel-${index}`,
    category: "pricing",
    author: AUTHOR,
    author_operator: OPERATOR,
    submitted_at: AT,
  } as unknown as Core;
}

/**
 * The stored entry: verified, and stale on the day being priced.
 *
 * Stale on purpose. A stale entry pays each holder half and writes the withheld
 * halves as a `bounty_pool` row of its own, so one entry is five rows — four
 * holders and the pool — and a run of LEDGER_ENTRIES_PER_RUN entries is exactly
 * one full batch, which is what makes the cut visible on the run that adds the
 * reconciliation to it.
 */
function entryOf(index: number): Entry {
  return {
    ...(core(index) as unknown as Record<string, unknown>),
    status: "verified",
    verified_at: "2026-01-01T00:00:00.000Z",
    stale: true,
    expires_at: "2026-06-01T00:00:00.000Z",
    supersedes: null,
    seal: null,
  } as unknown as Entry;
}

/** The sidecar beside it: three seated read-share slots, and a stated tier. */
function sidecarOf(seq: number): Sidecar {
  return {
    needs_replacement: false,
    effective_tier: "stated",
    test_verdict: null,
    trusted_count_at_decision: null,
    read_share_slots: SLOT_OPERATORS.map((operator) => ({ operator, seq })),
    revalidations: [],
  } as unknown as Sidecar;
}

/** What one run asked of D1: every statement, and the size of every batch. */
interface CountingDatabase extends D1Like {
  /** The size of every batch this database was asked to run. */
  readonly batches: number[];
  /**
   * How many statements it was asked to prepare.
   *
   * Counted at `prepare` rather than at `run`, because a statement bound for a
   * batch has to reach D1 as the object miniflare handed back and not as a
   * wrapper around it — so this counts what was built, which for a step that
   * batches nothing is exactly what it ran.
   */
  statements: number;
  /** Start counting again from zero. */
  reset(): void;
}

/** The real database, with every statement counted. Everything goes through. */
function countingDatabase(db: D1Like): CountingDatabase {
  const counter: CountingDatabase = {
    batches: [],
    statements: 0,
    reset() {
      counter.batches.length = 0;
      counter.statements = 0;
    },
    prepare(sql: string) {
      counter.statements += 1;
      return db.prepare(sql);
    },
    async batch<Row = Record<string, unknown>>(
      statements: D1LikeStatement[],
    ): Promise<D1LikeResult<Row>[]> {
      counter.batches.push(statements.length);
      return db.batch<Row>(statements);
    },
    exec: (sql: string) => db.exec(sql),
  };
  return counter;
}

describe("the ledger step: one day, priced across runs", () => {
  let store: TestDatabase;
  let db: CountingDatabase;
  let events: Event[] = [];
  /** The position of the day's `read_count` event. */
  let daySeq = 0;

  beforeAll(async () => {
    store = await openTestDatabase();
    db = countingDatabase(store.db);

    // One submission event per entry, then the stored row derivation would have
    // left behind: verified, stale, with its three slots seated.
    for (let index = 0; index < ENTRIES; index += 1) {
      events = await appendEvent(events, {
        at: AT,
        type: "entry_submitted",
        entry_id: entryId(index),
        payload: { core: core(index), signature: "c2lnbmF0dXJl" },
      });
    }
    await appendEvents(store.db, events);
    for (let index = 0; index < ENTRIES; index += 1) {
      await putEntry(store.db, entryOf(index), sidecarOf(index), index);
    }

    // And the day the sweep published, which is what the ledger prices.
    events = await appendEvent(events, {
      at: AT,
      type: "read_count",
      entry_id: null,
      payload: {
        date: DAY,
        reads: Array.from({ length: ENTRIES }, (_, index) => ({
          entry_id: entryId(index),
          count: READS,
        })),
        total: ENTRIES * READS,
        counter_first: 1,
        counter_last: ENTRIES * READS,
        receipts: ENTRIES * READS,
      },
    });
    daySeq = events[events.length - 1]!.seq;
    await appendEvents(store.db, events.slice(ENTRIES));
  }, 600_000);

  afterAll(async () => {
    await store?.dispose();
  });

  it("prices the first LEDGER_ENTRIES_PER_RUN entries and stops on the day", async () => {
    db.reset();
    // Never null: the step returns null only where no seal exists, and the
    // caller decides that, not the step.
    const report = (await ledgerStep(db, daySeq))!;

    expect(report.entries).toBe(LEDGER_ENTRIES_PER_RUN);
    expect(report.day).toBe(DAY);
    // Nothing is reconciled yet: the day is not finished, and a reconciliation
    // written over a third of it would name the other two thirds unpriced.
    expect(report.reconciliations).toBe(0);
    // Five rows an entry — four holders at half rate, and the pool of the
    // halves they did not get.
    expect(report.read_shares).toBe(LEDGER_ENTRIES_PER_RUN * 4);

    // The cursor is left below the day, and the entry cursor says where in it
    // the next run resumes.
    expect(await ledgerCursor(store.db, LEDGER_CURSOR)).toBe(daySeq - 1);
    expect(await ledgerCursor(store.db, LEDGER_DAY_CURSOR)).toBe(
      LEDGER_ENTRIES_PER_RUN,
    );
    expect(await reconciliationRows(store.db, 10)).toEqual([]);

    for (const size of db.batches) {
      expect(size).toBeLessThanOrEqual(SWEEP_BATCH_STATEMENTS);
    }
  }, 600_000);

  it("resumes the same day on the next run", async () => {
    db.reset();
    // Never null: the step returns null only where no seal exists, and the
    // caller decides that, not the step.
    const report = (await ledgerStep(db, daySeq))!;

    expect(report.entries).toBe(LEDGER_ENTRIES_PER_RUN);
    expect(report.day).toBe(DAY);
    expect(report.reconciliations).toBe(0);
    expect(await ledgerCursor(store.db, LEDGER_CURSOR)).toBe(daySeq - 1);
    expect(await ledgerCursor(store.db, LEDGER_DAY_CURSOR)).toBe(
      LEDGER_ENTRIES_PER_RUN * 2,
    );

    for (const size of db.batches) {
      expect(size).toBeLessThanOrEqual(SWEEP_BATCH_STATEMENTS);
    }
  }, 600_000);

  it("finishes the day on the third run, and reconciles it whole", async () => {
    db.reset();
    // Never null: the step returns null only where no seal exists, and the
    // caller decides that, not the step.
    const report = (await ledgerStep(db, daySeq))!;

    expect(report.entries).toBe(LEDGER_ENTRIES_PER_RUN);
    expect(report.reconciliations).toBe(1);
    expect(report.ok).toBe(true);
    // The day is done, so nothing is left part-way through and the cursor is at
    // the head.
    expect(report.day).toBeNull();
    expect(report.through).toBe(daySeq);
    expect(await ledgerCursor(store.db, LEDGER_CURSOR)).toBe(daySeq);
    expect(await ledgerCursor(store.db, LEDGER_DAY_CURSOR)).toBe(0);

    // The last run's rows are its own twenty entries plus the day's one
    // reconciliation, which is one statement more than a batch may carry.
    expect(db.batches).toEqual([SWEEP_BATCH_STATEMENTS, 1]);

    // And the reconciliation is about the whole day, not about the third of it
    // this run priced: every entry read that day accrued, and none is unpriced.
    const [reconciliation] = await reconciliationRows(store.db, 10);
    expect(reconciliation).toBeDefined();
    expect(reconciliation!.date).toBe(DAY);
    expect(reconciliation!.ref["ok"]).toBe(true);
    expect(reconciliation!.ref["published_total"]).toBe(ENTRIES * READS);
    expect(reconciliation!.ref["accrued_total"]).toBe(ENTRIES * READS);
    expect(reconciliation!.ref["unpriced"]).toEqual([]);
    expect(reconciliation!.ref["mismatches"]).toEqual([]);
  }, 600_000);

  it("pays every holder of every entry the day was read on", async () => {
    const rows = await ledgerRowsForOperator(store.db, OPERATOR, 1000);
    const shares = rows.filter((row) => row.kind === "read_share");
    expect(shares).toHaveLength(ENTRIES);
    // The submitter's share of a stale day is half of it, rounded down.
    for (const row of shares) {
      expect(row.role).toBe("submitter");
      expect(row.date).toBe(DAY);
      expect(row.reads).toBe(READS);
    }
    for (const operator of SLOT_OPERATORS) {
      const held = await ledgerRowsForOperator(store.db, operator, 1000);
      expect(held.filter((row) => row.kind === "read_share")).toHaveLength(
        ENTRIES,
      );
    }
  }, 600_000);

  it("does nothing on a run past the day it finished", async () => {
    db.reset();
    // Never null: the step returns null only where no seal exists, and the
    // caller decides that, not the step.
    const report = (await ledgerStep(db, daySeq))!;

    expect(report.entries).toBe(0);
    expect(report.reconciliations).toBe(0);
    expect(report.day).toBeNull();
    expect(report.through).toBe(daySeq);
    // Nothing was written: no batch at all, only the cursor move.
    expect(db.batches).toEqual([]);
    expect(await reconciliationRows(store.db, 10)).toHaveLength(1);
  }, 600_000);
});

describe("putLedgerRows: batches D1 can take", () => {
  let store: TestDatabase;
  let db: CountingDatabase;

  beforeAll(async () => {
    store = await openTestDatabase();
    db = countingDatabase(store.db);
  }, 600_000);

  afterAll(async () => {
    await store?.dispose();
  });

  it("cuts one write into batches of at most SWEEP_BATCH_STATEMENTS", async () => {
    const rows: LedgerRow[] = Array.from({ length: 250 }, (_, index) => ({
      id: `read_share:batch:${index}`,
      kind: "read_share",
      entry_id: entryId(index),
      operator: OPERATOR,
      role: "submitter",
      date: DAY,
      reads: READS,
      unit: "micros",
      amount: 1,
      available_at: "2026-10-11T00:00:00.000Z",
      seq: 1,
      at: AT,
      ref: {},
    }));

    db.reset();
    await putLedgerRows(db, rows);
    expect(db.batches).toEqual([
      SWEEP_BATCH_STATEMENTS,
      SWEEP_BATCH_STATEMENTS,
      50,
    ]);

    // Writing them again writes nothing new: every row is idempotent by its id,
    // which is what makes a chunked write safe to resume.
    const stored = await ledgerRowsForOperator(store.db, OPERATOR, 1000);
    await putLedgerRows(db, rows);
    expect(await ledgerRowsForOperator(store.db, OPERATOR, 1000)).toEqual(
      stored,
    );
  }, 600_000);
});

describe("the payout step: a cycle, per operator", () => {
  let store: TestDatabase;
  let db: CountingDatabase;
  const adapter = new MockPayoutAdapter();

  /** The operator paid earlier this month, and the one that crosses later. */
  const PAID_EARLY = "kestrel";
  const CROSSES_LATE = "heron";

  /** One released, unpaid accrual at exactly the published floor. */
  function released(id: string, operator: string): LedgerRow {
    return {
      id,
      kind: "read_share",
      entry_id: null,
      operator,
      role: "validator",
      date: "2026-08-01",
      reads: 1,
      unit: "micros",
      amount: PAYOUT_MINIMUM_MICROS,
      available_at: "2026-09-01T00:00:00.000Z",
      seq: 0,
      at: AT,
      ref: {},
    } as unknown as LedgerRow;
  }

  beforeAll(async () => {
    store = await openTestDatabase();
    db = countingDatabase(store.db);

    // Both operators are onboarded: the mock moves money only for a reference
    // it would also call verified.
    for (const id of [PAID_EARLY, CROSSES_LATE]) {
      await putOperator(store.db, {
        id,
        maintainer: false,
        provider: false,
        registeredSeq: 0,
        details: { payout_reference: `${MOCK_VERIFIED_PREFIX}${id}` },
      });
    }

    await putLedgerRows(store.db, [
      // Operator A was paid on the second, and has accrued again since.
      {
        id: `payout:${PAID_EARLY}:2026-09-02`,
        kind: "payout",
        entry_id: null,
        operator: PAID_EARLY,
        role: null,
        date: "2026-09-02",
        reads: null,
        unit: "micros",
        amount: 5_000_000,
        available_at: null,
        seq: 1,
        at: "2026-09-02T00:00:00.000Z",
        ref: { reference: "acct_mock", rows: [] },
      } as unknown as LedgerRow,
      released(`read_share:${PAID_EARLY}:again`, PAID_EARLY),
    ]);
  }, 600_000);

  afterAll(async () => {
    await store?.dispose();
  });

  it("asks one question and pays an operator already paid this cycle nothing", async () => {
    const skipped: string[] = [];
    db.reset();
    const payouts = await payoutStep(db, adapter, 1, AT, (reason) =>
      skipped.push(reason),
    );

    expect(payouts).toEqual([]);
    expect(skipped).toEqual(["payout_this_cycle"]);
    // One statement: who is owed anything, and which of them this cycle has
    // paid. Not one per operator in the directory, on a step whose work is due
    // once a month, and not a second statement about this one.
    expect(db.statements).toBe(1);
    expect(db.batches).toEqual([]);
    // And nothing was paid twice.
    expect(await payoutRows(store.db, 10)).toHaveLength(1);
  }, 600_000);

  it("pays the operator that crosses the minimum later in the same cycle", async () => {
    // D-053 is per operator per cycle, so operator B crossing the floor on the
    // twentieth is owed this month's batch even though operator A was paid on
    // the second. A global gate made the first payout of a month close the
    // month for everybody.
    await putLedgerRows(store.db, [
      released(`read_share:${CROSSES_LATE}:late`, CROSSES_LATE),
    ]);

    const skipped: string[] = [];
    const payouts = await payoutStep(db, adapter, 1, AT, (reason) =>
      skipped.push(reason),
    );

    expect(payouts).toEqual([
      {
        operator: CROSSES_LATE,
        amount: PAYOUT_MINIMUM_MICROS,
        transfer: expect.any(String),
      },
    ]);
    // A is passed over on the same run that pays B, and says why.
    expect(skipped).toEqual(["payout_this_cycle"]);

    const paid = await payoutRows(store.db, 10, CROSSES_LATE);
    expect(paid).toHaveLength(1);
    expect(paid[0]!.ref["rows"]).toEqual([`read_share:${CROSSES_LATE}:late`]);
    // And A's own cycle is still the one payout it had.
    expect(await payoutRows(store.db, 10, PAID_EARLY)).toHaveLength(1);
  }, 600_000);

  it("pays that operator once: the next run of the same cycle passes both over", async () => {
    const skipped: string[] = [];
    const payouts = await payoutStep(db, adapter, 1, AT, (reason) =>
      skipped.push(reason),
    );

    expect(payouts).toEqual([]);
    // Both operators still hold something released — A's later accrual, and
    // nothing of B's, which its payout claimed — so only A is listed now.
    expect(skipped).toEqual(["payout_this_cycle"]);
    expect(await payoutRows(store.db, 10)).toHaveLength(2);
  }, 600_000);
});
