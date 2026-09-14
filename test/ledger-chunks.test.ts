/**
 * The ledger step's work, which is now none.
 *
 * Decision D-127, "the record is free, no money anywhere": nothing is priced,
 * so the step that used to cut a published day into runs — LEDGER_ENTRIES_PER_RUN
 * entries at a time, resuming the same day across sweeps, reconciling it whole
 * on the run that reached the end — has nothing to cut. A day on which three
 * runs' worth of entries were each read ten times is built here exactly as it
 * was, because the point of the test is what the step does with it: no read
 * share, no bounty pool, no reconciliation, no batch, and a cursor that still
 * moves so a fork can restart from it.
 *
 * `putLedgerRows` keeps its own test below: the ledger table still holds the
 * rows the log accrued while the record was sold, and writing a set of them has
 * to stay inside what D1 will take.
 *
 * The database is miniflare's D1 with every migration applied, wrapped in a
 * counter that records every statement and the size of every batch. The log is
 * the real one: `appendEvent` chains and hashes every event.
 */

import { afterAll, beforeAll, describe, expect, it } from "vitest";

import type { Core } from "../src/core.js";
import type { Sidecar } from "../src/derive.js";
import { appendEvent, type Event } from "../src/events.js";
import type { LedgerRow } from "../src/ledger.js";
import {
  DEFAULT_DOMAIN,
  LEDGER_ENTRIES_PER_RUN,
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
  putEntry,
  putLedgerRows,
  reconciliationRows,
} from "../src/storage/repository.js";
import { LEDGER_CURSOR, ledgerStep } from "../src/worker/sweep.js";
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

  it("prices nothing, writes nothing, and says so", async () => {
    db.reset();
    // Never null: the step returns null only where no seal exists, and the
    // caller decides that, not the step.
    const report = (await ledgerStep(db, daySeq))!;

    // Decision D-127: the record is free. A published day of reads over three
    // runs' worth of entries is worth nothing to anybody, so the step that used
    // to cut it into runs has nothing to cut.
    expect(report).toEqual({
      through: daySeq,
      read_shares: 0,
      clawbacks: 0,
      bounties: 0,
      reconciliations: 0,
      entries: 0,
      day: null,
      ok: true,
    });
    expect(await reconciliationRows(store.db, 10)).toEqual([]);
    expect(await ledgerRowsForOperator(store.db, OPERATOR, 1000)).toEqual([]);
    for (const operator of SLOT_OPERATORS) {
      expect(await ledgerRowsForOperator(store.db, operator, 1000)).toEqual([]);
    }
    // Nothing was written: no batch at all, only the cursor move.
    expect(db.batches).toEqual([]);
  }, 600_000);

  it("still moves the cursor a fork restarts from", async () => {
    // `npm run import-mirror` sets LEDGER_CURSOR to the imported sealed head so
    // a fork's first sweep carries on from there. A step that stopped writing it
    // would leave that value standing at a position nothing ever advances, so
    // the cursor stays even though the pricing it guarded is gone.
    expect(await ledgerCursor(store.db, LEDGER_CURSOR)).toBe(daySeq);
  }, 600_000);

  it("is idempotent: a second run over the same head does the same nothing", async () => {
    db.reset();
    const again = (await ledgerStep(db, daySeq))!;
    expect(again.through).toBe(daySeq);
    expect(again.read_shares).toBe(0);
    expect(db.batches).toEqual([]);
    expect(await reconciliationRows(store.db, 10)).toEqual([]);
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
