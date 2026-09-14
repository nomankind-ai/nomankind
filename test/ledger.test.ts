/**
 * The ledger, after decision D-127: it prices nothing, and it still adds up.
 *
 * "The record is free, no money anywhere." There is no price of a read, no
 * contributor share, no payout floor and no cycle, so the functions that used to
 * build priced rows build none: a published day of reads is worth nothing to
 * anybody, an upheld dispute claws back nothing, and a reconfirmation collects a
 * pool that was never filled. What the paper's Section 9 arithmetic came to is
 * history now, and the rows that arithmetic wrote are still in the table — which
 * is why `ledgerBalance` is tested at length below and the pricing is tested
 * only for being absent.
 *
 * Every event is a real sealed event and every instant comes from a fake clock.
 * No test asserts a bare amount without deriving it from the policy constant
 * that produces it, which is now HOLDBACK_DAYS and nothing else.
 */

import { describe, expect, it } from "vitest";
import {
  HOLDBACK_DAYS,
  appendEvent,
  bountyAccrualRow,
  buildReadCountPayload,
  clawbackRows,
  disputeRewardRow,
  ledgerBalance,
  readShareRows,
  reconciliationRow,
  type EntryShareState,
  type Event,
  type LedgerRow,
  type ReadCountRow,
  type StakeRecord,
} from "../src/index.js";

const ENTRY = "nmk_01M21LEDGER";
const OTHER = "nmk_01M21OTHER";
const SUBMITTER = "sub.example";
const SLOTS = ["v1.example", "v2.example", "v3.example"] as const;

/** The paper's old example: ten thousand reads in a month, worth nothing now. */
const READS = 10_000;
const DAY = "2026-09-08";
const AT = `${DAY}T12:00:00.000Z`;
const KEY = "key_0123456789abcdef";

/** The day a row accrued on `date` may leave: the thirty-day holdback, in full. */
function releaseOf(date: string): string {
  const shifted = Date.parse(`${date}T00:00:00.000Z`) + HOLDBACK_DAYS * 86_400_000;
  return new Date(shifted).toISOString();
}

async function readCount(
  rows: readonly ReadCountRow[],
  paid?: { reads: readonly ReadCountRow[]; keys: Record<string, number> },
): Promise<Event<"read_count">> {
  const log = await appendEvent([], {
    at: AT,
    type: "read_count",
    entry_id: null,
    payload: buildReadCountPayload(DAY, rows, 1, rows.length, paid),
  });
  return log[0] as Event<"read_count">;
}

/** A verified entry with a submitter and three seated slots: the paid case. */
function state(overrides: Partial<EntryShareState> = {}): EntryShareState {
  return {
    author_operator: SUBMITTER,
    read_share_slots: SLOTS.map((operator, index) => ({
      operator,
      seq: index + 1,
      measured: false,
    })),
    stale: false,
    verified: true,
    effective_tier: "stated",
    ...overrides,
  };
}

/** The signed record a reconfirmation carries, in the shape the log takes. */
function reconfirmationRecord() {
  return {
    agent: "1F916:YWdlbnRJZGVudGl0eUFBQUFBQUFBQUFBQUFBQQ",
    operator: SUBMITTER,
    snapshot_hash: `sha256:${"a".repeat(64)}`,
    reproduction: null,
    observation: null,
    signed_at: AT,
  } as never;
}

/** One stored `read_share` row, as the table still holds thousands of them. */
function storedShare(overrides: Partial<LedgerRow> = {}): LedgerRow {
  return {
    id: `read_share:1:${ENTRY}:submitter:${SUBMITTER}`,
    kind: "read_share",
    entry_id: ENTRY,
    operator: SUBMITTER,
    role: "submitter",
    date: DAY,
    reads: READS,
    unit: "micros",
    amount: 750_000,
    available_at: releaseOf(DAY),
    seq: 1,
    at: AT,
    ref: {},
    ...overrides,
  };
}

// ---------------------------------------------------------------------------
// Nothing is priced
// ---------------------------------------------------------------------------

describe("readShareRows", () => {
  it("builds no row for a day of reads, however many there were", async () => {
    const event = await readCount([
      { entry_id: ENTRY, count: READS },
      { entry_id: OTHER, count: 7 },
    ]);
    expect(readShareRows(event, () => state())).toEqual([]);
  });

  it("builds no bounty pool for a stale entry either", async () => {
    // The stale rule used to withhold half of every holder's share into a pool
    // on the entry. Half of nothing is nothing, and no pool row is written.
    const event = await readCount([{ entry_id: ENTRY, count: READS }]);
    expect(readShareRows(event, () => state({ stale: true }))).toEqual([]);
  });

  it("builds no row for a paid block, which is what a key's reads are", async () => {
    const event = await readCount(
      [{ entry_id: ENTRY, count: READS }],
      { reads: [{ entry_id: ENTRY, count: 4 }], keys: { [KEY]: 4 } },
    );
    // The block is still published — the counts are evidence of use (D-127) —
    // and nobody is paid for a single one of them.
    expect(event.payload.paid!.keys).toEqual({ [KEY]: 4 });
    expect(readShareRows(event, () => state())).toEqual([]);
  });
});

describe("clawbackRows", () => {
  it("claws back nothing, because nothing accrued", async () => {
    const log = await appendEvent([], {
      at: "2026-09-10T00:00:00.000Z",
      type: "dispute_upheld",
      entry_id: ENTRY,
      payload: { correction_entry_id: OTHER },
    });
    const event = log[0] as Event<"dispute_upheld">;
    // Even handed a held share from the log's own history, it writes nothing:
    // Section 6's clawback was a money rule, and there is no money.
    expect(clawbackRows(event, [storedShare()])).toEqual([]);
  });
});

describe("disputeRewardRow", () => {
  it("prices an upheld challenge's reward at zero, explicitly", () => {
    const owed: StakeRecord = {
      kind: "dispute_reward",
      entry_id: ENTRY,
      operator: SUBMITTER,
      agent: null,
      seq: 42,
      at: AT,
      unit: null,
      amount: null,
    } as unknown as StakeRecord;

    const row = disputeRewardRow(owed, []);
    expect(row.id).toBe("dispute_reward:42");
    expect(row.kind).toBe("dispute_reward");
    expect(row.unit).toBe("micros");
    // Zero and not null: the step has passed the row, and what it found was
    // nothing. A row left unpriced would read as an amount still to come.
    expect(row.amount).toBe(0);
    expect(row.available_at).toBeNull();
    expect(row.ref).toMatchObject({ clawed_back: 0, clawbacks: [] });
  });
});

describe("bountyAccrualRow", () => {
  it("is null where nothing was stale", async () => {
    const log = await appendEvent([], {
      at: AT,
      type: "reconfirmation",
      entry_id: ENTRY,
      payload: { record: reconfirmationRecord(), signature: "c2ln" },
    });
    const event = log[0] as Event<"reconfirmation">;
    expect(bountyAccrualRow(event, null, [])).toBeNull();
  });

  it("collects an empty pool: a reconfirmation is paid nothing", async () => {
    const log = await appendEvent([], {
      at: AT,
      type: "reconfirmation",
      entry_id: ENTRY,
      payload: { record: reconfirmationRecord(), signature: "c2ln" },
    });
    const event = log[0] as Event<"reconfirmation">;
    const row = bountyAccrualRow(
      event,
      {
        entry_id: ENTRY,
        operator: SUBMITTER,
        seq: event.seq,
        stale_from: "2026-06-01",
        stale_until: AT,
      } as never,
      [],
    );
    expect(row!.amount).toBe(0);
    expect(row!.ref["pooled"]).toEqual([]);
  });
});

// ---------------------------------------------------------------------------
// The reconciliation is about counts, and counts are still published
// ---------------------------------------------------------------------------

describe("reconciliationRow", () => {
  it("still reports the day's published total, with nothing accrued", async () => {
    const event = await readCount([
      { entry_id: ENTRY, count: READS },
      { entry_id: OTHER, count: 7 },
    ]);
    const row = reconciliationRow(event, new Map());
    expect(row.amount).toBe(0);
    expect(row.date).toBe(DAY);
    expect(row.ref).toEqual({
      ok: true,
      published_total: READS + 7,
      accrued_total: 0,
      mismatches: [],
      unpriced: [ENTRY, OTHER],
    });
  });
});

// ---------------------------------------------------------------------------
// The history still adds up
// ---------------------------------------------------------------------------

describe("ledgerBalance", () => {
  it("adds up what is held, released, clawed back and paid", () => {
    const share = storedShare();
    const clawback: LedgerRow = {
      ...share,
      id: `clawback:9:${share.id}`,
      kind: "clawback",
      amount: -share.amount,
    };
    const paid: LedgerRow = {
      id: `payout:${SUBMITTER}:2026-10-10`,
      kind: "payout",
      entry_id: null,
      operator: SUBMITTER,
      role: null,
      date: "2026-10-10",
      reads: null,
      unit: "micros",
      amount: 1_000,
      available_at: null,
      seq: 9,
      at: "2026-10-10T00:00:00.000Z",
      ref: {},
    };

    // Inside the holdback: the share and its clawback both wait, so nothing is
    // held, because nothing is owed.
    expect(ledgerBalance([share, clawback], "2026-09-09T00:00:00.000Z")).toEqual({
      accrued: share.amount,
      held: 0,
      released: 0,
      clawed_back: -share.amount,
      paid: 0,
      carried_forward: 0,
    });

    // Past it, with the payout that took money out.
    const later = ledgerBalance([share, paid], "2026-10-10T00:00:00.000Z");
    expect(later).toEqual({
      accrued: share.amount,
      held: 0,
      released: share.amount,
      clawed_back: 0,
      paid: 1_000,
      carried_forward: share.amount - 1_000,
    });
  });

  it("carries a priced reward at its release, and ignores an unpriced one", () => {
    const base = {
      entry_id: ENTRY,
      operator: SUBMITTER,
      role: null,
      date: null,
      reads: null,
      at: AT,
      ref: {},
    } as const;
    const release = "2026-10-08T00:00:00.000Z";
    const priced: LedgerRow = {
      ...base,
      id: "dispute_reward:99",
      kind: "dispute_reward",
      unit: "micros",
      amount: 4_000,
      available_at: release,
      seq: 99,
    };
    const unpriced: LedgerRow = {
      ...base,
      id: "dispute_reward:100",
      kind: "dispute_reward",
      unit: "standing",
      amount: 0,
      available_at: null,
      seq: 100,
    };

    expect(ledgerBalance([priced, unpriced], "2026-09-09T00:00:00.000Z")).toEqual({
      accrued: 4_000,
      held: 4_000,
      released: 0,
      clawed_back: 0,
      paid: 0,
      carried_forward: 0,
    });
    expect(ledgerBalance([priced, unpriced], release)).toEqual({
      accrued: 4_000,
      held: 0,
      released: 4_000,
      clawed_back: 0,
      paid: 0,
      carried_forward: 4_000,
    });
    // On its own the unpriced row moves nothing at all.
    expect(ledgerBalance([unpriced], release)).toEqual({
      accrued: 0,
      held: 0,
      released: 0,
      clawed_back: 0,
      paid: 0,
      carried_forward: 0,
    });
  });

  it("accrues a bounty pool row to nobody", () => {
    const pool = storedShare({
      id: `bounty_pool:1:${ENTRY}`,
      kind: "bounty_pool",
      operator: null,
      role: null,
      available_at: null,
    });
    expect(ledgerBalance([pool], "2026-12-01T00:00:00.000Z")).toEqual({
      accrued: 0,
      held: 0,
      released: 0,
      clawed_back: 0,
      paid: 0,
      carried_forward: 0,
    });
  });
});
