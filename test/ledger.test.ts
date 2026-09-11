/**
 * The ledger: read shares, the stale bounty pool, clawbacks, payouts and the
 * daily reconciliation.
 *
 * The first test is the paper's own worked example, because it is the one number
 * Section 9 commits to in public: "At $0.50 per thousand paid reads, an entry
 * read ten thousand times in a month earns its submitter 75 cents and each
 * validator 25." If that arithmetic ever stops coming out, the paper is wrong or
 * the code is, and either way somebody has to look.
 *
 * Every event is a real sealed event and every instant comes from a fake clock.
 * No test asserts a bare amount without deriving it from the policy constants
 * that produce it.
 */

import { describe, expect, it } from "vitest";
import {
  HOLDBACK_DAYS,
  PAYOUT_MINIMUM_MICROS,
  READ_PRICE_MICROS_PER_READ,
  READ_SHARE_SPLIT,
  SLOT_COUNT,
  appendEvent,
  bountyAccrual,
  bountyAccrualRow,
  buildReadCountPayload,
  clawbackRows,
  ledgerBalance,
  payoutPlan,
  payoutRow,
  readShareRows,
  reconciliationRow,
  type EntryShareState,
  type Event,
  type LedgerRow,
  type ReadCountRow,
} from "../src/index.js";

const ENTRY = "nmk_01M21LEDGER";
const OTHER = "nmk_01M21OTHER";
const SUBMITTER = "sub.example";
const SLOTS = ["v1.example", "v2.example", "v3.example"] as const;

/** The paper's example: ten thousand reads in a month. */
const READS = 10_000;
const DAY = "2026-09-08";
const AT = `${DAY}T12:00:00.000Z`;

/** The day a row accrued on `date` may leave: the thirty-day holdback, in full. */
function releaseOf(date: string): string {
  const shifted = Date.parse(`${date}T00:00:00.000Z`) + HOLDBACK_DAYS * 86_400_000;
  return new Date(shifted).toISOString();
}

async function readCount(
  rows: readonly ReadCountRow[],
  date = DAY,
  at = AT,
): Promise<Event<"read_count">> {
  const log = await appendEvent([], {
    at,
    type: "read_count",
    entry_id: null,
    payload: buildReadCountPayload(date, rows, 1, rows.length),
  });
  return log[0] as Event<"read_count">;
}

function state(overrides: Partial<EntryShareState> = {}): EntryShareState {
  return {
    author_operator: SUBMITTER,
    read_share_slots: SLOTS.map((operator, index) => ({
      operator,
      seq: index + 1,
    })),
    stale: false,
    verified: true,
    ...overrides,
  };
}

/** The whole share of one day's reads, before the stale rule halves it. */
function share(percent: number, count = READS): number {
  return Math.floor((count * READ_PRICE_MICROS_PER_READ * percent) / 100);
}

describe("readShareRows", () => {
  it("splits the paper's own example, to the micro", async () => {
    const event = await readCount([{ entry_id: ENTRY, count: READS }]);
    const rows = readShareRows(event, () => state());

    // 75 cents to the submitter, 25 to each of the three slot holders.
    expect(rows).toHaveLength(1 + SLOT_COUNT);
    expect(rows.filter((row) => row.kind === "bounty_pool")).toEqual([]);

    const submitter = rows[0]!;
    expect(submitter).toMatchObject({
      id: `read_share:${event.seq}:${ENTRY}:submitter:${SUBMITTER}`,
      kind: "read_share",
      entry_id: ENTRY,
      operator: SUBMITTER,
      role: "submitter",
      date: DAY,
      reads: READS,
      unit: "micros",
      amount: 750_000,
      available_at: releaseOf(DAY),
    });
    expect(submitter.amount).toBe(share(READ_SHARE_SPLIT.submitter));
    expect(submitter.ref).toEqual({
      price_micros_per_read: READ_PRICE_MICROS_PER_READ,
      share_percent: READ_SHARE_SPLIT.submitter,
      stale: false,
    });

    for (const operator of SLOTS) {
      const row = rows.find((candidate) => candidate.operator === operator)!;
      expect(row.role).toBe("validator");
      expect(row.amount).toBe(250_000);
      expect(row.amount).toBe(share(READ_SHARE_SPLIT.validator));
      expect(row.id).toBe(
        `read_share:${event.seq}:${ENTRY}:validator:${operator}`,
      );
    }

    // Thirty percent of the day's revenue reaches contributors, and no more.
    const paid = rows.reduce((sum, row) => sum + row.amount, 0);
    expect(paid).toBe(1_500_000);
    expect(paid).toBe((READS * READ_PRICE_MICROS_PER_READ * 30) / 100);
  });

  it("halves every share on a stale day and pools the withheld halves", async () => {
    const event = await readCount([{ entry_id: ENTRY, count: READS }]);
    const rows = readShareRows(event, () => state({ stale: true }));

    const shares = rows.filter((row) => row.kind === "read_share");
    const pool = rows.filter((row) => row.kind === "bounty_pool");
    expect(shares).toHaveLength(1 + SLOT_COUNT);
    expect(pool).toHaveLength(1);

    let withheld = 0;
    for (const row of shares) {
      const percent =
        row.role === "submitter"
          ? READ_SHARE_SPLIT.submitter
          : READ_SHARE_SPLIT.validator;
      const full = share(percent);
      expect(row.amount).toBe(Math.floor(full / 2));
      expect(row.ref).toMatchObject({ stale: true });
      withheld += full - row.amount;
    }

    expect(pool[0]).toMatchObject({
      id: `bounty_pool:${event.seq}:${ENTRY}`,
      kind: "bounty_pool",
      entry_id: ENTRY,
      // The pool belongs to the entry: whoever reconfirms it collects it.
      operator: null,
      role: null,
      date: DAY,
      amount: withheld,
      available_at: null,
    });
    expect(pool[0]!.amount).toBe(750_000);
    expect(withheld + shares.reduce((sum, row) => sum + row.amount, 0)).toBe(
      1_500_000,
    );
  });

  it("pays only the slot holders when the submitter was a bare key", async () => {
    const event = await readCount([{ entry_id: ENTRY, count: READS }]);
    const rows = readShareRows(event, () => state({ author_operator: null }));
    expect(rows).toHaveLength(SLOT_COUNT);
    expect(rows.every((row) => row.role === "validator")).toBe(true);
  });

  it("pays nothing for an entry that is not verified, or that it cannot state", async () => {
    const event = await readCount([{ entry_id: ENTRY, count: READS }]);
    expect(readShareRows(event, () => state({ verified: false }))).toEqual([]);
    expect(readShareRows(event, () => null)).toEqual([]);
    // A verified entry with no submitter and no slots yet pays nobody.
    expect(
      readShareRows(event, () =>
        state({ author_operator: null, read_share_slots: null }),
      ),
    ).toEqual([]);
  });

  it("prices each entry of a day from its own state", async () => {
    const event = await readCount([
      { entry_id: ENTRY, count: READS },
      { entry_id: OTHER, count: 1 },
    ]);
    const rows = readShareRows(event, (entryId) =>
      entryId === ENTRY
        ? state()
        : state({ author_operator: "other.example", read_share_slots: [] }),
    );
    expect(rows.filter((row) => row.entry_id === OTHER)).toHaveLength(1);
    expect(rows.find((row) => row.entry_id === OTHER)!.amount).toBe(
      share(READ_SHARE_SPLIT.submitter, 1),
    );
  });

  it("writes the same ids twice, so a replayed day writes no second set", async () => {
    const event = await readCount([{ entry_id: ENTRY, count: READS }]);
    const first = readShareRows(event, () => state());
    const second = readShareRows(event, () => state());
    expect(second).toEqual(first);
    expect(new Set(first.map((row) => row.id)).size).toBe(first.length);
  });
});

describe("clawbackRows", () => {
  async function upheld(at: string): Promise<Event<"dispute_upheld">> {
    const log = await appendEvent([], {
      at,
      type: "dispute_upheld",
      entry_id: ENTRY,
      payload: { correction_entry_id: "nmk_01M21CORRECTION" },
    });
    return log[0] as Event<"dispute_upheld">;
  }

  it("negates every held row and leaves every released one alone", async () => {
    const day = await readCount([{ entry_id: ENTRY, count: READS }]);
    const held = readShareRows(day, () => state());
    // A second day, thirty days earlier, whose rows have already been released.
    const older = await readCount(
      [{ entry_id: ENTRY, count: READS }],
      "2026-08-01",
      "2026-08-01T12:00:00.000Z",
    );
    const released = readShareRows(older, () => state());

    const event = await upheld("2026-09-10T00:00:00.000Z");
    const rows = clawbackRows(event, [...held, ...released]);

    expect(rows).toHaveLength(held.length);
    for (const [index, row] of rows.entries()) {
      const source = held[index]!;
      expect(row).toMatchObject({
        id: `clawback:${event.seq}:${source.id}`,
        kind: "clawback",
        entry_id: ENTRY,
        operator: source.operator,
        unit: "micros",
        amount: -source.amount,
        // The negated row's own release instant: the two wait out one holdback
        // and come to nothing together.
        available_at: source.available_at,
        ref: { claws_back: source.id },
      });
    }
    // Section 9: "A dispute upheld later claws back nothing."
    const late = await upheld("2027-01-01T00:00:00.000Z");
    expect(clawbackRows(late, [...held, ...released])).toEqual([]);
  });

  it("claws back nothing from a pool row, which is owed to nobody", async () => {
    const day = await readCount([{ entry_id: ENTRY, count: READS }]);
    const rows = readShareRows(day, () => state({ stale: true }));
    const event = await upheld("2026-09-10T00:00:00.000Z");
    const clawed = clawbackRows(event, rows);
    expect(clawed.every((row) => row.role !== null)).toBe(true);
    expect(clawed).toHaveLength(1 + SLOT_COUNT);
  });
});

describe("bountyAccrualRow", () => {
  async function reconfirmation(at: string): Promise<Event<"reconfirmation">> {
    const log = await appendEvent([], {
      at,
      type: "reconfirmation",
      entry_id: ENTRY,
      payload: {
        record: {
          agent: "1F916:agent-r",
          operator: SLOTS[0],
          snapshot_hash: `sha256:${"4d".repeat(32)}`,
          reproduction: null,
          observation: null,
          signed_at: at,
        },
        signature: "c2ln",
      },
    });
    return log[0] as Event<"reconfirmation">;
  }

  /** One withheld pool row, dated. */
  async function pooled(date: string): Promise<LedgerRow> {
    const event = await readCount([{ entry_id: ENTRY, count: READS }], date, `${date}T12:00:00.000Z`);
    const rows = readShareRows(event, () => state({ stale: true }));
    return rows.find((row) => row.kind === "bounty_pool")!;
  }

  it("sums the pool rows inside the stale window and only those", async () => {
    const event = await reconfirmation("2026-09-20T00:00:00.000Z");
    const accrual = bountyAccrual(
      { expires_at: "2026-09-10", stale: true },
      event,
    );
    const pool = [
      // Before the window: collected by whoever ended the last stale spell.
      await pooled("2026-09-05"),
      await pooled("2026-09-12"),
      await pooled("2026-09-15"),
      // After the reconfirmation made it fresh again: a later spell's.
      await pooled("2026-09-25"),
    ];

    const row = bountyAccrualRow(event, accrual, pool);
    expect(row).toMatchObject({
      id: `bounty_accrual:${event.seq}`,
      kind: "bounty_accrual",
      entry_id: ENTRY,
      operator: SLOTS[0],
      role: "reconfirmer",
      unit: "micros",
      amount: pool[1]!.amount + pool[2]!.amount,
      available_at: releaseOf("2026-09-20"),
    });
    expect(row!.ref).toMatchObject({
      stale_from: "2026-09-10",
      stale_until: "2026-09-20T00:00:00.000Z",
      pooled: [pool[1]!.id, pool[2]!.id],
    });
  });

  it("prices nothing when the entry was not stale", async () => {
    const event = await reconfirmation("2026-09-20T00:00:00.000Z");
    expect(bountyAccrualRow(event, null, [])).toBeNull();
    expect(
      bountyAccrualRow(
        event,
        bountyAccrual({ expires_at: "2026-12-01", stale: false }, event),
        [],
      ),
    ).toBeNull();
  });

  it("prices a stale window with no reads at zero", async () => {
    const event = await reconfirmation("2026-09-20T00:00:00.000Z");
    const accrual = bountyAccrual({ expires_at: "2026-09-10", stale: true }, event);
    expect(bountyAccrualRow(event, accrual, [])!.amount).toBe(0);
  });
});

describe("payoutPlan and payoutRow", () => {
  const NOW = "2026-11-01T00:00:00.000Z";

  function row(overrides: Partial<LedgerRow>): LedgerRow {
    return {
      id: "read_share:1:x:submitter:sub.example",
      kind: "read_share",
      entry_id: ENTRY,
      operator: SUBMITTER,
      role: "submitter",
      date: DAY,
      reads: READS,
      unit: "micros",
      amount: PAYOUT_MINIMUM_MICROS,
      available_at: "2026-10-08T00:00:00.000Z",
      seq: 1,
      at: AT,
      ref: {},
      ...overrides,
    };
  }

  it("pays at the minimum and names the rows it covers", () => {
    const rows = [row({}), row({ id: "b", amount: 1 })];
    const plan = payoutPlan(SUBMITTER, rows, NOW);
    expect(plan).toEqual({
      operator: SUBMITTER,
      amount: PAYOUT_MINIMUM_MICROS + 1,
      rows: [rows[0]!.id, "b"],
      carried_forward: 0,
    });
  });

  it("carries forward below the minimum and claims nothing", () => {
    const plan = payoutPlan(SUBMITTER, [row({ amount: 1 })], NOW);
    expect(plan).toEqual({
      operator: SUBMITTER,
      amount: 0,
      // Nothing is claimed: a plan that named its rows without paying them
      // would let the next cycle think they had already left.
      rows: [],
      carried_forward: 1,
    });
  });

  it("never counts a row still inside the holdback", () => {
    const held = row({ id: "held", available_at: "2026-12-01T00:00:00.000Z" });
    const plan = payoutPlan(SUBMITTER, [row({}), held], NOW);
    expect(plan.rows).not.toContain("held");
    expect(plan.amount).toBe(PAYOUT_MINIMUM_MICROS);
  });

  it("counts a released clawback against the cycle", () => {
    const clawback = row({
      id: "clawback:9:x",
      kind: "clawback",
      amount: -PAYOUT_MINIMUM_MICROS,
    });
    const plan = payoutPlan(SUBMITTER, [row({}), clawback], NOW);
    expect(plan.amount).toBe(0);
    expect(plan.carried_forward).toBe(0);
    expect(plan.rows).toEqual([]);
  });

  it("never pays a share whose clawback is still held", () => {
    // The clawback carries the share's own available_at, so the two are held
    // together: a share cannot leave while the row that negates it waits.
    const stillHeld = "2026-12-01T00:00:00.000Z";
    const share = row({ id: "held", available_at: stillHeld });
    const clawback = row({
      id: "clawback:9:held",
      kind: "clawback",
      amount: -PAYOUT_MINIMUM_MICROS,
      available_at: stillHeld,
    });
    const plan = payoutPlan(SUBMITTER, [share, clawback], NOW);
    expect(plan.rows).toEqual([]);
    expect(plan.amount).toBe(0);
    expect(plan.carried_forward).toBe(0);
  });

  it("counts one operator's rows and nobody else's", () => {
    const plan = payoutPlan(SUBMITTER, [row({}), row({ id: "x", operator: SLOTS[0] })], NOW);
    expect(plan.rows).toHaveLength(1);
  });

  it("records the transfer that took the money out", () => {
    const plan = payoutPlan(SUBMITTER, [row({})], NOW);
    const paid = payoutRow(plan, 42, NOW, "mock-verified-sub");
    expect(paid).toMatchObject({
      id: `payout:${SUBMITTER}:2026-11-01`,
      kind: "payout",
      operator: SUBMITTER,
      entry_id: null,
      unit: "micros",
      amount: PAYOUT_MINIMUM_MICROS,
      available_at: null,
      seq: 42,
      at: NOW,
    });
    expect(paid.ref).toEqual({ reference: "mock-verified-sub", rows: plan.rows });
  });
});

describe("reconciliationRow", () => {
  it("is ok when what accrued equals what was published", async () => {
    const event = await readCount([
      { entry_id: ENTRY, count: READS },
      { entry_id: OTHER, count: 7 },
    ]);
    const row = reconciliationRow(
      event,
      new Map([
        [ENTRY, READS],
        [OTHER, 7],
      ]),
    );
    expect(row).toMatchObject({
      id: `reconciliation:${DAY}`,
      kind: "reconciliation",
      date: DAY,
      reads: READS + 7,
      amount: 0,
    });
    expect(row.ref).toEqual({
      ok: true,
      published_total: READS + 7,
      accrued_total: READS + 7,
      mismatches: [],
      unpriced: [],
    });
  });

  it("names the entry that disagrees", async () => {
    const event = await readCount([
      { entry_id: ENTRY, count: READS },
      { entry_id: OTHER, count: 7 },
    ]);
    const row = reconciliationRow(
      event,
      new Map([
        [ENTRY, READS],
        [OTHER, 6],
      ]),
    );
    expect(row.ref).toMatchObject({
      ok: false,
      mismatches: [{ entry_id: OTHER, published: 7, accrued: 6 }],
    });
  });

  it("reports an entry nobody was paid for rather than passing over it", async () => {
    const event = await readCount([
      { entry_id: ENTRY, count: READS },
      { entry_id: OTHER, count: 7 },
    ]);
    const row = reconciliationRow(event, new Map([[ENTRY, READS]]));
    // Not a mismatch — it had no share holder — but never silence either.
    expect(row.ref).toMatchObject({
      ok: true,
      unpriced: [OTHER],
      accrued_total: READS,
      published_total: READS + 7,
    });
  });
});

describe("ledgerBalance", () => {
  it("adds up what is held, released, clawed back and paid", async () => {
    const day = await readCount([{ entry_id: ENTRY, count: READS }]);
    const rows = readShareRows(day, () => state({ stale: true }));
    const shares = rows.filter((row) => row.kind === "read_share");
    const accrued = shares.reduce((sum, row) => sum + row.amount, 0);

    // Inside the holdback: everything is held and nothing is payable.
    const early = ledgerBalance(rows, "2026-09-09T00:00:00.000Z");
    expect(early).toMatchObject({
      accrued,
      held: accrued,
      released: 0,
      clawed_back: 0,
      paid: 0,
      carried_forward: 0,
    });
    // The pool rows are owed to nobody, so they accrue to nobody.
    expect(early.accrued).toBe(accrued);

    // Past it, with one share clawed back and one payout made.
    const clawback: LedgerRow = {
      ...shares[0]!,
      id: `clawback:9:${shares[0]!.id}`,
      kind: "clawback",
      amount: -shares[0]!.amount,
    };
    const paid = payoutRow(
      { operator: SUBMITTER, amount: 1000, rows: [], carried_forward: 0 },
      9,
      "2026-10-10T00:00:00.000Z",
      "mock-verified-sub",
    );
    const later = ledgerBalance(
      [...rows, clawback, paid],
      "2026-10-10T00:00:00.000Z",
    );
    expect(later).toMatchObject({
      accrued,
      held: 0,
      // Released nets the clawback against the share it negates: what is
      // payable is what is left after the money that has to come back.
      released: accrued - shares[0]!.amount,
      clawed_back: -shares[0]!.amount,
      paid: 1000,
      carried_forward: accrued - shares[0]!.amount - 1000,
    });
  });

  it("nets a held share against its clawback, and holds both", async () => {
    const day = await readCount([{ entry_id: ENTRY, count: READS }]);
    const share = readShareRows(day, () => state())[0]!;
    const clawback: LedgerRow = {
      ...share,
      id: `clawback:9:${share.id}`,
      kind: "clawback",
      amount: -share.amount,
    };

    // Inside the holdback, both rows wait: nothing is held, because nothing is
    // owed, and nothing carries forward, because nothing is payable.
    const balance = ledgerBalance([share, clawback], "2026-09-09T00:00:00.000Z");
    expect(balance).toEqual({
      accrued: share.amount,
      held: 0,
      released: 0,
      clawed_back: -share.amount,
      paid: 0,
      carried_forward: 0,
    });
  });
});

// ---------------------------------------------------------------------------
// M24: only the paid half of a day earns
// ---------------------------------------------------------------------------

describe("a published day with a paid block", () => {
  const KEY = "key_0123456789abcdef";

  /** One day whose rows count every reader and whose block names the payers. */
  async function paidDay(
    rows: readonly ReadCountRow[],
    paid: { reads: readonly ReadCountRow[]; keys: Record<string, number> },
  ): Promise<Event<"read_count">> {
    const log = await appendEvent([], {
      at: AT,
      type: "read_count",
      entry_id: null,
      payload: buildReadCountPayload(DAY, rows, 1, rows.length, paid),
    });
    return log[0] as Event<"read_count">;
  }

  it("prices the paid rows and never the free ones", async () => {
    const event = await paidDay(
      [
        { entry_id: ENTRY, count: READS },
        { entry_id: OTHER, count: 7 },
      ],
      { reads: [{ entry_id: ENTRY, count: 4 }], keys: { [KEY]: 4 } },
    );
    const rows = readShareRows(event, () => state());

    // Four reads, not ten thousand and seven: the rest of the day was free.
    expect(rows.every((row) => row.entry_id === ENTRY)).toBe(true);
    expect(rows.every((row) => row.reads === 4)).toBe(true);
    expect(rows[0]!.amount).toBe(share(READ_SHARE_SPLIT.submitter, 4));
  });

  it("reconciles against the paid rows, and says ok", async () => {
    const event = await paidDay(
      [
        { entry_id: ENTRY, count: READS },
        { entry_id: OTHER, count: 7 },
      ],
      { reads: [{ entry_id: ENTRY, count: 4 }], keys: { [KEY]: 4 } },
    );
    const rows = readShareRows(event, () => state());
    const accrued = new Map<string, number>();
    for (const row of rows) {
      if (row.kind === "read_share" && row.entry_id !== null && row.reads !== null) {
        accrued.set(row.entry_id, row.reads);
      }
    }
    const row = reconciliationRow(event, accrued);
    expect(row.ref).toEqual({
      ok: true,
      published_total: 4,
      accrued_total: 4,
      mismatches: [],
      unpriced: [],
    });
  });

  it("prices nothing at all on a day nobody paid for", async () => {
    const event = await paidDay([{ entry_id: ENTRY, count: 3 }], {
      reads: [],
      keys: {},
    });
    expect(readShareRows(event, () => state())).toEqual([]);
    expect(reconciliationRow(event, new Map()).ref).toMatchObject({
      ok: true,
      published_total: 0,
      accrued_total: 0,
    });
  });

  it("prices an event with no block from its rows, as it always did", async () => {
    // The M21 shape: a payload sealed before paid access existed.
    const event = await readCount([{ entry_id: ENTRY, count: READS }]);
    expect("paid" in event.payload).toBe(false);
    const rows = readShareRows(event, () => state());
    expect(rows).toHaveLength(1 + SLOT_COUNT);
    expect(rows[0]!.reads).toBe(READS);
  });
});
