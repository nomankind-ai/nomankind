/**
 * The anchor step's backlog: every sealed day gets its anchor, however the
 * sweeps fell.
 *
 * Whitepaper Section 12: the external anchor is what narrows the window a
 * compromised witness set could rewrite to the gap between sealing and
 * anchoring. A step that asked only about yesterday left that promise to the
 * timer's luck — a UTC day whose following day saw no sweep at all was never
 * anchored, and its window never closed. So the step walks the days it owes:
 * from the day after the newest anchored one — or from the day the log was
 * first sealed on — through yesterday, anchoring the oldest still owed and
 * leaving the rest to the runs after it, which is the pattern the read-count
 * step already uses.
 *
 * The world here is a real D1 with every migration applied, a real chained log
 * and real seals built by `buildSeal`; the clock is injected and the only fake
 * is the timestamping chain, because a calendar is not ours to run in a test.
 */

import { afterAll, beforeAll, describe, expect, it } from "vitest";

import type { EnvironmentWitnessAdapter } from "../src/adapters/witness.js";
import {
  utcDay,
  type AnchorAdapter,
  type AnchorExternal,
} from "../src/anchor.js";
import type { Core } from "../src/core.js";
import { appendEvent, type Event } from "../src/events.js";
import { DEFAULT_DOMAIN } from "../src/policy.js";
import { buildSeal, type Seal } from "../src/seal.js";
import {
  appendEvents,
  getAnchor,
  putSeal,
} from "../src/storage/repository.js";
import { anchorStep } from "../src/worker/sweep.js";
import { openTestDatabase, type TestDatabase } from "./helpers/d1.js";
import {
  FakeAnchorAdapter,
  FakeWitnessAdapter,
  pinnedSet,
} from "./helpers/witness.js";

/** A unit constant: the fake clock moves in whole days. */
const DAY_MS = 86_400_000;

/** Day 0 of this world, at five past midnight — the sweep's own hour. */
const DAY_ZERO = Date.parse("2026-09-01T00:05:00.000Z");

/** The instant `days` after day 0, at the same time of day. */
function at(days: number): Date {
  return new Date(DAY_ZERO + days * DAY_MS);
}

/** The UTC calendar day `days` after day 0. */
function day(days: number): string {
  return utcDay(at(days).toISOString());
}

/** The receipt a fake calendar answers with. */
const RECEIPT: AnchorExternal = {
  kind: "opentimestamps" as const,
  submitted_at: "2026-09-13T00:05:00.000Z",
  calendar: "https://alice.btc.calendar.opentimestamps.org",
  proof: "ZmFrZS1wcm9vZg",
  upgraded: null,
};

/** What the report of one run says, and what it counted on the way. */
interface Run {
  readonly anchored: Awaited<ReturnType<typeof anchorStep>>;
  readonly skipped: Record<string, number>;
  readonly asked: string[];
}

describe("the anchor step walks the days it owes", () => {
  let store: TestDatabase;
  /** The whole log, in order. */
  let events: Event[] = [];
  /** The seal chain, in order. */
  const seals: Seal[] = [];

  beforeAll(async () => {
    store = await openTestDatabase();
  }, 600_000);

  afterAll(async () => {
    await store?.dispose();
  });

  /** One more event in the log: what a day's seal is made over. */
  async function addEvent(days: number): Promise<void> {
    const id = `nmk_backlog_${events.length}`;
    const core = {
      id,
      domain: DEFAULT_DOMAIN,
      subject: "kestrel-1",
      category: "pricing",
      submitted_at: at(days).toISOString(),
    } as unknown as Core;
    events = await appendEvent(events, {
      at: at(days).toISOString(),
      type: "entry_submitted",
      entry_id: id,
      payload: { core, signature: "c2lnbmF0dXJl" },
    });
    await appendEvents(store.db, events.slice(-1));
  }

  /** A seal sealed on that day, over everything the last one did not cover. */
  async function sealOn(days: number): Promise<Seal> {
    await addEvent(days);
    const previous = seals.length === 0 ? null : seals[seals.length - 1]!;
    const built = await buildSeal(events, previous, {
      now: at(days).toISOString(),
    });
    if (!built.ok) throw new Error(`buildSeal refused: ${built.reason}`);
    await putSeal(store.db, built.seal);
    seals.push(built.seal);
    return built.seal;
  }

  /** One run of the step, at that instant, against a chain with that answer. */
  async function run(
    days: number,
    receipt: AnchorExternal = RECEIPT,
  ): Promise<Run> {
    const calendar: AnchorAdapter = new FakeAnchorAdapter(receipt);
    const skipped: Record<string, number> = {};
    const anchored = await anchorStep(
      store.db,
      {
        now: at(days),
        witness: new FakeWitnessAdapter() as EnvironmentWitnessAdapter,
        pinned: pinnedSet([]),
        ineligibleAgents: new Set<string>(),
        anchor: calendar,
      },
      (reason: string) => {
        skipped[reason] = (skipped[reason] ?? 0) + 1;
      },
    );
    return {
      anchored,
      skipped,
      asked: (calendar as FakeAnchorAdapter).asked,
    };
  }

  it("anchors nothing at all while nothing has been sealed", async () => {
    const first = await run(13);
    expect(first.anchored).toBeNull();
    expect(first.skipped).toEqual({ no_seals_to_anchor: 1 });
    expect(first.asked).toEqual([]);
  }, 600_000);

  it("anchors day 10 on the day 13 run, though yesterday held no seals", async () => {
    // The world seals on day 10, no sweep runs on day 11 or 12, and the next
    // sweep is on day 13. The old step asked only about day 12 and would have
    // left day 10 unanchored forever.
    await sealOn(10);
    await sealOn(13);

    const thirteenth = await run(13);

    expect(thirteenth.anchored).toEqual({
      date: day(10),
      seals: 1,
      external: "opentimestamps",
    });
    expect(thirteenth.asked).toEqual([day(10)]);
    // Day 13's seal is today's, and today is not over, so nothing behind day 10
    // is owed yet and the run does not claim a backlog it does not have.
    expect(thirteenth.skipped).toEqual({});

    const anchored = await getAnchor(store.db, day(10));
    expect(anchored!.roots).toEqual([seals[0]!.root]);
    expect(anchored!.external).toEqual(RECEIPT);
  }, 600_000);

  it("skips day 11 and day 12, which have no seals, without an anchor", async () => {
    // Day 13's own seal is what the run on day 14 owes an anchor for; the two
    // days between are never anchored — an anchor with no roots would be a
    // claim about a day nothing was sealed on — and the step never so much as
    // looks at them, because the next day owed is asked of the seals.
    const fourteenth = await run(14);

    expect(fourteenth.anchored).toEqual({
      date: day(13),
      seals: 1,
      external: "opentimestamps",
    });
    expect(fourteenth.asked).toEqual([day(13)]);
    // Day 13 is yesterday, so nothing is owed behind it any more.
    expect(fourteenth.skipped).toEqual({});

    expect(await getAnchor(store.db, day(11))).toBeNull();
    expect(await getAnchor(store.db, day(12))).toBeNull();
  }, 600_000);

  it("counts already_anchored once the backlog is empty", async () => {
    const again = await run(14);
    expect(again.anchored).toBeNull();
    expect(again.skipped).toEqual({ already_anchored: 1 });
    // And the chain was not asked a second time about a day it already took.
    expect(again.asked).toEqual([]);
  }, 600_000);

  it("takes one day a run, oldest first, when several are owed", async () => {
    await sealOn(15);
    await sealOn(16);

    const first = await run(17);
    expect(first.anchored).toMatchObject({ date: day(15) });
    expect(first.skipped).toEqual({ anchor_bounded: 1 });

    const second = await run(17);
    expect(second.anchored).toMatchObject({ date: day(16) });
    expect(second.skipped).toEqual({});
  }, 600_000);

  it("retries the receipt only when the walk owes nothing", async () => {
    await sealOn(18);

    // The calendar is down: the record is written and the receipt is not.
    const pending = await run(19, null);
    expect(pending.anchored).toEqual({
      date: day(18),
      seals: 1,
      external: null,
    });
    expect(pending.skipped).toEqual({ anchor_pending: 1 });
    expect((await getAnchor(store.db, day(18)))!.external).toBeNull();

    // The next run posts the same day's hash again rather than walking past it,
    // and the record it already wrote is the one that gets the receipt.
    const receipted = await run(19);
    expect(receipted.anchored).toEqual({
      date: day(18),
      seals: 1,
      external: "opentimestamps",
    });
    expect(receipted.asked).toEqual([day(18)]);
    expect((await getAnchor(store.db, day(18)))!.external).toEqual(RECEIPT);
  }, 600_000);

  it("walks past a day the chain never took rather than standing on it", async () => {
    // Day 25 is anchored while the calendar is down, so its record carries no
    // receipt. An outage must not become a stall: the two sealed days after it
    // are anchored by the next two runs, and the receiptless day is left to the
    // retry above and to the upgrade step, not to the walk.
    await sealOn(25);
    const down = await run(26, null);
    expect(down.anchored).toEqual({ date: day(25), seals: 1, external: null });
    expect((await getAnchor(store.db, day(25)))!.external).toBeNull();

    await sealOn(26);
    await sealOn(27);

    const first = await run(28);
    expect(first.anchored).toMatchObject({ date: day(26) });
    expect(first.skipped).toEqual({ anchor_bounded: 1 });
    expect(first.asked).toEqual([day(26)]);

    const second = await run(28);
    expect(second.anchored).toMatchObject({ date: day(27) });
    expect(second.asked).toEqual([day(27)]);

    // And the day the chain refused still has no receipt: the walk never went
    // back to it, which is the whole point.
    expect((await getAnchor(store.db, day(25)))!.external).toBeNull();
  }, 600_000);

  it("crosses a gap of a hundred and fifty sealless days in one run", async () => {
    // Nothing at all between day 28 and day 200. Stepping the calendar a page
    // of days at a time recorded no progress and stalled here forever; the next
    // day owed is one seek on the seals, so the gap costs nothing.
    await sealOn(200);

    const crossed = await run(201);
    expect(crossed.anchored).toMatchObject({ date: day(200) });
    expect(crossed.asked).toEqual([day(200)]);
    expect(crossed.skipped).toEqual({});

    // No day inside the gap was anchored, and the run after it owes nothing.
    for (const days of [29, 100, 150, 199]) {
      expect(await getAnchor(store.db, day(days))).toBeNull();
    }
    const after = await run(201);
    expect(after.anchored).toBeNull();
    expect(after.skipped).toEqual({ already_anchored: 1 });
  }, 600_000);
});
