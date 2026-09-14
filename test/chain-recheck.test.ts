/**
 * The chain re-check, on a real log.
 *
 * The gap the QA of 2026-09-12 named: a hand-edited `prev_hash` is noticed by
 * nothing live. The offline verifier catches it and so does the mirror, and
 * both are things somebody has to run — so a record whose whole claim is that
 * any later change leaves proof (whitepaper Section 6, "Seal") was relying on
 * somebody thinking to look.
 *
 * The sweep's chain step is the thing that looks. It re-walks one page of the
 * log a run against the kernel's own hash rule, wraps back to seq 0 after the
 * head, and reports what it found on the status board. What is pinned here is
 * the whole path and not the step alone: a real miniflare D1, real events
 * sealed by `appendEvent`, the real sweep, and the stage read off the board the
 * run wrote.
 *
 * Four things, in order: a clean log walks a page a run and wraps; a row edited
 * by hand is found on the page that holds it and named by its seq; the walk
 * does not carry past it, so the light stays red while the edit stands; and the
 * row put back is walked again by the next run, which is what makes it heal.
 * The step repairs nothing — a timer that could rewrite the record would be the
 * one thing this record must never have.
 */

import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { LocalAnchorAdapter } from "../src/adapters/anchor.js";
import { FixtureBeacon } from "../src/adapters/beacon.js";
import { MockPayoutAdapter } from "../src/adapters/payout.js";
import { MockWitnessAdapter, MOCK_WITNESSES } from "../src/adapters/witness.js";
import { appendEvent, type Event } from "../src/events.js";
import { LIST_PAGE_LIMIT } from "../src/policy.js";
import { stageStates, type Stage } from "../src/status.js";
import type { D1Like } from "../src/storage/d1.js";
import {
  appendEvents,
  readChainCheckState,
} from "../src/storage/repository.js";
import type { Env } from "../src/worker/env.js";
import { statusInput } from "../src/worker/status.js";
import { runSweep } from "../src/worker/sweep.js";
import { openTestDatabase, type TestDatabase } from "./helpers/d1.js";

/** The injected clock. Every run below is a minute after the one before it. */
const START = new Date("2026-09-12T09:00:00.000Z");
const MINUTE_MS = 60_000;

/**
 * A log of a page and a bit.
 *
 * More than LIST_PAGE_LIMIT on purpose: a walk that fits in one page could not
 * show that the cursor carries, and one that is an exact multiple could not
 * show where the wrap lands.
 */
const OVERFLOW = 5;
const EVENTS = LIST_PAGE_LIMIT + OVERFLOW;

let store: TestDatabase;
let db: D1Like;
let env: Env;
/** How many runs have been made, so each gets its own instant. */
let runs = 0;

const beacon = new FixtureBeacon("chain");

/** One sweep, at its own instant, with the mocks every environment but production runs. */
async function sweep(): Promise<Date> {
  runs += 1;
  const now = new Date(START.getTime() + runs * MINUTE_MS);
  await runSweep(env, {
    now,
    beacon,
    witness: new MockWitnessAdapter(),
    pinned: { witnesses: [...MOCK_WITNESSES], registry: null },
    ineligibleAgents: new Set<string>(),
    anchor: new LocalAnchorAdapter(),
    payout: new MockPayoutAdapter(),
  });
  return now;
}

/** The chain stage, read the way a reader reads it: off the board the run wrote. */
async function chainStage(now: Date): Promise<Stage> {
  const at = now.toISOString();
  const input = await statusInput(db, env, at);
  const found = stageStates(input, at).find((one) => one.stage === "chain");
  if (found === undefined) throw new Error("no chain stage");
  return found;
}

/** One stored event's `prev_hash` or `hash`, edited by hand. */
async function edit(seq: number, column: string, value: string): Promise<void> {
  await db
    .prepare(`UPDATE events SET ${column} = ? WHERE seq = ?`)
    .bind(value, seq)
    .run();
}

/** The stored event at one seq, as the row holds it. */
async function stored(seq: number): Promise<Record<string, unknown>> {
  const row = await db
    .prepare(`SELECT prev_hash, hash, payload FROM events WHERE seq = ?`)
    .bind(seq)
    .first<Record<string, unknown>>();
  if (row === null) throw new Error(`no event at ${seq}`);
  return row;
}

beforeAll(async () => {
  store = await openTestDatabase();
  db = store.db;
  env = { DB: store.db, ENVIRONMENT: "local" } as unknown as Env;

  // A log of plain snapshots: the chain rule is about the link and the digest
  // and never about what an event says, so the cheapest well-formed event in
  // the kernel is the honest fixture here.
  let chain: Event[] = [];
  for (let index = 0; index < EVENTS; index += 1) {
    chain = await appendEvent(chain, {
      at: new Date(START.getTime() + index).toISOString(),
      type: "pool_snapshot",
      entry_id: null,
      payload: { operators: [] },
    });
  }
  await appendEvents(db, chain);
}, 120_000);

afterAll(async () => {
  await store?.dispose();
});

describe("a clean log", () => {
  it("walks a page a run, and wraps back to the start after the head", async () => {
    const first = await sweep();
    expect(await readChainCheckState(db)).toEqual({
      checked_through: LIST_PAGE_LIMIT - 1,
      break_seq: null,
    });
    const one = await chainStage(first);
    expect(one.state).toBe("ok");
    expect(one.last).toContain(`checked through ${LIST_PAGE_LIMIT - 1}`);
    expect(one.last).toContain(`${LIST_PAGE_LIMIT} events`);

    // The rest of the log, and the cursor now at the head.
    const second = await sweep();
    expect(await readChainCheckState(db)).toEqual({
      checked_through: EVENTS - 1,
      break_seq: null,
    });
    expect((await chainStage(second)).state).toBe("ok");

    // Past the head, so back to seq 0: the whole log is re-walked for ever
    // rather than once, because an event proved last week is exactly the one a
    // hand edit would go for.
    const third = await sweep();
    expect(await readChainCheckState(db)).toEqual({
      checked_through: LIST_PAGE_LIMIT - 1,
      break_seq: null,
    });
    const wrapped = await chainStage(third);
    expect(wrapped.state).toBe("ok");
    expect(wrapped.last).toContain("wrapped");
  }, 240_000);

  it("sends a reader to the page of the log the walk is on", async () => {
    const stage = await chainStage(
      new Date(START.getTime() + runs * MINUTE_MS),
    );
    // `GET /events` pages from `after`, so the page holding seq n starts at
    // n - 1: the link is the evidence and has to open on the event it names.
    expect(stage.evidence).toEqual([
      { label: "/events", href: `/events?after=${LIST_PAGE_LIMIT - 1}` },
    ]);
  }, 120_000);
});

describe("a row edited by hand", () => {
  /** An event on the page the next run will walk. */
  const BROKEN = LIST_PAGE_LIMIT + 2;
  let original = "";

  it("is found on the page that holds it, and named by its seq", async () => {
    original = (await stored(BROKEN))["prev_hash"] as string;
    await edit(BROKEN, "prev_hash", `sha256:${"0".repeat(64)}`);

    const now = await sweep();
    const stage = await chainStage(now);
    expect(stage.state).toBe("failing");
    expect(stage.last).toContain(`seq ${BROKEN}`);
    expect(stage.last).toContain("bad_prev_hash");
    // The link to the page a reader checks it on is the broken event's own.
    expect(stage.evidence).toEqual([
      { label: "/events", href: `/events?after=${BROKEN - 1}` },
    ]);
  }, 240_000);

  it("stops the walk where it broke, and is never healed by the step", async () => {
    const state = await readChainCheckState(db);
    // The cursor did not carry past the break, so the next run walks the same
    // page: a light that went green again while the edit stood would be worse
    // than no light at all.
    expect(state).toEqual({
      checked_through: LIST_PAGE_LIMIT - 1,
      break_seq: BROKEN,
    });
    // And the row is exactly as the hand left it: nothing here writes to the
    // events table.
    expect((await stored(BROKEN))["prev_hash"]).toBe(
      `sha256:${"0".repeat(64)}`,
    );

    const again = await sweep();
    expect((await chainStage(again)).state).toBe("failing");
    expect((await readChainCheckState(db)).break_seq).toBe(BROKEN);
  }, 240_000);

  it("heals on the run after the row is put back", async () => {
    await edit(BROKEN, "prev_hash", original);

    const now = await sweep();
    const stage = await chainStage(now);
    expect(stage.state).toBe("ok");
    expect(await readChainCheckState(db)).toEqual({
      checked_through: EVENTS - 1,
      break_seq: null,
    });
    expect(stage.last).toContain(`checked through ${EVENTS - 1}`);
  }, 240_000);
});

describe("an event whose own bytes changed", () => {
  it("is caught by the kernel's hash rule and not only by the link", async () => {
    // The other half of the chain rule: a payload rewritten in place still
    // links to the event before it and to the one after, and only recomputing
    // the digest says so.
    const seq = 4;
    const original = (await stored(seq))["payload"] as string;
    await db
      .prepare(`UPDATE events SET payload = ? WHERE seq = ?`)
      .bind(JSON.stringify({ operators: ["ghost"] }), seq)
      .run();

    // The walk has wrapped to the head, so one run brings it back to page one,
    // and the run after that is the one that reaches seq 4.
    let stage = await chainStage(await sweep());
    while (stage.state === "ok" && !stage.last.includes(`seq ${seq}`)) {
      stage = await chainStage(await sweep());
    }
    expect(stage.state).toBe("failing");
    expect(stage.last).toContain(`seq ${seq}`);
    expect(stage.last).toContain("bad_hash");

    await db
      .prepare(`UPDATE events SET payload = ? WHERE seq = ?`)
      .bind(original, seq)
      .run();
    expect((await chainStage(await sweep())).state).toBe("ok");
  }, 240_000);
});
