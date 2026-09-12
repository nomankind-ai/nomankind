/**
 * The delta stream, served from the rows the log already derived.
 *
 * Whitepaper Section 8, "The delta stream": events are handed out "strictly by
 * sealed position with inclusion proofs", and two trainers resuming from the
 * same position are handed the same page — which is why every entry on a page
 * is described as it was derived at the sealed head, under the seal's own clock
 * (decision D-057), and never as it stands right now.
 *
 * Re-deriving each of them from the events cost a gathering of the entry's whole
 * world per entry: the registry six paged queries at a time, the supersession
 * and version-sibling walks, and the whole batch that sealed it. A page of a
 * hundred events over thirty entries spent hundreds of statements against
 * Workers' documented ceiling of fifty subrequests an invocation, to arrive at
 * the record the `entries` row already holds.
 *
 * So this file pins the promise rather than the shortcut: every item the door
 * served must be byte for byte the item a full re-derivation at that head and
 * that clock produces — including the entry whose staleness window closed
 * between the seal and the request, which is the one field derivation reads a
 * clock for — and the same page asked for twice must come back the same. The
 * statements are counted through a D1Like that records every `prepare`.
 *
 * The world is built the way the doors build one and then sealed: registry
 * events, thirty submitted entries, reconfirmations across them, a seal over all
 * of it, and the rows each door would have written. The signatures are not the
 * point here — src/worker/submit.ts and test/m18-end-to-end.test.ts own that —
 * so the log is appended through the real chain and the rows are written by the
 * real kernel, which is what the door's answer is compared against.
 */

import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { type Core } from "../src/core.js";
import { base64urlEncode } from "../src/encoding.js";
import { appendEvent, type Event } from "../src/events.js";
import { exportPrivateKeyPkcs8, generateKeypair } from "../src/identity.js";
import { mintKey } from "../src/keys.js";
import { DEFAULT_DOMAIN, LIST_PAGE_LIMIT } from "../src/policy.js";
import { buildSeal, type Seal } from "../src/seal.js";
import type {
  D1Like,
  D1LikeExecResult,
  D1LikeResult,
  D1LikeStatement,
} from "../src/storage/d1.js";
import {
  appendEvents,
  eventBySeq,
  eventsAfter,
  getEntry,
  headSeq,
  putEntry,
  putSeal,
} from "../src/storage/repository.js";
import { putKey } from "../src/storage/keys.js";
import type { Env } from "../src/worker/env.js";
import { handleSync } from "../src/worker/sync.js";
import { entryWorld, rederive, worldAt } from "../src/worker/world.js";
import { openTestDatabase, type TestDatabase } from "./helpers/d1.js";

/** Day 0: every event of the first seal, and the instant it was sealed at. */
const DAY0 = new Date("2026-09-12T00:00:00.000Z");
const DAY_MS = 86_400_000;

function day(days: number): Date {
  return new Date(DAY0.getTime() + days * DAY_MS);
}

/** Thirty entries, and a page of a hundred events across them. */
const ENTRIES = 30;
const PAGE = LIST_PAGE_LIMIT;

/** What the door answers with, as much of it as this file reads. */
interface WireItem {
  seq: number;
  kind: "entry" | "unlearn" | "event";
  event: Event;
  entry: Record<string, unknown> | null;
  sidecar: Record<string, unknown> | null;
  entry_hash: string | null;
}

interface SyncBody {
  from: number;
  head: number | null;
  sealed_head: number | null;
  as_of: string | null;
  events: WireItem[];
  receipt: { counter: number } | null;
}

/** Every statement a call made: `prepare` is what a D1 statement costs. */
class CountingDatabase implements D1Like {
  readonly statements: string[] = [];
  readonly #inner: D1Like;

  constructor(inner: D1Like) {
    this.#inner = inner;
  }

  prepare(sql: string): D1LikeStatement {
    this.statements.push(sql);
    return this.#inner.prepare(sql);
  }

  batch<Row = Record<string, unknown>>(
    statements: D1LikeStatement[],
  ): Promise<D1LikeResult<Row>[]> {
    return this.#inner.batch<Row>(statements);
  }

  exec(sql: string): Promise<D1LikeExecResult> {
    return this.#inner.exec(sql);
  }

  reset(): void {
    this.statements.length = 0;
  }
}

let store: TestDatabase;
let counting: CountingDatabase;
let env: Env;
let secret = "";
const ids: string[] = [];

/** One event, chained onto the log's head and appended. */
async function append(
  input: Parameters<typeof appendEvent>[1],
): Promise<Event> {
  const at = await headSeq(store.db);
  const previous = at === null ? [] : [(await eventBySeq(store.db, at))!];
  const chained = await appendEvent(previous, input);
  const event = chained[chained.length - 1]!;
  await appendEvents(store.db, [event]);
  return event;
}

/** A submitted core, complete to the schema's eighteen keys. */
function core(id: string): Core {
  return {
    id,
    subject: `example/kestrel-${id}`,
    category: "pricing",
    domain: DEFAULT_DOMAIN,
    claim: `Kestrel ${id} is priced per seat`,
    before: "$35 per seat per month",
    after: `$40 per seat per month (${id})`,
    effective_at: "2026-09-01",
    evidence_tier: "stated",
    evidence: null,
    observation: null,
    citation: "https://kestrel.example/pricing",
    snapshot_hash: `${"0".repeat(63)}1`,
    norm_version: "v1",
    supersedes: null,
    author: `agent:${id}`,
    author_operator: null,
    submitted_at: DAY0.toISOString(),
  } as Core;
}

/**
 * Store one entry exactly as a door would: derived over its whole world, on the
 * clock the door was answering at, through the position it saw.
 */
async function writeRow(entryId: string, now: Date): Promise<void> {
  const world = await entryWorld(store.db, entryId);
  const derived = rederive(world, entryId, now);
  await putEntry(
    store.db,
    derived.entry,
    derived.sidecar,
    (await headSeq(store.db))!,
  );
}

/**
 * Store one entry as a door would, but recording a position of the caller's
 * choosing rather than the log's head.
 *
 * Two doors leave rows like this: one whose clock was earlier than the seal the
 * page is served under, and one that folded an event past that seal. Both are
 * cases the page has to answer from the events instead of the row.
 */
async function writeRowThrough(
  entryId: string,
  now: Date,
  through: number,
): Promise<void> {
  const world = await entryWorld(store.db, entryId);
  const derived = rederive(world, entryId, now);
  await putEntry(store.db, derived.entry, derived.sidecar, through);
}

/** Seal every event the last seal did not cover, and rewrite the rows under it. */
async function seal(at: Date): Promise<Seal> {
  const events = await eventsAfter(store.db, -1, 1000);
  const previous = null;
  const built = await buildSeal(events, previous, { now: at.toISOString() });
  if (!built.ok) throw new Error(`seal: ${built.reason}`);
  await putSeal(store.db, built.seal);
  // `recordSeal` rewrites every entry the seal covers, because the entry's
  // `seal` object is a derived field like any other. The rows have to move with
  // it or they would deny a seal that was really made.
  for (const id of ids) await writeRow(id, at);
  return built.seal;
}

/** One sync, through the door, as a keyed reader. */
async function sync(from: number, now: Date): Promise<SyncBody> {
  const response = await handleSync(
    new Request(`https://api.test/sync?from=${from}&limit=${PAGE}`, {
      headers: { authorization: `Bearer ${secret}` },
    }),
    env,
    { now },
  );
  expect(response).not.toBeNull();
  expect(response!.status).toBe(200);
  return (await response!.json()) as SyncBody;
}

/**
 * Every item the page served, against the item a full re-derivation at the
 * page's own head and clock produces.
 */
async function expectRederived(body: SyncBody): Promise<number> {
  const head = body.sealed_head!;
  const at = new Date(body.as_of!);
  let checked = 0;
  for (const item of body.events) {
    if (item.entry === null) continue;
    const entryId = item.event.entry_id!;
    const world = worldAt(await entryWorld(store.db, entryId), head);
    const derived = rederive(world, entryId, at);
    expect([item.event.seq, JSON.stringify(item.entry)]).toEqual([
      item.event.seq,
      JSON.stringify(derived.entry),
    ]);
    expect([item.event.seq, JSON.stringify(item.sidecar)]).toEqual([
      item.event.seq,
      JSON.stringify(derived.sidecar),
    ]);
    checked += 1;
  }
  return checked;
}

beforeAll(async () => {
  store = await openTestDatabase();
  counting = new CountingDatabase(store.db);

  const pair = await generateKeypair();
  env = {
    DB: counting,
    CAPTURES: store.captures,
    ENVIRONMENT: "local",
    MAINTAINER_AGENT_ID: "agent:maintainer",
    SEALING_AGENT_KEY: base64urlEncode(
      await exportPrivateKeyPkcs8(pair.privateKey),
    ),
  } as Env;

  const minted = mintKey();
  secret = minted.secret;
  await putKey(store.db, {
    id: minted.id,
    keyHash: await minted.hash,
    tier: "standard",
    status: "active",
    customer: "cus_sync_fast_path",
    subscription: "sub_sync_fast_path",
    checkoutSession: "cs_sync_fast_path",
    createdAt: DAY0.toISOString(),
  });

  const at = DAY0.toISOString();
  await append({
    at,
    type: "operator_registered",
    entry_id: null,
    payload: { operator: "k1.example", maintainer: false },
  });
  await append({
    at,
    type: "operator_trusted",
    entry_id: null,
    payload: { operator: "k1.example" },
  });

  for (let index = 0; index < ENTRIES; index += 1) {
    const id = `entry${String(index).padStart(2, "0")}`;
    ids.push(id);
    await append({
      at,
      type: "entry_submitted",
      entry_id: id,
      payload: { core: core(id), signature: "sig" },
    });
  }

  // Reconfirmations across the same thirty entries, until the first page is a
  // hundred events long: the events the stream carries are mostly about entries
  // it has already described, which is the case this door pays for.
  for (let index = 0; (await headSeq(store.db))! + 1 < PAGE; index += 1) {
    const id = ids[index % ENTRIES]!;
    await append({
      at,
      type: "reconfirmation",
      entry_id: id,
      payload: {
        record: {
          agent: `agent:${id}`,
          operator: "k1.example",
          snapshot_hash: `${"0".repeat(63)}1`,
          reproduction: null,
          observation: null,
          signed_at: at,
        },
        signature: "sig",
      },
    });
  }
  expect((await headSeq(store.db))! + 1).toBe(PAGE);

  await seal(DAY0);
}, 120_000);

afterAll(async () => {
  await store?.dispose();
});

// ---------------------------------------------------------------------------
// (a) The page, at the first sealed head
// ---------------------------------------------------------------------------

describe("a page served from the stored rows", () => {
  it("hands out exactly what a full re-derivation would", async () => {
    const body = await sync(0, day(1));
    expect([body.from, body.head, body.sealed_head]).toEqual([
      0,
      PAGE - 1,
      PAGE - 1,
    ]);
    expect(body.as_of).toBe(DAY0.toISOString());
    expect(body.events.length).toBe(PAGE);
    expect(await expectRederived(body)).toBe(PAGE - 2);
  }, 120_000);

  it("costs fewer than fifty statements for thirty entries", async () => {
    counting.reset();
    const body = await sync(0, day(1));
    expect(body.events.length).toBe(PAGE);
    const distinct = new Set(
      body.events.map((item) => item.event.entry_id).filter((id) => id !== null),
    );
    expect(distinct.size).toBe(ENTRIES);
    // Cloudflare's documented ceiling is fifty subrequests an invocation, and
    // the page has to fit under it with the receipt's own writes inside. Pinned
    // at the measured cost with a little headroom rather than at the ceiling, so
    // a regression that doubled the work fails here instead of on the platform.
    expect(counting.statements.length).toBeLessThanOrEqual(45);
  }, 120_000);

  it("answers the same page twice, byte for byte", async () => {
    const first = await sync(0, day(1));
    const second = await sync(0, day(1));
    const page = (body: SyncBody): string =>
      JSON.stringify({
        events: body.events,
        head: body.head,
        sealed_head: body.sealed_head,
        as_of: body.as_of,
      });
    expect(page(second)).toBe(page(first));
    expect(second.receipt!.counter).toBe(first.receipt!.counter + 1);
  }, 120_000);
});

// ---------------------------------------------------------------------------
// (b) A later head, with a window closed between the seal and the request
// ---------------------------------------------------------------------------

describe("a page whose seal is past an entry's staleness window", () => {
  it("serves the entry stale at the seal's clock, exactly as derivation does", async () => {
    // Four more events, the rows their doors would have written, and a second
    // seal a hundred and twenty days on -- past the ninety-day pricing window
    // every entry of this log carries.
    const at = day(120).toISOString();
    for (const id of ids.slice(0, 4)) {
      await append({
        at,
        type: "reconfirmation",
        entry_id: id,
        payload: {
          record: {
            agent: `agent:${id}`,
            operator: "k1.example",
            snapshot_hash: `${"0".repeat(63)}1`,
            reproduction: null,
            observation: null,
            signed_at: DAY0.toISOString(),
          },
          signature: "sig",
        },
      });
      await writeRow(id, day(120));
    }
    const second = await seal(day(200));
    expect(second.last_seq).toBe(PAGE + 3);

    const body = await sync(0, day(201));
    expect(body.sealed_head).toBe(PAGE + 3);
    expect(body.as_of).toBe(day(200).toISOString());
    // The seal's clock is past every window in this log, so the page says so --
    // and says the same thing a re-derivation at that clock says.
    expect(
      body.events.every(
        (item) => item.entry === null || item.entry["stale"] === true,
      ),
    ).toBe(true);
    expect(await expectRederived(body)).toBe(PAGE - 2);
  }, 120_000);

  it("keeps serving what derivation says once an event is unsealed", async () => {
    // One event past the sealed head: the entry it names may not be served from
    // its row, because the row has folded an event this page does not carry.
    const moved = ids[5]!;
    await append({
      at: day(201).toISOString(),
      type: "dispute_upheld",
      entry_id: moved,
      payload: { correction_entry_id: ids[6]! },
    });
    await writeRow(moved, day(201));

    const body = await sync(0, day(202));
    expect(body.sealed_head).toBe(PAGE + 3);
    const served = body.events.filter((item) => item.event.entry_id === moved);
    expect(served.length).toBeGreaterThan(0);
    // Overturned in the store, and still standing on the page: the stream is
    // strictly by sealed position, and nothing past it is delivered.
    expect(served.every((item) => item.entry!["status"] === "draft")).toBe(true);
    expect(await expectRederived(body)).toBe(PAGE - 2);
  }, 120_000);
});

// ---------------------------------------------------------------------------
// (c) The two rows the page must not answer from
// ---------------------------------------------------------------------------

describe("a row the page cannot answer from", () => {
  it("re-reads the clock on a row written before the window closed", async () => {
    // Every row as its door left it on day 0, when nothing had expired, while
    // the page is served under a seal four hundred days later. The row says
    // fresh and the seal's clock says stale, and the page owes the reader the
    // seal's answer: `stale` is the one field derivation reads a clock for.
    const sealed = (await sync(0, day(201))).sealed_head!;
    for (const id of ids) await writeRowThrough(id, DAY0, sealed);
    const stored = await getEntry(store.db, ids[0]!);
    expect((stored!.entry as unknown as Record<string, unknown>)["stale"]).toBe(
      false,
    );

    const body = await sync(0, day(202));
    expect(body.as_of).toBe(day(200).toISOString());
    expect(
      body.events.every(
        (item) => item.entry === null || item.entry["stale"] === true,
      ),
    ).toBe(true);
    expect(await expectRederived(body)).toBe(PAGE - 2);
  }, 120_000);

  it("re-derives a row that folded a position the page does not cover", async () => {
    // The guard the other half of this door leans on: an entry nothing past the
    // head has moved is served from its row, and a row whose writer recorded a
    // position past the head folded something this page may not deliver. Written
    // here as such a writer would leave it — overturned, through a position five
    // past the seal — because that disagreement is the only way to see which of
    // the two the door answered with.
    const quiet = ids[10]!;
    const sealed = (await sync(0, day(202))).sealed_head!;
    const world = await entryWorld(store.db, quiet);
    const derived = rederive(world, quiet, day(202));
    expect(derived.entry["status"]).not.toBe("overturned");
    await putEntry(
      store.db,
      { ...derived.entry, status: "overturned", overturned_by: "nmk_01GHOST" },
      derived.sidecar,
      sealed + 5,
    );

    const body = await sync(0, day(202));
    expect(body.sealed_head).toBe(sealed);
    const served = body.events.filter((item) => item.event.entry_id === quiet);
    expect(served.length).toBeGreaterThan(0);
    expect(
      served.every((item) => item.entry!["status"] !== "overturned"),
    ).toBe(true);
    expect(await expectRederived(body)).toBe(PAGE - 2);
  }, 120_000);
});
