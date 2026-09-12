/**
 * The world one entry is derived over, gathered at a price a Worker can pay.
 *
 * src/worker/world.ts gathers the same registry for every entry a request
 * touches, and rebuilt the entry's seal object by reading the whole batch that
 * sealed it, once per entry. A Cloudflare invocation has a documented ceiling on
 * subrequests, and a sync page of a hundred events over a hundred entries spent
 * most of it re-answering two questions whose answers do not change: what the
 * registry holds, and what the entry's seal is.
 *
 * So this file pins the two readings, and pins what must not change with them:
 * the cache is an argument the caller creates and passes, a gathering without
 * one reads exactly what it always read, and every world that comes back — the
 * registry, the entry's own events, the superseders, the version siblings and
 * the seal — is equal to the world gathered the old way. The statements are
 * counted through a D1Like that records every `prepare` and hands the call
 * straight on to the real miniflare database underneath.
 */

import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { type Core } from "../src/core.js";
import { appendEvent, type Event } from "../src/events.js";
import { DEFAULT_DOMAIN } from "../src/policy.js";
import type { Entry } from "../src/schema.js";
import type { Sidecar } from "../src/derive.js";
import { buildSeal, entrySeal, type Seal } from "../src/seal.js";
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
  headSeq,
  putEntry,
  putSeal,
} from "../src/storage/repository.js";
import { entryWorld, worldCache, type EntryWorld } from "../src/worker/world.js";
import { openTestDatabase, type TestDatabase } from "./helpers/d1.js";

/** The instant every event in this file is at, and every gathering is made at. */
const AT = "2026-09-12T00:00:00.000Z";

/** The SQL fragments each reading under test is recognisable by. */
const REGISTRY_QUERY = "FROM events WHERE type = ?";
const RANGE_QUERY = "FROM events WHERE seq >= ? AND seq <= ?";

/** How many entries one request gathers in these tests. */
const ENTRIES = 10;

/**
 * Every statement a call made, in order, over the real database.
 *
 * Only `prepare` is counted, because that is what a D1 statement costs: `bind`,
 * `first`, `all` and `run` are the same statement being handed its parameters
 * and read back.
 */
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

  /** How many statements matched a fragment, or all of them when given none. */
  count(fragment?: string): number {
    if (fragment === undefined) return this.statements.length;
    return this.statements.filter((sql) => sql.includes(fragment)).length;
  }
}

let store: TestDatabase;
let counting: CountingDatabase;
let ids: string[] = [];
let seal: Seal;

/** One event, chained onto the log's head and appended. */
async function append(
  db: D1Like,
  input: Parameters<typeof appendEvent>[1],
): Promise<Event> {
  const at = await headSeq(db);
  const previous = at === null ? [] : [(await eventBySeq(db, at))!];
  const chained = await appendEvent(previous, input);
  const event = chained[chained.length - 1]!;
  await appendEvents(db, [event]);
  return event;
}

/** A submitted core, complete to the schema's eighteen keys. */
function core(id: string, supersedes: string | null): Core {
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
    supersedes,
    author: `agent:${id}`,
    author_operator: null,
    submitted_at: AT,
  } as Core;
}

/** The world's fields, as a value two gatherings can be compared through. */
function shape(world: EntryWorld): string {
  return JSON.stringify({
    registry: world.registry,
    entryEvents: world.entryEvents,
    superseders: world.superseders,
    versionSiblings: world.versionSiblings,
    seal: world.seal,
  });
}

beforeAll(async () => {
  store = await openTestDatabase();
  counting = new CountingDatabase(store.db);

  // A registry with something in it, so a cached reading is checked against
  // events and not against an empty list.
  await append(store.db, {
    at: AT,
    type: "operator_registered",
    entry_id: null,
    payload: { operator: "k1.example", maintainer: false },
  });
  await append(store.db, {
    at: AT,
    type: "operator_trusted",
    entry_id: null,
    payload: { operator: "k1.example" },
  });

  ids = [];
  for (let index = 0; index < ENTRIES; index += 1) {
    const id = `entry${index}`;
    ids.push(id);
    // The last entry declares it supersedes the first, so at least one world
    // carries superseders and the comparison is not over empty lists.
    const supersedes = index === ENTRIES - 1 ? ids[0]! : null;
    await append(store.db, {
      at: AT,
      type: "entry_submitted",
      entry_id: id,
      payload: { core: core(id, supersedes), signature: "sig" },
    });
  }

  // One seal over everything, and the rows a door would have stored under it:
  // the entry as derivation left it, seal object and all.
  const events = await eventsAfter(store.db, -1, 1000);
  const built = await buildSeal(events, null, { now: AT });
  expect(built.ok).toBe(true);
  if (!built.ok) return;
  seal = built.seal;
  await putSeal(store.db, seal);

  for (const id of ids) {
    const sealed = await entrySeal(events, [seal], id);
    const entry = {
      ...core(id, id === ids[ENTRIES - 1] ? ids[0]! : null),
      signature: "sig",
      approvers: [],
      reconfirmations: [],
      disputes: [],
      failure_reports: [],
      seal: sealed,
      staleness_window_days: null,
      verified_at: null,
      last_confirmed: AT.slice(0, 10),
      expires_at: null,
      stale: false,
      superseded_by: null,
      overturned_by: null,
      status: "draft",
      confidence: null,
    } as unknown as Entry;
    const sidecar = {
      needs_replacement: false,
      effective_tier: null,
      test_verdict: null,
      trusted_count_at_decision: 0,
      read_share_slots: [],
      revalidations: [],
      source: {
        class: "other",
        authority: null,
      },
    } as unknown as Sidecar;
    await putEntry(store.db, entry, sidecar, seal.last_seq);
  }
}, 120_000);

afterAll(async () => {
  await store?.dispose();
});

// ---------------------------------------------------------------------------
// (a) The registry, once
// ---------------------------------------------------------------------------

describe("one cache over many entries", () => {
  it("reads the registry once, and gathers the same worlds", async () => {
    counting.reset();
    const uncached: string[] = [];
    for (const id of ids) {
      uncached.push(shape(await entryWorld(counting, id)));
    }
    const without = counting.count(REGISTRY_QUERY);

    counting.reset();
    const cache = worldCache();
    const cached: string[] = [];
    for (const id of ids) {
      cached.push(shape(await entryWorld(counting, id, cache)));
    }
    const with_ = counting.count(REGISTRY_QUERY);

    // Six registry event types, paged to exhaustion: six statements for the one
    // reading, and six per entry without the cache.
    expect(without).toBe(6 * ENTRIES);
    expect(with_).toBe(6);
    expect(cached).toEqual(uncached);
  });

  it("shares the one reading between gatherings made at once", async () => {
    counting.reset();
    const cache = worldCache();
    const worlds = await Promise.all(
      ids.map((id) => entryWorld(counting, id, cache)),
    );
    expect(counting.count(REGISTRY_QUERY)).toBe(6);
    expect(worlds.every((world) => world.registry.length === 2)).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// (b) The seal, from the stored row
// ---------------------------------------------------------------------------

describe("a sealed entry's seal", () => {
  it("comes from the stored row, and never from the whole batch", async () => {
    const id = ids[1]!;

    counting.reset();
    const fast = await entryWorld(counting, id);
    const overTheBatch = counting.count(RANGE_QUERY);

    // The same gathering with no row to read it from: the rebuild, which is the
    // seal covering the submission and then every event that seal covers.
    await store.db.exec("DELETE FROM entries");
    counting.reset();
    const rebuilt = await entryWorld(counting, id);
    const withoutTheRow = counting.count(RANGE_QUERY);

    expect(shape(fast)).toBe(shape(rebuilt));
    expect(fast.seal).not.toBeNull();
    expect([overTheBatch, withoutTheRow]).toEqual([0, 1]);
  });
});
