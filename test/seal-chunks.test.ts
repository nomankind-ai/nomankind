/**
 * The seal's writes, cut into batches D1 can take.
 *
 * Whitepaper Section 6 (Seal): "every event gets sealed", and every entry the
 * batch covers acquires an inclusion proof of its own submission the moment the
 * batch closes. That is one statement per covered entry, and at
 * SEAL_MAX_EVENTS it is more statements than one D1 batch may carry — so the
 * write goes in chunks of SWEEP_BATCH_STATEMENTS, the seal row first and the
 * rewrites after it.
 *
 * What the chunks cost is that they are not one transaction: a run the platform
 * kills between two of them leaves a seal standing over entries that do not
 * carry it yet. What pays for it is that a rewrite is idempotent — re-deriving
 * an entry whose row already carries the seal writes the same row — so the next
 * run finishes what the killed one began, and that is what these tests measure:
 * the size of every batch that reaches D1, and the state of every entry after
 * a run that died in the middle.
 *
 * The database is miniflare's D1 with every migration applied, wrapped in a
 * counter that records the size of each batch and, where a test asks for it,
 * fails one. The log, the seals and the inclusion proofs are the real ones:
 * `appendEvent` chains and hashes every event, `buildSeal` builds the Merkle
 * batch, and `entrySeal` builds each entry's proof against it.
 */

import { afterAll, beforeAll, describe, expect, it } from "vitest";

import type { Core } from "../src/core.js";
import type { Sidecar } from "../src/derive.js";
import { appendEvent, type Event } from "../src/events.js";
import {
  DEFAULT_DOMAIN,
  SEAL_MAX_EVENTS,
  SWEEP_BATCH_STATEMENTS,
} from "../src/policy.js";
import type { Entry } from "../src/schema.js";
import { buildSeal, entrySeal, type Seal } from "../src/seal.js";
import type {
  D1Like,
  D1LikeResult,
  D1LikeStatement,
} from "../src/storage/d1.js";
import {
  appendEvents,
  completeSealRewrites,
  getEntry,
  putEntry,
  putSeal,
  recordSeal,
  sealBySeq,
  setSealWitnesses,
  type SealRederive,
} from "../src/storage/repository.js";
import { openTestDatabase, type TestDatabase } from "./helpers/d1.js";

/** The injected clock: nothing here reads a wall clock. */
const NOW = new Date("2026-09-12T00:05:00.000Z");
const AT = NOW.toISOString();

/** A witness signature, shaped like the real ones and never checked here. */
const COUNTERSIGNED = [
  {
    agent: "1F916:d2l0bmVzc09uZUFnZW50SWRlbnRpdHlBQUFB",
    signature: "c2lnbmF0dXJlLW9uZQ",
  },
];

/** The id of the nth entry, wide enough to keep log order and text order one. */
function entryId(index: number): string {
  return `nmk_chunk_${String(index).padStart(5, "0")}`;
}

/**
 * One entry's signed core, as the log carries it.
 *
 * Not validated anywhere on this path — storage writes what derivation hands
 * it, and derivation here is the test's own callback — so it carries the fields
 * the entry row is built from and nothing more.
 */
function core(index: number): Core {
  return {
    id: entryId(index),
    domain: DEFAULT_DOMAIN,
    subject: "kestrel-1",
    category: "pricing",
    author: "1F916:YXV0aG9yQWdlbnRJZGVudGl0eUFBQUFBQUE",
    submitted_at: AT,
  } as unknown as Core;
}

/** The stored entry, with or without the seal now covering it. */
function entryOf(index: number, seal: unknown): Entry {
  return {
    ...(core(index) as unknown as Record<string, unknown>),
    status: "draft",
    stale: false,
    expires_at: null,
    supersedes: null,
    seal,
  } as unknown as Entry;
}

/** The sidecar beside it: nothing in these tests reads a field of it. */
const SIDECAR = {
  needs_replacement: false,
  effective_tier: null,
  test_verdict: null,
  trusted_count_at_decision: null,
} as unknown as Sidecar;

/** What a batch of statements did to D1, in the order the batches were sent. */
interface CountingDatabase extends D1Like {
  /** The size of every batch this database was asked to run. */
  readonly batches: number[];
  /** Fail the nth batch (counting from one), the way a killed run fails. */
  failAt(batch: number | null): void;
}

/** The instant a run dies: thrown out of the batch the platform never ran. */
class KilledRun extends Error {
  constructor(batch: number) {
    super(`the run was killed inside batch ${batch}`);
    this.name = "KilledRun";
  }
}

/**
 * The real database, with every batch measured and one of them killable.
 *
 * Everything else goes straight through: the rows these tests read back are
 * miniflare's own.
 */
function countingDatabase(db: D1Like): CountingDatabase {
  const batches: number[] = [];
  let fail: number | null = null;
  return {
    batches,
    failAt(batch: number | null) {
      fail = batch;
    },
    prepare: (sql: string) => db.prepare(sql),
    async batch<Row = Record<string, unknown>>(
      statements: D1LikeStatement[],
    ): Promise<D1LikeResult<Row>[]> {
      batches.push(statements.length);
      if (fail !== null && batches.length === fail) throw new KilledRun(fail);
      return db.batch<Row>(statements);
    },
    exec: (sql: string) => db.exec(sql),
  };
}

describe("the seal's writes, chunked", () => {
  let store: TestDatabase;
  let db: CountingDatabase;
  /** The whole log, in order: one submission event per entry. */
  let events: Event[] = [];
  /** The seal chain, in order. */
  const seals: Seal[] = [];

  /**
   * Derivation, as the sweep's callback does it without the Worker's world
   * module: the entry rewritten with the real inclusion proof of its own
   * submission, against the seal that now covers it.
   */
  const rederive: SealRederive = async (id, seal, at) => {
    const sealed = await entrySeal(events, [seal], id);
    expect(sealed).not.toBeNull();
    expect(at.toISOString()).toBe(AT);
    return {
      entry: entryOf(indexOf(id), sealed),
      sidecar: SIDECAR,
      derivedThroughSeq: seal.last_seq,
    };
  };

  /** Which entry an id names: the log order these fixtures were built in. */
  function indexOf(id: string): number {
    return Number(id.slice("nmk_chunk_".length));
  }

  /**
   * Add `count` entries to the log: one chained submission event each, and one
   * stored row each, unsealed, which is what every entry looks like before a
   * seal closes over it.
   */
  async function addEntries(count: number): Promise<void> {
    const first = events.length;
    for (let index = first; index < first + count; index += 1) {
      events = await appendEvent(events, {
        at: AT,
        type: "entry_submitted",
        entry_id: entryId(index),
        payload: { core: core(index), signature: "c2lnbmF0dXJl" },
      });
    }
    await appendEvents(store.db, events.slice(first));
    for (let index = first; index < first + count; index += 1) {
      await putEntry(store.db, entryOf(index, null), SIDECAR, index);
    }
  }

  /** The seal over everything the previous one did not cover. */
  async function nextSeal(): Promise<Seal> {
    const previous = seals.length === 0 ? null : seals[seals.length - 1]!;
    const built = await buildSeal(events, previous, { now: AT });
    if (!built.ok) throw new Error(`buildSeal refused: ${built.reason}`);
    seals.push(built.seal);
    return built.seal;
  }

  /** The `seal` object on a stored entry row, null while nothing covers it. */
  async function sealOf(index: number): Promise<unknown> {
    const stored = await getEntry(store.db, entryId(index));
    expect(stored).not.toBeNull();
    return (stored!.entry as Record<string, unknown>)["seal"];
  }

  beforeAll(async () => {
    store = await openTestDatabase();
    db = countingDatabase(store.db);
  }, 600_000);

  afterAll(async () => {
    await store?.dispose();
  });

  it("writes a seal over the ceiling in batches D1 can take", async () => {
    await addEntries(SEAL_MAX_EVENTS);
    const seal = await nextSeal();
    expect(seal.size).toBe(SEAL_MAX_EVENTS);

    const rewritten = await recordSeal(db, seal, NOW, rederive);

    // One statement per covered entry plus the seal's own row, cut at the
    // ceiling: 200 entries is three batches, and no batch is over the size D1
    // is known to take.
    expect(db.batches).toEqual([100, 100, 1]);
    for (const size of db.batches) {
      expect(size).toBeLessThanOrEqual(SWEEP_BATCH_STATEMENTS);
    }

    // And every entry the seal covers carries it, exactly as one batch left
    // them before there were three.
    expect(rewritten).toHaveLength(SEAL_MAX_EVENTS);
    expect(await sealBySeq(store.db, seal.seq)).toEqual(seal);
    for (const index of [0, 99, 100, SEAL_MAX_EVENTS - 1]) {
      expect(await sealOf(index)).toMatchObject({
        log: "1F916",
        position: index,
        sealed_at: seal.sealed_at,
      });
    }
  }, 600_000);

  it("leaves a seal and its unfinished rewrites when a run is killed", async () => {
    const first = events.length;
    await addEntries(SEAL_MAX_EVENTS);
    const seal = await nextSeal();

    db.batches.length = 0;
    db.failAt(2);
    await expect(recordSeal(db, seal, NOW, rederive)).rejects.toBeInstanceOf(
      KilledRun,
    );
    db.failAt(null);

    // The seal row went in with the first chunk, so the seal stands: it is the
    // claim on the range, and the range is not sealed twice.
    expect(await sealBySeq(store.db, seal.seq)).toEqual(seal);
    // The first chunk carried the seal row and ninety-nine rewrites; the second
    // never ran, so the rest of the entries still deny the seal over them.
    expect(await sealOf(first + 98)).not.toBeNull();
    expect(await sealOf(first + 99)).toBeNull();
    expect(await sealOf(first + SEAL_MAX_EVENTS - 1)).toBeNull();
  }, 600_000);

  it("finishes the killed run's rewrites on the next run, once each", async () => {
    const first = events.length - SEAL_MAX_EVENTS;
    const seal = seals[seals.length - 1]!;

    db.batches.length = 0;
    const finished = await completeSealRewrites(db, seal, NOW, rederive);

    // Only the entries that were missing it, and every one of them: a hundred
    // and one rewrites, in two batches neither of which is over the ceiling.
    expect(finished).toEqual(
      Array.from({ length: 101 }, (_, offset) => entryId(first + 99 + offset)),
    );
    expect(db.batches).toEqual([100, 1]);

    for (const index of [first, first + 99, first + SEAL_MAX_EVENTS - 1]) {
      expect(await sealOf(index)).toMatchObject({
        log: "1F916",
        position: index,
        sealed_at: seal.sealed_at,
      });
    }

    // And the run after that has nothing to finish: the repair asks the rows,
    // so a seal whose entries all carry it writes nothing at all.
    db.batches.length = 0;
    expect(await completeSealRewrites(db, seal, NOW, rederive)).toEqual([]);
    expect(db.batches).toEqual([]);
  }, 600_000);

  it("chunks the witness step's rewrites too, one seal at a time", async () => {
    // Five seals waiting on their countersignatures, each covering more entries
    // than one batch may carry.
    const covered = SWEEP_BATCH_STATEMENTS + 1;
    const waiting: Seal[] = [];
    for (let seal = 0; seal < 5; seal += 1) {
      await addEntries(covered);
      const built = await nextSeal();
      await putSeal(store.db, built);
      waiting.push(built);
    }

    for (const seal of waiting) {
      db.batches.length = 0;
      const rewritten = await setSealWitnesses(
        db,
        seal,
        COUNTERSIGNED,
        NOW,
        async (id, updated, at) => rederive(id, updated, at),
      );

      // The entries first and the seal's own UPDATE last, cut at the ceiling:
      // a hundred and two statements is two batches.
      expect(rewritten).toHaveLength(covered);
      expect(db.batches).toEqual([100, 2]);
      for (const size of db.batches) {
        expect(size).toBeLessThanOrEqual(SWEEP_BATCH_STATEMENTS);
      }

      // The seal carries the countersignature, and so does every entry under
      // it: an entry that denied it would be one the verifier calls wrong.
      const stored = await sealBySeq(store.db, seal.seq);
      expect(stored!.witnesses).toEqual(COUNTERSIGNED);
      for (const index of [seal.first_seq, seal.last_seq]) {
        expect(await sealOf(index)).toMatchObject({
          witnesses: COUNTERSIGNED.map((witness) => witness.signature),
        });
      }
    }
  }, 600_000);
});
