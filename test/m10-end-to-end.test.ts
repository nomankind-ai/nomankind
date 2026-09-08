/**
 * M10 end to end: one whole world through the public surfaces of this
 * milestone, and nothing else.
 *
 * The pieces have their own tests — the Worker's router in test/worker.test.ts,
 * the repository in test/storage.test.ts — and this file is the one that puts
 * them together the way a deploy does: migrate a database, ask the health probe
 * whether it answers, write the log and everything derived from it, then read
 * it all back and rederive. The assertion that matters is the last one: the
 * entry stored in D1 is byte-for-byte the entry that derivation produces from
 * the events D1 gives back, including the draft whose seal is null. Nothing is
 * kept in memory between the write and the read; every read goes through the
 * repository.
 *
 * Only migrate.ts, repository.ts, the Worker's `handleRequest` and the D1 test
 * helper are used here. No internal is reached into, so this test keeps passing
 * across any refactor that leaves those four surfaces alone.
 */

import { afterAll, beforeAll, describe, expect, it } from "vitest";
import {
  deriveAll,
  sealsForEntries,
  verifyChain,
  type Entry,
} from "../src/index.js";
import { applyMigrations } from "../src/storage/migrate.js";
import {
  appendEvents,
  eventsInRange,
  getEntry,
  headSeq,
  listEntries,
  putEntry,
  putSeal,
  sealsBetween,
} from "../src/storage/repository.js";
import type { Env } from "../src/worker/env.js";
import { handleRequest } from "../src/worker/index.js";
import { loadMigrations, openTestDatabase, type TestDatabase } from "./helpers/d1.js";
import {
  DRAFT_ENTRY_ID,
  VERIFIED_ENTRY_ID,
  buildVerifyWorld,
  type VerifyWorld,
} from "./helpers/verify-world.js";

/** How many entries a listing may return here: two entries exist in the world. */
const ENOUGH_FOR_THE_WORLD = 10;

let test: TestDatabase;
let world: VerifyWorld;
let env: Env;

/** The derivation clock the world was built under. Nothing reads a wall clock. */
function clock(): { now: string } {
  return { now: world.bundle.as_of };
}

/** The log's head, as the storage layer sees it. */
async function head(): Promise<number> {
  const seq = await headSeq(test.db);
  if (seq === null) throw new Error("m10: the log is empty");
  return seq;
}

beforeAll(async () => {
  world = await buildVerifyWorld({ withReconfirmation: true });
  test = await openTestDatabase();
  // The shape the Worker is handed at request time: the binding, and the
  // environment name wrangler.jsonc gives the local environment.
  env = { DB: test.db, ENVIRONMENT: "local" };
});

// getPlatformProxy runs a child process; vitest would hold the run open
// without this.
afterAll(async () => {
  await test?.dispose();
});

describe("the Worker over the migrated database", () => {
  it("answers GET /health with 200 before anything is written", async () => {
    expect(await headSeq(test.db)).toBeNull();

    const response = await handleRequest(
      new Request("https://nomankind.ai/health"),
      env,
    );

    expect(response.status).toBe(200);
    expect(await response.json()).toEqual({
      ok: true,
      environment: "local",
      storage: "ok",
    });
  });
});

describe("the world, written and read back", () => {
  /** What was stored, keyed by entry id, kept only to compare against. */
  const stored = new Map<string, Entry>();

  beforeAll(async () => {
    await appendEvents(test.db, world.bundle.events);
    for (const seal of world.bundle.seals) await putSeal(test.db, seal);

    const derivedThroughSeq = await head();
    const entrySeals = await sealsForEntries(
      world.bundle.events,
      world.bundle.seals,
    );
    for (const [id, derived] of deriveAll(
      world.bundle.events,
      clock(),
      entrySeals,
    )) {
      await putEntry(test.db, derived.entry, derived.sidecar, derivedThroughSeq);
      stored.set(id, derived.entry);
    }
  });

  it("gives back a log that still verifies", async () => {
    const events = await eventsInRange(test.db, 0, await head());
    expect(events).toEqual(world.bundle.events);
    expect(await verifyChain(events)).toEqual({
      ok: true,
      length: world.bundle.events.length,
    });
  });

  it("rederives every stored entry from what D1 holds", async () => {
    const last = await head();
    const events = await eventsInRange(test.db, 0, last);
    const seals = await sealsBetween(test.db, 0, last);
    const entrySeals = await sealsForEntries(events, seals);
    const derived = deriveAll(events, clock(), entrySeals);

    expect([...derived.keys()]).toEqual([VERIFIED_ENTRY_ID, DRAFT_ENTRY_ID]);

    for (const [id, rederived] of derived) {
      const row = await getEntry(test.db, id);
      expect(row).not.toBeNull();
      // The stored JSON, the entry derived from the D1 events, and the entry
      // the world derived in memory are all the same object.
      expect(rederived.entry).toEqual(row!.entry);
      expect(rederived.entry).toEqual(stored.get(id));
      expect(row!.sidecar).toEqual(rederived.sidecar);
    }

    expect(derived.get(VERIFIED_ENTRY_ID)!.entry["status"]).toBe("verified");
    expect(derived.get(VERIFIED_ENTRY_ID)!.entry["seal"]).not.toBeNull();
    // Submitted after the seal closed, so it is a draft and carries no seal.
    expect(derived.get(DRAFT_ENTRY_ID)!.entry["status"]).toBe("draft");
    expect(derived.get(DRAFT_ENTRY_ID)!.entry["seal"]).toBeNull();
  });

  it("lists the verified entry by its subject and category", async () => {
    const listed = await listEntries(test.db, {
      subject: world.entry["subject"] as string,
      category: world.entry["category"] as string,
      limit: ENOUGH_FOR_THE_WORLD,
    });

    expect(listed.map((row) => row.entry["id"])).toEqual([VERIFIED_ENTRY_ID]);
    expect(listed[0]!.entry).toEqual(stored.get(VERIFIED_ENTRY_ID));
  });

  it("applies nothing when the migrations are applied a second time", async () => {
    expect(await applyMigrations(test.db, loadMigrations())).toEqual([]);
  });
});
