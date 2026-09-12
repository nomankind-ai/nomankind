/**
 * The running counter under parallel load.
 *
 * Whitepaper Section 8, "The frozen reader": a read returns "a signed read
 * receipt naming the entry, the time, and a running counter", and "The delta
 * stream" hands a trainer "one signed receipt with a running counter" over the
 * whole page. Section 9 then publishes the day's read counts "so nomankind
 * cannot quietly change the numbers later", and the receipts readers hold are
 * what makes under-reporting detectable.
 *
 * None of that survives a counter the doors guess at. The doors used to read
 * `MAX(seq)` and insert at it, which two isolates serving two readers in the
 * same instant both do with the same number; the loser signed again for the
 * next one, three times, and then answered 503 `receipt_conflict` to a reader
 * who had done nothing wrong. On the live demo that was 42 of 50 parallel
 * signed syncs.
 *
 * So this file asks the question that finds it: seventy-five readers at once,
 * through the real doors, against one database. Every one of them must be
 * served, every receipt must verify, and the numbers they hold must be
 * seventy-five distinct consecutive numbers — because a reused number is
 * exactly the hole the published count could hide a read in.
 *
 * Everything is real except the network and the clock: miniflare's D1 and R2,
 * real Ed25519 over the real canonical bytes, and the real submit, validate,
 * read and sync doors.
 */

import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { FixtureBeacon } from "../src/adapters/beacon.js";
import { MockPayoutAdapter } from "../src/adapters/payout.js";
import type { Core } from "../src/core.js";
import { base64urlEncode } from "../src/encoding.js";
import type { ApproverRecord } from "../src/events.js";
import { exportPrivateKeyPkcs8, generateKeypair } from "../src/identity.js";
import { DEFAULT_DOMAIN, LIST_PAGE_LIMIT } from "../src/policy.js";
import {
  verifyReadReceipt,
  verifySyncReceipt,
  type ReadReceipt,
  type SyncReceipt,
} from "../src/receipt.js";
import { signRecord } from "../src/records.js";
import { txtRecordName } from "../src/registry.js";
import { applyMigrations } from "../src/storage/migrate.js";
import {
  allocateReadCounter,
  countReceiptsOn,
  latestSeal,
  nextReadCounter,
  readCountsOn,
  readCounterRangeOn,
} from "../src/storage/repository.js";
import type { SubmissionProposal } from "../src/submit.js";
import type { Env } from "../src/worker/env.js";
import { handleRequest, type RequestDeps } from "../src/worker/index.js";
import { runSweep } from "../src/worker/sweep.js";
import { getPlatformProxy } from "wrangler";
import type { D1Like } from "../src/storage/d1.js";
import type { R2Like } from "../src/storage/r2.js";
import { buildReadCountPayload } from "../src/receipt.js";
import {
  CONFIG_PATH,
  loadMigrations,
  openTestDatabase,
  type TestDatabase,
} from "./helpers/d1.js";
import {
  FixtureResolver,
  attestFor,
  makeAgent,
  signedGet,
  signedPost,
  type TestAgent,
} from "./helpers/registry.js";
import {
  FixtureFetcher,
  SUBMIT_NOW,
  pageHash,
  submission,
  submittedCore,
  type FixturePage,
} from "./helpers/submit.js";
import {
  FakeAnchorAdapter,
  FakeWitnessAdapter,
  pinnedSet,
} from "./helpers/witness.js";

/** The instant every registration, submission, decision and read is at. */
const NOW = SUBMIT_NOW;
const AT = NOW.toISOString();
const DAY = AT.slice(0, 10);

/** How many readers and how many trainers arrive together. */
const READERS = 50;
const TRAINERS = 25;

/** A reference the mock payment provider calls onboarded. */
const VERIFIED_REFERENCE = "mock-verified-counter";

const PRICING: FixturePage = {
  body: "<!doctype html><html><body><main><h1>Osprey pricing</h1><p>per seat per month</p></main></body></html>",
  contentType: "text/html; charset=utf-8",
};
const PRICING_URL = "https://osprey.example/pricing";
const PAGES: Record<string, FixturePage> = { [PRICING_URL]: PRICING };

let PRICING_HASH = "";

interface Party {
  readonly operator: string;
  readonly agent: TestAgent;
}

let store: TestDatabase;
let env: Env;
let deps: RequestDeps;
let maintainer: TestAgent;
let k1: Party;
let k2: Party;
let k3: Party;
let author: TestAgent;
let entry: Core;

function send(request: Request): Promise<Response> {
  return handleRequest(request, env, deps);
}

async function register(party: Party): Promise<void> {
  const response = await send(
    await signedPost(party.agent, {
      path: "/operators",
      body: {
        operator: party.operator,
        attestation: await attestFor(party.agent, party.operator, AT),
        payout: { reference: VERIFIED_REFERENCE },
      },
      timestamp: AT,
    }),
  );
  expect([response.status, party.operator]).toEqual([201, party.operator]);
}

async function name(party: Party): Promise<void> {
  const response = await send(
    await signedPost(maintainer, {
      path: "/genesis",
      body: { operator: party.operator },
      timestamp: AT,
    }),
  );
  expect([response.status, party.operator]).toEqual([200, party.operator]);
}

function pricing(subject: string): Omit<SubmissionProposal, "author"> {
  return {
    subject,
    category: "pricing",
    domain: DEFAULT_DOMAIN,
    claim: `${subject} seat pricing is $40 per seat per month`,
    before: "$35 per seat per month",
    after: "$40 per seat per month",
    effective_at: "2026-09-01",
    citation: PRICING_URL,
    snapshot_hash: PRICING_HASH,
    supersedes: null,
  };
}

async function approve(entryId: string, party: Party): Promise<void> {
  const record: ApproverRecord = {
    agent: party.agent.agentId,
    operator: party.operator,
    decision: "approve",
    reason: null,
    snapshot_hash: PRICING_HASH,
    assigned_random: false,
    test_accepted: null,
    reproduction: null,
    observation: null,
    signed_at: AT,
  };
  const signature = await signRecord(
    entryId,
    "validation",
    record,
    party.agent.privateKey,
  );
  const response = await send(
    await signedPost(party.agent, {
      path: `/entries/${entryId}/validate`,
      body: { record, signature },
      timestamp: AT,
    }),
  );
  expect([response.status, entryId]).toEqual([201, entryId]);
}

beforeAll(async () => {
  PRICING_HASH = await pageHash(PRICING);

  const pair = await generateKeypair();
  const exported = base64urlEncode(
    await exportPrivateKeyPkcs8(pair.privateKey),
  );

  store = await openTestDatabase();
  maintainer = await makeAgent();
  author = await makeAgent();
  k1 = { operator: "c1.example", agent: await makeAgent() };
  k2 = { operator: "c2.example", agent: await makeAgent() };
  k3 = { operator: "c3.example", agent: await makeAgent() };

  const records: Record<string, string[]> = {};
  for (const party of [k1, k2, k3]) {
    records[txtRecordName(party.operator)] = [party.agent.agentId];
  }
  records[txtRecordName("maintainer.example")] = [maintainer.agentId];

  env = {
    DB: store.db,
    CAPTURES: store.captures,
    ENVIRONMENT: "local",
    MAINTAINER_AGENT_ID: maintainer.agentId,
    SEALING_AGENT_KEY: exported,
  };
  deps = {
    now: NOW,
    dns: new FixtureResolver(records),
    payout: new MockPayoutAdapter(),
    fetcher: new FixtureFetcher(PAGES),
  };

  for (const party of [k1, k2, k3]) {
    await register(party);
    await name(party);
  }
  await register({ operator: "maintainer.example", agent: maintainer });

  entry = await submittedCore(author, pricing("example/osprey-counter"));
  const submitted = await send(await submission(author, { core: entry }));
  expect(submitted.status).toBe(201);
  await approve(entry["id"] as string, k1);
  await approve(entry["id"] as string, k2);

  // Sealed, so the delta stream has a head to answer from.
  const beacon = new FixtureBeacon("counter");
  await beacon.advance(AT);
  await runSweep(env, {
    now: NOW,
    beacon,
    witness: new FakeWitnessAdapter(),
    pinned: pinnedSet([]),
    ineligibleAgents: new Set<string>(),
    anchor: new FakeAnchorAdapter(null),
  });
  expect(await latestSeal(store.db)).not.toBeNull();
}, 600_000);

afterAll(async () => {
  await store?.dispose();
}, 600_000);

// ---------------------------------------------------------------------------
// Seventy-five readers, one instant
// ---------------------------------------------------------------------------

describe("every reader served at the same instant", () => {
  /** What the parallel batch was handed, gathered once and asked about below. */
  let reads: ReadReceipt[] = [];
  let syncs: SyncReceipt[] = [];
  let statuses: number[] = [];
  let firstCounter = 0;

  beforeAll(async () => {
    const id = entry["id"] as string;
    firstCounter = await nextReadCounter(store.db);

    // Every request built before any of them is sent, so the fifty reads and
    // the twenty-five syncs go into the door together rather than in a queue
    // this test made. Each carries its own nonce, because a replayed nonce is
    // a different refusal and not the one being asked about.
    const requests: Request[] = [];
    for (let i = 0; i < READERS; i += 1) {
      requests.push(
        await signedGet(k3.agent, {
          path: `/read/${id}`,
          timestamp: AT,
          nonce: `read-${i}`,
        }),
      );
    }
    for (let i = 0; i < TRAINERS; i += 1) {
      requests.push(
        await signedGet(k3.agent, {
          path: "/sync?limit=5",
          timestamp: AT,
          nonce: `sync-${i}`,
        }),
      );
    }

    const responses = await Promise.all(requests.map((one) => send(one)));
    const bodies = await Promise.all(
      responses.map(
        async (one) => (await one.json()) as Record<string, unknown>,
      ),
    );
    statuses = responses.map((one) => one.status);
    reads = bodies
      .slice(0, READERS)
      .map((body) => body["receipt"] as ReadReceipt);
    syncs = bodies
      .slice(READERS)
      .map((body) => body["receipt"] as SyncReceipt);
  }, 600_000);

  it("answers every one of them, and refuses none", () => {
    // No 503 at all: not receipts_not_configured, not receipt_conflict, not
    // storage_unreachable. A reader who asked properly was served.
    expect(statuses).toEqual(Array.from({ length: READERS + TRAINERS }, () => 200));
    expect(reads.every((receipt) => receipt !== null)).toBe(true);
    expect(syncs.every((receipt) => receipt !== null)).toBe(true);
  });

  it("hands out distinct, consecutive counters across both doors", async () => {
    const counters = [
      ...reads.map((receipt) => receipt.counter),
      ...syncs.map((receipt) => receipt.counter),
    ].sort((a, b) => a - b);

    expect(new Set(counters).size).toBe(counters.length);
    expect(counters).toEqual(
      Array.from({ length: counters.length }, (_, i) => firstCounter + i),
    );
    // And the next reader continues from there rather than from a number
    // somebody already holds.
    expect(counters[counters.length - 1]! + 1).toBe(
      await nextReadCounter(store.db),
    );
  }, 600_000);

  it("signs every receipt it handed out", async () => {
    for (const receipt of reads) {
      await expect(verifyReadReceipt(receipt)).resolves.toBe(true);
    }
    for (const receipt of syncs) {
      await expect(verifySyncReceipt(receipt)).resolves.toBe(true);
    }
  }, 600_000);

  it("publishes a day whose count is exactly what was issued", async () => {
    // Section 9: the day's count is what a reader holds their receipts against.
    // A read receipt is one read; a sync receipt is one read of each verified
    // entry it delivered — so the day is the sum of the two, counted off the
    // receipts themselves rather than off a number this test chose.
    const delivered = syncs.reduce(
      (total, receipt) =>
        total +
        receipt.entries.filter((one) => one.status === "verified").length,
      0,
    );
    const counts = await readCountsOn(store.db, DAY, undefined, LIST_PAGE_LIMIT);
    const published = counts.reduce((total, row) => total + row.count, 0);
    expect(published).toBe(reads.length + delivered);

    // And the counter range the day publishes is the range these receipts
    // occupy, with nothing missing inside it: a range wider than the receipts
    // would be a number drawn and never handed over, and a range narrower than
    // them would be a number handed out twice.
    const range = await readCounterRangeOn(store.db, DAY);
    expect(range.counter_first).toBe(firstCounter);
    expect(range.counter_last).toBe(firstCounter + reads.length + syncs.length - 1);

    // And the payload says it in the one number that can be held against that
    // range. `total` counts reads and cannot: a sync receipt is one row and as
    // many reads as it delivered verified entries. `receipts` counts rows, so
    // the subtraction is exact, and today it is zero — every number this day
    // drew was handed to somebody.
    const issued = await countReceiptsOn(store.db, DAY);
    expect(issued).toBe(reads.length + syncs.length);
    const payload = buildReadCountPayload(
      DAY,
      counts,
      range.counter_first,
      range.counter_last,
      undefined,
      undefined,
      issued,
    );
    expect(payload.receipts).toBe(issued);
    expect(
      payload.counter_last! - payload.counter_first! + 1 - payload.receipts!,
    ).toBe(0);
  }, 600_000);
});

// ---------------------------------------------------------------------------
// What 0016 finds when it arrives
// ---------------------------------------------------------------------------

/**
 * A database migrated to a named file and no further, so the migration under
 * test can be applied to a log that already exists.
 *
 * Demo and production are not empty tables: 0016 seeds its counter row from
 * receipts that were issued under the old read-then-insert, and a seed that is
 * off by one would either renumber a receipt somebody holds or hand the next
 * reader a number the table already stands at. So this opens a real D1, runs
 * the migrations through `through`, and hands the caller the database and the
 * rest of the migrations to run when they are ready.
 */
async function partiallyMigrated(through: string): Promise<{
  db: D1Like;
  rest: () => Promise<string[]>;
  dispose: () => Promise<void>;
}> {
  const platform = await getPlatformProxy<{ DB: D1Like; CAPTURES: R2Like }>({
    configPath: CONFIG_PATH,
    persist: false,
  });
  const all = loadMigrations();
  const upTo = all.slice(0, all.findIndex((one) => one.name === through) + 1);
  expect(upTo[upTo.length - 1]?.name).toBe(through);
  await applyMigrations(platform.env.DB, upTo);
  return {
    db: platform.env.DB,
    rest: () => applyMigrations(platform.env.DB, all),
    dispose: () => platform.dispose(),
  };
}

describe("the counter migration on a log that has already served reads", () => {
  it("seeds from the receipts already issued and renumbers none", async () => {
    const migrated = await partiallyMigrated("0015_paid_access.sql");
    try {
      // The demo shape: a hundred and ten receipts of both kinds, sharing one
      // running counter, exactly as the old door left them.
      for (let seq = 1; seq <= 110; seq += 1) {
        const kind = seq % 2 === 0 ? "sync" : "read";
        await migrated.db
          .prepare(
            `INSERT INTO receipts (id, kind, entry_id, seq, created_at, payload_json, key_id, key_counter)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
          )
          .bind(
            `rcpt_${seq}`,
            kind,
            kind === "read" ? "nmk_old" : null,
            seq,
            `2026-09-07T00:00:${String(seq % 60).padStart(2, "0")}.000Z`,
            JSON.stringify({ counter: seq }),
            null,
            null,
          )
          .run();
      }

      expect(await migrated.rest()).toEqual([
        "0016_receipt_counter.sql",
        "0017_standing_cursor.sql",
      ]);

      // The row stands at the largest counter already issued, so the next
      // reader continues the stream rather than starting it again.
      expect(await nextReadCounter(migrated.db)).toBe(111);
      expect(await allocateReadCounter(migrated.db)).toBe(111);
      expect(await allocateReadCounter(migrated.db)).toBe(112);

      // And nothing that was already issued moved: a migration that renumbered
      // would break every receipt a reader is holding.
      const rows = await migrated.db
        .prepare(
          `SELECT COUNT(*) AS n, MIN(seq) AS lo, MAX(seq) AS hi FROM receipts`,
        )
        .first<Record<string, unknown>>();
      expect(rows).toMatchObject({ n: 110, lo: 1, hi: 110 });
    } finally {
      await migrated.dispose();
    }
  }, 600_000);

  it("seeds an empty log at zero, and hands the first reader 1", async () => {
    const migrated = await partiallyMigrated("0015_paid_access.sql");
    try {
      expect(await migrated.rest()).toEqual([
        "0016_receipt_counter.sql",
        "0017_standing_cursor.sql",
      ]);
      expect(await nextReadCounter(migrated.db)).toBe(1);
      expect(await allocateReadCounter(migrated.db)).toBe(1);
      expect(await nextReadCounter(migrated.db)).toBe(2);
    } finally {
      await migrated.dispose();
    }
  }, 600_000);
});
