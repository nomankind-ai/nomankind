/**
 * M24a, the money half of duplicate claims (decision D-085).
 *
 * Whitepaper Section 9, Money: "A read is one verified entry returned by the
 * paid API, or one verified entry delivered in a paid sync." Section 8, The
 * delta stream, hands a trainer everything the log learned, and when two
 * verified entries assert the same fact about the same subject the trainer was
 * handed one fact twice. The log is owed one read for it, not two, and the one
 * it is owed is for the entry it stands behind: the newest of the group, which
 * is the entry GET /read serves.
 *
 * So this file builds a day with three groups in it — a duplicate group whose
 * older entry was also read by hand, a duplicate group nobody read, and a pair
 * that only looks alike — syncs it, reads it, and checks the count the sweep
 * publishes the next morning against each of those three cases.
 *
 * Everything is real except the network and the clock: miniflare's D1 and R2,
 * real Ed25519 over the real canonical bytes, the real submit and validate
 * doors, the real derivation, and the sweep the alarm runs.
 *
 * The one thing built by hand is the second entry of each duplicate group. The
 * submit door refuses a duplicate of a live entry outright (D-085), so a pair
 * like this can only reach the log the way this file puts it there: as the
 * event the door writes, on the real chain, through the real write. That is
 * also the only way it happens in the world — a pair filed before the rule
 * existed, or two isolates filing the same fact in the same instant — and it is
 * exactly the pair the money rule is for. Everything after the event is real:
 * the entry is derived by the kernel, verified through the validate door, and
 * served by the same sync and read routes as any other.
 */

import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { FixtureBeacon } from "../src/adapters/beacon.js";
import { MockPayoutAdapter } from "../src/adapters/payout.js";
import type { Core } from "../src/core.js";
import { base64urlEncode } from "../src/encoding.js";
import { deriveEntry } from "../src/derive.js";
import { duplicateKey, sameDuplicateKey } from "../src/duplicate.js";
import type { ApproverRecord, Event, EventPayloads } from "../src/events.js";
import { appendEvent } from "../src/events.js";
import {
  exportPrivateKeyPkcs8,
  generateKeypair,
} from "../src/identity.js";
import { DEFAULT_DOMAIN, LIST_PAGE_LIMIT } from "../src/policy.js";
import { buildReadCountPayload } from "../src/receipt.js";
import type { ReadReceipt, SyncReceipt } from "../src/receipt.js";
import { signRecord } from "../src/records.js";
import { txtRecordName } from "../src/registry.js";
import { validateEntry } from "../src/schema.js";
import { signCore } from "../src/sign.js";
import {
  appendEvents,
  eventBySeq,
  eventsAfter,
  eventsForEntry,
  headSeq,
  latestSeal,
  putEntry,
} from "../src/storage/repository.js";
import type { SubmissionProposal } from "../src/submit.js";
import type { Env } from "../src/worker/env.js";
import { handleRequest, type RequestDeps } from "../src/worker/index.js";
import { runSweep, type SweepReport } from "../src/worker/sweep.js";
import { openTestDatabase, type TestDatabase } from "./helpers/d1.js";
import {
  FixtureResolver,
  TEST_ORIGIN,
  attestFor,
  makeAgent,
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

/** Day 0: the instant every registration, submission, decision and read is at. */
const NOW = SUBMIT_NOW;
const AT = NOW.toISOString();

/** A unit constant: the fake clock moves in whole days. */
const DAY_MS = 86_400_000;

function day(days: number): Date {
  return new Date(NOW.getTime() + days * DAY_MS);
}

function date(days: number): string {
  return day(days).toISOString().slice(0, 10);
}

/** A reference the mock payment provider calls onboarded. */
const VERIFIED_REFERENCE = "mock-verified-m24a";

const CATEGORY = "pricing";

/** The group whose older entry is also read by hand through GET /read. */
const READ_SUBJECT = "example/kestrel-read";
/** The group nobody reads: its older entry earns nothing at all. */
const QUIET_SUBJECT = "example/kestrel-quiet";
/** The pair that only looks alike: two values, two facts, two reads. */
const APART_SUBJECT = "example/kestrel-apart";

// ---------------------------------------------------------------------------
// The page every citation points at
// ---------------------------------------------------------------------------

const PRICING: FixturePage = {
  body: "<!doctype html><html><body><main><h1>Kestrel pricing</h1><p>per seat per month</p></main></body></html>",
  contentType: "text/html; charset=utf-8",
};

const PRICING_URL = "https://kestrel.example/pricing";
const PAGES: Record<string, FixturePage> = { [PRICING_URL]: PRICING };

let PRICING_HASH = "";

// ---------------------------------------------------------------------------
// The world
// ---------------------------------------------------------------------------

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
/** A bare key that submits: it names no operator, so every k may judge it. */
let author: TestAgent;

/** The duplicate group that is also read: older first, then the newer copy. */
let readOld: Core;
let readNew: Core;
/** The duplicate group nobody reads. */
let quietOld: Core;
let quietNew: Core;
/** The pair whose values differ, so they are two facts and not one. */
let apartOne: Core;
let apartTwo: Core;

/** Every receipt this file was handed, in the order it was handed them. */
const syncReceipts: SyncReceipt[] = [];
const readReceipts: ReadReceipt[] = [];

function send(request: Request, now: Date = NOW): Promise<Response> {
  return handleRequest(request, env, { ...deps, now });
}

async function read(
  path: string,
  now: Date = NOW,
): Promise<{ status: number; body: Record<string, unknown> }> {
  const response = await send(new Request(`${TEST_ORIGIN}${path}`), now);
  return {
    status: response.status,
    body: (await response.json()) as Record<string, unknown>,
  };
}

/** One sync that has to succeed, with the receipt it issued recorded. */
async function sync(query: string): Promise<Record<string, unknown>> {
  const answer = await read(`/sync${query}`);
  expect([answer.status, query]).toEqual([200, query]);
  const receipt = answer.body["receipt"] as SyncReceipt | null;
  if (receipt !== null) syncReceipts.push(receipt);
  return answer.body;
}

/** One read of one entry, by id, with the receipt it issued recorded. */
async function readEntry(entryId: string): Promise<void> {
  const answer = await read(`/read/${entryId}`);
  expect([answer.status, entryId]).toEqual([200, entryId]);
  readReceipts.push(answer.body["receipt"] as ReadReceipt);
}

async function register(party: Party): Promise<void> {
  const request = await signedPost(party.agent, {
    path: "/operators",
    body: {
      operator: party.operator,
      attestation: await attestFor(party.agent, party.operator, AT),
      payout: { reference: VERIFIED_REFERENCE },
    },
    timestamp: AT,
  });
  const response = await send(request);
  expect([response.status, party.operator]).toEqual([201, party.operator]);
}

async function name(party: Party): Promise<void> {
  const request = await signedPost(maintainer, {
    path: "/genesis",
    body: { operator: party.operator },
    timestamp: AT,
  });
  const response = await send(request);
  expect([response.status, party.operator]).toEqual([200, party.operator]);
}

/** A stated pricing proposal citing the fixture page. */
function pricing(
  subject: string,
  claim: string,
  after: string,
): Omit<SubmissionProposal, "author"> {
  return {
    subject,
    category: CATEGORY,
    domain: DEFAULT_DOMAIN,
    claim,
    before: "$35 per seat per month",
    after,
    effective_at: "2026-09-01",
    citation: PRICING_URL,
    snapshot_hash: PRICING_HASH,
    supersedes: null,
  };
}

/** One entry through the real submit door. */
async function submit(
  proposal: Omit<SubmissionProposal, "author">,
): Promise<Core> {
  const core = await submittedCore(author, proposal);
  const response = await send(await submission(author, { core }));
  expect([response.status, await response.json()]).toEqual([
    201,
    expect.objectContaining({ id: core["id"], status: "draft" }),
  ]);
  return core;
}

/**
 * One entry onto the log without the submit door: the event that door writes,
 * appended to the real chain, and the entry the kernel derives from it stored
 * exactly as that door stores it.
 *
 * This is the pair D-085 refuses at the door, and refusing it there is why the
 * only way to hold one is to have held it already. Nothing here is invented:
 * the core is signed by the real key, the event links onto the real head, and
 * the entry is `deriveEntry`'s own answer, checked against the schema before it
 * is written, exactly as the door checks it.
 */
async function fileWithoutTheDoor(
  proposal: Omit<SubmissionProposal, "author">,
): Promise<Core> {
  const core = await submittedCore(author, proposal);
  const id = core["id"] as string;
  const signature = await signCore(core, author.privateKey);

  const head = await headSeq(store.db);
  const previous = head === null ? [] : [(await eventBySeq(store.db, head))!];
  const chained = await appendEvent(previous, {
    at: AT,
    type: "entry_submitted",
    entry_id: id,
    payload: { core, signature },
  });
  const event = chained[chained.length - 1]!;
  await appendEvents(store.db, [event]);

  const derived = deriveEntry(await eventsForEntry(store.db, id), id, {
    now: AT,
  });
  expect(validateEntry(derived.entry).errors).toEqual([]);
  await putEntry(store.db, derived.entry, derived.sidecar, event.seq);
  return core;
}

/** One approval through the real validate door. */
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

/** Both judgments a small pool needs, so the entry comes out verified. */
async function verify(core: Core): Promise<void> {
  const id = core["id"] as string;
  await approve(id, k1);
  await approve(id, k2);
  const answer = await read(`/entries/${id}`);
  expect([answer.status, answer.body["status"]]).toEqual([200, "verified"]);
}

/** Run the sweep the alarm runs, with the fakes standing in for the world. */
async function sweep(at: Date): Promise<SweepReport> {
  const beacon = new FixtureBeacon("m24a");
  await beacon.advance(at.toISOString());
  return runSweep(env, {
    now: at,
    beacon,
    witness: new FakeWitnessAdapter(),
    pinned: pinnedSet([]),
    ineligibleAgents: new Set<string>(),
    anchor: new FakeAnchorAdapter(null),
  });
}

// ---------------------------------------------------------------------------
// The world, built once
// ---------------------------------------------------------------------------

beforeAll(async () => {
  PRICING_HASH = await pageHash(PRICING);

  // Nomankind's own key: the one that signs read and sync receipts.
  const pair = await generateKeypair();
  const sealingKey = base64urlEncode(
    await exportPrivateKeyPkcs8(pair.privateKey),
  );

  store = await openTestDatabase();
  maintainer = await makeAgent();
  author = await makeAgent();
  k1 = { operator: "k1.example", agent: await makeAgent() };
  k2 = { operator: "k2.example", agent: await makeAgent() };
  k3 = { operator: "k3.example", agent: await makeAgent() };

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
    SEALING_AGENT_KEY: sealingKey,
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

  // The group that is read: the older entry through the door, then the copy
  // that only differs by whitespace, which norm-v1.2 step 4 collapses away.
  readOld = await submit(
    pricing(
      READ_SUBJECT,
      "Kestrel read-group seat pricing is $40 per seat per month",
      "$40 per seat per month",
    ),
  );
  await verify(readOld);
  readNew = await fileWithoutTheDoor(
    pricing(
      READ_SUBJECT,
      "Kestrel read-group seat pricing, filed again in other words",
      "$40  per   seat per month",
    ),
  );
  await verify(readNew);

  // The group nobody reads, built the same way.
  quietOld = await submit(
    pricing(
      QUIET_SUBJECT,
      "Kestrel quiet-group seat pricing is $55 per seat per month",
      "$55 per seat per month",
    ),
  );
  await verify(quietOld);
  quietNew = await fileWithoutTheDoor(
    pricing(
      QUIET_SUBJECT,
      "Kestrel quiet-group seat pricing, filed again in other words",
      "$55 per  seat per  month",
    ),
  );
  await verify(quietNew);

  // Two entries about one subject that are not one fact: the values differ, so
  // the key differs, and the log is owed a read for each.
  apartOne = await submit(
    pricing(
      APART_SUBJECT,
      "Kestrel apart-group seat pricing is $60 per seat per month",
      "$60 per seat per month",
    ),
  );
  await verify(apartOne);
  apartTwo = await submit(
    pricing(
      APART_SUBJECT,
      "Kestrel apart-group volume pricing is $65 per seat per month",
      "$65 per seat per month",
    ),
  );
  await verify(apartTwo);

  // Everything above is sealed, so the sync below has a head to answer from.
  await sweep(NOW);
  expect(await latestSeal(store.db)).not.toBeNull();

  // The day's traffic: one sync that delivers every verified entry, and one
  // read of the older entry of the read group, by id.
  await sync("?from=0");
  await readEntry(readOld["id"] as string);
}, 300_000);

afterAll(async () => {
  await store?.dispose();
});

// ---------------------------------------------------------------------------
// (a) The fixture itself: these really are duplicates, and those really are not
// ---------------------------------------------------------------------------

describe("the day's entries", () => {
  it("are two duplicate groups and one pair that only looks alike", () => {
    expect(sameDuplicateKey(duplicateKey(readOld), duplicateKey(readNew))).toBe(
      true,
    );
    expect(
      sameDuplicateKey(duplicateKey(quietOld), duplicateKey(quietNew)),
    ).toBe(true);
    expect(
      sameDuplicateKey(duplicateKey(apartOne), duplicateKey(apartTwo)),
    ).toBe(false);

    // The copies are not the same bytes: they are the same claim, normalized.
    expect(readNew["after"]).not.toBe(readOld["after"]);
    expect(readNew["id"]).not.toBe(readOld["id"]);
    // And neither names the other: no supersession is in play anywhere here.
    for (const core of [readOld, readNew, quietOld, quietNew]) {
      expect(core["supersedes"]).toBeNull();
    }
  });

  it("were all delivered verified by the day's one sync", () => {
    expect(syncReceipts.length).toBe(1);
    const delivered = new Map(
      syncReceipts[0]!.entries.map((entry) => [entry.entry_id, entry.status]),
    );
    for (const core of [
      readOld,
      readNew,
      quietOld,
      quietNew,
      apartOne,
      apartTwo,
    ]) {
      expect([core["id"], delivered.get(core["id"] as string)]).toEqual([
        core["id"],
        "verified",
      ]);
    }

    // And the one read receipt names the older entry of the read group, not
    // the newer one: GET /read by id answers the entry it was asked for.
    expect(readReceipts.map((receipt) => receipt.entry_id)).toEqual([
      readOld["id"],
    ]);
  });
});

// ---------------------------------------------------------------------------
// (b) The day's published count
// ---------------------------------------------------------------------------

describe("the day's read count, with duplicates inside it", () => {
  let report: SweepReport;
  let published: Event<"read_count">;
  let payload: EventPayloads["read_count"];

  beforeAll(async () => {
    report = await sweep(day(1));
    const events = await eventsAfter(store.db, -1, LIST_PAGE_LIMIT * 4);
    published = events.find(
      (event) => event.type === "read_count",
    ) as Event<"read_count">;
    payload = published.payload as EventPayloads["read_count"];
  }, 300_000);

  it("pays one read for a duplicate group, and it is the newest entry's", () => {
    const counts = new Map(
      payload.reads.map((row) => [row.entry_id, row.count]),
    );

    // The read group: the sync delivered both, so the older one's sync read is
    // dropped and only the read a reader actually asked for is left standing.
    expect(counts.get(readNew["id"] as string)).toBe(1);
    expect(counts.get(readOld["id"] as string)).toBe(1);

    // The quiet group: the older entry earned nothing at all, so it is not in
    // the payload, exactly as an entry nobody read is not.
    expect(counts.get(quietNew["id"] as string)).toBe(1);
    expect(counts.has(quietOld["id"] as string)).toBe(false);
  });

  it("pays both entries of a pair whose values differ", () => {
    const counts = new Map(
      payload.reads.map((row) => [row.entry_id, row.count]),
    );
    expect(counts.get(apartOne["id"] as string)).toBe(1);
    expect(counts.get(apartTwo["id"] as string)).toBe(1);
  });

  it("publishes a payload of the same shape, summing to its own rows", () => {
    const ids = [readOld, readNew, quietNew, apartOne, apartTwo].map(
      (core) => core["id"] as string,
    );
    const expected = ids
      .map((entry_id) => ({ entry_id, count: 1 }))
      .sort((left, right) => (left.entry_id < right.entry_id ? -1 : 1));

    expect(payload.date).toBe(date(0));
    expect(payload.reads).toEqual(expected);
    expect(payload.total).toBe(expected.length);
    expect(payload.total).toBe(
      payload.reads.reduce((sum, row) => sum + row.count, 0),
    );

    // The bounds are the day's own counters, untouched by the rule: the sync
    // and the read are still both on the running counter.
    expect(payload.counter_first).toBe(1);
    expect(payload.counter_last).toBe(2);

    // Nobody held a key here: the day's paid half is empty (M24).
    expect(payload.paid).toEqual({ reads: [], total: 0, keys: {} });

    // Nothing about the payload is built anywhere but `buildReadCountPayload`.
    expect(payload).toEqual(
      buildReadCountPayload(
        date(0),
        payload.reads,
        payload.counter_first,
        payload.counter_last,
        // Every read of this day was free, so the block is empty — and it is
        // there, because a day that published no paid read published that fact.
        payload.paid!,
        payload.duplicates!,
      ),
    );
  });

  it("names every read it dropped, and where the group's reads went", () => {
    // M24b: a reader holding a sync receipt for the older entry of a group
    // cannot tell the D-085 rule from an under-count unless the day says so.
    // Both groups are here — the one whose older entry was also read by hand
    // and the one nobody read — because both lost a sync read to the rule.
    expect(payload.duplicates).toEqual(
      [
        {
          entry_id: readOld["id"] as string,
          newest: readNew["id"] as string,
          sync_reads: 1,
        },
        {
          entry_id: quietOld["id"] as string,
          newest: quietNew["id"] as string,
          sync_reads: 1,
        },
      ].sort((left, right) => (left.entry_id < right.entry_id ? -1 : 1)),
    );

    // The pair that only looks alike lost nothing: it is not a group.
    const dropped = payload.duplicates!.map((row) => row.entry_id);
    expect(dropped).not.toContain(apartOne["id"]);
    expect(dropped).not.toContain(apartTwo["id"]);

    // And the drop is exactly the gap between what the sync delivered and what
    // the day counted: the older entry of the quiet group is in neither `reads`
    // nor `paid`, and the reason is here rather than nowhere.
    const counts = new Map(
      payload.reads.map((row) => [row.entry_id, row.count]),
    );
    for (const row of payload.duplicates!) {
      expect(counts.get(row.newest)).toBe(1);
    }
  });

  it("reports the day it published and skips nothing new for it", () => {
    expect(report.published).toEqual([
      { date: date(0), total: payload.total, seq: published.seq },
    ]);
    for (const reason of Object.keys(report.skipped)) {
      expect(reason.includes("duplicate")).toBe(false);
    }
  });
});
