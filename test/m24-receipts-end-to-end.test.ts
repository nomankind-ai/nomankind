/**
 * M24 end to end: what a paid read leaves behind.
 *
 * Whitepaper Section 9, Money: "A read is one verified entry returned by the
 * paid API, or one verified entry delivered in a paid sync ... every paid read
 * also returns a signed receipt naming the entry, the time, and a running
 * counter", and "read counts are published to the sealed log daily, so
 * nomankind cannot quietly change the numbers later".
 *
 * So this file walks one day of traffic through the real doors — two keyed
 * reads, one free read and one keyed sync — and then asks the three questions
 * that make the money checkable. Does the receipt name the key and its own
 * counter, and does it still verify? Does the day's published count carry a
 * `paid` block that agrees with what the key's own usage page says it read? And
 * does the ledger price that block and nothing else, so a free reader earns
 * nobody anything and a payer earns exactly what they were billed for?
 *
 * Everything is real except the network, the clock and the payment provider:
 * miniflare's D1 and R2, real Ed25519 over the real canonical bytes, the real
 * submit, validate, read and sync doors, and the sweep the alarm runs. The key
 * is minted by src/keys.ts and stored exactly as the claim door stores one.
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
import { mintKey } from "../src/keys.js";
import type { LedgerRow } from "../src/ledger.js";
import { mirrorLedgerRows } from "../src/mirror.js";
import {
  DEFAULT_DOMAIN,
  LIST_PAGE_LIMIT,
  RATE_TIERS,
  READ_SHARE_SPLIT,
  READ_PRICE_MICROS_PER_READ,
} from "../src/policy.js";
import {
  signReadReceipt,
  verifyReadReceipt,
  verifySyncReceipt,
  type ReadReceipt,
  type SyncReceipt,
} from "../src/receipt.js";
import { signRecord } from "../src/records.js";
import { txtRecordName } from "../src/registry.js";
import { validateEntry } from "../src/schema.js";
import { signCore } from "../src/sign.js";
import { putKey } from "../src/storage/keys.js";
import {
  appendEvents,
  entryLedgerRows,
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
const VERIFIED_REFERENCE = "mock-verified-m24";

const CATEGORY = "pricing";
const TIER = "standard";

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
/** A third operator, so the pool is the size two approvals decide in. */
let k3: Party;
let author: TestAgent;

/** The two entries the day is read through. */
let first: Core;
let second: Core;

/** The key every paid read here is served on, and its id. */
let secret = "";
let keyId = "";

/** Nomankind's own signing key, so a receipt can be forged in the old shape. */
let sealingKey: CryptoKey;
let sealingIssuer = "";

/** The receipts the day handed out, in the order they were handed out. */
const keyedReads: ReadReceipt[] = [];
let freeRead: ReadReceipt;
let keyedSync: SyncReceipt;

function send(request: Request, now: Date = NOW): Promise<Response> {
  return handleRequest(request, env, { ...deps, now });
}

/** One GET, on the key's tier or on the free one, with the headers it answered. */
async function get(
  path: string,
  options: { key?: boolean; now?: Date } = {},
): Promise<{
  status: number;
  body: Record<string, unknown>;
  headers: Headers;
}> {
  const response = await send(
    new Request(`${TEST_ORIGIN}${path}`, {
      headers:
        options.key === true ? { authorization: `Bearer ${secret}` } : {},
    }),
    options.now ?? NOW,
  );
  return {
    status: response.status,
    body: (await response.json()) as Record<string, unknown>,
    headers: response.headers,
  };
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

/** A stated pricing proposal citing the fixture page. */
function pricing(subject: string, after: string): Omit<SubmissionProposal, "author"> {
  return {
    subject,
    category: CATEGORY,
    domain: DEFAULT_DOMAIN,
    claim: `${subject} seat pricing is ${after}`,
    before: "$35 per seat per month",
    after,
    effective_at: "2026-09-01",
    citation: PRICING_URL,
    snapshot_hash: PRICING_HASH,
    supersedes: null,
  };
}

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
 * D-085 refuses a duplicate of a live entry at the door, so a pair like this can
 * only reach the log the way it reaches it in the world — filed before the rule
 * existed, or two isolates filing the same fact in the same instant. Nothing is
 * invented: the core is signed by the real key, the event links onto the real
 * head, and the entry is `deriveEntry`'s own answer, checked against the schema
 * before it is written.
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

async function verify(core: Core): Promise<void> {
  const id = core["id"] as string;
  await approve(id, k1);
  await approve(id, k2);
  const answer = await get(`/entries/${id}`);
  expect([answer.status, answer.body["status"]]).toEqual([200, "verified"]);
}

/** Run the sweep the alarm runs, with the fakes standing in for the world. */
async function sweep(at: Date): Promise<SweepReport> {
  const beacon = new FixtureBeacon("m24");
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

beforeAll(async () => {
  PRICING_HASH = await pageHash(PRICING);

  const pair = await generateKeypair();
  sealingKey = pair.privateKey;
  const exported = base64urlEncode(
    await exportPrivateKeyPkcs8(pair.privateKey),
  );

  store = await openTestDatabase();
  maintainer = await makeAgent();
  author = await makeAgent();
  k1 = { operator: "o1.example", agent: await makeAgent() };
  k2 = { operator: "o2.example", agent: await makeAgent() };
  k3 = { operator: "o3.example", agent: await makeAgent() };

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

  // The reader who pays: one standard key, stored the way the claim door
  // stores one, and shown here once exactly as its holder would be.
  const minted = mintKey();
  secret = minted.secret;
  keyId = minted.id;
  await putKey(store.db, {
    id: minted.id,
    keyHash: await minted.hash,
    tier: TIER,
    status: "active",
    customer: "cus_m24",
    subscription: "sub_m24",
    checkoutSession: "cs_m24",
    createdAt: AT,
  });

  first = await submit(pricing("example/osprey-one", "$40 per seat per month"));
  await verify(first);
  second = await submit(pricing("example/osprey-two", "$50 per seat per month"));
  await verify(second);

  // Everything above is sealed, so the sync below has a head to answer from.
  await sweep(NOW);
  expect(await latestSeal(store.db)).not.toBeNull();

  // Day 0's traffic: two keyed reads, one free read of the same entry, and one
  // keyed sync that delivers both verified entries.
  for (const core of [first, second]) {
    const answer = await get(`/read/${core["id"] as string}`, { key: true });
    expect([answer.status, core["id"]]).toEqual([200, core["id"]]);
    keyedReads.push(answer.body["receipt"] as ReadReceipt);
  }
  const free = await get(`/read/${first["id"] as string}`);
  expect(free.status).toBe(200);
  freeRead = free.body["receipt"] as ReadReceipt;

  const synced = await get("/sync?from=0", { key: true });
  expect(synced.status).toBe(200);
  keyedSync = synced.body["receipt"] as SyncReceipt;

  sealingIssuer = freeRead.issuer;
}, 300_000);

afterAll(async () => {
  await store?.dispose();
});

// ---------------------------------------------------------------------------
// (a) The receipt a payer is handed
// ---------------------------------------------------------------------------

describe("a read served to a key", () => {
  it("names the key and counts the key's own reads from one", async () => {
    expect(keyedReads.map((receipt) => receipt.key)).toEqual([keyId, keyId]);
    expect(keyedReads.map((receipt) => receipt.key_counter)).toEqual([1, 2]);
    for (const receipt of keyedReads) {
      await expect(verifyReadReceipt(receipt)).resolves.toBe(true);
    }
    // The secret is nowhere in what the reader was handed.
    expect(JSON.stringify(keyedReads)).not.toContain(secret);
  });

  it("carries the log-wide counter beside the key's own", () => {
    // Two different numbers about two different things: the key's reads, and
    // everything nomankind has ever served.
    expect(keyedReads[0]!.counter).toBe(1);
    expect(keyedReads[1]!.counter).toBe(2);
  });

  it("answers the tier, the cap and what is left of the day", async () => {
    const answer = await get(`/read/${first["id"] as string}`, { key: true });
    expect(answer.status).toBe(200);
    expect(answer.headers.get("x-nomankind-tier")).toBe(TIER);
    const limit = Number(answer.headers.get("x-nomankind-limit"));
    const remaining = Number(answer.headers.get("x-nomankind-remaining"));
    expect(limit).toBe(RATE_TIERS[TIER]!.reads_per_day);
    // Two reads and a sync of two entries came before this one, and this one is
    // charged too: five of the day's cap are gone.
    expect(remaining).toBe(limit - 5);
    const receipt = answer.body["receipt"] as ReadReceipt;
    expect(receipt.key_counter).toBe(4);
  });
});

describe("a read served without a key", () => {
  it("says so in the receipt, in nulls rather than in silence", async () => {
    expect([freeRead.key, freeRead.key_counter]).toEqual([null, null]);
    await expect(verifyReadReceipt(freeRead)).resolves.toBe(true);
  });

  it("still verifies a receipt written before the fields existed", async () => {
    // The M17 shape: no `key` property at all, signed by the same agent.
    const old = await signReadReceipt(
      {
        entry_id: first["id"] as string,
        entry_hash: freeRead.entry_hash,
        read_at: AT,
        counter: 9_999,
        issuer: sealingIssuer,
      },
      sealingKey,
    );
    expect("key" in old).toBe(false);
    await expect(verifyReadReceipt(old)).resolves.toBe(true);
  });
});

describe("a sync served to a key", () => {
  it("counts the verified entries it delivered and charges them", async () => {
    expect(keyedSync.key).toBe(keyId);
    expect(keyedSync.key_counter).toBe(3);
    await expect(verifySyncReceipt(keyedSync)).resolves.toBe(true);

    const verified = keyedSync.entries.filter(
      (entry) => entry.status === "verified",
    );
    expect(verified.map((entry) => entry.entry_id).sort()).toEqual(
      [first["id"] as string, second["id"] as string].sort(),
    );

    // Two keyed reads, the two entries the sync delivered, and the read the
    // header case above made: five on the key's day, and the free read on
    // nobody's.
    const me = await get("/keys/me", { key: true });
    expect(me.status).toBe(200);
    expect(me.body["used_today"]).toBe(5);
  });
});

// ---------------------------------------------------------------------------
// (b) The day, published
// ---------------------------------------------------------------------------

describe("the day's published count", () => {
  let published: Event<"read_count">;
  let payload: EventPayloads["read_count"];

  beforeAll(async () => {
    await sweep(day(1));
    const events = await eventsAfter(store.db, -1, LIST_PAGE_LIMIT * 4);
    published = events.find(
      (event) =>
        event.type === "read_count" &&
        (event.payload as EventPayloads["read_count"]).date === date(0),
    ) as Event<"read_count">;
    payload = published.payload as EventPayloads["read_count"];
  }, 300_000);

  it("counts every reader in `reads` and only the payer in `paid`", async () => {
    const counts = new Map(payload.reads.map((row) => [row.entry_id, row.count]));
    const paid = new Map(
      payload.paid!.reads.map((row) => [row.entry_id, row.count]),
    );
    const one = first["id"] as string;
    const two = second["id"] as string;

    // Entry one: a keyed read, a free read, one sync delivery, and the extra
    // keyed read the header test made. Entry two: a keyed read and a delivery.
    expect(counts.get(one)).toBe(4);
    expect(counts.get(two)).toBe(2);
    expect(paid.get(one)).toBe(3);
    expect(paid.get(two)).toBe(2);
    expect(payload.total).toBe(6);
    expect(payload.paid!.total).toBe(5);
  });

  it("names the key's own day, and it is what the key's usage says", async () => {
    expect(payload.paid!.keys).toEqual({ [keyId]: 5 });
    expect(payload.paid!.total).toBe(
      Object.values(payload.paid!.keys).reduce((sum, count) => sum + count, 0),
    );

    // The key's own usage page, which reads the quota rows rather than the
    // event, agrees with the number the log published — which is the whole of
    // Section 9's "compare the receipts you hold against the published counts".
    const usage = await get("/keys/me/usage", { key: true, now: day(1) });
    expect(usage.status).toBe(200);
    const days = usage.body["days"] as {
      date: string;
      reads: number;
      published: { reads: number; seq: number } | null;
    }[];
    const zero = days.find((row) => row.date === date(0))!;
    expect(zero.reads).toBe(payload.paid!.keys[keyId]);
    expect(zero.published).toEqual({
      reads: payload.paid!.keys[keyId],
      seq: published.seq,
    });
  });
});

// ---------------------------------------------------------------------------
// (c) The money, over the paid half only
// ---------------------------------------------------------------------------

describe("the ledger over a day with free reads in it", () => {
  it("prices the paid block and nothing beside it", async () => {
    const rows = (
      await entryLedgerRows(store.db, first["id"] as string, LIST_PAGE_LIMIT)
    ).filter((row: LedgerRow) => row.kind === "read_share");
    expect(rows.length).toBeGreaterThan(0);

    // Three paid reads of entry one, not the four the day published: the free
    // read earned nobody anything, because nobody was billed for it.
    expect(rows.every((row) => row.reads === 3)).toBe(true);
    const submitter = rows.find((row) => row.role === "submitter");
    // A bare-key submission has no operator to pay, so the slots are the rows.
    expect(submitter).toBeUndefined();
    expect(rows.map((row) => row.amount)).toEqual(
      rows.map(() =>
        Math.floor((3 * READ_PRICE_MICROS_PER_READ * READ_SHARE_SPLIT.validator) / 100),
      ),
    );
  });

  it("prices the day exactly as the mirror recomputes it", async () => {
    // The ledger table is a cache of the fold the mirror runs over the sealed
    // events, so the two readings of one day have to be one answer — and for a
    // day with a `paid` block that means both of them price `paid.reads`. A
    // mirror that priced the whole day's traffic would hand a verifier a
    // different number than the row the sweep wrote, on the same events.
    const sealed = (await latestSeal(store.db))!;
    const events = await eventsAfter(store.db, -1, LIST_PAGE_LIMIT * 4);
    const id = first["id"] as string;
    const recomputed = mirrorLedgerRows(events, sealed.sealed_at).filter(
      (row: LedgerRow) => row.kind === "read_share" && row.entry_id === id,
    );
    const stored = (
      await entryLedgerRows(store.db, id, LIST_PAGE_LIMIT)
    ).filter((row: LedgerRow) => row.kind === "read_share");
    expect(recomputed.length).toBeGreaterThan(0);
    expect(recomputed).toEqual(stored);
    // Three paid reads of entry one, and not the four the day published.
    expect(recomputed.every((row) => row.reads === 3)).toBe(true);
  });

  it("reconciles the day against the priced rows and says ok", async () => {
    const answer = await get("/ledger", { now: day(1) });
    expect(answer.status).toBe(200);
    const reconciliations = answer.body["reconciliations"] as LedgerRow[];
    const zero = reconciliations.find((row) => row.date === date(0))!;
    expect(zero.ref["ok"]).toBe(true);
    expect(zero.ref["published_total"]).toBe(5);
    expect(zero.ref["accrued_total"]).toBe(5);
  });
});

// ---------------------------------------------------------------------------
// (d) One fact delivered twice, billed once (D-085)
// ---------------------------------------------------------------------------

/**
 * Decision D-085 inside the paid block.
 *
 * A sync hands the trainer the whole delta, so when two verified entries assert
 * the same fact about the same subject the trainer was delivered one fact
 * twice. The log is owed one read for it, and the one it is owed is the entry it
 * stands behind: the newest of the group, which is what GET /read serves. The
 * rule is one fold in the publish step, so it has to hold for the paid half
 * exactly as it holds for the public count — a `paid.keys` that counted both
 * copies would bill a reader twice for a fact they were handed once.
 */
describe("a duplicate group delivered in one paid sync", () => {
  const DUP_SUBJECT = "example/osprey-twice";
  /** The day this group's one sync is served on, and the day it publishes for. */
  const DUP_DAY = 1;

  let dupOld: Core;
  let dupNew: Core;
  let dupKeyId = "";
  let dupSecret = "";
  let payload: EventPayloads["read_count"];

  beforeAll(async () => {
    // The older entry through the real door, then the copy that differs from it
    // only by whitespace, which norm-v1.2 collapses away.
    const before = (await headSeq(store.db))!;
    dupOld = await submit(pricing(DUP_SUBJECT, "$77 per seat per month"));
    await verify(dupOld);
    dupNew = await fileWithoutTheDoor(
      pricing(DUP_SUBJECT, "$77  per   seat per  month"),
    );
    await verify(dupNew);

    // Everything the sync will deliver is sealed before it is asked for.
    await sweep(day(DUP_DAY));

    // A key of its own, so the day's paid half is this one sync and nothing
    // else: what the block says is what this sync was worth.
    const minted = mintKey();
    dupKeyId = minted.id;
    dupSecret = minted.secret;
    await putKey(store.db, {
      id: minted.id,
      keyHash: await minted.hash,
      tier: TIER,
      status: "active",
      customer: "cus_m24_dup",
      subscription: "sub_m24_dup",
      checkoutSession: "cs_m24_dup",
      createdAt: AT,
    });

    const response = await send(
      new Request(`${TEST_ORIGIN}/sync?from=${before + 1}`, {
        headers: { authorization: `Bearer ${minted.secret}` },
      }),
      day(DUP_DAY),
    );
    expect(response.status).toBe(200);
    const body = (await response.json()) as Record<string, unknown>;
    const receipt = body["receipt"] as SyncReceipt;
    expect(receipt.key).toBe(dupKeyId);
    expect(
      receipt.entries
        .filter((entry) => entry.status === "verified")
        .map((entry) => entry.entry_id)
        .sort(),
    ).toEqual([dupOld["id"] as string, dupNew["id"] as string].sort());

    await sweep(day(DUP_DAY + 1));
    const events = await eventsAfter(store.db, -1, LIST_PAGE_LIMIT * 8);
    const published = events.find(
      (event) =>
        event.type === "read_count" &&
        (event.payload as EventPayloads["read_count"]).date === date(DUP_DAY),
    ) as Event<"read_count">;
    payload = published.payload as EventPayloads["read_count"];
  }, 300_000);

  it("is a real duplicate group: one fact, filed twice", () => {
    expect(sameDuplicateKey(duplicateKey(dupOld), duplicateKey(dupNew))).toBe(
      true,
    );
    expect(dupNew["after"]).not.toBe(dupOld["after"]);
    expect(dupNew["id"]).not.toBe(dupOld["id"]);
  });

  it("bills the key for one read, not for the two it was handed", () => {
    expect(payload.paid!.keys).toEqual({ [dupKeyId]: 1 });
    expect(payload.paid!.total).toBe(1);
    expect(payload.paid!.total).toBe(
      Object.values(payload.paid!.keys).reduce((sum, count) => sum + count, 0),
    );
    expect(payload.paid!.reads).toEqual([
      { entry_id: dupNew["id"] as string, count: 1 },
    ]);
  });

  it("drops the older copy's sync read from the public count too", () => {
    // One rule, one fold: the public count and the paid block drop the same
    // read, so a reader checking the two against each other finds them agreed.
    const counts = new Map(payload.reads.map((row) => [row.entry_id, row.count]));
    expect(counts.get(dupNew["id"] as string)).toBe(1);
    expect(counts.get(dupOld["id"] as string)).toBeUndefined();
    expect(payload.total).toBe(1);
  });

  it("still charged the cap for both entries it delivered", async () => {
    // Two numbers about two different things: the cap counts what the door
    // handed over, and the published count is what the log says it is owed for.
    // The gap between them is exactly the duplicate, and it is the published
    // number the money follows.
    const response = await send(
      new Request(`${TEST_ORIGIN}/keys/me`, {
        headers: { authorization: `Bearer ${dupSecret}` },
      }),
      day(DUP_DAY),
    );
    expect(response.status).toBe(200);
    const me = (await response.json()) as Record<string, unknown>;
    expect(me["used_today"]).toBe(2);
    expect(payload.paid!.keys[dupKeyId]).toBe(1);
  });
});
