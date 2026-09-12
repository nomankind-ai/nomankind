/**
 * M17 end to end: the frozen reader, through the Worker and the sweep.
 *
 * Whitepaper Section 8, "The frozen reader": "The request names a subject and a
 * category, or an entry id, and optionally a minimum tier and a maximum age. The
 * response is the entry record as in Section 3, the inclusion proof for its
 * seal, and a signed read receipt naming the entry, the time, and a running
 * counter." And Section 9, the accounting paragraph of Money: "Read counts are
 * published to the sealed log daily ... every paid read also returns a signed
 * receipt naming the entry, the time, and a running counter ... Each day's
 * published count is the number the seal commits to."
 *
 * So this file reads a real log as a stranger would and then checks the two
 * promises the paper makes about what came back. The receipt is a real Ed25519
 * signature over the real canonical bytes, and it verifies against the key
 * inside its own issuer id; the entry hash inside it is the entry's own core
 * hash; the inclusion proof beside it recomputes against the seal's root; the
 * counter runs; and the day's published count, when the day is over, is exactly
 * the receipts that day issued, sealed by the run that published it.
 *
 * Everything is real except the network and the clock. The database is
 * miniflare's D1 with every migration applied, every key is generated through
 * WebCrypto and every signature is made by it, and the sweep under test is the
 * one the Durable Object's alarm runs. Only the DNS resolver, the payment
 * provider, the page fetch, the beacon, the witness adapter and the timestamping
 * chain are injected, because only those are not ours to run in a test.
 */

import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";

import { FixtureBeacon } from "../src/adapters/beacon.js";
import { MockPayoutAdapter } from "../src/adapters/payout.js";
import { buildExport } from "../src/cli/export.js";
import type { Core } from "../src/core.js";
import { extractCore } from "../src/core.js";
import { base64urlEncode } from "../src/encoding.js";
import type { ApproverRecord, Event, EventPayloads } from "../src/events.js";
import { entryHash } from "../src/hash.js";
import {
  agentIdFromPublicKey,
  exportPrivateKeyPkcs8,
  exportPublicKeyRaw,
  generateKeypair,
} from "../src/identity.js";
import { decodeProof, verifyInclusion } from "../src/merkle.js";
import { DEFAULT_DOMAIN, LIST_PAGE_LIMIT } from "../src/policy.js";
import { verifyReadReceipt, type ReadReceipt } from "../src/receipt.js";
import { signRecord } from "../src/records.js";
import { txtRecordName } from "../src/registry.js";
import type { Seal } from "../src/seal.js";
import {
  eventsAfter,
  latestEventOfType,
  nextReadCounter,
  readReceiptByCounter,
  sealCovering,
} from "../src/storage/repository.js";
import type { SubmissionProposal } from "../src/submit.js";
import { verifyOffline } from "../src/verify.js";
import type { Env } from "../src/worker/env.js";
import { handleRequest, type RequestDeps } from "../src/worker/index.js";
import { runSweep, type SweepReport } from "../src/worker/sweep.js";
import { openTestDatabase, type TestDatabase } from "./helpers/d1.js";
import {
  FixtureResolver,
  TEST_ORIGIN,
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

/**
 * The one thing in this file that is not real.
 *
 * The cron and the Durable Object's alarm can both reach the publish step for
 * the same day: both read the head, both build the same `read_count` onto it,
 * and the chain rule refuses the second one's event. Nothing in a test can make
 * two runs interleave inside a single D1 batch, so the write door is wrapped
 * rather than replaced — every call goes to the real `appendEvents` — and one
 * test arms `conflict` for exactly one call, which is the losing write. Delete
 * the `EventAppendError` catch from src/worker/sweep.ts and that test, and only
 * that test, fails.
 */
const publishGate = vi.hoisted(() => ({ conflict: false }));

vi.mock("../src/storage/repository.js", async (importOriginal) => {
  const actual =
    await importOriginal<typeof import("../src/storage/repository.js")>();
  return {
    ...actual,
    appendEvents: async (
      ...args: Parameters<typeof actual.appendEvents>
    ): Promise<void> => {
      if (publishGate.conflict) {
        publishGate.conflict = false;
        const events = args[1];
        throw new actual.EventAppendError(
          "bad_seq",
          events[0]?.seq ?? 0,
          "the other timer appended first",
        );
      }
      await actual.appendEvents(...args);
    },
  };
});

/** Day 0: the instant every registration, submission and decision is served at. */
const NOW = SUBMIT_NOW;
const AT = NOW.toISOString();

/** A unit constant: the fake clock moves in whole days. */
const DAY_MS = 86_400_000;

/** The instant `days` after day 0, at the same time of day. */
function day(days: number): Date {
  return new Date(NOW.getTime() + days * DAY_MS);
}

/** The UTC calendar day `days` after day 0. */
function date(days: number): string {
  return day(days).toISOString().slice(0, 10);
}

/** A reference the mock payment provider calls onboarded. */
const VERIFIED_REFERENCE = "mock-verified-m17";

/** The subject and category every read in this file asks about. */
const SUBJECT = "example/kestrel-1";
const CATEGORY = "pricing";

// ---------------------------------------------------------------------------
// The page the citations point at
// ---------------------------------------------------------------------------

const PRICING: FixturePage = {
  body: "<!doctype html><html><body><main><h1>Kestrel pricing</h1><p>$40 per seat per month</p></main></body></html>",
  contentType: "text/html; charset=utf-8",
};

const PRICING_URL = "https://kestrel.example/pricing";
const PAGES: Record<string, FixturePage> = { [PRICING_URL]: PRICING };

/** The pricing page's hash under the real norm rule. */
let PRICING_HASH = "";

// ---------------------------------------------------------------------------
// The world
// ---------------------------------------------------------------------------

/** One operator and the agent bound to it. */
interface Party {
  readonly operator: string;
  readonly agent: TestAgent;
}

interface World {
  readonly store: TestDatabase;
  readonly env: Env;
  readonly deps: RequestDeps;
  readonly maintainer: TestAgent;
}

let world: World;
let k1: Party;
let k2: Party;
let k3: Party;
let maintainerParty: Party;
/** A bare key that submits: it names no operator, so every k may judge it. */
let author: TestAgent;

/** The entry nobody ever validated. */
let draftEntry: Core;
/** The entry two operators approved. */
let verifiedEntry: Core;

/** Nomankind's own agent: the receipt signer, and the id it signs under. */
let sealingKey = "";
let sealingAgentId = "";

/** Every receipt this file was handed, in the order it was handed them. */
const issued: ReadReceipt[] = [];

async function makeParty(operator: string): Promise<Party> {
  return { operator, agent: await makeAgent() };
}

/** Send one request, at day 0 unless the caller names another instant. */
function send(
  request: Request,
  now: Date = NOW,
  env: Env = world.env,
): Promise<Response> {
  return handleRequest(request, env, { ...world.deps, now });
}

/**
 * One GET, signed by an agent bound to a registered operator.
 *
 * The release window (decision D-100) withholds an unreleased entry's content
 * from a free reader, and every entry in this file is inside the window: it is
 * read at the instant it was submitted, before any seal has aged thirty days.
 * So these reads are made the way a validator's client makes them, with the M2
 * signature the disclosure gate already asks for. What is under test here is
 * the receipt and the count, and both are exactly what a free read of a
 * released entry would produce — an operator read is metered on the free tier
 * and issues a receipt, as any read does.
 */
function get(path: string, now: Date = NOW): Promise<Request> {
  return signedGet(k1.agent, { path, timestamp: now.toISOString() });
}

/** The same signature on every request one client makes, at one instant. */
function signingClient(now: Date): { fetch: (request: Request) => Promise<Response> } {
  return {
    fetch: async (request: Request): Promise<Response> => {
      if (request.method !== "GET") return send(request, now);
      const path = new URL(request.url).pathname + new URL(request.url).search;
      return send(await get(path, now), now);
    },
  };
}

/** One GET, with its status and whatever JSON came back. */
async function read(
  path: string,
  now: Date = NOW,
  env: Env = world.env,
): Promise<{ status: number; body: Record<string, unknown> }> {
  const response = await send(await get(path, now), now, env);
  expect(response.headers.get("cache-control")).toBe("no-store");
  return {
    status: response.status,
    body: (await response.json()) as Record<string, unknown>,
  };
}

/**
 * One read that has to succeed, with the receipt it handed back recorded. Every
 * assertion about the counters and the day's totals is made against this list,
 * so the test counts what it actually asked for rather than a number written
 * down twice.
 */
async function readOk(
  path: string,
  now: Date = NOW,
): Promise<Record<string, unknown>> {
  const answer = await read(path, now);
  expect([answer.status, path]).toEqual([200, path]);
  issued.push(answer.body["receipt"] as ReadReceipt);
  return answer.body;
}

/** The receipts issued on one UTC day, in counter order. */
function issuedOn(utcDate: string): ReadReceipt[] {
  return issued
    .filter((receipt) => receipt.read_at.startsWith(`${utcDate}T`))
    .sort((left, right) => left.counter - right.counter);
}

/** Register one operator through the door, exactly as an outsider would. */
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

/** Name one registered operator to the trusted pool, as only the maintainer may. */
async function name(party: Party): Promise<void> {
  const request = await signedPost(world.maintainer, {
    path: "/genesis",
    body: { operator: party.operator },
    timestamp: AT,
  });
  const response = await send(request);
  expect([response.status, party.operator]).toEqual([200, party.operator]);
}

/** A stated pricing proposal citing the fixture page. */
function pricing(claim: string): Omit<SubmissionProposal, "author"> {
  return {
    subject: SUBJECT,
    category: CATEGORY,
    domain: DEFAULT_DOMAIN,
    claim,
    before: "$35 per seat per month",
    // The value is the duplicate key (decision D-085): two live entries on
    // one subject and category may not both assert it. Every entry this
    // helper builds shares a subject and a category, and none of these tests
    // is about duplicates, so each one's value names its own case, which the
    // claim already does.
    after: `$40 per seat per month, per: ${claim}`,
    effective_at: "2026-09-01",
    citation: PRICING_URL,
    snapshot_hash: PRICING_HASH,
  };
}

async function submit(claim: string): Promise<Core> {
  const core = await submittedCore(author, pricing(claim));
  const response = await send(await submission(author, { core }));
  expect([response.status, await response.json()]).toEqual([
    201,
    expect.objectContaining({ id: core["id"], status: "draft" }),
  ]);
  return core;
}

/** One signed approval, through the real door. */
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
  expect(response.status).toBe(201);
}

/** The whole log, as it is stored. */
function logEvents(): Promise<Event[]> {
  return eventsAfter(world.store.db, -1, LIST_PAGE_LIMIT);
}

/** Run the sweep the alarm runs, with the fakes standing in for the world. */
async function sweep(at: Date): Promise<SweepReport> {
  const beacon = new FixtureBeacon("m17");
  await beacon.advance(at.toISOString());
  return runSweep(world.env, {
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

  // Nomankind's own agent, generated here and handed to the Worker exactly as a
  // secret is: the private key PKCS#8 in unpadded base64url.
  const pair = await generateKeypair();
  sealingKey = base64urlEncode(await exportPrivateKeyPkcs8(pair.privateKey));
  sealingAgentId = agentIdFromPublicKey(
    await exportPublicKeyRaw(pair.publicKey),
  );

  const store = await openTestDatabase();
  const maintainer = await makeAgent();
  author = await makeAgent();
  k1 = await makeParty("k1.example");
  k2 = await makeParty("k2.example");
  k3 = await makeParty("k3.example");
  maintainerParty = { operator: "maintainer.example", agent: maintainer };

  const records: Record<string, string[]> = {};
  for (const party of [k1, k2, k3, maintainerParty]) {
    records[txtRecordName(party.operator)] = [party.agent.agentId];
  }

  world = {
    store,
    env: {
      DB: store.db,
      CAPTURES: store.captures,
      ENVIRONMENT: "local",
      MAINTAINER_AGENT_ID: maintainer.agentId,
      SEALING_AGENT_KEY: sealingKey,
    },
    deps: {
      now: NOW,
      dns: new FixtureResolver(records),
      payout: new MockPayoutAdapter(),
      fetcher: new FixtureFetcher(PAGES),
    },
    maintainer,
  };

  for (const party of [k1, k2, k3]) {
    await register(party);
    await name(party);
  }
  await register(maintainerParty);

  draftEntry = await submit("Kestrel-1 seat pricing is $40 per seat per month");
  verifiedEntry = await submit(
    "Kestrel-1 seat pricing is listed at $40 per seat per month",
  );

  await approve(verifiedEntry["id"] as string, k1);
  await approve(verifiedEntry["id"] as string, k2);
}, 180_000);

afterAll(async () => {
  await world?.store.dispose();
});

// ---------------------------------------------------------------------------
// GET /read/{id}
// ---------------------------------------------------------------------------

describe("one entry by id, before anything is sealed", () => {
  it("refuses an id that is not one", async () => {
    expect(await read("/read/nope")).toEqual({
      status: 400,
      body: { error: "bad_id" },
    });
    expect(await read("/read/nmk_0011")).toEqual({
      status: 400,
      body: { error: "bad_id" },
    });
  });

  it("answers 404 for an entry the log does not hold", async () => {
    expect(
      await read(`/read/nmk_${"0".repeat(32)}`),
    ).toEqual({ status: 404, body: { error: "not_found" } });
  });

  it("refuses a draft with its status and no receipt", async () => {
    const before = await nextReadCounter(world.store.db);
    const answer = await read(`/read/${draftEntry["id"] as string}`);

    expect(answer.status).toBe(409);
    expect(answer.body).toEqual({
      error: "entry_not_verified",
      status: "draft",
      superseded_by: null,
    });
    // Nothing was served, so nothing was counted.
    expect(await nextReadCounter(world.store.db)).toBe(before);
  });

  it("serves the verified entry with an unsealed seal and the first receipt", async () => {
    const body = await readOk(`/read/${verifiedEntry["id"] as string}`);
    const entry = body["entry"] as Record<string, unknown>;
    const receipt = body["receipt"] as ReadReceipt;

    expect(entry["id"]).toBe(verifiedEntry["id"]);
    expect(entry["status"]).toBe("verified");
    // The sidecar the schema cannot hold, beside the entry it belongs to.
    expect(body["sidecar"]).toMatchObject({ effective_tier: "stated" });
    // Nothing has sealed the submission yet, so there is no covering seal.
    expect(body["seal"]).toBeNull();

    expect(receipt.counter).toBe(1);
    expect(receipt.entry_id).toBe(verifiedEntry["id"]);
    expect(receipt.read_at).toBe(AT);
    expect(receipt.issuer).toBe(sealingAgentId);
    expect(receipt.entry_hash).toBe(await entryHash(extractCore(entry)));
    expect(await verifyReadReceipt(receipt)).toBe(true);
  }, 60_000);

  it("runs the counter, and stores every receipt it handed out", async () => {
    const body = await readOk(`/read/${verifiedEntry["id"] as string}`);
    const second = body["receipt"] as ReadReceipt;
    expect(second.counter).toBe(2);
    expect(await verifyReadReceipt(second)).toBe(true);

    for (const counter of [1, 2]) {
      const stored = await readReceiptByCounter(world.store.db, counter);
      expect([counter, stored]).toEqual([counter, issued[counter - 1]]);
    }
  }, 60_000);

  it("refuses a receipt whose signature was touched", async () => {
    const receipt = issued[0]!;
    const flipped = receipt.signature.startsWith("A")
      ? `B${receipt.signature.slice(1)}`
      : `A${receipt.signature.slice(1)}`;
    expect(await verifyReadReceipt({ ...receipt, signature: flipped })).toBe(
      false,
    );
  });
});

// ---------------------------------------------------------------------------
// The seal beside the entry
// ---------------------------------------------------------------------------

describe("once a sweep has sealed the log", () => {
  let report: SweepReport;

  beforeAll(async () => {
    report = await sweep(NOW);
  }, 120_000);

  it("publishes no read count on the day the reads happened", () => {
    expect(report.published).toEqual([]);
    // Today is not over, so nothing is owed yet.
    expect(report.skipped["read_counts_current"]).toBe(1);
  });

  it("serves the covering seal, and the entry's proof checks against it", async () => {
    const body = await readOk(`/read/${verifiedEntry["id"] as string}`);
    const entry = body["entry"] as Record<string, unknown>;
    const seal = body["seal"] as Seal;
    const entrySeal = entry["seal"] as Record<string, unknown>;

    expect(seal).not.toBeNull();
    expect(seal.seq).toBe(report.sealed!.seq);
    expect(entrySeal["log"]).toBe("1F916");
    expect(entrySeal["sealed_at"]).toBe(seal.sealed_at);

    // The submission event the entry's seal names, and its proof against the
    // root the covering seal committed to.
    const events = await logEvents();
    const submitted = events.find(
      (event) =>
        event.type === "entry_submitted" &&
        event.entry_id === verifiedEntry["id"],
    );
    expect(entrySeal["position"]).toBe(submitted!.seq);

    const proof = decodeProof(entrySeal["inclusion_proof"] as string);
    expect(proof).not.toBeNull();
    expect(await verifyInclusion(submitted!.hash, proof!, seal.root)).toBe(true);
  }, 60_000);
});

// ---------------------------------------------------------------------------
// GET /read?subject=&category=
// ---------------------------------------------------------------------------

describe("the current answer about a subject", () => {
  const search = `subject=${encodeURIComponent(SUBJECT)}&category=${CATEGORY}`;

  it("answers the verified entry, and never the draft beside it", async () => {
    const body = await readOk(`/read?${search}`);
    expect((body["entry"] as Record<string, unknown>)["id"]).toBe(
      verifiedEntry["id"],
    );
    expect(await verifyReadReceipt(body["receipt"])).toBe(true);
  }, 60_000);

  it("refuses a stated entry to a reader who demanded a measurement", async () => {
    expect(await read(`/read?${search}&min_tier=observed`)).toEqual({
      status: 404,
      body: { error: "no_entry" },
    });
  });

  it("answers a reader who demanded a document", async () => {
    const body = await readOk(`/read?${search}&min_tier=stated`);
    expect((body["entry"] as Record<string, unknown>)["id"]).toBe(
      verifiedEntry["id"],
    );
  }, 60_000);

  it("answers the same entry by entry_id", async () => {
    const body = await readOk(
      `/read?entry_id=${verifiedEntry["id"] as string}`,
    );
    expect((body["entry"] as Record<string, unknown>)["id"]).toBe(
      verifiedEntry["id"],
    );
  }, 60_000);

  it("refuses the draft by entry_id exactly as the path form does", async () => {
    expect(await read(`/read?entry_id=${draftEntry["id"] as string}`)).toEqual({
      status: 409,
      body: {
        error: "entry_not_verified",
        status: "draft",
        superseded_by: null,
      },
    });
  });

  it("refuses every malformed query in the kernel's own word", async () => {
    const cases: [string, string][] = [
      [`${search}&nope=1`, "unknown_parameter"],
      [`entry_id=${verifiedEntry["id"] as string}&subject=x`, "mixed_query"],
      [`subject=${encodeURIComponent(SUBJECT)}&category=nope`, "bad_category"],
      [`${search}&min_tier=nope`, "bad_min_tier"],
      [`${search}&max_age=-1`, "bad_max_age"],
    ];
    for (const [query, reason] of cases) {
      expect([query, await read(`/read?${query}`)]).toEqual([
        query,
        { status: 400, body: { error: reason } },
      ]);
    }
  });

  it("refuses a method that is not GET", async () => {
    const posted = await send(
      new Request(`${TEST_ORIGIN}/read`, { method: "POST" }),
    );
    expect(posted.status).toBe(405);
    expect(posted.headers.get("allow")).toBe("GET");
    expect(await posted.json()).toEqual({ error: "method_not_allowed" });
  });
});

// ---------------------------------------------------------------------------
// The reader's age demand
// ---------------------------------------------------------------------------

describe("the maximum age a reader will accept", () => {
  const search = `subject=${encodeURIComponent(SUBJECT)}&category=${CATEGORY}`;

  it("answers max_age=0 on the day the entry was confirmed", async () => {
    const body = await readOk(`/read?${search}&max_age=0`);
    expect((body["entry"] as Record<string, unknown>)["id"]).toBe(
      verifiedEntry["id"],
    );
  }, 60_000);

  it("refuses max_age=0 a day later, and answers max_age=1", async () => {
    expect(await read(`/read?${search}&max_age=0`, day(1))).toEqual({
      status: 404,
      body: { error: "no_entry" },
    });

    const body = await readOk(`/read?${search}&max_age=1`, day(1));
    expect((body["entry"] as Record<string, unknown>)["id"]).toBe(
      verifiedEntry["id"],
    );
    expect((body["receipt"] as ReadReceipt).read_at).toBe(
      day(1).toISOString(),
    );
  }, 60_000);
});

// ---------------------------------------------------------------------------
// A deployment with no key
// ---------------------------------------------------------------------------

describe("an environment with no receipt signer", () => {
  it("refuses the read rather than issuing an unsigned receipt", async () => {
    const bare: Env = { ...world.env };
    delete bare.SEALING_AGENT_KEY;

    const before = await nextReadCounter(world.store.db);
    const answer = await read(
      `/read/${verifiedEntry["id"] as string}`,
      NOW,
      bare,
    );

    expect(answer).toEqual({
      status: 503,
      body: { error: "receipts_not_configured" },
    });
    expect(await nextReadCounter(world.store.db)).toBe(before);
  });
});

// ---------------------------------------------------------------------------
// The day's published count
// ---------------------------------------------------------------------------

describe("the day's read count, published to the sealed log", () => {
  let report: SweepReport;
  let published: Event<"read_count">;

  beforeAll(async () => {
    report = await sweep(day(1));
    const events = await logEvents();
    published = events.find(
      (event) => event.type === "read_count",
    ) as Event<"read_count">;
  }, 120_000);

  it("publishes exactly the receipts the day issued", () => {
    const receipts = issuedOn(date(0));
    expect(receipts.length).toBeGreaterThan(0);

    expect(report.published).toEqual([
      { date: date(0), total: receipts.length, seq: published.seq },
    ]);

    const payload = published.payload as EventPayloads["read_count"];
    expect(payload.date).toBe(date(0));
    expect(payload.total).toBe(receipts.length);
    expect(payload.reads).toEqual([
      { entry_id: verifiedEntry["id"], count: receipts.length },
    ]);
    expect(payload.counter_first).toBe(receipts[0]!.counter);
    expect(payload.counter_last).toBe(receipts[receipts.length - 1]!.counter);
    expect(published.entry_id).toBeNull();
    expect(published.at).toBe(day(1).toISOString());
  });

  it("seals the count in the run that published it", async () => {
    const covering = await sealCovering(world.store.db, published.seq);
    expect(covering).not.toBeNull();
    expect(covering!.seq).toBe(report.sealed!.seq);
  });

  it("publishes nothing on a second run of the same day", async () => {
    const again = await sweep(day(1));
    expect(again.published).toEqual([]);
    expect(again.skipped["read_counts_current"]).toBe(1);
  }, 120_000);

  it("publishes a zero for a day nobody read", async () => {
    const later = await sweep(day(3));

    // Day 1 carried the age-demand reads; day 2 carried none, and a day nobody
    // read is published as zero rather than left out.
    expect(later.published).toEqual([
      { date: date(1), total: issuedOn(date(1)).length, seq: expect.any(Number) },
      { date: date(2), total: 0, seq: expect.any(Number) },
    ]);

    const events = await logEvents();
    const zero = events.find(
      (event) =>
        event.type === "read_count" &&
        (event.payload as EventPayloads["read_count"]).date === date(2),
    ) as Event<"read_count">;
    expect(zero.payload).toEqual({
      date: date(2),
      reads: [],
      total: 0,
      counter_first: null,
      counter_last: null,
      // No receipt rows either, said as a number rather than left out: the
      // count of rows is what the counter range is held against, and a day
      // that published nothing published that too.
      receipts: 0,
      // A day nobody read is also a day nobody paid for, and both halves are
      // published rather than left out (M24).
      paid: { reads: [], total: 0, keys: {} },
      // And a day nobody read dropped nothing, said out loud for the same
      // reason (M24b): an empty block is an answer, a missing one is not.
      duplicates: [],
    });
  }, 120_000);
});

// ---------------------------------------------------------------------------
// The offline verifier, over a log that now holds read counts
// ---------------------------------------------------------------------------

describe("the offline verifier, on a log carrying read counts", () => {
  it("answers ok with zero diffs", async () => {
    const exported = await buildExport({
      baseUrl: TEST_ORIGIN,
      entryId: verifiedEntry["id"] as string,
      http: signingClient(day(3)),
      now: day(3),
    });

    expect(
      exported.bundle.events.some((event) => event.type === "read_count"),
    ).toBe(true);

    const report = await verifyOffline(exported.entry, exported.bundle);
    expect(report.diffs).toEqual([]);
    expect(report.ok).toBe(true);
    expect(report.entry_id).toBe(verifiedEntry["id"]);
  }, 120_000);
});

// ---------------------------------------------------------------------------
// Two timers, one day to publish
// ---------------------------------------------------------------------------

describe("a publish that lost the race to the other timer", () => {
  let conflicted: SweepReport;

  beforeAll(async () => {
    // Day 4's run publishes day 3 and seals the count in the same run, which is
    // what leaves day 4 with seals for the run after it to anchor.
    await sweep(day(4));

    // Now both timers reach the publish step for day 4. The other one appended
    // first, so this one's event no longer links and the door refuses it.
    publishGate.conflict = true;
    conflicted = await sweep(day(5));
  }, 180_000);

  it("counts the conflict and publishes nothing", () => {
    // Armed for exactly one write, and that write was the publish step's.
    expect(publishGate.conflict).toBe(false);
    expect(conflicted.skipped["publish_conflict"]).toBe(1);
    expect(conflicted.published).toEqual([]);
  });

  it("appends no read count for the day it lost", async () => {
    const last = await latestEventOfType(world.store.db, "read_count");
    expect((last!.payload as EventPayloads["read_count"]).date).toBe(date(3));
  });

  it("runs the steps after it rather than rejecting the run", async () => {
    // The anchor is the last step of all, so a report carrying yesterday's is a
    // run that carried on past the refusal instead of throwing out of it.
    expect(conflicted.anchored).toMatchObject({ date: date(4) });
  });

  it("leaves the day for the next run to publish", async () => {
    const again = await sweep(day(5));
    expect(again.published).toEqual([
      {
        date: date(4),
        total: issuedOn(date(4)).length,
        seq: expect.any(Number),
      },
    ]);
  }, 120_000);
});
