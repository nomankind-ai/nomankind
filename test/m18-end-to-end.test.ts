/**
 * M18 end to end: the delta stream, through the Worker and the sweep.
 *
 * Whitepaper Section 8, "The delta stream": a trainer asks for everything the
 * log learned after a position it already holds, and is handed "events strictly
 * by sealed position with inclusion proofs"; `flatten` collapses a supersession
 * chain to its newest entry; an overturned entry arrives as an unlearn item
 * rather than quietly vanishing; and the response carries "the new head and one
 * signed sync receipt covering every delivered entry". Section 8, "Paying for
 * the training path", with Section 9's accounting paragraph: "each delivered
 * verified entry counts as a read", so a sync lands in the same daily published
 * count a reader's receipt does, on the same running counter.
 *
 * So this file syncs a real log as a trainer would and checks each of those
 * promises against what came back. The signatures are real Ed25519 over the
 * real canonical bytes, the proofs recompute against the roots the seals
 * committed to, the entries are re-derived at the sealed head by the same
 * kernel every write door uses, and the day's published count is exactly the
 * receipts — read and sync — the day issued.
 *
 * The world is the m17 world with a chain in it: entry A verified, entry B
 * superseding A and verified, a draft entry C, a verified entry D that nothing
 * touches, and an upheld dispute on B so B derives as overturned. Everything is
 * real except the network and the clock. The one thing built by hand is the
 * `dispute_upheld` event, because M20's dispute door does not exist yet and the
 * unlearn item has to be put in front of the stream today.
 */

import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { FixtureBeacon } from "../src/adapters/beacon.js";
import { MockPayoutAdapter } from "../src/adapters/payout.js";
import type { Core } from "../src/core.js";
import { base64urlEncode } from "../src/encoding.js";
import type { ApproverRecord, Event, EventPayloads } from "../src/events.js";
import { appendEvent } from "../src/events.js";
import {
  agentIdFromPublicKey,
  exportPrivateKeyPkcs8,
  exportPublicKeyRaw,
  generateKeypair,
} from "../src/identity.js";
import { decodeProof, verifyInclusion } from "../src/merkle.js";
import { DEFAULT_DOMAIN, LIST_PAGE_LIMIT } from "../src/policy.js";
import {
  verifySyncReceipt,
  type ReadReceipt,
  type SyncReceipt,
} from "../src/receipt.js";
import { signRecord } from "../src/records.js";
import { txtRecordName } from "../src/registry.js";
import {
  appendEvents,
  eventBySeq,
  eventsAfter,
  headSeq,
  latestSeal,
  nextReadCounter,
  readCountsOn,
} from "../src/storage/repository.js";
import type { SubmissionProposal } from "../src/submit.js";
import type { SyncReceiptEntry } from "../src/sync.js";
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

/** Day 0: the instant every registration, submission, decision and sync is at. */
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
const VERIFIED_REFERENCE = "mock-verified-m18";

/** The chain's subject, and the subject of the entry beside it. */
const CHAIN_SUBJECT = "example/kestrel-1";
const OTHER_SUBJECT = "example/kestrel-2";
const CATEGORY = "pricing";

// ---------------------------------------------------------------------------
// The pages the citations point at
// ---------------------------------------------------------------------------

const PRICING: FixturePage = {
  body: "<!doctype html><html><body><main><h1>Kestrel pricing</h1><p>$40 per seat per month</p></main></body></html>",
  contentType: "text/html; charset=utf-8",
};

const PRICING_URL = "https://kestrel.example/pricing";
const PAGES: Record<string, FixturePage> = { [PRICING_URL]: PRICING };

let PRICING_HASH = "";

// ---------------------------------------------------------------------------
// What a sync answers with
// ---------------------------------------------------------------------------

interface WireSeal {
  seq: number;
  root: string;
  hash: string;
  sealed_at: string;
  witnesses: unknown[];
  registry: unknown;
}

interface WireItem {
  seq: number;
  kind: "entry" | "unlearn" | "event";
  event: Event;
  proof: { seal_seq: number; inclusion_proof: string };
  entry: Record<string, unknown> | null;
  sidecar: Record<string, unknown> | null;
  entry_hash: string | null;
}

interface SyncBody {
  from: number;
  head: number | null;
  sealed_head: number | null;
  as_of: string | null;
  seals: WireSeal[];
  events: WireItem[];
  receipt: SyncReceipt | null;
}

// ---------------------------------------------------------------------------
// The world
// ---------------------------------------------------------------------------

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

/** The entry two operators approved, and that entry B then superseded. */
let entryA: Core;
/** The entry naming A as its target, verified, and then overturned by hand. */
let entryB: Core;
/** The entry nobody ever validated. */
let entryC: Core;
/** The verified entry nothing ever touched again. */
let entryD: Core;

/** Nomankind's own agent: the receipt signer, and the id it signs under. */
let sealingKey = "";
let sealingAgentId = "";

/** The sealed head every test in this file syncs against. */
let sealedHead = 0;
/** The instant that head was sealed at. */
let sealedAt = "";
/** The one event appended after the seal, which no sync may deliver. */
let unsealedSeq = 0;

/** Every receipt this file was handed, in the order it was handed them. */
const syncReceipts: SyncReceipt[] = [];
const readReceipts: ReadReceipt[] = [];

async function makeParty(operator: string): Promise<Party> {
  return { operator, agent: await makeAgent() };
}

function send(
  request: Request,
  now: Date = NOW,
  env: Env = world.env,
): Promise<Response> {
  return handleRequest(request, env, { ...world.deps, now });
}

function get(path: string): Request {
  return new Request(`${TEST_ORIGIN}${path}`);
}

async function read(
  path: string,
  now: Date = NOW,
  env: Env = world.env,
): Promise<{ status: number; body: Record<string, unknown> }> {
  const response = await send(get(path), now, env);
  expect(response.headers.get("cache-control")).toBe("no-store");
  return {
    status: response.status,
    body: (await response.json()) as Record<string, unknown>,
  };
}

/** One sync that has to succeed, with the receipt it issued recorded. */
async function sync(query: string, now: Date = NOW): Promise<SyncBody> {
  const answer = await read(`/sync${query}`, now);
  expect([answer.status, query]).toEqual([200, query]);
  const body = answer.body as unknown as SyncBody;
  if (body.receipt !== null) syncReceipts.push(body.receipt);
  return body;
}

/** One read that has to succeed, with the receipt it issued recorded. */
async function readEntry(entryId: string): Promise<Record<string, unknown>> {
  const answer = await read(`/read/${entryId}`);
  expect(answer.status).toBe(200);
  readReceipts.push(answer.body["receipt"] as ReadReceipt);
  return answer.body;
}

/** The reads each entry is owed on day 0, from the receipts this file holds. */
function expectedReads(): Map<string, number> {
  const counts = new Map<string, number>();
  const add = (entryId: string): void => {
    counts.set(entryId, (counts.get(entryId) ?? 0) + 1);
  };
  for (const receipt of readReceipts) {
    if (receipt.read_at.startsWith(`${date(0)}T`)) add(receipt.entry_id);
  }
  for (const receipt of syncReceipts) {
    if (!receipt.issued_at.startsWith(`${date(0)}T`)) continue;
    for (const entry of receipt.entries) {
      if (entry.status === "verified") add(entry.entry_id);
    }
  }
  return counts;
}

/** The day's counted reads as the store has them, entry by entry. */
async function storedReads(): Promise<Map<string, number>> {
  const rows = await readCountsOn(
    world.store.db,
    date(0),
    undefined,
    LIST_PAGE_LIMIT,
  );
  return new Map(rows.map((row) => [row.entry_id, row.count]));
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
  const request = await signedPost(world.maintainer, {
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
  supersedes: string | null = null,
): Omit<SubmissionProposal, "author"> {
  return {
    subject,
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
    supersedes,
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

/** Run the sweep the alarm runs, with the fakes standing in for the world. */
async function sweep(at: Date): Promise<SweepReport> {
  const beacon = new FixtureBeacon("m18");
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

  // The chain: A verified, then B superseding it and verified, which is what
  // leaves A superseded rather than standing.
  entryA = await submit(
    pricing(CHAIN_SUBJECT, "Kestrel-1 seat pricing is $40 per seat per month"),
  );
  await approve(entryA["id"] as string, k1);
  await approve(entryA["id"] as string, k2);

  entryB = await submit(
    pricing(
      CHAIN_SUBJECT,
      "Kestrel-1 seat pricing is listed at $40 per seat per month",
      entryA["id"] as string,
    ),
  );
  await approve(entryB["id"] as string, k1);
  await approve(entryB["id"] as string, k2);

  // The draft nobody judged, and the verified entry nothing ever touched again.
  entryC = await submit(
    pricing(CHAIN_SUBJECT, "Kestrel-1 seat pricing may rise again in October"),
  );
  entryD = await submit(
    pricing(OTHER_SUBJECT, "Kestrel-2 seat pricing is $40 per seat per month"),
  );
  await approve(entryD["id"] as string, k1);
  await approve(entryD["id"] as string, k2);

  // The unlearn. M20 builds the dispute door; until then the only way to put an
  // overturned entry in front of the delta stream is to append the event the
  // door will append, on the real chain, through the real write.
  const at = await headSeq(store.db);
  const previous = at === null ? [] : [(await eventBySeq(store.db, at))!];
  const chained = await appendEvent(previous, {
    at: AT,
    type: "dispute_upheld",
    entry_id: entryB["id"] as string,
    payload: { correction_entry_id: entryD["id"] as string },
  });
  await appendEvents(store.db, [chained[chained.length - 1]!]);

  // Everything above is sealed; everything after it is not, and no sync may
  // deliver it.
  await sweep(NOW);
  const seal = await latestSeal(store.db);
  sealedHead = seal!.last_seq;
  sealedAt = seal!.sealed_at;

  await approve(entryC["id"] as string, k1);
  unsealedSeq = (await headSeq(store.db))!;
  expect(unsealedSeq).toBeGreaterThan(sealedHead);
}, 240_000);

afterAll(async () => {
  await world?.store.dispose();
});

// ---------------------------------------------------------------------------
// (a) The same question, twice
// ---------------------------------------------------------------------------

describe("two syncs from the same position", () => {
  it("answer the same page, byte for byte, but for the receipt", async () => {
    const first = await sync("?from=0");
    const second = await sync("?from=0");

    const page = (body: SyncBody): string =>
      JSON.stringify({
        events: body.events,
        seals: body.seals,
        head: body.head,
        sealed_head: body.sealed_head,
        as_of: body.as_of,
      });

    expect(page(second)).toBe(page(first));
    expect(first.receipt).not.toBeNull();
    expect(second.receipt!.counter).toBe(first.receipt!.counter + 1);
    expect(second.receipt!.issuer).toBe(sealingAgentId);
  }, 120_000);
});

// ---------------------------------------------------------------------------
// (b) Strictly by sealed position
// ---------------------------------------------------------------------------

describe("the events after the last seal", () => {
  it("are never delivered, and the head is the sealed head", async () => {
    const body = await sync("?from=0");

    expect(body.sealed_head).toBe(sealedHead);
    expect(body.as_of).toBe(sealedAt);
    expect(body.head).toBe(sealedHead);
    expect(body.events.every((item) => item.seq <= sealedHead)).toBe(true);
    expect(body.events.some((item) => item.seq === unsealedSeq)).toBe(false);

    // The log really does hold that event: it is withheld, not missing.
    const log = await eventsAfter(world.store.db, sealedHead, LIST_PAGE_LIMIT);
    expect(log.map((event) => event.seq)).toContain(unsealedSeq);
  }, 120_000);
});

// ---------------------------------------------------------------------------
// (c) flatten
// ---------------------------------------------------------------------------

describe("flatten, over a supersession chain", () => {
  it("drops the superseded entry and keeps the newest, and everything else", async () => {
    const plain = await sync("?from=0");
    const flat = await sync("?from=0&flatten=true");

    const aId = entryA["id"] as string;
    const bId = entryB["id"] as string;

    // A is superseded at the sealed head, so the chain's older entry is gone.
    expect(plain.events.some((item) => item.event.entry_id === aId)).toBe(true);
    expect(flat.events.some((item) => item.event.entry_id === aId)).toBe(false);

    // B is the newest of the chain and is delivered, dispute and all.
    const bItems = flat.events.filter((item) => item.event.entry_id === bId);
    expect(bItems.length).toBe(
      plain.events.filter((item) => item.event.entry_id === bId).length,
    );
    expect(bItems.length).toBeGreaterThan(0);

    // Nothing about an entry is filtered by an entry filter.
    const others = (body: SyncBody): number[] =>
      body.events.filter((item) => item.kind !== "entry").map((item) => item.seq);
    expect(others(flat)).toEqual(others(plain));
  }, 120_000);
});

// ---------------------------------------------------------------------------
// (d) The unlearn item
// ---------------------------------------------------------------------------

describe("an entry the log has overturned", () => {
  it("arrives as an unlearn item carrying the overturned record", async () => {
    const body = await sync("?from=0");
    const bId = entryB["id"] as string;

    const unlearn = body.events.filter((item) => item.kind === "unlearn");
    expect(unlearn.length).toBe(1);

    const item = unlearn[0]!;
    expect(item.event.type).toBe("dispute_upheld");
    expect(item.event.entry_id).toBe(bId);
    expect(item.entry!["id"]).toBe(bId);
    expect(item.entry!["status"]).toBe("overturned");
    expect(item.entry!["overturned_by"]).toBe(entryD["id"]);
    // The schema's confidence field travels inside the entry record.
    expect(item.entry!["confidence"]).toBeNull();
    expect(item.sidecar).not.toBeNull();
    expect(item.entry_hash).not.toBeNull();
  }, 120_000);
});

// ---------------------------------------------------------------------------
// (e) The receipt
// ---------------------------------------------------------------------------

describe("the one signed receipt covering the page", () => {
  it("names every delivered entry once, in first-delivery order", async () => {
    const body = await sync("?from=0");
    const receipt = body.receipt!;

    const firstSeen: string[] = [];
    for (const item of body.events) {
      if (item.kind === "event") continue;
      const id = item.event.entry_id!;
      if (!firstSeen.includes(id)) firstSeen.push(id);
    }
    expect(receipt.entries.map((entry) => entry.entry_id)).toEqual(firstSeen);

    const byId = new Map<string, SyncReceiptEntry>(
      receipt.entries.map((entry) => [entry.entry_id, entry]),
    );
    for (const item of body.events) {
      if (item.kind === "event") continue;
      const named = byId.get(item.event.entry_id!)!;
      expect(named.entry_hash).toBe(item.entry_hash);
      expect(named.status).toBe(item.entry!["status"]);
    }

    expect(receipt.from).toBe(0);
    expect(receipt.head).toBe(sealedHead);
    expect(receipt.event_count).toBe(body.events.length);
    expect(receipt.issued_at).toBe(AT);
    expect(await verifySyncReceipt(receipt)).toBe(true);
  }, 120_000);

  it("refuses a receipt whose signature was touched", async () => {
    const receipt = syncReceipts[0]!;
    const flipped = receipt.signature.startsWith("A")
      ? `B${receipt.signature.slice(1)}`
      : `A${receipt.signature.slice(1)}`;
    expect(await verifySyncReceipt({ ...receipt, signature: flipped })).toBe(
      false,
    );
  });
});

// ---------------------------------------------------------------------------
// (f) Paying for the training path
// ---------------------------------------------------------------------------

describe("each delivered verified entry counts as a read", () => {
  it("counts the verified entries and never the draft, and doubles on a second sync", async () => {
    const before = await storedReads();
    const first = await sync("?from=0");
    const afterOne = await storedReads();

    const verified = first.receipt!.entries.filter(
      (entry) => entry.status === "verified",
    ).map((entry) => entry.entry_id);
    // The world's one standing entry: A is superseded, B overturned, C draft.
    expect(verified).toEqual([entryD["id"]]);

    const delta = (now: Map<string, number>, id: string): number =>
      (now.get(id) ?? 0) - (before.get(id) ?? 0);

    expect(delta(afterOne, entryD["id"] as string)).toBe(1);
    for (const other of [entryA, entryB, entryC]) {
      expect([other["id"], delta(afterOne, other["id"] as string)]).toEqual([
        other["id"],
        0,
      ]);
    }

    await sync("?from=0");
    const afterTwo = await storedReads();
    expect(delta(afterTwo, entryD["id"] as string)).toBe(2);
  }, 180_000);

  it("shares the running counter with the read door", async () => {
    const body = await sync("?from=0");
    const answer = await readEntry(entryD["id"] as string);
    const receipt = answer["receipt"] as ReadReceipt;
    expect(receipt.counter).toBe(body.receipt!.counter + 1);
    expect(await nextReadCounter(world.store.db)).toBe(receipt.counter + 1);
  }, 120_000);
});

// ---------------------------------------------------------------------------
// (g) Paging
// ---------------------------------------------------------------------------

describe("paging by sealed position", () => {
  it("continues without a gap or an overlap", async () => {
    const first = await sync("?from=0&limit=3");
    expect(first.from).toBe(0);
    expect(first.head).toBe(2);
    expect(first.events.every((item) => item.seq <= 2)).toBe(true);

    const second = await sync("?from=3&limit=3");
    expect(second.head).toBe(5);
    expect(second.events.every((item) => item.seq >= 3 && item.seq <= 5)).toBe(
      true,
    );

    const whole = await sync("?from=0&limit=6");
    expect(whole.head).toBe(5);
    expect(whole.events.map((item) => item.seq)).toEqual([
      ...first.events.map((item) => item.seq),
      ...second.events.map((item) => item.seq),
    ]);
  }, 180_000);

  it("answers a position past the sealed head with no head and no receipt", async () => {
    const before = await nextReadCounter(world.store.db);
    const body = await sync(`?from=${sealedHead + 1}`);

    expect(body).toEqual({
      from: sealedHead + 1,
      head: null,
      sealed_head: sealedHead,
      as_of: sealedAt,
      seals: [],
      events: [],
      receipt: null,
    });
    expect(await nextReadCounter(world.store.db)).toBe(before);
  }, 120_000);
});

// ---------------------------------------------------------------------------
// (h) min_tier
// ---------------------------------------------------------------------------

describe("the minimum tier a trainer will learn from", () => {
  it("delivers no entry a stated world can satisfy, and still unlearns", async () => {
    const body = await sync("?from=0&min_tier=observed");

    expect(body.events.some((item) => item.kind === "entry")).toBe(false);
    expect(body.events.some((item) => item.kind === "unlearn")).toBe(true);
    expect(
      body.events.some((item) => item.event.type === "operator_registered"),
    ).toBe(true);
  }, 120_000);

  it("delivers the verified entries to a trainer that asked for a document", async () => {
    const body = await sync("?from=0&min_tier=stated");
    const entries = body.events.filter((item) => item.kind === "entry");

    expect(entries.length).toBeGreaterThan(0);
    for (const item of entries) {
      expect(item.event.entry_id).toBe(entryD["id"]);
      expect(item.entry!["status"]).toBe("verified");
      expect(item.sidecar!["effective_tier"]).toBe("stated");
    }
    expect(body.events.some((item) => item.kind === "unlearn")).toBe(true);
  }, 120_000);
});

// ---------------------------------------------------------------------------
// (i) Refusals
// ---------------------------------------------------------------------------

describe("a query the kernel will not answer", () => {
  it("refuses each one in the kernel's own word, in the order they are checked", async () => {
    const cases: [string, string][] = [
      ["?nope=1", "unknown_parameter"],
      ["?from=nope", "bad_from"],
      ["?limit=0", "bad_limit"],
      [`?limit=${LIST_PAGE_LIMIT + 1}`, "bad_limit"],
      ["?flatten=yes", "bad_flatten"],
      ["?min_tier=nope", "bad_min_tier"],
    ];
    for (const [query, reason] of cases) {
      expect([query, await read(`/sync${query}`)]).toEqual([
        query,
        { status: 400, body: { error: reason } },
      ]);
    }
  });

  it("refuses a parameter given twice rather than guessing which was meant", async () => {
    expect(await read("/sync?from=0&from=1")).toEqual({
      status: 400,
      body: { error: "bad_from" },
    });
  });
});

// ---------------------------------------------------------------------------
// (j) The proofs
// ---------------------------------------------------------------------------

describe("the inclusion proof beside every event", () => {
  it("recomputes against the root its seal committed to", async () => {
    const body = await sync("?from=0");
    const roots = new Map(body.seals.map((seal) => [seal.seq, seal.root]));
    expect(body.events.length).toBeGreaterThan(0);

    for (const item of body.events) {
      const root = roots.get(item.proof.seal_seq);
      expect([item.seq, root]).toEqual([item.seq, expect.any(String)]);
      const proof = decodeProof(item.proof.inclusion_proof);
      expect([item.seq, proof]).not.toEqual([item.seq, null]);
      expect([
        item.seq,
        await verifyInclusion(item.event.hash, proof!, root!),
      ]).toEqual([item.seq, true]);
    }
  }, 180_000);
});

// ---------------------------------------------------------------------------
// (k) and (l) A deployment with no key, and a method that is not GET
// ---------------------------------------------------------------------------

describe("the door itself", () => {
  it("refuses the sync rather than issuing an unsigned receipt", async () => {
    const bare: Env = { ...world.env };
    delete bare.SEALING_AGENT_KEY;

    const before = await nextReadCounter(world.store.db);
    expect(await read("/sync?from=0", NOW, bare)).toEqual({
      status: 503,
      body: { error: "receipts_not_configured" },
    });
    expect(await nextReadCounter(world.store.db)).toBe(before);
  });

  it("refuses a method that is not GET", async () => {
    const posted = await send(
      new Request(`${TEST_ORIGIN}/sync`, { method: "POST" }),
    );
    expect(posted.status).toBe(405);
    expect(posted.headers.get("allow")).toBe("GET");
    expect(await posted.json()).toEqual({ error: "method_not_allowed" });
  });
});

// ---------------------------------------------------------------------------
// (m) The day's published count
// ---------------------------------------------------------------------------

describe("the day's read count, with the syncs inside it", () => {
  let report: SweepReport;
  let published: Event<"read_count">;

  beforeAll(async () => {
    report = await sweep(day(1));
    const events = await eventsAfter(world.store.db, -1, LIST_PAGE_LIMIT * 2);
    published = events.find(
      (event) => event.type === "read_count",
    ) as Event<"read_count">;
  }, 180_000);

  it("publishes exactly the reads the syncs and the reads earned", () => {
    const expected = [...expectedReads().entries()]
      .map(([entry_id, count]) => ({ entry_id, count }))
      .sort((left, right) => left.entry_id.localeCompare(right.entry_id));
    const total = expected.reduce((sum, row) => sum + row.count, 0);

    expect(expected.length).toBeGreaterThan(0);
    expect(report.published).toEqual([
      { date: date(0), total, seq: published.seq },
    ]);

    const payload = published.payload as EventPayloads["read_count"];
    expect(payload.date).toBe(date(0));
    expect(payload.reads).toEqual(expected);
    expect(payload.total).toBe(total);
  });
});
