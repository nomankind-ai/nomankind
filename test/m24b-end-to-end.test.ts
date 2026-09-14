/**
 * M24b end to end: observed is still observed, and pays nothing.
 *
 * Decision D-127, "the record is free, no money anywhere": the read share, the
 * split and the contributor pool are gone, and with them the sentence this file
 * was written for. What survives is the half of D-087 that was never about
 * money — an entry verifies at the tier its evidence earned, a stated entry
 * stays stated whatever anyone brings to it later (D-035), and a validator that
 * reproduced earns standing where one that copied does not. So every amount
 * this file used to assert is asserted as absent instead.
 *
 * The original note follows, because it says what the world here is built to
 * exercise.
 *
 * Whitepaper Section 4, "Two tiers of evidence": "A submitter who can measure a
 * fact may submit it as observed, and is paid more for it." Section 9, "Money":
 * "observed entries take a larger read share than stated ones, by published
 * policy, so the operators who measure are paid more than the operators who
 * copy." M21's ledger paid one split to everyone; decision D-087 publishes the
 * split per evidence tier and pays a slot holder the observed validator rate
 * only when its own signed record carried a passing measurement.
 *
 * Three entries carry the whole rule, through the real doors on a real
 * miniflare D1, with real keys and real signatures, and only the network, the
 * beacon, the witnesses, the payment provider and the clock as fixtures:
 *
 *   - an observed entry every one of whose holders measured,
 *   - an observed entry whose oldest holder accepted the test and measured
 *     nothing,
 *   - a stated entry, which stays at the stated split whatever anyone brings to
 *     it later (D-035: the tier is the one verification fixed).
 *
 * Every amount asserted here comes back out of the ledger the sweep wrote, and
 * every one of them is recomputed a second time by the mirror's own fold over
 * the sealed events: two independent readings of one log, which is what
 * Section 9's "any operator can reconcile their payout against the log" means.
 */

import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { FixtureBeacon } from "../src/adapters/beacon.js";
import { MockPayoutAdapter } from "../src/adapters/payout.js";
import { receiptArtifactHash } from "../src/artifact.js";
import type { Core } from "../src/core.js";
import { base64urlEncode } from "../src/encoding.js";
import type { ApproverRecord, ReconfirmationRecord } from "../src/events.js";
import {
  agentIdFromPublicKey,
  exportPrivateKeyPkcs8,
  exportPublicKeyRaw,
  generateKeypair,
} from "../src/identity.js";
import { mintKey } from "../src/keys.js";
import type { LedgerRow } from "../src/ledger.js";
import { mirrorLedgerRows } from "../src/mirror.js";
import {
  DEFAULT_DOMAIN,
  LIST_PAGE_LIMIT,
  REPRODUCTION_HOLDS,
  REPRODUCTION_RUNS,
  STANDING_VALIDATION_REPRODUCED,
  STANDING_VALIDATION_VOLUNTEERED,
} from "../src/policy.js";
import { signRecord } from "../src/records.js";
import { txtRecordName } from "../src/registry.js";
import {
  entryLedgerRows,
  eventsAfter,
  latestSeal,
} from "../src/storage/repository.js";
import { putKey } from "../src/storage/keys.js";
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

/** Day 0: the instant every registration, submission and decision is at. */
const NOW = SUBMIT_NOW;
const AT = NOW.toISOString();

const DAY_MS = 86_400_000;
const HOUR_MS = 3_600_000;

/** The instant `days` days (and `hours` hours) after day 0. */
function day(days: number, hours = 0): Date {
  return new Date(NOW.getTime() + days * DAY_MS + hours * HOUR_MS);
}

/** The UTC day `days` days after day 0. */
function dayDate(days: number): string {
  return day(days).toISOString().slice(0, 10);
}

const VERIFIED_REFERENCE = "mock-verified-m24b";
const CATEGORY = "pricing";
const TEST_TEXT =
  "Buy one seat and read the invoice line; holds if it reads $40 per seat per month.";

/**
 * Pricing entries carry a ninety-day window, so the reconfirmations wait for
 * the entries to go stale: the door refuses to reconfirm a fresh entry, and a
 * stale day's reads are halved, so the second day of reads is the day after.
 */
const STALE_DAY = 91;
const RECONFIRM_DAY = 92;
const SECOND_DAY = 93;

/** Every read day is read this many times, which divides into whole micros. */
const READS = 3;

const PRICING: FixturePage = {
  body: "<!doctype html><html><body><main><h1>Kestrel pricing</h1><p>$40 per seat per month</p></main></body></html>",
  contentType: "text/html; charset=utf-8",
};
const PRICING_URL = "https://kestrel.example/pricing";

let PRICING_HASH = "";

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

/** The author, and seven trusted validators: eight, so the pool stays small. */
let k1: Party;
let k2: Party;
let k3: Party;
let k4: Party;
let k5: Party;
let k6: Party;
let k7: Party;
let k8: Party;
let parties: Party[] = [];

let sealingKey = "";
let readerSecret = "";

/** The observed entry every holder of which measured. */
let observedEntry: Core;
/** The observed entry whose oldest holder measured nothing. */
let mixedEntry: Core;
/** The stated entry. */
let statedEntry: Core;

/** Entry id -> the receipt hash its measurement was taken against. */
const receiptHashes = new Map<string, string>();

const payout = new MockPayoutAdapter();

function send(request: Request, now: Date = NOW): Promise<Response> {
  return handleRequest(request, world.env, { ...world.deps, now });
}

async function read(
  path: string,
  now: Date = NOW,
): Promise<{ status: number; body: Record<string, unknown> }> {
  const response = await send(
    new Request(`${TEST_ORIGIN}${path}`, {
      headers: path.startsWith("/read")
        ? { authorization: `Bearer ${readerSecret}` }
        : {},
    }),
    now,
  );
  return {
    status: response.status,
    body: (await response.json()) as Record<string, unknown>,
  };
}

async function post(
  agent: TestAgent,
  path: string,
  body: unknown,
  now: Date = NOW,
): Promise<{ status: number; body: Record<string, unknown> }> {
  const request = await signedPost(agent, {
    path,
    body,
    timestamp: now.toISOString(),
  });
  const response = await send(request, now);
  return {
    status: response.status,
    body: (await response.json()) as Record<string, unknown>,
  };
}

async function makeParty(operator: string): Promise<Party> {
  return { operator, agent: await makeAgent() };
}

async function register(party: Party): Promise<void> {
  const answer = await post(party.agent, "/operators", {
    operator: party.operator,
    attestation: await attestFor(party.agent, party.operator, AT),
    payout: { reference: VERIFIED_REFERENCE },
  });
  expect([answer.status, party.operator]).toEqual([201, party.operator]);
}

async function name(party: Party): Promise<void> {
  const answer = await post(world.maintainer, "/genesis", {
    operator: party.operator,
  });
  expect([answer.status, party.operator]).toEqual([200, party.operator]);
}

/** The eight-key receipt artifact one measured entry is taken against. */
function receiptFor(subject: string): Record<string, unknown> {
  return {
    method: "completed_request",
    subject,
    test: TEST_TEXT,
    request: { method: "GET", url: PRICING_URL, headers: {} },
    response: { status: 200, final_url: PRICING_URL, content_type: "text/html" },
    billing: null,
    observed_at: "2026-09-01",
    observer: "m24b fixture",
  };
}

/** One measurement, at the published n and the holds a test asks for. */
function measurement(
  entryId: string,
  holds: number,
): Record<string, unknown> {
  return {
    method: "completed_request",
    receipt_hash: receiptHashes.get(entryId) ?? "",
    observed_at: "2026-09-01",
    runs: REPRODUCTION_RUNS,
    holds,
  };
}

/** An observed submission, with the receipt its observation names. */
async function submitObserved(subject: string, author: Party): Promise<Core> {
  const receipt = receiptFor(subject);
  const hashed = await receiptArtifactHash(receipt);
  if (!hashed.ok) throw new Error("m24b: the fixture receipt is refused");
  const core = await submittedCore(author.agent, {
    author_operator: author.operator,
    subject,
    category: CATEGORY,
    domain: DEFAULT_DOMAIN,
    claim: `${subject} seat pricing is $40 per seat per month, measured`,
    before: "$35 per seat per month",
    after: `$40 per seat per month, measured for ${subject}`,
    effective_at: "2026-09-01",
    evidence_tier: "observed",
    observation: {
      method: "completed_request",
      test: TEST_TEXT,
      receipt_hash: hashed.hash,
      observed_at: "2026-09-01",
      notes: null,
    },
    citation: PRICING_URL,
    snapshot_hash: PRICING_HASH,
    supersedes: null,
  });
  const response = await send(await submission(author.agent, { core, receipt }));
  expect([response.status, subject]).toEqual([201, subject]);
  receiptHashes.set(core["id"] as string, hashed.hash);
  return core;
}

/** A stated submission of the same fact, resting on the cited page alone. */
async function submitStated(subject: string, author: Party): Promise<Core> {
  const core = await submittedCore(author.agent, {
    author_operator: author.operator,
    subject,
    category: CATEGORY,
    domain: DEFAULT_DOMAIN,
    claim: `${subject} seat pricing is $40 per seat per month`,
    before: "$35 per seat per month",
    after: `$40 per seat per month, stated for ${subject}`,
    effective_at: "2026-09-01",
    citation: PRICING_URL,
    snapshot_hash: PRICING_HASH,
    supersedes: null,
  });
  const response = await send(await submission(author.agent, { core }));
  expect([response.status, subject]).toEqual([201, subject]);
  return core;
}

/**
 * One approval, posted to the validate door.
 *
 * `holds` is null on a stated entry, which has no test to judge and no
 * measurement to carry; on an observed entry it is this validator's own n-of-k
 * count, at or below the published n.
 */
async function approve(
  entryId: string,
  party: Party,
  holds: number | null,
  now: Date = NOW,
): Promise<void> {
  const record = {
    agent: party.agent.agentId,
    operator: party.operator,
    decision: "approve",
    reason: null,
    snapshot_hash: PRICING_HASH,
    assigned_random: false,
    test_accepted: holds === null ? null : true,
    reproduction: null,
    observation: holds === null ? null : measurement(entryId, holds),
    signed_at: now.toISOString(),
  } as unknown as ApproverRecord;
  const signature = await signRecord(
    entryId,
    "validation",
    record,
    party.agent.privateKey,
  );
  const answer = await post(
    party.agent,
    `/entries/${entryId}/validate`,
    { record, signature },
    now,
  );
  expect([answer.status, answer.body["error"] ?? null]).toEqual([201, null]);
}

/** One reconfirmation, posted to the reconfirm door; the status it answered. */
async function reconfirm(
  entryId: string,
  party: Party,
  holds: number | null,
  now: Date,
): Promise<{ status: number; body: Record<string, unknown> }> {
  const record = {
    agent: party.agent.agentId,
    operator: party.operator,
    snapshot_hash: PRICING_HASH,
    reproduction: null,
    observation: holds === null ? null : measurement(entryId, holds),
    signed_at: now.toISOString(),
  } as unknown as ReconfirmationRecord;
  const signature = await signRecord(
    entryId,
    "reconfirmation",
    record,
    party.agent.privateKey,
  );
  return post(
    party.agent,
    `/entries/${entryId}/reconfirm`,
    { record, signature },
    now,
  );
}

/** One paid read through Section 8's door, `count` times. */
async function readEntry(entryId: string, count: number, now: Date): Promise<void> {
  for (let index = 0; index < count; index += 1) {
    const answer = await read(`/read/${entryId}`, now);
    expect([answer.status, entryId]).toEqual([200, entryId]);
  }
}

/** Run the sweep the alarm runs, with the fakes standing in for the world. */
async function sweep(at: Date): Promise<SweepReport> {
  const beacon = new FixtureBeacon("m24b");
  await beacon.advance(at.toISOString());
  return runSweep(world.env, {
    now: at,
    beacon,
    witness: new FakeWitnessAdapter(),
    pinned: pinnedSet([]),
    ineligibleAgents: new Set<string>(),
    anchor: new FakeAnchorAdapter(null),
    payout,
  });
}

/** The read-share rows of one entry on one day, in the order they were written. */
async function sharesOn(entryId: string, date: string): Promise<LedgerRow[]> {
  const rows = await entryLedgerRows(world.store.db, entryId, LIST_PAGE_LIMIT);
  return rows.filter((row) => row.kind === "read_share" && row.date === date);
}

/** One operator's standing, as the endpoint recomputes it from the log. */
async function standingOf(
  operator: string,
  now: Date = NOW,
): Promise<Record<string, unknown>> {
  const answer = await read(`/operators/${operator}/standing`, now);
  expect([answer.status, operator]).toEqual([200, operator]);
  return answer.body;
}

// ---------------------------------------------------------------------------
// The world, built once
// ---------------------------------------------------------------------------

beforeAll(async () => {
  PRICING_HASH = await pageHash(PRICING);

  const pair = await generateKeypair();
  sealingKey = base64urlEncode(await exportPrivateKeyPkcs8(pair.privateKey));
  agentIdFromPublicKey(await exportPublicKeyRaw(pair.publicKey));

  const store = await openTestDatabase();
  const maintainer = await makeAgent();

  // The reader whose reads this file prices: Section 9 pays out of paid-read
  // revenue, so every read here goes through a standard key.
  const minted = mintKey();
  readerSecret = minted.secret;
  await putKey(store.db, {
    id: minted.id,
    keyHash: await minted.hash,
    tier: "standard",
    status: "active",
    customer: "cus_m24b",
    subscription: "sub_m24b",
    checkoutSession: "cs_m24b",
    createdAt: AT,
  });

  k1 = await makeParty("k1.example");
  k2 = await makeParty("k2.example");
  k3 = await makeParty("k3.example");
  k4 = await makeParty("k4.example");
  k5 = await makeParty("k5.example");
  k6 = await makeParty("k6.example");
  k7 = await makeParty("k7.example");
  k8 = await makeParty("k8.example");
  parties = [k1, k2, k3, k4, k5, k6, k7, k8];
  const maintainerParty: Party = {
    operator: "maintainer.example",
    agent: maintainer,
  };

  const records: Record<string, string[]> = {};
  for (const party of [...parties, maintainerParty]) {
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
      payout,
      fetcher: new FixtureFetcher({ [PRICING_URL]: PRICING }),
    },
    maintainer,
  };

  for (const party of parties) {
    await register(party);
    await name(party);
  }
  await register(maintainerParty);

  // (1) Observed, and both holders measured. The small pool verifies on two
  // approvals and seats exactly those two.
  observedEntry = await submitObserved("example/kestrel-1", k1);
  await approve(observedEntry["id"] as string, k2, REPRODUCTION_HOLDS);
  await approve(observedEntry["id"] as string, k3, REPRODUCTION_RUNS);

  // (2) Observed, and the first holder accepted the test and measured nothing
  // that passed: its own count holds below k. The gate refuses to promote on
  // one passing measurement against one failing, so the entry waits for a
  // third approval and seats all three.
  mixedEntry = await submitObserved("example/kestrel-2", k1);
  await approve(mixedEntry["id"] as string, k5, REPRODUCTION_HOLDS - 1);
  await approve(mixedEntry["id"] as string, k6, REPRODUCTION_HOLDS);
  await approve(mixedEntry["id"] as string, k7, REPRODUCTION_RUNS);

  // (3) Stated: a document, and nobody measured anything.
  statedEntry = await submitStated("example/kestrel-3", k1);
  await approve(statedEntry["id"] as string, k2, null);
  await approve(statedEntry["id"] as string, k3, null);

  for (const core of [observedEntry, mixedEntry, statedEntry]) {
    await readEntry(core["id"] as string, READS, NOW);
  }

  // Two sweeps: the first seals day 0's events, the second prices what the
  // first sealed. Nothing is ever priced off an unsealed event.
  await sweep(day(1));
  await sweep(day(1, 1));
}, 600_000);

afterAll(async () => {
  await world?.store.dispose();
});

// ---------------------------------------------------------------------------
// (a) The tiers, as the doors and the derivation left them
// ---------------------------------------------------------------------------

describe("the three entries", () => {
  it("verify at the tier their evidence earned", async () => {
    const observed = await read(`/read/${observedEntry["id"] as string}`);
    const observedCore = observed.body["entry"] as Record<string, unknown>;
    expect([observedCore["status"], observedCore["evidence_tier"]]).toEqual([
      "verified",
      "observed",
    ]);
    const sidecar = observed.body["sidecar"] as Record<string, unknown>;
    expect(sidecar["effective_tier"]).toBe("observed");

    const mixed = await read(`/read/${mixedEntry["id"] as string}`);
    expect([
      (mixed.body["entry"] as Record<string, unknown>)["status"],
      (mixed.body["sidecar"] as Record<string, unknown>)["effective_tier"],
    ]).toEqual(["verified", "observed"]);

    const stated = await read(`/read/${statedEntry["id"] as string}`);
    expect([
      (stated.body["entry"] as Record<string, unknown>)["status"],
      (stated.body["sidecar"] as Record<string, unknown>)["effective_tier"],
    ]).toEqual(["verified", "stated"]);
  }, 600_000);
});

// ---------------------------------------------------------------------------
// (b) The rate rule, over one published day
// ---------------------------------------------------------------------------

describe("a day of reads over entries of both tiers", () => {
  it("pays nobody, at either tier", async () => {
    // The rule D-087 published was a rate, and there is no rate (D-127): the
    // observed entry, the mixed one and the stated one are all worth the same
    // nothing, and no row is written for any of them.
    for (const core of [observedEntry, mixedEntry, statedEntry]) {
      expect(await sharesOn(core["id"] as string, dayDate(0))).toEqual([]);
    }
  }, 600_000);

  it("agrees with the mirror's own recompute, which builds nothing either", async () => {
    const sealed = (await latestSeal(world.store.db))!;
    const events = await eventsAfter(world.store.db, -1, LIST_PAGE_LIMIT * 8);
    expect(
      mirrorLedgerRows(events, sealed.sealed_at).filter(
        (row) => row.kind === "read_share",
      ),
    ).toEqual([]);
  }, 600_000);
});

// ---------------------------------------------------------------------------
// (c) Reconfirmation: the slot moves, the tier does not (D-035)
// ---------------------------------------------------------------------------

describe("a reconfirmation of each entry", () => {
  it("seats the reconfirmer, and never moves what verification fixed", async () => {
    // Section 6 reconfirms a stale entry, and the door refuses a fresh one, so
    // the window has to close first: the sweep that notices it rewrites the
    // stored row, exactly as it does in production.
    const closed = await sweep(day(STALE_DAY));
    expect(closed.staled).toContain(observedEntry["id"] as string);
    const at = day(RECONFIRM_DAY);

    // An observed entry reopens its window on a fresh measurement, and this
    // one takes the slot the two approvals left empty.
    const filled = await reconfirm(
      observedEntry["id"] as string,
      k4,
      REPRODUCTION_RUNS,
      at,
    );
    expect([filled.status, filled.body["error"] ?? null]).toEqual([201, null]);

    // The mixed entry's oldest holder is the one that measured nothing, so the
    // rotation replaces exactly that holder.
    const rotated = await reconfirm(
      mixedEntry["id"] as string,
      k8,
      REPRODUCTION_RUNS,
      at,
    );
    expect([rotated.status, rotated.body["error"] ?? null]).toEqual([201, null]);

    // A stated entry's attestation is the fresh snapshot hash and nothing else:
    // the door refuses a measurement on it, which is why no later measurement
    // can move a stated entry onto the observed rate (D-035).
    const refused = await reconfirm(
      statedEntry["id"] as string,
      k4,
      REPRODUCTION_RUNS,
      at,
    );
    expect([refused.status, refused.body["error"]]).toEqual([
      422,
      "unexpected_observation",
    ]);
    const plain = await reconfirm(statedEntry["id"] as string, k4, null, at);
    expect([plain.status, plain.body["error"] ?? null]).toEqual([201, null]);

    for (const core of [observedEntry, mixedEntry, statedEntry]) {
      await readEntry(core["id"] as string, READS, day(SECOND_DAY, 1));
    }
    await sweep(day(SECOND_DAY + 1));
    await sweep(day(SECOND_DAY + 1, 1));
  }, 600_000);

  it("pays nothing for any of the three, before or after", async () => {
    for (const core of [observedEntry, mixedEntry, statedEntry]) {
      const id = core["id"] as string;
      expect(await sharesOn(id, dayDate(0))).toEqual([]);
      expect(await sharesOn(id, dayDate(SECOND_DAY))).toEqual([]);
    }
  }, 600_000);

  it("keeps the tier verification fixed, whatever the reconfirmation brought", async () => {
    // D-035, which is a fact about evidence rather than about money: a stated
    // entry stays stated, and an observed one stays observed.
    const mixed = await read(
      `/read/${mixedEntry["id"] as string}`,
      day(SECOND_DAY, 2),
    );
    expect(
      (mixed.body["sidecar"] as Record<string, unknown>)["effective_tier"],
    ).toBe("observed");
    const stated = await read(
      `/read/${statedEntry["id"] as string}`,
      day(SECOND_DAY, 2),
    );
    expect(
      (stated.body["sidecar"] as Record<string, unknown>)["effective_tier"],
    ).toBe("stated");
  }, 600_000);
});

// ---------------------------------------------------------------------------
// (d) The standing side of the same rule
// ---------------------------------------------------------------------------

describe("standing", () => {
  it("rises for a validator that reproduced, and not for one that did not", async () => {
    const at = day(SECOND_DAY + 1, 2);
    // Both validated exactly once, on the same entry, at the same position in
    // the pool: the only difference between them is the measurement.
    const measured = await standingOf(k6.operator, at);
    const copied = await standingOf(k5.operator, at);

    expect(measured["earned"]).toBe(
      STANDING_VALIDATION_VOLUNTEERED + STANDING_VALIDATION_REPRODUCED,
    );
    expect(
      (measured["counts"] as Record<string, number>)["validations_reproduced"],
    ).toBe(1);

    expect(copied["earned"]).toBe(STANDING_VALIDATION_VOLUNTEERED);
    expect(
      (copied["counts"] as Record<string, number>)["validations_reproduced"],
    ).toBe(0);
    expect(measured["standing"]).toBeGreaterThan(copied["standing"] as number);

    // A reconfirmation that measured earns it too; one that could not — the
    // stated entry's — does not.
    const reconfirmer = await standingOf(k8.operator, at);
    expect(
      (reconfirmer["counts"] as Record<string, number>)["validations_reproduced"],
    ).toBe(1);
  }, 600_000);
});
