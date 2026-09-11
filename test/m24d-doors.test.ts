/**
 * M24d: the release window at the API doors (decisions D-100, D-101).
 *
 * One rule, and this file is where it is made falsifiable at every door a
 * reader can knock on: an event's content opens RELEASE_WINDOW_DAYS after the
 * seal that covers it, an entry's window is its `entry_submitted` event's, an
 * entry nothing has sealed is not released at all, and the proof is public from
 * the first minute whoever is asking.
 *
 * So the world below holds three kinds of record at once — an entry sealed on
 * day 0, an entry submitted after that seal and never sealed, and a paid key —
 * and every test reads them at an instant the injected clock names: day 0,
 * inside the window, and day 31, after it. Nothing waits for a wall clock and
 * nothing is mocked but the network: the database is miniflare's D1 with every
 * migration applied, every key is generated through WebCrypto, every signature
 * is made by it, and the receipts are verified against the key inside their own
 * issuer id.
 *
 * What each door owes the window:
 *
 *   GET /read/{id}          402 `unreleased` to a free reader, with the date;
 *                           served to a key, to a signed operator, and to
 *                           anybody once the window has passed
 *   GET /sync               a free page stops at the released head and its
 *                           receipt names that boundary; `sealed_head` still
 *                           reports the true head; a keyed page reaches it
 *   GET /entries/{id}       `{ proof, release_date }` to a free reader and the
 *                           entry itself to a signed one
 *   GET /events             unreleased events as hash lines to a free reader
 *   GET /captures/{hash}    403 `unreleased` to a free reader, served to a key
 *                           or a signed operator
 *   GET /events/{seq}/proof proof, and served as it always was
 *   GET /entries/{id}/confidence-inputs   proof, and served as it always was
 *
 * And the two commands the window changed: `npm run export`, whose two views a
 * credential chooses between, and `npm run validate`, which reads the draft it
 * is judging through the signature it already holds.
 */

import { mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { FixtureBeacon } from "../src/adapters/beacon.js";
import { MockPayoutAdapter } from "../src/adapters/payout.js";
import { buildExport, exportPlan, exportClient } from "../src/cli/export.js";
import { runValidator } from "../src/cli/validator.js";
import type { Core } from "../src/core.js";
import { base64urlEncode } from "../src/encoding.js";
import type { ApproverRecord, Event } from "../src/events.js";
import {
  agentIdFromPublicKey,
  exportPrivateKeyPkcs8,
  exportPublicKeyRaw,
  generateKeypair,
} from "../src/identity.js";
import { entryHash } from "../src/hash.js";
import { mintKey } from "../src/keys.js";
import {
  DEFAULT_DOMAIN,
  LIST_PAGE_LIMIT,
  RELEASE_WINDOW_DAYS,
} from "../src/policy.js";
import { verifyReadReceipt, verifySyncReceipt } from "../src/receipt.js";
import { signRecord } from "../src/records.js";
import { isWithheld, releaseDateOf } from "../src/release.js";
import { txtRecordName } from "../src/registry.js";
import { putKey } from "../src/storage/keys.js";
import { latestSeal, readCountsOn } from "../src/storage/repository.js";
import { buildSubmittedCore, type SubmissionProposal } from "../src/submit.js";
import type { Env } from "../src/worker/env.js";
import { handleRequest, type RequestDeps } from "../src/worker/index.js";
import { runSweep } from "../src/worker/sweep.js";
import { openTestDatabase, type TestDatabase } from "./helpers/d1.js";
import {
  FixtureResolver,
  TEST_ORIGIN,
  attestFor,
  makeAgent,
  signedGet,
  signedPost,
  signingHttp,
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

/** Day 0: the instant the world below is built at. */
const NOW = SUBMIT_NOW;
const AT = NOW.toISOString();

/** A unit constant: the fake clock moves in whole days. */
const DAY_MS = 86_400_000;

function day(days: number): Date {
  return new Date(NOW.getTime() + days * DAY_MS);
}

/** Day 21: the second seal, whose own window has not run on day 31. */
const LATER = day(RELEASE_WINDOW_DAYS - 9);

/** After the window on day 0's seal, whatever the published number is. */
const AFTER_WINDOW = day(RELEASE_WINDOW_DAYS + 1);

const VERIFIED_REFERENCE = "mock-verified-m24d";

const SUBJECT = "example/kestrel-w";
const CATEGORY = "pricing";

const PRICING: FixturePage = {
  body: "<!doctype html><html><body><main><h1>Kestrel-W pricing</h1><p>$40 per seat per month</p></main></body></html>",
  contentType: "text/html; charset=utf-8",
};
const PRICING_URL = "https://kestrel-w.example/pricing";
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
let author: TestAgent;
let k1: Party;
let k2: Party;
let k3: Party;

/** The entry sealed on day 0: released after the window, and not before it. */
let sealedEntry: Core;
/** Sealed on day 21, so it is still withheld on the day day 0's seal opens. */
let laterEntry: Core;
/** Submitted after that seal and never sealed: never released (isReleased(null)). */
let unsealedEntry: Core;
/** A draft the validate command judges, under day 0's seal like the first. */
let draftEntry: Core;

/** A paid key, active, stored the way GET /keys/claim stores one. */
let keySecret = "";

/** The seal covering day 0, and the instant its content opens. */
let sealedAt = "";
let releaseDate = "";
/** The first seal's last position: the released head on the day it opens. */
let releasedHeadSeq = 0;
/** The second seal's, which is the true sealed head from day 21 onward. */
let sealedHeadSeq = 0;

/** The reads one UTC day has been charged, as the published count adds them. */
async function readsOn(at: Date): Promise<number> {
  const rows = await readCountsOn(
    store.db,
    at.toISOString().slice(0, 10),
    undefined,
    LIST_PAGE_LIMIT,
  );
  return rows.reduce((total, row) => total + row.count, 0);
}

function send(request: Request, now: Date = NOW): Promise<Response> {
  return handleRequest(request, env, { ...deps, now });
}

/** One free GET: no key, no signature, which is most of the world. */
async function free(
  path: string,
  now: Date = NOW,
): Promise<{ status: number; body: Record<string, unknown> }> {
  const response = await send(new Request(`${TEST_ORIGIN}${path}`), now);
  return {
    status: response.status,
    body: (await response.json()) as Record<string, unknown>,
  };
}

/** One GET on the paid key's tier. */
async function keyed(
  path: string,
  now: Date = NOW,
  secret: string = keySecret,
): Promise<{ status: number; body: Record<string, unknown> }> {
  const response = await send(
    new Request(`${TEST_ORIGIN}${path}`, {
      headers: { authorization: `Bearer ${secret}` },
    }),
    now,
  );
  return {
    status: response.status,
    body: (await response.json()) as Record<string, unknown>,
  };
}

/** One GET signed by an agent bound to a registered operator. */
async function signed(
  path: string,
  now: Date = NOW,
  agent: TestAgent = k1.agent,
): Promise<{ status: number; body: Record<string, unknown> }> {
  const response = await send(
    await signedGet(agent, { path, timestamp: now.toISOString() }),
    now,
  );
  return {
    status: response.status,
    body: (await response.json()) as Record<string, unknown>,
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

function pricing(claim: string): Omit<SubmissionProposal, "author"> {
  return {
    subject: SUBJECT,
    category: CATEGORY,
    domain: DEFAULT_DOMAIN,
    claim,
    before: "$35 per seat per month",
    // The duplicate key (D-085): one live entry per subject and category may
    // assert one value, and none of these tests is about duplicates.
    after: `$40 per seat per month, per: ${claim}`,
    effective_at: "2026-09-01",
    citation: PRICING_URL,
    snapshot_hash: PRICING_HASH,
  };
}

async function submit(claim: string, at: Date = NOW): Promise<Core> {
  // The core's `submitted_at` is the instant it is actually submitted at: the
  // door refuses one that is far from its own clock, and the entries below are
  // written three weeks apart on purpose.
  const core =
    at.getTime() === NOW.getTime()
      ? await submittedCore(author, pricing(claim))
      : await buildSubmittedCore(
          { ...pricing(claim), author: author.agentId },
          { now: at.toISOString() },
        );
  const response = await send(
    await submission(author, { core, timestamp: at.toISOString() }),
    at,
  );
  expect([response.status, claim]).toEqual([201, claim]);
  return core;
}

async function approve(entryId: string, party: Party, at: Date = NOW): Promise<void> {
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
    signed_at: at.toISOString(),
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
      timestamp: at.toISOString(),
    }),
    at,
  );
  expect([response.status, entryId]).toEqual([201, entryId]);
}

async function sweep(at: Date): Promise<void> {
  const beacon = new FixtureBeacon("m24d");
  await beacon.advance(at.toISOString());
  await runSweep(env, {
    now: at,
    beacon,
    witness: new FakeWitnessAdapter(),
    pinned: pinnedSet([]),
    ineligibleAgents: new Set<string>(),
    anchor: new FakeAnchorAdapter(null),
    payout: new MockPayoutAdapter(),
  });
}

beforeAll(async () => {
  PRICING_HASH = await pageHash(PRICING);

  const pair = await generateKeypair();
  const sealingKey = base64urlEncode(
    await exportPrivateKeyPkcs8(pair.privateKey),
  );
  agentIdFromPublicKey(await exportPublicKeyRaw(pair.publicKey));

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

  const minted = mintKey();
  keySecret = minted.secret;
  await putKey(store.db, {
    id: minted.id,
    keyHash: await minted.hash,
    tier: "standard",
    status: "active",
    customer: "cus_m24d",
    subscription: "sub_m24d",
    checkoutSession: "cs_m24d",
    createdAt: AT,
  });

  for (const party of [k1, k2, k3]) {
    await register(party);
    await name(party);
  }

  sealedEntry = await submit("Kestrel-W seat pricing is $40 per seat per month");
  await approve(sealedEntry["id"] as string, k1);
  await approve(sealedEntry["id"] as string, k2);
  draftEntry = await submit(
    "Kestrel-W seat pricing is published at $40 per seat per month",
  );

  // Everything above is sealed on day 0, so its window runs from here.
  await sweep(NOW);
  const first = await latestSeal(store.db);
  expect(first).not.toBeNull();
  sealedAt = first!.sealed_at;
  releaseDate = releaseDateOf(sealedAt);
  releasedHeadSeq = first!.last_seq;

  // A second seal three weeks later, whose own window has not run when the
  // first one's has: this is the gap a free reader is served to and a paying
  // one is served past.
  laterEntry = await submit(
    "Kestrel-W seat pricing is listed at $40 per seat per month",
    LATER,
  );
  await approve(laterEntry["id"] as string, k1, LATER);
  await approve(laterEntry["id"] as string, k2, LATER);
  await sweep(LATER);
  const second = await latestSeal(store.db);
  sealedHeadSeq = second!.last_seq;
  expect(sealedHeadSeq).toBeGreaterThan(releasedHeadSeq);

  // And one last entry after that seal, sealed by nothing at all, which is the
  // other half of the rule: an unsealed event is not released.
  unsealedEntry = await submit(
    "Kestrel-W seat pricing stands at $40 per seat per month",
    LATER,
  );
  await approve(unsealedEntry["id"] as string, k1, LATER);
  await approve(unsealedEntry["id"] as string, k2, LATER);
}, 300_000);

afterAll(async () => {
  await store?.dispose();
});

// ---------------------------------------------------------------------------
// The rule itself
// ---------------------------------------------------------------------------

describe("the window, as the doors compute it", () => {
  it("opens a sealed entry the window after its seal, and never before", () => {
    expect(Date.parse(releaseDate) - Date.parse(sealedAt)).toBe(
      RELEASE_WINDOW_DAYS * DAY_MS,
    );
    expect(Date.parse(releaseDate)).toBeGreaterThan(NOW.getTime());
    expect(Date.parse(releaseDate)).toBeLessThan(AFTER_WINDOW.getTime());
  });
});

// ---------------------------------------------------------------------------
// GET /read/{id}
// ---------------------------------------------------------------------------

describe("the read door", () => {
  it("refuses a free read of an unreleased entry, and names the day", async () => {
    const answer = await free(`/read/${sealedEntry["id"] as string}`);
    expect([answer.status, answer.body]).toEqual([
      402,
      { error: "unreleased", release_date: releaseDate },
    ]);
  });

  it("names no day for an entry nothing has sealed yet", async () => {
    // `isReleased(null)` is false: the window has not started rather than
    // passed, and there is no date to promise.
    const answer = await free(
      `/read/${unsealedEntry["id"] as string}`,
      AFTER_WINDOW,
    );
    expect([answer.status, answer.body]).toEqual([
      402,
      { error: "unreleased", release_date: null },
    ]);
  });

  it("serves it to everybody once the window has passed, and counts it", async () => {
    const before = await readsOn(AFTER_WINDOW);
    const answer = await free(
      `/read/${sealedEntry["id"] as string}`,
      AFTER_WINDOW,
    );
    expect(answer.status).toBe(200);
    expect((answer.body["entry"] as Record<string, unknown>)["id"]).toBe(
      sealedEntry["id"],
    );

    // Counted and unpaid, exactly as a free read has always been: the receipt
    // carries null key fields and the day's count moved by one.
    const receipt = answer.body["receipt"] as Record<string, unknown>;
    expect([receipt["key"], receipt["key_counter"]]).toEqual([null, null]);
    await expect(verifyReadReceipt(receipt)).resolves.toBe(true);
    expect(await readsOn(AFTER_WINDOW)).toBe(before + 1);
  });

  it("serves a keyed read inside the window, and bills it as today", async () => {
    const answer = await keyed(`/read/${sealedEntry["id"] as string}`);
    expect(answer.status).toBe(200);
    const receipt = answer.body["receipt"] as Record<string, unknown>;
    expect(receipt["entry_id"]).toBe(sealedEntry["id"]);
    // A paid read: the key is named in the receipt and the key's own counter
    // runs beside the log-wide one.
    expect(receipt["key"]).not.toBeNull();
    expect(typeof receipt["key_counter"]).toBe("number");
    await expect(verifyReadReceipt(receipt)).resolves.toBe(true);
  });

  it("serves a signed operator read inside the window, with a receipt", async () => {
    const answer = await signed(
      `/read/${unsealedEntry["id"] as string}`,
      AFTER_WINDOW,
    );
    expect(answer.status).toBe(200);
    const receipt = answer.body["receipt"] as Record<string, unknown>;
    expect([receipt["entry_id"], receipt["key"]]).toEqual([
      unsealedEntry["id"],
      null,
    ]);
    await expect(verifyReadReceipt(receipt)).resolves.toBe(true);
  });

  it("refuses a bad key rather than downgrading it to a free read", async () => {
    const answer = await keyed(
      `/read/${sealedEntry["id"] as string}`,
      NOW,
      "not-a-key",
    );
    expect([answer.status, answer.body["error"]]).toEqual([401, "bad_key"]);
  });

  it("refuses a signature that does not verify, on the same rule", async () => {
    const request = await signedGet(k1.agent, {
      path: `/read/${sealedEntry["id"] as string}`,
      timestamp: AT,
    });
    const headers = new Headers(request.headers);
    headers.set("x-nomankind-signature", base64urlEncode(new Uint8Array(64)));
    const response = await send(
      new Request(request.url, { headers }),
      NOW,
    );
    expect([response.status, await response.json()]).toEqual([
      401,
      { error: "bad_signature" },
    ]);
  });

  it("answers the query form the same way", async () => {
    const query = `subject=${encodeURIComponent(SUBJECT)}&category=${CATEGORY}`;
    const refused = await free(`/read?${query}`);
    expect([refused.status, refused.body["error"]]).toEqual([402, "unreleased"]);
    const served = await signed(`/read?${query}`);
    expect(served.status).toBe(200);
  });
});

// ---------------------------------------------------------------------------
// GET /entries/{id}
// ---------------------------------------------------------------------------

describe("the entry door", () => {
  it("answers a free reader with the proof and the date, and no entry", async () => {
    const answer = await free(`/entries/${sealedEntry["id"] as string}`);
    expect(answer.status).toBe(200);
    expect(Object.keys(answer.body).sort()).toEqual([
      "entry_hash",
      "proof",
      "release_date",
      "sidecar",
    ]);
    expect(answer.body["release_date"]).toBe(releaseDate);
    expect(answer.body["entry"]).toBeUndefined();

    // The hash is the proof that makes the rest of the proof usable: it is
    // taken over the whole core, so it is the hash of the entry the door will
    // serve on release, and a keyless reader who has never been shown the
    // content can still say which record they are looking at. Pinned against
    // the released entry's own hash rather than against itself.
    expect(answer.body["entry_hash"]).toBe(await entryHash(sealedEntry));

    // The proof is all there and the content is not.
    const proof = answer.body["proof"] as Record<string, unknown>;
    expect(proof["id"]).toBe(sealedEntry["id"]);
    expect(proof["status"]).toBe("verified");
    expect(typeof proof["signature"]).toBe("string");
    expect(typeof proof["subject"]).toBe("string");
    expect(proof["seal"]).not.toBeNull();
    expect([proof["claim"], proof["before"], proof["after"]]).toEqual([
      null,
      null,
      null,
    ]);
    for (const approver of proof["approvers"] as Record<string, unknown>[]) {
      expect(approver["reason"]).toBeNull();
      // Everything else the record carries is proof, and it stays.
      expect(approver["agent"]).toBeDefined();
      expect(approver["operator"]).toBeDefined();
      expect(approver["signed_at"]).toBeDefined();
      expect(approver["snapshot_hash"]).toBe(PRICING_HASH);
    }
  });

  it("answers a signed reader with the entry itself", async () => {
    const answer = await signed(`/entries/${sealedEntry["id"] as string}`);
    expect(answer.status).toBe(200);
    expect(answer.body["id"]).toBe(sealedEntry["id"]);
    expect(answer.body["claim"]).toBe(sealedEntry["claim"]);
    expect([answer.body["proof"], answer.body["release_date"]]).toEqual([
      undefined,
      undefined,
    ]);
  });

  it("answers a keyed reader with the entry itself", async () => {
    const answer = await keyed(`/entries/${sealedEntry["id"] as string}`);
    expect([answer.status, answer.body["claim"]]).toEqual([
      200,
      sealedEntry["claim"],
    ]);
  });

  it("answers everybody with the entry once the window has passed", async () => {
    const answer = await free(
      `/entries/${sealedEntry["id"] as string}`,
      AFTER_WINDOW,
    );
    expect([answer.status, answer.body["claim"]]).toEqual([
      200,
      sealedEntry["claim"],
    ]);
  });
});

// ---------------------------------------------------------------------------
// GET /events, and the proof beside it
// ---------------------------------------------------------------------------

describe("the log's own page", () => {
  it("serves unreleased events to a free reader as hash lines", async () => {
    const answer = await free("/events?limit=100");
    expect(answer.status).toBe(200);
    const events = answer.body["events"] as Record<string, unknown>[];
    expect(events.length).toBeGreaterThan(0);
    // Every one of them is withheld today: the seal is an hour old.
    expect(events.every((event) => isWithheld(event))).toBe(true);
    for (const event of events) {
      expect(event["payload"]).toBeNull();
      // The proof stays whole: the position, the instant, the type, the entry
      // and both links.
      expect(typeof event["hash"]).toBe("string");
      expect(typeof event["at"]).toBe("string");
      expect(typeof event["type"]).toBe("string");
      expect("prev_hash" in event).toBe(true);
    }
    // The head is the true head whoever is asking.
    expect(typeof answer.body["head"]).toBe("number");
  });

  it("serves the whole event to a key and to a signed operator", async () => {
    for (const answer of [
      await keyed("/events?limit=100"),
      await signed("/events?limit=100"),
    ]) {
      const events = answer.body["events"] as Record<string, unknown>[];
      expect(answer.status).toBe(200);
      expect(events.some((event) => event["payload"] !== null)).toBe(true);
      expect(events.every((event) => !isWithheld(event))).toBe(true);
    }
  });

  it("serves the whole event to everybody once the window has passed", async () => {
    const answer = await free("/events?limit=100", AFTER_WINDOW);
    const events = answer.body["events"] as Event[];
    // Day 0's events have opened; the ones written after that seal are still
    // sealed by nothing at all, so they stay hash lines.
    expect(events.some((event) => event.payload !== null)).toBe(true);
    const sealedSeqs = events.filter((event) => event.payload !== null);
    expect(sealedSeqs[0]!.seq).toBe(0);
  });

  it("refuses a bad key rather than serving hash lines", async () => {
    const answer = await keyed("/events", NOW, "not-a-key");
    expect([answer.status, answer.body["error"]]).toEqual([401, "bad_key"]);
  });

  it("serves an unreleased event's inclusion proof, because a proof is public", async () => {
    const answer = await free("/events/0/proof");
    expect(answer.status).toBe(200);
    expect(typeof answer.body["inclusion_proof"]).toBe("string");
  });
});

// ---------------------------------------------------------------------------
// GET /sync
// ---------------------------------------------------------------------------

describe("the delta stream", () => {
  it("answers a free trainer an empty page while nothing has released", async () => {
    const answer = await free("/sync?from=0");
    expect(answer.status).toBe(200);
    expect([answer.body["head"], answer.body["receipt"]]).toEqual([null, null]);
    expect(answer.body["events"]).toEqual([]);
    // The true head is still reported, so a reader sees the gap.
    expect(answer.body["sealed_head"]).not.toBeNull();
  });

  it("stops a free page at the released head, and the receipt names it", async () => {
    const answer = await free(`/sync?from=0&limit=${LIST_PAGE_LIMIT}`, AFTER_WINDOW);
    expect(answer.status).toBe(200);

    // Day 0's seal has opened and day 21's has not, so the page stops at the
    // first seal's last position — and says so twice, in the head and in the
    // receipt the trainer resumes from.
    expect(answer.body["head"]).toBe(releasedHeadSeq);
    const receipt = answer.body["receipt"] as Record<string, unknown>;
    expect([receipt["head"], receipt["from"]]).toEqual([releasedHeadSeq, 0]);
    await expect(verifySyncReceipt(receipt)).resolves.toBe(true);

    // And the true sealed head is still reported, so the trainer can see
    // exactly how far ahead the log is of what it was handed.
    expect(answer.body["sealed_head"]).toBe(sealedHeadSeq);
    expect(sealedHeadSeq).toBeGreaterThan(releasedHeadSeq);

    // Nothing past the boundary is in the page.
    const items = answer.body["events"] as { seq: number }[];
    expect(items.every((item) => item.seq <= releasedHeadSeq)).toBe(true);
  });

  it("serves a keyed trainer to the sealed head, past the boundary", async () => {
    const answer = await keyed(
      `/sync?from=0&limit=${LIST_PAGE_LIMIT}`,
      AFTER_WINDOW,
    );
    expect(answer.status).toBe(200);
    expect([answer.body["head"], answer.body["sealed_head"]]).toEqual([
      sealedHeadSeq,
      sealedHeadSeq,
    ]);
    const receipt = answer.body["receipt"] as Record<string, unknown>;
    expect(receipt["head"]).toBe(sealedHeadSeq);
    expect(receipt["key"]).not.toBeNull();
    await expect(verifySyncReceipt(receipt)).resolves.toBe(true);
    // The entries a trainer was handed are the entries themselves.
    const items = answer.body["events"] as Record<string, unknown>[];
    expect(items.some((item) => item["entry"] !== null)).toBe(true);
  });

  it("serves a signed operator to the sealed head as well", async () => {
    const answer = await signed(
      `/sync?from=0&limit=${LIST_PAGE_LIMIT}`,
      AFTER_WINDOW,
    );
    expect([answer.status, answer.body["head"]]).toEqual([200, sealedHeadSeq]);
  });

  it("answers an empty page with no receipt when the range has not opened", async () => {
    // Strictly inside the unreleased seal: nothing in the range has opened, so
    // the page is the empty one a trainer past the sealed head is handed.
    const answer = await free(
      `/sync?from=${releasedHeadSeq + 1}`,
      AFTER_WINDOW,
    );
    expect([answer.status, answer.body["head"], answer.body["receipt"]]).toEqual([
      200,
      null,
      null,
    ]);
    expect(answer.body["events"]).toEqual([]);
    expect(answer.body["sealed_head"]).toBe(sealedHeadSeq);
  });
});

// ---------------------------------------------------------------------------
// GET /captures/{hash}
// ---------------------------------------------------------------------------

describe("the captures door", () => {
  async function capture(
    path: string,
    request: "free" | "key" | "sign",
    now: Date = NOW,
  ): Promise<Response> {
    if (request === "free") return send(new Request(`${TEST_ORIGIN}${path}`), now);
    if (request === "key") {
      return send(
        new Request(`${TEST_ORIGIN}${path}`, {
          headers: { authorization: `Bearer ${keySecret}` },
        }),
        now,
      );
    }
    return send(
      await signedGet(k1.agent, { path, timestamp: now.toISOString() }),
      now,
    );
  }

  it("refuses a free read of an unreleased entry's evidence, with the day", async () => {
    const response = await capture(`/captures/${PRICING_HASH}`, "free");
    expect([response.status, await response.json()]).toEqual([
      403,
      { error: "unreleased", release_date: releaseDate },
    ]);

    // The sidecar waits with the bytes: when a page was fetched is a fact
    // about the page.
    const sidecar = await capture(`/captures/${PRICING_HASH}/sidecar`, "free");
    expect(sidecar.status).toBe(403);
  });

  it("serves the bytes to a key and to a signed operator", async () => {
    for (const who of ["key", "sign"] as const) {
      const response = await capture(`/captures/${PRICING_HASH}`, who);
      expect([who, response.status]).toEqual([who, 200]);
      expect(await response.text()).toContain("Kestrel-W pricing");
    }
  });

  it("serves them to everybody once one of its entries has released", async () => {
    const response = await capture(
      `/captures/${PRICING_HASH}`,
      "free",
      AFTER_WINDOW,
    );
    expect(response.status).toBe(200);
  });
});

// ---------------------------------------------------------------------------
// The proof doors the window does not touch
// ---------------------------------------------------------------------------

describe("the confidence field's raw inputs", () => {
  it("serve for an unreleased entry, because every input is proof", async () => {
    const answer = await free(
      `/entries/${sealedEntry["id"] as string}/confidence-inputs`,
    );
    expect([answer.status, answer.body["confidence"]]).toEqual([200, null]);
    expect(answer.body["formula"]).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// The commands
// ---------------------------------------------------------------------------

describe("the export command", () => {
  it("exports the released view without a credential, and says so", async () => {
    const io = { out: [] as string[], err: [] as string[] };
    const result = await buildExport({
      baseUrl: TEST_ORIGIN,
      entryId: sealedEntry["id"] as string,
      http: { fetch: (request: Request) => send(request) },
      now: NOW,
    });
    expect(result.release_date).toBe(releaseDate);
    const entry = result.entry as Record<string, unknown>;
    expect([entry["id"], entry["claim"]]).toEqual([sealedEntry["id"], null]);
    // The proof is whole: the log is there, hash line by hash line, and the
    // seals are there to check them against.
    expect(result.bundle.events.every((event) => isWithheld(event))).toBe(true);
    expect(result.bundle.seals.length).toBeGreaterThan(0);
    expect(io.err).toEqual([]);
  });

  it("exports the whole entry with --sign", async () => {
    const directory = await mkdtemp(join(tmpdir(), "nomankind-m24d-"));
    const keyPath = join(directory, "key.json");
    await writeFile(
      keyPath,
      JSON.stringify({
        agent_id: k1.agent.agentId,
        private_key_pkcs8: base64urlEncode(
          await exportPrivateKeyPkcs8(k1.agent.privateKey),
        ),
      }),
      "utf8",
    );

    const plan = exportPlan([
      TEST_ORIGIN,
      sealedEntry["id"] as string,
      directory,
      "--sign",
      keyPath,
    ]);
    expect(plan).not.toBeNull();
    const http = await exportClient(
      { fetch: (request: Request) => send(request) },
      plan!,
      NOW,
    );

    const result = await buildExport({
      baseUrl: plan!.baseUrl,
      entryId: plan!.entryId,
      http,
      now: NOW,
    });
    expect(result.release_date).toBeUndefined();
    const entry = result.entry as Record<string, unknown>;
    expect(entry["claim"]).toBe(sealedEntry["claim"]);
    expect(result.bundle.events.some((event) => event.payload !== null)).toBe(
      true,
    );
  });

  it("reads a key and a signing file as alternatives, never as a pair", () => {
    expect(
      exportPlan([TEST_ORIGIN, "nmk_x", "out", "--key", "k", "--sign", "f"]),
    ).toBeNull();
    expect(exportPlan([TEST_ORIGIN, "nmk_x", "out", "--nope", "f"])).toBeNull();
    expect(exportPlan([TEST_ORIGIN, "nmk_x", "out"])?.key).toBeNull();
  });
});

describe("the validate command", () => {
  it("verifies an unreleased draft through its own signed read", async () => {
    const lines: string[] = [];
    const io = {
      stdout: (line: string) => lines.push(line),
      stderr: (line: string) => lines.push(line),
    };
    const run = await runValidator({
      baseUrl: TEST_ORIGIN,
      entryId: draftEntry["id"] as string,
      deps: {
        http: { fetch: (request: Request) => send(request) },
        fetcher: new FixtureFetcher(PAGES),
        now: NOW,
        key: { agentId: k1.agent.agentId, privateKey: k1.agent.privateKey },
      },
      io,
    });
    expect([run.ok, run.decision, run.error]).toEqual([true, "approve", null]);
  });

  it("is refused when the reader behind it is nobody the registry knows", async () => {
    const stranger = await makeAgent();
    const lines: string[] = [];
    const run = await runValidator({
      baseUrl: TEST_ORIGIN,
      entryId: draftEntry["id"] as string,
      deps: {
        http: { fetch: (request: Request) => send(request) },
        fetcher: new FixtureFetcher(PAGES),
        now: NOW,
        key: { agentId: stranger.agentId, privateKey: stranger.privateKey },
      },
      io: {
        stdout: (line: string) => lines.push(line),
        stderr: (line: string) => lines.push(line),
      },
    });
    // The signature verifies and the agent is nobody's, so the read is free and
    // the entry comes back withheld: the command stops rather than judging a
    // document it cannot see.
    expect(run.ok).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// Signing the same reads through the shared client
// ---------------------------------------------------------------------------

describe("a signed client, as --sign builds one", () => {
  it("signs every read it makes and passes writes through untouched", async () => {
    const client = signingHttp((request) => send(request), k1.agent, NOW);
    const response = await client.fetch(
      new Request(`${TEST_ORIGIN}/entries/${sealedEntry["id"] as string}`),
    );
    const body = (await response.json()) as Record<string, unknown>;
    expect([response.status, body["claim"]]).toEqual([200, sealedEntry["claim"]]);
  });
});
