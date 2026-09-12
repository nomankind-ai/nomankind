/**
 * M21 end to end: standing and the ledger, through the Worker and the sweep.
 *
 * Whitepaper Section 9, "Standing": "It is derived from the sealed public events
 * by a published formula, so anyone can recompute anyone's standing from the log
 * and get the same number ... It gates everything discretionary, from entry to
 * and stay in the trusted pool." And "Money": "Thirty percent of paid-read
 * revenue goes to the contributor pool at launch, fifteen to the submitter and
 * five to each validator, paid to their operators ... Accrued fees are held for
 * thirty days before payout so an upheld dispute can claw them back before they
 * leave ... A dispute upheld later claws back nothing and burns standing only."
 * Section 7: "Stale entries earn half rate, and the withheld half builds up on
 * the entry as a reconfirmation bounty, paid to whoever makes it fresh again."
 * Decision D-053: payouts are batched per operator per calendar month above a
 * published minimum, through a mock adapter on demo and local.
 *
 * Every one of those sentences is exercised here through the real doors, on a
 * real miniflare D1, with real Ed25519 keys and real signatures over the real
 * canonical bytes. Only the network, the beacon, the witnesses, the payment
 * provider and the clock are fixtures. Nothing is asserted that the Worker did
 * not say: every amount comes back out of the ledger the sweep wrote, and every
 * standing out of the endpoint that recomputes it from the sealed log.
 *
 * The world: six trusted operators, one registered but untrusted challenger, a
 * maintainer, and three verified entries — one that goes stale and is
 * reconfirmed and read, one that is overturned while its money is still held,
 * and one that is overturned long after its money was released.
 *
 * The clock runs from day 0 to day 95, because the rules under test are dated:
 * a ninety-day freshness window, a thirty-day holdback, and a monthly payout
 * cycle cannot be shown inside an hour.
 */

import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { FixtureBeacon } from "../src/adapters/beacon.js";
import { MockPayoutAdapter } from "../src/adapters/payout.js";
import type { Core } from "../src/core.js";
import { base64urlEncode } from "../src/encoding.js";
import type {
  ApproverRecord,
  ReconfirmationRecord,
} from "../src/events.js";
import {
  agentIdFromPublicKey,
  exportPrivateKeyPkcs8,
  exportPublicKeyRaw,
  generateKeypair,
} from "../src/identity.js";
import { mintKey } from "../src/keys.js";
import { payoutPlan, type LedgerRow } from "../src/ledger.js";
import { mirrorLedgerRows } from "../src/mirror.js";
import {
  DEFAULT_DOMAIN,
  DISPUTE_STAKE_STANDING,
  HOLDBACK_DAYS,
  LIST_PAGE_LIMIT,
  PAYOUT_MINIMUM_MICROS,
  READ_PRICE_MICROS_PER_READ,
  READ_SHARE_SPLIT,
  STANDING_OVERTURNED_SIGNER,
  STANDING_TRUSTED_ENTRY,
  STANDING_VALIDATION_VOLUNTEERED,
} from "../src/policy.js";
import { signRecord } from "../src/records.js";
import { txtRecordName } from "../src/registry.js";
import { signCore } from "../src/sign.js";
import { buildSubmittedCore, type SubmissionProposal } from "../src/submit.js";
import {
  entryLedgerRows,
  eventsAfter,
  getOperator,
  latestSeal,
  payoutRows,
  putLedgerRows,
  putOperator,
  releasedUnpaidRows,
  setOperatorStanding,
} from "../src/storage/repository.js";
import type { Env } from "../src/worker/env.js";
import { handleRequest, type RequestDeps } from "../src/worker/index.js";
import { runSweep, type SweepReport } from "../src/worker/sweep.js";
import { putKey } from "../src/storage/keys.js";
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

/** A unit constant: the fake clock moves in whole days and whole hours. */
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

/** A reference the mock payment provider calls onboarded. */
const VERIFIED_REFERENCE = "mock-verified-m21";

const CATEGORY = "pricing";

/** Pricing entries carry a ninety-day window, so day 91 is stale. */
const STALE_READ_DAY = 91;
const RECONFIRM_DAY = 92;
const FRESH_READ_DAY = 93;

// ---------------------------------------------------------------------------
// The pages the citations point at
// ---------------------------------------------------------------------------

const PRICING: FixturePage = {
  body: "<!doctype html><html><body><main><h1>Kestrel pricing</h1><p>$40 per seat per month</p></main></body></html>",
  contentType: "text/html; charset=utf-8",
};

const CORRECTED: FixturePage = {
  body: "<!doctype html><html><body><main><h1>Kestrel pricing</h1><p>$44 per seat per month</p></main></body></html>",
  contentType: "text/html; charset=utf-8",
};

const PRICING_URL = "https://kestrel.example/pricing";
const CORRECTED_URL = "https://kestrel.example/pricing-corrected";
const PAGES: Record<string, FixturePage> = {
  [PRICING_URL]: PRICING,
  [CORRECTED_URL]: CORRECTED,
};

let PRICING_HASH = "";
let CORRECTED_HASH = "";

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

/** Six trusted operators: the author, the validators, and the judges. */
let k1: Party;
let k2: Party;
let k3: Party;
let k4: Party;
let k5: Party;
let k6: Party;
let parties: Party[] = [];

/** Registered and untrusted: the challenger that earns its way into the pool. */
let n1: Party;

let sealingKey = "";

/** The entry that goes stale, is reconfirmed, and is read fresh again. */
let staleEntry: Core;
/** The entry overturned while its read shares are still held. */
let heldEntry: Core;
/** The entry overturned long after its read shares were released. */
let releasedEntry: Core;

/**
 * One payment provider for the whole run, so the transfer numbers it hands back
 * are a sequence rather than the same number every time.
 */
const payout = new MockPayoutAdapter();

function send(request: Request, now: Date = NOW): Promise<Response> {
  return handleRequest(request, world.env, { ...world.deps, now });
}

/**
 * The key every read in this file is served on (M24).
 *
 * Section 9 pays the contributor pool out of paid-read revenue, so the reads a
 * money test makes have to be paid reads: a free read earns its holders nothing
 * and would leave this file pricing a day nobody was billed for. One standard
 * key, minted here and stored exactly as the claim door stores one.
 */
let readerSecret = "";

async function read(
  path: string,
  now: Date = NOW,
): Promise<{ status: number; body: Record<string, unknown> }> {
  const response = await send(
    new Request(`${TEST_ORIGIN}${path}`, {
      // The reading doors, and the entry door beside them: the rest of the
      // paths here are the log's own and are free to everyone, key or no key.
      // The entry door joined the list with the release window (decision
      // D-100) — every entry in this file is read at the instant it was
      // written, and a free reader inside the window is handed the proof and a
      // release date rather than the entry.
      headers:
        path.startsWith("/read") || path.startsWith("/entries")
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

/** One signed write, with its status and whatever JSON came back. */
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

/** A stated pricing proposal citing the fixture page. */
function pricing(
  subject: string,
  author: Party,
): Omit<SubmissionProposal, "author"> {
  return {
    author_operator: author.operator,
    subject,
    category: CATEGORY,
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

/** One signed decision, posted to the validate door. */
async function decide(
  entryId: string,
  party: Party,
  decision: "approve" | "reject",
  hash: string,
  now: Date = NOW,
): Promise<{ status: number; body: Record<string, unknown> }> {
  const record: ApproverRecord = {
    agent: party.agent.agentId,
    operator: party.operator,
    decision,
    reason: decision === "reject" ? "the cited page says otherwise" : null,
    snapshot_hash: hash,
    assigned_random: false,
    test_accepted: null,
    reproduction: null,
    observation: null,
    signed_at: now.toISOString(),
  };
  const signature = await signRecord(
    entryId,
    "validation",
    record,
    party.agent.privateKey,
  );
  return post(
    party.agent,
    `/entries/${entryId}/validate`,
    { record, signature },
    now,
  );
}

async function approve(
  entryId: string,
  party: Party,
  hash: string = PRICING_HASH,
  now: Date = NOW,
): Promise<void> {
  const answer = await decide(entryId, party, "approve", hash, now);
  expect([answer.status, party.operator]).toEqual([201, party.operator]);
}

/** One verified entry: submitted by an operator's own key, approved twice. */
async function verified(
  subject: string,
  author: Party,
  approvers: readonly Party[],
): Promise<Core> {
  const core = await submittedCore(author.agent, pricing(subject, author));
  const response = await send(await submission(author.agent, { core }));
  expect([response.status, await response.json()]).toEqual([
    201,
    expect.objectContaining({ id: core["id"], status: "draft" }),
  ]);
  const id = core["id"] as string;
  for (const approver of approvers) await approve(id, approver);
  const entry = await read(`/entries/${id}`);
  expect([entry.status, entry.body["status"]]).toEqual([200, "verified"]);
  return core;
}

/** One paid read through Section 8's door, `count` times. */
async function readEntry(entryId: string, count: number, now: Date): Promise<void> {
  for (let index = 0; index < count; index += 1) {
    const answer = await read(`/read/${entryId}`, now);
    expect([answer.status, entryId]).toEqual([200, entryId]);
  }
}

/** A correction core, signed by the challenger, against one target's subject. */
async function correction(
  challenger: Party,
  target: Core,
  now: Date,
): Promise<Core> {
  return buildSubmittedCore(
    {
      author: challenger.agent.agentId,
      author_operator: challenger.operator,
      subject: target["subject"] as string,
      category: "correction",
      domain: DEFAULT_DOMAIN,
      claim: `${target["subject"] as string} seat pricing is $44 per seat per month, not $40`,
      before: "$40 per seat per month",
      after: "$44 per seat per month",
      effective_at: "2026-09-02",
      citation: CORRECTED_URL,
      snapshot_hash: CORRECTED_HASH,
      supersedes: null,
    },
    { now: now.toISOString() },
  );
}

/**
 * File a challenge and carry it to verified, which overturns the target: the
 * whole M20 path, driven through the doors, because M21 prices what it leaves
 * behind and must not be shown a state the doors cannot produce.
 */
async function overturn(
  target: Core,
  challenger: Party,
  judges: readonly Party[],
  now: Date,
): Promise<string> {
  const core = await correction(challenger, target, now);
  const signature = await signCore(core, challenger.agent.privateKey);
  // A TEST FIXTURE: standing on the challenger's row for the dispute door's
  // gate to read (Section 9: standing gates the dispute stake). The challenger
  // earns its way into the pool over this run, and its first challenge is filed
  // before it has earned anything, so the column is set here exactly as the
  // sweep's standing step sets it — the gate is never weakened for it. The next
  // sweep recomputes the column from the log and this is forgotten.
  await setOperatorStanding(
    world.store.db,
    challenger.operator,
    DISPUTE_STAKE_STANDING,
    0,
  );
  const filed = await post(
    challenger.agent,
    `/entries/${target["id"] as string}/dispute`,
    { entry: { ...core, signature } },
    now,
  );
  expect([filed.status, filed.body["error"] ?? null]).toEqual([201, null]);

  const correctionId = core["id"] as string;
  for (const judge of judges) {
    await approve(correctionId, judge, CORRECTED_HASH, now);
  }

  const target_ = await read(`/entries/${target["id"] as string}`, now);
  expect([target_.status, target_.body["status"]]).toEqual([200, "overturned"]);
  return correctionId;
}

/** One signed reconfirmation, posted to the reconfirm door. */
async function reconfirm(entryId: string, party: Party, now: Date): Promise<void> {
  const record: ReconfirmationRecord = {
    agent: party.agent.agentId,
    operator: party.operator,
    snapshot_hash: PRICING_HASH,
    reproduction: null,
    observation: null,
    signed_at: now.toISOString(),
  };
  const signature = await signRecord(
    entryId,
    "reconfirmation",
    record,
    party.agent.privateKey,
  );
  const answer = await post(
    party.agent,
    `/entries/${entryId}/reconfirm`,
    { record, signature },
    now,
  );
  expect([answer.status, answer.body["error"] ?? null]).toEqual([201, null]);
}

/**
 * Run the sweep the alarm runs, with the fakes standing in for the world.
 *
 * `sealing` off is the pre-M16 sweep: no witness and no anchor adapter, so
 * nothing is sealed, which is how the state before the first seal is reached at
 * all.
 */
async function sweep(at: Date, sealing = true): Promise<SweepReport> {
  const beacon = new FixtureBeacon("m21");
  await beacon.advance(at.toISOString());
  if (!sealing) {
    return runSweep(world.env, { now: at, beacon, payout });
  }
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

/** Every ledger row about one entry, oldest first. */
function rowsFor(entryId: string): Promise<LedgerRow[]> {
  return entryLedgerRows(world.store.db, entryId, LIST_PAGE_LIMIT);
}

/** The rows of one kind an entry carries. */
async function rowsOfKind(
  entryId: string,
  kind: LedgerRow["kind"],
): Promise<LedgerRow[]> {
  return (await rowsFor(entryId)).filter((row) => row.kind === kind);
}

/** One operator's ledger page, as the endpoint serves it. */
async function ledgerOf(
  operator: string,
  now: Date,
): Promise<{ balance: Record<string, number>; rows: LedgerRow[] }> {
  const answer = await read(`/operators/${operator}/ledger`, now);
  expect([answer.status, operator]).toEqual([200, operator]);
  return {
    balance: answer.body["balance"] as Record<string, number>,
    rows: answer.body["rows"] as LedgerRow[],
  };
}

/** One operator's standing, as the endpoint recomputes it. */
async function standingOfOperator(
  operator: string,
  now: Date = NOW,
): Promise<Record<string, unknown>> {
  const answer = await read(`/operators/${operator}/standing`, now);
  expect([answer.status, operator]).toEqual([200, operator]);
  return answer.body;
}

/** What one read of one entry pays one share, in micros. */
function share(count: number, percent: number): number {
  return Math.floor((count * READ_PRICE_MICROS_PER_READ * percent) / 100);
}

// ---------------------------------------------------------------------------
// The world, built once
// ---------------------------------------------------------------------------

beforeAll(async () => {
  PRICING_HASH = await pageHash(PRICING);
  CORRECTED_HASH = await pageHash(CORRECTED);

  const pair = await generateKeypair();
  sealingKey = base64urlEncode(await exportPrivateKeyPkcs8(pair.privateKey));
  agentIdFromPublicKey(await exportPublicKeyRaw(pair.publicKey));

  const store = await openTestDatabase();
  const maintainer = await makeAgent();

  // The reader whose reads this file prices: a standard key, active, stored the
  // way GET /keys/claim stores one.
  const minted = mintKey();
  readerSecret = minted.secret;
  await putKey(store.db, {
    id: minted.id,
    keyHash: await minted.hash,
    tier: "standard",
    status: "active",
    customer: "cus_m21",
    subscription: "sub_m21",
    checkoutSession: "cs_m21",
    createdAt: AT,
  });

  k1 = await makeParty("k1.example");
  k2 = await makeParty("k2.example");
  k3 = await makeParty("k3.example");
  k4 = await makeParty("k4.example");
  k5 = await makeParty("k5.example");
  k6 = await makeParty("k6.example");
  n1 = await makeParty("n1.example");
  parties = [k1, k2, k3, k4, k5, k6];
  const maintainerParty: Party = {
    operator: "maintainer.example",
    agent: maintainer,
  };

  const records: Record<string, string[]> = {};
  for (const party of [...parties, n1, maintainerParty]) {
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
      fetcher: new FixtureFetcher(PAGES),
    },
    maintainer,
  };

  for (const party of parties) {
    await register(party);
    await name(party);
  }
  // The challenger joins the registry and is named by nobody: Section 9's own
  // path into the pool is standing, and this is the operator that walks it.
  await register(n1);
  await register(maintainerParty);

  staleEntry = await verified("example/kestrel-1", k1, [k2, k3]);
  heldEntry = await verified("example/kestrel-2", k1, [k4, k5]);
  releasedEntry = await verified("example/kestrel-3", k1, [k2, k3]);

  // Two reads on day 0, of the entry whose money is released long before it is
  // overturned.
  await readEntry(releasedEntry["id"] as string, 2, NOW);
}, 600_000);

afterAll(async () => {
  await world?.store.dispose();
});

// ---------------------------------------------------------------------------
// (h) Before the first seal
// ---------------------------------------------------------------------------

describe("the three steps before anything is sealed", () => {
  it("refuse, and the report says so in one word", async () => {
    const report = await sweep(day(1), false);

    expect(report.ledger).toBeNull();
    expect(report.standing).toBeNull();
    expect(report.payouts).toEqual([]);
    // One refusal each: nothing may be priced, folded or paid off events the
    // log has not committed to.
    expect(report.skipped["unsealed"]).toBe(3);
    // Day 0's read count still went in: it needs the clock and nothing else.
    expect(report.published.map((entry) => entry.date)).toEqual([dayDate(0)]);
  }, 600_000);
});

// ---------------------------------------------------------------------------
// (a) Standing, recomputed and cached
// ---------------------------------------------------------------------------

describe("after a sweep, standing", () => {
  it("agrees between the stored column, the recompute, and the table", async () => {
    const report = await sweep(day(1, 1));
    expect(report.standing).not.toBeNull();
    const position = report.standing!.position;
    expect(report.standing!.operators).toBeGreaterThanOrEqual(parties.length);

    const table = await read("/standing");
    expect(table.status).toBe(200);
    expect(table.body["position"]).toBe(position);
    const listed = table.body["operators"] as Record<string, unknown>[];
    // The formula's terms are published beside the numbers.
    expect(table.body["formula"]).toEqual(
      expect.arrayContaining(["STANDING_VALIDATION_VOLUNTEERED"]),
    );

    for (const party of [...parties, n1]) {
      const served = await standingOfOperator(party.operator);
      const stored = served["stored"] as { standing: number; seq: number };
      // The column is a cache of exactly what the formula returned, at the
      // position it was computed at.
      expect([party.operator, stored.standing, stored.seq]).toEqual([
        party.operator,
        served["standing"],
        position,
      ]);
      expect(served["position"]).toBe(position);
      expect(served["standing"]).toBe(
        (served["earned"] as number) - (served["burned"] as number),
      );
      expect(
        listed.find((row) => row["operator"] === party.operator)?.["standing"],
      ).toBe(served["standing"]);
    }

    // An operator nobody registered has no standing, rather than a zero one.
    expect(await read("/operators/nobody.example/standing")).toEqual({
      status: 404,
      body: { error: "not_found" },
    });
  }, 600_000);

  it("prices the day that was sealed with it", async () => {
    const rows = await rowsOfKind(releasedEntry["id"] as string, "read_share");
    // One submitter and the two operators that verified it: three shares of two
    // reads, at the published price and the published split.
    expect(rows.map((row) => [row.operator, row.amount])).toEqual([
      [k1.operator, share(2, READ_SHARE_SPLIT.stated.submitter)],
      [k2.operator, share(2, READ_SHARE_SPLIT.stated.validator)],
      [k3.operator, share(2, READ_SHARE_SPLIT.stated.validator)],
    ]);
    expect(rows[0]!.available_at).toBe(`${dayDate(HOLDBACK_DAYS)}T00:00:00.000Z`);

    const ledger = await read("/ledger");
    expect(ledger.status).toBe(200);
    const reconciliations = ledger.body["reconciliations"] as LedgerRow[];
    const day0 = reconciliations.find((row) => row.date === dayDate(0));
    expect(day0?.ref["ok"]).toBe(true);
    expect(day0?.ref["published_total"]).toBe(2);
    expect(day0?.ref["accrued_total"]).toBe(2);
    expect(ledger.body["policy"]).toEqual({
      READ_PRICE_MICROS_PER_READ,
      PAYOUT_MINIMUM_MICROS,
      PAYOUT_CYCLE: "monthly",
      HOLDBACK_DAYS,
    });
  }, 600_000);
});

// ---------------------------------------------------------------------------
// (e) The payout cycle, below the floor
// ---------------------------------------------------------------------------

describe("an operator whose released rows sit below the minimum", () => {
  it("is not paid, and the rows carry forward", async () => {
    const at = day(HOLDBACK_DAYS + 2);
    const report = await sweep(at);

    expect(report.payouts).toEqual([]);
    expect(report.skipped["payout_below_minimum"]).toBeGreaterThan(0);

    const ledger = await ledgerOf(k1.operator, at);
    expect(ledger.balance["held"]).toBe(0);
    expect(ledger.balance["released"]).toBe(
      share(2, READ_SHARE_SPLIT.stated.submitter),
    );
    expect(ledger.balance["paid"]).toBe(0);
    expect(ledger.balance["carried_forward"]).toBe(
      share(2, READ_SHARE_SPLIT.stated.submitter),
    );
    expect(await payoutRows(world.store.db, LIST_PAGE_LIMIT)).toEqual([]);
  }, 600_000);
});

// ---------------------------------------------------------------------------
// (c) An overturn after the money was released
// ---------------------------------------------------------------------------

describe("a dispute upheld after the holdback", () => {
  it("claws back nothing and burns standing only", async () => {
    const at = day(HOLDBACK_DAYS + 5);
    await overturn(releasedEntry, n1, [k4, k5], at);

    const report = await sweep(new Date(at.getTime() + HOUR_MS));
    expect(report.ledger!.clawbacks).toBe(0);
    expect(
      await rowsOfKind(releasedEntry["id"] as string, "clawback"),
    ).toEqual([]);

    // The rows are untouched: released is released.
    const ledger = await ledgerOf(k2.operator, at);
    expect(ledger.balance["clawed_back"]).toBe(0);
    expect(ledger.balance["released"]).toBe(
      share(2, READ_SHARE_SPLIT.stated.validator),
    );

    // The signers burn, and the challenger earns.
    const signer = await standingOfOperator(k2.operator, at);
    expect((signer["counts"] as Record<string, number>)["overturned"]).toBe(1);
    expect(signer["burned"]).toBe(STANDING_OVERTURNED_SIGNER);
    const challenger = await standingOfOperator(n1.operator, at);
    expect(
      (challenger["counts"] as Record<string, number>)["disputes_upheld"],
    ).toBe(1);
    // The stake is unlocked the moment the challenge holds.
    expect(challenger["locked"]).toBe(0);
  }, 600_000);
});

// ---------------------------------------------------------------------------
// (e) The payout cycle, at the floor
// ---------------------------------------------------------------------------

describe("an operator whose released rows reach the minimum", () => {
  it("is paid once through the provider, and not twice in one cycle", async () => {
    const at = day(HOLDBACK_DAYS + 5, 2);

    // Onboarding stored the reference at registration; this world writes the
    // one the mock provider calls verified onto the row the payout step reads.
    const record = await getOperator(world.store.db, k6.operator);
    await putOperator(world.store.db, {
      ...record!,
      details: { ...record!.details, payout_reference: VERIFIED_REFERENCE },
    });
    // A released accrual at exactly the published floor. Sixty-six thousand
    // real reads would say the same thing more slowly.
    await putLedgerRows(world.store.db, [
      {
        id: "read_share:fixture:payout",
        kind: "read_share",
        entry_id: null,
        operator: k6.operator,
        role: "validator",
        date: dayDate(0),
        reads: 1,
        unit: "micros",
        amount: PAYOUT_MINIMUM_MICROS,
        available_at: `${dayDate(HOLDBACK_DAYS)}T00:00:00.000Z`,
        seq: 0,
        at: AT,
        ref: {},
      },
    ]);

    const report = await sweep(at);
    expect(report.payouts).toHaveLength(1);
    expect(report.payouts[0]!.operator).toBe(k6.operator);
    expect(report.payouts[0]!.amount).toBe(PAYOUT_MINIMUM_MICROS);
    expect(report.payouts[0]!.transfer).toMatch(/^mock-transfer-\d+$/);

    const ledger = await ledgerOf(k6.operator, at);
    expect(ledger.balance["paid"]).toBe(PAYOUT_MINIMUM_MICROS);
    expect(ledger.balance["carried_forward"]).toBe(0);
    const paid = await payoutRows(world.store.db, LIST_PAGE_LIMIT, k6.operator);
    expect(paid).toHaveLength(1);
    expect(paid[0]!.ref["rows"]).toEqual(["read_share:fixture:payout"]);

    // The cycle is monthly and per operator (D-053), so a second run in the same
    // month pays nothing: the accrual this one paid is claimed, so the operator
    // holds nothing released at all and is not even asked about.
    const again = await sweep(new Date(at.getTime() + HOUR_MS));
    expect(again.payouts).toEqual([]);
    expect(again.skipped["payout_below_minimum"]).toBeGreaterThan(0);
    expect(
      await payoutRows(world.store.db, LIST_PAGE_LIMIT, k6.operator),
    ).toHaveLength(1);
  }, 600_000);
});

// ---------------------------------------------------------------------------
// (d) The stale half, and the bounty it builds
// ---------------------------------------------------------------------------

describe("a stale entry", () => {
  it("earns half rate, and the remainder pools on the entry", async () => {
    const at = day(STALE_READ_DAY);
    const id = staleEntry["id"] as string;

    // Section 7's own step first: the window closing is a fact about the
    // calendar, and the stored row is rewritten by the sweep that notices it.
    const closed = await sweep(at);
    expect(closed.staled).toContain(id);
    const entry = await read(`/entries/${id}`, at);
    expect([entry.body["status"], entry.body["stale"]]).toEqual([
      "verified",
      true,
    ]);

    await readEntry(id, 2, day(STALE_READ_DAY, 1));
    const report = await sweep(day(RECONFIRM_DAY));
    expect(report.ledger!.ok).toBe(true);

    const shares = (await rowsOfKind(id, "read_share")).filter(
      (row) => row.date === dayDate(STALE_READ_DAY),
    );
    const full = [
      share(2, READ_SHARE_SPLIT.stated.submitter),
      share(2, READ_SHARE_SPLIT.stated.validator),
      share(2, READ_SHARE_SPLIT.stated.validator),
    ];
    expect(shares.map((row) => [row.operator, row.amount])).toEqual([
      [k1.operator, Math.floor(full[0]! / 2)],
      [k2.operator, Math.floor(full[1]! / 2)],
      [k3.operator, Math.floor(full[2]! / 2)],
    ]);

    const pool = await rowsOfKind(id, "bounty_pool");
    expect(pool).toHaveLength(1);
    expect(pool[0]!.operator).toBeNull();
    expect(pool[0]!.amount).toBe(
      full.reduce((sum, amount) => sum + amount - Math.floor(amount / 2), 0),
    );
  }, 600_000);

  it("pays the pool to whoever makes it fresh again, once", async () => {
    const at = day(RECONFIRM_DAY, 1);
    const id = staleEntry["id"] as string;
    const pooled = (await rowsOfKind(id, "bounty_pool"))[0]!.amount;

    await reconfirm(id, k4, at);
    // The other stale entry is reconfirmed too: it accrued no pool, so its
    // bounty is priced at nothing rather than left unpriced.
    await reconfirm(heldEntry["id"] as string, k6, at);

    const report = await sweep(day(FRESH_READ_DAY));
    expect(report.ledger!.bounties).toBe(2);

    const accruals = await rowsOfKind(id, "bounty_accrual");
    // One row, not two: the door's unpriced row and the priced one are the same
    // row, under the same id.
    expect(accruals).toHaveLength(1);
    expect([accruals[0]!.operator, accruals[0]!.amount]).toEqual([
      k4.operator,
      pooled,
    ]);
    expect(accruals[0]!.role).toBe("reconfirmer");
    expect(accruals[0]!.available_at).toBe(
      new Date(at.getTime() + HOLDBACK_DAYS * DAY_MS).toISOString(),
    );
    expect(await rowsOfKind(heldEntry["id"] as string, "bounty_accrual")).toEqual([
      expect.objectContaining({ operator: k6.operator, amount: 0 }),
    ]);
  }, 600_000);
});

// ---------------------------------------------------------------------------
// (b) One day, four shares, and a second run that adds nothing
// ---------------------------------------------------------------------------

describe("a day of reads over an entry with a submitter and three slots", () => {
  it("splits four ways, reconciles, and prices exactly once", async () => {
    const at = day(FRESH_READ_DAY, 1);
    const id = staleEntry["id"] as string;

    // The reconfirmation seated a third slot holder, so the split is the
    // paper's own: fifteen to the submitter and five to each of three.
    const entry = await read(`/read/${id}`, at);
    expect(entry.status).toBe(200);
    const slots = (entry.body["sidecar"] as Record<string, unknown>)[
      "read_share_slots"
    ] as { operator: string }[];
    expect(slots.map((slot) => slot.operator)).toEqual([
      k2.operator,
      k3.operator,
      k4.operator,
    ]);
    // Two more reads of it, and two of the entry whose money is clawed back.
    await readEntry(id, 2, at);
    await readEntry(heldEntry["id"] as string, 2, at);

    const report = await sweep(day(FRESH_READ_DAY + 1));
    expect(report.ledger!.ok).toBe(true);

    const shares = (await rowsOfKind(id, "read_share")).filter(
      (row) => row.date === dayDate(FRESH_READ_DAY),
    );
    expect(shares.map((row) => [row.operator, row.role, row.amount])).toEqual([
      [k1.operator, "submitter", share(3, READ_SHARE_SPLIT.stated.submitter)],
      [k2.operator, "validator", share(3, READ_SHARE_SPLIT.stated.validator)],
      [k3.operator, "validator", share(3, READ_SHARE_SPLIT.stated.validator)],
      [k4.operator, "validator", share(3, READ_SHARE_SPLIT.stated.validator)],
    ]);
    // Fresh again, so nothing is withheld on that day.
    expect(
      (await rowsOfKind(id, "bounty_pool")).filter(
        (row) => row.date === dayDate(FRESH_READ_DAY),
      ),
    ).toEqual([]);

    const ledger = await read("/ledger");
    const reconciliation = (ledger.body["reconciliations"] as LedgerRow[]).find(
      (row) => row.date === dayDate(FRESH_READ_DAY),
    );
    expect(reconciliation?.ref["ok"]).toBe(true);
    expect(reconciliation?.ref["published_total"]).toBe(5);

    // A second run over the same sealed log writes nothing at all.
    const before = await rowsFor(id);
    const again = await sweep(day(FRESH_READ_DAY + 1, 1));
    expect([
      again.ledger!.read_shares,
      again.ledger!.clawbacks,
      again.ledger!.bounties,
      again.ledger!.reconciliations,
    ]).toEqual([0, 0, 0, 0]);
    expect(await rowsFor(id)).toEqual(before);
  }, 600_000);
});

// ---------------------------------------------------------------------------
// (c) An overturn inside the holdback, and (f) the pool it moves
// ---------------------------------------------------------------------------

describe("a dispute upheld inside the holdback", () => {
  it("claws back every held share and burns the signers", async () => {
    const at = day(FRESH_READ_DAY + 2);
    const id = heldEntry["id"] as string;
    const held = await rowsOfKind(id, "read_share");
    expect(held).toHaveLength(4);

    await overturn(heldEntry, n1, [k2, k3], at);
    const report = await sweep(new Date(at.getTime() + HOUR_MS));
    expect(report.ledger!.clawbacks).toBe(4);

    const clawbacks = await rowsOfKind(id, "clawback");
    expect(clawbacks).toHaveLength(4);
    expect(clawbacks.map((row) => row.amount)).toEqual(
      held.map((row) => -row.amount),
    );

    // Every clawback waits with the share it negates, so the two release
    // together and neither can leave alone.
    expect(clawbacks.map((row) => row.available_at)).toEqual(
      held.map((row) => row.available_at),
    );

    // Section 6's same sentence pays the challenger: the reward the dispute
    // door wrote unpriced is priced here at exactly what came back, and leaves
    // when the last of those shares would have.
    const rewards = await rowsOfKind(id, "dispute_reward");
    expect(rewards).toHaveLength(1);
    const reward = rewards[0]!;
    expect([reward.unit, reward.amount]).toEqual([
      "micros",
      -clawbacks.reduce((sum, row) => sum + row.amount, 0),
    ]);
    expect(reward.available_at).toBe(
      clawbacks.map((row) => row.available_at).sort().at(-1),
    );
    expect(reward.ref["clawbacks"]).toEqual(clawbacks.map((row) => row.id));
    // The row it was written as is still under `ref`, naming the challenger.
    expect(reward.ref["agent"]).toBe(n1.agent.agentId);

    // An operator that held a share on this entry and nowhere else: everything
    // it accrued came back.
    const ledger = await ledgerOf(k5.operator, at);
    expect(ledger.balance["accrued"] + ledger.balance["clawed_back"]).toBe(0);
    expect(ledger.balance["accrued"]).toBeGreaterThan(0);
    // Inside the holdback both rows are held, so they net to nothing: nothing
    // is owed, nothing is payable, and nothing carries to the next cycle.
    expect(ledger.balance["held"]).toBe(0);
    expect(ledger.balance["released"]).toBe(0);
    expect(ledger.balance["carried_forward"]).toBe(0);
    expect(ledger.balance["paid"]).toBe(0);

    // The reconfirmer signed it too, and burns for it exactly once.
    const reconfirmer = await standingOfOperator(k6.operator, at);
    expect(
      (reconfirmer["counts"] as Record<string, number>)["overturned"],
    ).toBe(1);
  }, 600_000);

  it("holds the challenger's reward, then releases it to their operator", async () => {
    // Section 6 pays the challenger, and Section 9 holds what it pays for as
    // long as the shares it was priced off: the reward waits with them and
    // comes out with them, on the challenger's operator's own balance.
    const id = heldEntry["id"] as string;
    const reward = (await rowsOfKind(id, "dispute_reward"))[0]!;
    expect([reward.operator, reward.unit]).toEqual([n1.operator, "micros"]);
    expect(reward.amount).toBeGreaterThan(0);

    // An hour inside the holdback: held, and no cycle can reach it.
    const inside = new Date(new Date(reward.available_at!).getTime() - HOUR_MS);
    const held = (await ledgerOf(n1.operator, inside)).balance;
    expect([held["accrued"], held["held"], held["released"]]).toEqual([
      reward.amount,
      reward.amount,
      0,
    ]);
    expect(
      (
        await releasedUnpaidRows(world.store.db, n1.operator, inside.toISOString())
      ).map((row) => row.id),
    ).not.toContain(reward.id);

    // At its release it is what the payout cycle reads: released, unpaid, and
    // either paid this cycle or carried whole to the next.
    const out = new Date(reward.available_at!);
    const released = await releasedUnpaidRows(
      world.store.db,
      n1.operator,
      out.toISOString(),
    );
    expect(released.map((row) => row.id)).toContain(reward.id);
    const plan = payoutPlan(n1.operator, released, out.toISOString());
    expect(plan.amount + plan.carried_forward).toBe(reward.amount);

    const balance = (await ledgerOf(n1.operator, out)).balance;
    expect([balance["released"], balance["paid"], balance["carried_forward"]]).toEqual(
      [reward.amount, 0, reward.amount],
    );
  }, 600_000);

  it("stores the reward the mirror recomputes, field for field", async () => {
    // The property verify-mirror's ledger check rests on: a clone recomputes
    // the reward from the sealed events rather than believing the number, so a
    // stored row and a recomputed one cannot disagree about what an upheld
    // challenge is owed.
    const id = heldEntry["id"] as string;
    const stored = (await rowsOfKind(id, "dispute_reward"))[0]!;

    const sealed = (await latestSeal(world.store.db))!;
    const events = await eventsAfter(world.store.db, -1, LIST_PAGE_LIMIT * 20);
    const recomputed = mirrorLedgerRows(events, sealed.sealed_at).filter(
      (row) => row.kind === "dispute_reward" && row.entry_id === id,
    );
    expect(recomputed).toHaveLength(1);
    expect(recomputed[0]).toEqual(stored);
    // Named field by field as well, so a failure says which one moved.
    expect([
      recomputed[0]!.id,
      recomputed[0]!.amount,
      recomputed[0]!.unit,
      recomputed[0]!.available_at,
      recomputed[0]!.operator,
      recomputed[0]!.ref,
    ]).toEqual([
      stored.id,
      stored.amount,
      stored.unit,
      stored.available_at,
      stored.operator,
      stored.ref,
    ]);
  }, 600_000);

  it("moves the trusted pool, and the next run's snapshot says so", async () => {
    const at = day(FRESH_READ_DAY + 2, 1);
    // The run above appended the trust changes; this reads what it decided.
    // Two upheld challenges and the two corrections they verified: the entry
    // bar, cleared by the formula and by nobody's decision.
    const challenger = await standingOfOperator(n1.operator, at);
    expect(challenger["standing"]).toBeGreaterThanOrEqual(
      STANDING_TRUSTED_ENTRY,
    );

    const trusted = await read(`/operators/${n1.operator}`, at);
    expect(
      (trusted.body["details"] as Record<string, unknown>)["trusted"],
    ).toBe(true);
    expect(
      (trusted.body["details"] as Record<string, unknown>)["named_by"],
    ).toBe("standing");

    const dropped = await read(`/operators/${k5.operator}`, at);
    expect(
      (dropped.body["details"] as Record<string, unknown>)["trusted"],
    ).toBe(false);

    const next = await sweep(day(FRESH_READ_DAY + 2, 2));
    expect(next.snapshot).not.toBeNull();
    expect(next.snapshot!.operators).toContain(n1.operator);
    expect(next.snapshot!.operators).not.toContain(k5.operator);
  }, 600_000);
});

// ---------------------------------------------------------------------------
// (b) The standing step reads the sealed head, and never the head
// ---------------------------------------------------------------------------

describe("a validation the log has not sealed yet", () => {
  it("does not move the stored standing until a run seals it", async () => {
    const at = day(FRESH_READ_DAY + 3);
    const before = await standingOfOperator(n1.operator, at);
    const storedBefore = before["stored"] as { standing: number; seq: number };

    // A draft is submitted and one operator volunteers a decision on it: a
    // validation event past the head the last seal covers, worth
    // STANDING_VALIDATION_VOLUNTEERED to whoever signed it — once the log
    // commits to it. One decision and no more, so the entry stays a draft and
    // nothing but the volunteered term moves.
    const core = await buildSubmittedCore(
      {
        author: k1.agent.agentId,
        author_operator: k1.operator,
        subject: "example/kestrel-4",
        category: CATEGORY,
        domain: DEFAULT_DOMAIN,
        claim: "example/kestrel-4 seat pricing is $40 per seat per month",
        before: "$35 per seat per month",
        after: "$40 per seat per month",
        effective_at: "2026-09-01",
        citation: PRICING_URL,
        snapshot_hash: PRICING_HASH,
        supersedes: null,
      },
      { now: at.toISOString() },
    );
    const posted = await send(
      await submission(k1.agent, { core, timestamp: at.toISOString() }),
      at,
    );
    expect(posted.status).toBe(201);
    await approve(core["id"] as string, n1, PRICING_HASH, at);

    // A run with no witness and no anchor seals nothing, so the sealed head is
    // exactly where it was. Section 9: standing "is derived from the sealed
    // public events", so this run must recompute at the old position and write
    // the old number — a step that read through the unsealed head would credit
    // the reconfirmation here, and would be crediting an event the log has not
    // committed to and could still recompute differently.
    const unsealed = await sweep(day(FRESH_READ_DAY + 3, 1), false);
    expect(unsealed.sealed).toBeNull();
    expect(unsealed.standing).not.toBeNull();
    expect(unsealed.standing!.position).toBe(storedBefore.seq);

    const during = await standingOfOperator(n1.operator, at);
    expect(during["stored"]).toEqual(storedBefore);
    expect(during["standing"]).toBe(before["standing"]);
    expect(
      (during["counts"] as Record<string, number>)["validations_volunteered"],
    ).toBe(
      (before["counts"] as Record<string, number>)["validations_volunteered"],
    );

    // The next run seals it, and only then is it worth anything.
    const sealedRun = await sweep(day(FRESH_READ_DAY + 3, 2));
    expect(sealedRun.sealed).not.toBeNull();
    expect(sealedRun.standing!.position).toBeGreaterThan(storedBefore.seq);

    const after = await standingOfOperator(n1.operator, at);
    expect(after["standing"]).toBe(
      (before["standing"] as number) + STANDING_VALIDATION_VOLUNTEERED,
    );
    expect(after["stored"]).toEqual({
      standing: after["standing"],
      seq: sealedRun.standing!.position,
    });
    expect(
      (after["counts"] as Record<string, number>)["validations_volunteered"],
    ).toBe(
      (before["counts"] as Record<string, number>)["validations_volunteered"] +
        1,
    );
  }, 600_000);
});
