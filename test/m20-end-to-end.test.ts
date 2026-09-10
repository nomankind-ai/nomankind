/**
 * M20 end to end: dispute, revalidate and failure reports, through the Worker
 * and the sweep.
 *
 * Whitepaper Section 6, "Dispute": "Verified entries stay open to challenge. A
 * challenge is itself an entry, in the correction category, and it requires a
 * citation. It passes through the same validation process with one extra
 * exclusion: no operator that signed the original, submitter or validator, may
 * validate the challenge against it ... An upheld challenge returns the stake,
 * pays the challenger, overturns the entry ... A failed challenge forfeits the
 * stake." Section 6, "Revalidate": a staked request, a random assignment, a cap
 * per operator per window, the stake back plus a reward when the fact changed
 * and the stake lost when the entry holds. Section 8 and Section 12: reports
 * from a threshold of distinct VERIFIED OPERATORS auto-open a check, and a
 * flood of bare keys opens nothing.
 *
 * Every one of those sentences is exercised here through the real doors, on a
 * real miniflare D1, with real Ed25519 keys and real signatures over the real
 * canonical bytes. Only the network, the beacon, the witnesses and the clock are
 * fixtures. Nothing is asserted that the Worker did not say, and every status
 * and every derived field comes back out of the log rather than out of this
 * file.
 *
 * The world: five trusted operators and the maintainer, a bare-key author, and
 * five verified entries, one per thing this milestone has to prove.
 */

import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { FixtureBeacon } from "../src/adapters/beacon.js";
import { MockPayoutAdapter } from "../src/adapters/payout.js";
import { buildExport } from "../src/cli/export.js";
import type { HttpClient } from "../src/cli/validator.js";
import type { Core } from "../src/core.js";
import type { RevalidationView } from "../src/derive.js";
import { base64urlEncode } from "../src/encoding.js";
import type { ApproverRecord, Event, ReconfirmationRecord } from "../src/events.js";
import {
  agentIdFromPublicKey,
  exportPrivateKeyPkcs8,
  exportPublicKeyRaw,
  generateKeypair,
} from "../src/identity.js";
import {
  DEFAULT_DOMAIN,
  ASSIGNMENT_WINDOW_HOURS,
  DISPUTE_FILING_FEE_CENTS,
  DISPUTE_STAKE_STANDING,
  LIST_PAGE_LIMIT,
  REVALIDATION_REQUEST_STAKE_STANDING,
} from "../src/policy.js";
import { signRecord } from "../src/records.js";
import { txtRecordName } from "../src/registry.js";
import type { StakeRecord } from "../src/stake.js";
import {
  eventsForEntry,
  ledgerRowsForEntry,
  setOperatorStanding,
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

/** A unit constant: the fake clock moves in whole hours. */
const HOUR_MS = 3_600_000;

function hour(hours: number): Date {
  return new Date(NOW.getTime() + hours * HOUR_MS);
}

/** A reference the mock payment provider calls onboarded. */
const VERIFIED_REFERENCE = "mock-verified-m20";

const CATEGORY = "pricing";

// ---------------------------------------------------------------------------
// The pages the citations point at
// ---------------------------------------------------------------------------

const PRICING: FixturePage = {
  body: "<!doctype html><html><body><main><h1>Kestrel pricing</h1><p>$40 per seat per month</p></main></body></html>",
  contentType: "text/html; charset=utf-8",
};

/** The page a correction cites: the same source, saying something else. */
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
/** Five trusted operators: two sign the originals, the rest judge challenges. */
let k1: Party;
let k2: Party;
let k3: Party;
let k4: Party;
let k5: Party;
let parties: Party[] = [];

/** Bare keys: the author of every entry, and the two challengers. */
let author: TestAgent;
let challenger: TestAgent;
let secondChallenger: TestAgent;
/** Three more bare keys, for the flood Section 12 answers at the threshold. */
let readers: TestAgent[] = [];

let sealingKey = "";

/** The entry that is challenged and overturned. */
let overturnedEntry: Core;
/** The entry whose challenge fails. */
let standingEntry: Core;
/** The entry the revalidation requests are made about. */
let checkedEntry: Core;
/** The entry the failure reports are filed against. */
let reportedEntry: Core;
/** The entry whose report is upgraded into a dispute. */
let upgradedEntry: Core;

/** The correction that overturned `overturnedEntry`, once it is filed. */
let upheldCorrectionId = "";
/** The correction that failed against `standingEntry`. */
let failedCorrectionId = "";
/** The correction the report was upgraded into. */
let upgradeCorrectionId = "";

function send(request: Request, now: Date = NOW): Promise<Response> {
  return handleRequest(request, world.env, { ...world.deps, now });
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

/** The entry as the log serves it. */
async function entry(id: string): Promise<Record<string, unknown>> {
  const answer = await read(`/entries/${id}`);
  expect(answer.status).toBe(200);
  return answer.body;
}

/** The stake rows one entry produced, oldest first. */
function stakes(entryId: string): Promise<StakeRecord[]> {
  return ledgerRowsForEntry(world.store.db, entryId, LIST_PAGE_LIMIT);
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

/** A stated pricing proposal citing one of the two fixture pages. */
function pricing(
  subject: string,
  claim: string,
  url: string = PRICING_URL,
  hash: string = PRICING_HASH,
): Omit<SubmissionProposal, "author"> {
  return {
    subject,
    category: CATEGORY,
    domain: DEFAULT_DOMAIN,
    claim,
    before: "$35 per seat per month",
    after: "$40 per seat per month",
    effective_at: "2026-09-01",
    citation: url,
    snapshot_hash: hash,
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
): Promise<void> {
  const answer = await decide(entryId, party, "approve", hash);
  expect([answer.status, party.operator]).toEqual([201, party.operator]);
}

/** One verified entry, submitted by the bare-key author and approved twice. */
async function verified(claim: string, subject: string): Promise<Core> {
  const core = await submit(pricing(subject, claim));
  const id = core["id"] as string;
  await approve(id, k1);
  await approve(id, k2);
  expect((await entry(id))["status"]).toBe("verified");
  return core;
}

/** A correction core, signed by a challenger, against one target's subject. */
async function correction(
  signer: TestAgent,
  target: Core,
  claim: string,
  operator: string | null = null,
): Promise<Core> {
  return submittedCore(signer, {
    author_operator: operator,
    subject: target["subject"] as string,
    category: "correction",
    claim,
    before: "$40 per seat per month",
    after: "$44 per seat per month",
    effective_at: "2026-09-02",
    citation: CORRECTED_URL,
    snapshot_hash: CORRECTED_HASH,
    supersedes: null,
  });
}

/** One filing, posted to the dispute door. */
async function file(
  signer: TestAgent,
  target: Core,
  core: Core,
  extra: Record<string, unknown> = {},
): Promise<{ status: number; body: Record<string, unknown> }> {
  const { signCore } = await import("../src/sign.js");
  const signature = await signCore(core, signer.privateKey);
  return post(signer, `/entries/${target["id"] as string}/dispute`, {
    entry: { ...core, signature },
    ...extra,
  });
}

/** A receipt artifact a reader freezes with their report. */
function artifact(observer: string, note: string): Record<string, unknown> {
  return {
    method: "endpoint_error",
    subject: "kestrel/kestrel-1",
    test: `contains:${note}`,
    request: {
      method: "GET",
      url: PRICING_URL,
      headers: { accept: "text/html" },
    },
    response: {
      status: 404,
      final_url: PRICING_URL,
      content_type: "text/html",
      snapshot_hash: PRICING_HASH,
    },
    billing: null,
    observed_at: "2026-09-08",
    observer,
  };
}

/**
 * A TEST FIXTURE, and nothing this milestone's rules produce: standing on the
 * operator rows for the gate to read.
 *
 * Section 9 has standing gate the dispute and revalidation stakes, and M20's
 * world earns almost none of it — five operators approving a handful of entries.
 * So the column is set directly, exactly as the sweep's standing step would set
 * it, rather than the gate being weakened to let the fixture through. The sweep
 * recomputes the column from the log on every run, so it is written again after
 * each one.
 */
const FIXTURE_STANDING = DISPUTE_STAKE_STANDING * 4;

async function fundStanding(): Promise<void> {
  for (const party of parties) {
    await setOperatorStanding(
      world.store.db,
      party.operator,
      FIXTURE_STANDING,
      0,
    );
  }
}

/** Run the sweep the alarm runs, with the fakes standing in for the world. */
async function sweep(at: Date): Promise<SweepReport> {
  const beacon = new FixtureBeacon("m20");
  await beacon.advance(at.toISOString());
  const report = await runSweep(world.env, {
    now: at,
    beacon,
    witness: new FakeWitnessAdapter(),
    pinned: pinnedSet([]),
    ineligibleAgents: new Set<string>(),
    anchor: new FakeAnchorAdapter(null),
  });
  // The standing step just overwrote the fixture with what the log says.
  await fundStanding();
  return report;
}

/** An HttpClient that routes straight into the router, with no network. */
class InProcessHttp implements HttpClient {
  async fetch(request: Request): Promise<Response> {
    return send(request);
  }
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
  author = await makeAgent();
  challenger = await makeAgent();
  secondChallenger = await makeAgent();
  readers = [await makeAgent(), await makeAgent(), await makeAgent()];

  k1 = await makeParty("k1.example");
  k2 = await makeParty("k2.example");
  k3 = await makeParty("k3.example");
  k4 = await makeParty("k4.example");
  k5 = await makeParty("k5.example");
  parties = [k1, k2, k3, k4, k5];
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
      payout: new MockPayoutAdapter(),
      fetcher: new FixtureFetcher(PAGES),
    },
    maintainer,
  };

  for (const party of parties) {
    await register(party);
    await name(party);
  }
  await register(maintainerParty);
  await fundStanding();

  overturnedEntry = await verified(
    "Kestrel-1 seat pricing is $40 per seat per month",
    "kestrel/kestrel-1",
  );
  standingEntry = await verified(
    "Kestrel-2 seat pricing is $40 per seat per month",
    "kestrel/kestrel-2",
  );
  checkedEntry = await verified(
    "Kestrel-3 seat pricing is $40 per seat per month",
    "kestrel/kestrel-3",
  );
  reportedEntry = await verified(
    "Kestrel-4 seat pricing is $40 per seat per month",
    "kestrel/kestrel-4",
  );
  upgradedEntry = await verified(
    "Kestrel-5 seat pricing is $40 per seat per month",
    "kestrel/kestrel-5",
  );
}, 240_000);

afterAll(async () => {
  await world?.store.dispose();
});

// ---------------------------------------------------------------------------
// (a) The upheld challenge
// ---------------------------------------------------------------------------

describe("a challenge by a bare key", () => {
  it("is filed, refuses an original signer, and overturns the entry when upheld", async () => {
    const targetId = overturnedEntry["id"] as string;
    const core = await correction(
      challenger,
      overturnedEntry,
      "Kestrel-1 seat pricing is $44 per seat per month, not $40",
    );
    upheldCorrectionId = core["id"] as string;

    const filed = await file(challenger, overturnedEntry, core);
    expect([filed.status, filed.body["correction"]]).toEqual([
      201,
      expect.objectContaining({ id: upheldCorrectionId, status: "draft" }),
    ]);
    // The target says the challenge is open before any validator has spoken.
    const openTarget = filed.body["target"] as Record<string, unknown>;
    expect(openTarget["status"]).toBe("verified");
    expect((openTarget["disputes"] as Record<string, unknown>[])[0]).toEqual(
      expect.objectContaining({
        id: upheldCorrectionId,
        challenger: challenger.agentId,
        operator: null,
        outcome: "open",
        citation: CORRECTED_URL,
        snapshot_hash: CORRECTED_HASH,
      }),
    );

    // Section 6's extra exclusion: k1 approved the original, so k1 may not
    // judge the challenge against it.
    const refused = await decide(
      upheldCorrectionId,
      k1,
      "approve",
      CORRECTED_HASH,
    );
    expect([refused.status, refused.body["error"]]).toEqual([
      422,
      "original_signer",
    ]);

    // Two operators from outside the original verify it, and the target is
    // overturned at exactly the decision that verified the correction.
    await approve(upheldCorrectionId, k3, CORRECTED_HASH);
    const decided = await decide(
      upheldCorrectionId,
      k4,
      "approve",
      CORRECTED_HASH,
    );
    expect(decided.status).toBe(201);
    expect(decided.body["status"]).toBe("verified");

    const target = await entry(targetId);
    expect(target["status"]).toBe("overturned");
    expect(target["overturned_by"]).toBe(upheldCorrectionId);
    expect((target["disputes"] as Record<string, unknown>[])[0]).toEqual(
      expect.objectContaining({ id: upheldCorrectionId, outcome: "upheld" }),
    );
  }, 240_000);

  it("returns the stake and pays the challenger", async () => {
    const rows = await stakes(overturnedEntry["id"] as string);
    expect(rows.map((row) => row.kind)).toEqual([
      "dispute_stake",
      "dispute_refund",
      "dispute_reward",
    ]);
    // A bare key stakes a refundable filing fee, not standing.
    expect(rows[0]).toEqual(
      expect.objectContaining({
        agent: challenger.agentId,
        operator: null,
        unit: "cents",
        amount: DISPUTE_FILING_FEE_CENTS,
        correction_entry_id: upheldCorrectionId,
      }),
    );
    expect(rows[1]!.amount).toBe(DISPUTE_FILING_FEE_CENTS);
    // Section 9's pricing is M21's, so a reward is a fact with no number yet.
    expect([rows[2]!.unit, rows[2]!.amount]).toEqual([null, null]);
  }, 120_000);

  it("refuses a second challenge while one is open", async () => {
    const other = await correction(
      secondChallenger,
      standingEntry,
      "Kestrel-2 seat pricing is $44 per seat per month, not $40",
    );
    const first = await file(secondChallenger, standingEntry, other);
    expect(first.status).toBe(201);
    failedCorrectionId = other["id"] as string;

    const again = await correction(
      challenger,
      standingEntry,
      "Kestrel-2 seat pricing is $44, filed twice",
    );
    const refused = await file(challenger, standingEntry, again);
    expect([refused.status, refused.body["error"]]).toEqual([
      409,
      "dispute_open",
    ]);
  }, 240_000);
});

// ---------------------------------------------------------------------------
// (b) The failed challenge
// ---------------------------------------------------------------------------

describe("a challenge its own validators reject", () => {
  it("fails, forfeits the stake, and leaves the entry verified", async () => {
    await (async () => {
      const first = await decide(
        failedCorrectionId,
        k3,
        "reject",
        CORRECTED_HASH,
      );
      expect(first.status).toBe(201);
    })();
    const second = await decide(
      failedCorrectionId,
      k4,
      "reject",
      CORRECTED_HASH,
    );
    expect([second.status, second.body["status"]]).toEqual([201, "rejected"]);

    const target = await entry(standingEntry["id"] as string);
    expect(target["status"]).toBe("verified");
    expect(target["overturned_by"]).toBeNull();
    expect((target["disputes"] as Record<string, unknown>[])[0]).toEqual(
      expect.objectContaining({
        id: failedCorrectionId,
        outcome: "failed",
        reason: "the cited page says otherwise",
      }),
    );

    const rows = await stakes(standingEntry["id"] as string);
    expect(rows.map((row) => row.kind)).toEqual([
      "dispute_stake",
      "dispute_forfeit",
    ]);
    expect(rows[1]!.amount).toBe(DISPUTE_FILING_FEE_CENTS);
  }, 240_000);
});

// ---------------------------------------------------------------------------
// (c) The revalidation request, the cap, and the draw
// ---------------------------------------------------------------------------

/** The party whose agent the sweep drew as checker, and one that it did not. */
function partyOf(operator: string): Party {
  const found = parties.find((party) => party.operator === operator);
  expect(found).toBeDefined();
  return found as Party;
}

describe("a staked revalidation request", () => {
  it("opens a check, holds the cap, and refuses a second while one is open", async () => {
    const id = checkedEntry["id"] as string;

    const opened = await post(k3.agent, `/entries/${id}/revalidate`, {});
    expect(opened.status).toBe(201);
    const views = (
      await eventsForEntry(world.store.db, id)
    ).filter((event) => event.type === "revalidation_requested");
    expect(views.length).toBe(1);

    // "Requests are capped per operator per window."
    const capped = await post(k3.agent, `/entries/${id}/revalidate`, {});
    expect([capped.status, capped.body["error"]]).toEqual([
      422,
      "cap_exceeded",
    ]);

    // And one check at a time, whoever asks for it.
    const busy = await post(k4.agent, `/entries/${id}/revalidate`, {});
    expect([busy.status, busy.body["error"]]).toEqual([409, "request_open"]);

    const rows = await stakes(id);
    expect(rows.map((row) => row.kind)).toEqual(["revalidation_stake"]);
    expect(rows[0]).toEqual(
      expect.objectContaining({
        agent: k3.agent.agentId,
        operator: k3.operator,
        unit: "standing",
        amount: REVALIDATION_REQUEST_STAKE_STANDING,
      }),
    );
  }, 240_000);

  it("is drawn to a trusted operator outside the excluded ones, and held forfeits", async () => {
    const id = checkedEntry["id"] as string;

    // The first run commits the pool snapshot, which is later than every beacon
    // round it can read, so the draw waits for a later round. That is the
    // paper's own ordering rule working.
    const first = await sweep(hour(1));
    expect(first.revalidation_drawn).toEqual([]);

    const second = await sweep(hour(2));
    expect(second.revalidation_drawn.length).toBe(1);
    const draw = second.revalidation_drawn[0]!;
    expect(draw.entry_id).toBe(id);
    // The requester's own operator is barred: it would be answering its own
    // question, and either outcome would be its own to decide.
    expect(draw.operator).not.toBe(k3.operator);
    expect(parties.map((party) => party.operator)).toContain(draw.operator);

    const checker = partyOf(draw.operator);
    const notChecker = parties.find(
      (party) => party.operator !== draw.operator && party.operator !== k3.operator,
    ) as Party;

    // Only the drawn agent answers the check.
    const strangerRecord = await resolution(notChecker, id, hour(3));
    const refused = await post(
      notChecker.agent,
      `/entries/${id}/revalidate/resolve`,
      strangerRecord,
      hour(3),
    );
    expect([refused.status, refused.body["error"]]).toEqual([
      422,
      "not_assigned",
    ]);

    const answered = await post(
      checker.agent,
      `/entries/${id}/revalidate/resolve`,
      await resolution(checker, id, hour(3), true),
      hour(3),
    );
    expect(answered.status).toBe(200);
    // Section 12: "revalidation confirms rather than overturns."
    expect(answered.body["status"]).toBe("verified");

    const rows = await stakes(id);
    expect(rows.map((row) => row.kind)).toEqual([
      "revalidation_stake",
      "revalidation_forfeit",
    ]);
    expect(rows[1]!.amount).toBe(REVALIDATION_REQUEST_STAKE_STANDING);
  }, 240_000);

  it("refunds and rewards a check that found the fact changed", async () => {
    const id = checkedEntry["id"] as string;

    // A different operator, so the per-operator cap has room again.
    const opened = await post(
      k4.agent,
      `/entries/${id}/revalidate`,
      {},
      hour(4),
    );
    expect(opened.status).toBe(201);

    const swept = await sweep(hour(5));
    expect(swept.revalidation_drawn.length).toBe(1);
    const draw = swept.revalidation_drawn[0]!;
    expect(draw.operator).not.toBe(k4.operator);

    const checker = partyOf(draw.operator);
    const answered = await post(
      checker.agent,
      `/entries/${id}/revalidate/resolve`,
      await resolution(checker, id, hour(6), false),
      hour(6),
    );
    expect(answered.status).toBe(200);
    expect(answered.body["status"]).toBe("verified");

    const rows = await stakes(id);
    expect(rows.map((row) => row.kind)).toEqual([
      "revalidation_stake",
      "revalidation_forfeit",
      "revalidation_stake",
      "revalidation_refund",
      "revalidation_reward",
    ]);
    expect(rows[3]!.amount).toBe(REVALIDATION_REQUEST_STAKE_STANDING);
    expect([rows[4]!.unit, rows[4]!.amount]).toEqual([null, null]);
  }, 240_000);

  it("redraws the check when the drawn checker lets the window run out", async () => {
    const id = checkedEntry["id"] as string;

    // A third requester, so the per-operator cap has room again.
    const opened = await post(k5.agent, `/entries/${id}/revalidate`, {}, hour(7));
    expect(opened.status).toBe(201);

    const drew = await sweep(hour(8));
    expect(drew.revalidation_drawn.length).toBe(1);
    const first = drew.revalidation_drawn[0]!;
    expect(first.entry_id).toBe(id);
    expect(first.operator).not.toBe(k5.operator);
    const firstDeadline = (await assignmentIn(id)).assigned!.deadline;

    // Section 6: the check carries the same seventy-two hours a validation
    // assignment does, and nobody answered inside them.
    const after = hour(8 + ASSIGNMENT_WINDOW_HOURS + 1);
    expect(new Date(firstDeadline).getTime()).toBeLessThan(after.getTime());
    const late = await sweep(after);

    expect(late.revalidation_missed.length).toBe(1);
    const miss = late.revalidation_missed[0]!;
    expect([miss.entry_id, miss.request_seq, miss.agent]).toEqual([
      id,
      first.request_seq,
      first.agent,
    ]);

    const missedEvents = (await eventsForEntry(world.store.db, id)).filter(
      (event) => event.type === "revalidation_missed",
    );
    expect(missedEvents.length).toBe(1);
    expect(missedEvents[0]!.seq).toBe(miss.seq);

    // A miss closes the draw and never the request, so the check is still owed:
    // the same run's draw step finds the request open again and redraws it, to
    // an eligible operator and with a deadline counted from this run.
    expect(late.revalidation_drawn.length).toBe(1);
    const second = late.revalidation_drawn[0]!;
    expect(second.request_seq).toBe(first.request_seq);
    expect(second.seq).toBeGreaterThan(miss.seq);
    // Eligible: a trusted operator that is not the requester's own.
    expect(second.operator).not.toBe(k5.operator);
    expect(parties.map((party) => party.operator)).toContain(second.operator);

    const assigned = (await eventsForEntry(world.store.db, id)).filter(
      (event) => event.type === "revalidation_assigned",
    );
    expect(assigned[assigned.length - 1]!.seq).toBe(second.seq);

    // And the redraw is not repeated: the next run finds an assignment open.
    const quiet = await sweep(hour(8 + ASSIGNMENT_WINDOW_HOURS + 2));
    expect(quiet.revalidation_drawn).toEqual([]);
    expect(quiet.revalidation_missed).toEqual([]);
    expect(quiet.skipped["revalidation_assigned"]).toBe(1);

    // And the sidecar a reader sees carries the new draw, not the missed one.
    const view = await assignmentIn(id);
    expect(view.outcome).toBe("open");
    expect(view.assigned).toEqual({
      agent: second.agent,
      operator: second.operator,
      deadline: expect.any(String),
    });
    expect(new Date(view.assigned!.deadline).getTime()).toBeGreaterThan(
      new Date(firstDeadline).getTime(),
    );
  }, 240_000);
});

/** The newest revalidation view in the stored sidecar of one entry. */
async function assignmentIn(entryId: string): Promise<RevalidationView> {
  const row = await world.store.db
    .prepare(`SELECT sidecar_json FROM entries WHERE id = ?`)
    .bind(entryId)
    .first<{ sidecar_json: string }>();
  const sidecar = JSON.parse(row!.sidecar_json) as {
    revalidations: RevalidationView[];
  };
  const view = sidecar.revalidations[sidecar.revalidations.length - 1];
  expect(view).toBeDefined();
  return view as RevalidationView;
}

/** One signed resolution body, as the drawn checker sends it. */
async function resolution(
  party: Party,
  entryId: string,
  now: Date,
  held = true,
): Promise<Record<string, unknown>> {
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
  return { record, signature, held };
}

// ---------------------------------------------------------------------------
// (d) Failure reports and the threshold
// ---------------------------------------------------------------------------

describe("failure reports", () => {
  it("open nothing for three bare keys and a check for three operators", async () => {
    const id = reportedEntry["id"] as string;

    for (const reader of readers) {
      const answer = await post(reader, `/entries/${id}/failure-reports`, {
        observed: "the cited page 404s and no price is documented",
        artifact: artifact(reader.agentId, "40 per seat"),
      });
      expect([answer.status, answer.body["opened_revalidation"]]).toEqual([
        201,
        false,
      ]);
    }

    // A reader who files twice is the same reader saying the same thing again.
    const twice = await post(readers[0]!, `/entries/${id}/failure-reports`, {
      observed: "the same thing, again",
      artifact: artifact(readers[0]!.agentId, "again"),
    });
    expect([twice.status, twice.body["error"]]).toEqual([
      409,
      "duplicate_reporter",
    ]);

    // Section 12 counts distinct verified operators only, so the third
    // registered one is what opens the check.
    const opened: boolean[] = [];
    for (const party of [k1, k2, k3]) {
      const answer = await post(party.agent, `/entries/${id}/failure-reports`, {
        observed: `the price is wrong, seen by ${party.operator}`,
        artifact: artifact(party.agent.agentId, party.operator),
      });
      expect(answer.status).toBe(201);
      opened.push(answer.body["opened_revalidation"] === true);
    }
    expect(opened).toEqual([false, false, true]);

    const stored = await read(`/entries/${id}`);
    expect((stored.body["failure_reports"] as unknown[]).length).toBe(6);

    // The check nomankind opened at its own expense: nobody staked, so the
    // ledger has nothing to say about it.
    const events = await eventsForEntry(world.store.db, id);
    const requested = events.filter(
      (event) => event.type === "revalidation_requested",
    ) as Event<"revalidation_requested">[];
    expect(requested.length).toBe(1);
    expect(requested[0]!.payload).toEqual({
      requester: null,
      operator: null,
      source: "failure_reports",
    });
    expect(await stakes(id)).toEqual([]);
  }, 240_000);

  it("shows the opened check in the sidecar, with the source that opened it", async () => {
    const id = reportedEntry["id"] as string;
    const stored = await world.store.db
      .prepare(`SELECT sidecar_json FROM entries WHERE id = ?`)
      .bind(id)
      .first<Record<string, unknown>>();
    const sidecar = JSON.parse(
      stored!["sidecar_json"] as string,
    ) as Record<string, unknown>;
    const views = sidecar["revalidations"] as Record<string, unknown>[];
    expect(views.length).toBe(1);
    expect(views[0]).toEqual(
      expect.objectContaining({
        source: "failure_reports",
        requester: null,
        operator: null,
        outcome: "open",
      }),
    );
  }, 120_000);

  it("upgrade a reporter's own report into a dispute", async () => {
    const id = upgradedEntry["id"] as string;

    const filed = await post(k5.agent, `/entries/${id}/failure-reports`, {
      observed: "the documented price is $44, not $40",
      artifact: artifact(k5.agent.agentId, "44 per seat"),
      citation: CORRECTED_URL,
    });
    expect([filed.status, filed.body["opened_revalidation"]]).toEqual([
      201,
      false,
    ]);

    const events = await eventsForEntry(world.store.db, id);
    const report = events.find((event) => event.type === "failure_report");
    expect(report).toBeDefined();
    const reportSeq = report!.seq;

    const core = await correction(
      k5.agent,
      upgradedEntry,
      "Kestrel-5 seat pricing is $44 per seat per month, not $40",
      k5.operator,
    );
    upgradeCorrectionId = core["id"] as string;
    const upgraded = await file(k5.agent, upgradedEntry, core, {
      from_report_seq: reportSeq,
    });
    expect([upgraded.status, upgraded.body["error"] ?? null]).toEqual([
      201,
      null,
    ]);

    const target = upgraded.body["target"] as Record<string, unknown>;
    expect((target["failure_reports"] as Record<string, unknown>[])[0]).toEqual(
      expect.objectContaining({
        reporter: k5.agent.agentId,
        operator: k5.operator,
        upgraded_to: upgradeCorrectionId,
      }),
    );

    const filedEvent = (await eventsForEntry(world.store.db, id)).find(
      (event) => event.type === "dispute_filed",
    ) as Event<"dispute_filed"> | undefined;
    expect(filedEvent?.payload.from_report_seq).toBe(reportSeq);

    // A report nobody else filed is not anybody else's to upgrade.
    const stranger = await correction(
      challenger,
      upgradedEntry,
      "Kestrel-5 pricing, upgraded by a stranger",
    );
    const refused = await file(challenger, upgradedEntry, stranger, {
      from_report_seq: reportSeq,
    });
    // The open dispute is the first refusal in order; the link is checked after.
    expect([refused.status, refused.body["error"]]).toEqual([
      409,
      "dispute_open",
    ]);
  }, 240_000);
});

// ---------------------------------------------------------------------------
// (e) What the outside world sees
// ---------------------------------------------------------------------------

describe("the overturned entry", () => {
  it("reaches the delta stream as an unlearn item", async () => {
    // Seal everything, so the stream has something to deliver.
    await sweep(hour(7));

    const answer = await read("/sync?from=0");
    expect(answer.status).toBe(200);
    const items = answer.body["events"] as Record<string, unknown>[];
    const unlearn = items.filter(
      (item) =>
        item["kind"] === "unlearn" &&
        (item["event"] as Record<string, unknown>)["entry_id"] ===
          (overturnedEntry["id"] as string),
    );
    expect(unlearn.length).toBeGreaterThan(0);
    const entryOf = unlearn[0]!["entry"] as Record<string, unknown>;
    expect(entryOf["status"]).toBe("overturned");
    expect(entryOf["overturned_by"]).toBe(upheldCorrectionId);
  }, 240_000);

  it("verifies offline from its own export bundle", async () => {
    const exported = await buildExport({
      baseUrl: TEST_ORIGIN,
      entryId: overturnedEntry["id"] as string,
      http: new InProcessHttp(),
      now: hour(8),
    });
    const report = await verifyOffline(exported.entry, exported.bundle);
    expect(report.diffs).toEqual([]);
    expect(report.ok).toBe(true);
  }, 240_000);
});

// ---------------------------------------------------------------------------
// (f) Standing at the door (M21): what a filer must be able to cover
// ---------------------------------------------------------------------------

/**
 * Whitepaper Section 9: standing "gates everything discretionary, from entry to
 * and stay in the trusted pool to revalidation-request caps and dispute stakes."
 * So a registered operator that cannot cover the published stake is refused at
 * the door, with nothing written; a bare key is not gated, because Section 6 has
 * it stake a refundable fee instead.
 */
describe("a filing an operator cannot cover", () => {
  it("is refused at the dispute door, and a bare key's is not", async () => {
    const target = checkedEntry;
    const id = target["id"] as string;
    const before = (await eventsForEntry(world.store.db, id)).length;

    // Below the dispute stake, which is what the gate reads.
    await setOperatorStanding(
      world.store.db,
      k3.operator,
      DISPUTE_STAKE_STANDING - 1,
      0,
    );
    const poor = await correction(
      k3.agent,
      target,
      "Kestrel-3 seat pricing is $44 per seat per month, not $40",
      k3.operator,
    );
    const refused = await file(k3.agent, target, poor);
    expect([refused.status, refused.body["error"]]).toEqual([
      422,
      "insufficient_standing",
    ]);
    // Nothing was written: not the correction, not the challenge, not a stake.
    expect((await eventsForEntry(world.store.db, id)).length).toBe(before);

    // The same filing from a bare key is not gated: its stake is a fee.
    const bare = await correction(
      secondChallenger,
      target,
      "Kestrel-3 seat pricing is $44 per seat per month, not $40, says a reader",
    );
    const filed = await file(secondChallenger, target, bare);
    expect([filed.status, filed.body["error"] ?? null]).toEqual([201, null]);

    await fundStanding();
  }, 240_000);

  it("is refused at the revalidate door, and a bare key is refused for being one", async () => {
    const id = standingEntry["id"] as string;

    await setOperatorStanding(
      world.store.db,
      k4.operator,
      REVALIDATION_REQUEST_STAKE_STANDING - 1,
      0,
    );
    const refused = await post(k4.agent, `/entries/${id}/revalidate`, {});
    expect([refused.status, refused.body["error"]]).toEqual([
      422,
      "insufficient_standing",
    ]);
    expect(
      (await eventsForEntry(world.store.db, id)).some(
        (event) => event.type === "revalidation_requested",
      ),
    ).toBe(false);

    // A bare key never reaches the gate: it has no standing to gate.
    const bare = await post(challenger, `/entries/${id}/revalidate`, {});
    expect([bare.status, bare.body["error"]]).toEqual([422, "bare_key"]);

    // And with the stake covered, the same request opens the check.
    await fundStanding();
    const opened = await post(k4.agent, `/entries/${id}/revalidate`, {});
    expect([opened.status, opened.body["error"] ?? null]).toEqual([201, null]);
  }, 240_000);
});
