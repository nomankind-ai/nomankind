/**
 * Two writes in one tick, and which of them the log loses.
 *
 * The chain is single-file by design: an event's seq is the head's plus one and
 * its `prev_hash` is the head's hash, so two writes that land together cannot
 * both be written. That much is right. What was wrong is what the doors did
 * about it — the loser's whole batch was refused by the unique index on
 * events.seq, every door read that as the database being unreachable, and a
 * signed request that had passed every check was dropped with 503
 * `storage_unreachable`. A validation that arrived while the sweep was sealing
 * was simply lost.
 *
 * So the doors rebuild instead. `withChainRetry` runs a door's own derivation
 * and its batch again, up to three times, onto the head that moved — the
 * events' positions and hashes are the head's, so nothing but a rebuild will
 * do — and only if even that keeps losing does the caller get a refusal, and
 * then its own one (`chain_conflict`) rather than an outage that is not
 * happening.
 *
 * Three questions, in the order they matter. Does a validation survive the
 * sweep landing underneath it? Do two operators registering the same name in
 * one instant get the two honest answers rather than one honest answer and one
 * 503? And when the rebuild really does run out, is the refusal the documented
 * one?
 */

import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { FixtureBeacon } from "../src/adapters/beacon.js";
import { MockPayoutAdapter } from "../src/adapters/payout.js";
import type { Core } from "../src/core.js";
import { base64urlEncode } from "../src/encoding.js";
import type { ApproverRecord } from "../src/events.js";
import { exportPrivateKeyPkcs8, generateKeypair } from "../src/identity.js";
import { DEFAULT_DOMAIN } from "../src/policy.js";
import { signRecord } from "../src/records.js";
import { txtRecordName } from "../src/registry.js";
import type {
  D1Like,
  D1LikeResult,
  D1LikeStatement,
} from "../src/storage/d1.js";
import {
  EventAppendError,
  getEntry,
  getOperator,
  headSeq,
} from "../src/storage/repository.js";
import type { SubmissionProposal } from "../src/submit.js";
import type { Env } from "../src/worker/env.js";
import { handleRequest, type RequestDeps } from "../src/worker/index.js";
import {
  StorageUnreachable,
  unavailable,
  withChainRetry,
} from "../src/worker/registry.js";
import { runSweep } from "../src/worker/sweep.js";
import { openTestDatabase, type TestDatabase } from "./helpers/d1.js";
import {
  FixtureResolver,
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

const NOW = SUBMIT_NOW;
const AT = NOW.toISOString();

const VERIFIED_REFERENCE = "mock-verified-chain";

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

/** The name two would-be operators reach for at the same instant. */
const CONTESTED = "contested.example";

let store: TestDatabase;
let env: Env;
let deps: RequestDeps;
let maintainer: TestAgent;
let k1: Party;
let k2: Party;
let k3: Party;
let author: TestAgent;
/** The two agents that race for the contested name. */
let twinA: TestAgent;
let twinB: TestAgent;

function send(request: Request, on: Env = env): Promise<Response> {
  return handleRequest(request, on, deps);
}

/**
 * The sweep, run exactly as the alarm runs it, against the raw database.
 *
 * The fakes stand in for the world and nothing else: a fixture beacon, a fake
 * witness and a fake anchor. What it writes is real, and what it writes is the
 * point — it seals, and sealing appends an event, which is the head moving
 * under whoever else is writing.
 */
async function sweep(): Promise<void> {
  const beacon = new FixtureBeacon("chain");
  await beacon.advance(AT);
  await runSweep(
    { ...env, DB: store.db },
    {
      now: NOW,
      beacon,
      witness: new FakeWitnessAdapter(),
      pinned: pinnedSet([]),
      ineligibleAgents: new Set<string>(),
      anchor: new FakeAnchorAdapter(null),
    },
  );
}

/**
 * The database, with one other writer landing in the middle of the first batch
 * of events this handle is asked to write.
 *
 * Not a stub of the failure: the race itself, put where it happens. A door
 * reads the head, derives its events onto it, prepares the inserts and then
 * sends the batch — and this runs `race` in the gap between the last prepare
 * and the send, which is exactly the gap two isolates sharing one D1 have.
 * Everything else passes straight through to the real database, so what fails
 * is what really fails: the unique index on events.seq.
 */
function racedBy(db: D1Like, race: () => Promise<void>): D1Like {
  let armed = false;
  let done = false;
  return {
    prepare(sql: string): D1LikeStatement {
      if (sql.startsWith("INSERT INTO events")) armed = true;
      return db.prepare(sql);
    },
    async batch<Row = Record<string, unknown>>(
      statements: D1LikeStatement[],
    ): Promise<D1LikeResult<Row>[]> {
      if (armed && !done) {
        done = true;
        await race();
      }
      return db.batch<Row>(statements);
    },
    exec: (sql: string) => db.exec(sql),
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

/** One signed approval, ready to be sent at whatever instant a test chooses. */
async function approval(entryId: string, party: Party): Promise<Request> {
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
  return signedPost(party.agent, {
    path: `/entries/${entryId}/validate`,
    body: { record, signature },
    timestamp: AT,
    nonce: `approve-${party.operator}-${entryId}`,
  });
}

async function submit(subject: string): Promise<Core> {
  const core = await submittedCore(author, pricing(subject));
  const response = await send(await submission(author, { core }));
  expect(response.status).toBe(201);
  return core;
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
  twinA = await makeAgent();
  twinB = await makeAgent();
  k1 = { operator: "r1.example", agent: await makeAgent() };
  k2 = { operator: "r2.example", agent: await makeAgent() };
  k3 = { operator: "r3.example", agent: await makeAgent() };

  const records: Record<string, string[]> = {};
  for (const party of [k1, k2, k3]) {
    records[txtRecordName(party.operator)] = [party.agent.agentId];
  }
  records[txtRecordName("maintainer.example")] = [maintainer.agentId];
  // Both twins really control the contested name: the DNS step passes for each
  // of them, so the only thing between them is which one the log takes first.
  records[txtRecordName(CONTESTED)] = [twinA.agentId, twinB.agentId];

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
}, 600_000);

afterAll(async () => {
  await store?.dispose();
}, 600_000);

// ---------------------------------------------------------------------------
// A decision while the sweep is writing
// ---------------------------------------------------------------------------

describe("a validation that lands while the sweep is sealing", () => {
  it("is written, and answers 201 rather than 503", async () => {
    const core = await submit("example/osprey-sweep");
    const id = core["id"] as string;
    await send(await approval(id, k1));

    const before = await headSeq(store.db);
    // The sweep runs inside this door's write: the head it derived its event
    // onto is gone by the time the batch is sent, which is the race that used
    // to lose the decision.
    const response = await send(await approval(id, k2), {
      ...env,
      DB: racedBy(store.db, sweep),
    });

    expect([response.status, await response.json()]).toEqual([
      201,
      expect.objectContaining({ id, status: "verified" }),
    ]);
    // And the record is really in the log, at a position after the sweep's own
    // event rather than at the one it lost.
    expect(await headSeq(store.db)).toBeGreaterThan(before! + 1);
    const stored = await getEntry(store.db, id);
    expect(stored?.entry["status"]).toBe("verified");
    expect(
      (stored?.entry["approvers"] as readonly ApproverRecord[]).map(
        (one) => one.operator,
      ),
    ).toEqual([k1.operator, k2.operator]);
  }, 600_000);
});

// ---------------------------------------------------------------------------
// Two registrations of one name
// ---------------------------------------------------------------------------

describe("two operators registering the same name in one tick", () => {
  it("answers 201 and 409 operator_exists, and never 503", async () => {
    const both = await Promise.all(
      [twinA, twinB].map(async (agent) =>
        signedPost(agent, {
          path: "/operators",
          body: {
            operator: CONTESTED,
            attestation: await attestFor(agent, CONTESTED, AT),
            payout: { reference: VERIFIED_REFERENCE },
          },
          timestamp: AT,
          nonce: `twin-${agent.agentId}`,
        }),
      ),
    );

    const responses = await Promise.all(both.map((one) => send(one)));
    const answers = await Promise.all(
      responses.map(async (one) => ({
        status: one.status,
        body: (await one.json()) as Record<string, unknown>,
      })),
    );

    const statuses = answers.map((one) => one.status).sort((a, b) => a - b);
    expect(statuses).toEqual([201, 409]);
    const refused = answers.find((one) => one.status === 409)!;
    expect(refused.body["error"]).toBe("operator_exists");

    // One of them really holds the name, and the log holds one registration.
    const record = await getOperator(store.db, CONTESTED);
    expect(record?.id).toBe(CONTESTED);
  }, 600_000);
});

// ---------------------------------------------------------------------------
// When the rebuild runs out
// ---------------------------------------------------------------------------

describe("the shared retry", () => {
  it("rebuilds three times and then refuses with chain_conflict", async () => {
    let attempts = 0;
    const doomed = withChainRetry(async () => {
      attempts += 1;
      // What a door sees when the head it derived onto is already gone.
      throw new EventAppendError("bad_prev_hash", 7, "expected prev_hash x");
    });

    await expect(doomed).rejects.toMatchObject({ name: "ChainConflict" });
    expect(attempts).toBe(3);

    const answer = unavailable(
      await doomed.catch((error: unknown) => error),
      "test",
    )!;
    expect(answer.status).toBe(503);
    expect(await answer.json()).toEqual({ error: "chain_conflict" });
  }, 600_000);

  it("gives back what it was handed when the write succeeds", async () => {
    let attempts = 0;
    const answered = await withChainRetry(async () => {
      attempts += 1;
      return "written";
    });
    expect([answered, attempts]).toEqual(["written", 1]);
  }, 600_000);

  it("retries the database's own refusal of a taken position", async () => {
    let attempts = 0;
    // The same race one layer down: both writers passed the chain rule against
    // the head they read, and the index refused the second insert.
    const taken = new StorageUnreachable(
      new Error("D1_ERROR: UNIQUE constraint failed: events.seq"),
    );
    await expect(
      withChainRetry(async () => {
        attempts += 1;
        throw taken;
      }),
    ).rejects.toMatchObject({ name: "ChainConflict" });
    expect(attempts).toBe(3);
  }, 600_000);

  it("never renames a storage failure, even while the head is moving", async () => {
    let attempts = 0;
    const broken = new StorageUnreachable(new Error("D1 is not answering"));
    await expect(
      withChainRetry(async () => {
        attempts += 1;
        // Another writer really does take the next position in this same
        // moment, which is exactly the coincidence that must not rename this
        // failure: the head moving says nothing about why *this* write failed,
        // and a database that is not answering is not a race to try again.
        await sweep();
        throw broken;
      }),
    ).rejects.toBe(broken);
    expect(attempts).toBe(1);

    const answer = unavailable(broken, "test")!;
    expect(answer.status).toBe(503);
    expect(await answer.json()).toEqual({ error: "storage_unreachable" });
  }, 600_000);

  it("leaves a unique violation on anything but events.seq alone", async () => {
    let attempts = 0;
    // A name already taken inside the same batch is not a lost position, and
    // answering it as one would retry into the same wall three times and then
    // call a settled refusal a race.
    const elsewhere = new StorageUnreachable(
      new Error("D1_ERROR: UNIQUE constraint failed: operators.id"),
    );
    await expect(
      withChainRetry(async () => {
        attempts += 1;
        throw elsewhere;
      }),
    ).rejects.toBe(elsewhere);
    expect(attempts).toBe(1);
  }, 600_000);
});
