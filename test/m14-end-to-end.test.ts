/**
 * M14 end to end: validating, assigning and reaching consensus, through the
 * Worker and the sweep.
 *
 * Whitepaper, Lifecycle of an entry, Validate: three agents from distinct
 * operators, none under the submitter's own, sign approve or reject; two of
 * them volunteer and the third is drawn from the trusted pool by public
 * randomness against a pool snapshot committed before the beacon round it uses;
 * an assigned validator has seventy-two hours, and a miss draws a replacement.
 * Below ten operators two approvals verify and no draw is made at all.
 *
 * Everything here is real except the network. The requests are signed with
 * generated Ed25519 keys and verified by the Worker, the record signatures are
 * real nomankind-record-v1 signatures over the real canonical bytes, the
 * database is miniflare's D1 with the migrations applied, the entries come back
 * out of derivation and are checked against the published schema, and the sweep
 * under test is the one the cron trigger runs. Only the DNS resolver, the
 * payment provider, the page fetch and the beacon are injected, because only
 * those are not ours to run in a test, and the clock is injected because nothing
 * under src/ is allowed to read one.
 *
 * Every refusal below asserts the log's head is exactly where it was. A door
 * that refuses must leave no trace in the record, or a refused decision would
 * be a decision.
 *
 * Two worlds, two databases. The small one is under the ten-operator switch,
 * where two approvals verify and the sweep draws nothing; the large one is over
 * it, where the draw, the seventy-two-hour window and the replacement all
 * happen. They cannot share a log: a pool cannot be under and over the switch at
 * once.
 */

import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { FixtureBeacon } from "../src/adapters/beacon.js";
import { MockPayoutAdapter } from "../src/adapters/payout.js";
import type { Core } from "../src/core.js";
import { base64urlDecode, base64urlEncode } from "../src/encoding.js";
import type { ApproverRecord, Event } from "../src/events.js";
import {
  DEFAULT_DOMAIN,
  APPROVALS_TO_VERIFY_SMALL_POOL,
  ASSIGNMENT_WINDOW_HOURS,
  LIST_PAGE_LIMIT,
  TRUSTED_POOL_SWITCH,
} from "../src/policy.js";
import { signRecord } from "../src/records.js";
import { txtRecordName } from "../src/registry.js";
import { validateEntry } from "../src/schema.js";
import type { SubmissionProposal } from "../src/submit.js";
import {
  eventBySeq,
  getEntry,
  headSeq,
  openAssignment as storedAssignment,
} from "../src/storage/repository.js";
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

/** The instant every signed request in this file is served at. */
const NOW = SUBMIT_NOW;
const AT = NOW.toISOString();

/** A unit constant: the fake clock moves in whole minutes and whole hours. */
const MINUTE_MS = 60_000;
const HOUR_MS = 3_600_000;

/** An instant `minutes` after the base clock, as a Date. */
function after(minutes: number): Date {
  return new Date(NOW.getTime() + minutes * MINUTE_MS);
}

/** An instant `hours` after `from`, as a Date. */
function hoursAfter(from: Date, hours: number): Date {
  return new Date(from.getTime() + hours * HOUR_MS);
}

/** A reference the mock payment provider calls onboarded. */
const VERIFIED_REFERENCE = "mock-verified-m14";

// ---------------------------------------------------------------------------
// The pages the citations point at
// ---------------------------------------------------------------------------

const PRICING: FixturePage = {
  body: "<!doctype html><html><body><main><h1>Harrier pricing</h1><p>$30 per seat per month</p></main></body></html>",
  contentType: "text/html; charset=utf-8",
};
const LIMITS: FixturePage = {
  body: "<!doctype html><html><body><main><p>Harrier allows 90 requests per minute</p></main></body></html>",
  contentType: "text/html; charset=utf-8",
};

const PRICING_URL = "https://harrier.example/pricing";
const LIMITS_URL = "https://harrier.example/limits";

const PAGES: Record<string, FixturePage> = {
  [PRICING_URL]: PRICING,
  [LIMITS_URL]: LIMITS,
};

/**
 * The pricing page's hash under the real norm rule, computed once the crypto is
 * available. Every entry below cites that page and every approval carries this
 * same value as the validator's own snapshot hash, which is what an honest
 * validator who fetched the page for themselves would have arrived at.
 */
let PRICING_HASH = "";

// ---------------------------------------------------------------------------
// Parties
// ---------------------------------------------------------------------------

/** One operator and the agent bound to it. */
interface Party {
  readonly operator: string;
  readonly agent: TestAgent;
}

async function makeParty(operator: string): Promise<Party> {
  return { operator, agent: await makeAgent() };
}

/** One world: a database, its bindings, and the deps every request is served with. */
interface World {
  readonly store: TestDatabase;
  readonly env: Env;
  readonly deps: RequestDeps;
  readonly maintainer: TestAgent;
  readonly parties: readonly Party[];
}

async function buildWorld(operators: readonly string[]): Promise<World> {
  const store = await openTestDatabase();
  const maintainer = await makeAgent();
  const parties: Party[] = [];
  for (const operator of operators) parties.push(await makeParty(operator));

  const records: Record<string, string[]> = {};
  for (const party of parties) {
    records[txtRecordName(party.operator)] = [party.agent.agentId];
  }

  const env: Env = {
    DB: store.db,
    CAPTURES: store.captures,
    ENVIRONMENT: "local",
    MAINTAINER_AGENT_ID: maintainer.agentId,
  };
  const deps: RequestDeps = {
    now: NOW,
    dns: new FixtureResolver(records),
    payout: new MockPayoutAdapter(),
    fetcher: new FixtureFetcher(PAGES),
  };
  return { store, env, deps, maintainer, parties };
}

/** Send one request into a world, at that world's clock unless told otherwise. */
function send(
  world: World,
  request: Request,
  override: Partial<RequestDeps> = {},
): Promise<Response> {
  return handleRequest(request, world.env, { ...world.deps, ...override });
}

function get(path: string): Request {
  return new Request(`${TEST_ORIGIN}${path}`);
}

/** Register one operator through the door, exactly as an outsider would. */
async function register(world: World, party: Party): Promise<void> {
  const request = await signedPost(party.agent, {
    path: "/operators",
    body: {
      operator: party.operator,
      attestation: await attestFor(party.agent, party.operator, AT),
      payout: { reference: VERIFIED_REFERENCE },
    },
    timestamp: AT,
  });
  const response = await send(world, request);
  expect([response.status, party.operator]).toEqual([201, party.operator]);
}

/** Name one registered operator to the trusted pool, as only the maintainer may. */
async function name(world: World, party: Party): Promise<void> {
  const request = await signedPost(world.maintainer, {
    path: "/genesis",
    body: { operator: party.operator },
    timestamp: AT,
  });
  const response = await send(world, request);
  expect([response.status, party.operator]).toEqual([200, party.operator]);
}

/**
 * Bind a second agent under an operator, through the door the operator itself
 * would use: POST /operators/{id}/agents, signed by an agent the operator
 * already has, carrying the new key's own attestation.
 *
 * Section 5: "An operator runs agents", and every agent under an operator
 * counts as one for validation. The exclusion rule below is about exactly that,
 * so the second key gets there the way a real one does.
 */
async function bind(
  world: World,
  party: Party,
  bound: TestAgent,
): Promise<void> {
  const request = await signedPost(party.agent, {
    path: `/operators/${encodeURIComponent(party.operator)}/agents`,
    body: {
      agent: bound.agentId,
      attestation: await attestFor(bound, party.operator, AT),
    },
    timestamp: AT,
  });
  const response = await send(world, request);
  const body = (await response.json()) as Record<string, unknown>;
  expect([response.status, body["error"] ?? null]).toEqual([201, null]);
  expect(body["agents"]).toContain(bound.agentId);
}

/** Every party joins and is named: the pool this world validates under. */
async function joinAll(world: World): Promise<void> {
  for (const party of world.parties) {
    await register(world, party);
    await name(world, party);
  }
}

// ---------------------------------------------------------------------------
// Submissions and decisions
// ---------------------------------------------------------------------------

/** A stated pricing proposal citing the fixture page. */
function pricing(
  claim: string,
  overrides: Partial<Omit<SubmissionProposal, "author">> = {},
): Omit<SubmissionProposal, "author"> {
  return {
    subject: "example/harrier-1",
    category: "pricing",
    domain: DEFAULT_DOMAIN,
    claim,
    before: "$25 per seat per month",
    // The value is the duplicate key (decision D-085): two live entries on
    // one subject and category may not both assert it. Every entry this
    // helper builds shares a subject and a category, and none of these tests
    // is about duplicates, so each one's value names its own case, which the
    // claim already does.
    after: `$30 per seat per month, per: ${claim}`,
    effective_at: "2026-09-01",
    citation: PRICING_URL,
    snapshot_hash: PRICING_HASH,
    ...overrides,
  };
}

/** Submit one entry through the door and answer the core that went in. */
async function submit(
  world: World,
  author: TestAgent,
  proposal: Omit<SubmissionProposal, "author">,
): Promise<Core> {
  const core = await submittedCore(author, proposal);
  const response = await send(world, await submission(author, { core }));
  expect([response.status, await response.json()]).toEqual([
    201,
    expect.objectContaining({ id: core["id"], status: "draft" }),
  ]);
  return core;
}

/** The schema's approvers[] item, for a stated entry. */
function decision(
  party: Party,
  overrides: Partial<ApproverRecord> = {},
): ApproverRecord {
  return {
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
    ...overrides,
  };
}

/** One signed decision, ready for the door. */
async function validation(input: {
  entryId: string;
  record: ApproverRecord;
  /** The key that signs the record; the record's own agent unless told otherwise. */
  signingKey: TestAgent;
  /** The key that signs the request envelope; the record's own unless told otherwise. */
  signer?: TestAgent;
  /** A signature to send instead of the real one. */
  signature?: string;
  timestamp?: string;
}): Promise<Request> {
  const signature =
    input.signature ??
    (await signRecord(
      input.entryId,
      "validation",
      input.record,
      input.signingKey.privateKey,
    ));
  return signedPost(input.signer ?? input.signingKey, {
    path: `/entries/${input.entryId}/validate`,
    body: { record: input.record, signature },
    timestamp: input.timestamp ?? AT,
  });
}

// ---------------------------------------------------------------------------
// The small pool: under the switch, two approvals verify and nothing is drawn
// ---------------------------------------------------------------------------

const SMALL_OPERATORS = [
  "a1.example",
  "a2.example",
  "a3.example",
  "submitter.example",
];

describe("a small pool, under the ten-operator switch", () => {
  let world: World;
  let a1: Party;
  let a2: Party;
  let a3: Party;
  let submitterParty: Party;
  /** A second agent under the submitter's operator, for the exclusion rule. */
  let secondAgent: TestAgent;
  let verified: Core;
  let open: Core;
  let rejectedEntry: Core;

  /** The log's head, or null when nothing has been written. */
  const head = (): Promise<number | null> => headSeq(world.store.db);

  /** Send a decision that must be refused, and prove it wrote nothing. */
  async function refused(
    request: Request,
    status: number,
    error: string,
  ): Promise<Record<string, unknown>> {
    const before = await head();
    const response = await send(world, request);
    const body = (await response.json()) as Record<string, unknown>;

    expect([response.status, body["error"]]).toEqual([status, error]);
    expect(response.headers.get("cache-control")).toBe("no-store");
    expect(await head()).toBe(before);
    return body;
  }

  beforeAll(async () => {
    PRICING_HASH = await pageHash(PRICING);
    world = await buildWorld(SMALL_OPERATORS);
    [a1, a2, a3, submitterParty] = world.parties as [
      Party,
      Party,
      Party,
      Party,
    ];
    await joinAll(world);

    // A second agent under the submitter's operator, bound through the door the
    // operator would use: the joining door binds one agent per operator (a
    // second registration is refused operator_exists), and the bind door is
    // where an operator adds the next key. Section 5's rule is that every agent
    // under an operator counts as one, and this is what puts that rule in front
    // of the validate door.
    secondAgent = await makeAgent();
    await bind(world, submitterParty, secondAgent);

    // Section 5: anyone can submit with a bare agent key. The maintainer's own
    // key is a bare key here — it registered no operator — so the entry names no
    // operator and every one of the three outside operators may validate it.
    verified = await submit(
      world,
      world.maintainer,
      pricing("Harrier-1 seat pricing rose to $30 per seat per month"),
    );
    open = await submit(world, submitterParty.agent, {
      ...pricing("Harrier-1 seat pricing is listed at $30 per seat per month"),
      author_operator: submitterParty.operator,
    });
    rejectedEntry = await submit(
      world,
      world.maintainer,
      pricing("Harrier-1 seat pricing is $30 per seat per month, as published"),
    );
  }, 120_000);

  afterAll(async () => {
    await world?.store.dispose();
  });

  describe("consensus", () => {
    it("keeps the entry draft on the first approval", async () => {
      const response = await send(
        world,
        await validation({
          entryId: verified["id"] as string,
          record: decision(a1),
          signingKey: a1.agent,
        }),
      );

      expect(response.status).toBe(201);
      expect(response.headers.get("cache-control")).toBe("no-store");
      const body = (await response.json()) as Record<string, unknown>;
      expect(validateEntry(body).errors).toEqual([]);
      expect(body["status"]).toBe("draft");
      expect(body["approvers"]).toHaveLength(1);
      expect(body["verified_at"]).toBeNull();
    });

    it("verifies on the second, because the pool is under the switch", async () => {
      const record = decision(a2);
      const response = await send(
        world,
        await validation({
          entryId: verified["id"] as string,
          record,
          signingKey: a2.agent,
        }),
      );

      expect(response.status).toBe(201);
      const body = (await response.json()) as Record<string, unknown>;
      expect(validateEntry(body).errors).toEqual([]);
      expect(body["status"]).toBe("verified");
      expect(body["approvers"]).toHaveLength(APPROVALS_TO_VERIFY_SMALL_POOL);
      // Derived from the records, never sent: the promoting decision's own
      // signed_at is the moment the entry became verified.
      expect(body["verified_at"]).toBe(record.signed_at);
    });

    it("states the tier it verified at in the sidecar, beside the entry", async () => {
      const stored = await getEntry(world.store.db, verified["id"] as string);

      expect(stored?.sidecar.effective_tier).toBe("stated");
      expect(stored?.sidecar.test_verdict).toBeNull();
      expect(stored?.sidecar.trusted_count_at_decision).toBe(
        SMALL_OPERATORS.length,
      );
      expect(stored?.sidecar.needs_replacement).toBe(false);
      // The row is caught up with the log that verified it.
      expect(stored?.derivedThroughSeq).toBe(await head());
    });

    it("serves the verified entry at its own URL, exactly as it answered", async () => {
      const created = await send(
        world,
        // Signed by a registered operator's agent: the entry is minutes old and
        // the release window has not opened on it (decision D-100).
        await signedGet(world.parties[0]!.agent, {
          path: `/entries/${verified["id"] as string}`,
          timestamp: AT,
        }),
      );
      const body = (await created.json()) as Record<string, unknown>;

      expect(created.status).toBe(200);
      expect(body["status"]).toBe("verified");
      expect((body["approvers"] as unknown[]).length).toBe(
        APPROVALS_TO_VERIFY_SMALL_POOL,
      );
    });

    it("refuses a third decision on an entry that is no longer draft", async () => {
      // The verdict stands: a record counted by nobody is not sealed at all.
      await refused(
        await validation({
          entryId: verified["id"] as string,
          record: decision(a3),
          signingKey: a3.agent,
        }),
        409,
        "entry_closed",
      );
    });

    it("rejects an entry on two rejections and then closes it too", async () => {
      const id = rejectedEntry["id"] as string;
      const first = await send(
        world,
        await validation({
          entryId: id,
          record: decision(a1, {
            decision: "reject",
            reason: "the page says $30 for a different plan",
            snapshot_hash: null,
          }),
          signingKey: a1.agent,
        }),
      );
      expect(first.status).toBe(201);
      expect(((await first.json()) as Record<string, unknown>)["status"]).toBe(
        "draft",
      );

      const second = await send(
        world,
        await validation({
          entryId: id,
          record: decision(a2, {
            decision: "reject",
            reason: "the cited page does not carry this price",
            snapshot_hash: null,
          }),
          signingKey: a2.agent,
        }),
      );
      expect(second.status).toBe(201);
      const body = (await second.json()) as Record<string, unknown>;
      expect(validateEntry(body).errors).toEqual([]);
      expect(body["status"]).toBe("rejected");

      await refused(
        await validation({
          entryId: id,
          record: decision(a3),
          signingKey: a3.agent,
        }),
        409,
        "entry_closed",
      );
    });
  });

  describe("the door refuses before it writes", () => {
    it("refuses an id the schema would not accept", async () => {
      await refused(
        await validation({
          entryId: "not-an-entry-id",
          record: decision(a1),
          signingKey: a1.agent,
        }),
        400,
        "bad_id",
      );
    });

    it("refuses a body that is not a decision", async () => {
      await refused(
        await signedPost(a1.agent, {
          path: `/entries/${open["id"] as string}/validate`,
          body: { record: { agent: a1.agent.agentId }, signature: "x" },
          timestamp: AT,
        }),
        400,
        "bad_body",
      );
    });

    it("refuses a record carrying a field the schema has never heard of", async () => {
      await refused(
        await signedPost(a1.agent, {
          path: `/entries/${open["id"] as string}/validate`,
          body: {
            record: { ...decision(a1), verdict: "yes" },
            signature: "x",
          },
          timestamp: AT,
        }),
        400,
        "bad_body",
      );
    });

    it("refuses an unsigned request", async () => {
      const before = await head();
      const response = await send(
        world,
        new Request(`${TEST_ORIGIN}/entries/${open["id"] as string}/validate`, {
          method: "POST",
          body: JSON.stringify({
            record: decision(a1),
            signature: "x",
          }),
          headers: { "content-type": "application/json" },
        }),
      );

      expect(response.status).toBe(401);
      expect(await response.json()).toEqual({ error: "missing_header" });
      expect(await head()).toBe(before);
    });

    it("refuses a decision on an entry nobody submitted", async () => {
      await refused(
        await validation({
          entryId: "nmk_01M14NOSUCHENTRY",
          record: decision(a1),
          signingKey: a1.agent,
        }),
        404,
        "not_found",
      );
    });

    it("refuses a decision relayed by a key that is not the record's own", async () => {
      await refused(
        await validation({
          entryId: open["id"] as string,
          record: decision(a2),
          signingKey: a2.agent,
          signer: a1.agent,
        }),
        403,
        "agent_mismatch",
      );
    });

    it("refuses a record signed too long ago to be about now", async () => {
      await refused(
        await validation({
          entryId: open["id"] as string,
          record: decision(a1, {
            signed_at: new Date(NOW.getTime() - 24 * HOUR_MS).toISOString(),
          }),
          signingKey: a1.agent,
        }),
        422,
        "bad_signed_at",
      );
    });

    it("refuses a record signature with a byte flipped", async () => {
      const record = decision(a1);
      const real = await signRecord(
        open["id"] as string,
        "validation",
        record,
        a1.agent.privateKey,
      );
      // The signature bytes themselves, not the text: base64url's last
      // character carries spare bits, so editing the text can leave the same
      // 64 bytes behind and would test nothing.
      const bytes = base64urlDecode(real);
      bytes[0] = bytes[0]! ^ 0xff;
      const flipped = base64urlEncode(bytes);
      expect(flipped).not.toBe(real);

      await refused(
        await validation({
          entryId: open["id"] as string,
          record,
          signingKey: a1.agent,
          signature: flipped,
        }),
        422,
        "bad_record_signature",
      );
    });

    it("refuses an agent under the submitter's own operator (Section 5)", async () => {
      await refused(
        await validation({
          entryId: open["id"] as string,
          record: decision({
            operator: submitterParty.operator,
            agent: secondAgent,
          }),
          signingKey: secondAgent,
        }),
        422,
        "submitter_operator",
      );
    });

    it("accepts one decision from an outside operator", async () => {
      const response = await send(
        world,
        await validation({
          entryId: open["id"] as string,
          record: decision(a1),
          signingKey: a1.agent,
        }),
      );

      expect(response.status).toBe(201);
      const body = (await response.json()) as Record<string, unknown>;
      expect(body["status"]).toBe("draft");
      expect(body["approvers"]).toHaveLength(1);
    });

    it("refuses a second decision from the same operator", async () => {
      // Every agent under an operator counts as one, so one signature per
      // operator per entry: an entity cannot fill an entry with its own agents.
      await refused(
        await validation({
          entryId: open["id"] as string,
          record: decision(a1, { signed_at: after(1).toISOString() }),
          signingKey: a1.agent,
        }),
        422,
        "duplicate_operator",
      );
    });

    it("refuses a record the entry schema would not accept, and writes nothing", async () => {
      // An expanded-year timestamp: a real instant JavaScript parses, and not
      // the date-time the schema's format allows. Every rule before the schema
      // passes, so this is the schema's own refusal and nothing else's.
      const body = await refused(
        await validation({
          entryId: open["id"] as string,
          record: decision(a3, { signed_at: "+002026-09-08T12:00:00.000Z" }),
          signingKey: a3.agent,
        }),
        422,
        "schema_invalid",
      );

      expect(
        (body["errors"] as { path: string }[]).map((error) => error.path),
      ).toContain("/approvers/1/signed_at");
    });

    it("answers 405 with an Allow header on another method", async () => {
      const response = await send(
        world,
        new Request(
          `${TEST_ORIGIN}/entries/${open["id"] as string}/validate`,
          { method: "GET" },
        ),
      );

      expect(response.status).toBe(405);
      expect(response.headers.get("allow")).toBe("POST");
    });
  });

  describe("the sweep under the switch", () => {
    let report: SweepReport;

    beforeAll(async () => {
      report = await runSweep(world.env, {
        now: after(5),
        beacon: await advanced(new FixtureBeacon("m14-small"), after(4)),
      });
    });

    it("commits exactly one pool snapshot, naming the trusted pool", async () => {
      expect(report.snapshot?.operators).toEqual([...SMALL_OPERATORS].sort());
      expect(report.snapshot?.seq).toBeGreaterThan(0);
      const event = await eventBySeq(
        world.store.db,
        report.snapshot?.seq as number,
      );
      expect(event?.type).toBe("pool_snapshot");
      expect(event?.at).toBe(after(5).toISOString());
    });

    it("draws nobody, because below ten operators there is no draw at all", () => {
      expect(report.drawn).toEqual([]);
      expect(report.missed).toEqual([]);
      // One draft entry is left in this world, and the rule that passes it over
      // is the pool size and not the beacon.
      expect(report.skipped["pool_below_switch"]).toBe(1);
      expect(report.skipped["snapshot_after_beacon"]).toBeUndefined();
    });

    it("commits nothing a second time, because the pool has not moved", async () => {
      const before = await head();
      const again = await runSweep(world.env, {
        now: after(10),
        beacon: await advanced(new FixtureBeacon("m14-small"), after(9)),
      });

      expect(again.snapshot).toBeNull();
      expect(again.drawn).toEqual([]);
      expect(await head()).toBe(before);
    });
  });
});

/** A fixture beacon advanced one round, at the instant the caller names. */
async function advanced(
  beacon: FixtureBeacon,
  at: Date,
): Promise<FixtureBeacon> {
  await beacon.advance(at.toISOString());
  return beacon;
}

// ---------------------------------------------------------------------------
// The large pool: over the switch, the draw and the seventy-two-hour window
// ---------------------------------------------------------------------------

/** Two more than the switch, so the pool is comfortably over it. */
const LARGE_OPERATORS = Array.from(
  { length: TRUSTED_POOL_SWITCH + 2 },
  (_, index) => `b${index + 1}.example`,
);

describe("a large pool, over the ten-operator switch", () => {
  let world: World;
  let beacon: FixtureBeacon;
  let submitterParty: Party;
  let volunteer: Party;
  let assignedEntry: Core;
  let expiringEntry: Core;

  /** The operator drawn for the assigned entry, once the sweep has drawn one. */
  let drawnOperator = "";

  const head = (): Promise<number | null> => headSeq(world.store.db);

  /** The party behind an operator id. */
  const partyFor = (operator: string): Party =>
    world.parties.find((party) => party.operator === operator) as Party;

  /** The `answered_seq` column of an entry's newest assignment row. */
  async function answeredSeq(entryId: string): Promise<number | null> {
    const row = await world.store.db
      .prepare(
        `SELECT answered_seq FROM assignments WHERE entry_id = ? ORDER BY seq DESC LIMIT 1`,
      )
      .bind(entryId)
      .first<{ answered_seq: number | null }>();
    return row === null ? null : row.answered_seq;
  }

  beforeAll(async () => {
    PRICING_HASH = await pageHash(PRICING);
    world = await buildWorld(LARGE_OPERATORS);
    submitterParty = world.parties[0] as Party;
    volunteer = world.parties[1] as Party;
    await joinAll(world);

    beacon = new FixtureBeacon("m14-large");
    // Round 1 is older than the snapshot the first sweep will commit, which is
    // exactly the ordering the paper requires and exactly why that sweep draws
    // nothing.
    await beacon.advance(NOW.toISOString());

    assignedEntry = await submit(world, submitterParty.agent, {
      ...pricing("Harrier-1 seat pricing went to $30 per seat per month"),
      author_operator: submitterParty.operator,
    });
  }, 180_000);

  afterAll(async () => {
    await world?.store.dispose();
  });

  describe("the pool snapshot comes before the round that uses it", () => {
    it("takes one volunteer's approval with no assignment open", async () => {
      const response = await send(
        world,
        await validation({
          entryId: assignedEntry["id"] as string,
          record: decision(volunteer),
          signingKey: volunteer.agent,
        }),
      );

      expect(response.status).toBe(201);
      const body = (await response.json()) as Record<string, unknown>;
      // Three approvals verify over the switch, so one is not enough.
      expect(body["status"]).toBe("draft");
      expect(body["approvers"]).toHaveLength(1);
    });

    it("commits the snapshot and draws nothing on the run that commits it", async () => {
      const report = await runSweep(world.env, { now: after(1), beacon });

      expect(report.snapshot?.operators).toEqual([...LARGE_OPERATORS].sort());
      expect(report.drawn).toEqual([]);
      // The round this run can read precedes the snapshot it would draw
      // against, so the entry waits rather than being drawn against a
      // commitment made after the round.
      expect(report.skipped["snapshot_after_beacon"]).toBe(1);
    });

    it("draws one validator on the next round", async () => {
      await beacon.advance(after(2).toISOString());
      const report = await runSweep(world.env, { now: after(3), beacon });

      expect(report.snapshot).toBeNull();
      expect(report.drawn).toHaveLength(1);
      const draw = report.drawn[0]!;
      expect(draw.entry_id).toBe(assignedEntry["id"]);
      expect(draw.replacement).toBe(false);
      expect(draw.beacon_round).toBe(2);
      // Neither the submitter's operator nor one that already signed.
      expect(draw.operator).not.toBe(submitterParty.operator);
      expect(draw.operator).not.toBe(volunteer.operator);
      expect(draw.agent).toBe(partyFor(draw.operator).agent.agentId);
      drawnOperator = draw.operator;

      const stored = await getEntry(
        world.store.db,
        assignedEntry["id"] as string,
      );
      expect(stored?.derivedThroughSeq).toBe(draw.seq);
    });

    it("opens the assignment with a seventy-two-hour deadline", async () => {
      const open = await storedAssignment(
        world.store.db,
        assignedEntry["id"] as string,
      );

      expect(open?.operator).toBe(drawnOperator);
      expect(open?.deadline).toBe(
        hoursAfter(after(3), ASSIGNMENT_WINDOW_HOURS).toISOString(),
      );
      expect(open?.replacement).toBe(false);
    });

    it("refuses a volunteer claiming the draw they do not hold", async () => {
      const impostor = world.parties.find(
        (party) =>
          party.operator !== drawnOperator &&
          party.operator !== submitterParty.operator &&
          party.operator !== volunteer.operator,
      ) as Party;
      const before = await head();

      const response = await send(
        world,
        await validation({
          entryId: assignedEntry["id"] as string,
          record: decision(impostor, { assigned_random: true }),
          signingKey: impostor.agent,
          timestamp: after(3).toISOString(),
        }),
        { now: after(3) },
      );

      expect([response.status, await response.json()]).toEqual([
        422,
        { error: "assigned_random_without_assignment" },
      ]);
      expect(await head()).toBe(before);
    });

    it("takes the drawn validator's decision and closes the assignment", async () => {
      const drawn = partyFor(drawnOperator);
      const response = await send(
        world,
        await validation({
          entryId: assignedEntry["id"] as string,
          record: decision(drawn, {
            assigned_random: true,
            signed_at: after(3).toISOString(),
          }),
          signingKey: drawn.agent,
          timestamp: after(3).toISOString(),
        }),
        { now: after(3) },
      );

      expect(response.status).toBe(201);
      const body = (await response.json()) as Record<string, unknown>;
      expect(validateEntry(body).errors).toEqual([]);
      expect(body["approvers"]).toHaveLength(2);
      // Two approvals do not verify over the switch: the third is still owed.
      expect(body["status"]).toBe("draft");

      expect(
        await storedAssignment(world.store.db, assignedEntry["id"] as string),
      ).toBeNull();
      expect(await answeredSeq(assignedEntry["id"] as string)).toBe(
        await head(),
      );
    });
  });

  describe("a missed window draws a replacement", () => {
    /** Every operator the entry has drawn, in the order the sweep drew them. */
    const drawnInOrder: string[] = [];
    let firstDraw: Date;

    beforeAll(async () => {
      expiringEntry = await submit(world, submitterParty.agent, {
        ...pricing("Harrier-1 request limits rose to 90 per minute"),
        category: "limit",
        before: "60 requests per minute",
        after: "90 requests per minute",
        citation: LIMITS_URL,
        snapshot_hash: await pageHash(LIMITS),
        author_operator: submitterParty.operator,
      });

      firstDraw = after(4);
      await beacon.advance(after(3).toISOString());
      const first = await runSweep(world.env, { now: firstDraw, beacon });
      expect(first.drawn).toHaveLength(1);
      drawnInOrder.push(first.drawn[0]!.operator);
    }, 60_000);

    it("marks the assignment missed and redraws, once past the deadline", async () => {
      const late = hoursAfter(firstDraw, ASSIGNMENT_WINDOW_HOURS + 1);
      await beacon.advance(hoursAfter(firstDraw, ASSIGNMENT_WINDOW_HOURS).toISOString());
      const report = await runSweep(world.env, { now: late, beacon });

      expect(report.missed).toHaveLength(1);
      expect(report.missed[0]!.entry_id).toBe(expiringEntry["id"]);
      expect(report.missed[0]!.operator).toBe(drawnInOrder[0]);

      expect(report.drawn).toHaveLength(1);
      const draw = report.drawn[0]!;
      expect(draw.entry_id).toBe(expiringEntry["id"]);
      expect(draw.replacement).toBe(true);
      expect(draw.operator).not.toBe(drawnInOrder[0]);
      expect(draw.operator).not.toBe(submitterParty.operator);
      drawnInOrder.push(draw.operator);
    });

    it("never draws an operator that already missed this entry", async () => {
      const later = hoursAfter(firstDraw, 2 * ASSIGNMENT_WINDOW_HOURS + 2);
      await beacon.advance(
        hoursAfter(firstDraw, 2 * ASSIGNMENT_WINDOW_HOURS).toISOString(),
      );
      const report = await runSweep(world.env, { now: later, beacon });

      expect(report.missed.map((miss) => miss.operator)).toEqual([
        drawnInOrder[1],
      ]);
      expect(report.drawn).toHaveLength(1);
      const draw = report.drawn[0]!;
      expect(draw.replacement).toBe(true);
      expect(drawnInOrder).not.toContain(draw.operator);
      expect(draw.operator).not.toBe(submitterParty.operator);
    });

    it("leaves the answered entry alone, because it owes no draw", async () => {
      const report = await runSweep(world.env, {
        now: hoursAfter(firstDraw, 2 * ASSIGNMENT_WINDOW_HOURS + 3),
        beacon,
      });

      expect(report.drawn).toEqual([]);
      // The entry whose drawn validator answered is waiting on volunteers, and
      // the one just redrawn has an assignment standing.
      expect(report.skipped["awaiting_volunteers"]).toBe(1);
      expect(report.skipped["assignment_open"]).toBe(1);
    });
  });

  describe("the log, paged", () => {
    it("pages in seq order and says where the head is", async () => {
      const response = await send(world, get("/events?limit=3"));

      expect(response.status).toBe(200);
      expect(response.headers.get("cache-control")).toBe("no-store");
      const body = (await response.json()) as { events: Event[]; head: number };
      expect(body.events.map((event) => event.seq)).toEqual([0, 1, 2]);
      expect(body.head).toBe(await head());
      // The chain, as stored: seq 0 opens it and each event names the one before.
      expect(body.events[0]!.prev_hash).toBeNull();
      expect(body.events[1]!.prev_hash).toBe(body.events[0]!.hash);
    });

    it("resumes strictly after the position the caller already has", async () => {
      const response = await send(world, get("/events?after=2&limit=3"));
      const body = (await response.json()) as { events: Event[] };

      expect(body.events.map((event) => event.seq)).toEqual([3, 4, 5]);
    });

    it("answers the tail of the log with an empty page", async () => {
      const at = (await head()) as number;
      const response = await send(world, get(`/events?after=${at}`));
      const body = (await response.json()) as { events: Event[]; head: number };

      expect(body.events).toEqual([]);
      expect(body.head).toBe(at);
    });

    for (const query of [
      "limit=0",
      "limit=-1",
      "limit=abc",
      `limit=${LIST_PAGE_LIMIT + 1}`,
      "after=-1",
      "after=1.5",
    ]) {
      it(`refuses /events?${query}`, async () => {
        const response = await send(world, get(`/events?${query}`));

        expect(response.status).toBe(400);
        expect(await response.json()).toEqual({ error: "bad_query" });
      });
    }

    it("answers 405 with an Allow header on another method", async () => {
      const response = await send(
        world,
        new Request(`${TEST_ORIGIN}/events`, { method: "POST" }),
      );

      expect(response.status).toBe(405);
      expect(response.headers.get("allow")).toBe("GET");
    });
  });
});
