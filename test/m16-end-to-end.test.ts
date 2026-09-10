/**
 * M16 end to end: sealing, witnessing and anchoring, through the Worker and the
 * sweep.
 *
 * Whitepaper, Lifecycle of an entry (Seal): "Everything gets sealed, including
 * drafts and rejections ... The hash of each entry is sealed as a fingerprint
 * into that agent's log at submission, draft state and all, and every later
 * event ... is hashed into the day's batch and sealed the same way, with the
 * registry head countersigned by witnesses nomankind does not control ... at an
 * initial interval of five minutes set by policy ... Anyone can verify, offline,
 * that an entry or event existed, who signed it, and that it has not changed."
 * And beside it: "Anchoring each day's batch hash into an external public
 * timestamping chain ... makes the existence proof independent of 1F916's
 * maturity."
 *
 * So this file seals a real log and then asks a stranger's questions of it. A
 * draft that nobody validated and an entry two operators rejected are sealed
 * exactly like the verified one; every event in the log has an inclusion proof
 * that recomputes against the seal's root; the witnesses are real Ed25519
 * countersignatures over the real seal hash, and the ones the rule refuses — a
 * witness under the maintainer's operator, nomankind's own agent, a second key
 * under an operator that already signed — never reach the log; the day's roots
 * are anchored once and not rebuilt; and the offline verifier answers ok on the
 * two files the export writes.
 *
 * Everything is real except the network and the clock. The database is
 * miniflare's D1 with every migration applied, the archive is miniflare's R2,
 * every key is generated through WebCrypto and every signature is made by it,
 * and the sweep under test is the one the Durable Object's alarm runs. Only the
 * DNS resolver, the payment provider, the page fetch, the beacon, the witness
 * adapter and the timestamping chain are injected, because only those are not
 * ours to run in a test.
 */

import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { FixtureBeacon } from "../src/adapters/beacon.js";
import { MockPayoutAdapter } from "../src/adapters/payout.js";
import { utcDay } from "../src/anchor.js";
import { buildExport } from "../src/cli/export.js";
import type { Core } from "../src/core.js";
import type { ApproverRecord, Event } from "../src/events.js";
import { decodeProof, verifyInclusion } from "../src/merkle.js";
import { DEFAULT_DOMAIN, LIST_PAGE_LIMIT, WITNESSES_REQUIRED } from "../src/policy.js";
import { signRecord } from "../src/records.js";
import { txtRecordName } from "../src/registry.js";
import { validateEntry } from "../src/schema.js";
import { buildSeal, type Seal } from "../src/seal.js";
import type {
  D1Like,
  D1LikeResult,
  D1LikeStatement,
} from "../src/storage/d1.js";
import {
  eventsAfter,
  getAnchor,
  getEntry,
  headSeq,
  latestSeal,
  putSeal,
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
  makeWitness,
  pinnedSet,
  type FakeWitness,
} from "./helpers/witness.js";

/** Day 0: the instant every registration, submission and decision is served at. */
const NOW = SUBMIT_NOW;
const AT = NOW.toISOString();

/** A unit constant: the fake clock moves in whole days. */
const DAY_MS = 86_400_000;

/** The instant `days` after day 0, at the same time of day. */
function day(days: number): Date {
  return new Date(NOW.getTime() + days * DAY_MS);
}

/** A reference the mock payment provider calls onboarded. */
const VERIFIED_REFERENCE = "mock-verified-m16";

/** The receipt a fake calendar answers with. */
const OTS_RECEIPT = {
  kind: "opentimestamps" as const,
  calendar: "https://calendar.example/",
  submitted_at: day(1).toISOString(),
  proof: "AAAA",
};

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
/** The three trusted operators of the paper's small-pool checkpoint. */
let k1: Party;
let k2: Party;
let k3: Party;
/** The maintainer's own operator: registered, never trusted, never a witness. */
let maintainerParty: Party;
/** A bare key that submits: it names no operator, so every k may judge it. */
let author: TestAgent;

/** The entry nobody ever validated. */
let draftEntry: Core;
/** The entry two operators rejected. */
let rejectedEntry: Core;
/** The entry two operators approved. */
let verifiedEntry: Core;

/** The pinned witness set, and who is in it. */
let w1: FakeWitness;
let w2: FakeWitness;
let w3: FakeWitness;
/** A second key under w1's operator: one witness, not two (D-033). */
let w1SecondKey: FakeWitness;
/** A witness under the maintainer's own operator. */
let maintainerWitness: FakeWitness;
/** A witness that is nomankind's own agent, whatever operator files it. */
let ineligibleWitness: FakeWitness;

async function makeParty(operator: string): Promise<Party> {
  return { operator, agent: await makeAgent() };
}

/** Send one request, at day 0 unless the caller names another instant. */
function send(request: Request, now: Date = NOW): Promise<Response> {
  return handleRequest(request, world.env, { ...world.deps, now });
}

function get(path: string): Request {
  return new Request(`${TEST_ORIGIN}${path}`);
}

/** One GET, with its status and whatever JSON came back. */
async function read(
  path: string,
): Promise<{ status: number; body: Record<string, unknown> }> {
  const response = await send(get(path));
  expect(response.headers.get("cache-control")).toBe("no-store");
  return {
    status: response.status,
    body: (await response.json()) as Record<string, unknown>,
  };
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
    subject: "kestrel/kestrel-1",
    category: "pricing",
    domain: DEFAULT_DOMAIN,
    claim,
    before: "$35 per seat per month",
    after: "$40 per seat per month",
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

/** One signed decision, through the real door. */
async function decide(
  entryId: string,
  party: Party,
  overrides: Partial<ApproverRecord> = {},
): Promise<Record<string, unknown>> {
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
    ...overrides,
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
  return (await response.json()) as Record<string, unknown>;
}

/** The stored row for one entry, which is what the public read serves. */
async function stored(entryId: string): Promise<Record<string, unknown>> {
  const row = await getEntry(world.store.db, entryId);
  expect(row).not.toBeNull();
  return row!.entry as unknown as Record<string, unknown>;
}

/** The whole log, as it is stored. */
function logEvents(): Promise<Event[]> {
  return eventsAfter(world.store.db, -1, LIST_PAGE_LIMIT);
}

/** The pinned set every run judges countersignatures against. */
function pinned(): ReturnType<typeof pinnedSet> {
  return pinnedSet([
    w1,
    w2,
    w3,
    w1SecondKey,
    maintainerWitness,
    ineligibleWitness,
  ]);
}

/** Nomankind's own agents: the maintainer's, and one witness that is ours. */
function ineligibleAgents(): Set<string> {
  return new Set([
    world.maintainer.agentId,
    ineligibleWitness.witness.agent,
  ]);
}

/** Run the sweep the alarm runs, with the fakes standing in for the world. */
async function sweep(input: {
  at: Date;
  witness: FakeWitnessAdapter;
  anchor?: FakeAnchorAdapter;
  db?: D1Like;
}): Promise<SweepReport> {
  const beacon = new FixtureBeacon("m16");
  await beacon.advance(input.at.toISOString());
  return runSweep(
    input.db === undefined ? world.env : { ...world.env, DB: input.db },
    {
      now: input.at,
      beacon,
      witness: input.witness,
      pinned: pinned(),
      ineligibleAgents: ineligibleAgents(),
      anchor: input.anchor ?? new FakeAnchorAdapter(null),
    },
  );
}

// ---------------------------------------------------------------------------
// The world, built once
// ---------------------------------------------------------------------------

beforeAll(async () => {
  PRICING_HASH = await pageHash(PRICING);

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
    },
    deps: {
      now: NOW,
      dns: new FixtureResolver(records),
      payout: new MockPayoutAdapter(),
      fetcher: new FixtureFetcher(PAGES),
    },
    maintainer,
  };

  // Three trusted operators, and the maintainer's own operator beside them:
  // registered so the log flags it as the maintainer's, and never named to the
  // pool, because Section 11 forbids naming it.
  for (const party of [k1, k2, k3]) {
    await register(party);
    await name(party);
  }
  await register(maintainerParty);

  // Everything gets sealed, drafts and rejections included, so the world holds
  // one of each.
  draftEntry = await submit("Kestrel-1 seat pricing is $40 per seat per month");
  rejectedEntry = await submit(
    "Kestrel-1 seat pricing rose to $40 per seat per month",
  );
  verifiedEntry = await submit(
    "Kestrel-1 seat pricing is listed at $40 per seat per month",
  );

  await decide(verifiedEntry["id"] as string, k1);
  const verified = await decide(verifiedEntry["id"] as string, k2);
  expect(verified["status"]).toBe("verified");

  const rejection = { decision: "reject" as const, reason: "The page does not say this." };
  await decide(rejectedEntry["id"] as string, k1, rejection);
  const rejected = await decide(rejectedEntry["id"] as string, k2, rejection);
  expect(rejected["status"]).toBe("rejected");

  // The pinned witness directory: three independent operators, a second key
  // under the first of them, one under the maintainer's operator, and one that
  // is nomankind's own agent.
  w1 = await makeWitness("witness-a.example");
  w2 = await makeWitness("witness-b.example");
  w3 = await makeWitness("witness-c.example");
  w1SecondKey = await makeWitness("witness-a.example");
  maintainerWitness = await makeWitness(maintainerParty.operator);
  ineligibleWitness = await makeWitness("witness-d.example");
}, 180_000);

afterAll(async () => {
  await world?.store.dispose();
});

// ---------------------------------------------------------------------------
// (e) The seal
// ---------------------------------------------------------------------------

describe("the first sweep seals the whole log", () => {
  let report: SweepReport;
  let seal: Seal;
  let head: number;

  beforeAll(async () => {
    // The only countersignatures offered are the two the rule refuses, so this
    // run seals and gathers nothing.
    report = await sweep({
      at: NOW,
      witness: new FakeWitnessAdapter({
        signers: [maintainerWitness, ineligibleWitness],
      }),
    });
    head = (await headSeq(world.store.db)) as number;
    seal = (await latestSeal(world.store.db)) as Seal;
  }, 120_000);

  it("makes one seal covering every event up to the head", () => {
    expect(report.sealed).not.toBeNull();
    expect(seal).not.toBeNull();
    expect([seal.seq, seal.first_seq, seal.last_seq]).toEqual([0, 0, head]);
    expect(seal.size).toBe(head + 1);
    expect(seal.prev_hash).toBeNull();
    expect(report.sealed).toEqual({
      seq: 0,
      first_seq: 0,
      last_seq: head,
      size: head + 1,
      entries: expect.arrayContaining([
        draftEntry["id"],
        rejectedEntry["id"],
        verifiedEntry["id"],
      ]),
    });
  });

  it("proves every event in the log against the seal's root", async () => {
    const events = await logEvents();
    expect(events).toHaveLength(head + 1);

    for (const event of events) {
      const answer = await read(`/events/${event.seq}/proof`);
      expect([answer.status, event.seq]).toEqual([200, event.seq]);
      expect(answer.body["hash"]).toBe(event.hash);
      expect(answer.body["seal"]).toEqual({
        seq: seal.seq,
        root: seal.root,
        hash: seal.hash,
        sealed_at: seal.sealed_at,
      });

      const proof = decodeProof(answer.body["inclusion_proof"] as string);
      expect(proof).not.toBeNull();
      expect(await verifyInclusion(event.hash, proof!, seal.root)).toBe(true);
    }
  }, 120_000);

  it("seals the draft and the rejected entry like everything else", async () => {
    const events = await logEvents();
    for (const core of [draftEntry, rejectedEntry]) {
      const id = core["id"] as string;
      const entry = await stored(id);
      const submitted = events.find(
        (event) => event.type === "entry_submitted" && event.entry_id === id,
      );

      const sealObject = entry["seal"] as Record<string, unknown>;
      expect(sealObject).not.toBeNull();
      expect(sealObject["log"]).toBe("1F916");
      expect(sealObject["position"]).toBe(submitted!.seq);
      expect(sealObject["sealed_at"]).toBe(seal.sealed_at);

      const proof = decodeProof(sealObject["inclusion_proof"] as string);
      expect(proof).not.toBeNull();
      expect(await verifyInclusion(submitted!.hash, proof!, seal.root)).toBe(
        true,
      );
      // The row is still what the schema says an entry is.
      expect(validateEntry(entry).errors).toEqual([]);
    }
    // A rejection is sealed exactly like a verified entry.
    expect((await stored(rejectedEntry["id"] as string))["status"]).toBe(
      "rejected",
    );
  }, 120_000);

  it("refuses the maintainer's witness and nomankind's own agent", async () => {
    // Both were offered and neither was kept: the first is refused for its
    // operator, the second for being ours whatever operator files it.
    expect(report.witnessed).toEqual([]);
    expect(report.skipped["maintainer_witness"]).toBe(2);
    expect(report.skipped["witness_pending"]).toBe(1);
    expect(seal.witnesses).toEqual([]);
    expect(
      (await stored(draftEntry["id"] as string))["seal"],
    ).toMatchObject({ witnesses: [] });
  });
});

// ---------------------------------------------------------------------------
// (f) The witnesses
// ---------------------------------------------------------------------------

describe("the witness step", () => {
  let report: SweepReport;
  let seal: Seal;

  beforeAll(async () => {
    // The three good witnesses, with a second key under the first one's
    // operator offered between them.
    report = await sweep({
      at: NOW,
      witness: new FakeWitnessAdapter({ signers: [w1, w1SecondKey, w2, w3] }),
    });
    seal = (await latestSeal(world.store.db)) as Seal;
  }, 120_000);

  it("seals nothing when no event was appended since the last seal", () => {
    expect(report.sealed).toBeNull();
    expect(report.skipped["nothing_to_seal"]).toBe(1);
  });

  it("keeps one signature per operator, the earlier of the two", () => {
    expect(report.witnessed).toEqual([
      {
        seq: 0,
        operators: [w1.witness.operator, w2.witness.operator, w3.witness.operator],
      },
    ]);
    expect(report.skipped["duplicate_operator"]).toBe(1);
    expect(seal.witnesses.map((signature) => signature.agent)).toEqual([
      w1.witness.agent,
      w2.witness.agent,
      w3.witness.agent,
    ]);
    // The bar the seal had to clear is the published one, not a number here.
    expect(seal.witnesses.length).toBeGreaterThanOrEqual(WITNESSES_REQUIRED);
  });

  it("writes the countersignatures onto every entry the seal covers", async () => {
    const signatures = seal.witnesses.map((witness) => witness.signature);
    for (const core of [draftEntry, rejectedEntry, verifiedEntry]) {
      const entry = await stored(core["id"] as string);
      expect((entry["seal"] as Record<string, unknown>)["witnesses"]).toEqual(
        signatures,
      );
      expect(validateEntry(entry).errors).toEqual([]);
    }
  });

  it("gathers nothing more once the seal is witnessed", async () => {
    const again = await sweep({
      at: NOW,
      witness: new FakeWitnessAdapter({ signers: [w1, w2, w3] }),
    });

    expect(again.witnessed).toEqual([]);
    expect(again.skipped["already_witnessed"]).toBe(1);
    const unchanged = (await latestSeal(world.store.db)) as Seal;
    expect(unchanged.witnesses).toEqual(seal.witnesses);
  }, 120_000);
});

// ---------------------------------------------------------------------------
// The offline verifier, on the two files the export writes
// ---------------------------------------------------------------------------

describe("the offline verifier, on a sealed entry", () => {
  it("answers ok with zero diffs", async () => {
    const exported = await buildExport({
      baseUrl: TEST_ORIGIN,
      entryId: verifiedEntry["id"] as string,
      http: { fetch: (request: Request) => send(request) },
      now: NOW,
    });

    // The bundle carries the seal chain now, paged out of GET /seals.
    expect(exported.bundle.seals).toHaveLength(1);
    expect(exported.bundle.seals[0]!.seq).toBe(0);

    const report = await verifyOffline(exported.entry, exported.bundle);

    expect(report.diffs).toEqual([]);
    expect(report.ok).toBe(true);
    expect(report.entry_id).toBe(verifiedEntry["id"]);
  }, 120_000);
});

// ---------------------------------------------------------------------------
// The routes
// ---------------------------------------------------------------------------

describe("the seal, proof and anchor routes", () => {
  it("pages the seal chain and names its head", async () => {
    const listed = await read("/seals");

    expect(listed.status).toBe(200);
    expect(listed.body["head"]).toBe(0);
    const seals = listed.body["seals"] as Seal[];
    expect(seals).toHaveLength(1);
    expect(seals[0]!.hash).toBe((await latestSeal(world.store.db))!.hash);

    // `after` is exclusive, so asking after the head answers an empty page.
    const empty = await read("/seals?after=0");
    expect(empty.status).toBe(200);
    expect(empty.body["seals"]).toEqual([]);
    expect(empty.body["head"]).toBe(0);
  });

  it("answers one seal, and 404 for one that does not exist", async () => {
    const one = await read("/seals/0");
    expect(one.status).toBe(200);
    expect(one.body["seq"]).toBe(0);

    expect(await read("/seals/9999")).toEqual({
      status: 404,
      body: { error: "not_found" },
    });
  });

  it("refuses a bad query, a bad id and a method that is not GET", async () => {
    expect(await read("/seals?limit=0")).toEqual({
      status: 400,
      body: { error: "bad_query" },
    });
    expect(await read(`/seals?limit=${LIST_PAGE_LIMIT + 1}`)).toEqual({
      status: 400,
      body: { error: "bad_query" },
    });
    expect(await read("/seals?after=x")).toEqual({
      status: 400,
      body: { error: "bad_query" },
    });
    expect(await read("/seals/nope")).toEqual({
      status: 400,
      body: { error: "bad_id" },
    });

    const posted = await send(
      new Request(`${TEST_ORIGIN}/seals`, { method: "POST" }),
    );
    expect(posted.status).toBe(405);
    expect(posted.headers.get("allow")).toBe("GET");
  });

  it("refuses a proof for an event the log does not hold", async () => {
    expect(await read("/events/9999/proof")).toEqual({
      status: 404,
      body: { error: "not_found" },
    });
    expect(await read("/events/nope/proof")).toEqual({
      status: 400,
      body: { error: "bad_id" },
    });
  });

  it("answers the anchors, and refuses a day that is not a day", async () => {
    const listed = await read("/anchors");
    expect(listed.status).toBe(200);
    // Nothing is anchored yet: yesterday had no seals at all.
    expect(listed.body["anchors"]).toEqual([]);

    expect(await read("/anchors/nope")).toEqual({
      status: 400,
      body: { error: "bad_id" },
    });
    expect(await read(`/anchors/${utcDay(AT)}`)).toEqual({
      status: 404,
      body: { error: "not_found" },
    });
    expect(await read("/anchors?after=nope")).toEqual({
      status: 400,
      body: { error: "bad_query" },
    });
  });
});

// ---------------------------------------------------------------------------
// The racing timer
// ---------------------------------------------------------------------------

/**
 * A database that lets another timer in at exactly the wrong moment.
 *
 * The race the plain INSERT exists to lose is one no test can wait for: two
 * sweeps read the same head and both build the same seal seq. So the racing
 * seal is written by this wrapper, in the instant between `recordSeal`
 * preparing its INSERT and the batch that runs it — which is precisely where a
 * second timer would land — and everything else goes straight through to the
 * real D1.
 */
function racedDatabase(db: D1Like, racing: Seal): D1Like {
  let arming = false;
  let raced = false;
  return {
    prepare(sql: string): D1LikeStatement {
      if (sql.includes("INSERT INTO seals")) arming = true;
      return db.prepare(sql);
    },
    async batch<Row = Record<string, unknown>>(
      statements: D1LikeStatement[],
    ): Promise<D1LikeResult<Row>[]> {
      if (arming && !raced) {
        raced = true;
        await putSeal(db, racing);
      }
      return db.batch<Row>(statements);
    },
    exec: (sql: string) => db.exec(sql),
  };
}

describe("a second timer that sealed the same range first", () => {
  it("counts the conflict and leaves the other seal standing", async () => {
    // Something new to seal: one more entry, submitted through the door.
    const fourth = await submit("Kestrel-1 lists $40 per seat per month today");

    const previous = (await latestSeal(world.store.db)) as Seal;
    const pending = await eventsAfter(
      world.store.db,
      previous.last_seq,
      LIST_PAGE_LIMIT,
    );
    expect(pending.length).toBeGreaterThan(0);
    // The other timer's seal: the same range, a moment earlier, so it is a
    // different seal standing at the seq this run is about to claim.
    const built = await buildSeal(pending, previous, {
      now: new Date(NOW.getTime() - 1000).toISOString(),
    });
    expect(built.ok).toBe(true);
    if (!built.ok) return;

    const report = await sweep({
      at: NOW,
      witness: new FakeWitnessAdapter(),
      db: racedDatabase(world.store.db, built.seal),
    });

    expect(report.sealed).toBeNull();
    expect(report.skipped["seal_conflict"]).toBe(1);
    // The other timer's seal is the one in the log, unchanged.
    const standing = (await latestSeal(world.store.db)) as Seal;
    expect(standing.hash).toBe(built.seal.hash);
    expect([standing.first_seq, standing.last_seq]).toEqual([
      built.seal.first_seq,
      built.seal.last_seq,
    ]);
    // And the entry it covers is in the log either way.
    expect(await stored(fourth["id"] as string)).toBeDefined();
  }, 120_000);
});

// ---------------------------------------------------------------------------
// (g) The anchor
// ---------------------------------------------------------------------------

describe("the daily anchor", () => {
  /** Yesterday, from a day later: the day every seal above was made on. */
  const date = utcDay(AT);

  it("anchors yesterday's roots, with no receipt when nothing took the hash", async () => {
    const report = await sweep({
      at: day(1),
      witness: new FakeWitnessAdapter(),
      anchor: new FakeAnchorAdapter(null),
    });

    expect(report.anchored).toEqual({ date, seals: 2, external: null });
    expect(report.skipped["anchor_pending"]).toBe(1);

    const anchored = await getAnchor(world.store.db, date);
    expect(anchored).not.toBeNull();
    expect(anchored!.roots).toHaveLength(2);
    expect(anchored!.external).toBeNull();
    expect(anchored!.first_seal_seq).toBe(0);
  }, 120_000);

  it("posts the hash again on the next run, and records the receipt", async () => {
    const calendar = new FakeAnchorAdapter(OTS_RECEIPT);

    const report = await sweep({
      at: day(1),
      witness: new FakeWitnessAdapter(),
      anchor: calendar,
    });

    expect(calendar.asked).toEqual([date]);
    expect(report.anchored).toEqual({
      date,
      seals: 2,
      external: "opentimestamps",
    });

    const anchored = await getAnchor(world.store.db, date);
    expect(anchored!.external).toEqual(OTS_RECEIPT);
  }, 120_000);

  it("counts already_anchored and rebuilds nothing", async () => {
    const before = await getAnchor(world.store.db, date);
    const calendar = new FakeAnchorAdapter(OTS_RECEIPT);

    const report = await sweep({
      at: day(1),
      witness: new FakeWitnessAdapter(),
      anchor: calendar,
    });

    expect(report.anchored).toBeNull();
    // The no-op names its reason, like every other skip in the sweep.
    expect(report.skipped["already_anchored"]).toBe(1);
    // The chain was not asked a second time, and the record did not move.
    expect(calendar.asked).toEqual([]);
    expect(await getAnchor(world.store.db, date)).toEqual(before);
  }, 120_000);

  it("answers the anchor over the routes", async () => {
    const listed = await read("/anchors");
    expect(listed.status).toBe(200);
    const anchors = listed.body["anchors"] as { date: string }[];
    expect(anchors).toHaveLength(1);
    expect(anchors[0]!.date).toBe(date);

    const one = await read(`/anchors/${date}`);
    expect(one.status).toBe(200);
    expect(one.body["hash"]).toBe((await getAnchor(world.store.db, date))!.hash);
  });
});
