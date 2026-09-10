/**
 * M22 end to end: drift attestation and the confidence field, through the
 * Worker and the sweep.
 *
 * Whitepaper Section 8, "Drift attestation": "A probe set is drawn from
 * verified, observed, fresh entries by public randomness, the same
 * beacon-and-snapshot construction as validator assignment (Section 6), so
 * neither the model's operator nor the maintainer picks the questions. The model
 * answers the probes. Three operators from the trusted pool, none under the
 * model's operator, score its answers against the log and sign the result, and
 * the score and the probe hash are sealed with a date." And "The confidence
 * field": "Until then the field is null and every input to it is exposed raw, so
 * a learner can build its own weighting from the receipts rather than trust a
 * number nobody has tested."
 *
 * Every one of those sentences is exercised here through the real doors, on a
 * real miniflare D1, with real Ed25519 keys and real signatures over the real
 * canonical bytes. Only the network, the beacon, the witnesses, the payment
 * provider and the clock are fixtures. Nothing is asserted that the Worker did
 * not say: every probe, every scorer and every score comes back out of the
 * routes that wrote them.
 *
 * The world: four trusted operators outside the maintainer's, a fifth that the
 * model's key answers for, a maintainer registered and named by nobody, and one
 * verified, observed, fresh entry seeded through the submit and validate doors
 * with a real measurement receipt behind it — which is the whole candidate pool
 * an attestation may be drawn from, so the probe set is one probe wide. Section
 * 12 says the observed tier will be thin at genesis, and `PROBE_SET_MIN_CANDIDATES`
 * is what lets a thin tier attest at all.
 */

import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { FixtureBeacon } from "../src/adapters/beacon.js";
import { MockPayoutAdapter } from "../src/adapters/payout.js";
import { receiptArtifactHash } from "../src/artifact.js";
import {
  attestationDeadline,
  attestationId,
  deriveAttestation,
  type DerivedAttestation,
} from "../src/attest.js";
import type { Core } from "../src/core.js";
import { base64urlEncode } from "../src/encoding.js";
import type { ApproverRecord, AttestationScoreRecord, Event } from "../src/events.js";
import { verifyChain } from "../src/events.js";
import {
  exportPrivateKeyPkcs8,
  generateKeypair,
} from "../src/identity.js";
import {
  ATTESTATION_SCORERS,
  ATTESTATION_WINDOW_HOURS,
  LIST_PAGE_LIMIT,
  REPRODUCTION_HOLDS,
  REPRODUCTION_RUNS,
} from "../src/policy.js";
import { signRecord } from "../src/records.js";
import { txtRecordName } from "../src/registry.js";
import type { SubmissionProposal } from "../src/submit.js";
import {
  agentsForOperator,
  latestSeal,
  putAgent,
  recordAttestationRequest,
  type AgentRecord,
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

/** Unit constants: the fake clock moves in whole hours. */
const HOUR_MS = 3_600_000;

/** The instant `hours` hours after day 0. */
function hour(hours: number): Date {
  return new Date(NOW.getTime() + hours * HOUR_MS);
}

/** A reference the mock payment provider calls onboarded. */
const VERIFIED_REFERENCE = "mock-verified-m22";

const CATEGORY = "pricing";
const SUBJECT = "kestrel/kestrel-1";
const CLAIM = `${SUBJECT} seat pricing is $40 per seat per month`;

const PRICING: FixturePage = {
  body: "<!doctype html><html><body><main><h1>Kestrel pricing</h1><p>$40 per seat per month</p></main></body></html>",
  contentType: "text/html; charset=utf-8",
};
const PRICING_URL = "https://kestrel.example/pricing";

/**
 * The measurement receipt behind the observed entry: exactly the eight receipt
 * artifact keys, hashed by the kernel's own rule, so the submit door archives it
 * at the hash the signed core names.
 */
const RECEIPT: Record<string, unknown> = {
  method: "completed_request",
  subject: SUBJECT,
  test: "contains:$40 per seat per month",
  request: { method: "GET", url: PRICING_URL, headers: {} },
  response: { status: 200, final_url: PRICING_URL, content_type: "text/html" },
  billing: null,
  observed_at: "2026-09-01",
  observer: "m22 fixture",
};

interface Party {
  readonly operator: string;
  readonly agent: TestAgent;
}

let store: TestDatabase;
let env: Env;
let deps: RequestDeps;
let maintainer: TestAgent;

/** Four trusted operators outside the maintainer's: the author and the judges. */
let k1: Party;
let k2: Party;
let k3: Party;
let k4: Party;
/** The fifth: the operator the model's key answers for. */
let k5: Party;
let trusted: Party[] = [];

/** The model under attestation, and a model bound to nobody. */
let model: TestAgent;
let bareModel: TestAgent;

let pricingHash = "";
let receiptHash = "";
let entry: Core;
let entryId = "";
let snapshotSeq = -1;

/** One beacon for the whole run, so the tests own which round each request sees. */
const beacon = new FixtureBeacon("m22");
const payout = new MockPayoutAdapter();

/** The attestations this file builds, in the order it builds them. */
let first: DerivedAttestation;
let second: DerivedAttestation;

function send(request: Request, now: Date): Promise<Response> {
  return handleRequest(request, env, { ...deps, now, beacon });
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

async function register(party: Party): Promise<void> {
  const answer = await post(party.agent, "/operators", {
    operator: party.operator,
    attestation: await attestFor(party.agent, party.operator, AT),
    payout: { reference: VERIFIED_REFERENCE },
  });
  expect([answer.status, party.operator]).toEqual([201, party.operator]);
}

async function name(party: Party): Promise<void> {
  const answer = await post(maintainer, "/genesis", { operator: party.operator });
  expect([answer.status, party.operator]).toEqual([200, party.operator]);
}

/** An observed pricing proposal: a frozen test, and a receipt behind it. */
function proposal(): Omit<SubmissionProposal, "author"> {
  return {
    author_operator: k1.operator,
    subject: SUBJECT,
    category: CATEGORY,
    claim: CLAIM,
    before: "$35 per seat per month",
    after: "$40 per seat per month",
    effective_at: "2026-09-01",
    citation: PRICING_URL,
    snapshot_hash: pricingHash,
    supersedes: null,
    evidence_tier: "observed",
    observation: {
      method: "completed_request",
      test: "contains:$40 per seat per month",
      receipt_hash: receiptHash,
      observed_at: "2026-09-01",
      notes: null,
    },
  };
}

/**
 * One approval that accepts the frozen test and carries the approver's own
 * passing n-of-k measurement, which is what an entry has to have a majority of
 * before it verifies at the observed tier (src/evidence.ts, `evidenceGate`).
 */
async function approve(party: Party): Promise<void> {
  const record: ApproverRecord = {
    agent: party.agent.agentId,
    operator: party.operator,
    decision: "approve",
    reason: null,
    snapshot_hash: pricingHash,
    assigned_random: false,
    test_accepted: true,
    reproduction: null,
    observation: {
      method: "completed_request",
      receipt_hash: receiptHash,
      observed_at: "2026-09-01",
      runs: REPRODUCTION_RUNS,
      holds: REPRODUCTION_HOLDS + 1,
    },
    signed_at: AT,
  } as unknown as ApproverRecord;
  const signature = await signRecord(
    entryId,
    "validation",
    record,
    party.agent.privateKey,
  );
  const answer = await post(party.agent, `/entries/${entryId}/validate`, {
    record,
    signature,
  });
  expect([answer.status, answer.body["error"] ?? null]).toEqual([201, null]);
}

/** Run the sweep the alarm runs, with the fakes standing in for the world. */
async function sweep(at: Date): Promise<SweepReport> {
  return runSweep(env, {
    now: at,
    beacon,
    witness: new FakeWitnessAdapter(),
    pinned: pinnedSet([]),
    ineligibleAgents: new Set<string>(),
    anchor: new FakeAnchorAdapter(null),
    payout,
  });
}

/** One signed score, posted to the score door. */
async function score(
  attestation: DerivedAttestation,
  party: Party,
  agreed: number,
  now: Date,
  answersHash: string | null = attestation.answers_hash,
): Promise<{ status: number; body: Record<string, unknown> }> {
  const record: AttestationScoreRecord = {
    agent: party.agent.agentId,
    operator: party.operator,
    agreed,
    probe_hash: attestation.probe_hash,
    answers_hash: answersHash as string,
    signed_at: now.toISOString(),
  };
  const signature = await signRecord(
    attestation.id,
    "attestation_score",
    record,
    party.agent.privateKey,
  );
  return post(
    party.agent,
    `/attestations/${attestation.id}/score`,
    { record, signature },
    now,
  );
}

/** The party behind one operator name, for a scorer the draw picked. */
function partyOf(operator: string): Party {
  const party = [k1, k2, k3, k4, k5].find((one) => one.operator === operator);
  if (party === undefined) throw new Error(`no party for ${operator}`);
  return party;
}

/** The whole log, paged through the events door. */
async function wholeLog(now: Date): Promise<Event[]> {
  const events: Event[] = [];
  for (;;) {
    // `after` is exclusive and seq 0 is a real position, so the start of the
    // log is the query with no `after` at all.
    const page = await read(
      events.length === 0
        ? "/events?limit=100"
        : `/events?after=${events[events.length - 1]!.seq}&limit=100`,
      now,
    );
    expect(page.status).toBe(200);
    const got = page.body["events"] as Event[];
    events.push(...got);
    if (got.length < 100) break;
  }
  return events;
}

// ---------------------------------------------------------------------------
// The world, built once
// ---------------------------------------------------------------------------

beforeAll(async () => {
  pricingHash = await pageHash(PRICING);
  const hashed = await receiptArtifactHash(RECEIPT);
  expect(hashed.ok).toBe(true);
  receiptHash = hashed.ok ? hashed.hash : "";

  const pair = await generateKeypair();
  const sealingKey = base64urlEncode(await exportPrivateKeyPkcs8(pair.privateKey));

  store = await openTestDatabase();
  maintainer = await makeAgent();
  k1 = { operator: "k1.example", agent: await makeAgent() };
  k2 = { operator: "k2.example", agent: await makeAgent() };
  k3 = { operator: "k3.example", agent: await makeAgent() };
  k4 = { operator: "k4.example", agent: await makeAgent() };
  // The model's own key is the key its operator registered with, so "the
  // model's operator" is a fact the registry answers rather than a fixture.
  model = await makeAgent();
  k5 = { operator: "k5.example", agent: model };
  bareModel = await makeAgent();
  trusted = [k1, k2, k3, k4, k5];
  const maintainerParty: Party = {
    operator: "maintainer.example",
    agent: maintainer,
  };

  const records: Record<string, string[]> = {};
  for (const party of [...trusted, maintainerParty]) {
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
    payout,
    fetcher: new FixtureFetcher({ [PRICING_URL]: PRICING }),
    beacon,
  };

  for (const party of trusted) {
    await register(party);
    await name(party);
  }
  // The maintainer registers and is named by nobody, so it is never in the pool
  // — and the draw excludes it anyway, which is the rule under test.
  await register(maintainerParty);

  entry = await submittedCore(k1.agent, proposal());
  entryId = entry["id"] as string;
  const submitted = await send(
    await submission(k1.agent, { core: entry, receipt: RECEIPT }),
    NOW,
  );
  expect([submitted.status, await submitted.json()]).toEqual([
    201,
    expect.objectContaining({ id: entryId, status: "draft" }),
  ]);
  await approve(k2);
  await approve(k3);

  const verified = await read(`/entries/${entryId}`);
  expect([verified.status, verified.body["status"]]).toEqual([200, "verified"]);

  // The pool snapshot has to be committed BEFORE the beacon round that uses it,
  // so the snapshot goes in on a run with no round to read and the round is
  // advanced after it.
  const opened = await sweep(hour(1));
  expect(opened.snapshot).not.toBeNull();
  snapshotSeq = opened.snapshot!.seq;
  expect([...opened.snapshot!.operators].sort()).toEqual(
    trusted.map((party) => party.operator).sort(),
  );
  await beacon.advance(hour(2).toISOString());
}, 600_000);

afterAll(async () => {
  await store?.dispose();
});

// ---------------------------------------------------------------------------
// The request door
// ---------------------------------------------------------------------------

describe("a request from a registered model agent", () => {
  it("draws probes and three scorers, none under the model's operator", async () => {
    const at = hour(3);
    const answer = await post(model, "/attestations", {}, at);
    expect([answer.status, answer.body["error"] ?? null]).toEqual([201, null]);
    first = answer.body as unknown as DerivedAttestation;

    // The whole observed tier is one entry, and Section 12's thin tier draws
    // every candidate rather than refusing to attest at all.
    expect(first.probes.map((probe) => probe.entry_id)).toEqual([entryId]);
    expect(first.probe_count).toBe(1);
    expect(first.model).toBe(model.agentId);
    expect(first.model_operator).toBe(k5.operator);
    expect(first.status).toBe("open");
    expect(first.score).toBeNull();
    expect(first.date).toBeNull();
    expect(first.deadline).toBe(attestationDeadline(at.toISOString()));
    expect(first.pool_snapshot_seq).toBe(snapshotSeq);

    // Three of them, distinct, none the model's own operator and none the
    // maintainer's: "judged by parties its lab does not control".
    const operators = first.scorers.map((scorer) => scorer.operator);
    expect(operators).toHaveLength(ATTESTATION_SCORERS);
    expect(new Set(operators).size).toBe(ATTESTATION_SCORERS);
    expect(operators).not.toContain(k5.operator);
    expect(operators).not.toContain("maintainer.example");
    for (const scorer of first.scorers) {
      expect(partyOf(scorer.operator).agent.agentId).toBe(scorer.agent);
    }

    // The id is a function of the model, the snapshot, the round and the probe
    // hash, which is what makes "at most once per beacon round" a fact about
    // the data rather than a rule someone has to remember.
    expect(first.id).toBe(
      await attestationId({
        model: model.agentId,
        pool_snapshot_seq: first.pool_snapshot_seq,
        beacon_round: first.beacon_round,
        probe_hash: first.probe_hash,
      }),
    );
  }, 600_000);

  it("refuses a second request while one is open", async () => {
    const answer = await post(model, "/attestations", {}, hour(4));
    expect([answer.status, answer.body["error"]]).toEqual([
      409,
      "attestation_open",
    ]);
  }, 600_000);

  it("refuses a body that asks for anything", async () => {
    const answer = await post(model, "/attestations", { probes: 3 }, hour(4));
    expect([answer.status, answer.body["error"]]).toEqual([400, "bad_body"]);
  }, 600_000);
});

// ---------------------------------------------------------------------------
// The answers door
// ---------------------------------------------------------------------------

describe("answering the probes", () => {
  it("refuses a key that is not the model's", async () => {
    const answer = await post(
      k1.agent,
      `/attestations/${first.id}/answers`,
      { answers: [{ entry_id: entryId, answer: CLAIM }] },
      hour(5),
    );
    expect([answer.status, answer.body["error"]]).toEqual([403, "not_model"]);
  }, 600_000);

  it("refuses answers that are not the probes", async () => {
    const answer = await post(
      model,
      `/attestations/${first.id}/answers`,
      {
        answers: [
          { entry_id: entryId, answer: CLAIM },
          { entry_id: "nmk_00000000000000000000000000000000", answer: CLAIM },
        ],
      },
      hour(5),
    );
    expect([answer.status, answer.body["error"]]).toEqual([422, "bad_answers"]);
  }, 600_000);

  it("refuses a score before there is anything to score", async () => {
    // Nothing has been answered, so there is no answers hash yet; the record
    // carries one anyway, because a well-formed score is what the rule is
    // supposed to refuse rather than a malformed one.
    const answer = await score(
      first,
      partyOf(first.scorers[0]!.operator),
      1,
      hour(5),
      `sha256:${"0".repeat(64)}`,
    );
    expect([answer.status, answer.body["error"]]).toEqual([409, "not_open"]);
  }, 600_000);

  it("takes the model's answers and hashes them into the log", async () => {
    const answer = await post(
      model,
      `/attestations/${first.id}/answers`,
      { answers: [{ entry_id: entryId, answer: CLAIM }] },
      hour(6),
    );
    expect(answer.status).toBe(200);
    first = answer.body as unknown as DerivedAttestation;
    expect(first.status).toBe("answered");
    expect(first.answers_hash).toMatch(/^sha256:[0-9a-f]{64}$/);
    expect(first.answered_at).toBe(hour(6).toISOString());

    // The answers themselves are stored beside the attestation and served from
    // there: the log carries only the hash.
    const served = await read(`/attestations/${first.id}`, hour(6));
    expect(served.body["answers"]).toEqual([
      { entry_id: entryId, answer: CLAIM },
    ]);
  }, 600_000);
});

// ---------------------------------------------------------------------------
// The score door
// ---------------------------------------------------------------------------

describe("scoring the answers", () => {
  it("refuses an operator the draw did not pick", async () => {
    const drawn = new Set(first.scorers.map((scorer) => scorer.operator));
    const outsider = [k1, k2, k3, k4].find(
      (party) => !drawn.has(party.operator),
    );
    expect(outsider).toBeDefined();
    const answer = await score(first, outsider!, 1, hour(7));
    expect([answer.status, answer.body["error"]]).toEqual([403, "not_a_scorer"]);
  }, 600_000);

  it("takes the first score and refuses the same operator twice", async () => {
    const scorer = partyOf(first.scorers[0]!.operator);
    const answer = await score(first, scorer, 1, hour(7));
    expect([answer.status, answer.body["error"] ?? null]).toEqual([201, null]);
    expect((answer.body as unknown as DerivedAttestation).status).toBe("answered");

    const again = await score(first, scorer, 1, hour(7));
    expect([again.status, again.body["error"]]).toEqual([
      409,
      "duplicate_scorer",
    ]);
  }, 600_000);

  it("refuses a score whose answers hash is not the attestation's", async () => {
    const answer = await score(
      first,
      partyOf(first.scorers[1]!.operator),
      1,
      hour(7),
      `sha256:${"0".repeat(64)}`,
    );
    expect([answer.status, answer.body["error"]]).toEqual([
      422,
      "answers_hash_mismatch",
    ]);
  }, 600_000);

  it("refuses a count that is not a count of these probes", async () => {
    const answer = await score(first, partyOf(first.scorers[1]!.operator), 2, hour(7));
    expect([answer.status, answer.body["error"]]).toEqual([422, "bad_agreed"]);
  }, 600_000);

  it("seals a median score with a date on the third", async () => {
    const at = hour(8);
    const second_ = await score(first, partyOf(first.scorers[1]!.operator), 1, at);
    expect(second_.status).toBe(201);
    const third = await score(first, partyOf(first.scorers[2]!.operator), 0, at);
    expect(third.status).toBe(201);

    const scored = third.body as unknown as DerivedAttestation;
    expect(scored.status).toBe("scored");
    // The median of 1, 1 and 0 is 1: one scorer who read the log differently
    // moves nothing, which is the point of scoring three times.
    expect(scored.score).toEqual({ agreed: 1, probe_count: 1 });
    expect(scored.date).toBe(at.toISOString().slice(0, 10));
    expect(scored.scores).toHaveLength(ATTESTATION_SCORERS);

    // The row, the single read and the listing all say the same thing.
    const served = await read(`/attestations/${first.id}`, at);
    expect([served.status, served.body["status"], served.body["score"]]).toEqual([
      200,
      "scored",
      { agreed: 1, probe_count: 1 },
    ]);
    expect(served.body["date"]).toBe(scored.date);
    const listed = await read(`/attestations?model=${first.model}`, at);
    expect(
      (listed.body["attestations"] as DerivedAttestation[]).map((one) => [
        one.id,
        one.status,
      ]),
    ).toEqual([[first.id, "scored"]]);
    first = scored;
  }, 600_000);
});

// ---------------------------------------------------------------------------
// The window, and the sweep that closes it
// ---------------------------------------------------------------------------

describe("an attestation nobody scored", () => {
  it("expires on the sweep, naming the scorers that never answered", async () => {
    // A new round, so the same model draws a different attestation rather than
    // the one it already has.
    await beacon.advance(hour(9).toISOString());
    const opened = await post(model, "/attestations", {}, hour(10));
    expect(opened.status).toBe(201);
    second = opened.body as unknown as DerivedAttestation;
    expect(second.id).not.toBe(first.id);

    const late = hour(10 + ATTESTATION_WINDOW_HOURS + 1);
    const report = await sweep(late);
    expect(report.attestations.expired).toEqual([second.id]);

    const served = await read(`/attestations/${second.id}`, late);
    expect(served.body["status"]).toBe("expired");

    // The expiry names who never scored, which is what makes it a scorer
    // problem rather than a claim about the model.
    const expired = (await wholeLog(late)).filter(
      (event) => event.type === "attestation_expired",
    );
    expect(expired).toHaveLength(1);
    expect(
      [...(expired[0]!.payload as { missing: readonly string[] }).missing].sort(),
    ).toEqual(second.scorers.map((scorer) => scorer.operator).sort());
  }, 600_000);

  it("refuses a late score", async () => {
    const answer = await score(
      second,
      partyOf(second.scorers[0]!.operator),
      1,
      hour(10 + ATTESTATION_WINDOW_HOURS + 2),
      `sha256:${"0".repeat(64)}`,
    );
    expect([answer.status, answer.body["error"]]).toEqual([409, "not_open"]);
  }, 600_000);

  it("draws the same probes for another model in the same round", async () => {
    // The probe set is a function of the candidates, the snapshot and the round
    // and of nothing else, so a second request against the same round asks the
    // same questions. A bare key excludes nobody but the maintainer: there is no
    // lab behind it whose control the exclusion exists to answer.
    const at = hour(10 + ATTESTATION_WINDOW_HOURS + 3);
    const answer = await post(bareModel, "/attestations", {}, at);
    expect([answer.status, answer.body["error"] ?? null]).toEqual([201, null]);
    const bare = answer.body as unknown as DerivedAttestation;

    expect(bare.beacon_round).toBe(second.beacon_round);
    expect(bare.probes).toEqual(second.probes);
    expect(bare.probe_hash).toBe(second.probe_hash);
    expect(bare.model_operator).toBeNull();
    expect(bare.id).not.toBe(second.id);
    // Every trusted operator was eligible, so a scorer under the fifth operator
    // is allowed here where it was refused above.
    for (const scorer of bare.scorers) {
      expect(trusted.map((party) => party.operator)).toContain(scorer.operator);
    }
  }, 600_000);
});

// ---------------------------------------------------------------------------
// A drawn operator nobody answers for
// ---------------------------------------------------------------------------

describe("a trusted operator with no agent bound under it", () => {
  it("refuses the request rather than naming a scorer nobody answers for", async () => {
    // The operator is the unit of the draw and the agent named beside it is the
    // first one bound under it, so an operator the registry holds with no agent
    // left under it cannot be published as a scorer.
    //
    // A FIXTURE: the agent rows of three trusted operators are lifted out for
    // the length of this one request and put back after it, because there is no
    // door that unbinds an agent. Two operators are left with agents and three
    // scorers are drawn from five eligible ones, so whichever three the beacon
    // picks, one of them has nobody under it — the refusal is a fact about the
    // world rather than a guess about the draw. The request itself is real: a
    // bare key, signed, through the door.
    const at = hour(10 + ATTESTATION_WINDOW_HOURS + 3);
    const unbound = [k1, k2, k3];
    const lifted: AgentRecord[] = [];
    for (const party of unbound) {
      lifted.push(
        ...(await agentsForOperator(store.db, party.operator, LIST_PAGE_LIMIT)),
      );
      await store.db
        .prepare("DELETE FROM agents WHERE operator_id = ?")
        .bind(party.operator)
        .run();
    }
    expect(lifted.length).toBeGreaterThanOrEqual(unbound.length);

    try {
      // A key nobody has registered: its operator is null, so nothing but the
      // maintainer is excluded and all five trusted operators are eligible.
      const stranger = await makeAgent();
      const answer = await post(stranger, "/attestations", {}, at);
      expect([answer.status, answer.body["error"]]).toEqual([
        422,
        "no_agent_for_operator",
      ]);

      // Nothing was written: a refused request leaves no attestation behind.
      const listed = await read("/attestations", at);
      expect(
        (listed.body["attestations"] as DerivedAttestation[]).map(
          (one) => one.model,
        ),
      ).not.toContain(stranger.agentId);
    } finally {
      for (const agent of lifted) await putAgent(store.db, agent);
    }

    // The world is whole again, which the next tests depend on.
    for (const party of unbound) {
      const agents = await agentsForOperator(
        store.db,
        party.operator,
        LIST_PAGE_LIMIT,
      );
      expect(agents.map((one) => one.agentId)).toContain(party.agent.agentId);
    }
  }, 600_000);
});

// ---------------------------------------------------------------------------
// The model's own operator
// ---------------------------------------------------------------------------

describe("a scorer under the model's own operator", () => {
  it("is refused whatever the draw said", async () => {
    // A FIXTURE: the request door excludes the model's operator from the draw,
    // so no live draw can name it as a scorer. The kernel refuses one anyway
    // (`model_operator`), because a judgment nomankind publishes about a model
    // must not be its own lab's, and this seeds the state the rule is about —
    // a scorers list naming the model's operator — to check the door reports it.
    // Everything else here is real: the event is sealed by the repository's own
    // writer onto the chain, the model answers through its door, and the score
    // is a real signature over the real canonical bytes.
    const at = hour(10 + ATTESTATION_WINDOW_HOURS + 4);
    const round = 9_999;
    const id = await attestationId({
      model: model.agentId,
      pool_snapshot_seq: snapshotSeq,
      beacon_round: round,
      probe_hash: first.probe_hash,
    });
    const scorers = [
      { operator: k5.operator, agent: model.agentId },
      { operator: k1.operator, agent: k1.agent.agentId },
      { operator: k2.operator, agent: k2.agent.agentId },
    ];
    await recordAttestationRequest(store.db, {
      event: {
        at: at.toISOString(),
        type: "attestation_requested",
        entry_id: null,
        payload: {
          attestation: id,
          model: model.agentId,
          model_operator: k5.operator,
          probes: first.probes,
          probe_hash: first.probe_hash,
          probe_count: first.probe_count,
          pool_snapshot_seq: snapshotSeq,
          beacon_round: round,
          beacon_randomness: "0".repeat(64),
          scorers,
          deadline: attestationDeadline(at.toISOString()),
        },
      },
      // The derived record, folded by the kernel from the event the writer just
      // sealed, exactly as the request door folds its own.
      row: (event) => deriveAttestation([event], { now: at.toISOString() }),
      scorers,
    });

    const answered = await post(
      model,
      `/attestations/${id}/answers`,
      { answers: [{ entry_id: entryId, answer: CLAIM }] },
      at,
    );
    expect(answered.status).toBe(200);

    const seeded = answered.body as unknown as DerivedAttestation;
    const answer = await score(seeded, k5, 1, at);
    expect([answer.status, answer.body["error"]]).toEqual([
      403,
      "model_operator",
    ]);
  }, 600_000);
});

// ---------------------------------------------------------------------------
// The reads
// ---------------------------------------------------------------------------

describe("the confidence field", () => {
  it("is null, and every input to it is served raw", async () => {
    const at = hour(10 + ATTESTATION_WINDOW_HOURS + 5);
    const answer = await read(`/entries/${entryId}/confidence-inputs`, at);
    expect(answer.status).toBe(200);

    expect(Object.keys(answer.body).sort()).toEqual(
      [
        "age_ratio",
        "confidence",
        "counts",
        "dispute_count",
        "effective_tier",
        "evidence_tier",
        "formula",
        "overturned",
        "report_count",
        "stale",
        "status",
        "superseded",
        "test_acceptance",
        "test_verdict",
      ].sort(),
    );
    // conf-v1 is unpublished on purpose, and there is no code path that returns
    // a number for either of these.
    expect(answer.body["confidence"]).toBeNull();
    expect(answer.body["formula"]).toBeNull();
    expect(answer.body["evidence_tier"]).toBe("observed");
    expect(answer.body["effective_tier"]).toBe("observed");
    expect(answer.body["test_verdict"]).toBe("accepted");
    expect(answer.body["test_acceptance"]).toEqual({ accepted: 2, rejected: 0 });
    expect(answer.body["counts"]).toEqual({
      approvals: 2,
      rejections: 0,
      reproductions: { records: 0, runs: 0, holds: 0 },
      observations: 2,
      reconfirmations: 0,
    });
    // Whole UTC days from the entry's last_confirmed to the request clock,
    // against the pricing category's ninety-day window.
    expect(answer.body["age_ratio"]).toEqual({ days: 4, window_days: 90 });
    expect(answer.body["stale"]).toBe(false);
    expect(answer.body["dispute_count"]).toEqual({
      open: 0,
      upheld: 0,
      failed: 0,
      total: 0,
    });
    expect(answer.body["report_count"]).toEqual({
      total: 0,
      distinct_operators: 0,
    });
    expect(answer.body["superseded"]).toBe(false);
    expect(answer.body["overturned"]).toBe(false);
    expect(answer.body["status"]).toBe("verified");
  }, 600_000);

  it("is 404 for an entry the log does not hold", async () => {
    const answer = await read(
      "/entries/nmk_00000000000000000000000000000000/confidence-inputs",
    );
    expect([answer.status, answer.body["error"]]).toEqual([404, "not_found"]);
  }, 600_000);
});

describe("one operator's two sides of attestation", () => {
  it("splits what it attested from what it judged", async () => {
    const at = hour(10 + ATTESTATION_WINDOW_HOURS + 5);
    const forModel = await read(`/operators/${k5.operator}/attestations`, at);
    expect(forModel.status).toBe(200);
    const asModel = forModel.body["as_model"] as DerivedAttestation[];
    expect(asModel.map((one) => one.id)).toContain(first.id);
    expect(asModel.map((one) => one.id)).toContain(second.id);
    // The fifth operator was never drawn to score by any live draw.
    expect(
      (forModel.body["as_scorer"] as DerivedAttestation[]).map((one) => one.id),
    ).not.toContain(first.id);

    const scorer = partyOf(first.scorers[0]!.operator);
    const forScorer = await read(`/operators/${scorer.operator}/attestations`, at);
    expect(
      (forScorer.body["as_scorer"] as DerivedAttestation[]).map((one) => one.id),
    ).toContain(first.id);
    expect(
      (forScorer.body["as_model"] as DerivedAttestation[]).map((one) => one.id),
    ).not.toContain(first.id);
  }, 600_000);

  it("answers 405 with Allow on the wrong method", async () => {
    const response = await send(
      new Request(`${TEST_ORIGIN}/attestations/${first.id}`, { method: "DELETE" }),
      NOW,
    );
    expect([response.status, response.headers.get("allow")]).toEqual([
      405,
      "GET",
    ]);
    expect(response.headers.get("cache-control")).toBe("no-store");
  }, 600_000);
});

// ---------------------------------------------------------------------------
// The log itself
// ---------------------------------------------------------------------------

describe("the log the attestations went into", () => {
  it("verifies, and the sweep seals what the doors wrote", async () => {
    const at = hour(10 + ATTESTATION_WINDOW_HOURS + 6);
    const report = await sweep(at);
    expect(report.sealed).not.toBeNull();

    const events = await wholeLog(at);
    expect(await verifyChain(events)).toEqual({ ok: true, length: events.length });

    // Every attestation event is on the chain, entry-scoped to nothing, and
    // inside what the seal now covers.
    const attestationEvents = events.filter((event) =>
      event.type.startsWith("attestation_"),
    );
    expect(attestationEvents.length).toBeGreaterThanOrEqual(7);
    for (const event of attestationEvents) expect(event.entry_id).toBeNull();

    const seal = await latestSeal(store.db);
    expect(seal).not.toBeNull();
    expect(seal!.last_seq).toBeGreaterThanOrEqual(
      attestationEvents[attestationEvents.length - 1]!.seq,
    );
  }, 600_000);
});
