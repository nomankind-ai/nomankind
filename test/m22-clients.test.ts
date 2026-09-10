/**
 * The attest command and the submit command's receipt, driven in process
 * against the real Worker.
 *
 * Whitepaper Section 8, "Drift attestation": "The model answers the probes.
 * Three operators from the trusted pool, none under the model's operator, score
 * its answers against the log and sign the result." This file walks that
 * sentence with the clients an operator actually runs: `attest request`,
 * `attest answer`, and `attest score` three times over, against a world stood up
 * on a real miniflare D1 with real keys and real signatures, and no network
 * anywhere.
 *
 * Both ends of the scale are exercised, because a scorer that could only ever
 * return the same number would be worth nothing: the default answers are the
 * log's own claims, which score fully agreed, and `--drift` answers everything
 * with one word, which scores zero.
 *
 * The world is seeded by `npm run submit --receipt`, which is the other half of
 * this milestone's client work: an observed entry rests on a measurement, the
 * receipt artifact is checked and hashed by the kernel's own rule before the
 * network is touched, and the hash fills `observation.receipt_hash` in the core
 * the author signs. Without it there is no observed entry for a probe set to be
 * drawn from at all.
 */

import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { FixtureBeacon } from "../src/adapters/beacon.js";
import { MockPayoutAdapter } from "../src/adapters/payout.js";
import { receiptArtifactHash } from "../src/artifact.js";
import type { DerivedAttestation } from "../src/attest.js";
import {
  DRIFT_ANSWER,
  attestPlan,
  runAnswer,
  runRequest,
  runScore,
  type AttestDeps,
} from "../src/cli/attest.js";
import {
  parseSubmitArgs,
  runSubmit,
  type SubmitRun,
} from "../src/cli/submit.js";
import type {
  HttpClient,
  ValidatorIo,
  ValidatorKey,
} from "../src/cli/validator.js";
import { base64urlEncode } from "../src/encoding.js";
import type { ApproverRecord } from "../src/events.js";
import {
  exportPrivateKeyPkcs8,
  generateKeypair,
} from "../src/identity.js";
import {
  ATTESTATION_SCORERS,
  DEFAULT_DOMAIN,
  REPRODUCTION_HOLDS,
  REPRODUCTION_RUNS,
} from "../src/policy.js";
import { signRecord } from "../src/records.js";
import { txtRecordName } from "../src/registry.js";
import type { Env } from "../src/worker/env.js";
import { handleRequest, type RequestDeps } from "../src/worker/index.js";
import { runSweep } from "../src/worker/sweep.js";
import { openTestDatabase, type TestDatabase } from "./helpers/d1.js";
import {
  FixtureResolver,
  TEST_ORIGIN,
  attestFor,
  makeAgent,
  signedPost,
  type TestAgent,
} from "./helpers/registry.js";
import { FixtureFetcher, SUBMIT_NOW, pageHash, type FixturePage } from "./helpers/submit.js";
import {
  FakeAnchorAdapter,
  FakeWitnessAdapter,
  pinnedSet,
} from "./helpers/witness.js";

const NOW = SUBMIT_NOW;
const AT = NOW.toISOString();
const HOUR_MS = 3_600_000;

function hour(hours: number): Date {
  return new Date(NOW.getTime() + hours * HOUR_MS);
}

const VERIFIED_REFERENCE = "mock-verified-m22";

const SUBJECT = "example/kestrel-1";
const CLAIM = `${SUBJECT} seat pricing is $40 per seat per month`;
const TEST = "contains:$40 per seat per month";

const PAGE: FixturePage = {
  body: "<!doctype html><html><body><main><h1>Kestrel pricing</h1><p>$40 per seat per month</p></main></body></html>",
  contentType: "text/html; charset=utf-8",
};
const PAGE_URL = "https://kestrel.example/pricing";

/** The measurement receipt the submit command carries: the eight receipt keys. */
const RECEIPT: Record<string, unknown> = {
  method: "completed_request",
  subject: SUBJECT,
  test: TEST,
  request: { method: "GET", url: PAGE_URL, headers: {} },
  response: { status: 200, final_url: PAGE_URL, content_type: "text/html" },
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
let k1: Party;
let k2: Party;
let k3: Party;
let k4: Party;
/** The fifth operator: the one the model's key answers for. */
let k5: Party;
let trusted: Party[] = [];

let pageHashValue = "";
let receiptHash = "";
let entryId = "";
let submitted: SubmitRun;

const beacon = new FixtureBeacon("m22-clients");
const payout = new MockPayoutAdapter();

/** The clock the CLI runs at. Moved by the tests as the world advances. */
let clock = NOW;

function send(request: Request, now: Date = clock): Promise<Response> {
  return handleRequest(request, env, { ...deps, now, beacon });
}

/** An HttpClient that routes straight into the router, with no network. */
class InProcessHttp implements HttpClient {
  async fetch(request: Request): Promise<Response> {
    return send(request);
  }
}

/** What one run printed. */
function recorder(): { io: ValidatorIo; out: string[] } {
  const out: string[] = [];
  return {
    io: {
      stdout: (line: string) => out.push(line),
      stderr: (line: string) => out.push(line),
    },
    out,
  };
}

/** The CLI's injected world, at whatever the clock now says. */
function cliDeps(io: ValidatorIo): AttestDeps {
  return { http: new InProcessHttp(), now: clock, io };
}

/** A TestAgent is exactly what a key file gives a command: an id and a key. */
function keyOf(agent: TestAgent): ValidatorKey {
  return { agentId: agent.agentId, privateKey: agent.privateKey };
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

/** One approval that accepts the frozen test and carries its own measurement. */
async function approve(party: Party): Promise<void> {
  const record: ApproverRecord = {
    agent: party.agent.agentId,
    operator: party.operator,
    decision: "approve",
    reason: null,
    snapshot_hash: pageHashValue,
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

/** One attestation as the read route serves it. */
async function servedAttestation(id: string): Promise<DerivedAttestation> {
  const response = await send(new Request(`${TEST_ORIGIN}/attestations/${id}`));
  expect(response.status).toBe(200);
  return (await response.json()) as DerivedAttestation;
}

/** The party behind one drawn scorer's operator. */
function partyOf(operator: string): Party {
  const party = trusted.find((one) => one.operator === operator);
  if (party === undefined) throw new Error(`no party for ${operator}`);
  return party;
}

/**
 * Ask for a probe set, answer it, and let all three drawn scorers score it.
 * Returns the attestation as the log finished it.
 */
async function attestOnce(drift: boolean): Promise<DerivedAttestation> {
  const asked = recorder();
  const request = await runRequest({
    key: keyOf(k5.agent),
    baseUrl: TEST_ORIGIN,
    deps: cliDeps(asked.io),
  });
  expect([request.code, request.error]).toEqual([0, null]);
  const id = request.attestation as string;

  const answering = recorder();
  const answered = await runAnswer({
    key: keyOf(k5.agent),
    baseUrl: TEST_ORIGIN,
    attestation: id,
    drift,
    deps: cliDeps(answering.io),
  });
  expect([answered.code, answered.error]).toEqual([0, null]);
  expect(answered.attestationStatus).toBe("answered");

  const drawn = await servedAttestation(id);
  for (const scorer of drawn.scorers) {
    const scoring = recorder();
    const run = await runScore({
      key: keyOf(partyOf(scorer.operator).agent),
      baseUrl: TEST_ORIGIN,
      attestation: id,
      deps: cliDeps(scoring.io),
    });
    expect([scorer.operator, run.code, run.error]).toEqual([
      scorer.operator,
      0,
      null,
    ]);
    expect(run.agreed).toBe(drift ? 0 : drawn.probe_count);
    expect(scoring.out).toContain(
      `agreed ${drift ? 0 : drawn.probe_count} of ${drawn.probe_count}`,
    );
  }

  return servedAttestation(id);
}

beforeAll(async () => {
  pageHashValue = await pageHash(PAGE);
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
  k5 = { operator: "k5.example", agent: await makeAgent() };
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
    fetcher: new FixtureFetcher({ [PAGE_URL]: PAGE }),
    beacon,
  };

  for (const party of trusted) {
    await register(party);
    await name(party);
  }
  await register(maintainerParty);

  // The seed, through the submit command with its receipt. The fields file
  // leaves `receipt_hash` null: filling it is what `--receipt` is for.
  const io = recorder();
  submitted = await runSubmit({
    key: keyOf(k1.agent),
    baseUrl: TEST_ORIGIN,
    fields: {
      subject: SUBJECT,
      category: "pricing",
      // Decision D-071: the fields file names the domain the author signs.
      domain: DEFAULT_DOMAIN,
      claim: CLAIM,
      before: "$35 per seat per month",
      after: "$40 per seat per month",
      effective_at: "2026-09-01",
      citation: PAGE_URL,
      observation: {
        method: "completed_request",
        test: TEST,
        receipt_hash: null,
        observed_at: "2026-09-01",
        notes: null,
      },
      supersedes: null,
    },
    receipt: RECEIPT,
    deps: {
      http: new InProcessHttp(),
      fetcher: new FixtureFetcher({ [PAGE_URL]: PAGE }),
      now: NOW,
      io: io.io,
    },
  });
  entryId = submitted.entryId ?? "";

  await approve(k2);
  await approve(k3);

  // The pool snapshot is committed before the beacon round that uses it.
  const opened = await runSweep(env, {
    now: hour(1),
    beacon,
    witness: new FakeWitnessAdapter(),
    pinned: pinnedSet([]),
    ineligibleAgents: new Set<string>(),
    anchor: new FakeAnchorAdapter(null),
    payout,
  });
  expect(opened.snapshot).not.toBeNull();
  await beacon.advance(hour(2).toISOString());
  clock = hour(3);
}, 600_000);

afterAll(async () => {
  await store?.dispose();
});

describe("the submit command's receipt", () => {
  it("hashes the artifact and fills observation.receipt_hash", async () => {
    expect([submitted.ok, submitted.status, submitted.error]).toEqual([
      true,
      201,
      null,
    ]);

    const response = await send(new Request(`${TEST_ORIGIN}/entries/${entryId}`));
    const entry = (await response.json()) as Record<string, unknown>;
    expect([response.status, entry["status"]]).toEqual([200, "verified"]);
    // The tier the whole milestone rests on: an entry with an observation is
    // observed, and it verified as observed because a majority of its approvals
    // carried a passing measurement.
    expect(entry["evidence_tier"]).toBe("observed");
    expect((entry["observation"] as Record<string, unknown>)["receipt_hash"]).toBe(
      receiptHash,
    );

    // And the artifact itself is archived at exactly that hash.
    const archived = await send(
      new Request(`${TEST_ORIGIN}/captures/${encodeURIComponent(receiptHash)}`),
    );
    expect(archived.status).toBe(200);
  }, 600_000);

  it("refuses an artifact the kernel will not take, before the network", async () => {
    const io = recorder();
    const run = await runSubmit({
      key: keyOf(k1.agent),
      baseUrl: TEST_ORIGIN,
      fields: {
        subject: SUBJECT,
        category: "pricing",
        claim: CLAIM,
        before: "$35 per seat per month",
        after: "$40 per seat per month",
        effective_at: "2026-09-01",
        citation: PAGE_URL,
        supersedes: null,
      },
      receipt: { method: "completed_request" },
      deps: {
        http: new InProcessHttp(),
        fetcher: new FixtureFetcher({ [PAGE_URL]: PAGE }),
        now: clock,
        io: io.io,
      },
    });
    expect([run.code, run.status, run.error]).toEqual([2, null, "receipt_shape"]);
  }, 600_000);

  it("reads a plain call's three paths, with no receipt flag anywhere", () => {
    // The flag is optional, so the common call is the one without it, and the
    // parser has to leave all three positional arguments standing: a filter
    // that dropped the argument after `--receipt` by index would drop the key
    // path itself when there is no flag to find.
    expect(parseSubmitArgs(["k.json", TEST_ORIGIN, "fields.json"])).toEqual({
      keyPath: "k.json",
      baseUrl: TEST_ORIGIN,
      fieldsPath: "fields.json",
    });
  });

  it("takes the receipt file out of the positional arguments", () => {
    const withFlag = ["k.json", TEST_ORIGIN, "fields.json", "--receipt", "r.json"];
    expect(parseSubmitArgs(withFlag)).toEqual({
      keyPath: "k.json",
      baseUrl: TEST_ORIGIN,
      fieldsPath: "fields.json",
      receiptPath: "r.json",
    });
    // The flag may come first, and the file after it is still not positional.
    expect(
      parseSubmitArgs(["--receipt", "r.json", "k.json", TEST_ORIGIN, "fields.json"]),
    ).toEqual({
      keyPath: "k.json",
      baseUrl: TEST_ORIGIN,
      fieldsPath: "fields.json",
      receiptPath: "r.json",
    });
  });

  it("asks for the usage line when the call is not one", () => {
    expect(parseSubmitArgs([])).toBeNull();
    expect(parseSubmitArgs(["k.json", TEST_ORIGIN])).toBeNull();
    expect(
      parseSubmitArgs(["k.json", TEST_ORIGIN, "fields.json", "extra.json"]),
    ).toBeNull();
    // A flag with nothing after it names no file.
    expect(
      parseSubmitArgs(["k.json", TEST_ORIGIN, "fields.json", "--receipt"]),
    ).toBeNull();
  });
});

describe("the attest command", () => {
  it("reads its arguments, and refuses anything that is not a run", () => {
    expect(attestPlan(["request", "k.json", TEST_ORIGIN])).toEqual({
      subcommand: "request",
      keyPath: "k.json",
      baseUrl: TEST_ORIGIN,
      attestation: null,
      answersPath: null,
      drift: false,
    });
    expect(attestPlan(["answer", "k.json", TEST_ORIGIN, "att_x", "--drift"])).toEqual(
      {
        subcommand: "answer",
        keyPath: "k.json",
        baseUrl: TEST_ORIGIN,
        attestation: "att_x",
        answersPath: null,
        drift: true,
      },
    );
    // Two different answers to the same probes; a run naming both would have to
    // pick one silently.
    expect(
      attestPlan([
        "answer",
        "k.json",
        TEST_ORIGIN,
        "att_x",
        "--drift",
        "--answers",
        "a.json",
      ]),
    ).toBeNull();
    expect(attestPlan(["score", "k.json", TEST_ORIGIN])).toBeNull();
    expect(attestPlan(["nonsense", "k.json", TEST_ORIGIN])).toBeNull();
    expect(attestPlan([])).toBeNull();
  });

  it("asks, answers with the log's own claims, and scores fully agreed", async () => {
    const scored = await attestOnce(false);

    expect(scored.status).toBe("scored");
    expect(scored.score).toEqual({
      agreed: scored.probe_count,
      probe_count: scored.probe_count,
    });
    expect(scored.scores).toHaveLength(ATTESTATION_SCORERS);
    expect(scored.date).toBe(clock.toISOString().slice(0, 10));
    // The model's answers are the entries' own claims, read back from the log.
    const served = await send(
      new Request(`${TEST_ORIGIN}/attestations/${scored.id}`),
    );
    const body = (await served.json()) as Record<string, unknown>;
    expect(body["answers"]).toEqual([{ entry_id: entryId, answer: CLAIM }]);
  }, 600_000);

  it("scores a drifted model at nothing", async () => {
    // A fresh round, so the same model draws a new attestation rather than the
    // one it has already finished.
    clock = hour(4);
    await beacon.advance(clock.toISOString());
    clock = hour(5);

    const scored = await attestOnce(true);
    expect(scored.status).toBe("scored");
    expect(scored.score).toEqual({ agreed: 0, probe_count: scored.probe_count });

    const served = await send(
      new Request(`${TEST_ORIGIN}/attestations/${scored.id}`),
    );
    const body = (await served.json()) as Record<string, unknown>;
    expect(body["answers"]).toEqual([
      { entry_id: entryId, answer: DRIFT_ANSWER },
    ]);
  }, 600_000);

  it("stops when the attestation is not one the log holds", async () => {
    const io = recorder();
    const run = await runScore({
      key: keyOf(k1.agent),
      baseUrl: TEST_ORIGIN,
      attestation: "att_00000000000000000000000000000000",
      deps: cliDeps(io.io),
    });
    expect([run.code, run.status, run.error]).toEqual([1, null, "not_found"]);
  }, 600_000);
});
