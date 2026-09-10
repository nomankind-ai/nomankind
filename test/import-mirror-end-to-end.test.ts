/**
 * import-mirror end to end: the fork answers the same questions, and then goes
 * on asking its own.
 *
 * Whitepaper Section 11 and the Conclusion: "the exit is not a promise, it is a
 * copy", and a copy is only an exit if somebody can run it. test/import-mirror
 * .test.ts proves the replay is faithful row by row and refuses what it should.
 * This file asks the other half of the question, the one a person leaving
 * actually has: if nomankind goes away and I import the last export, does my
 * instance answer what nomankind's answered, and does my log keep moving?
 *
 * So there are two databases here and one router. One world is built through the
 * real doors on a real miniflare D1 — four named operators and a maintainer, a
 * v0.7 entry validated by the two operators that did not submit it, a dispute
 * filed against it by a bare key, a whole scored drift attestation, a published
 * day of reads — and the sweep seals it, anchors the day after, and exports the
 * directory. That directory is replayed into a database that has never seen any
 * of it, and then both are asked the same nine questions through `handleRequest`
 * under the same injected clock:
 *
 *   GET /entries/{id} for the entry and for the correction it is disputed by,
 *   /operators, /operators/{id}, /seals/{seq}, /anchors/{date},
 *   /attestations/{id}, /standing, /read/{id} and /mirror/latest.
 *
 * Two answers legitimately differ, and every field is named at the call rather
 * than quietly normalized away. The operator rows carry `payout_status` and
 * `payout_reference`, which the mirror deliberately does not export — a payment
 * provider's name for an operator is not the log's to publish, so a fork
 * onboards its own operators before it pays any — and `named_by`, the agent
 * that exercised a genesis naming, which the `operator_trusted` event does not
 * name and a replay will not invent. And `/mirror/latest` describes
 * the fork's own first export rather than nomankind's, so the commit, the tree,
 * the two URLs built from the commit and the count of files that push changed
 * are the fork's; the day, the instant, the head, the seal and the entry count
 * are the record's and have to agree.
 *
 * Then the fork's own clockwork. A sweep on the imported database seals nothing
 * — the imported head is already sealed — rebuilds the export byte for byte, and
 * writes a row for every step of the sweep, which is what makes it a running
 * instance rather than a directory being served. And then one new operator joins
 * through the real door, on the fork, and the next sweep seals it as the seal
 * after nomankind's last one, chained to it by `prev_hash`. That seal is the
 * whole claim of this file: the log did not restart, it continued.
 *
 * No network anywhere: the capture archive the verification reads is reached
 * through an http client that routes straight into the origin's own router, and
 * every clock is injected.
 */

import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";

import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { FixtureBeacon } from "../src/adapters/beacon.js";
import { MockMirrorAdapter } from "../src/adapters/mirror.js";
import { MockPayoutAdapter } from "../src/adapters/payout.js";
import {
  attestationDeadline,
  attestationId,
  deriveAttestation,
} from "../src/attest.js";
import type { Core } from "../src/core.js";
import { base64urlEncode } from "../src/encoding.js";
import {
  appendEvent,
  type ApproverRecord,
  type AttestationScoreRecord,
  type AttestationScorer,
  type Event,
  type Probe,
} from "../src/events.js";
import { entryHash } from "../src/hash.js";
import { exportPrivateKeyPkcs8, generateKeypair } from "../src/identity.js";
import { importMirror, type ImportSummary } from "../src/cli/import-mirror.js";
import type { HttpClient } from "../src/cli/validator.js";
import { DEFAULT_DOMAIN, LIST_PAGE_LIMIT } from "../src/policy.js";
import { answersHash, probeSetHash, type ProbeAnswer } from "../src/probe.js";
import { signRecord } from "../src/records.js";
import { txtRecordName } from "../src/registry.js";
import { signCore } from "../src/sign.js";
import {
  appendEvents,
  eventsInRange,
  headSeq,
  latestAnchor,
  latestSeal,
  sweepSteps,
  recordAttestationAnswers,
  recordAttestationRequest,
  recordAttestationScore,
} from "../src/storage/repository.js";
import type { Env } from "../src/worker/env.js";
import { handleRequest, type RequestDeps } from "../src/worker/index.js";
import { SWEEP_STEPS, runSweep, type SweepReport } from "../src/worker/sweep.js";
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

const HOUR_MS = 3_600_000;
const DAY_MS = 86_400_000;

/** The instant every registration, the submission and the dispute are at. */
const NOW = SUBMIT_NOW;
const AT = NOW.toISOString();

/** The run that seals the day's work and exports it for the first time. */
const EXPORT_AT = new Date(NOW.getTime() + HOUR_MS);

/**
 * The same hour a UTC day on: the run that anchors the day before's seals and
 * exports again. That export is the copy this file imports, and it is taken a
 * day on because an anchor is a fact about a finished day — a mirror exported
 * the same day it sealed carries no anchor, and an import that had never put one
 * back would be untested where it matters.
 */
const ANCHOR_AT = new Date(EXPORT_AT.getTime() + DAY_MS);

/** The instant both databases are asked the same questions at. */
const ASK_AT = ANCHOR_AT;

/** The fork's own run, an hour after the operator that joined it. */
const FORK_AT = new Date(ANCHOR_AT.getTime() + HOUR_MS);

/** Not `local`: the directory name and the captures base are part of the copy. */
const ENVIRONMENT = "demo";

const VERIFIED_REFERENCE = "mock-verified-import-e2e";

const SUBJECT = "example/kestrel-1";
const CITATION = "https://kestrel.example/pricing";
const PAGE: FixturePage = {
  body: "<!doctype html><html><body><main><h1>Kestrel pricing</h1><p>$40 per seat per month</p></main></body></html>",
  contentType: "text/html; charset=utf-8",
};

/** The page the challenger cites, which says something else. */
const CORRECTION_CITATION = "https://kestrel.example/pricing-2026";
const CORRECTION_PAGE: FixturePage = {
  body: "<!doctype html><html><body><main><h1>Kestrel pricing</h1><p>$44 per seat per month</p></main></body></html>",
  contentType: "text/html; charset=utf-8",
};

/** The day the seeded read counts are published for, and how many. */
const READ_DAY = "2026-09-09";
const READS = 10_000;

/** What the model answered, which the log only ever hashed. */
const MODEL_ANSWER = "example/kestrel-1 seat pricing is $40 per seat per month";

interface Party {
  readonly operator: string;
  readonly agent: TestAgent;
}

let origin: TestDatabase;
let fork: TestDatabase;
let deps: RequestDeps;
let maintainer: TestAgent;
let witness: FakeWitness;
let k1: Party;
let k2: Party;
let k3: Party;
let k4: Party;
/** A bare key with no operator behind it: the challenger. */
let challenger: TestAgent;
/** The operator that joins the fork after nomankind stopped. */
let newcomer: Party;

let entryId = "";
let correctionId = "";
let entryCore: Core;
let attestation = "";

/** The bytes the origin's sweep pushed: the copy this file replays. */
let pushed: MockMirrorAdapter;
let workspace = "";
let mirrorDir = "";

/** What the import said it wrote. */
let summary: ImportSummary;

const beacon = new FixtureBeacon("import-mirror-e2e");
const payout = new MockPayoutAdapter();

/** The environment one database is served under. Only the bindings differ. */
function envFor(store: TestDatabase, sealingKey: string): Env {
  return {
    DB: store.db,
    CAPTURES: store.captures,
    ENVIRONMENT,
    MAINTAINER_AGENT_ID: maintainer.agentId,
    SEALING_AGENT_KEY: sealingKey,
  };
}

let originEnv: Env;
let forkEnv: Env;

function send(
  request: Request,
  env: Env = originEnv,
  now: Date = NOW,
): Promise<Response> {
  return handleRequest(request, env, { ...deps, now });
}

/**
 * An HttpClient that routes straight into the origin's router, with no network.
 *
 * The verification the import runs first fetches every capture an entry names
 * from the manifest's `captures_base`, which is demo.nomankind.ai — a real
 * origin this test has no business reaching, and the reason the client routes by
 * path rather than by host.
 */
class InProcessHttp implements HttpClient {
  async fetch(request: Request): Promise<Response> {
    const url = new URL(request.url);
    return send(
      new Request(`${TEST_ORIGIN}${url.pathname}${url.search}`, request),
    );
  }
}

async function post(
  agent: TestAgent,
  path: string,
  body: unknown,
  where: { readonly env?: Env; readonly at?: Date } = {},
): Promise<{ status: number; body: Record<string, unknown> }> {
  const now = where.at ?? NOW;
  const request = await signedPost(agent, {
    path,
    body,
    timestamp: now.toISOString(),
  });
  const response = await send(request, where.env ?? originEnv, now);
  return {
    status: response.status,
    body: (await response.json()) as Record<string, unknown>,
  };
}

async function register(
  party: Party,
  where: { readonly env?: Env; readonly at?: Date } = {},
): Promise<void> {
  const at = (where.at ?? NOW).toISOString();
  const answer = await post(
    party.agent,
    "/operators",
    {
      operator: party.operator,
      attestation: await attestFor(party.agent, party.operator, at),
      payout: { reference: VERIFIED_REFERENCE },
    },
    where,
  );
  expect([answer.status, party.operator]).toEqual([201, party.operator]);
}

async function name(party: Party): Promise<void> {
  const answer = await post(maintainer, "/genesis", { operator: party.operator });
  expect([answer.status, party.operator]).toEqual([200, party.operator]);
}

async function approve(party: Party, id: string, hash: string): Promise<void> {
  const record = {
    agent: party.agent.agentId,
    operator: party.operator,
    decision: "approve",
    reason: null,
    snapshot_hash: hash,
    assigned_random: false,
    test_accepted: null,
    reproduction: null,
    observation: null,
    signed_at: AT,
  } as unknown as ApproverRecord;
  const signature = await signRecord(
    id,
    "validation",
    record,
    party.agent.privateKey,
  );
  const answer = await post(party.agent, `/entries/${id}/validate`, {
    record,
    signature,
  });
  expect([answer.status, answer.body["error"] ?? null]).toEqual([201, null]);
}

/** Every event one log holds, in seq order. */
async function wholeLog(store: TestDatabase): Promise<Event[]> {
  const head = await headSeq(store.db);
  if (head === null) return [];
  const events: Event[] = [];
  for (let from = 0; from <= head; from += LIST_PAGE_LIMIT) {
    events.push(
      ...(await eventsInRange(
        store.db,
        from,
        Math.min(from + LIST_PAGE_LIMIT - 1, head),
      )),
    );
  }
  return events;
}

/**
 * One whole drift attestation, through the repository's own writers: the
 * request, the model's answers, and one signed score per scorer.
 *
 * Through the writers rather than the doors because the doors want a pool
 * snapshot sealed before a beacon round and a probe set drawn from the observed
 * tier, which is M22's subject. What matters here is that the log holds a real
 * attestation and the store holds the answers the log only hashed, because those
 * two are exactly what an import has to put back and what `/attestations/{id}`
 * is asked for below.
 */
async function seedAttestation(): Promise<void> {
  const probes: readonly Probe[] = [
    { entry_id: entryId, entry_hash: await entryHash(entryCore) },
  ];
  const probeHash = await probeSetHash(probes);
  const beaconRound = 4_343;
  const snapshotSeq = (await headSeq(origin.db)) ?? 0;
  attestation = await attestationId({
    model: k1.agent.agentId,
    pool_snapshot_seq: snapshotSeq,
    beacon_round: beaconRound,
    probe_hash: probeHash,
  });
  const scorers: readonly AttestationScorer[] = [k2, k3].map((party) => ({
    operator: party.operator,
    agent: party.agent.agentId,
  }));

  const events: Event[] = [];
  events.push(
    await recordAttestationRequest(origin.db, {
      event: {
        at: AT,
        type: "attestation_requested",
        entry_id: null,
        payload: {
          attestation,
          domain: DEFAULT_DOMAIN,
          model: k1.agent.agentId,
          model_operator: k1.operator,
          probes,
          probe_hash: probeHash,
          probe_count: probes.length,
          pool_snapshot_seq: snapshotSeq,
          beacon_round: beaconRound,
          beacon_randomness: "cd".repeat(32),
          scorers,
          deadline: attestationDeadline(AT),
        },
      },
      row: (event) => deriveAttestation([event], { now: AT }),
      scorers,
    }),
  );

  const answers: readonly ProbeAnswer[] = [
    { entry_id: entryId, answer: MODEL_ANSWER },
  ];
  const hashed = await answersHash(answers);
  events.push(
    await recordAttestationAnswers(origin.db, {
      event: {
        at: AT,
        type: "attestation_answered",
        entry_id: null,
        payload: { attestation, answers_hash: hashed },
      },
      id: attestation,
      answers,
      attestation: (event) => deriveAttestation([...events, event], { now: AT }),
    }),
  );

  for (const party of [k2, k3]) {
    const record: AttestationScoreRecord = {
      agent: party.agent.agentId,
      operator: party.operator,
      agreed: probes.length,
      probe_hash: probeHash,
      answers_hash: hashed,
      signed_at: AT,
    };
    events.push(
      await recordAttestationScore(origin.db, {
        event: {
          at: AT,
          type: "attestation_scored",
          entry_id: null,
          payload: {
            attestation,
            record,
            signature: await signRecord(
              attestation,
              "attestation_score",
              record,
              party.agent.privateKey,
            ),
          },
        },
        id: attestation,
        operator: party.operator,
        answers,
        attestation: (event) => deriveAttestation([...events, event], { now: AT }),
      }),
    );
  }
}

/** Run the sweep the alarm runs, over one database, with the fakes. */
async function sweepOn(
  env: Env,
  at: Date,
  mirror: MockMirrorAdapter,
): Promise<SweepReport> {
  await beacon.advance(at.toISOString());
  return runSweep(env, {
    now: at,
    beacon,
    payout,
    mirror,
    trigger: "alarm",
    witness: new FakeWitnessAdapter({ signers: [witness] }),
    pinned: pinnedSet([witness]),
    ineligibleAgents: new Set<string>(),
    anchor: new FakeAnchorAdapter(null),
  });
}

/** One export, as the layout keys its files: without the environment prefix. */
function filesOf(mirror: MockMirrorAdapter): Map<string, string> {
  const files = new Map<string, string>();
  for (const [path, content] of mirror.files) {
    files.set(path.slice(`${ENVIRONMENT}/`.length), content);
  }
  return files;
}

/** Write one export to disk, under the environment's own directory. */
async function writeMirrorDirectory(target: string): Promise<void> {
  for (const [path, content] of filesOf(pushed)) {
    const at = join(target, path);
    await mkdir(dirname(at), { recursive: true });
    await writeFile(at, content, "utf8");
  }
}

// ---------------------------------------------------------------------------
// The comparison
// ---------------------------------------------------------------------------

/** One GET, asked of one database at one instant, as JSON. */
async function ask(
  env: Env,
  path: string,
): Promise<{ status: number; body: unknown }> {
  const response = await handleRequest(
    new Request(`${TEST_ORIGIN}${path}`, {
      headers: { accept: "application/json" },
    }),
    env,
    { ...deps, now: ASK_AT },
  );
  return { status: response.status, body: (await response.json()) as unknown };
}

/** Drop one field, named by the path to it, `*` standing for every array item. */
function remove(value: unknown, path: readonly string[]): void {
  const [head, ...rest] = path;
  if (head === undefined || typeof value !== "object" || value === null) return;
  if (Array.isArray(value)) {
    if (head !== "*") return;
    for (const item of value as unknown[]) remove(item, rest);
    return;
  }
  const record = value as Record<string, unknown>;
  if (rest.length === 0) {
    delete record[head];
    return;
  }
  remove(record[head], rest);
}

/** One answer with the named fields removed, leaving what has to agree. */
function without(body: unknown, fields: readonly string[]): unknown {
  const copy = JSON.parse(JSON.stringify(body)) as unknown;
  for (const field of fields) remove(copy, field.split("/").slice(1));
  return copy;
}

/**
 * Ask both databases the same question, and hold the answers against each other.
 *
 * `differ` names every field the two are allowed to disagree about, as a path
 * from the body's root. There is no wildcard for a whole object: a field that
 * differs is named, at the call, with a comment saying why.
 *
 * Both answers are held to 200 as well as to each other, because two refusals
 * agree with each other perfectly and would prove nothing at all.
 */
async function sameAnswer(
  path: string,
  differ: readonly string[] = [],
): Promise<void> {
  const there = await ask(originEnv, path);
  const here = await ask(forkEnv, path);
  expect([path, there.status, here.status]).toEqual([path, 200, 200]);
  expect([path, without(here.body, differ)]).toEqual([
    path,
    without(there.body, differ),
  ]);
}

// ---------------------------------------------------------------------------
// The world
// ---------------------------------------------------------------------------

beforeAll(async () => {
  const snapshotHash = await pageHash(PAGE);
  const correctionHash = await pageHash(CORRECTION_PAGE);

  const pair = await generateKeypair();
  const sealingKey = base64urlEncode(await exportPrivateKeyPkcs8(pair.privateKey));

  origin = await openTestDatabase();
  fork = await openTestDatabase();
  maintainer = await makeAgent();
  witness = await makeWitness("witness.example");
  challenger = await makeAgent();
  k1 = { operator: "k1.example", agent: await makeAgent() };
  k2 = { operator: "k2.example", agent: await makeAgent() };
  k3 = { operator: "k3.example", agent: await makeAgent() };
  k4 = { operator: "k4.example", agent: await makeAgent() };
  newcomer = { operator: "k5.example", agent: await makeAgent() };
  const maintainerParty: Party = {
    operator: "maintainer.example",
    agent: maintainer,
  };

  // The newcomer's record is published from the start and nobody registers it
  // on the origin: it is the operator that joins the fork after nomankind
  // stopped, and the resolver is the world rather than either instance's.
  const records: Record<string, string[]> = {};
  for (const party of [k1, k2, k3, k4, newcomer, maintainerParty]) {
    records[txtRecordName(party.operator)] = [party.agent.agentId];
  }

  originEnv = envFor(origin, sealingKey);
  forkEnv = envFor(fork, sealingKey);
  deps = {
    now: NOW,
    dns: new FixtureResolver(records),
    payout,
    fetcher: new FixtureFetcher({
      [CITATION]: PAGE,
      [CORRECTION_CITATION]: CORRECTION_PAGE,
    }),
    beacon,
  };

  for (const party of [k1, k2, k3, k4]) {
    await register(party);
    await name(party);
  }
  await register(maintainerParty);

  // One v0.7 entry through the real door, decided on by the two operators that
  // did not submit it.
  const core = await submittedCore(k1.agent, {
    author_operator: k1.operator,
    subject: SUBJECT,
    category: "pricing",
    claim: "example/kestrel-1 seat pricing is $40 per seat per month",
    before: "$38 per seat per month",
    after: "$40 per seat per month",
    effective_at: "2026-09-01",
    citation: CITATION,
    snapshot_hash: snapshotHash,
    supersedes: null,
    evidence_tier: "stated",
  });
  entryId = core["id"] as string;
  entryCore = core;
  const submitted = await send(await submission(k1.agent, { core }));
  expect([submitted.status, entryId]).toEqual([201, entryId]);
  await approve(k2, entryId, snapshotHash);
  await approve(k3, entryId, snapshotHash);

  // And one dispute against it, by a bare key. Section 6: filing takes a stake
  // and the challenge is a correction entry of its own, so the log carries a
  // `dispute_filed`, a second submission and a stake — three shapes the replay
  // has to carry and the pages have to answer for.
  const correction = await submittedCore(challenger, {
    author_operator: null,
    subject: SUBJECT,
    category: "correction",
    claim: "example/kestrel-1 seat pricing is $44 per seat per month, not $40",
    before: "$40 per seat per month",
    after: "$44 per seat per month",
    effective_at: "2026-09-02",
    citation: CORRECTION_CITATION,
    snapshot_hash: correctionHash,
    supersedes: null,
    evidence_tier: "stated",
  });
  correctionId = correction["id"] as string;
  const filed = await post(challenger, `/entries/${entryId}/dispute`, {
    entry: {
      ...correction,
      signature: await signCore(correction, challenger.privateKey),
    },
  });
  expect([filed.status, filed.body["error"] ?? null]).toEqual([201, null]);

  // One published day of reads, so the ledger has something to be.
  const counted = await appendEvent(await wholeLog(origin), {
    at: AT,
    type: "read_count",
    entry_id: null,
    payload: {
      date: READ_DAY,
      reads: [{ entry_id: entryId, count: READS }],
      total: READS,
      counter_first: 1,
      counter_last: READS,
    },
  });
  await appendEvents(origin.db, [counted[counted.length - 1] as Event]);

  await seedAttestation();

  // The first run seals everything and exports the day; the second, a day on,
  // anchors what the first sealed and exports again. The bytes the second one
  // pushed are the copy the fork is started from.
  pushed = new MockMirrorAdapter();
  const sealed = await sweepOn(originEnv, EXPORT_AT, pushed);
  expect(sealed.sealed).not.toBeNull();
  const anchored = await sweepOn(originEnv, ANCHOR_AT, pushed);
  expect(anchored.anchored).not.toBeNull();
  expect(anchored.mirror).not.toBeNull();

  workspace = await mkdtemp(join(tmpdir(), "nomankind-import-e2e-"));
  mirrorDir = join(workspace, "log", ENVIRONMENT);
  await writeMirrorDirectory(mirrorDir);

  summary = await importMirror(mirrorDir, fork.db, { http: new InProcessHttp() });
}, 600_000);

afterAll(async () => {
  await fork?.dispose();
  await origin?.dispose();
  if (workspace !== "") await rm(workspace, { recursive: true, force: true });
});

// ---------------------------------------------------------------------------
// The same questions
// ---------------------------------------------------------------------------

describe("the fork answers what nomankind answered", () => {
  it("imported the whole sealed record", async () => {
    const newest = (await latestSeal(origin.db))!;
    expect([summary.environment, summary.head, summary.sealSeq]).toEqual([
      ENVIRONMENT,
      newest.last_seq,
      newest.seq,
    ]);
    // Two entries — the entry and the correction it is disputed by — one seal,
    // one anchor, five operators and the scored attestation.
    expect([summary.entries, summary.seals, summary.anchors]).toEqual([2, 1, 1]);
    expect([summary.operators, summary.attestations]).toEqual([5, 1]);
    expect(await headSeq(fork.db)).toBe(newest.last_seq);
  }, 600_000);

  it("serves the disputed entry and its correction the same way", async () => {
    await sameAnswer(`/entries/${entryId}`);
    await sameAnswer(`/entries/${correctionId}`);
  }, 600_000);

  it("serves the registry the same way, but for three fields", async () => {
    // Three fields, and each is a thing the sealed log does not carry.
    //
    // `payout_status` and `payout_reference` are the payment provider's
    // (D-053): the mirror is CC0 and a provider's name for an operator is not
    // the log's to publish, so an imported operator has neither and a fork
    // onboards its own operators before it pays any.
    //
    // `named_by` is which of the maintainer's agents exercised the genesis
    // naming. The `operator_trusted` event names the operator and not the agent
    // that named it, so a replay can say that the operator is trusted and from
    // which position — `trusted` and `trusted_seq` are compared here and agree —
    // and cannot invent the agent. Left off the row rather than guessed.
    const missing = [
      "details/payout_status",
      "details/payout_reference",
      "details/named_by",
    ];
    await sameAnswer(
      "/operators",
      missing.map((field) => `/operators/*/${field}`),
    );
    for (const party of [k1, k2, k3, k4]) {
      await sameAnswer(
        `/operators/${party.operator}`,
        missing.map((field) => `/${field}`),
      );
    }
  }, 600_000);

  it("serves the seal, the anchor and the attestation the same way", async () => {
    const newest = (await latestSeal(origin.db))!;
    const anchor = (await latestAnchor(origin.db))!;
    await sameAnswer(`/seals/${newest.seq}`);
    await sameAnswer(`/anchors/${anchor.date}`);
    await sameAnswer(`/attestations/${attestation}`);
  }, 600_000);

  it("recomputes the same standing at the same position", async () => {
    await sameAnswer("/standing");
  }, 600_000);

  it("serves the frozen reader the same entry, seal and receipt", async () => {
    // Asked once of each database and never twice of either: the receipt
    // carries a running counter the read itself moves, so the first read of the
    // imported log has to be held against the first read of nomankind's.
    await sameAnswer(`/read/${entryId}`);
  }, 600_000);
});

// ---------------------------------------------------------------------------
// The fork's own clockwork
// ---------------------------------------------------------------------------

describe("the fork's first sweep", () => {
  let rebuilt: MockMirrorAdapter;
  let report: SweepReport;

  beforeAll(async () => {
    rebuilt = new MockMirrorAdapter();
    report = await sweepOn(forkEnv, ANCHOR_AT, rebuilt);
  }, 600_000);

  it("seals nothing, because the imported head is already sealed", async () => {
    expect(report.sealed).toBeNull();
    expect(report.skipped["nothing_to_seal"]).toBe(1);
    const newest = (await latestSeal(fork.db))!;
    expect(newest.seq).toBe(summary.sealSeq);
    expect(newest.last_seq).toBe(summary.head);
  }, 600_000);

  it("reports every step of the sweep", async () => {
    const rows = await sweepSteps(fork.db);
    expect(rows.map((row) => row.step).sort()).toEqual([...SWEEP_STEPS].sort());
    for (const row of rows) {
      expect([row.step, row.last_run_at, row.trigger]).toEqual([
        row.step,
        ANCHOR_AT.toISOString(),
        "alarm",
      ]);
    }
  }, 600_000);

  it("exports the same bytes for the same sealed head", async () => {
    expect(report.mirror).not.toBeNull();
    expect(report.mirror!.head).toBe(summary.head);

    const source = filesOf(pushed);
    const again = filesOf(rebuilt);
    expect([...again.keys()].sort()).toEqual([...source.keys()].sort());
    for (const [path, content] of source) {
      expect([path, again.get(path)]).toEqual([path, content]);
    }
  }, 600_000);

  it("points at its own export, over the same record", async () => {
    // The mirror row is the one thing here that is the fork's rather than
    // nomankind's: it is where this instance pushed. So the commit, the tree,
    // the two URLs built from the commit, and how many files that push changed
    // are the fork's own — and the day, the instant, the sealed head, the seal
    // and the entry count are the record's and have to agree.
    await sameAnswer("/mirror/latest", [
      "/latest/commit",
      "/latest/tree",
      "/latest/files_changed",
      "/latest/url",
      "/latest/raw_url",
    ]);
  }, 600_000);
});

// ---------------------------------------------------------------------------
// And then it keeps going
// ---------------------------------------------------------------------------

describe("the fork's own next seal", () => {
  it("chains onto the last seal nomankind made", async () => {
    const imported = (await latestSeal(fork.db))!;
    expect(imported.seq).toBe(summary.sealSeq);

    // One new operator joins the fork through the real door. Nothing about it
    // is in the mirror: it is the first thing that ever happened to this log.
    await register(newcomer, { env: forkEnv, at: ANCHOR_AT });
    expect(await headSeq(fork.db)).toBeGreaterThan(summary.head);

    const report = await sweepOn(forkEnv, FORK_AT, new MockMirrorAdapter());
    expect(report.sealed).not.toBeNull();

    const sealed = (await latestSeal(fork.db))!;
    expect([sealed.seq, sealed.first_seq, sealed.prev_hash]).toEqual([
      imported.seq + 1,
      imported.last_seq + 1,
      imported.hash,
    ]);

    // And the registration is inside it: the new events are sealed by the seal
    // that chains onto nomankind's last one.
    const events = await wholeLog(fork);
    const registered = events.find(
      (event) =>
        event.type === "operator_registered" &&
        (event.payload as { operator?: string }).operator === newcomer.operator,
    )!;
    expect(registered.seq).toBeGreaterThanOrEqual(sealed.first_seq);
    expect(registered.seq).toBeLessThanOrEqual(sealed.last_seq);
  }, 600_000);
});
