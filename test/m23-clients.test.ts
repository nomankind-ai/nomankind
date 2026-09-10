/**
 * M23's two commands, driven in process against the real Worker.
 *
 * Whitepaper Section 11, "Deployment and status": the sealed log is exported
 * daily to a public repository under CC0, and the Conclusion says what that is
 * for — the exit is a copy rather than a promise. A copy is only worth having
 * if a stranger can make it and check it, so this file makes both halves of
 * that claim falsifiable:
 *
 *   - `npm run mirror -- <base-url> <out-dir>` builds the `<env>/` layout from
 *     nothing but the public doors, and its bytes are the bytes the Worker's
 *     own sweep pushed for the same sealed head — path for path, file for file;
 *   - `npm run verify-mirror -- <mirror-dir>` checks that directory end to end
 *     and exits 0, and exits 1 with a named check the moment one entry file or
 *     one event line is edited.
 *
 * The world holds both kinds of record the mirror can carry: a v0.7 entry
 * submitted through the real door and verified by two named operators, and a
 * legacy v0.6 record seeded straight into the store, which no door would take
 * and which the demo's own log already holds. The v0.6 one is reported as
 * legacy and never as ok — it was sealed before the domain key existed, and
 * v0.7's rules cannot be applied to bytes that never claimed them — but
 * "legacy" is a description of the record, never a pass: an edited status, hash,
 * index row or core in a legacy file is a named failure and exit 1, exactly as
 * it is in a v0.7 one, and the tests below edit each of them to prove it.
 *
 * No network anywhere: the http client routes straight into `handleRequest`,
 * the fetcher reads a fixture page, and the clock is injected — the mirror
 * command runs at the very instant the sweep exported at, which is what lets
 * the two `exported_at` stamps be the same string.
 */

import { cp, mkdir, mkdtemp, readFile, readdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, relative } from "node:path";

import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { FixtureBeacon } from "../src/adapters/beacon.js";
import {
  attestationDeadline,
  attestationId,
  deriveAttestation,
} from "../src/attest.js";
import { MockMirrorAdapter } from "../src/adapters/mirror.js";
import { MockPayoutAdapter } from "../src/adapters/payout.js";
import { type Core } from "../src/core.js";
import { deriveEntry } from "../src/derive.js";
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
import { answersHash, probeSetHash, type ProbeAnswer } from "../src/probe.js";
import { exportPrivateKeyPkcs8, generateKeypair } from "../src/identity.js";
import { runMirror } from "../src/cli/mirror.js";
import { mirrorVerifyPlan, verifyMirror } from "../src/cli/verify-mirror.js";
import type { HttpClient, ValidatorIo } from "../src/cli/validator.js";
import { DEFAULT_DOMAIN, LIST_PAGE_LIMIT, NORM_VERSION } from "../src/policy.js";
import { signRecord } from "../src/records.js";
import type { Entry } from "../src/schema.js";
import { signCore } from "../src/sign.js";
import { entryIdFor } from "../src/submit.js";
import {
  appendEvents,
  headSeq,
  putEntry,
  recordAttestationAnswers,
  recordAttestationRequest,
  recordAttestationScore,
} from "../src/storage/repository.js";
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
import {
  FixtureFetcher,
  SUBMIT_NOW,
  bytesOf,
  pageHash,
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

const NOW = SUBMIT_NOW;
const AT = NOW.toISOString();
const HOUR_MS = 3_600_000;

/** The instant the sweep exports at, and the instant the command runs at. */
const EXPORT_AT = new Date(NOW.getTime() + HOUR_MS);

/**
 * The environment the mirror lands under. Not `local`: the directory name is
 * part of what is under test, and so is the public origin the manifest's
 * `captures_base` is built from.
 */
const ENVIRONMENT = "demo";

const VERIFIED_REFERENCE = "mock-verified-m23-clients";

const SUBJECT = "kestrel/kestrel-1";
const CATEGORY = "pricing";
const CITATION = "https://kestrel.example/pricing";
const PAGE: FixturePage = {
  body: "<!doctype html><html><body><main><h1>Kestrel pricing</h1><p>$40 per seat per month</p></main></body></html>",
  contentType: "text/html; charset=utf-8",
};

interface Party {
  readonly operator: string;
  readonly agent: TestAgent;
}

let store: TestDatabase;
let env: Env;
let deps: RequestDeps;
let maintainer: TestAgent;
let witness: FakeWitness;
let k1: Party;
let k2: Party;
let k3: Party;

let pageHashValue = "";
let entryId = "";
let legacyId = "";
/** The v0.7 core the door took, which the seeded probe set asks about. */
let entryCore: Core;

/** The mirror the sweep pushed to: the bytes the command has to reproduce. */
let mirror: MockMirrorAdapter;

/** The directory the command wrote, kept pristine for the copies below. */
let pristine = "";
let workspace = "";

const beacon = new FixtureBeacon("m23-clients");
const payout = new MockPayoutAdapter();

function send(request: Request, now: Date = NOW): Promise<Response> {
  return handleRequest(request, env, { ...deps, now, beacon });
}

/**
 * An HttpClient that routes straight into the router, with no network.
 *
 * The path is what is kept: the mirror command asks a base URL and the verify
 * command asks the manifest's `captures_base`, which names demo.nomankind.ai —
 * a real origin this test has no business reaching, and the reason the client
 * routes by path rather than by host.
 */
class InProcessHttp implements HttpClient {
  calls = 0;
  constructor(private readonly now: Date = NOW) {}
  async fetch(request: Request): Promise<Response> {
    this.calls += 1;
    const url = new URL(request.url);
    return send(
      new Request(`${TEST_ORIGIN}${url.pathname}${url.search}`, request),
      this.now,
    );
  }
}

/** A client that must not be used: proof a local archive was read instead. */
class RefusingHttp implements HttpClient {
  calls = 0;
  async fetch(): Promise<Response> {
    this.calls += 1;
    throw new Error("m23-clients: no capture may be fetched in this run");
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

async function post(
  agent: TestAgent,
  path: string,
  body: unknown,
): Promise<{ status: number; body: Record<string, unknown> }> {
  const request = await signedPost(agent, { path, body, timestamp: AT });
  const response = await send(request);
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

async function approve(party: Party, id: string): Promise<void> {
  const record = {
    agent: party.agent.agentId,
    operator: party.operator,
    decision: "approve",
    reason: null,
    snapshot_hash: pageHashValue,
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

/**
 * A seventeen-key core: exactly what an author signed under v0.6, with no
 * `domain` key at all rather than a null one. Its id is the hash of the
 * seventeen keys it actually carried, so no door could have made it.
 */
async function legacyCore(agent: TestAgent): Promise<Core> {
  const core = {
    id: null,
    subject: SUBJECT,
    category: CATEGORY,
    claim: "kestrel/kestrel-1 seat pricing was $38 per seat per month",
    before: "$35 per seat per month",
    after: "$38 per seat per month",
    effective_at: "2026-08-01",
    evidence_tier: "stated",
    evidence: null,
    observation: null,
    citation: CITATION,
    snapshot_hash: pageHashValue,
    norm_version: NORM_VERSION,
    supersedes: null,
    author: agent.agentId,
    author_operator: null,
    submitted_at: AT,
  } as unknown as Core;
  return { ...core, id: await entryIdFor(core) };
}

/** Every event the log holds, as `GET /events` serves them. */
async function allEvents(): Promise<Event[]> {
  const response = await send(
    new Request(`${TEST_ORIGIN}/events?limit=${LIST_PAGE_LIMIT}`),
  );
  const body = (await response.json()) as Record<string, unknown>;
  const events = body["events"];
  return Array.isArray(events) ? (events as Event[]) : [];
}

/** Every file under a directory, by its path relative to it. */
async function filesUnder(dir: string): Promise<Map<string, string>> {
  const found = new Map<string, string>();
  const walk = async (at: string): Promise<void> => {
    for (const item of await readdir(at, { withFileTypes: true })) {
      const path = join(at, item.name);
      if (item.isDirectory()) await walk(path);
      else found.set(relative(dir, path).split("\\").join("/"), await readFile(path, "utf8"));
    }
  };
  await walk(dir);
  return found;
}

/** A fresh copy of the pristine export, for a test that edits one of its files. */
async function copyOfMirror(name: string): Promise<string> {
  const target = join(workspace, name);
  await rm(target, { recursive: true, force: true });
  await cp(pristine, target, { recursive: true });
  return target;
}

/** The day the seeded read counts are published for, and how many. */
const READ_DAY = "2026-09-09";
const READS = 10_000;

/** The seeded attestation's id, and what the model answered. */
let attestation = "";
const MODEL_ANSWER = "kestrel/kestrel-1 seat pricing is $40 per seat per month";

/**
 * One whole drift attestation, written through the repository's own writers:
 * the request, the model's answers, and one signed score per scorer.
 *
 * Through the writers rather than through the doors because the doors want a
 * pool snapshot committed before a beacon round and a probe set drawn from the
 * observed tier, which is M22's subject and not this file's. What matters here
 * is that the log holds a real attestation — real ids, real signatures over the
 * real canonical bytes — and that the store holds the answers the log only
 * hashed, because those two are exactly what the export has to put in a file.
 */
async function seedAttestation(): Promise<void> {
  const probes: readonly Probe[] = [
    { entry_id: entryId, entry_hash: await entryHash(entryCore) },
  ];
  const probeHash = await probeSetHash(probes);
  const beaconRound = 4_242;
  const snapshotSeq = (await headSeq(store.db)) ?? 0;
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
  const requested = await recordAttestationRequest(store.db, {
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
        beacon_randomness: "ab".repeat(32),
        scorers,
        deadline: attestationDeadline(AT),
      },
    },
    row: (event) => deriveAttestation([event], { now: AT }),
    scorers,
  });
  events.push(requested);

  const answers: readonly ProbeAnswer[] = [
    { entry_id: entryId, answer: MODEL_ANSWER },
  ];
  const hashed = await answersHash(answers);
  const answered = await recordAttestationAnswers(store.db, {
    event: {
      at: AT,
      type: "attestation_answered",
      entry_id: null,
      payload: { attestation, answers_hash: hashed },
    },
    id: attestation,
    answers,
    attestation: (event) => deriveAttestation([...events, event], { now: AT }),
  });
  events.push(answered);

  for (const party of [k2, k3]) {
    const record: AttestationScoreRecord = {
      agent: party.agent.agentId,
      operator: party.operator,
      agreed: probes.length,
      probe_hash: probeHash,
      answers_hash: hashed,
      signed_at: AT,
    };
    const scored = await recordAttestationScore(store.db, {
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
    });
    events.push(scored);
  }
}

beforeAll(async () => {
  pageHashValue = await pageHash(PAGE);

  const pair = await generateKeypair();
  const sealingKey = base64urlEncode(await exportPrivateKeyPkcs8(pair.privateKey));

  store = await openTestDatabase();
  maintainer = await makeAgent();
  witness = await makeWitness("witness.example");
  k1 = { operator: "k1.example", agent: await makeAgent() };
  k2 = { operator: "k2.example", agent: await makeAgent() };
  k3 = { operator: "k3.example", agent: await makeAgent() };
  const maintainerParty: Party = {
    operator: "maintainer.example",
    agent: maintainer,
  };

  const records: Record<string, string[]> = {};
  for (const party of [k1, k2, k3, maintainerParty]) {
    records[`_nomankind.${party.operator}`] = [party.agent.agentId];
  }

  env = {
    DB: store.db,
    CAPTURES: store.captures,
    ENVIRONMENT,
    MAINTAINER_AGENT_ID: maintainer.agentId,
    SEALING_AGENT_KEY: sealingKey,
  };
  deps = {
    now: NOW,
    dns: new FixtureResolver(records),
    payout,
    fetcher: new FixtureFetcher({ [CITATION]: PAGE }),
    beacon,
  };

  for (const party of [k1, k2, k3]) {
    await register(party);
    await name(party);
  }
  await register(maintainerParty);

  // One v0.7 entry through the real door, verified by the two operators that
  // did not submit it (the pool is below the switch, so two approvals verify).
  const core = await submittedCore(k1.agent, {
    author_operator: k1.operator,
    subject: SUBJECT,
    category: CATEGORY,
    claim: "kestrel/kestrel-1 seat pricing is $40 per seat per month",
    before: "$38 per seat per month",
    after: "$40 per seat per month",
    effective_at: "2026-09-01",
    citation: CITATION,
    snapshot_hash: pageHashValue,
    supersedes: null,
    evidence_tier: "stated",
  });
  entryId = core["id"] as string;
  entryCore = core;
  const submitted = await send(
    await signedPost(k1.agent, {
      path: "/entries",
      body: { entry: { ...core, signature: await signCore(core, k1.agent.privateKey) } },
      timestamp: AT,
    }),
  );
  expect([submitted.status, entryId]).toEqual([201, entryId]);
  await approve(k2, entryId);
  await approve(k3, entryId);

  // And one legacy v0.6 record, seeded straight into the store because no door
  // would take it. It stands for what the demo's own log already holds.
  const legacy = await legacyCore(k1.agent);
  legacyId = legacy["id"] as string;
  const appended = await appendEvent(await allEvents(), {
    at: AT,
    type: "entry_submitted",
    entry_id: legacyId,
    payload: { core: legacy, signature: await signCore(legacy, k1.agent.privateKey) },
  });
  const event = appended[appended.length - 1] as Event;
  await appendEvents(store.db, [event]);
  const derived = deriveEntry([event], legacyId, { now: AT });
  await putEntry(store.db, derived.entry as Entry, derived.sidecar, event.seq);

  // One published day of reads on the verified entry, seeded the same way the
  // legacy record is: `read_count` is the publish step's own event, and what
  // this file is about is the export of a log that holds one, not the step that
  // writes it. It gives the ledger something to be.
  const counted = await appendEvent(await allEvents(), {
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
  await appendEvents(store.db, [counted[counted.length - 1] as Event]);

  // And one drift attestation, through the store's own writers, so the export
  // has an attestation file with the model's answers beside it. k1's key is the
  // model and k2 and k3 score it: Section 8's "none under the model's operator".
  await seedAttestation();

  // The sweep seals both records and exports the day, which is the directory
  // the command below has to reproduce byte for byte.
  mirror = new MockMirrorAdapter();
  await beacon.advance(EXPORT_AT.toISOString());
  const report = await runSweep(env, {
    now: EXPORT_AT,
    beacon,
    payout,
    mirror,
    trigger: "alarm",
    witness: new FakeWitnessAdapter({ signers: [witness] }),
    pinned: pinnedSet([witness]),
    ineligibleAgents: new Set<string>(),
    anchor: new FakeAnchorAdapter(null),
  });
  expect(report.mirror).not.toBeNull();

  workspace = await mkdtemp(join(tmpdir(), "nomankind-m23-"));
  pristine = join(workspace, "pristine");
}, 600_000);

afterAll(async () => {
  await store?.dispose();
  if (workspace !== "") await rm(workspace, { recursive: true, force: true });
});

// ---------------------------------------------------------------------------
// mirror
// ---------------------------------------------------------------------------

describe("the mirror command rebuilds the export from the public doors", () => {
  it("writes the environment's directory and says what it exported", async () => {
    const io = recorder();
    const code = await runMirror(
      [TEST_ORIGIN, pristine],
      io.io,
      new InProcessHttp(),
      EXPORT_AT,
    );
    expect([code, io.out.join("\n")]).toEqual([0, io.out.join("\n")]);
    expect(code).toBe(0);
    expect(io.out[0]).toMatch(/^mirror demo head \d+ seal \d+ files \d+$/);
    expect(io.out[1]).toBe(join(pristine, ENVIRONMENT));
  }, 600_000);

  it("is byte-identical to what the Worker pushed for the same sealed head", async () => {
    const written = await filesUnder(join(pristine, ENVIRONMENT));
    const pushed = new Map<string, string>();
    for (const [path, content] of mirror.files) {
      pushed.set(path.slice(`${ENVIRONMENT}/`.length), content);
    }

    expect([...written.keys()].sort()).toEqual([...pushed.keys()].sort());
    // Both records are in it: the entry the door took and the legacy one.
    expect([...written.keys()]).toContain(`entries/${entryId}.json`);
    expect([...written.keys()]).toContain(`entries/${legacyId}.json`);
    for (const [path, content] of pushed) {
      expect([path, written.get(path)]).toEqual([path, content]);
    }
  }, 600_000);

  it("carries the three families the layout recomputes, with their counts", async () => {
    const written = await filesUnder(join(pristine, ENVIRONMENT));
    expect([...written.keys()]).toContain(`attestations/${attestation}.json`);
    expect([...written.keys()]).toContain("standing.json");
    expect([...written.keys()]).toContain("ledger.jsonl");

    // The attestation is the fold's, and the answers are the ones the store
    // holds: the log carries only their hash, so the command had to ask for
    // them through `GET /attestations/{id}` and get the same set the sweep read
    // out of its own database.
    const record = JSON.parse(written.get(`attestations/${attestation}.json`)!) as {
      attestation: Record<string, unknown>;
      answers: { entry_id: string; answer: string }[];
    };
    expect(record.attestation["id"]).toBe(attestation);
    expect(record.attestation["status"]).toBe("scored");
    expect(record.attestation["score"]).toEqual({ agreed: 1, probe_count: 1 });
    expect(record.answers).toEqual([{ entry_id: entryId, answer: MODEL_ANSWER }]);

    const standing = JSON.parse(written.get("standing.json")!) as {
      position: number;
      operators: { operator: string }[];
    };
    expect(standing.operators.map((one) => one.operator)).toEqual([
      "k1.example",
      "k2.example",
      "k3.example",
      "maintainer.example",
    ]);

    const ledger = written
      .get("ledger.jsonl")!
      .split("\n")
      .filter((line) => line.length > 0)
      .map((line) => JSON.parse(line) as Record<string, unknown>);
    expect(ledger.length).toBeGreaterThan(0);
    // The day is reconciled and nothing is priced: this world's entry is a
    // draft — three operators outside the submitter's own are what verify one,
    // and there are two here — and Section 9 pays for verified entries, so the
    // reconciliation names it under `unpriced` rather than passing over it.
    expect(ledger).toHaveLength(1);
    expect(ledger[0]!["kind"]).toBe("reconciliation");
    expect(ledger[0]!["date"]).toBe(READ_DAY);
    expect((ledger[0]!["ref"] as Record<string, unknown>)["unpriced"]).toEqual([
      entryId,
    ]);

    const manifest = JSON.parse(written.get("mirror.json")!) as Record<
      string,
      unknown
    >;
    expect(manifest["attestations"]).toBe(1);
    expect(manifest["ledger_rows"]).toBe(ledger.length);
    expect(manifest["standing_position"]).toBe(standing.position);
  }, 600_000);

  it("refuses a call that is not one, before any read", async () => {
    const io = recorder();
    const http = new InProcessHttp();
    expect(await runMirror([TEST_ORIGIN], io.io, http, EXPORT_AT)).toBe(2);
    expect(http.calls).toBe(0);
  });
});

// ---------------------------------------------------------------------------
// verify-mirror
// ---------------------------------------------------------------------------

describe("verify-mirror checks a fresh clone end to end", () => {
  it("exits 0, with a line per item and one summary", async () => {
    const io = recorder();
    const code = await verifyMirror(
      [join(pristine, ENVIRONMENT)],
      io.io,
      new InProcessHttp(),
    );
    expect([code, io.out.join("\n")]).toEqual([0, io.out.join("\n")]);
    expect(code).toBe(0);
    expect(io.out).toContain("ok mirror.json");
    expect(io.out).toContain("ok events");
    expect(io.out).toContain("ok seal/0");
    expect(io.out).toContain(`ok ${entryId}`);
    expect(io.out[io.out.length - 1]).toMatch(
      /^summary demo head \d+ seals 1 anchors \d+ entries 2 ok 1 legacy 1 failed 0$/,
    );
  }, 600_000);

  it("re-derives the attestations, standing and the ledger from the events", async () => {
    const io = recorder();
    const code = await verifyMirror(
      [join(pristine, ENVIRONMENT)],
      io.io,
      new InProcessHttp(),
    );
    expect([code, io.out.join("\n")]).toEqual([0, io.out.join("\n")]);
    expect(io.out).toContain(`ok attestation/${attestation}`);
    expect(io.out).toContain("ok standing");
    expect(io.out).toContain("ok ledger");
  }, 600_000);

  it("exits 1 and names the check when the attestation file is edited", async () => {
    const dir = join(await copyOfMirror("edited-attestation"), ENVIRONMENT);
    const path = join(dir, "attestations", `${attestation}.json`);
    const file = JSON.parse(await readFile(path, "utf8")) as {
      attestation: Record<string, unknown>;
    };
    expect(file.attestation["score"]).toEqual({ agreed: 1, probe_count: 1 });
    file.attestation["score"] = { agreed: 0, probe_count: 1 };
    await writeFile(path, `${JSON.stringify(file, null, 2)}\n`, "utf8");

    const io = recorder();
    const code = await verifyMirror([dir], io.io, new InProcessHttp());
    expect(code).toBe(1);
    expect(io.out).toContain(
      `FAIL attestation/${attestation} attestation /attestation/score mismatch`,
    );
    // The rest of the layout is untouched, and says so.
    expect(io.out).toContain("ok standing");
    expect(io.out).toContain("ok ledger");
  }, 600_000);

  it("exits 1 and names the check when a standing row is edited", async () => {
    const dir = join(await copyOfMirror("edited-standing"), ENVIRONMENT);
    const path = join(dir, "standing.json");
    const file = JSON.parse(await readFile(path, "utf8")) as {
      operators: Record<string, unknown>[];
    };
    const index = file.operators.findIndex(
      (one) => one["operator"] === "k2.example",
    );
    expect(index).toBeGreaterThanOrEqual(0);
    file.operators[index]!["standing"] =
      (file.operators[index]!["standing"] as number) + 1_000;
    await writeFile(path, `${JSON.stringify(file, null, 2)}\n`, "utf8");

    const io = recorder();
    const code = await verifyMirror([dir], io.io, new InProcessHttp());
    expect(code).toBe(1);
    expect(io.out).toContain(
      `FAIL standing standing /operators/${index}/standing mismatch`,
    );
    expect(io.out).toContain("ok ledger");
  }, 600_000);

  it("exits 1 and names the check when a ledger line is edited", async () => {
    const dir = join(await copyOfMirror("edited-ledger"), ENVIRONMENT);
    const path = join(dir, "ledger.jsonl");
    const lines = (await readFile(path, "utf8"))
      .split("\n")
      .filter((line) => line.length > 0)
      .map((line) => JSON.parse(line) as Record<string, unknown>);
    expect(lines.length).toBeGreaterThan(0);
    lines[0]!["reads"] = 1;
    await writeFile(
      path,
      `${lines.map((line) => JSON.stringify(line)).join("\n")}\n`,
      "utf8",
    );

    const io = recorder();
    const code = await verifyMirror([dir], io.io, new InProcessHttp());
    expect(code).toBe(1);
    expect(io.out).toContain("FAIL ledger ledger /0/reads mismatch");
    expect(io.out).toContain("ok standing");
  }, 600_000);

  it("reports the v0.6 record as legacy and does not fail it", async () => {
    const io = recorder();
    const code = await verifyMirror(
      [join(pristine, ENVIRONMENT)],
      io.io,
      new InProcessHttp(),
    );
    expect(code).toBe(0);
    expect(io.out).toContain(
      `legacy ${legacyId} (v0.6 record, not decided on again; core, signature, ` +
        `derivation, chain, and seal checked; captures and records not, the ` +
        `verifier checks v0.7 only)`,
    );
    expect(io.out.filter((line) => line.startsWith("FAIL"))).toEqual([]);
  }, 600_000);

  it("checks only the entry --entry names", async () => {
    const io = recorder();
    const code = await verifyMirror(
      [join(pristine, ENVIRONMENT), "--entry", entryId],
      io.io,
      new InProcessHttp(),
    );
    expect(code).toBe(0);
    expect(io.out).toContain(`ok ${entryId}`);
    expect(io.out.some((line) => line.includes(legacyId))).toBe(false);
  }, 600_000);

  it("reads the captures out of a local archive when --captures names one", async () => {
    const archive = join(workspace, "captures");
    await mkdir(archive, { recursive: true });
    const hex = pageHashValue.slice("sha256:".length);
    await writeFile(join(archive, hex), bytesOf(PAGE));
    await writeFile(
      join(archive, `${hex}.meta.json`),
      `${JSON.stringify({ content_type: PAGE.contentType }, null, 2)}\n`,
      "utf8",
    );

    const io = recorder();
    const http = new RefusingHttp();
    const code = await verifyMirror(
      [join(pristine, ENVIRONMENT), "--captures", archive],
      io.io,
      http,
    );
    expect([code, io.out.join("\n")]).toEqual([0, io.out.join("\n")]);
    expect(code).toBe(0);
    expect(http.calls).toBe(0);
    expect(io.out).toContain(`ok ${entryId}`);
  }, 600_000);

  it("exits 1 and names the check when one entry file is edited", async () => {
    const dir = join(await copyOfMirror("edited-entry"), ENVIRONMENT);
    const path = join(dir, "entries", `${entryId}.json`);
    const file = JSON.parse(await readFile(path, "utf8")) as {
      entry: Record<string, unknown>;
    };
    file.entry["claim"] = "kestrel/kestrel-1 seat pricing is $4 per seat per month";
    await writeFile(path, `${JSON.stringify(file, null, 2)}\n`, "utf8");

    const io = recorder();
    const code = await verifyMirror([dir], io.io, new InProcessHttp());
    expect(code).toBe(1);
    const failures = io.out.filter((line) => line.startsWith(`FAIL ${entryId} `));
    expect(failures.length).toBeGreaterThan(0);
    expect(failures.some((line) => line.startsWith(`FAIL ${entryId} core /claim `))).toBe(
      true,
    );
    // The layout itself is still sound: only the entry failed.
    expect(io.out).toContain("ok mirror.json");
    expect(io.out).toContain("ok events");
  }, 600_000);

  /** One entry file of a fresh copy, edited by the caller and written back. */
  async function editEntry(
    name: string,
    id: string,
    edit: (file: {
      entry: Record<string, unknown>;
      sidecar: Record<string, unknown>;
      entry_hash: string;
    }) => void,
  ): Promise<string> {
    const dir = join(await copyOfMirror(name), ENVIRONMENT);
    const path = join(dir, "entries", `${id}.json`);
    const file = JSON.parse(await readFile(path, "utf8")) as {
      entry: Record<string, unknown>;
      sidecar: Record<string, unknown>;
      entry_hash: string;
    };
    edit(file);
    await writeFile(path, `${JSON.stringify(file, null, 2)}\n`, "utf8");
    return dir;
  }

  it("names the derivation when a legacy entry's status is edited", async () => {
    // The bug this pins: a legacy record used to be skipped before any check,
    // so a status somebody typed into the file passed with exit 0.
    const dir = await editEntry("edited-legacy-status", legacyId, (file) => {
      expect(file.entry["status"]).toBe("draft");
      file.entry["status"] = "verified";
    });

    const io = recorder();
    const code = await verifyMirror([dir], io.io, new InProcessHttp());
    expect(code).toBe(1);
    expect(io.out).toContain(`FAIL ${legacyId} derived /entry/status mismatch`);
    // Still described for what it is, and still never ok.
    expect(io.out.some((line) => line.startsWith(`legacy ${legacyId} `))).toBe(true);
    expect(io.out.some((line) => line.startsWith(`ok ${legacyId}`))).toBe(false);
  }, 600_000);

  it("names entry_hash when the file's own hash is edited", async () => {
    const dir = await editEntry("edited-hash", entryId, (file) => {
      file.entry_hash = `sha256:${"0".repeat(64)}`;
    });

    const io = recorder();
    const code = await verifyMirror([dir], io.io, new InProcessHttp());
    expect(code).toBe(1);
    expect(io.out).toContain(`FAIL ${entryId} entry_hash /entry_hash mismatch`);
  }, 600_000);

  it("names the index when the entry's row is edited", async () => {
    const dir = join(await copyOfMirror("edited-index"), ENVIRONMENT);
    const path = join(dir, "index.json");
    const index = JSON.parse(await readFile(path, "utf8")) as Record<
      string,
      unknown
    >[];
    const row = index.find((one) => one["id"] === entryId)!;
    expect(row["status"]).toBe("draft");
    row["status"] = "verified";
    await writeFile(path, `${JSON.stringify(index, null, 2)}\n`, "utf8");

    const io = recorder();
    const code = await verifyMirror([dir], io.io, new InProcessHttp());
    expect(code).toBe(1);
    expect(io.out).toContain(`FAIL ${entryId} index /index/status mismatch`);
    // The entry file itself is untouched, so the derivation still holds.
    expect(io.out.some((line) => line.startsWith(`FAIL ${entryId} derived `))).toBe(
      false,
    );
  }, 600_000);

  it("names the core or the signature when a legacy core is edited", async () => {
    const dir = await editEntry("edited-legacy-core", legacyId, (file) => {
      file.entry["claim"] =
        "kestrel/kestrel-1 seat pricing was $3 per seat per month";
    });

    const io = recorder();
    const code = await verifyMirror([dir], io.io, new InProcessHttp());
    expect(code).toBe(1);
    const failures = io.out.filter((line) =>
      line.startsWith(`FAIL ${legacyId} `),
    );
    expect(failures).toContain(`FAIL ${legacyId} core /entry/claim mismatch`);
    expect(failures).toContain(
      `FAIL ${legacyId} signature /entry/signature bad_signature`,
    );
  }, 600_000);

  it("exits 1 and names the chain when one event line is edited", async () => {
    const dir = join(await copyOfMirror("edited-events"), ENVIRONMENT);
    const path = join(dir, "events", "00000000.jsonl");
    const lines = (await readFile(path, "utf8")).split("\n");
    const first = JSON.parse(lines[0]!) as Record<string, unknown>;
    first["at"] = "2020-01-01T00:00:00.000Z";
    lines[0] = JSON.stringify(first);
    await writeFile(path, lines.join("\n"), "utf8");

    const io = recorder();
    const code = await verifyMirror([dir], io.io, new InProcessHttp());
    expect(code).toBe(1);
    expect(io.out).toContain("FAIL events chain /events/0 bad_hash");
  }, 600_000);

  it("refuses arguments that are not a run, before it opens anything", async () => {
    for (const args of [
      [],
      ["--entry", entryId],
      [join(pristine, ENVIRONMENT), "--nope", "x"],
      [join(pristine, ENVIRONMENT), "--entry"],
      [join(pristine, ENVIRONMENT), "--entry", "a", "--entry", "b"],
    ]) {
      expect(mirrorVerifyPlan(args)).toBeNull();
    }
    const io = recorder();
    expect(await verifyMirror([], io.io, new InProcessHttp())).toBe(2);
  });

  it("exits 1 on a directory that holds no mirror, without a stack trace", async () => {
    const io = recorder();
    const code = await verifyMirror(
      [join(workspace, "nowhere")],
      io.io,
      new InProcessHttp(),
    );
    expect(code).toBe(1);
    expect(io.out.length).toBe(1);
    expect(io.out[0]).toContain("cannot read");
    expect(io.out[0]).not.toContain("    at ");
  });
});
