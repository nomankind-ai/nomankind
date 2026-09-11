/**
 * import-mirror: a fork starts a log from the copy.
 *
 * Whitepaper Section 11 and the Conclusion: "the exit is not a promise, it is a
 * copy". `npm run verify-mirror` proves the copy is real; this file proves it is
 * an exit. One world is built through the real doors on a real miniflare D1 —
 * four operators, a v0.7 entry, a legacy v0.6 record no door would take, a
 * published day of reads, a whole scored drift attestation, a seal, an anchor —
 * and the sweep exports it. The directory that comes out is then replayed into a
 * database that has never seen any of it, and four things are asked of the
 * result:
 *
 *   - the chain and the head are the same log, hash for hash;
 *   - every entry row is the origin's entry and sidecar, re-derived rather than
 *     copied;
 *   - `buildMirror` over the imported database is byte-identical to the
 *     directory that was imported — the round trip, which is the whole claim;
 *   - and a sweep on the imported database seals nothing new, because the
 *     imported head is already sealed.
 *
 * Then the four refusals, which are the other half of the claim: a mirror is a
 * stranger's directory, and an importer that took one on trust would be a door
 * into the log nobody had checked. A tampered entry file is refused before a
 * single row is written; a database with a log in it is refused without
 * `--force`; `--force` on a database whose log is a prefix of the mirror imports
 * only the tail; and a database whose log parts from the mirror is refused
 * whatever flags it is given.
 *
 * No network anywhere: the capture archive is reached through an http client
 * that routes straight into `handleRequest`, and every clock is injected.
 */

import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

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
import { deriveEntry } from "../src/derive.js";
import { base64urlEncode } from "../src/encoding.js";
import {
  appendEvent,
  verifyChain,
  type ApproverRecord,
  type AttestationScoreRecord,
  type AttestationScorer,
  type Event,
  type Probe,
} from "../src/events.js";
import { entryHash } from "../src/hash.js";
import { exportPrivateKeyPkcs8, generateKeypair } from "../src/identity.js";
import { ImportRefusal } from "../src/import.js";
import { sealFileName } from "../src/mirror.js";
import {
  importArguments,
  importMirror,
  persistPathFor,
  run,
  summaryLine,
} from "../src/cli/import-mirror.js";
import { verifyMirror } from "../src/cli/verify-mirror.js";
import type { HttpClient, ValidatorIo } from "../src/cli/validator.js";
import {
  DEFAULT_DOMAIN,
  LIST_PAGE_LIMIT,
  NORM_VERSION,
  RELEASE_WINDOW_DAYS,
} from "../src/policy.js";
import { answersHash, probeSetHash, type ProbeAnswer } from "../src/probe.js";
import { signRecord } from "../src/records.js";
import type { Entry } from "../src/schema.js";
import type { Seal } from "../src/seal.js";
import { signCore } from "../src/sign.js";
import { entryIdFor } from "../src/submit.js";
import {
  appendEvents,
  eventsInRange,
  getAttestation,
  getEntry,
  headSeq,
  latestSeal,
  ledgerCursor,
  operatorDomains,
  operatorStanding,
  putEntry,
  recordAttestationAnswers,
  recordAttestationRequest,
  recordAttestationScore,
  agentsForOperator,
  getOperator,
  ledgerRowsForOperator,
  latestAnchor,
} from "../src/storage/repository.js";
import type { Env } from "../src/worker/env.js";
import { handleRequest, type RequestDeps } from "../src/worker/index.js";
import { LEDGER_CURSOR, runSweep, type SweepReport } from "../src/worker/sweep.js";
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

/** The instant the origin's first sweep seals and exports at. */
const EXPORT_AT = new Date(NOW.getTime() + HOUR_MS);

/**
 * The same hour a UTC day on: the run that anchors the day before's seals and
 * exports again, which is the directory every import below replays.
 *
 * A day on rather than an hour, because an anchor is a fact about a finished
 * day: a mirror exported the same day it sealed carries no anchor at all, and an
 * import that had never put one back would be untested where it matters.
 */
const ANCHOR_AT = new Date(EXPORT_AT.getTime() + 86_400_000);

/**
 * A window and a day after the anchor: the run whose export the imports replay
 * (decision D-100).
 *
 * The two runs before it push directories in which the one seal is still inside
 * its window — every event a hash line, no entry file at all — which is a real
 * export and one a fork can replay nothing of. By this run the first seal has
 * opened, so the export carries it in full.
 *
 * Its own new seal has not. A sweep publishes a day of read counts per
 * unpublished day and seals what it appended in the same run, so a run a month
 * on seals thirty fresh events at its own instant — and that seal is inside its
 * window on the day it is made. That is not an artefact of this test: it is what
 * every live export looks like, the record in full behind the window and the
 * newest seal as hash lines, and it is exactly what the import has to stop in
 * front of.
 */
const RELEASE_AT = new Date(
  ANCHOR_AT.getTime() + (RELEASE_WINDOW_DAYS + 1) * 86_400_000,
);

/** How many days of read counts the release run backfills, and so seals. */
const BACKFILL_DAYS = RELEASE_WINDOW_DAYS;

/** Not `local`: the directory name and the captures base are part of the copy. */
const ENVIRONMENT = "demo";

const VERIFIED_REFERENCE = "mock-verified-import";

const SUBJECT = "example/kestrel-1";
const CATEGORY = "pricing";
const CITATION = "https://kestrel.example/pricing";
const PAGE: FixturePage = {
  body: "<!doctype html><html><body><main><h1>Kestrel pricing</h1><p>$40 per seat per month</p></main></body></html>",
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
let entryCore: Core;
let attestation = "";

/** The bytes the origin's sweep pushed: what every import below replays. */
let pushed: MockMirrorAdapter;
/**
 * The origin's first seal: the one whose window has run out by the export, and
 * so the head every import below stops at (D-100).
 */
let released: Seal;
/** The export made while every seal was still inside its window. */
let insideWindow: Map<string, string> = new Map();
/** The mirror as a directory on disk, and the workspace holding it. */
let workspace = "";
let mirrorDir = "";

const beacon = new FixtureBeacon("import-mirror");
const payout = new MockPayoutAdapter();

/** The databases opened by the tests, disposed together at the end. */
const opened: TestDatabase[] = [];

function send(request: Request, now: Date = NOW): Promise<Response> {
  return handleRequest(request, env, { ...deps, now, beacon });
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
  /**
   * The instant the doors answer at, which is the instant the export was made
   * at (decision D-100).
   *
   * A capture of an entry nobody may read yet is refused to a keyless reader,
   * so a verification of this export run at some other clock would be reading a
   * different instance's answers. The default is the release run's own instant:
   * the clock the directory under test was written at.
   */
  constructor(private readonly at: Date = RELEASE_AT) {}

  async fetch(request: Request): Promise<Response> {
    const url = new URL(request.url);
    return send(
      new Request(`${TEST_ORIGIN}${url.pathname}${url.search}`, request),
      this.at,
    );
  }
}

/** A fresh migrated in-memory database, disposed with the rest at the end. */
async function freshDatabase(): Promise<TestDatabase> {
  const store = await openTestDatabase();
  opened.push(store);
  return store;
}

/** One import into `store`, through the command's own function. */
function replay(
  store: TestDatabase,
  options: { readonly force?: boolean; readonly dir?: string } = {},
): ReturnType<typeof importMirror> {
  return importMirror(options.dir ?? mirrorDir, store.db, {
    ...(options.force === undefined ? {} : { force: options.force }),
    http: new InProcessHttp(),
  });
}

/** The refusal one call made, or null when it made none. */
async function refusalOf(run: Promise<unknown>): Promise<string | null> {
  try {
    await run;
    return null;
  } catch (error) {
    if (error instanceof ImportRefusal) return error.reason;
    throw error;
  }
}

/**
 * The sidecar one entry row actually holds, as it was written.
 *
 * The column rather than `getEntry`, which folds a source class into a row that
 * has none on the way out: what is being asked here is what the import wrote.
 */
async function storedSidecar(
  store: TestDatabase,
  id: string,
): Promise<Record<string, unknown>> {
  const row = await store.db
    .prepare(`SELECT sidecar_json FROM entries WHERE id = ?`)
    .bind(id)
    .first<{ sidecar_json: string }>();
  return JSON.parse(row!.sidecar_json) as Record<string, unknown>;
}

/** The whole refusal one call made, so a test can read the field it named. */
async function refusalMessageOf(run: Promise<unknown>): Promise<string> {
  try {
    await run;
    return "";
  } catch (error) {
    if (error instanceof ImportRefusal) return error.message;
    throw error;
  }
}

/** One io that keeps every line a command wrote, in the order it wrote them. */
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

/** Every event the log holds, in seq order. */
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

/** The origin's export, as the layout keys its files. */
function mirrorFiles(): Map<string, string> {
  const files = new Map<string, string>();
  for (const [path, content] of pushed.files) {
    files.set(path.slice(`${ENVIRONMENT}/`.length), content);
  }
  return files;
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
 * `domain` key at all rather than a null one. It stands for what the demo's own
 * log already holds, and no door would take it.
 */
async function legacyCore(agent: TestAgent): Promise<Core> {
  const core = {
    id: null,
    subject: SUBJECT,
    category: CATEGORY,
    claim: "example/kestrel-1 seat pricing was $38 per seat per month",
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

/**
 * One whole drift attestation, through the repository's own writers: the
 * request, the model's answers, and one signed score per scorer.
 *
 * Through the writers rather than the doors because the doors want a pool
 * snapshot sealed before a beacon round and a probe set drawn from the observed
 * tier, which is M22's subject. What matters here is that the log holds a real
 * attestation and the store holds the answers the log only hashed, because those
 * two are exactly what an import has to put back.
 */
async function seedAttestation(): Promise<void> {
  const probes: readonly Probe[] = [
    { entry_id: entryId, entry_hash: await entryHash(entryCore) },
  ];
  const probeHash = await probeSetHash(probes);
  const beaconRound = 4_242;
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
          beacon_randomness: "ab".repeat(32),
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

/** Write one export to disk, under the environment's own directory. */
async function writeMirrorDirectory(
  target: string,
  files: ReadonlyMap<string, string> = mirrorFiles(),
): Promise<void> {
  for (const [path, content] of files) {
    const at = join(target, path);
    await mkdir(dirname(at), { recursive: true });
    await writeFile(at, content, "utf8");
  }
}

/**
 * The same export rewritten as the layout `nomankind-mirror-v1` was: the seven
 * files, and entry sidecars without the key v1 never had.
 *
 * Built from the v2 export rather than checked in, so it is the real thing on
 * every run. The three families went in with #58 and the sidecar's source class
 * with #59, which is exactly what the public demo mirror pulled before them is
 * missing — and exactly what an importer that refused it would be refusing.
 */
function v1MirrorFiles(): Map<string, string> {
  const files = new Map(mirrorFiles());
  for (const path of [...files.keys()]) {
    if (path.startsWith("attestations/")) files.delete(path);
  }
  files.delete("standing.json");
  files.delete("ledger.jsonl");

  for (const [path, content] of [...files]) {
    if (!path.startsWith("entries/")) continue;
    const file = JSON.parse(content) as { sidecar: Record<string, unknown> };
    delete file.sidecar["source"];
    files.set(path, `${JSON.stringify(file, null, 2)}\n`);
  }

  // The index column the release window added (D-100) was not a v1 column
  // either: a copy pulled before the window has no release date to carry.
  const index = JSON.parse(files.get("index.json")!) as Record<string, unknown>[];
  for (const row of index) delete row["release_date"];
  files.set("index.json", `${JSON.stringify(index, null, 2)}\n`);

  const manifest = JSON.parse(files.get("mirror.json")!) as Record<
    string,
    unknown
  >;
  manifest["format"] = "nomankind-mirror-v1";
  delete manifest["attestations"];
  delete manifest["standing_position"];
  delete manifest["ledger_rows"];
  delete manifest["release_window_days"];
  delete manifest["released_head"];
  files.set("mirror.json", `${JSON.stringify(manifest, null, 2)}\n`);
  return files;
}

beforeAll(async () => {
  pageHashValue = await pageHash(PAGE);

  const pair = await generateKeypair();
  const sealingKey = base64urlEncode(await exportPrivateKeyPkcs8(pair.privateKey));

  origin = await openTestDatabase();
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
    DB: origin.db,
    CAPTURES: origin.captures,
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

  // One v0.7 entry through the real door, decided on by the two operators that
  // did not submit it.
  const core = await submittedCore(k1.agent, {
    author_operator: k1.operator,
    subject: SUBJECT,
    category: CATEGORY,
    claim: "example/kestrel-1 seat pricing is $40 per seat per month",
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
      body: {
        entry: { ...core, signature: await signCore(core, k1.agent.privateKey) },
      },
      timestamp: AT,
    }),
  );
  expect([submitted.status, entryId]).toEqual([201, entryId]);
  await approve(k2, entryId);
  await approve(k3, entryId);

  // And one legacy v0.6 record, seeded straight into the store because no door
  // would take it.
  const legacy = await legacyCore(k1.agent);
  legacyId = legacy["id"] as string;
  const appended = await appendEvent(await wholeLog(origin), {
    at: AT,
    type: "entry_submitted",
    entry_id: legacyId,
    payload: { core: legacy, signature: await signCore(legacy, k1.agent.privateKey) },
  });
  const event = appended[appended.length - 1] as Event;
  await appendEvents(origin.db, [event]);
  const derived = deriveEntry([event], legacyId, { now: AT });
  await putEntry(origin.db, derived.entry as Entry, derived.sidecar, event.seq);

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

  // The first sweep seals everything and exports the day; the second, a day on,
  // anchors what the first sealed and exports again. The bytes the second one
  // pushed are the copy every import below replays.
  pushed = new MockMirrorAdapter();
  const sweepAt = async (at: Date): Promise<SweepReport> => {
    await beacon.advance(at.toISOString());
    return runSweep(env, {
      now: at,
      beacon,
      payout,
      mirror: pushed,
      trigger: "alarm",
      witness: new FakeWitnessAdapter({ signers: [witness] }),
      pinned: pinnedSet([witness]),
      ineligibleAgents: new Set<string>(),
      anchor: new FakeAnchorAdapter(null),
    });
  };
  const sealed = await sweepAt(EXPORT_AT);
  expect(sealed.sealed).not.toBeNull();
  released = (await latestSeal(origin.db))!;
  const anchored = await sweepAt(ANCHOR_AT);
  expect(anchored.anchored).not.toBeNull();
  expect(anchored.mirror).not.toBeNull();
  // Kept as it stands: the export of a log every seal of which is still inside
  // its window, which is what a new environment's mirror looks like all month.
  insideWindow = mirrorFiles();
  // And a third, a window on: the run whose export carries the first seal in
  // full and its own new one as hash lines, which is the directory every import
  // below replays.
  const releasedRun = await sweepAt(RELEASE_AT);
  expect(releasedRun.sealed).not.toBeNull();
  expect(releasedRun.mirror).not.toBeNull();

  workspace = await mkdtemp(join(tmpdir(), "nomankind-import-"));
  mirrorDir = join(workspace, "log", ENVIRONMENT);
  await writeMirrorDirectory(mirrorDir);
}, 600_000);

afterAll(async () => {
  for (const store of opened) await store.dispose();
  await origin?.dispose();
  if (workspace !== "") await rm(workspace, { recursive: true, force: true });
});

// ---------------------------------------------------------------------------
// The replay
// ---------------------------------------------------------------------------

describe("a fresh database replays the whole record", () => {
  let fork: TestDatabase;
  let summary: Awaited<ReturnType<typeof importMirror>>;

  beforeAll(async () => {
    fork = await freshDatabase();
    summary = await replay(fork);
  }, 600_000);

  it("says what it imported, and what it stopped in front of", async () => {
    expect(summary).toEqual({
      environment: ENVIRONMENT,
      format: "v3",
      answers: true,
      events: released.last_seq + 1,
      seals: 1,
      anchors: 1,
      operators: 4,
      entries: 2,
      attestations: 1,
      ledgerRows: 1,
      // The export's own newest seal is a month of read counts sealed at the
      // instant it exported, and a hash line cannot be replayed: the import
      // stops in front of them and says how many (D-100).
      withheld: BACKFILL_DAYS,
      head: released.last_seq,
      sealSeq: released.seq,
    });
    expect(summaryLine(summary)).toContain(`withheld ${BACKFILL_DAYS}`);
    expect(await latestSeal(origin.db)).not.toEqual(released);
  }, 600_000);

  it("is the same chain at the same head", async () => {
    const forked = await wholeLog(fork);
    const original = await wholeLog(origin);

    // The origin's log went past its own sealed head on the run that exported
    // it: the standing step appends the trust changes it decided, and they are
    // not part of the sealed record.
    expect(await headSeq(fork.db)).toBe(summary.head);
    expect(original.length).toBeGreaterThanOrEqual(forked.length);
    expect(forked.map((event) => event.hash)).toEqual(
      original.slice(0, forked.length).map((event) => event.hash),
    );
    expect((await verifyChain(forked)).ok).toBe(true);
  }, 600_000);

  it("carries the seals, the anchors and the registry the log implies", async () => {
    // The released seal, which is the fork's head: the origin's newer one is
    // still inside its window and was not replayed.
    const newest = (await latestSeal(fork.db))!;
    expect(newest).toEqual(released);
    expect(newest.witnesses.length).toBeGreaterThan(0);
    expect(await latestAnchor(fork.db)).toEqual(await latestAnchor(origin.db));

    for (const party of [k1, k2, k3]) {
      const record = (await getOperator(fork.db, party.operator))!;
      expect(record.details["trusted"]).toBe(true);
      expect(
        (await agentsForOperator(fork.db, party.operator, LIST_PAGE_LIMIT)).map(
          (agent) => agent.agentId,
        ),
      ).toEqual([party.agent.agentId]);
      expect(
        (await operatorDomains(fork.db, party.operator)).map((row) => row.domain),
      ).toEqual([DEFAULT_DOMAIN]);
    }
  }, 600_000);

  it("re-derives every entry to the origin's own entry and sidecar", async () => {
    const files = mirrorFiles();
    for (const id of [entryId, legacyId]) {
      const imported = (await getEntry(fork.db, id))!;
      const stored = (await getEntry(origin.db, id))!;
      expect([id, imported.entry]).toEqual([id, stored.entry]);
      expect([id, imported.sidecar]).toEqual([id, stored.sidecar]);

      const file = JSON.parse(files.get(`entries/${id}.json`)!) as {
        entry: unknown;
        sidecar: unknown;
      };
      expect([id, imported.entry]).toEqual([id, file.entry]);
      expect([id, imported.sidecar]).toEqual([id, file.sidecar]);
    }
  }, 600_000);

  it("puts the attestation and its answers back beside the log", async () => {
    const held = (await getAttestation(fork.db, attestation))!;
    expect(held.attestation).toEqual(
      (await getAttestation(origin.db, attestation))!.attestation,
    );
    expect(held.attestation.status).toBe("scored");
    expect(held.answers).toEqual([{ entry_id: entryId, answer: MODEL_ANSWER }]);
  }, 600_000);

  it("rebuilds the ledger and the standing, and leaves both cursors at the head", async () => {
    expect(await ledgerCursor(fork.db, LEDGER_CURSOR)).toBe(summary.head);
    // The one row this world's log is worth: the day's reconciliation.
    const rows = await ledgerRowsForOperator(fork.db, k1.operator, LIST_PAGE_LIMIT);
    expect(rows.filter((row) => row.kind === "read_share")).toEqual([]);

    for (const party of [k1, k2, k3]) {
      const standing = (await operatorStanding(fork.db, party.operator))!;
      expect([party.operator, standing.seq]).toEqual([
        party.operator,
        summary.head,
      ]);
      expect(standing.standing).toBe(
        (await operatorStanding(origin.db, party.operator))!.standing,
      );
    }
  }, 600_000);

  it("exports byte-identical bytes for the same sealed head", async () => {
    const again = new MockMirrorAdapter();
    await beacon.advance(ANCHOR_AT.toISOString());
    const report = await runSweep(
      {
        ...env,
        DB: fork.db,
        CAPTURES: fork.captures,
      },
      {
        // A window on, so the fork's own export is the released view: a
        // re-export inside the window would be hash lines, which is right and
        // is not what this test is about.
        now: RELEASE_AT,
        beacon,
        payout,
        mirror: again,
        trigger: "alarm",
        witness: new FakeWitnessAdapter({ signers: [witness] }),
        pinned: pinnedSet([witness]),
        ineligibleAgents: new Set<string>(),
        anchor: new FakeAnchorAdapter(null),
      },
    );

    // The fork seals on from the released head, and what it seals is what the
    // origin's own run at this instant sealed: the same thirty days of read
    // counts, on the same log, at the same clock — so the same events, the same
    // hashes and the same seal.
    expect(report.sealed).not.toBeNull();
    expect(report.sealed!.first_seq).toBe(released.last_seq + 1);
    expect(report.sealed!.size).toBe(BACKFILL_DAYS);
    expect(report.mirror).not.toBeNull();
    expect(report.mirror!.head).toBe(released.last_seq + BACKFILL_DAYS);

    const rebuilt = new Map<string, string>();
    for (const [path, content] of again.files) {
      rebuilt.set(path.slice(`${ENVIRONMENT}/`.length), content);
    }
    const source = mirrorFiles();
    expect([...rebuilt.keys()].sort()).toEqual([...source.keys()].sort());
    for (const [path, content] of source) {
      expect([path, rebuilt.get(path)]).toEqual([path, content]);
    }
  }, 600_000);
});

// ---------------------------------------------------------------------------
// The refusals
// ---------------------------------------------------------------------------

describe("the four refusals", () => {
  it("refuses a tampered entry file before it writes anything", async () => {
    const target = join(workspace, "tampered", ENVIRONMENT);
    await writeMirrorDirectory(target);
    const path = join(target, "entries", `${entryId}.json`);
    const file = JSON.parse(await readFile(path, "utf8")) as {
      entry: Record<string, unknown>;
    };
    file.entry["status"] = "verified";
    await writeFile(path, `${JSON.stringify(file, null, 2)}\n`, "utf8");

    const store = await freshDatabase();
    const message = await refusalMessageOf(replay(store, { dir: target }));
    // The field and not just the word: what is refused is a file that disagrees
    // with the re-derivation, and a reader who edited one key is told which.
    expect(message.startsWith("verify_failed:")).toBe(true);
    expect(message).toContain(`FAIL ${entryId} derived /entry/status`);
    // Not one row: the verifier ran before the first write, and refused.
    expect(await headSeq(store.db)).toBeNull();
    expect(await latestSeal(store.db)).toBeNull();
    expect(await getEntry(store.db, entryId)).toBeNull();
  }, 600_000);

  it("refuses a database that already holds a log, without --force", async () => {
    const store = await freshDatabase();
    const first = await replay(store);
    expect(await refusalOf(replay(store))).toBe("database_not_empty");
    // And says the same about it under --force, because the mirror adds nothing.
    const again = await replay(store, { force: true });
    expect(again.events).toBe(0);
    expect(again.head).toBe(first.head);
    expect(await headSeq(store.db)).toBe(first.head);
  }, 600_000);

  it("imports only the tail when --force finds a prefix", async () => {
    const events = await wholeLog(origin);
    const newest = released;
    const prefix = events.slice(0, 3);

    const store = await freshDatabase();
    await appendEvents(store.db, prefix);
    expect(await refusalOf(replay(store))).toBe("database_not_empty");

    const summary = await replay(store, { force: true });
    expect(summary.events).toBe(newest.last_seq + 1 - prefix.length);
    expect(await headSeq(store.db)).toBe(newest.last_seq);
    expect((await wholeLog(store)).map((event) => event.hash)).toEqual(
      events.slice(0, newest.last_seq + 1).map((event) => event.hash),
    );
    // The tail import is a whole import: the rows are the log's index at the
    // sealed head however much of the log was already there.
    expect(await getEntry(store.db, entryId)).not.toBeNull();
    expect(await getAttestation(store.db, attestation)).not.toBeNull();
  }, 600_000);

  it("refuses a database whose log parts from the mirror", async () => {
    const events = await wholeLog(origin);
    const prefix = events.slice(0, 3);
    // A real event, sealed onto the same prefix, that the mirror does not hold:
    // from seq 3 on the two logs are different logs.
    const diverged = await appendEvent(prefix, {
      at: AT,
      type: "pool_snapshot",
      entry_id: null,
      payload: { operators: [] },
    });

    const store = await freshDatabase();
    await appendEvents(store.db, diverged);
    expect(await refusalOf(replay(store, { force: true }))).toBe("not_a_prefix");
    // Nothing of the mirror landed on top of it.
    expect(await headSeq(store.db)).toBe(prefix.length);
    expect(await latestSeal(store.db)).toBeNull();
  }, 600_000);
});

// ---------------------------------------------------------------------------
// The older layout
// ---------------------------------------------------------------------------

describe("a v1 mirror is still an exit", () => {
  let fork: TestDatabase;
  let summary: Awaited<ReturnType<typeof importMirror>>;
  let v1Dir = "";

  beforeAll(async () => {
    v1Dir = join(workspace, "v1", ENVIRONMENT);
    await writeMirrorDirectory(v1Dir, v1MirrorFiles());
    fork = await freshDatabase();
    summary = await replay(fork, { dir: v1Dir });
  }, 600_000);

  it("imports the whole record, and says it has no answers to put back", async () => {
    expect(summary).toEqual({
      environment: ENVIRONMENT,
      format: "v1",
      answers: false,
      events: released.last_seq + 1,
      seals: 1,
      anchors: 1,
      operators: 4,
      entries: 2,
      attestations: 1,
      ledgerRows: 1,
      withheld: BACKFILL_DAYS,
      head: released.last_seq,
      sealSeq: released.seq,
    });
    expect(summaryLine(summary)).toContain("format v1");
    expect(summaryLine(summary)).toContain("attestations 1 answers none");

    // The attestation is the log's own fold either way; the one thing missing
    // is what the model said, which the older layout never carried.
    const held = (await getAttestation(fork.db, attestation))!;
    expect(held.attestation).toEqual(
      (await getAttestation(origin.db, attestation))!.attestation,
    );
    expect(held.answers).toBeNull();

    // The ledger and the standing are recomputed from the events, so a mirror
    // that carries neither file is imported with both all the same.
    expect(await ledgerCursor(fork.db, LEDGER_CURSOR)).toBe(summary.head);
    for (const party of [k1, k2, k3]) {
      const standing = (await operatorStanding(fork.db, party.operator))!;
      expect([party.operator, standing.seq, standing.standing]).toEqual([
        party.operator,
        summary.head,
        (await operatorStanding(origin.db, party.operator))!.standing,
      ]);
    }
  }, 600_000);

  it("stores the sidecar the kernel derives, which the v1 file never had", async () => {
    // The mutation this kills: an import that wrote the mirror's files instead
    // of the re-derivation. A v1 file carries no source class at all, so a copy
    // of it would store a sidecar the kernel disagrees with — and every other
    // key is equal, which is why only this one can tell the two apart.
    const file = JSON.parse(
      v1MirrorFiles().get(`entries/${entryId}.json`)!,
    ) as { sidecar: Record<string, unknown> };
    expect(Object.prototype.hasOwnProperty.call(file.sidecar, "source")).toBe(
      false,
    );

    for (const id of [entryId, legacyId]) {
      const imported = (await getEntry(fork.db, id))!;
      const stored = (await getEntry(origin.db, id))!;
      expect([id, imported.entry]).toEqual([id, stored.entry]);
      expect([id, imported.sidecar]).toEqual([id, stored.sidecar]);

      // The stored bytes and not the read: a row written before the source
      // class existed is read back with one folded in (`toSidecar`), so the
      // only place the question can be asked is the column itself.
      const written = await storedSidecar(fork, id);
      expect([id, written["source"]]).toEqual([id, stored.sidecar.source]);
      expect([id, written["source"]]).not.toEqual([id, undefined]);
    }
  }, 600_000);

  it("re-exports the record under v2, and that export verifies", async () => {
    const again = new MockMirrorAdapter();
    await beacon.advance(ANCHOR_AT.toISOString());
    const report = await runSweep(
      { ...env, DB: fork.db, CAPTURES: fork.captures },
      {
        // A window on, as the run that exported the directory this fork was
        // built from: the record in full behind the window, the seal this run
        // makes as hash lines.
        now: RELEASE_AT,
        beacon,
        payout,
        mirror: again,
        trigger: "alarm",
        witness: new FakeWitnessAdapter({ signers: [witness] }),
        pinned: pinnedSet([witness]),
        ineligibleAgents: new Set<string>(),
        anchor: new FakeAnchorAdapter(null),
      },
    );
    expect(report.mirror).not.toBeNull();
    expect(report.mirror!.head).toBe(released.last_seq + BACKFILL_DAYS);

    const rebuilt = new Map<string, string>();
    for (const [path, content] of again.files) {
      rebuilt.set(path.slice(`${ENVIRONMENT}/`.length), content);
    }
    const manifest = JSON.parse(rebuilt.get("mirror.json")!) as Record<
      string,
      unknown
    >;
    // A v1 mirror goes in and the current layout comes back out: the three
    // families and the source class are functions of the log, and the fork has
    // the log now.
    expect(manifest["format"]).toBe("nomankind-mirror-v3");
    expect(rebuilt.has("standing.json")).toBe(true);
    expect(rebuilt.has("ledger.jsonl")).toBe(true);

    const target = join(workspace, "v1-reexport", ENVIRONMENT);
    await writeMirrorDirectory(target, rebuilt);
    const io = recorder();
    const code = await verifyMirror([target], io.io, new InProcessHttp());
    expect([code, io.out.join("\n")]).toEqual([0, io.out.join("\n")]);
    // The three families are folded over the released events at the released
    // head, by the export and by the verifier alike, so a clone whose newest
    // seal is still inside its window still checks all three.
    expect(io.out).toContain("ok standing");
    expect(io.out).toContain("ok ledger");
  }, 600_000);
});

// ---------------------------------------------------------------------------
// The window
// ---------------------------------------------------------------------------

/**
 * The export a log inside its window makes, and what a fork can do with it
 * (decisions D-100, D-101).
 *
 * The sweep's mirror step is the same step it always was — this is the same
 * directory, at a clock a month earlier — and what the window changes is which
 * of it is written out: the seal's events as hash lines, no entry file at all,
 * and an index that still names every entry, its proof columns and the day it
 * opens. A fork handed that copy has the proof of the whole record and nothing
 * to replay, and is told so in one word.
 */
describe("an export made inside the window", () => {
  it("writes the seal as hash lines and no entry file", () => {
    const seal = insideWindow.get(sealFileName(released.seq))!;
    const lines = seal
      .split("\n")
      .filter((line) => line.length > 0)
      .map((line) => JSON.parse(line) as Record<string, unknown>);
    expect(lines).toHaveLength(released.size);
    for (const line of lines) {
      expect(line["payload"]).toBeNull();
      expect(line["withheld"]).toBe(true);
      expect(typeof line["hash"]).toBe("string");
    }
    expect(
      [...insideWindow.keys()].filter((path) => path.startsWith("entries/")),
    ).toEqual([]);

    // And the same export a window later holds everything: the same seal file,
    // written once, with the payloads in it.
    const later = mirrorFiles().get(sealFileName(released.seq))!;
    expect(later).not.toBe(seal);
    expect(
      [...mirrorFiles().keys()].filter((path) => path.startsWith("entries/")),
    ).toHaveLength(2);
  });

  it("keeps every index row, its proof and the date it opens", () => {
    const rows = JSON.parse(insideWindow.get("index.json")!) as Record<
      string,
      unknown
    >[];
    expect(rows).toHaveLength(2);
    for (const row of rows) {
      expect(typeof row["entry_hash"]).toBe("string");
      expect(typeof row["subject"]).toBe("string");
      expect(row["release_date"]).toBe(
        new Date(
          Date.parse(released.sealed_at) + RELEASE_WINDOW_DAYS * 86_400_000,
        ).toISOString(),
      );
    }
    const manifest = JSON.parse(insideWindow.get("mirror.json")!) as Record<
      string,
      unknown
    >;
    expect(manifest["release_window_days"]).toBe(RELEASE_WINDOW_DAYS);
    expect(manifest["released_head"]).toBeNull();
  });

  it("is verified as the proof it is, and refused as a replay", async () => {
    const target = join(workspace, "inside", ENVIRONMENT);
    await writeMirrorDirectory(target, insideWindow);

    const io = recorder();
    expect(await verifyMirror([target], io.io, new InProcessHttp())).toBe(0);
    expect(io.out).toContain("ok events");
    expect(io.out).toContain(`ok seal/${released.seq}`);
    // Both entries are counted withheld — neither has a file yet — and nothing
    // is failed: the chain, the seal and the index rows are all there to check.
    expect(io.out.some((line) => line.startsWith("withheld "))).toBe(true);
    expect(io.out.some((line) => line.includes("withheld 2 failed 0"))).toBe(
      true,
    );

    // And nothing to replay: a hash line cannot be appended, and a fork is told
    // that in one word rather than handed an empty log.
    const store = await freshDatabase();
    expect(await refusalOf(replay(store, { dir: target }))).toBe(
      "nothing_released",
    );
    expect(await headSeq(store.db)).toBeNull();
  }, 600_000);
});

// ---------------------------------------------------------------------------
// The layout before the window
// ---------------------------------------------------------------------------

/**
 * The released record as a `nomankind-mirror-v2` directory: the layout the
 * export wrote before the window existed.
 *
 * Built from the v3 export rather than checked in, exactly as the v1 copy is:
 * the withheld seal and its events come out, the three families are recomputed
 * at the released head — which is what a v2 export of this log would have
 * written, since a v2 export had no withheld seal to fold over — and the
 * manifest says v2 and carries neither of the two fields the window added.
 */
function v2MirrorFiles(): Map<string, string> {
  const files = new Map(mirrorFiles());
  const events = files
    .get(sealFileName(released.seq))!
    .split("\n")
    .filter((line) => line.length > 0)
    .map((line) => JSON.parse(line) as Event);

  for (const path of [...files.keys()]) {
    if (path.startsWith("events/") && path !== sealFileName(released.seq)) {
      files.delete(path);
    }
  }
  const seals = files
    .get("seals.jsonl")!
    .split("\n")
    .filter((line) => line.length > 0)
    .map((line) => JSON.parse(line) as Seal)
    .filter((seal) => seal.seq === released.seq);
  files.set("seals.jsonl", `${JSON.stringify(seals[0])}\n`);

  // The three families need no rewriting: the export folds them over the
  // released events at the released head, which for this log is exactly the
  // seal a v2 export would have been headed by.
  const document = (value: unknown): string =>
    `${JSON.stringify(value, null, 2)}\n`;

  const index = JSON.parse(files.get("index.json")!) as Record<string, unknown>[];
  for (const row of index) delete row["release_date"];
  files.set("index.json", document(index));

  const manifest = JSON.parse(files.get("mirror.json")!) as Record<
    string,
    unknown
  >;
  manifest["format"] = "nomankind-mirror-v2";
  manifest["head"] = released.last_seq;
  manifest["seal_seq"] = released.seq;
  manifest["as_of"] = released.sealed_at;
  manifest["seals"] = 1;
  manifest["events"] = released.size;
  delete manifest["release_window_days"];
  delete manifest["released_head"];
  files.set("mirror.json", document(manifest));
  return files;
}

describe("a v2 mirror is still an exit", () => {
  let fork: TestDatabase;
  let v2Dir = "";

  beforeAll(async () => {
    v2Dir = join(workspace, "v2", ENVIRONMENT);
    await writeMirrorDirectory(v2Dir, v2MirrorFiles());
    fork = await freshDatabase();
  }, 600_000);

  it("verifies whole, with nothing withheld in it", async () => {
    const io = recorder();
    const code = await verifyMirror([v2Dir], io.io, new InProcessHttp());
    expect([code, io.out.join("\n")]).toEqual([0, io.out.join("\n")]);
    // A copy with no hash line in it is checked exactly as it always was: the
    // three families included, and every entry re-derived.
    expect(io.out).toContain("ok standing");
    expect(io.out).toContain("ok ledger");
    expect(io.out).toContain(`ok ${entryId}`);
    expect(io.out.some((line) => line.includes("withheld 0"))).toBe(true);
  }, 600_000);

  it("replays the whole record it carries", async () => {
    const summary = await replay(fork, { dir: v2Dir });
    expect(summary.format).toBe("v2");
    expect(summary.withheld).toBe(0);
    expect(summary.head).toBe(released.last_seq);
    expect(summary.entries).toBe(2);
    expect(await headSeq(fork.db)).toBe(released.last_seq);
    expect(await getEntry(fork.db, entryId)).not.toBeNull();
  }, 600_000);
});

// ---------------------------------------------------------------------------
// The call itself
// ---------------------------------------------------------------------------

describe("the command's arguments", () => {
  it("reads the directory, the flags, and nothing it was not given", () => {
    expect(importArguments(["../log/demo"])).toEqual({
      dir: "../log/demo",
      persistTo: null,
      captures: null,
      force: false,
    });
    expect(
      importArguments([
        "../log/demo",
        "--persist-to",
        ".wrangler/state",
        "--captures",
        "./captures",
        "--force",
      ]),
    ).toEqual({
      dir: "../log/demo",
      persistTo: ".wrangler/state",
      captures: "./captures",
      force: true,
    });
  });

  it("puts the state where wrangler dev looks for it", () => {
    // The bug this pins: `getPlatformProxy`'s persist path is the inner
    // directory, so an import that passed `--persist-to X` straight through
    // wrote beside the database `wrangler dev --persist-to X` reads, and the
    // fork got an empty, unmigrated log. The `v3` segment is wrangler's persist
    // layout; the same X now works for both, and for `wrangler d1 migrations
    // apply DB --local --persist-to X`.
    const given = join(workspace, "fork-state");
    expect(persistPathFor(given)).toBe(join(given, "v3"));
    expect(persistPathFor("relative/state")).toBe(
      join(resolve("relative/state"), "v3"),
    );

    // With no flag: the directory `npm run dev` serves from, resolved from the
    // repository rather than from wherever the command was run.
    const root = fileURLToPath(new URL("../", import.meta.url));
    expect(persistPathFor(null)).toBe(join(root, ".wrangler", "state", "v3"));
  });

  it("refuses a call that is not one rather than guessing", () => {
    expect(importArguments([])).toBeNull();
    expect(importArguments(["--force"])).toBeNull();
    expect(importArguments(["../log/demo", "--persist-to"])).toBeNull();
    expect(importArguments(["../log/demo", "--unknown", "x"])).toBeNull();
    expect(importArguments(["../log/demo", "--force", "--force"])).toBeNull();
  });

  it("exits 2 on a call that is not one, before it opens a database", async () => {
    const io = recorder();
    let opened = 0;
    const code = await run([], io.io, async () => {
      opened += 1;
      throw new Error("never reached");
    });
    expect([code, opened]).toEqual([2, 0]);
  });

  it("names database_unavailable when the local database will not open", async () => {
    // A locked state directory, a missing wrangler.jsonc, a miniflare that will
    // not start: every one of those is about this laptop rather than about the
    // mirror, and rule 6 is a named line and never a stack trace.
    const io = recorder();
    const code = await run(
      [mirrorDir, "--persist-to", join(workspace, "locked")],
      io.io,
      async (persistTo) => {
        expect(persistTo).toBe(join(workspace, "locked"));
        throw new Error(
          "miniflare: the persist directory is held by another process\n" +
            "    at somewhere (file.js:1:1)",
        );
      },
    );
    expect([code, io.out]).toEqual([
      1,
      [
        "import database_unavailable: miniflare: the persist directory is " +
          "held by another process",
      ],
    ]);
    expect(io.out.some((line) => line.includes("    at "))).toBe(false);
  });
});
