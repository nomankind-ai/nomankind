/**
 * M23 end to end: the daily log mirror, through the sweep, the route and the
 * status board.
 *
 * Whitepaper Section 11, "Deployment and status": the sealed log is exported
 * daily to a public repository under CC0. The Conclusion says what that is for —
 * "the exit is not a promise, it is a copy" — and this file is the copy being
 * made: a real world on a real miniflare D1, a real submission through the real
 * door, a real seal, and then the sweep's mirror step pushing a directory of
 * files into a mirror that exists only in this process.
 *
 * Everything that is not the mirror is the same fake every other end-to-end file
 * in this suite uses: the beacon, the witnesses, the anchor and the payment
 * provider. The clock is injected everywhere, so "the day rolled over" and "it
 * is half an hour past midnight UTC" are fixed instants and never a wait.
 *
 * What is pinned here that the unit files cannot show: the step refuses in the
 * right words and in the right order, a day is exported exactly once, the second
 * run of the same day writes nothing, the next day rewrites only what changed, a
 * refused push is a skip and not a failed sweep, `/mirror/latest` answers both
 * of its shapes, and the thirteenth status stage reads all four of its states
 * off the same rows.
 */

import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { FixtureBeacon } from "../src/adapters/beacon.js";
import {
  MockMirrorAdapter,
  UnavailableMirrorAdapter,
  type MirrorAdapter,
  type MirrorPush,
  type MirrorPushInput,
} from "../src/adapters/mirror.js";
import { MockPayoutAdapter } from "../src/adapters/payout.js";
import type { ApproverRecord, Event } from "../src/events.js";
import {
  DEFAULT_DOMAIN,
  MIRROR,
  RELEASE_WINDOW_DAYS,
  STATUS_FAILING_AFTER_MINUTES,
} from "../src/policy.js";
import { signRecord } from "../src/records.js";
import { txtRecordName } from "../src/registry.js";
import type { Seal } from "../src/seal.js";
import type { Stage } from "../src/status.js";
import { buildSubmittedCore } from "../src/submit.js";
import {
  headSeq,
  latestMirror,
  mirrorOn,
  sweepSteps,
} from "../src/storage/repository.js";
import type { Env } from "../src/worker/env.js";
import { handleRequest } from "../src/worker/index.js";
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

/** Day one: the instant every registration and the submission are at. */
const DAY_ONE = SUBMIT_NOW;
const AT = DAY_ONE.toISOString();
const DAY_ONE_DATE = AT.slice(0, 10);

const MINUTE_MS = 60_000;
const DAY_MS = 86_400_000;

/**
 * The four runs of day one, a minute apart.
 *
 * Apart on purpose: `putSweepSteps` carries a step's last refusal forward past a
 * run with nothing new to say, and a run that shared an instant with the refusal
 * before it could not be told from it.
 */
const UNAVAILABLE_AT = DAY_ONE;
const UNSEALED_AT = new Date(DAY_ONE.getTime() + MINUTE_MS);
const EXPORT_AT = new Date(DAY_ONE.getTime() + 2 * MINUTE_MS);
const AGAIN_AT = new Date(DAY_ONE.getTime() + 3 * MINUTE_MS);

/** The same hour, one UTC day on. */
const DAY_TWO = new Date(DAY_ONE.getTime() + DAY_MS);
const DAY_TWO_DATE = DAY_TWO.toISOString().slice(0, 10);

/** A reference the mock payment provider calls onboarded. */
const VERIFIED_REFERENCE = "mock-verified-m23";

const ENVIRONMENT = "demo";

const CITATION = "https://kestrel.example/limits";
const PAGE: FixturePage = {
  body: "<!doctype html><html><body><main><h1>Limits</h1><p>200 requests a minute</p></main></body></html>",
  contentType: "text/html; charset=utf-8",
};

interface Party {
  readonly operator: string;
  readonly agent: TestAgent;
}

let store: TestDatabase;
let env: Env;
let dns: FixtureResolver;
let maintainer: TestAgent;
let parties: Party[] = [];
let latecomer: Party;
let witness: FakeWitness;
let entryId = "";

const beacon = new FixtureBeacon("m23");
const payout = new MockPayoutAdapter();

/** The mirror every sweep below pushes to, unless a test names another. */
let mirror: MockMirrorAdapter;

function send(request: Request, now: Date): Promise<Response> {
  return handleRequest(request, env, { now, dns, payout, beacon, fetcher });
}

let fetcher: FixtureFetcher;

async function post(
  agent: TestAgent,
  path: string,
  body: unknown,
  now: Date,
): Promise<number> {
  const request = await signedPost(agent, {
    path,
    body,
    timestamp: now.toISOString(),
  });
  return (await send(request, now)).status;
}

async function register(party: Party, now: Date): Promise<void> {
  const answer = await post(
    party.agent,
    "/operators",
    {
      operator: party.operator,
      attestation: await attestFor(party.agent, party.operator, now.toISOString()),
      payout: { reference: VERIFIED_REFERENCE },
    },
    now,
  );
  expect([answer, party.operator]).toEqual([201, party.operator]);
}

async function name(party: Party, now: Date): Promise<void> {
  const answer = await post(
    maintainer,
    "/genesis",
    { operator: party.operator },
    now,
  );
  expect([answer, party.operator]).toEqual([200, party.operator]);
}

/** Run the sweep the alarm runs, with the fakes standing in for the world. */
async function sweep(
  at: Date,
  over: {
    readonly mirror?: MirrorAdapter;
    readonly sealing?: boolean;
  } = {},
): Promise<SweepReport> {
  await beacon.advance(at.toISOString());
  const sealing = over.sealing !== false;
  return runSweep(env, {
    now: at,
    beacon,
    payout,
    trigger: "alarm",
    ...(over.mirror === undefined ? {} : { mirror: over.mirror }),
    ...(sealing
      ? {
          witness: new FakeWitnessAdapter({ signers: [witness] }),
          pinned: pinnedSet([witness]),
          ineligibleAgents: new Set<string>(),
          anchor: new FakeAnchorAdapter(null),
        }
      : {}),
  });
}

/** The reason one step gave on its last run, or null. */
async function skipOf(step: string): Promise<string | null> {
  const rows = await sweepSteps(store.db);
  const row = rows.find((one) => one.step === step);
  return row === undefined ? null : row.last_skip_reason;
}

/** `GET /mirror/latest` as an agent asks for it: JSON, never the page. */
async function latest(
  now: Date,
): Promise<{ status: number; body: Record<string, unknown> }> {
  const response = await send(
    new Request(`${TEST_ORIGIN}/mirror/latest`, {
      headers: { accept: "application/json" },
    }),
    now,
  );
  expect(response.headers.get("cache-control")).toBe("no-store");
  return {
    status: response.status,
    body: (await response.json()) as Record<string, unknown>,
  };
}

/** The mirror export stage of `GET /status`. */
async function mirrorStage(now: Date): Promise<Stage> {
  const response = await send(
    new Request(`${TEST_ORIGIN}/status`, {
      headers: { accept: "application/json" },
    }),
    now,
  );
  expect(response.status).toBe(200);
  const body = (await response.json()) as Record<string, unknown>;
  const found = (body["stages"] as Stage[]).find(
    (one) => one.stage === "mirror export",
  );
  if (found === undefined) throw new Error("no mirror export stage");
  return found;
}

/** One file of the pushed directory, by its path under the environment. */
function fileAt(path: string): string | undefined {
  return mirror.files.get(`${ENVIRONMENT}/${path}`);
}

beforeAll(async () => {
  store = await openTestDatabase();
  maintainer = await makeAgent();
  witness = await makeWitness("witness.example");
  parties = [
    { operator: "first.example", agent: await makeAgent() },
    { operator: "second.example", agent: await makeAgent() },
    { operator: "third.example", agent: await makeAgent() },
  ];
  latecomer = { operator: "fourth.example", agent: await makeAgent() };
  const maintainerParty: Party = {
    operator: "maintainer.example",
    agent: maintainer,
  };

  const records: Record<string, string[]> = {};
  for (const party of [...parties, latecomer, maintainerParty]) {
    records[txtRecordName(party.operator)] = [party.agent.agentId];
  }
  dns = new FixtureResolver(records);
  fetcher = new FixtureFetcher({ [CITATION]: PAGE });
  mirror = new MockMirrorAdapter();

  env = {
    DB: store.db,
    CAPTURES: store.captures,
    // The mirror's directory is the environment's name, so this world is not
    // `local`: the directory the files land in is part of what is under test.
    ENVIRONMENT,
    MAINTAINER_AGENT_ID: maintainer.agentId,
  };

  for (const party of parties) {
    await register(party, DAY_ONE);
    await name(party, DAY_ONE);
  }
  await register(maintainerParty, DAY_ONE);

  // One stated entry through the real door, so the export has an entry file and
  // an index row rather than only a registry.
  const core = await submittedCore(parties[0]!.agent, {
    author_operator: parties[0]!.operator,
    subject: "example/kestrel-1",
    category: "limit",
    claim: "kestrel-1 allows 200 requests a minute",
    before: "no documented request limit",
    after: "200 requests a minute",
    effective_at: "2026-09-01",
    citation: CITATION,
    snapshot_hash: await pageHash(PAGE),
    supersedes: null,
    evidence_tier: "stated",
  });
  entryId = core["id"] as string;
  const submitted = await send(
    await submission(parties[0]!.agent, { core }),
    DAY_ONE,
  );
  expect([submitted.status, entryId]).toEqual([201, entryId]);
}, 240_000);

afterAll(async () => {
  await store?.dispose();
});

describe("the step refuses before it exports, in its own words", () => {
  it("says mirror_unavailable when this environment has no token", async () => {
    // No mirror dep at all is the same thing as an environment whose secret is
    // unset: `mirrorAdapterFor` answers the unavailable adapter for both.
    const report = await sweep(UNAVAILABLE_AT, {
      mirror: new UnavailableMirrorAdapter(),
      sealing: false,
    });
    expect(report.mirror).toBeNull();
    expect(report.skipped["mirror_unavailable"]).toBe(1);
    expect(await skipOf("mirror")).toBe("mirror_unavailable");
    expect(await latestMirror(store.db)).toBeNull();
  }, 240_000);

  it("says no_seal while the log has sealed nothing", async () => {
    // The sealing deps are left out, so nothing is sealed on this run either:
    // the mirror is the sealed record, and there is not one yet.
    const report = await sweep(UNSEALED_AT, { mirror, sealing: false });
    expect(report.mirror).toBeNull();
    expect(report.skipped["no_seal"]).toBe(1);
    expect(await skipOf("mirror")).toBe("no_seal");
    expect(mirror.commits).toBe(0);
  }, 240_000);
});

describe("the day's export", () => {
  let first: SweepReport;

  it("exports once the log has a seal, and writes the day's row", async () => {
    first = await sweep(EXPORT_AT, { mirror });

    expect(first.sealed).not.toBeNull();
    expect(first.mirror).toEqual({
      date: DAY_ONE_DATE,
      commit: "mock-commit-1",
      changed: expect.any(Number),
      head: first.sealed!.last_seq,
      seal_seq: first.sealed!.seq,
      unchanged: false,
    });
    expect(mirror.commits).toBe(1);
    // The step refused nothing on this run. The stored reason is the previous
    // run's and is carried forward by design (`putSweepSteps` COALESCEs it), so
    // what says "this run was clean" is the skip instant, not the reason.
    const swept = (await sweepSteps(store.db)).find((one) => one.step === "mirror")!;
    expect(swept.last_skip_at).not.toBe(swept.last_run_at);
    expect(swept.last_ok_at).toBe(EXPORT_AT.toISOString());

    const row = await mirrorOn(store.db, DAY_ONE_DATE);
    expect(row).toEqual({
      date: DAY_ONE_DATE,
      exported_at: EXPORT_AT.toISOString(),
      commit: "mock-commit-1",
      tree: "mock-tree-1",
      head: first.sealed!.last_seq,
      seal_seq: first.sealed!.seq,
      // No entry file yet: this export was made the minute its seal was, and
      // the row counts the entry files the export actually wrote (D-100). The
      // entry is in `index.json` with its proof and its release date.
      entries: 0,
      files_changed: first.mirror!.changed,
      url: `${MIRROR.web}/${MIRROR.repository}/tree/mock-commit-1/${ENVIRONMENT}`,
      raw_url: `${MIRROR.raw}/${MIRROR.repository}/mock-commit-1/${ENVIRONMENT}/mirror.json`,
    });
  }, 240_000);

  it("lands the layout under the environment's own directory", async () => {
    const paths = [...mirror.files.keys()].sort();
    expect(paths).toEqual([
      `${ENVIRONMENT}/anchors.jsonl`,
      `${ENVIRONMENT}/events/00000000.jsonl`,
      `${ENVIRONMENT}/index.json`,
      `${ENVIRONMENT}/ledger.jsonl`,
      `${ENVIRONMENT}/mirror.json`,
      `${ENVIRONMENT}/operators.json`,
      `${ENVIRONMENT}/seals.jsonl`,
      `${ENVIRONMENT}/standing.json`,
    ]);
    const manifest = JSON.parse(fileAt("mirror.json")!) as Record<string, unknown>;
    expect(manifest).toMatchObject({
      format: "nomankind-mirror-v3",
      environment: ENVIRONMENT,
      exported_at: EXPORT_AT.toISOString(),
      head: first.sealed!.last_seq,
      // One index row per entry from the first minute; the entry's own file
      // arrives on its release date, and `released_head` says nothing of this
      // log is public yet (D-100).
      entries: 1,
      release_window_days: RELEASE_WINDOW_DAYS,
      released_head: null,
      captures_base: "https://demo.nomankind.ai/captures/",
      license: MIRROR.license,
    });
  }, 240_000);

  it("carries the entry the door took as proof, and its release date", async () => {
    // Inside the window the export carries the row and not the file: every
    // column of the row is proof, and `release_date` is the day the file
    // appears (D-100). The events of the seal it was submitted in are hash
    // lines, so the claim itself is nowhere in this directory.
    expect(fileAt(`entries/${entryId}.json`)).toBeUndefined();

    const index = JSON.parse(fileAt("index.json")!) as Record<string, unknown>[];
    expect(index).toHaveLength(1);
    expect(index[0]).toMatchObject({
      id: entryId,
      status: "draft",
      tier: "stated",
      seal_seq: first.sealed!.seq,
      release_date: new Date(
        Date.parse(EXPORT_AT.toISOString()) + RELEASE_WINDOW_DAYS * DAY_MS,
      ).toISOString(),
    });
    expect(index[0]!["entry_hash"]).toMatch(/^sha256:[0-9a-f]{64}$/);

    const events = fileAt("events/00000000.jsonl")!
      .split("\n")
      .filter((line) => line.length > 0)
      .map((line) => JSON.parse(line) as Record<string, unknown>);
    expect(events.length).toBeGreaterThan(0);
    for (const event of events) {
      expect(event["payload"]).toBeNull();
      expect(event["withheld"]).toBe(true);
    }
  }, 240_000);

  it("recomputes standing and the ledger at the released head", async () => {
    // Neither file is read from a table: standing is `standingAt` over the
    // events and the ledger is the rows the log itself proves. Both are folds
    // over payloads, so both are folded over the events this export made
    // public — and nothing of this log has released yet, so standing stands at
    // the position before the first event and names nobody (D-100). They catch
    // up with the sealed head one seal at a time, as the windows run out.
    const standing = JSON.parse(fileAt("standing.json")!) as {
      position: number;
      formula: string[];
      operators: { operator: string }[];
    };
    expect(standing.position).toBe(-1);
    expect(standing.formula.length).toBeGreaterThan(0);
    expect(standing.operators).toEqual([]);

    expect(fileAt("ledger.jsonl")).toBe("");
    const manifest = JSON.parse(fileAt("mirror.json")!) as Record<string, unknown>;
    expect(manifest["attestations"]).toBe(0);
    expect(manifest["ledger_rows"]).toBe(0);
    expect(manifest["standing_position"]).toBe(-1);
  }, 240_000);

  it("carries every operator the registry knows, with its agents", async () => {
    const written = JSON.parse(fileAt("operators.json")!) as {
      operators: { operator: string; trusted: boolean; agents: string[] }[];
      agents: Record<string, string>;
    };
    expect(written.operators.map((one) => one.operator)).toEqual([
      "first.example",
      "maintainer.example",
      "second.example",
      "third.example",
    ]);
    expect(written.agents[parties[0]!.agent.agentId]).toBe("first.example");
  }, 240_000);

  it("does not export the same day twice", async () => {
    const again = await sweep(AGAIN_AT, { mirror });
    expect(again.mirror).toBeNull();
    expect(again.skipped["mirror_current"]).toBe(1);
    expect(await skipOf("mirror")).toBe("mirror_current");
    expect(mirror.commits).toBe(1);
    // The row is the one the first run wrote, untouched.
    expect((await mirrorOn(store.db, DAY_ONE_DATE))!.exported_at).toBe(
      EXPORT_AT.toISOString(),
    );
  }, 240_000);
});

describe("the next day", () => {
  it("rewrites only what changed, and never a sealed day's events", async () => {
    const dayOneEvents = fileAt("events/00000000.jsonl")!;
    const dayOneEntry = fileAt(`entries/${entryId}.json`)!;

    // Something new to seal, so the second export is not only a new timestamp.
    await register(latecomer, DAY_TWO);
    const report = await sweep(DAY_TWO, { mirror });

    expect(report.mirror).toMatchObject({
      date: DAY_TWO_DATE,
      unchanged: false,
    });
    expect(mirror.commits).toBe(2);

    // A seal's range never moves, so a seal's file never changes.
    expect(fileAt("events/00000000.jsonl")).toBe(dayOneEvents);
    // The entry did not move either: nothing about it happened on day two.
    expect(fileAt(`entries/${entryId}.json`)).toBe(dayOneEntry);
    // What did change: the manifest, the seal chain, the new seal's events, and
    // the registry that gained an operator.
    const manifest = JSON.parse(fileAt("mirror.json")!) as Record<string, unknown>;
    expect(manifest["exported_at"]).toBe(DAY_TWO.toISOString());
    expect(fileAt("events/00000001.jsonl")).toBeDefined();
    const operators = JSON.parse(fileAt("operators.json")!) as {
      operators: { operator: string }[];
    };
    expect(operators.operators.map((one) => one.operator)).toContain(
      "fourth.example",
    );

    // And the day's row is the new day's, beside the old one.
    expect((await latestMirror(store.db))!.date).toBe(DAY_TWO_DATE);
    expect((await mirrorOn(store.db, DAY_ONE_DATE))!.commit).toBe("mock-commit-1");
  }, 240_000);
});

describe("a push that refuses", () => {
  /** A mirror that answers one named refusal and records nothing. */
  function refusing(push: MirrorPush): MirrorAdapter {
    return {
      kind: "mock",
      push: (_input: MirrorPushInput) => Promise.resolve(push),
    };
  }

  it("is a skip on the step and never a failed sweep", async () => {
    const dayThree = new Date(DAY_TWO.getTime() + DAY_MS);
    const report = await sweep(dayThree, {
      mirror: refusing({
        ok: false,
        reason: "mirror_conflict",
        detail: "409",
      }),
    });

    expect(report.mirror).toBeNull();
    expect(report.skipped["mirror_conflict"]).toBe(1);
    // The run went on: the ledger step below the mirror still priced.
    expect(report.ledger).not.toBeNull();

    const rows = await sweepSteps(store.db);
    const row = rows.find((one) => one.step === "mirror")!;
    expect(row.last_skip_reason).toBe("mirror_conflict");
    expect(row.detail).toEqual({ date: null, detail: "409" });
    // Nothing was written for the day, so the next run tries again.
    expect(await mirrorOn(store.db, dayThree.toISOString().slice(0, 10))).toBeNull();
  }, 240_000);

  it("says mirror_failed with the adapter's own detail", async () => {
    const dayFour = new Date(DAY_TWO.getTime() + 2 * DAY_MS);
    const report = await sweep(dayFour, {
      mirror: refusing({
        ok: false,
        reason: "mirror_failed",
        detail: "tree_truncated",
      }),
    });
    expect(report.skipped["mirror_failed"]).toBe(1);
    const rows = await sweepSteps(store.db);
    expect(rows.find((one) => one.step === "mirror")!.detail).toEqual({
      date: null,
      detail: "tree_truncated",
    });
  }, 240_000);
});

describe("the step's place in the run", () => {
  it("runs between the anchor and the ledger, and has a row of its own", async () => {
    expect([...SWEEP_STEPS]).toEqual([
      "sweep",
      "snapshot",
      "expiry",
      "draws",
      "revalidation",
      "staleness",
      "publish",
      "seal",
      "witness",
      "anchor",
      "mirror",
      "ledger",
      "metering",
      "alerts",
      "standing",
      "payout",
      "attestation",
      // M25: the counters step, after the standing step so the trusted count is
      // the run's, and last in the list because it is the last step to run.
      "counters",
    ]);
    const rows = await sweepSteps(store.db);
    expect(rows).toHaveLength(SWEEP_STEPS.length);
    expect(rows.some((one) => one.step === "mirror")).toBe(true);
  }, 240_000);
});

describe("GET /mirror/latest", () => {
  it("points at the newest export, in the shape an agent parses", async () => {
    const answer = await latest(DAY_TWO);
    expect(answer.status).toBe(200);
    const row = (await latestMirror(store.db))!;
    expect(answer.body).toEqual({
      environment: ENVIRONMENT,
      repository: `${MIRROR.web}/${MIRROR.repository}`,
      branch: MIRROR.branch,
      path: ENVIRONMENT,
      // No token is set on this env, so the route says so beside the export the
      // injected adapter made: the two are different questions.
      configured: false,
      latest: {
        date: row.date,
        exported_at: row.exported_at,
        commit: row.commit,
        tree: row.tree,
        head: row.head,
        seal_seq: row.seal_seq,
        entries: row.entries,
        files_changed: row.files_changed,
        url: row.url,
        raw_url: row.raw_url,
      },
    });
  }, 240_000);

  it("says why there is no export, and where one would appear", async () => {
    const empty = await openTestDatabase();
    try {
      const bare: Env = { ...env, DB: empty.db };
      const response = await handleRequest(
        new Request(`${TEST_ORIGIN}/mirror/latest`, {
          headers: { accept: "application/json" },
        }),
        bare,
        { now: DAY_TWO, dns, payout, beacon },
      );
      expect(response.status).toBe(404);
      expect(await response.json()).toEqual({
        error: "no_export",
        reason: "mirror_not_configured",
        configured: false,
        repository: `${MIRROR.web}/${MIRROR.repository}`,
        branch: MIRROR.branch,
        path: ENVIRONMENT,
      });

      // With the secret set the same empty log is owed an export rather than
      // unable to make one, and the reason says which.
      const configured: Env = { ...bare, MIRROR_TOKEN: "a-token" };
      const second = await handleRequest(
        new Request(`${TEST_ORIGIN}/mirror/latest`, {
          headers: { accept: "application/json" },
        }),
        configured,
        { now: DAY_TWO, dns, payout, beacon },
      );
      expect(second.status).toBe(404);
      expect(await second.json()).toMatchObject({
        error: "no_export",
        reason: "no_export_yet",
        configured: true,
      });
    } finally {
      await empty.dispose();
    }
  }, 240_000);

  it("answers 405 with Allow to anything but a GET", async () => {
    const response = await send(
      new Request(`${TEST_ORIGIN}/mirror/latest`, {
        method: "POST",
        headers: { accept: "application/json" },
      }),
      DAY_TWO,
    );
    expect(response.status).toBe(405);
    expect(response.headers.get("allow")).toBe("GET, HEAD");
    expect(await response.json()).toEqual({ error: "method_not_allowed" });
  }, 240_000);
});

describe("the thirteenth stage", () => {
  it("is idle on an environment that mirrors nowhere", async () => {
    const stage = await mirrorStage(DAY_TWO);
    expect([stage.stage, stage.state, stage.last]).toEqual([
      "mirror export",
      "idle",
      "not configured",
    ]);
    expect(stage.rule).toBe("today's export committed to the mirror repository");
    expect(stage.evidence[0]).toEqual({
      label: "/mirror/latest",
      href: "/mirror/latest",
    });
  }, 240_000);

  it("is ok on the day of its own export", async () => {
    const configured: Env = { ...env, MIRROR_TOKEN: "a-token" };
    const response = await handleRequest(
      new Request(`${TEST_ORIGIN}/status`, {
        headers: { accept: "application/json" },
      }),
      configured,
      { now: DAY_TWO, dns, payout, beacon },
    );
    const body = (await response.json()) as Record<string, unknown>;
    const stage = (body["stages"] as Stage[]).find(
      (one) => one.stage === "mirror export",
    )!;
    expect(stage.state).toBe("ok");
    expect(stage.last).toContain(DAY_TWO_DATE);
    // The commit is a link a reader can follow to the export itself.
    expect(stage.evidence.map((one) => one.label)).toEqual([
      "/mirror/latest",
      "commit",
    ]);
  }, 240_000);

  it("is attention in the first minutes of a day that is owed one", async () => {
    const configured: Env = { ...env, MIRROR_TOKEN: "a-token" };
    const dayThree = new Date(`${DAY_TWO_DATE}T00:00:00.000Z`);
    const justAfterMidnight = new Date(
      dayThree.getTime() + DAY_MS + (STATUS_FAILING_AFTER_MINUTES - 1) * MINUTE_MS,
    );
    const response = await handleRequest(
      new Request(`${TEST_ORIGIN}/status`, {
        headers: { accept: "application/json" },
      }),
      configured,
      { now: justAfterMidnight, dns, payout, beacon },
    );
    const stage = ((await response.json()) as Record<string, unknown>)["stages"] as Stage[];
    const mirrorRow = stage.find((one) => one.stage === "mirror export")!;
    expect(mirrorRow.state).toBe("attention");
    expect(mirrorRow.last).toContain("owed, not yet");
  }, 240_000);

  it("is failing once the grace has run out, naming the step's reason", async () => {
    const configured: Env = { ...env, MIRROR_TOKEN: "a-token" };
    const wellIntoTheDay = new Date(
      Date.parse(`${DAY_TWO_DATE}T00:00:00.000Z`) +
        DAY_MS +
        (STATUS_FAILING_AFTER_MINUTES + 1) * MINUTE_MS,
    );
    const response = await handleRequest(
      new Request(`${TEST_ORIGIN}/status`, {
        headers: { accept: "application/json" },
      }),
      configured,
      { now: wellIntoTheDay, dns, payout, beacon },
    );
    const stage = ((await response.json()) as Record<string, unknown>)["stages"] as Stage[];
    const mirrorRow = stage.find((one) => one.stage === "mirror export")!;
    expect(mirrorRow.state).toBe("failing");
    expect(mirrorRow.last).toContain(`last ${DAY_TWO_DATE}`);
  }, 240_000);
});


describe("nothing unsealed is exported", () => {
  /**
   * Days on from the last export, so the day is owed one of its own — and a
   * window on, so that what this export carries it carries in full (D-100).
   *
   * The release window and the sealed head are two different rules and this
   * block is about the second one: an export made inside the window would be
   * hash lines whatever the seals covered, and the question here is what the
   * seals covered.
   */
  const DAY_FIVE = new Date(
    DAY_TWO.getTime() + (RELEASE_WINDOW_DAYS + 3) * DAY_MS,
  );

  /** The mirror this one export is pushed to, so its files are only its own. */
  let tail: MockMirrorAdapter;

  /** The entry submitted above the newest seal, which must not be exported. */
  let tailEntryId = "";

  /** The head the seal chain committed to, which is the head of the export. */
  let sealedHead = 0;

  /** One file of the export, by its path under the environment's directory. */
  function tailFileAt(path: string): string | undefined {
    return tail.files.get(`${ENVIRONMENT}/${path}`);
  }

  /** Every line of a `.jsonl` file of the export, parsed. */
  function tailLines(path: string): Record<string, unknown>[] {
    const content = tailFileAt(path);
    if (content === undefined) return [];
    return content
      .split("\n")
      .filter((line) => line.length > 0)
      .map((line) => JSON.parse(line) as Record<string, unknown>);
  }

  /** One approval on a sealed entry, signed and posted at `now`. */
  async function approve(party: Party, id: string, now: Date): Promise<void> {
    const record = {
      agent: party.agent.agentId,
      operator: party.operator,
      decision: "approve",
      reason: null,
      snapshot_hash: await pageHash(PAGE),
      assigned_random: false,
      test_accepted: null,
      reproduction: null,
      observation: null,
      signed_at: now.toISOString(),
    } as unknown as ApproverRecord;
    const signature = await signRecord(
      id,
      "validation",
      record,
      party.agent.privateKey,
    );
    const status = await post(
      party.agent,
      `/entries/${id}/validate`,
      { record, signature },
      now,
    );
    expect([status, party.operator]).toEqual([201, party.operator]);
  }

  it("exports the newest seal's head and nothing above it", async () => {
    // Two kinds of unsealed event on top of a log whose newest seal is days
    // old: decisions on an entry that was sealed long before them, and a whole
    // entry submitted after them.
    await approve(parties[1]!, entryId, DAY_FIVE);
    await approve(parties[2]!, entryId, DAY_FIVE);

    const core = await buildSubmittedCore(
      {
        domain: DEFAULT_DOMAIN,
        author: parties[0]!.agent.agentId,
        author_operator: parties[0]!.operator,
        subject: "example/kestrel-2",
        category: "limit",
        claim: "kestrel-2 allows 200 requests a minute",
        before: "no documented request limit",
        after: "200 requests a minute",
        effective_at: "2026-09-01",
        citation: CITATION,
        snapshot_hash: await pageHash(PAGE),
        supersedes: null,
        evidence_tier: "stated",
      },
      { now: DAY_FIVE.toISOString() },
    );
    tailEntryId = core["id"] as string;
    const submitted = await send(
      await submission(parties[0]!.agent, {
        core,
        timestamp: DAY_FIVE.toISOString(),
      }),
      DAY_FIVE,
    );
    expect([submitted.status, tailEntryId]).toEqual([201, tailEntryId]);

    // The sealing deps are left out, so this run seals nothing: whatever it
    // exports, it exports at the head the runs before it sealed.
    tail = new MockMirrorAdapter();
    const report = await sweep(DAY_FIVE, { mirror: tail, sealing: false });
    expect(report.sealed).toBeNull();
    expect(report.mirror).not.toBeNull();

    const seals = tailLines("seals.jsonl") as unknown as Seal[];
    const newest = seals.reduce((left, right) =>
      right.seq > left.seq ? right : left,
    );
    sealedHead = newest.last_seq;

    // The tail is real: the log is past the head this export was built at, so
    // an export that read the log's own head instead would be a different one.
    expect(await headSeq(store.db)).toBeGreaterThan(sealedHead);

    const manifest = JSON.parse(tailFileAt("mirror.json")!) as Record<
      string,
      unknown
    >;
    expect(manifest["head"]).toBe(sealedHead);
    expect(manifest["seal_seq"]).toBe(newest.seq);
    expect(report.mirror!.head).toBe(sealedHead);
  }, 240_000);

  it("carries no event above the sealed head in any events file", async () => {
    const exported: Event[] = [];
    for (const path of tail.files.keys()) {
      const name = path.slice(`${ENVIRONMENT}/`.length);
      if (!name.startsWith("events/")) continue;
      exported.push(...(tailLines(name) as unknown as Event[]));
    }
    expect(exported.length).toBeGreaterThan(0);
    expect(exported.filter((event) => event.seq > sealedHead)).toEqual([]);
  }, 240_000);

  it("leaves an entry submitted above the seal out of the export", async () => {
    expect([...tail.files.keys()]).not.toContain(
      `${ENVIRONMENT}/entries/${tailEntryId}.json`,
    );
    const index = JSON.parse(tailFileAt("index.json")!) as Record<
      string,
      unknown
    >[];
    expect(index.map((row) => row["id"])).not.toContain(tailEntryId);
    expect(index.map((row) => row["id"])).toContain(entryId);
  }, 240_000);

  it("exports an entry whose later decisions are unsealed as it stood sealed", async () => {
    const written = JSON.parse(tailFileAt(`entries/${entryId}.json`)!) as {
      entry: Record<string, unknown>;
    };
    // The two approvals above are past the head, so at the head this entry is
    // the draft nobody had decided on yet.
    expect(written.entry["status"]).toBe("draft");
    expect(written.entry["approvers"]).toEqual([]);

    const index = JSON.parse(tailFileAt("index.json")!) as Record<
      string,
      unknown
    >[];
    expect(index.find((row) => row["id"] === entryId)!["status"]).toBe("draft");
  }, 240_000);
});
