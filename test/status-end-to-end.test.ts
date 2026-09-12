/**
 * The status board, end to end: a real world on a real miniflare D1, a real
 * sweep, and the endpoint's own answer.
 *
 * Whitepaper Section 11, Deployment and status. The fixtures in
 * test/status.test.ts show that the rules read facts correctly; this file shows
 * that the facts are the ones the machine actually produces — that a sweep
 * writes a row for every step it has, that a healthy world lights up green, and
 * that a clock moved forward turns the lights amber and then red without
 * anything else in the world changing.
 *
 * How it works is here too, for the one thing about it that is not the page's
 * own: the pool numbers it shows are counts of the operators table and not the
 * length of the page of operators the names came from, which only a real store
 * can show.
 *
 * The clock is injected everywhere, so "the sweep stopped forty minutes ago" is
 * a fixed instant and never a wait. Nothing here sleeps and nothing reaches the
 * network: the beacon, the witnesses, the anchor and the payment provider are
 * all fakes, exactly as every other end-to-end file in this suite runs them.
 */

import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { FixtureBeacon, type BeaconReader } from "../src/adapters/beacon.js";
import { MockPayoutAdapter } from "../src/adapters/payout.js";
import {
  STATUS_ATTENTION_AFTER_INTERVALS,
  STATUS_FAILING_AFTER_MINUTES,
  SWEEP_INTERVAL_MINUTES,
} from "../src/policy.js";
import { buildAnchor, type Anchor } from "../src/anchor.js";
import { txtRecordName } from "../src/registry.js";
import type { Stage } from "../src/status.js";
import type { D1Like, D1LikeStatement } from "../src/storage/d1.js";
import {
  countOperators,
  countTrustedOperators,
  putAnchor,
  setAnchorExternal,
  sweepSteps,
} from "../src/storage/repository.js";
import type { Env } from "../src/worker/env.js";
import { handleRequest } from "../src/worker/index.js";
import { handleStatus } from "../src/worker/status.js";
import { SWEEP_STEPS, runSweep } from "../src/worker/sweep.js";
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
  FakeAnchorAdapter,
  FakeWitnessAdapter,
  makeWitness,
  pinnedSet,
  type FakeWitness,
} from "./helpers/witness.js";

const NOW = new Date("2026-09-10T09:00:00.000Z");
const AT = NOW.toISOString();
const MINUTE_MS = 60_000;

/** A reference the mock payment provider calls onboarded. */
const VERIFIED_REFERENCE = "mock-verified-status";

/** The instant `minutes` after the last sweep of the run below. */
function later(minutes: number, from: Date): Date {
  return new Date(from.getTime() + minutes * MINUTE_MS);
}

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
/** The instant the last sweep of the healthy world ran at. */
let settled = NOW;

const beacon = new FixtureBeacon("status");
const payout = new MockPayoutAdapter();
/** One witness nomankind does not control, with a real key behind it. */
let witness: FakeWitness;

function send(request: Request, now: Date, on: Env = env): Promise<Response> {
  return handleRequest(request, on, { now, dns, payout, beacon });
}

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

/** `GET /status` as an agent asks for it: JSON, never the page. */
async function status(now: Date): Promise<Record<string, unknown>> {
  const response = await send(
    new Request(`${TEST_ORIGIN}/status`, {
      headers: { accept: "application/json" },
    }),
    now,
  );
  expect(response.status).toBe(200);
  expect(response.headers.get("cache-control")).toBe("no-store");
  return (await response.json()) as Record<string, unknown>;
}

/** The state one named stage reads in an answer. */
function stateOf(body: Record<string, unknown>, stage: string): string {
  const stages = body["stages"] as Stage[];
  const found = stages.find((one) => one.stage === stage);
  if (found === undefined) throw new Error(`no stage named ${stage}`);
  return found.state;
}

/** Run the sweep the alarm runs, with the fakes standing in for the world. */
async function sweep(at: Date): Promise<void> {
  await beacon.advance(at.toISOString());
  await runSweep(env, {
    now: at,
    beacon,
    witness: new FakeWitnessAdapter({ signers: [witness] }),
    pinned: pinnedSet([witness]),
    ineligibleAgents: new Set<string>(),
    anchor: new FakeAnchorAdapter(null),
    payout,
    trigger: "alarm",
  });
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

  env = {
    DB: store.db,
    CAPTURES: store.captures,
    ENVIRONMENT: "local",
    MAINTAINER_AGENT_ID: maintainer.agentId,
  };
}, 240_000);

afterAll(async () => {
  await store?.dispose();
});

describe("a log nothing has happened in", () => {
  it("answers every stage idle and every counter empty", async () => {
    const body = await status(NOW);

    expect(body["as_of"]).toBeNull();
    expect(body["environment"]).toBe("local");
    for (const stage of body["stages"] as Stage[]) {
      expect([stage.stage, stage.state]).toEqual([stage.stage, "idle"]);
    }
    expect(body["counters"]).toMatchObject({
      lastSweepAt: null,
      lastSweepAge: null,
      stagesOk: 15,
      stagesTotal: 15,
      sealedHead: null,
    });
    // The thresholds travel with the answer: a state nobody can recompute is a
    // state nobody can check.
    expect(body["thresholds"]).toEqual({
      STATUS_ATTENTION_AFTER_INTERVALS,
      STATUS_FAILING_AFTER_MINUTES,
    });
  }, 60_000);

  it("says never for all five exercised doors", async () => {
    const body = await status(NOW);
    const rows = body["exercised"] as { stage: string; last: string }[];
    expect(rows).toHaveLength(5);
    for (const row of rows) expect(row.last).toContain("never");
  }, 60_000);
});

describe("a sweep's own account of itself", () => {
  it("writes one row per step, and tells three refusals of one word apart", async () => {
    // A world with operators in it, so the snapshot step has something to
    // commit. This first run is asked for without the sealing deps, which is
    // the pre-M16 sweep: three steps stand down together on one counted reason,
    // and the three money steps below them refuse on another, because nothing
    // is sealed for them to read.
    for (const party of parties) {
      await register(party, NOW);
      await name(party, NOW);
    }
    await beacon.advance(AT);
    await runSweep(env, { now: NOW, beacon });

    const rows = await sweepSteps(store.db);
    expect(rows).toHaveLength(SWEEP_STEPS.length);
    expect([...rows.map((row) => row.step)].sort()).toEqual(
      [...SWEEP_STEPS].sort(),
    );
    for (const row of rows) {
      expect([row.step, row.last_run_at]).toEqual([row.step, AT]);
      expect([row.step, row.trigger]).toEqual([row.step, "alarm"]);
    }

    const byStep = new Map(rows.map((row) => [row.step, row]));
    // The run itself never refuses.
    expect(byStep.get("sweep")!.last_skip_reason).toBeNull();
    expect(byStep.get("sweep")!.last_ok_at).toBe(AT);
    expect(byStep.get("sweep")!.detail).toMatchObject({
      started_at: AT,
      finished_at: AT,
    });
    // The pool snapshot went in on this run, and the detail says how big it was.
    expect(byStep.get("snapshot")!.detail["operators"]).toBe(parties.length);
    // One `sealing_unconfigured` in the report, three steps on the board: a
    // witness row left blank would read as "never reached" rather than "not
    // configured here".
    for (const step of ["seal", "witness", "anchor"]) {
      expect([step, byStep.get(step)!.last_skip_reason]).toEqual([
        step,
        "sealing_unconfigured",
      ]);
      expect([step, byStep.get(step)!.last_ok_at]).toEqual([step, null]);
    }
    // And the same again for the three money steps, which the report counts as
    // one word three times.
    for (const step of ["ledger", "standing", "payout"]) {
      expect([step, byStep.get(step)!.last_skip_reason]).toEqual([
        step,
        "unsealed",
      ]);
    }
    // The beacon answered, so the draws step's last good read is this run.
    expect(byStep.get("draws")!.last_ok_at).toBe(AT);
    expect(byStep.get("draws")!.detail["beacon_reason"]).toBeNull();
    expect(byStep.get("draws")!.detail["beacon_at"]).toBe(AT);
  }, 240_000);

  it("carries a step's last refusal forward past a later run that worked", async () => {
    // Three full runs settle the world: the first seals what the registrations
    // left, the next two find less and less to do.
    for (let run = 0; run < 3; run += 1) {
      settled = later(SWEEP_INTERVAL_MINUTES, settled);
      await sweep(settled);
    }

    const rows = await sweepSteps(store.db);
    for (const row of rows) {
      expect([row.step, row.last_run_at]).toEqual([
        row.step,
        settled.toISOString(),
      ]);
    }
    // The ledger step refused with `unsealed` on the very first run and has not
    // since: the reason is still stored, and its instant says it is old news
    // rather than this run's, which is exactly what the rules read to tell a
    // step that is refusing now from one that refused once.
    const ledger = rows.find((row) => row.step === "ledger")!;
    expect(ledger.last_skip_reason).toBe("unsealed");
    expect(ledger.last_skip_at).toBe(AT);
    expect(ledger.last_skip_at).not.toBe(ledger.last_run_at);
    expect(ledger.last_ok_at).toBe(settled.toISOString());
  }, 240_000);
});

describe("a healthy world", () => {
  it("lights every stage that is owed something, and idles the rest", async () => {
    const body = await status(settled);
    const stages = body["stages"] as Stage[];

    // Nothing wants attention and nothing is failing. The stages that have work
    // in this world are ok; the ones with no entry, no read and no attestation
    // are idle, which is not a fourth degree of broken.
    expect(
      stages
        .filter((one) => one.state === "attention" || one.state === "failing")
        .map((one) => [one.stage, one.state, one.last]),
    ).toEqual([]);
    for (const named of [
      "sweep timer",
      "pool snapshot",
      "beacon",
      "sealing",
      "witnessing",
    ]) {
      expect([named, stateOf(body, named)]).toEqual([named, "ok"]);
    }

    expect(body["as_of"]).toBe(settled.toISOString());
    expect(body["counters"]).toMatchObject({
      lastSweepAge: "0 min ago",
      lastSweepTrigger: "alarm",
      stagesFailing: 0,
      stagesAttention: 0,
      stagesOk: 15,
      unsealedEvents: 0,
      witnessKind: "mock witnesses on local",
    });
  }, 240_000);

  it("says who last came through the registration door", async () => {
    const body = await status(settled);
    const rows = body["exercised"] as { stage: string; last: string }[];
    const registration = rows.find(
      (row) => row.stage === "registration, DNS check",
    )!;
    expect(registration.last).toContain("third.example");
  }, 60_000);
});

/**
 * The anchoring row, once something outside has finished timestamping a day.
 *
 * Every seal in this world was made today, so the anchoring stage is idle —
 * which is exactly the state that used to say nothing at all about the chain
 * the anchors go to. A calendar folds a commitment into a block on its own
 * schedule, so the newest finished proof is almost never yesterday's, and a
 * board that only ever spoke about yesterday could not tell a chain that has
 * never completed a timestamp from one that completed on Monday.
 */
describe("a proof that reached a block", () => {
  const DAY = "2026-09-08";
  const BLOCK = 966_287;

  it("names the day and the block on the anchoring row, through the endpoint", async () => {
    const built = await buildAnchor(
      [{ seq: 1, root: `sha256:${DAY}`, sealed_at: `${DAY}T12:00:00.000Z` }],
      DAY,
    );
    expect(built.ok).toBe(true);
    await putAnchor(store.db, (built as { ok: true; anchor: Anchor }).anchor);
    await setAnchorExternal(store.db, DAY, {
      kind: "opentimestamps",
      calendar: "https://alice.btc.calendar.opentimestamps.org",
      submitted_at: `${DAY}T00:10:00.000Z`,
      proof: "AE9wZW5UaW1lc3RhbXBz",
      upgraded: {
        proof: "AE9wZW5UaW1lc3RhbXBzAAEC",
        block_height: BLOCK,
        upgraded_at: `${DAY}T09:00:00.000Z`,
      },
    });

    const body = await status(settled);
    const anchoring = (body["stages"] as Stage[]).find(
      (one) => one.stage === "anchoring",
    )!;
    // A pending proof is not a fault and a finished one is not a repair: the
    // line grows, the light does not move.
    expect(anchoring.state).toBe("idle");
    const yesterday = new Date(settled.getTime() - 86_400_000)
      .toISOString()
      .slice(0, 10);
    expect(anchoring.last).toBe(
      `${yesterday} · no seal that day · newest upgrade ${DAY} · block ${BLOCK}`,
    );
  }, 240_000);
});

describe("a clock that moved on without the sweep", () => {
  /** An event the settled seal does not cover, appended after the last run. */
  beforeAll(async () => {
    await register(latecomer, settled);
  }, 240_000);

  it("turns the sweep timer and sealing amber past two intervals", async () => {
    const late = later(
      STATUS_ATTENTION_AFTER_INTERVALS * SWEEP_INTERVAL_MINUTES + 1,
      settled,
    );
    const body = await status(late);

    expect(stateOf(body, "sweep timer")).toBe("attention");
    expect(stateOf(body, "sealing")).toBe("attention");
    expect(body["counters"]).toMatchObject({ stagesFailing: 0 });
    expect((body["counters"] as Record<string, unknown>)["stagesAttention"]).toBe(
      (body["stages"] as Stage[]).filter((one) => one.state === "attention")
        .length,
    );
  }, 60_000);

  it("turns them red past the failing threshold", async () => {
    const dead = later(STATUS_FAILING_AFTER_MINUTES + 1, settled);
    const body = await status(dead);

    expect(stateOf(body, "sweep timer")).toBe("failing");
    expect(stateOf(body, "sealing")).toBe("failing");
    // The board still says when it last worked rather than forgetting it.
    expect(body["as_of"]).toBe(settled.toISOString());
  }, 60_000);
});

describe("the door itself", () => {
  it("refuses a write with 405 and says which method it takes", async () => {
    const response = await handleStatus(
      new Request(`${TEST_ORIGIN}/status`, { method: "PUT" }),
      env,
      { now: NOW },
    );

    expect(response).not.toBeNull();
    expect(response!.status).toBe(405);
    expect(response!.headers.get("allow")).toBe("GET, HEAD");
    expect(await response!.json()).toEqual({ error: "method_not_allowed" });
  }, 60_000);

  it("leaves every other path alone", async () => {
    expect(
      await handleStatus(new Request(`${TEST_ORIGIN}/statuses`), env, { now: NOW }),
    ).toBeNull();
  }, 60_000);

  it("answers 503 rather than a raw 500 when storage is unreachable", async () => {
    const response = await handleStatus(
      new Request(`${TEST_ORIGIN}/status`),
      { ...env, DB: unreachableDatabase() },
      { now: NOW },
    );

    expect(response!.status).toBe(503);
    expect(response!.headers.get("content-type")).toBe("application/json");
    expect(await response!.json()).toEqual({ error: "storage_unreachable" });
  }, 60_000);
});

describe("the how it works page, over the same world", () => {
  it("takes its pool numbers from the counts and not from a page", async () => {
    // The page shows the trusted names from one page of operators and the two
    // numbers beside them from `countTrustedOperators` and `countOperators`. A
    // page's length is how many rows were read; these are how many there are,
    // and past LIST_PAGE_LIMIT operators the two stop being the same number.
    const response = await send(
      new Request(`${TEST_ORIGIN}/how-it-works`, {
        headers: { accept: "text/html" },
      }),
      settled,
    );
    expect(response.status).toBe(200);
    const page = await response.text();

    const trusted = await countTrustedOperators(store.db);
    const registered = await countOperators(store.db);
    expect(registered).toBeGreaterThan(trusted);
    expect(page).toContain(`${trusted} of ${registered} registered`);
  }, 240_000);
});

describe("a step whose dependency throws", () => {
  it("writes the board anyway, with the throw's message on the step", async () => {
    // The beacon is the draws step's one dependency, and this one does not
    // refuse under a rule — it breaks, which is the case the report has no word
    // for. Everything above the draws step has already happened when it does.
    const at = later(SWEEP_INTERVAL_MINUTES, settled);
    const broken: BeaconReader = {
      latest: () => Promise.reject(new Error("beacon adapter exploded")),
    };

    await expect(
      runSweep(env, { now: at, beacon: broken }),
    ).rejects.toThrow("beacon adapter exploded");

    // The run threw, and the board is still there: every step still has a row,
    // and every step the run reached is dated to it.
    const rows = await sweepSteps(store.db);
    expect(rows).toHaveLength(SWEEP_STEPS.length);
    const byStep = new Map(rows.map((row) => [row.step, row]));
    for (const step of ["sweep", "snapshot", "expiry", "draws"]) {
      expect([step, byStep.get(step)!.last_run_at]).toEqual([
        step,
        at.toISOString(),
      ]);
      expect([step, byStep.get(step)!.trigger]).toEqual([step, "alarm"]);
    }
    // The step it threw in carries what the throw said, dated to this run, and
    // does not claim to have got through. Marked as thrown rather than left as a
    // bare message: a rule's refusal and a thrown message share one column, and
    // every stage rule reads the mark to tell them apart (the QA of 2026-09-12).
    expect(byStep.get("draws")!.last_skip_reason).toBe(
      "threw: beacon adapter exploded",
    );
    expect(byStep.get("draws")!.last_skip_at).toBe(at.toISOString());
    expect(byStep.get("draws")!.last_ok_at).not.toBe(at.toISOString());
    // So does the run itself: a sweep that fell over did not get through.
    expect(byStep.get("sweep")!.last_skip_reason).toBe(
      "threw: beacon adapter exploded",
    );
    expect(byStep.get("sweep")!.last_ok_at).not.toBe(at.toISOString());
    // The steps above it ran, and say so.
    expect(byStep.get("snapshot")!.last_ok_at).toBe(at.toISOString());
    expect(byStep.get("expiry")!.last_ok_at).toBe(at.toISOString());
    // The steps below it never ran, so their rows are untouched: the run that
    // last reached them is still the run they describe, detail and all.
    for (const step of ["seal", "ledger", "attestation"]) {
      expect([step, byStep.get(step)!.last_run_at]).toEqual([
        step,
        settled.toISOString(),
      ]);
    }
    expect(byStep.get("standing")!.detail["position"]).toEqual(
      expect.any(Number),
    );

    // And the page reads it: the sweep timer is dated by the run that fell over
    // rather than by the last one that worked, which is the whole point of
    // writing the board on the way out.
    const body = await status(at);
    expect(body["as_of"]).toBe(at.toISOString());
  }, 240_000);
});

/** A D1 binding that fails every way it can be asked. */
function unreachableDatabase(): D1Like {
  const fail = (): Promise<never> =>
    Promise.reject(new Error("D1_ERROR: no such table: sweep_steps"));
  const statement = {
    bind: () => statement,
    first: fail,
    all: fail,
    run: fail,
  } as unknown as D1LikeStatement;
  return {
    prepare: () => statement,
    batch: fail,
    exec: fail,
  } as unknown as D1Like;
}
