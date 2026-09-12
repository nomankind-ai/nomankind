/**
 * A sweep step that threw, on the board and on the page (the QA of 2026-09-12).
 *
 * The board was already written on the way out of a run that fell over — the
 * step that threw carried the message as its reason — and the page could not see
 * it. Four of the fifteen stage rules read a step's reason at all; the rest
 * decide from derived facts, and derived facts are exactly what a step that
 * threw never got round to changing. So a D1 error inside the seal step left
 * fifteen green lights and "0 failing", with the error named nowhere: the one
 * failure a reader most needs to see was the one the board hid.
 *
 * What is held here is the repair, end to end on a real miniflare D1: a run
 * whose seal write throws makes the sealing stage read failing with the message
 * named in its line, whatever the seal's own age says, and names the thrown run
 * on the sweep timer beside it — and a later healthy run of that step puts both
 * back to ok with nothing having to clear anything.
 *
 * And the other half of the same board: `putSweepSteps` never moves an instant
 * backwards. A run whose clock is behind the stored row — a redeploy, a retried
 * alarm — used to overwrite the board with the earlier instant and make every
 * stage on the page look that much further behind than it was.
 *
 * The clock is injected, the witnesses and the anchor are fakes, and nothing
 * here sleeps or reaches the network.
 */

import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { FixtureBeacon } from "../src/adapters/beacon.js";
import { SWEEP_INTERVAL_MINUTES } from "../src/policy.js";
import { txtRecordName } from "../src/registry.js";
import { THROWN_REASON_PREFIX, type Stage } from "../src/status.js";
import type { D1Like, D1LikeStatement } from "../src/storage/d1.js";
import { putSweepSteps, sweepSteps } from "../src/storage/repository.js";
import type { Env } from "../src/worker/env.js";
import { handleRequest } from "../src/worker/index.js";
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
  FakeAnchorAdapter,
  FakeWitnessAdapter,
  makeWitness,
  pinnedSet,
  type FakeWitness,
} from "./helpers/witness.js";

const NOW = new Date("2026-09-10T09:00:00.000Z");
const MINUTE_MS = 60_000;

/** What the broken seal write says when it says it. */
const D1_ERROR = "D1_ERROR: no such table: seals";

/** The instant `minutes` after `from`. */
function later(minutes: number, from: Date): Date {
  return new Date(from.getTime() + minutes * MINUTE_MS);
}

let store: TestDatabase;
let env: Env;
let dns: FixtureResolver;
let maintainer: TestAgent;
let witness: FakeWitness;
/** The second operator, held back so the broken run has something to seal. */
let latecomer: TestAgent;

const beacon = new FixtureBeacon("thrown");

/**
 * The same database, with the seal step's own write broken.
 *
 * The statements are wrapped rather than the batch inspected after the fact:
 * `bind` hands back a new statement, so the SQL a batch was built from is only
 * knowable by carrying it along the chain. Every call but the failing batch goes
 * through to the real database, so the world this run reads is the real one and
 * only the one write falls over — which is what a table that has gone missing
 * under a running Worker actually looks like.
 */
function withBrokenSeal(db: D1Like): D1Like {
  const sqlOf = new WeakMap<D1LikeStatement, string>();
  const real = new WeakMap<D1LikeStatement, D1LikeStatement>();

  const wrap = (statement: D1LikeStatement, sql: string): D1LikeStatement => {
    const wrapped: D1LikeStatement = {
      bind: (...values: unknown[]) => wrap(statement.bind(...values), sql),
      first: <Row>() => statement.first<Row>(),
      all: <Row>() => statement.all<Row>(),
      run: <Row>() => statement.run<Row>(),
    };
    sqlOf.set(wrapped, sql);
    real.set(wrapped, statement);
    return wrapped;
  };

  return {
    prepare: (sql: string) => wrap(db.prepare(sql), sql),
    batch: <Row>(statements: D1LikeStatement[]) => {
      const breaks = statements.some((one) =>
        (sqlOf.get(one) ?? "").includes("INSERT INTO seals"),
      );
      if (breaks) return Promise.reject(new Error(D1_ERROR));
      return db.batch<Row>(statements.map((one) => real.get(one) ?? one));
    },
    exec: (sql: string) => db.exec(sql),
  };
}

/** One operator through the joining door, which is one event to seal. */
async function join(
  agent: TestAgent,
  operator: string,
  at: Date,
): Promise<void> {
  const request = await signedPost(agent, {
    path: "/operators",
    body: {
      operator,
      attestation: await attestFor(agent, operator, at.toISOString()),
      payout: { reference: "mock-verified-thrown" },
    },
    timestamp: at.toISOString(),
  });
  const joined = await handleRequest(request, env, { now: at, dns, beacon });
  expect([operator, joined.status]).toEqual([operator, 201]);
}

/** Run the sweep the alarm runs, against whichever database is handed in. */
async function sweep(at: Date, on: Env = env): Promise<void> {
  await beacon.advance(at.toISOString());
  await runSweep(on, {
    now: at,
    beacon,
    witness: new FakeWitnessAdapter({ signers: [witness] }),
    pinned: pinnedSet([witness]),
    ineligibleAgents: new Set<string>(),
    anchor: new FakeAnchorAdapter(null),
    trigger: "alarm",
  });
}

/** `GET /status` as an agent asks for it: JSON, never the page. */
async function stages(now: Date): Promise<Stage[]> {
  const response = await handleRequest(
    new Request(`${TEST_ORIGIN}/status`, {
      headers: { accept: "application/json" },
    }),
    env,
    { now, dns, beacon },
  );
  expect(response.status).toBe(200);
  const body = (await response.json()) as Record<string, unknown>;
  return body["stages"] as Stage[];
}

function rowOf(all: readonly Stage[], stage: string): Stage {
  const found = all.find((one) => one.stage === stage);
  if (found === undefined) throw new Error(`no stage named ${stage}`);
  return found;
}

beforeAll(async () => {
  store = await openTestDatabase();
  maintainer = await makeAgent();
  witness = await makeWitness("witness.example");
  const operator: TestAgent = await makeAgent();
  latecomer = await makeAgent();
  dns = new FixtureResolver({
    [txtRecordName("first.example")]: [operator.agentId],
    [txtRecordName("second.example")]: [latecomer.agentId],
    [txtRecordName("maintainer.example")]: [maintainer.agentId],
  });
  env = {
    DB: store.db,
    CAPTURES: store.captures,
    ENVIRONMENT: "local",
    MAINTAINER_AGENT_ID: maintainer.agentId,
  };

  // One registration, so the log has events for the seal step to seal.
  await join(operator, "first.example", NOW);
}, 240_000);

afterAll(async () => {
  await store?.dispose();
});

describe("a run whose seal step throws", () => {
  it("reads failing on the stage that threw, whatever the facts say", async () => {
    // A healthy run first, so the board has a seal of its own and the sealing
    // rule's own facts are green: the failing reading below is the throw and
    // nothing else.
    await sweep(NOW);
    expect(rowOf(await stages(NOW), "sealing").state).toBe("ok");

    // One interval later, with something new in the log for the seal step to
    // reach for and its write broken under it. The run fell over, and the
    // platform is told so.
    const broke = later(SWEEP_INTERVAL_MINUTES, NOW);
    await join(latecomer, "second.example", broke);
    await expect(
      sweep(broke, { ...env, DB: withBrokenSeal(store.db) }),
    ).rejects.toThrow(D1_ERROR);

    // The row says which of the two it was: a thrown message and a rule's
    // refusal share one column, and the mark is what tells them apart.
    const rows = await sweepSteps(store.db);
    const seal = rows.find((row) => row.step === "seal");
    expect(seal?.last_skip_reason).toBe(`${THROWN_REASON_PREFIX}${D1_ERROR}`);
    expect(seal?.last_skip_at).toBe(broke.toISOString());

    const board = await stages(broke);
    const sealing = rowOf(board, "sealing");
    expect(sealing.state).toBe("failing");
    // Named, and not merely counted: a board that said "failing" without the
    // message would send a reader to the logs to find out what broke.
    expect(sealing.last).toContain(D1_ERROR);
    expect(sealing.rule).toContain("a step that threw reads failing");

    // And the run itself is named on the timer, which is the only row that can
    // say "the sweep did not get through" rather than "one stage is behind".
    const timer = rowOf(board, "sweep timer");
    expect(timer.state).toBe("failing");
    expect(timer.last).toContain(D1_ERROR);

    // The counters are read off the same stages, so they cannot disagree.
    expect(board.filter((one) => one.state === "failing").length).toBe(
      [sealing, timer].length,
    );
  }, 240_000);

  it("reads ok again after a later run of that step gets through", async () => {
    const healed = later(2 * SWEEP_INTERVAL_MINUTES, NOW);
    await sweep(healed);

    const board = await stages(healed);
    expect(rowOf(board, "sealing").state).toBe("ok");
    expect(rowOf(board, "sweep timer").state).toBe("ok");
    for (const stage of board) {
      expect([stage.stage, stage.last.includes(D1_ERROR)]).toEqual([
        stage.stage,
        false,
      ]);
    }
  }, 240_000);
});

describe("a run whose clock is behind the board", () => {
  it("leaves the later instant in place, and records the run", async () => {
    const at = new Date("2026-09-10T12:00:00.000Z");
    const earlier = new Date(at.getTime() - 40 * MINUTE_MS);

    await putSweepSteps(store.db, [
      {
        step: "counters",
        last_run_at: at.toISOString(),
        last_ok_at: at.toISOString(),
        last_skip_reason: null,
        last_skip_at: null,
        detail: { position: 9 },
        trigger: "alarm",
      },
    ]);
    await putSweepSteps(store.db, [
      {
        step: "counters",
        last_run_at: earlier.toISOString(),
        last_ok_at: earlier.toISOString(),
        last_skip_reason: "counters_failed",
        last_skip_at: earlier.toISOString(),
        detail: { position: 7 },
        trigger: "alarm",
      },
    ]);

    const row = (await sweepSteps(store.db)).find(
      (one) => one.step === "counters",
    );
    // The board answers "when did this last happen", which is a maximum and
    // never a latest write.
    expect(row?.last_run_at).toBe(at.toISOString());
    expect(row?.last_ok_at).toBe(at.toISOString());
    // The run is still recorded: its reason and its detail landed, and only the
    // clock refused to go back.
    expect(row?.last_skip_reason).toBe("counters_failed");
    expect(row?.last_skip_at).toBe(earlier.toISOString());
    expect(row?.detail["position"]).toBe(7);
  }, 240_000);

  it("moves every instant forward for a run that is ahead of the board", async () => {
    const ahead = new Date("2026-09-10T13:00:00.000Z");
    await putSweepSteps(store.db, [
      {
        step: "counters",
        last_run_at: ahead.toISOString(),
        last_ok_at: ahead.toISOString(),
        last_skip_reason: null,
        last_skip_at: null,
        detail: { position: 11 },
        trigger: "alarm",
      },
    ]);

    const row = (await sweepSteps(store.db)).find(
      (one) => one.step === "counters",
    );
    expect(row?.last_run_at).toBe(ahead.toISOString());
    expect(row?.last_ok_at).toBe(ahead.toISOString());
  }, 240_000);
});
