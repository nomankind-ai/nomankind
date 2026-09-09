/**
 * The sweep's timer: the Sweeper Durable Object.
 *
 * The class is driven directly rather than through miniflare, which is what the
 * structural typing buys — a fake state holding one alarm in a variable, an
 * injected clock, and a fixture beacon are all the platform this file needs.
 * The database underneath is not faked though: it is miniflare's own D1 with
 * the migrations applied, so `/run` and `alarm()` run the real sweep against
 * the real query planner and the pool snapshot they commit is a real event in a
 * real log.
 *
 * The interval is asserted against SWEEP_INTERVAL_MINUTES rather than against
 * five: the number lives in src/policy.ts, and a test that wrote it down again
 * would be a second place for it to drift.
 */

import { afterEach, describe, expect, it } from "vitest";

import { FixtureBeacon } from "../src/adapters/beacon.js";
import { SWEEP_INTERVAL_MINUTES } from "../src/policy.js";
import type { D1Like, D1LikeStatement } from "../src/storage/d1.js";
import { eventBySeq, headSeq } from "../src/storage/repository.js";
import type { R2Like } from "../src/storage/r2.js";
import type { Env } from "../src/worker/env.js";
import {
  SWEEPER_INSTANCE,
  Sweeper,
  ensureSweeper,
  type SweeperDeps,
  type SweeperNamespace,
  type SweeperState,
  type SweeperStorage,
} from "../src/worker/sweeper.js";
import type { SweepReport } from "../src/worker/sweep.js";
import { openTestDatabase, type TestDatabase } from "./helpers/d1.js";
import {
  FakeAnchorAdapter,
  FakeWitnessAdapter,
  makeWitness,
  pinnedSet,
  type FakeWitness,
} from "./helpers/witness.js";

/** A unit constant: the alarm is set in milliseconds. */
const MINUTE_MS = 60_000;
const INTERVAL_MS = SWEEP_INTERVAL_MINUTES * MINUTE_MS;

/** The instant this file's fake clock reads, and never moves off by itself. */
const NOW = Date.parse("2026-09-08T12:00:00.000Z");

/** The alarm store, in one variable. */
function fakeState(): SweeperState & { readonly armedAt: () => number | null } {
  let alarm: number | null = null;
  const storage: SweeperStorage = {
    getAlarm: () => Promise.resolve(alarm),
    setAlarm: (scheduledTime: number) => {
      alarm = scheduledTime;
      return Promise.resolve();
    },
  };
  return { storage, armedAt: () => alarm };
}

/** The bindings, around a database the caller opened. */
function envFor(store: TestDatabase): Env {
  return {
    DB: store.db,
    CAPTURES: store.captures,
    ENVIRONMENT: "local",
    MAINTAINER_AGENT_ID: "",
  };
}

/** A beacon with one round on it, at the instant the fake clock reads. */
async function fixtureBeacon(): Promise<FixtureBeacon> {
  const beacon = new FixtureBeacon("sweeper");
  await beacon.advance(new Date(NOW - MINUTE_MS).toISOString());
  return beacon;
}

/**
 * The deps the object is built with: the fake clock, a fixture beacon, and the
 * sealing adapters faked, so no run of the timer reaches a registry, a witness
 * or a timestamping calendar.
 */
async function sweeperDeps(
  witness: FakeWitness,
): Promise<SweeperDeps & { readonly anchor: FakeAnchorAdapter }> {
  return {
    nowMs: () => NOW,
    beacon: await fixtureBeacon(),
    witness: new FakeWitnessAdapter({ signers: [witness] }),
    pinned: pinnedSet([witness]),
    ineligibleAgents: new Set<string>(),
    anchor: new FakeAnchorAdapter(null),
  };
}

/** The databases a test opened, disposed after it however it ended. */
const opened: TestDatabase[] = [];

async function database(): Promise<TestDatabase> {
  const store = await openTestDatabase();
  opened.push(store);
  return store;
}

afterEach(async () => {
  while (opened.length > 0) await opened.pop()?.dispose();
});

/** An env whose every call into the database fails. */
function throwingEnv(): Env {
  const fail = (): Promise<never> =>
    Promise.reject(new Error("D1_ERROR: no such table: events"));
  const statement = {
    bind: () => statement,
    first: fail,
    all: fail,
    run: fail,
  } as unknown as D1LikeStatement;
  const db = {
    prepare: () => statement,
    batch: fail,
    exec: fail,
  } as unknown as D1Like;
  const captures = { put: fail, get: fail, head: fail } as unknown as R2Like;
  return { DB: db, CAPTURES: captures, ENVIRONMENT: "local", MAINTAINER_AGENT_ID: "" };
}

describe("the sweeper's alarm, armed by a request", () => {
  it("arms the alarm one interval out when nothing is armed", async () => {
    const state = fakeState();
    const sweeper = new Sweeper(
      state,
      envFor(await database()),
      await sweeperDeps(await makeWitness("sweeper-witness.example")),
    );

    const response = await sweeper.fetch(new Request("https://sweeper/ensure"));

    expect(response.status).toBe(200);
    expect(await response.json()).toEqual({ armed: true, at: NOW + INTERVAL_MS });
    expect(state.armedAt()).toBe(NOW + INTERVAL_MS);
  });

  it("arms nothing the second time, so a busy Worker sets one alarm", async () => {
    const state = fakeState();
    const sweeper = new Sweeper(
      state,
      envFor(await database()),
      await sweeperDeps(await makeWitness("sweeper-witness.example")),
    );

    await sweeper.fetch(new Request("https://sweeper/ensure"));
    const again = await sweeper.fetch(new Request("https://sweeper/ensure"));

    expect(again.status).toBe(200);
    // The instant the standing alarm is set for, not a new one.
    expect(await again.json()).toEqual({ armed: false, at: NOW + INTERVAL_MS });
    expect(state.armedAt()).toBe(NOW + INTERVAL_MS);
  });

  it("answers an unknown path with 404", async () => {
    const sweeper = new Sweeper(
      fakeState(),
      envFor(await database()),
      await sweeperDeps(await makeWitness("sweeper-witness.example")),
    );

    const response = await sweeper.fetch(new Request("https://sweeper/nope"));

    expect(response.status).toBe(404);
    expect(await response.json()).toEqual({ ok: false, error: "not_found" });
  });
});

describe("running the sweep through the object", () => {
  it("answers the report and commits the pool snapshot on a fresh log", async () => {
    const store = await database();
    const witness = await makeWitness("sweeper-witness.example");
    const sweeper = new Sweeper(
      fakeState(),
      envFor(store),
      await sweeperDeps(witness),
    );

    const response = await sweeper.fetch(new Request("https://sweeper/run"));

    expect(response.status).toBe(200);
    const report = (await response.json()) as SweepReport;
    // The instant is the injected clock's, which is what says the object reads
    // no wall clock of its own.
    expect(report.at).toBe(new Date(NOW).toISOString());
    // A fresh log has no snapshot at all, so one is owed; the pool is empty
    // because no operator has been named to it yet.
    expect(report.snapshot?.operators).toEqual([]);
    expect(report.drawn).toEqual([]);
    expect(report.missed).toEqual([]);

    const event = await eventBySeq(store.db, report.snapshot?.seq as number);
    expect(event?.type).toBe("pool_snapshot");
    expect(event?.at).toBe(new Date(NOW).toISOString());

    // The same run seals what it appended and gathers the countersignature the
    // fake witness offers: everything gets sealed, and a seal is countersigned
    // as soon as it exists.
    expect(report.sealed).toEqual({
      seq: 0,
      first_seq: 0,
      last_seq: event!.seq,
      size: event!.seq + 1,
      entries: [],
    });
    expect(report.witnessed).toEqual([
      { seq: 0, operators: [witness.witness.operator] },
    ]);
    // Yesterday holds no seals at all on a fresh log, so nothing is anchored.
    expect(report.anchored).toBeNull();
    expect(report.skipped["no_seals_to_anchor"]).toBe(1);
  });

  it("sweeps and re-arms exactly one interval later on the alarm", async () => {
    const store = await database();
    const state = fakeState();
    const sweeper = new Sweeper(
      state,
      envFor(store),
      await sweeperDeps(await makeWitness("sweeper-witness.example")),
    );

    expect(await headSeq(store.db)).toBeNull();
    await sweeper.alarm();

    // The sweep really ran: the log moved, and the event it appended is the
    // snapshot the fresh log was owed.
    const head = await headSeq(store.db);
    expect(head).not.toBeNull();
    expect((await eventBySeq(store.db, head as number))?.type).toBe(
      "pool_snapshot",
    );
    expect(state.armedAt()).toBe(NOW + INTERVAL_MS);
  });

  it("re-arms even when the sweep throws, so the timer never stops", async () => {
    const state = fakeState();
    const sweeper = new Sweeper(
      state,
      throwingEnv(),
      await sweeperDeps(await makeWitness("sweeper-witness.example")),
    );

    // A storage failure is a lost run and nothing more: the alarm still returns
    // normally, and the next one is set.
    await expect(sweeper.alarm()).resolves.toBeUndefined();
    expect(state.armedAt()).toBe(NOW + INTERVAL_MS);
  });
});

describe("arming the timer from a request", () => {
  /** A namespace recording what was asked of it, over one stub. */
  function fakeNamespace(): SweeperNamespace & {
    readonly names: string[];
    readonly urls: string[];
  } {
    const names: string[] = [];
    const urls: string[] = [];
    const stub = {
      fetch: (input: string | Request): Promise<Response> => {
        urls.push(typeof input === "string" ? input : input.url);
        return Promise.resolve(new Response("{}", { status: 200 }));
      },
    };
    return {
      names,
      urls,
      idFromName: (name: string) => {
        names.push(name);
        return name;
      },
      get: () => stub,
    };
  }

  /** An execution context that keeps what it was handed. */
  function fakeContext(): {
    waitUntil: (promise: Promise<unknown>) => void;
    readonly promises: Promise<unknown>[];
  } {
    const promises: Promise<unknown>[] = [];
    return { promises, waitUntil: (promise) => promises.push(promise) };
  }

  it("defers one ensure fetch against the single instance", async () => {
    const namespace = fakeNamespace();
    const ctx = fakeContext();

    ensureSweeper(
      { ...throwingEnv(), SWEEPER: namespace },
      ctx,
    );

    expect(ctx.promises).toHaveLength(1);
    await ctx.promises[0];
    expect(namespace.names).toEqual([SWEEPER_INSTANCE]);
    expect(namespace.urls).toEqual(["https://sweeper/ensure"]);
  });

  it("does nothing at all without the binding", () => {
    const ctx = fakeContext();

    // The tests and the bindings-only platform proxy both hold an env with no
    // SWEEPER, and a missing doorbell must never cost a request.
    expect(() => ensureSweeper(throwingEnv(), ctx)).not.toThrow();
    expect(ctx.promises).toEqual([]);
  });

  it("never throws when the stub itself fails", async () => {
    const ctx = fakeContext();
    const namespace: SweeperNamespace = {
      idFromName: (name: string) => name,
      get: () => ({
        fetch: () => Promise.reject(new Error("no such object")),
      }),
    };

    ensureSweeper({ ...throwingEnv(), SWEEPER: namespace }, ctx);

    expect(ctx.promises).toHaveLength(1);
    await expect(ctx.promises[0]).resolves.toBeUndefined();
  });
});
