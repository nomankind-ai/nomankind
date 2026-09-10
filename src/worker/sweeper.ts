/**
 * The timer the sweep runs on: a Durable Object that re-arms its own alarm.
 *
 * Why this exists rather than the cron trigger alone. The cron registered on
 * the demo Worker (wrangler.jsonc `triggers`) was watched for an hour across
 * six deploys and a re-add by hand, and it never fired once — no scheduled
 * invocation and no error. A sweep that only runs when someone else's scheduler
 * decides to call is not a timer nomankind controls, so the cadence is moved
 * onto a Durable Object alarm, which is a real timer on the free plan and is
 * ours: the object sets it, the platform delivers it, and the object sets the
 * next one before it returns.
 *
 * The cron stays where it is. It costs nothing, and the sweep is idempotent —
 * a snapshot is committed only when the pool has moved, an assignment is closed
 * only when its window has run out, a draw is made only when one is owed — so
 * two timers pointed at it are two chances to catch up rather than a race.
 *
 * The object holds no state of its own beyond the alarm. Everything the sweep
 * needs is read from D1 on each run, so a Sweeper that is evicted, moved, or
 * restarted loses nothing: the log is the record and the alarm is only a
 * doorbell. There is exactly one instance, `idFromName("sweeper")`, because two
 * would only do the same idempotent work twice.
 *
 * Typed structurally, like `Env` and `ScheduledController` before it: the
 * platform's Durable Object types are not imported, so the kernel stays
 * buildable on the approved dependency baseline (decision D-011).
 *
 * No wall clock and no network of its own that a test cannot replace: the
 * clock, the beacon and the sealing adapters all arrive through the
 * constructor, defaulting to `Date.now`, the real `DrandReader` and whichever
 * witness and anchor adapters this environment runs, which is decision D-013 as
 * amended — the deployed object builds the real ones, and nothing here can be
 * handed a fixture by a request.
 *
 * The only number here is SWEEP_INTERVAL_MINUTES from src/policy.ts.
 */

import { DrandReader, type BeaconReader } from "../adapters/beacon.js";
import { anchorAdapterFor } from "../adapters/anchor.js";
import { mirrorAdapterFor, type MirrorAdapter } from "../adapters/mirror.js";
import {
  pinnedWitnessesFor,
  sealingAgentIdFor,
  witnessAdapterFor,
  type EnvironmentWitnessAdapter,
} from "../adapters/witness.js";
import { payoutAdapterFor, type PayoutAdapter } from "../adapters/payout.js";
import type { AnchorAdapter } from "../anchor.js";
import { SWEEP_INTERVAL_MINUTES } from "../policy.js";
import type { Env } from "./env.js";
import { json } from "./registry.js";
import { runSweep, type PinnedWitnesses, type SweepDeps } from "./sweep.js";

/** A unit constant, not a policy number: minutes are stated in milliseconds. */
const MILLISECONDS_PER_MINUTE = 60_000;

/** The one instance. Named rather than random, so every request finds it. */
export const SWEEPER_INSTANCE = "sweeper";

/** The arming request `ensureSweeper` makes. The host is ignored by the stub. */
const ENSURE_URL = "https://sweeper/ensure";

/** The alarm store the platform hands a Durable Object. */
export interface SweeperStorage {
  /** The instant the alarm is set for, or null when none is set. */
  getAlarm(): Promise<number | null>;
  setAlarm(scheduledTime: number): Promise<void>;
}

/** What the platform constructs a Durable Object with. */
export interface SweeperState {
  readonly storage: SweeperStorage;
  /** The object's own id. Not used here; present because the platform sets it. */
  readonly id?: { toString(): string };
}

/** A stub for one instance: a fetch into the object, and nothing else. */
export interface SweeperStub {
  fetch(input: string | Request, init?: RequestInit): Promise<Response>;
}

/** The namespace binding a Worker holds for the Sweeper class. */
export interface SweeperNamespace {
  idFromName(name: string): unknown;
  get(id: unknown): SweeperStub;
}

/** The execution context, for the parts of it this file uses. */
export interface ExecutionContextLike {
  waitUntil(promise: Promise<unknown>): void;
}

/**
 * What a caller may supply in place of the world: the clock, the beacon, and the
 * three sealing adapters beside them.
 *
 * Every one of them defaults to the real thing, built from the bindings, so the
 * deployed object reaches the real drand, the environment's own witness track
 * and its own timestamping chain, and no request can hand it a fixture
 * (decision D-013 as amended).
 */
export interface SweeperDeps {
  /** Milliseconds since the epoch. Defaults to the platform's own clock. */
  readonly nowMs?: () => number;
  readonly beacon?: BeaconReader;
  readonly witness?: EnvironmentWitnessAdapter;
  readonly pinned?: PinnedWitnesses;
  readonly ineligibleAgents?: ReadonlySet<string>;
  readonly anchor?: AnchorAdapter;
  readonly payout?: PayoutAdapter;
  readonly mirror?: MirrorAdapter;
}

/**
 * The whole of what one sweep needs, built from the bindings.
 *
 * The one place the sealing adapters are constructed: the scheduled handler, the
 * alarm and `/run` all come through here, so the three timers into the sweep
 * cannot disagree about which witness track or which calendar this environment
 * is on. `ineligibleAgents` is nomankind's own pair — the maintainer agent and
 * whatever key the sealing agent holds — because the paper makes nomankind
 * ineligible to witness its own seal, and an unset binding is simply absent
 * rather than an empty id in the set.
 */
export async function sweepDepsFor(
  env: Env,
  nowMs: () => number,
  deps?: SweeperDeps,
): Promise<SweepDeps> {
  const ineligible =
    deps?.ineligibleAgents ??
    new Set(
      [env.MAINTAINER_AGENT_ID, await sealingAgentIdFor(env)].filter(
        (agent): agent is string => typeof agent === "string" && agent !== "",
      ),
    );
  return {
    now: new Date(nowMs()),
    beacon: deps?.beacon ?? new DrandReader(),
    witness: deps?.witness ?? witnessAdapterFor(env),
    pinned: deps?.pinned ?? pinnedWitnessesFor(env.ENVIRONMENT),
    ineligibleAgents: ineligible,
    anchor:
      deps?.anchor ??
      anchorAdapterFor(env.ENVIRONMENT, () => new Date(nowMs())),
    // The payout adapter this environment runs (D-013 as amended, D-053): a
    // mock on demo and local, the stub that refuses on production. Built here
    // rather than only at the scheduled handler because the alarm is a sweep
    // like any other — a cycle that pays through the cron door and skips
    // `payout_unconfigured` through the alarm would be two different sweeps.
    payout: deps?.payout ?? payoutAdapterFor(env.ENVIRONMENT),
    // Where the day's export goes (M23). Built here for the reason the payout
    // adapter is: the alarm is a sweep like any other, and an environment that
    // mirrored through the cron door and skipped `mirror_unavailable` through
    // the alarm would be two different sweeps. The secret decides the track, so
    // an environment without one says so rather than failing a call a day.
    mirror: deps?.mirror ?? mirrorAdapterFor(env),
  };
}

/**
 * The sweep's timer.
 *
 * `/ensure` arms the alarm when nothing is armed, and is safe to call on every
 * request: the object reads its own alarm first, so a busy Worker sets one
 * alarm rather than one per visitor. `/run` sweeps immediately and answers the
 * report, which is what makes the object testable and checkable by hand without
 * waiting out an interval.
 */
export class Sweeper {
  readonly #state: SweeperState;
  readonly #env: Env;
  readonly #nowMs: () => number;
  readonly #deps: SweeperDeps | undefined;

  constructor(state: SweeperState, env: Env, deps?: SweeperDeps) {
    this.#state = state;
    this.#env = env;
    this.#nowMs = deps?.nowMs ?? (() => Date.now());
    this.#deps = deps;
  }

  /** One run's deps, built fresh so every run reads the clock for itself. */
  #sweepDeps(): Promise<SweepDeps> {
    return sweepDepsFor(this.#env, this.#nowMs, this.#deps);
  }

  async fetch(request: Request): Promise<Response> {
    const { pathname } = new URL(request.url);

    if (pathname === "/ensure") {
      const existing = await this.#state.storage.getAlarm();
      if (existing !== null) return json({ armed: false, at: existing }, 200);
      const at = this.#nowMs() + SWEEP_INTERVAL_MINUTES * MILLISECONDS_PER_MINUTE;
      await this.#state.storage.setAlarm(at);
      return json({ armed: true, at }, 200);
    }

    if (pathname === "/run") {
      const report = await runSweep(this.#env, await this.#sweepDeps());
      return json(report, 200);
    }

    return json({ ok: false, error: "not_found" }, 404);
  }

  /**
   * The alarm. Sweep, then arm the next one.
   *
   * The sweep runs inside try/catch and the re-arm is outside it on purpose: an
   * alarm that fails and does not set the next one is a timer that has stopped,
   * and a database blip or an unreachable beacon must cost one run rather than
   * every run after it. What went wrong is logged as a message and nothing more
   * — no binding contents and no log rows.
   */
  async alarm(): Promise<void> {
    try {
      await runSweep(this.#env, await this.#sweepDeps());
    } catch (error) {
      console.error(
        `sweeper: sweep failed: ${error instanceof Error ? error.message : String(error)}`,
      );
    }
    await this.#state.storage.setAlarm(
      this.#nowMs() + SWEEP_INTERVAL_MINUTES * MILLISECONDS_PER_MINUTE,
    );
  }
}

/**
 * Arm the timer, from a request.
 *
 * Called on every request the Worker serves, which is what makes the alarm
 * self-healing: any visitor rearms a Sweeper whose chain of alarms was ever
 * broken, and the object itself decides whether anything needs setting. It is
 * deferred through `waitUntil`, so the response never waits on it.
 *
 * Never throws. A missing binding is the normal case in tests and under the
 * bindings-only platform proxy, and a serving Worker must not fail a request
 * because a timer could not be armed.
 */
export function ensureSweeper(env: Env, ctx: ExecutionContextLike): void {
  const namespace = env.SWEEPER;
  if (namespace === undefined || namespace === null) return;
  try {
    const stub = namespace.get(namespace.idFromName(SWEEPER_INSTANCE));
    ctx.waitUntil(
      stub.fetch(ENSURE_URL).then(
        () => undefined,
        (error: unknown) => {
          console.error(
            `sweeper: ensure failed: ${error instanceof Error ? error.message : String(error)}`,
          );
        },
      ),
    );
  } catch (error) {
    console.error(
      `sweeper: ensure failed: ${error instanceof Error ? error.message : String(error)}`,
    );
  }
}
