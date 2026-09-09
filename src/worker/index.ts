/**
 * The Worker entry point.
 *
 * Whitepaper Section 11, Deployment and status: every merge to main deploys
 * this Worker to demo and production through a public build action. The health
 * probe below says whether the Worker booted and whether its D1 binding
 * answers; M12 mounts the registry routes beside it (src/worker/registry.ts),
 * which are Section 11's joining door and the genesis naming, and M13 mounts
 * the submit routes (src/worker/submit.ts), which are Section 6's door for
 * entries and the reads that show a capture. M14 mounts the validate door
 * (src/worker/validate.ts) and the log's own page (src/worker/events.ts), and
 * adds the scheduled sweep (src/worker/sweep.ts) beside the request handler.
 * M15 mounts the reconfirmation door (src/worker/reconfirm.ts) beside the
 * validate one and gives the sweep its staleness step. M16 mounts the seal's own
 * pages (src/worker/seals.ts) — the seal chain, one seal, an event's inclusion
 * proof, and the daily anchors — and gives the sweep the three steps that make
 * them: seal, witness, anchor. Later milestones mount the rest — the public
 * pages — on the same router.
 *
 * This file is the one place in the system that reads a wall clock, and it
 * reads it once per request. Everything below it takes the instant as an
 * argument, which is what lets a test drive the real router at a fixed time.
 * The network and the payment provider enter the same way, as injected
 * adapters, so a test never reaches either.
 *
 * The health probe fails loud. If D1 does not answer, the endpoint reports 503
 * and `storage: "unreachable"`; it never reports `ok` on a database it could
 * not reach. It also deliberately does not go through the repository: the probe
 * has to work before any migration has run, so it asks D1 the one question that
 * needs no schema.
 *
 * No policy number lives here — nothing in this file is a policy number; the
 * bare integers are HTTP status codes. No environment-specific branch lives
 * here either: `ENVIRONMENT` is read from the binding and echoed back.
 */

import { DrandReader } from "../adapters/beacon.js";
import { DohResolver, type DnsResolver } from "../adapters/dns.js";
import { WebFetcher, type SnapshotFetcher } from "../adapters/fetch.js";
import { payoutAdapterFor, type PayoutAdapter } from "../adapters/payout.js";
import type { Env } from "./env.js";
import { handleEvents } from "./events.js";
import { handleReconfirm } from "./reconfirm.js";
import { handleRegistry, json } from "./registry.js";
import { handleSeals } from "./seals.js";
import { handleSubmit } from "./submit.js";
import { runSweep } from "./sweep.js";
import {
  ensureSweeper,
  sweepDepsFor,
  type ExecutionContextLike,
} from "./sweeper.js";
import { handleValidate } from "./validate.js";

/**
 * The sweep's timer, re-exported from the entry point because that is where
 * wrangler looks for a Durable Object class named in wrangler.jsonc.
 */
export { Sweeper } from "./sweeper.js";

/**
 * Ask D1 the cheapest question there is.
 *
 * Returns true only when a row actually came back: a driver that resolves with
 * nothing is as broken, for our purposes, as one that throws.
 */
async function storageReachable(env: Env): Promise<boolean> {
  try {
    const row = await env.DB.prepare("SELECT 1").first();
    return row !== null && row !== undefined;
  } catch (error) {
    // The message only: no binding contents, no request data.
    console.error(
      `health: storage probe failed: ${error instanceof Error ? error.message : String(error)}`,
    );
    return false;
  }
}

async function health(env: Env): Promise<Response> {
  const reachable = await storageReachable(env);
  if (!reachable) {
    return json(
      { ok: false, environment: env.ENVIRONMENT, storage: "unreachable" },
      503,
    );
  }
  return json({ ok: true, environment: env.ENVIRONMENT, storage: "ok" }, 200);
}

/**
 * What a caller may supply in place of the real world: the instant, the
 * resolver, the payment provider, the fetcher that takes a capture. A test
 * passes all four; the deployed Worker passes none and gets the wall clock,
 * real DNS-over-HTTPS, whichever payout adapter this environment runs (decision
 * D-013 as amended), and the norm rule's own fetch over the real network.
 */
export interface RequestDeps {
  readonly now?: Date;
  readonly dns?: DnsResolver;
  readonly payout?: PayoutAdapter;
  readonly fetcher?: SnapshotFetcher;
}

/** The router. Exported by name so tests can call it without a fetch stack. */
export async function handleRequest(
  request: Request,
  env: Env,
  deps?: RequestDeps,
): Promise<Response> {
  const { pathname } = new URL(request.url);

  if (pathname === "/health") {
    if (request.method !== "GET") {
      return json({ ok: false, error: "method_not_allowed" }, 405, { allow: "GET" });
    }
    return health(env);
  }

  // Read once, here, and passed down: two checks in one request must not be
  // able to disagree about what time it is.
  const now = deps?.now ?? new Date();

  const registry = await handleRegistry(request, env, {
    now,
    dns: deps?.dns ?? new DohResolver(),
    payout: deps?.payout ?? payoutAdapterFor(env.ENVIRONMENT),
  });
  if (registry !== null) return registry;

  const submitted = await handleSubmit(request, env, {
    now,
    fetcher: deps?.fetcher ?? new WebFetcher(),
  });
  if (submitted !== null) return submitted;

  const validated = await handleValidate(request, env, { now });
  if (validated !== null) return validated;

  const reconfirmed = await handleReconfirm(request, env, { now });
  if (reconfirmed !== null) return reconfirmed;

  const events = await handleEvents(request, env);
  if (events !== null) return events;

  const seals = await handleSeals(request, env);
  if (seals !== null) return seals;

  return json({ ok: false, error: "not_found" }, 404);
}

/**
 * What the platform hands a scheduled invocation. Typed structurally rather than
 * imported from a generated Worker types package: the kernel stays buildable
 * with the approved dependency baseline (decision D-011), exactly as `Env` types
 * its bindings structurally.
 */
export interface ScheduledController {
  /** The instant this run was scheduled for, in milliseconds since the epoch. */
  readonly scheduledTime: number;
  readonly cron: string;
}

/** The execution context. Unused here: the sweep is awaited, not deferred. */
export interface ScheduledContext {
  waitUntil(promise: Promise<unknown>): void;
}

/**
 * The deployed entry point. It passes no deps, so the Worker always runs on the
 * real clock and the real adapters: there is no argument a request could carry
 * that swaps either out.
 *
 * Every request arms the sweep's timer before it is served. `ensureSweeper` is
 * a `waitUntil` into the Sweeper Durable Object, which sets an alarm only when
 * none is set, so the cost is one cheap call and the benefit is that a timer
 * whose chain of alarms was ever broken is repaired by the next visitor. It
 * never throws and the response never waits on it.
 *
 * `scheduled` is the cron trigger's door (wrangler.jsonc names the cadence). It
 * reads the instant off the controller, which is the platform's own clock for
 * this run and is read exactly once, and constructs the real drand reader: the
 * fixture beacon in src/adapters/beacon.ts is for tests and is never reachable
 * from here (decision D-013 as amended). The witness and anchor adapters are
 * built the same way, by `sweepDepsFor`, so the cron door and the Durable
 * Object's alarm sweep against exactly the same world. The sweep is awaited
 * rather than passed to `waitUntil`, so a run that fails is a failed run the
 * platform can see.
 */
export default {
  fetch: (
    request: Request,
    env: Env,
    ctx: ExecutionContextLike,
  ): Promise<Response> => {
    ensureSweeper(env, ctx);
    return handleRequest(request, env);
  },
  scheduled: async (
    controller: ScheduledController,
    env: Env,
    _ctx: ScheduledContext,
  ): Promise<void> => {
    await runSweep(
      env,
      await sweepDepsFor(env, () => controller.scheduledTime, {
        beacon: new DrandReader(),
      }),
    );
  },
};
