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
 * validate one and gives the sweep its staleness step. M20 mounts Section 6's
 * dispute and revalidation doors and Section 8's failure-report door beside
 * them (src/worker/dispute.ts, src/worker/revalidate.ts,
 * src/worker/failure-reports.ts), and gives the sweep the draw and the miss that
 * answer a revalidation request. M16 mounts the seal's own
 * pages (src/worker/seals.ts) — the seal chain, one seal, an event's inclusion
 * proof, and the daily anchors — and gives the sweep the three steps that make
 * them: seal, witness, anchor. M17 mounts Section 8's read door
 * (src/worker/read.ts), which serves one entry with its seal and a signed read
 * receipt, and gives the sweep the step that publishes each day's read count.
 * M18 mounts Section 8's other door beside it, the delta stream
 * (src/worker/sync.ts), which serves the sealed log after a position a trainer
 * already holds, with an inclusion proof for every event and one signed sync
 * receipt covering the page. M19 mounts the browsing UI (src/worker/pages.ts)
 * ahead of all of them: it is the log's face for a person rather than an agent,
 * it owns the pages and the stylesheets, and on the four paths it shares with the
 * JSON doors it answers HTML to a browser and returns null otherwise. M21
 * mounts Section 9's own reads (src/worker/standing.ts) — the standing table,
 * one operator's standing, one operator's ledger, and the ledger page — and
 * gives the sweep the three steps that produce them: price what the seal
 * committed to, recompute standing, and pay the cycle. M22 mounts Section 8's
 * training path (src/worker/attest.ts) last: the three doors a drift
 * attestation moves through — a model asks for a probe set drawn by public
 * randomness, answers it, and three drawn operators sign what they made of the
 * answers — the reads beside them, and the confidence field's raw inputs, which
 * is where `confidence: null` is served from. The sweep gains the step that
 * closes an attestation nobody finished. The final
 * refusal below answers in the same two voices for the same reason.
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

import { DrandReader, type BeaconReader } from "../adapters/beacon.js";
import { DohResolver, type DnsResolver } from "../adapters/dns.js";
import { WebFetcher, type SnapshotFetcher } from "../adapters/fetch.js";
import { mirrorAdapterFor } from "../adapters/mirror.js";
import { payoutAdapterFor, type PayoutAdapter } from "../adapters/payout.js";
import {
  paymentsAdapterFor,
  type PaymentsAdapter,
} from "../adapters/stripe.js";
import { htmlResponse } from "../ui/html.js";
import { renderNotFound } from "../ui/pages/errors.js";
import type { Env } from "./env.js";
import { handleAlerts } from "./alerts.js";
import { handleAttest } from "./attest.js";
import { handleDispute } from "./dispute.js";
import { handleEvents } from "./events.js";
import { handleFailureReports } from "./failure-reports.js";
import { handleKeys } from "./keys.js";
import { handleMirror } from "./mirror.js";
import { forMethod, handlePages, wantsHtml } from "./pages.js";
import { handleRead } from "./read.js";
import { handleReconfirm } from "./reconfirm.js";
import { handleRegistry, json } from "./registry.js";
import { handleRevalidate } from "./revalidate.js";
import { handleSeals } from "./seals.js";
import { handleStanding } from "./standing.js";
import { handleStatus } from "./status.js";
import { handleStripeWebhook } from "./stripe.js";
import { handleSubmit } from "./submit.js";
import { runSweep } from "./sweep.js";
import {
  ensureSweeper,
  sweepDepsFor,
  type ExecutionContextLike,
} from "./sweeper.js";
import { handleSync } from "./sync.js";
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
  /**
   * Where the attestation door reads public randomness (M22). The deployed
   * Worker passes none and gets the real drand reader, exactly as the cron
   * door's sweep does; the fixture beacon is for tests and is never reachable
   * from here (decision D-013 as amended).
   */
  readonly beacon?: BeaconReader;
  /**
   * Where the paid loop's money goes (M24, decision D-078). The deployed Worker
   * passes none and gets whichever track this environment's secrets say it
   * runs — the real provider where a key is set, the refusal on production
   * where none is, and the mock everywhere else — exactly as the payout and
   * mirror adapters are built. A test passes a mock and never reaches the
   * network.
   */
  readonly payments?: PaymentsAdapter;
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

  // The browsing UI answers first (M19). It owns the pages and the stylesheets,
  // and it shares four paths with the JSON doors below — an entry, the operator
  // directory, one operator, and the policy endpoint — where it answers HTML to
  // a browser and hands the request on to them otherwise.
  const page = await handlePages(request, env, { now });
  if (page !== null) return page;

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

  // M20's three doors, Section 6's "Dispute" and "Revalidate" and Section 8's
  // failure reports. The dispute door runs the submit route's own pipeline on
  // the correction entry, so it takes the same fetcher.
  const disputed = await handleDispute(request, env, {
    now,
    fetcher: deps?.fetcher ?? new WebFetcher(),
  });
  if (disputed !== null) return disputed;

  const revalidated = await handleRevalidate(request, env, { now });
  if (revalidated !== null) return revalidated;

  const reported = await handleFailureReports(request, env, { now });
  if (reported !== null) return reported;

  const readable = await handleRead(request, env, { now });
  if (readable !== null) return readable;

  const synced = await handleSync(request, env, { now });
  if (synced !== null) return synced;

  // M24's paid access, Section 9's "Money": the tiers, the checkout, the claim
  // that hands a key over once, and what one key read. The payment provider
  // enters as an injected adapter, so a test never reaches one.
  const payments = deps?.payments ?? paymentsAdapterFor(env);

  const keys = await handleKeys(request, env, { now, payments });
  if (keys !== null) return keys;

  // The one door the provider knocks on. It trusts nothing it is sent until the
  // signature over the raw body verifies against this deployment's own webhook
  // secret, and it may change exactly one column: a key's status.
  const webhook = await handleStripeWebhook(request, env, { now, payments });
  if (webhook !== null) return webhook;

  // M24's change alerts, Section 9's "structured feeds and webhooks, change
  // alerts": the endpoints one key subscribes, under /keys/me/webhooks.
  const alerts = await handleAlerts(request, env, { now });
  if (alerts !== null) return alerts;

  const events = await handleEvents(request, env);
  if (events !== null) return events;

  const seals = await handleSeals(request, env);
  if (seals !== null) return seals;

  // M21's four reads, Section 9's "Standing" and "Money": the whole standing
  // table and one operator's, recomputed from the sealed log, and the ledger
  // beside them. JSON only, whatever the caller asks for.
  const standing = await handleStanding(request, env, { now });
  if (standing !== null) return standing;

  // M23's one read, Section 11's "Deployment and status": whether the clockwork
  // is running, as JSON. A browser asking for the same path never gets here —
  // src/worker/pages.ts answered it with the page above.
  const status = await handleStatus(request, env, { now });
  if (status !== null) return status;

  // M23's other read, Section 11's daily log mirror: where the newest export of
  // the sealed log landed, as JSON. A browser asking for the same path never
  // gets here — src/worker/pages.ts answered it with the page above, exactly as
  // /policy and /status split.
  const mirror = await handleMirror(request, env);
  if (mirror !== null) return mirror;

  // M22's three doors and four reads, Section 8's "Drift attestation" and "The
  // confidence field": a model asks for a probe set drawn by public randomness,
  // answers it, and three drawn operators sign what they made of the answers;
  // beside them, the raw inputs to the confidence field, which is null.
  const attested = await handleAttest(request, env, {
    now,
    beacon: deps?.beacon ?? new DrandReader(),
  });
  if (attested !== null) return attested;

  // Nothing answered. A browser gets the 404 page, which tells a reader what
  // kinds of address land there; everything else gets the same JSON refusal it
  // has always got, because an agent parsing `not_found` must keep parsing it.
  // A HEAD is a GET without the body on this path as on every other, so it is on
  // the browser's side of the split and answers the page's own headers.
  const browsing =
    (request.method === "GET" || request.method === "HEAD") &&
    wantsHtml(request);
  if (browsing) {
    return forMethod(
      request,
      htmlResponse(
        renderNotFound({
          environment: env.ENVIRONMENT,
          path: pathname,
          origin: new URL(request.url).origin,
        }),
        404,
      ),
    );
  }
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
      {
        ...(await sweepDepsFor(env, () => controller.scheduledTime, {
          beacon: new DrandReader(),
        })),
        // The payout adapter this environment runs (decision D-013 as amended,
        // D-053): a mock on demo and local, the stub that refuses on
        // production, and never a fixture — the same rule the beacon follows.
        payout: payoutAdapterFor(env.ENVIRONMENT),
        // Where the day's export goes (M23), built the same way and for the
        // same reason: the cron door and the alarm mirror to one repository.
        mirror: mirrorAdapterFor(env),
        // Where the day's paid reads are reported (M24, D-078), built the same
        // way and for the same reason: the cron door and the alarm bill through
        // one provider, and production without a key meters nothing at all.
        payments: paymentsAdapterFor(env),
        // Which door ran it, for the status board's own row (D-076). The Sweeper
        // Durable Object says nothing and is read as `alarm`, which is what it
        // is: the sweep's own timer, with this cron trigger as the repair.
        trigger: "cron",
      },
    );
  },
};
