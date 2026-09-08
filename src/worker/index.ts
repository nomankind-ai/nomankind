/**
 * The Worker entry point.
 *
 * Whitepaper Section 11, Deployment and status: every merge to main deploys
 * this Worker to demo and production through a public build action. The health
 * probe below says whether the Worker booted and whether its D1 binding
 * answers; M12 mounts the registry routes beside it (src/worker/registry.ts),
 * which are Section 11's joining door and the genesis naming, and M13 mounts
 * the submit routes (src/worker/submit.ts), which are Section 6's door for
 * entries and the reads that show a capture. Later milestones mount the rest —
 * validation, reconfirmation, the public pages — on the same router.
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

import { DohResolver, type DnsResolver } from "../adapters/dns.js";
import { WebFetcher, type SnapshotFetcher } from "../adapters/fetch.js";
import { payoutAdapterFor, type PayoutAdapter } from "../adapters/payout.js";
import type { Env } from "./env.js";
import { handleRegistry, json } from "./registry.js";
import { handleSubmit } from "./submit.js";

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

  return json({ ok: false, error: "not_found" }, 404);
}

/**
 * The deployed entry point. It passes no deps, so the Worker always runs on the
 * real clock and the real adapters: there is no argument a request could carry
 * that swaps either out.
 */
export default {
  fetch: (request: Request, env: Env): Promise<Response> =>
    handleRequest(request, env),
};
