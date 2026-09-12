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
 * Three rules live around the routing rather than inside it, because each is
 * one rule and a door that had to remember it would be a door that could
 * forget. The anonymous pages are served through the Cache API (the QA of
 * 2026-09-12): Cloudflare does not cache a Worker's own response on a
 * `cache-control` header alone, so the lookup and the write are made here, keyed
 * by host, path, query and which of the two documents the path answers. A
 * request carrying a key or an agent signature is never served from that cache
 * and never stored in it, because what it is answered depends on who is asking
 * (the release window, D-100), and no JSON door but `GET /policy` is cached at
 * all. A path that answers HTML to a browser and JSON to everyone else carries
 * `vary: Accept` on both variants and on its refusals. And a HEAD is a GET
 * without the body: every read door answers it, and the body is dropped once,
 * here.
 *
 * No policy number lives here — nothing in this file is a policy number; the
 * bare integers are HTTP status codes, and the cache's two are
 * PAGE_CACHE_SECONDS and PAGE_CACHE_STALE_SECONDS from src/policy.ts. No
 * environment-specific branch lives here either: `ENVIRONMENT` is read from the
 * binding and echoed back.
 */

import { DrandReader, type BeaconReader } from "../adapters/beacon.js";
import { DohResolver, type DnsResolver } from "../adapters/dns.js";
import { WebFetcher, type SnapshotFetcher } from "../adapters/fetch.js";
import { payoutAdapterFor, type PayoutAdapter } from "../adapters/payout.js";
import {
  paymentsAdapterFor,
  type PaymentsAdapter,
} from "../adapters/stripe.js";
import { PAGE_CACHE_SECONDS, PAGE_CACHE_STALE_SECONDS } from "../policy.js";
import { HEADER_AGENT } from "../request.js";
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
import { READ_METHODS, handleRegistry, isRead, json } from "./registry.js";
import { handleRevalidate } from "./revalidate.js";
import { handleSeals } from "./seals.js";
import { handleStanding } from "./standing.js";
import { handleStatus } from "./status.js";
import { handleStripeWebhook } from "./stripe.js";
import { handleSubmit } from "./submit.js";
import {
  armSweeper,
  ensureSweeper,
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
  /**
   * The edge cache the anonymous pages are served from (D-059 as amended). The
   * deployed Worker passes `caches.default`; a test passes its own, and a
   * caller that passes none — which is every existing test — renders every
   * page as before, because a cache nobody handed us is a cache we do not use.
   */
  readonly cache?: CacheLike;
  /** Where the cache write is deferred to: the platform's `ctx.waitUntil`. */
  readonly waitUntil?: (promise: Promise<unknown>) => void;
}

/**
 * The Cache API, typed structurally rather than imported from a generated
 * Worker types package, exactly as `Env` types its bindings (decision D-011).
 */
export interface CacheLike {
  match(request: Request): Promise<Response | undefined>;
  put(request: Request, response: Response): Promise<void>;
}

/**
 * What a cached page says about itself. A minute at the edge, and five more in
 * which a stale copy may be served while a fresh one is fetched; both numbers
 * are src/policy.ts's and neither is spelt out here.
 */
const PAGE_CACHE_CONTROL =
  `public, max-age=${PAGE_CACHE_SECONDS}, ` +
  `stale-while-revalidate=${PAGE_CACHE_STALE_SECONDS}`;

/**
 * The paths whose 200 is a page: everything `handlePages` renders, plus the two
 * JSON doors that are cached with them — `GET /policy` and `GET /status`, named
 * in CACHEABLE_JSON_PATHS below. The listing, the entry, the operator directory
 * and one operator are the prefixes below.
 */
const CACHEABLE_PATHS: ReadonlySet<string> = new Set([
  "/",
  "/landing",
  "/entries",
  "/operators",
  "/policy",
  "/api",
  "/docs",
  "/dry-run",
  "/genesis",
  "/how-it-works",
  "/domains",
  "/status",
  "/mirror/latest",
]);

/**
 * Whether a path is one of those, an id or a document under it included.
 *
 * Exported for the test that enumerates every path src/worker/pages.ts serves
 * and asks this of each one: a page added there and forgotten here would be a
 * page that went on costing the log a read per reader, quietly.
 */
export function cacheablePath(path: string): boolean {
  return (
    CACHEABLE_PATHS.has(path) ||
    path.startsWith("/entries/") ||
    path.startsWith("/operators/") ||
    path.startsWith("/docs/")
  );
}

/**
 * The paths that answer HTML to a browser and JSON to everyone else.
 *
 * Every response on one of them carries `vary: Accept` — both variants, the
 * refusals included — because a shared cache that keyed one of these paths
 * without the header would hand an agent a web page. The HTML side gets it from
 * `htmlResponse`; this is the other side.
 */
const NEGOTIATED_PATHS: ReadonlySet<string> = new Set([
  "/policy",
  "/operators",
  "/status",
  "/mirror/latest",
  "/keys/claim",
]);

function negotiates(path: string): boolean {
  return (
    NEGOTIATED_PATHS.has(path) ||
    path.startsWith("/entries/") ||
    path.startsWith("/operators/")
  );
}

/** `vary: Accept` on a negotiated path, on whichever variant answered. */
function varyOnNegotiated(path: string, response: Response): Response {
  if (!negotiates(path)) return response;
  if (response.headers.get("vary") !== null) return response;
  const headers = new Headers(response.headers);
  headers.set("vary", "Accept");
  return new Response(response.body, {
    status: response.status,
    statusText: response.statusText,
    headers,
  });
}

/** The variant marker: the same path answers two documents, and both cache. */
const VARIANT_PARAMETER = "__nmk_variant";

/**
 * The key one page is cached under: this host, this path, this query, and which
 * of the two documents the path answers. The marker is what keeps the JSON twin
 * of a shared path from ever being served to a browser, or the page to an agent.
 * It is a key and never a URL anything fetches.
 */
function pageCacheKey(url: URL, html: boolean): Request {
  const key = new URL(url.toString());
  // Every copy a caller sent goes first. The marker is ours, and a request that
  // arrived carrying `?__nmk_variant=html` would otherwise be keyed as though it
  // were the HTML twin of itself — one query string aliasing another page's
  // entry, chosen by whoever sent the link.
  key.searchParams.delete(VARIANT_PARAMETER);
  key.searchParams.set(VARIANT_PARAMETER, html ? "html" : "json");
  return new Request(key.toString(), { method: "GET" });
}

/**
 * Whether this request may be served from the edge at all.
 *
 * A GET only — a HEAD is answered from the same path without storing anything,
 * and every other method is a write. And anonymous only: a request carrying a
 * key or an agent signature is a request whose answer depends on who is asking
 * (the release window, decision D-100), and an answer like that must never be
 * handed to the next reader.
 */
function cacheable(request: Request, url: URL): boolean {
  if (request.method !== "GET") return false;
  if (request.headers.get("authorization") !== null) return false;
  if (request.headers.get(HEADER_AGENT) !== null) return false;
  return cacheablePath(url.pathname);
}

/**
 * The JSON doors cached beside the pages, and the only ones.
 *
 * `GET /policy` is a frozen module constant and the same object for every
 * caller. `GET /status` is the same reading of the same stored rows the status
 * page is rendered from, and nothing on it is probed when it is asked for — so
 * the twin that a browser gets cached and the twin that an agent gets rendered
 * from D1 every time was one door answering the same question at two prices.
 * Both are anonymous answers: a request carrying a key or an agent signature is
 * never served from the cache or stored in it, whatever its path.
 */
const CACHEABLE_JSON_PATHS: ReadonlySet<string> = new Set(["/policy", "/status"]);

/** Whether the answer we rendered is one of the documents that may be stored. */
function storable(path: string, response: Response): boolean {
  if (response.status !== 200) return false;
  const type = response.headers.get("content-type") ?? "";
  return type.startsWith("text/html") || CACHEABLE_JSON_PATHS.has(path);
}

/**
 * The two calls into the cache, and the one rule about them: a cache that fails
 * is a cache that is not there.
 *
 * The Cache API is a service, and a service can be unavailable. Unguarded, a
 * throwing `match` or `put` would turn every page of the site into a 500 — the
 * log would go dark because an optimisation broke, which is the opposite of what
 * an optimisation may cost. So a failed lookup is a miss and a failed write is a
 * page that was served and not stored; the reason is logged once, with nothing
 * from the request in it, and the reader gets their page.
 */
async function cached(
  cache: CacheLike,
  key: Request,
): Promise<Response | undefined> {
  try {
    return await cache.match(key);
  } catch (error) {
    console.error(`cache: lookup failed: ${messageOf(error)}`);
    return undefined;
  }
}

async function store(
  cache: CacheLike,
  key: Request,
  response: Response,
): Promise<void> {
  try {
    await cache.put(key, response);
  } catch (error) {
    console.error(`cache: write failed: ${messageOf(error)}`);
  }
}

/** The message only: no binding contents, no request data. */
function messageOf(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

/** The same response, saying it may be held for a minute. */
function forPageCache(response: Response): Response {
  const headers = new Headers(response.headers);
  headers.set("cache-control", PAGE_CACHE_CONTROL);
  return new Response(response.body, {
    status: response.status,
    statusText: response.statusText,
    headers,
  });
}

/**
 * The router. Exported by name so tests can call it without a fetch stack.
 *
 * Three things happen around the dispatch below and nowhere else in the system:
 * the anonymous pages are looked up in and written to the edge cache, a
 * negotiated path's answer is given `vary: Accept` on whichever variant
 * answered, and a HEAD is turned into its GET without a body. Each is one rule
 * in one place, so no door can forget it.
 */
export async function handleRequest(
  request: Request,
  env: Env,
  deps?: RequestDeps,
): Promise<Response> {
  const url = new URL(request.url);
  const cache = deps?.cache;
  const key =
    cache !== undefined && cacheable(request, url)
      ? pageCacheKey(url, wantsHtml(request))
      : null;
  if (cache !== undefined && key !== null) {
    const hit = await cached(cache, key);
    // Served exactly as it was stored, headers and all: a page that was
    // rewritten on the way out would not be the page that was checked.
    if (hit !== undefined) return hit;
  }

  const answered = varyOnNegotiated(
    url.pathname,
    await dispatch(request, env, deps),
  );

  if (cache !== undefined && key !== null && storable(url.pathname, answered)) {
    const stored = forPageCache(answered);
    const write = store(cache, key, stored.clone());
    // Deferred where the platform gave us somewhere to defer to, awaited
    // otherwise, so the answer never waits on the write but a test can.
    if (deps?.waitUntil === undefined) await write;
    else deps.waitUntil(write);
    return stored;
  }

  return forMethod(request, answered);
}

/**
 * The routing itself: every door in the order it is mounted, and the final
 * refusal under them. It answers the request and nothing more — the cache, the
 * negotiation header and the HEAD are `handleRequest`'s, above.
 */
async function dispatch(
  request: Request,
  env: Env,
  deps?: RequestDeps,
): Promise<Response> {
  const { pathname } = new URL(request.url);

  if (pathname === "/health") {
    if (!isRead(request)) {
      return json({ ok: false, error: "method_not_allowed" }, 405, {
        allow: READ_METHODS,
      });
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

  const events = await handleEvents(request, env, { now });
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
 * `scheduled` is the cron trigger's door (wrangler.jsonc names the cadence),
 * and it no longer sweeps: it arms the Sweeper's alarm and nothing else. The
 * sweep runs on one timer — the alarm in src/worker/sweeper.ts — and this door
 * is the watchdog over it, for the one failure that timer cannot repair on its
 * own: a run killed mid-flight (a CPU limit, say) sets no next alarm, and
 * without a visitor the chain stays stopped. Arming is idempotent, so a Sweeper
 * whose alarm is already set is read and left alone, with nothing written. It
 * is awaited rather than deferred, because a scheduled invocation has nothing
 * else to wait on.
 */
export default {
  fetch: (
    request: Request,
    env: Env,
    ctx: ExecutionContextLike,
  ): Promise<Response> => {
    ensureSweeper(env, ctx);
    // The platform's own cache, read here and passed in, so the router has no
    // global to reach for and a test can hand it another.
    const shared = (globalThis as { caches?: { default?: CacheLike } }).caches;
    const cache = shared?.default;
    return handleRequest(request, env, {
      ...(cache === undefined ? {} : { cache }),
      waitUntil: (promise: Promise<unknown>) => ctx.waitUntil(promise),
    });
  },
  scheduled: async (
    _controller: ScheduledController,
    env: Env,
    _ctx: ScheduledContext,
  ): Promise<void> => {
    await armSweeper(env);
  },
};
