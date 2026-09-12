/**
 * The page cache (the QA of 2026-09-12).
 *
 * Measured on the live demo: every storage-backed page's latency doubled when
 * concurrency doubled, because every reader's page was rendered from D1 again.
 * Cloudflare does not cache a Worker's own responses on a `cache-control`
 * header alone — the header tells the browser and nothing else — so the router
 * puts the anonymous pages through the Cache API itself, and that is what these
 * tests hold: a second reader inside the lifetime costs the log nothing, a
 * reader after it costs what the first one did, and nothing that depends on who
 * is asking is ever stored or served.
 *
 * The cache is injected rather than reached for as a global, exactly as the
 * clock and the adapters are (decision D-013): wrangler's `getPlatformProxy`
 * hands back a no-op `caches`, so a test that wanted the platform's own would be
 * testing nothing. The one below is a cache written the way the platform's
 * behaves — it stores bytes and headers, it keys on the request URL, and it
 * treats an entry older than its own `max-age` as a miss — and it is driven by
 * the same fake clock everything else in this system is.
 */

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

import { PAGE_CACHE_SECONDS, PAGE_CACHE_STALE_SECONDS } from "../src/policy.js";
import { CONTENT_SECURITY_POLICY } from "../src/ui/html.js";
import type { D1Like, D1LikeStatement } from "../src/storage/d1.js";
import type { Env } from "../src/worker/env.js";
import {
  cacheablePath,
  handleRequest,
  type CacheLike,
} from "../src/worker/index.js";

/** What a cached page must say about itself, from the policy module's numbers. */
const EXPECTED_CACHE_CONTROL =
  `public, max-age=${PAGE_CACHE_SECONDS}, ` +
  `stale-while-revalidate=${PAGE_CACHE_STALE_SECONDS}`;

const NOW = new Date("2026-09-12T00:00:00.000Z");

/** How many of everything the stub database says there are. */
const COUNTED = 5;

/**
 * A database that answers every count with the same number and counts how many
 * statements were prepared against it. The number is the point: a page served
 * from the cache prepares none.
 */
function countingDatabase(): { db: D1Like; statements: () => number } {
  let prepared = 0;
  const statement = {
    bind: () => statement,
    first: () => Promise.resolve({ n: COUNTED }),
    all: () => Promise.resolve({ results: [], success: true }),
    run: () => Promise.resolve({ results: [], success: true }),
  } as unknown as D1LikeStatement;
  const db: D1Like = {
    prepare: () => {
      prepared += 1;
      return statement;
    },
    batch: () => Promise.resolve([]),
    exec: () => Promise.resolve({ count: 0, duration: 0 }),
  };
  return { db, statements: () => prepared };
}

function envWith(db: D1Like): Env {
  return {
    DB: db,
    CAPTURES: {},
    ENVIRONMENT: "local",
    MAINTAINER_AGENT_ID: "",
  } as unknown as Env;
}

/** One entry of the cache: the bytes, the headers, and when it was written. */
interface Held {
  readonly status: number;
  readonly headers: [string, string][];
  readonly body: string;
  readonly storedAt: number;
}

/**
 * A cache the way the platform's behaves, on a clock a test can move.
 *
 * `put` reads the response to bytes, which is what a real cache does and why the
 * router hands it a clone; `match` builds a fresh response from them, so a hit
 * is servable however many times it is read. An entry whose own `max-age` has
 * passed is a miss and is dropped, which is the only way the lifetime is
 * checked: nothing in the router reads the clock for it.
 */
class TestCache implements CacheLike {
  readonly held = new Map<string, Held>();
  now = NOW.getTime();

  async put(request: Request, response: Response): Promise<void> {
    this.held.set(request.url, {
      status: response.status,
      headers: [...response.headers.entries()],
      body: await response.text(),
      storedAt: this.now,
    });
  }

  async match(request: Request): Promise<Response | undefined> {
    const held = this.held.get(request.url);
    if (held === undefined) return undefined;
    const headers = new Headers(held.headers);
    const control = headers.get("cache-control") ?? "";
    const maxAge = /max-age=(\d+)/.exec(control);
    const lifetime = maxAge === null ? 0 : Number(maxAge[1]) * 1000;
    if (this.now - held.storedAt >= lifetime) {
      this.held.delete(request.url);
      return undefined;
    }
    return new Response(held.body, { status: held.status, headers });
  }

  /** The one key the cache holds, for the tests that assert on its shape. */
  keys(): string[] {
    return [...this.held.keys()];
  }
}

interface Sent {
  readonly path: string;
  readonly method?: string;
  readonly accept?: string;
  readonly headers?: Record<string, string>;
}

const ORIGIN = "https://app.nomankind.ai";

function send(
  what: Sent,
  env: Env,
  cache: CacheLike | undefined,
): Promise<Response> {
  const headers = new Headers(what.headers);
  headers.set("accept", what.accept ?? "text/html");
  return handleRequest(
    new Request(`${ORIGIN}${what.path}`, {
      method: what.method ?? "GET",
      headers,
    }),
    env,
    { now: NOW, ...(cache === undefined ? {} : { cache }) },
  );
}

describe("the page cache", () => {
  it("renders once and serves the second reader from the cache", async () => {
    const { db, statements } = countingDatabase();
    const env = envWith(db);
    const cache = new TestCache();

    const first = await send({ path: "/domains" }, env, cache);
    expect(first.status).toBe(200);
    const rendered = statements();
    expect(rendered).toBeGreaterThan(0);
    const page = await first.text();

    const second = await send({ path: "/domains" }, env, cache);
    expect(second.status).toBe(200);
    // The point of the whole exercise: the log was not read again.
    expect(statements()).toBe(rendered);
    expect(await second.text()).toBe(page);
  });

  it("says how long it may be held, in the policy module's own numbers", async () => {
    const { db } = countingDatabase();
    const cache = new TestCache();
    const response = await send({ path: "/domains" }, envWith(db), cache);
    expect(response.headers.get("cache-control")).toBe(EXPECTED_CACHE_CONTROL);
    const hit = await send({ path: "/domains" }, envWith(db), cache);
    expect(hit.headers.get("cache-control")).toBe(EXPECTED_CACHE_CONTROL);
  });

  it("keeps every other header a page carries", async () => {
    const { db } = countingDatabase();
    const cache = new TestCache();
    await send({ path: "/domains" }, envWith(db), cache);
    const hit = await send({ path: "/domains" }, envWith(db), cache);

    expect(hit.headers.get("content-type")).toBe("text/html; charset=utf-8");
    expect(hit.headers.get("content-security-policy")).toBe(
      CONTENT_SECURITY_POLICY,
    );
    expect(hit.headers.get("x-content-type-options")).toBe("nosniff");
    expect(hit.headers.get("referrer-policy")).toBe("no-referrer");
    expect(hit.headers.get("vary")).toBe("Accept");
  });

  it("renders again once the lifetime has passed", async () => {
    const { db, statements } = countingDatabase();
    const env = envWith(db);
    const cache = new TestCache();

    await send({ path: "/domains" }, env, cache);
    const rendered = statements();

    cache.now += (PAGE_CACHE_SECONDS - 1) * 1000;
    await send({ path: "/domains" }, env, cache);
    expect(statements()).toBe(rendered);

    cache.now += 2 * 1000;
    const stale = await send({ path: "/domains" }, env, cache);
    expect(stale.status).toBe(200);
    expect(statements()).toBeGreaterThan(rendered);
  });

  it("keys the host, the path and the query apart", async () => {
    const { db, statements } = countingDatabase();
    const env = envWith(db);
    const cache = new TestCache();

    await send({ path: "/domains" }, env, cache);
    const first = statements();
    await send({ path: "/domains?anchor=ai-safety" }, env, cache);
    expect(statements()).toBeGreaterThan(first);
    expect(cache.keys()).toHaveLength(2);

    const other = new Request("https://demo.nomankind.ai/domains", {
      headers: { accept: "text/html" },
    });
    await handleRequest(other, env, { now: NOW, cache });
    expect(cache.keys()).toHaveLength(3);
    for (const key of cache.keys()) expect(key).toContain("__nmk_variant=html");
  });

  it("never lets the JSON twin of a shared path collide with the page", async () => {
    const { db } = countingDatabase();
    const env = envWith(db);
    const cache = new TestCache();

    const page = await send({ path: "/policy" }, env, cache);
    expect(page.headers.get("content-type")).toBe("text/html; charset=utf-8");

    const object = await send(
      { path: "/policy", accept: "application/json" },
      env,
      cache,
    );
    expect(object.headers.get("content-type")).toBe("application/json");
    expect(object.headers.get("cache-control")).toBe(EXPECTED_CACHE_CONTROL);
    // The one JSON door that is cached, and it negotiates, so it says so.
    expect(object.headers.get("vary")).toBe("Accept");
    expect(cache.keys()).toHaveLength(2);

    const again = await send({ path: "/policy" }, env, cache);
    expect(again.headers.get("content-type")).toBe("text/html; charset=utf-8");
    const objectAgain = await send(
      { path: "/policy", accept: "application/json" },
      env,
      cache,
    );
    expect(objectAgain.headers.get("content-type")).toBe("application/json");
    expect((await objectAgain.json()) as Record<string, unknown>).toHaveProperty(
      "SCHEMA_VERSION",
    );
  });

  it("never caches a JSON door that is not /policy", async () => {
    const { db, statements } = countingDatabase();
    const env = envWith(db);
    const cache = new TestCache();

    const first = await send(
      { path: "/health", accept: "application/json" },
      env,
      cache,
    );
    expect(first.headers.get("cache-control")).toBe("no-store");
    const asked = statements();
    const second = await send(
      { path: "/health", accept: "application/json" },
      env,
      cache,
    );
    expect(second.status).toBe(200);
    // The probe ran again: nothing about a door's answer is held anywhere.
    expect(statements()).toBeGreaterThan(asked);
    expect(cache.keys()).toHaveLength(0);
  });

  it("never serves or stores a request that carries a key", async () => {
    const { db, statements } = countingDatabase();
    const env = envWith(db);
    const cache = new TestCache();

    await send({ path: "/domains" }, env, cache);
    const anonymous = statements();
    expect(cache.keys()).toHaveLength(1);

    const keyed = await send(
      { path: "/domains", headers: { authorization: "Bearer nmk_key_x" } },
      env,
      cache,
    );
    expect(keyed.status).toBe(200);
    // Rendered for this reader, and never from the copy the last one left.
    expect(statements()).toBeGreaterThan(anonymous);
    expect(keyed.headers.get("cache-control")).toBe("no-store");
    expect(cache.keys()).toHaveLength(1);
  });

  it("never serves or stores a request that carries an agent signature", async () => {
    const { db, statements } = countingDatabase();
    const env = envWith(db);
    const cache = new TestCache();

    await send({ path: "/domains" }, env, cache);
    const anonymous = statements();

    const signed = await send(
      { path: "/domains", headers: { "x-nomankind-agent": "nmk_agent_x" } },
      env,
      cache,
    );
    expect(signed.status).toBe(200);
    expect(statements()).toBeGreaterThan(anonymous);
    expect(cache.keys()).toHaveLength(1);
  });

  it("answers a HEAD from the same path and stores nothing", async () => {
    const { db, statements } = countingDatabase();
    const env = envWith(db);
    const cache = new TestCache();

    const head = await send({ path: "/domains", method: "HEAD" }, env, cache);
    expect(head.status).toBe(200);
    expect(head.body).toBeNull();
    expect(head.headers.get("content-type")).toBe("text/html; charset=utf-8");
    expect(statements()).toBeGreaterThan(0);
    expect(cache.keys()).toHaveLength(0);
  });

  it("stores nothing that is not a 200", async () => {
    const { db } = countingDatabase();
    const env = envWith(db);
    const cache = new TestCache();

    const missing = await send({ path: "/entries/nmk_nonsense" }, env, cache);
    expect(missing.status).toBe(404);
    expect(cache.keys()).toHaveLength(0);

    const bad = await send({ path: "/domains", method: "PUT" }, env, cache);
    expect(bad.status).toBe(405);
    expect(cache.keys()).toHaveLength(0);
  });

  it("leaves the stylesheets' own hour alone", async () => {
    const { db } = countingDatabase();
    const cache = new TestCache();
    const sheet = await send({ path: "/static/app.css" }, envWith(db), cache);
    expect(sheet.headers.get("cache-control")).toBe("public, max-age=3600");
    expect(cache.keys()).toHaveLength(0);
  });

  it("renders every page as before when no cache was handed to the router", async () => {
    const { db, statements } = countingDatabase();
    const env = envWith(db);

    const first = await send({ path: "/domains" }, env, undefined);
    expect(first.headers.get("cache-control")).toBe("no-store");
    const rendered = statements();
    await send({ path: "/domains" }, env, undefined);
    expect(statements()).toBeGreaterThan(rendered);
  });

  it("defers the write when the platform gave it somewhere to defer to", async () => {
    const { db } = countingDatabase();
    const env = envWith(db);
    const cache = new TestCache();
    const deferred: Promise<unknown>[] = [];

    const response = await handleRequest(
      new Request(`${ORIGIN}/domains`, { headers: { accept: "text/html" } }),
      env,
      { now: NOW, cache, waitUntil: (promise) => deferred.push(promise) },
    );
    expect(response.status).toBe(200);
    expect(deferred).toHaveLength(1);
    await Promise.all(deferred);
    expect(cache.keys()).toHaveLength(1);
  });
});

// ---------------------------------------------------------------------------
// The cache's failure modes, its coverage, and its key
// ---------------------------------------------------------------------------

/**
 * A cache that is broken rather than absent.
 *
 * The Cache API is a service and a service can fail. What must not happen is
 * what an unguarded `match` or `put` would do: turn every page of the site into
 * a 500 because an optimisation was unavailable.
 */
class BrokenCache implements CacheLike {
  constructor(private readonly where: "match" | "put" | "both") {}

  match(_request: Request): Promise<Response | undefined> {
    if (this.where === "put") return Promise.resolve(undefined);
    return Promise.reject(new Error("cache unavailable"));
  }

  put(_request: Request, _response: Response): Promise<void> {
    if (this.where === "match") return Promise.resolve();
    return Promise.reject(new Error("cache unavailable"));
  }
}

describe("a cache that throws", () => {
  for (const where of ["match", "put", "both"] as const) {
    it(`degrades to an uncached render when ${where} fails`, async () => {
      const { db, statements } = countingDatabase();
      const env = envWith(db);
      const cache = new BrokenCache(where);

      const first = await send({ path: "/domains" }, env, cache);
      expect(first.status).toBe(200);
      expect(await first.text()).toContain("<h1>Domains</h1>");

      // And again: a failure is never a state the router is left in.
      const rendered = statements();
      const second = await send({ path: "/domains" }, env, cache);
      expect(second.status).toBe(200);
      expect(statements()).toBeGreaterThan(rendered);
    });
  }

  it("still defers a failing write without failing the response", async () => {
    const { db } = countingDatabase();
    const deferred: Promise<unknown>[] = [];
    const response = await handleRequest(
      new Request(`${ORIGIN}/domains`, { headers: { accept: "text/html" } }),
      envWith(db),
      {
        now: NOW,
        cache: new BrokenCache("put"),
        waitUntil: (promise) => deferred.push(promise),
      },
    );
    expect(response.status).toBe(200);
    // The write is swallowed where it happens, so the deferred promise the
    // platform is handed never rejects and never kills the invocation.
    await expect(Promise.all(deferred)).resolves.toBeDefined();
  });
});

/**
 * Every path the browsing route serves, read out of the route itself.
 *
 * A page added to src/worker/pages.ts and forgotten here would go on costing the
 * log a read per reader, and nothing would say so. So the list is not written
 * out by hand: it is the path literals the route matches on, and each one has to
 * be either cacheable or named below with a reason it is not.
 */
const NOT_CACHED: Readonly<Record<string, string>> = Object.freeze({
  "/static/app.css":
    "a stylesheet, already public for an hour with its own version in the href",
  "/static/landing.css":
    "the landing stylesheet, cached the same way for the same reason",
});

describe("every page the route serves", () => {
  const source = readFileSync(
    fileURLToPath(new URL("../src/worker/pages.ts", import.meta.url)),
    "utf8",
  );

  it("is either cached or excluded with a reason", () => {
    const literals = [
      ...source.matchAll(/(?:path|url\.pathname) === "([^"]+)"/g),
    ].map((match) => match[1]!);
    // The route matches on more than a dozen paths; a regex that found two
    // would pass this file while checking nothing.
    expect(literals.length).toBeGreaterThan(12);

    for (const path of literals) {
      const excluded = Object.prototype.hasOwnProperty.call(NOT_CACHED, path);
      expect([path, cacheablePath(path) || excluded]).toEqual([path, true]);
      // And never both: a path with a reason not to be cached that is cached
      // anyway is a reason nobody is applying.
      if (excluded) expect([path, cacheablePath(path)]).toEqual([path, false]);
    }
  });

  it("covers the paths the route matches by prefix too", () => {
    const prefixes = [
      ...source.matchAll(/segmentAfter\(path, "([^"]+)"\)/g),
    ].map((match) => match[1]!);
    expect(prefixes.length).toBeGreaterThan(0);
    for (const prefix of prefixes) {
      expect([prefix, cacheablePath(`${prefix}x`)]).toEqual([prefix, true]);
    }
  });

  it("leaves the JSON doors out of it", () => {
    for (const path of [
      "/health",
      "/events",
      "/seals",
      "/read",
      "/sync",
      "/standing",
      "/ledger",
      "/keys/tiers",
      "/keys/me",
      "/attestations",
      "/captures/abc",
    ]) {
      expect([path, cacheablePath(path)]).toEqual([path, false]);
    }
  });
});

describe("the variant marker is the router's and not the caller's", () => {
  it("never lets a supplied marker alias the other variant's entry", async () => {
    const { db } = countingDatabase();
    const env = envWith(db);
    const cache = new TestCache();

    // The page, stored under the marker the router writes.
    const page = await send({ path: "/policy" }, env, cache);
    expect(page.headers.get("content-type")).toBe("text/html; charset=utf-8");

    // The same path asked for as JSON, with the marker forged in the query. It
    // must be answered as JSON and keyed apart, not handed the page.
    const forged = await send(
      { path: "/policy?__nmk_variant=html", accept: "application/json" },
      env,
      cache,
    );
    expect(forged.headers.get("content-type")).toBe("application/json");
    expect((await forged.json()) as Record<string, unknown>).toHaveProperty(
      "SCHEMA_VERSION",
    );

    for (const key of cache.keys()) {
      // The marker appears once and says what the router decided.
      expect(key.match(/__nmk_variant=/g)).toHaveLength(1);
    }
    expect(
      cache.keys().filter((key) => key.endsWith("__nmk_variant=json")),
    ).toHaveLength(1);
  });

  it("does not let a supplied marker be served to the next reader", async () => {
    const { db } = countingDatabase();
    const env = envWith(db);
    const cache = new TestCache();

    // A reader who followed a link with the marker in it.
    await send(
      { path: "/policy?__nmk_variant=json", accept: "text/html" },
      env,
      cache,
    );
    // The reader who did not: still the page, never the object.
    const honest = await send(
      { path: "/policy", accept: "application/json" },
      env,
      cache,
    );
    expect(honest.headers.get("content-type")).toBe("application/json");
  });
});
