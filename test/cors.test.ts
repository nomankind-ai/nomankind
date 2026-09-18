/**
 * The read doors answer a browser from any origin (decision D-118).
 *
 * The record is public and CC0 from the seal that covers it, and until this
 * rule a page in a browser could not read a word of it without somebody running
 * a proxy: the same origin rule hid the whole log behind an intermediary nobody
 * asked for. So every GET and HEAD a read door answers carries
 * `access-control-allow-origin: *` and names the headers a reader may look at,
 * and a browser's preflight to one of those doors is answered 204 with the four
 * headers it asked for.
 *
 * The other half of the rule is what does NOT carry it. A write door — the free
 * key door, the submit door — answers a preflight exactly as it always has, 405
 * with `Allow`, and carries no CORS header on any method: a page in a browser
 * may read the whole record and may not write a word of it. No credentials
 * header is sent anywhere, on any door, so there is nothing ambient for a
 * hostile page to spend on a reader's behalf.
 *
 * Driven through the real router on a real migrated D1 with nothing in it,
 * because what is checked is the shape of the answer rather than any record. The
 * clock and the cache are injected, as everywhere else.
 */

import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { CORS_MAX_AGE_SECONDS } from "../src/policy.js";
import type { Env } from "../src/worker/env.js";
import { handleRequest, type CacheLike } from "../src/worker/index.js";
import { openTestDatabase, type TestDatabase } from "./helpers/d1.js";

const NOW = new Date("2026-09-17T00:00:00.000Z");
const ORIGIN = "https://app.nomankind.ai";
/** The page asking. Any origin at all: that is the point of the rule. */
const READER = "https://somebody-elses-page.example";

const ALLOW_ORIGIN = "access-control-allow-origin";
const EXPOSE = "access-control-expose-headers";
const ALLOW_METHODS = "access-control-allow-methods";
const ALLOW_HEADERS = "access-control-allow-headers";
const MAX_AGE = "access-control-max-age";

/** Five read doors, one of every kind the router mounts. */
const READ_DOORS: readonly string[] = [
  "/health",
  "/policy",
  "/status",
  "/events",
  "/keys/tiers",
];

/** The two write doors this rule is defined against. */
const WRITE_DOORS: readonly string[] = ["/entries", "/keys/free"];

let store: TestDatabase;
let env: Env;

beforeAll(async () => {
  store = await openTestDatabase();
  env = {
    DB: store.db,
    CAPTURES: store.captures,
    ENVIRONMENT: "local",
    MAINTAINER_AGENT_ID: "",
  } as unknown as Env;
}, 240_000);

afterAll(async () => {
  await store?.dispose();
});

interface Sent {
  readonly path: string;
  readonly method?: string;
  readonly accept?: string;
  readonly origin?: string | null;
  /** What a preflight says it is asking about. */
  readonly asks?: string;
  readonly headers?: Record<string, string>;
}

function send(what: Sent, cache?: CacheLike): Promise<Response> {
  const headers = new Headers(what.headers);
  headers.set("accept", what.accept ?? "application/json");
  if (what.origin !== null) headers.set("origin", what.origin ?? READER);
  if (what.asks !== undefined) {
    headers.set("access-control-request-method", what.asks);
  }
  return handleRequest(
    new Request(`${ORIGIN}${what.path}`, {
      method: what.method ?? "GET",
      headers,
    }),
    env,
    { now: NOW, ...(cache === undefined ? {} : { cache }) },
  );
}

/** A cache that keeps bytes and headers, the way the platform's does. */
class TestCache implements CacheLike {
  readonly held = new Map<
    string,
    { status: number; headers: [string, string][]; body: string }
  >();

  async put(request: Request, response: Response): Promise<void> {
    this.held.set(request.url, {
      status: response.status,
      headers: [...response.headers.entries()],
      body: await response.text(),
    });
  }

  async match(request: Request): Promise<Response | undefined> {
    const held = this.held.get(request.url);
    if (held === undefined) return undefined;
    return new Response(held.body, {
      status: held.status,
      headers: new Headers(held.headers),
    });
  }
}

describe("a read door answers any origin", () => {
  for (const path of READ_DOORS) {
    it(`carries the header on GET ${path}`, async () => {
      const response = await send({ path });
      expect([path, response.status]).toEqual([path, 200]);
      expect(response.headers.get(ALLOW_ORIGIN)).toBe("*");
      // Never credentials: with `*` the browser sent nothing ambient, and a
      // door that asked for credentials would be asking for what it cannot use.
      expect(response.headers.get("access-control-allow-credentials")).toBeNull();
    }, 60_000);

    it(`names the receipt and rate headers on ${path}`, async () => {
      const exposed = (await send({ path })).headers.get(EXPOSE) ?? "";
      const named = exposed.split(",").map((each) => each.trim());
      expect(named).toEqual([
        "x-nomankind-tier",
        "x-nomankind-limit",
        "x-nomankind-remaining",
        "x-nomankind-archive-hash",
        "retry-after",
      ]);
    }, 60_000);

    it(`carries it on a HEAD of ${path} too`, async () => {
      const response = await send({ path, method: "HEAD" });
      expect(response.body).toBeNull();
      expect(response.headers.get(ALLOW_ORIGIN)).toBe("*");
    }, 60_000);

    it(`answers the preflight to ${path} with 204 and the four headers`, async () => {
      const response = await send({ path, method: "OPTIONS", asks: "GET" });
      expect([path, response.status]).toEqual([path, 204]);
      expect(response.headers.get(ALLOW_ORIGIN)).toBe("*");
      expect(response.headers.get(ALLOW_METHODS)).toBe("GET, HEAD, OPTIONS");
      const allowed = (response.headers.get(ALLOW_HEADERS) ?? "")
        .split(",")
        .map((each) => each.trim());
      expect(allowed).toEqual(["accept", "authorization", "content-type"]);
      // The signed-write headers are not on a read door's list: nothing signed
      // is read cross-origin.
      for (const header of allowed) expect(header).not.toMatch(/^x-nomankind-/);
      expect(response.headers.get(MAX_AGE)).toBe(String(CORS_MAX_AGE_SECONDS));
      expect(response.headers.get("access-control-allow-credentials")).toBeNull();
    }, 60_000);
  }

  it("answers a keyed GET with the header too", async () => {
    // A key is a header a caller sets deliberately rather than an ambient
    // credential, so a browser sends none of it on its own: the answer to a
    // request carrying one is as cross-origin readable as any other. The key
    // below is nobody's, so the door refuses it — and the refusal is what a
    // page has to be able to read.
    const response = await send({
      path: "/keys/me",
      headers: { authorization: "Bearer nmk_live_notakeyatall" },
    });
    expect(response.status).toBeGreaterThanOrEqual(400);
    expect(response.headers.get(ALLOW_ORIGIN)).toBe("*");
  }, 60_000);

  it("carries it on the final not-found, so a reader can read the refusal", async () => {
    const response = await send({ path: "/nothing-here" });
    expect(response.status).toBe(404);
    expect(response.headers.get(ALLOW_ORIGIN)).toBe("*");
  }, 60_000);

  it("leaves a bare OPTIONS the 405 it has always answered", async () => {
    // Not a browser's question: no `Origin`, so nothing is preflighting and the
    // door's own refusal stands, `Allow` and all.
    const response = await send({ path: "/policy", method: "OPTIONS", origin: null });
    expect(response.status).toBe(405);
    expect(response.headers.get("allow")).toBe("GET, HEAD");
    expect(response.headers.get(ALLOW_ORIGIN)).toBeNull();
  }, 60_000);
});

describe("a write door answers nothing to a browser", () => {
  for (const path of WRITE_DOORS) {
    it(`carries no CORS header on POST ${path}`, async () => {
      const response = await send({
        path,
        method: "POST",
        headers: { "content-type": "application/json" },
      });
      expect(response.headers.get(ALLOW_ORIGIN)).toBeNull();
      expect(response.headers.get(EXPOSE)).toBeNull();
    }, 60_000);

    it(`refuses the preflight to ${path} as it always did`, async () => {
      for (const asks of ["POST", "GET"]) {
        const response = await send({ path, method: "OPTIONS", asks });
        expect([path, asks, response.status]).toEqual([path, asks, 405]);
        expect(response.headers.get("allow")).not.toBeNull();
        expect(response.headers.get(ALLOW_ORIGIN)).toBeNull();
        expect(response.headers.get(ALLOW_METHODS)).toBeNull();
        expect(response.headers.get(MAX_AGE)).toBeNull();
      }
    }, 60_000);
  }

  it("says nothing to a GET of the door that only takes a POST", async () => {
    const response = await send({ path: "/keys/free" });
    expect(response.status).toBe(405);
    expect(response.headers.get("allow")).toBe("POST");
    expect(response.headers.get(ALLOW_ORIGIN)).toBeNull();
  }, 60_000);
});

describe("the page cache holds the headers with the page", () => {
  it("serves them on the second read, from the cache", async () => {
    const cache = new TestCache();
    const first = await send({ path: "/docs", accept: "text/html" }, cache);
    expect(first.status).toBe(200);
    expect(first.headers.get(ALLOW_ORIGIN)).toBe("*");
    expect([...cache.held.keys()]).toHaveLength(1);

    // The same page, now out of the cache: the headers are constant, so the
    // stored copy carries them and there is nothing here for a cache to mix.
    const second = await send({ path: "/docs", accept: "text/html" }, cache);
    expect(second.status).toBe(200);
    expect(second.headers.get(ALLOW_ORIGIN)).toBe("*");
    expect(second.headers.get(EXPOSE)).toBe(first.headers.get(EXPOSE));
  }, 60_000);

  it("holds them on a cached JSON door as well", async () => {
    const cache = new TestCache();
    const first = await send({ path: "/policy" }, cache);
    const second = await send({ path: "/policy" }, cache);
    expect(first.headers.get(ALLOW_ORIGIN)).toBe("*");
    expect(second.headers.get(ALLOW_ORIGIN)).toBe("*");
    expect(await second.json()).toEqual(await first.json());
  }, 60_000);
});
