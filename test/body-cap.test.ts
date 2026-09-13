/**
 * The cheap refusals: the body cap, the order the write doors check in, and the
 * one shape an `Authorization` header may take. Through the real Worker on a
 * real miniflare D1.
 *
 * The QA of 2026-09-12: no write door checked the size of a body before it
 * parsed one, and the registry door parsed before it read the auth headers at
 * all — so twelve megabytes of anything, signed by nobody, bought a twelve
 * megabyte read and a parse of it (583 ms live) before the Worker discovered
 * there was no signature to check. Both halves are fixed here and both are
 * pinned: the four signing headers are checked on headers alone, then the body
 * against REQUEST_MAX_BODY_BYTES, and only then is anything parsed.
 *
 * The order, stated once because it is the contract: headers (401
 * missing_header, agent_mismatch, bad_timestamp, clock_skew), then the cap (413
 * body_too_large), then the parse (400 bad_body), then the nonce and the
 * signature (401), then the day's write (429 write_quota), then the door's own
 * refusals. So an unsigned twelve-megabyte body is 401 and not 413: the headers
 * are cheaper to check than the length is, and neither costs a read.
 *
 * The third piece is the same QA's smallest finding and belongs beside them: an
 * `Authorization` header with no scheme, or with somebody else's, was read as a
 * bare secret, which is a second wire format nobody documented and nobody can
 * withdraw. One form is accepted now — `Bearer <key>` — and anything else is
 * `bad_key`.
 *
 * No policy number lives here: the cap is REQUEST_MAX_BODY_BYTES's and the bare
 * integers are HTTP status codes.
 */

import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { MockPayoutAdapter } from "../src/adapters/payout.js";
import { REQUEST_MAX_BODY_BYTES } from "../src/policy.js";
import type { Env } from "../src/worker/env.js";
import { handleRequest, type RequestDeps } from "../src/worker/index.js";
import { openTestDatabase, type TestDatabase } from "./helpers/d1.js";
import {
  FixtureResolver,
  TEST_ORIGIN,
  makeAgent,
  signedHeaders,
  type TestAgent,
} from "./helpers/registry.js";
import { FixtureFetcher, SUBMIT_NOW } from "./helpers/submit.js";

const NOW = SUBMIT_NOW;
const AT = NOW.toISOString();

/** Twelve megabytes, which is what the QA actually sent. */
const HUGE_BYTES = 12 * 1024 * 1024;

/**
 * How long a refusal that reads nothing may take, in milliseconds.
 *
 * Generous on purpose: the point is not to measure the machine, it is that a
 * twelve megabyte body is refused in the time a header comparison takes rather
 * than in the time a twelve megabyte read and parse take (583 ms, measured).
 */
const NO_READ_MS = 50;

let store: TestDatabase;
let env: Env;
let deps: RequestDeps;
let fetcher: FixtureFetcher;
let agent: TestAgent;

beforeAll(async () => {
  store = await openTestDatabase();
  agent = await makeAgent();
  fetcher = new FixtureFetcher({});
  env = {
    DB: store.db,
    CAPTURES: store.captures,
    ENVIRONMENT: "local",
    MAINTAINER_AGENT_ID: (await makeAgent()).agentId,
    SEALING_AGENT_KEY: "",
  };
  deps = {
    now: NOW,
    dns: new FixtureResolver({}),
    payout: new MockPayoutAdapter(),
    fetcher,
  };
});

afterAll(async () => {
  await store.dispose();
});

function send(request: Request): Promise<Response> {
  return handleRequest(request, env, deps);
}

/** A POST with a body of `size` bytes that is not JSON, and no signature. */
function unsigned(path: string, size: number): Request {
  return new Request(`${TEST_ORIGIN}${path}`, {
    method: "POST",
    body: "x".repeat(size),
    headers: { "content-type": "application/json" },
  });
}

/**
 * A POST whose four signing headers are real and whose body is not the body
 * they were signed over.
 *
 * Which is the whole point: the signature can only be checked against the body,
 * so a caller who wants the cap checked rather than the headers has to get past
 * the headers first. The signature here will never be reached.
 */
async function signedOversize(
  path: string,
  size: number,
): Promise<Request> {
  const headers = await signedHeaders(agent, {
    method: "POST",
    path,
    body: {},
    timestamp: AT,
  });
  return new Request(`${TEST_ORIGIN}${path}`, {
    method: "POST",
    body: "x".repeat(size),
    headers: { ...headers, "content-type": "application/json" },
  });
}

/** A POST whose body arrives as a stream, so no Content-Length is declared. */
async function streamed(path: string, size: number): Promise<Request> {
  const headers = await signedHeaders(agent, {
    method: "POST",
    path,
    body: {},
    timestamp: AT,
  });
  const chunk = new TextEncoder().encode("x".repeat(64 * 1024));
  let sent = 0;
  const body = new ReadableStream<Uint8Array>({
    pull(controller) {
      if (sent >= size) {
        controller.close();
        return;
      }
      controller.enqueue(chunk);
      sent += chunk.byteLength;
    },
  });
  return new Request(`${TEST_ORIGIN}${path}`, {
    method: "POST",
    body,
    headers: { ...headers, "content-type": "application/json" },
    // Node's fetch requires this for a stream body; it says the request body is
    // sent before the response is read, which is what a POST does.
    duplex: "half",
  } as RequestInit & { duplex: "half" });
}

describe("the write doors check the signing headers before they read a body", () => {
  it("refuses a 12 MB unsigned POST /entries 401 missing_header, without reading or parsing it", async () => {
    const started = Date.now();
    const response = await send(unsigned("/entries", HUGE_BYTES));
    const elapsed = Date.now() - started;

    // missing_header and not bad_body: the body is twelve megabytes of `x`,
    // which is not JSON, so a 400 here would be proof that it was parsed.
    expect(response.status).toBe(401);
    expect(await response.json()).toEqual({ error: "missing_header" });
    expect(elapsed).toBeLessThan(NO_READ_MS);
    expect(fetcher.requests).toEqual([]);
  });

  it("refuses the same body at every other signed write door the same way", async () => {
    for (const path of [
      "/operators",
      "/entries/nmk_00000000000000000000000000000000/validate",
      "/entries/nmk_00000000000000000000000000000000/reconfirm",
      "/entries/nmk_00000000000000000000000000000000/dispute",
      "/entries/nmk_00000000000000000000000000000000/revalidate",
      "/entries/nmk_00000000000000000000000000000000/failure-reports",
      "/attestations",
    ]) {
      const response = await send(unsigned(path, HUGE_BYTES));
      expect({ path, status: response.status }).toEqual({ path, status: 401 });
      expect(await response.json()).toEqual({ error: "missing_header" });
    }
  });
});

describe("the body cap", () => {
  it("refuses a Content-Length above the cap with 413 body_too_large, before any read", async () => {
    const started = Date.now();
    const response = await send(await signedOversize("/entries", HUGE_BYTES));
    const elapsed = Date.now() - started;

    expect(response.status).toBe(413);
    expect(await response.json()).toEqual({ error: "body_too_large" });
    expect(elapsed).toBeLessThan(NO_READ_MS);
    expect(fetcher.requests).toEqual([]);
  });

  it("refuses a body that declares no length the same way, stopping at the cap", async () => {
    const response = await send(
      await streamed("/entries", REQUEST_MAX_BODY_BYTES * 4),
    );

    expect(response.status).toBe(413);
    expect(await response.json()).toEqual({ error: "body_too_large" });
    expect(fetcher.requests).toEqual([]);
  });

  it("lets a body under the cap through to the parse", async () => {
    // Under the cap and still not JSON: the answer is the parse's, which is how
    // this says the cap let it past rather than that nothing was read.
    const response = await send(
      await signedOversize("/entries", REQUEST_MAX_BODY_BYTES - 1024),
    );

    expect(response.status).toBe(400);
    expect(await response.json()).toEqual({ error: "bad_body" });
  });
});

describe("the header checks are the verifier's own, in the verifier's order", () => {
  it("answers agent_mismatch for an agent header that is not an agent id", async () => {
    const headers = await signedHeaders(agent, {
      method: "POST",
      path: "/entries",
      body: {},
      timestamp: AT,
    });
    const response = await send(
      new Request(`${TEST_ORIGIN}/entries`, {
        method: "POST",
        body: "{}",
        headers: { ...headers, "x-nomankind-agent": "not-an-agent-id" },
      }),
    );

    expect(response.status).toBe(401);
    expect(await response.json()).toEqual({ error: "agent_mismatch" });
  });

  it("answers bad_timestamp for a timestamp that is not one", async () => {
    const headers = await signedHeaders(agent, {
      method: "POST",
      path: "/entries",
      body: {},
      timestamp: AT,
    });
    const response = await send(
      new Request(`${TEST_ORIGIN}/entries`, {
        method: "POST",
        body: "{}",
        headers: { ...headers, "x-nomankind-timestamp": "yesterday" },
      }),
    );

    expect(response.status).toBe(401);
    expect(await response.json()).toEqual({ error: "bad_timestamp" });
  });

  it("answers clock_skew for a timestamp outside the window, before the body", async () => {
    const far = new Date(NOW.getTime() + 86_400_000).toISOString();
    const headers = await signedHeaders(agent, {
      method: "POST",
      path: "/entries",
      body: {},
      timestamp: far,
    });
    const response = await send(
      new Request(`${TEST_ORIGIN}/entries`, {
        method: "POST",
        // Oversized: a 413 here would mean the cap was checked first.
        body: "x".repeat(HUGE_BYTES),
        headers,
      }),
    );

    expect(response.status).toBe(401);
    expect(await response.json()).toEqual({ error: "clock_skew" });
  });
});

describe("the Authorization header is `Bearer <key>` and nothing else", () => {
  /** One read, carrying whatever the case says it carries. */
  function read(headers: Record<string, string>): Request {
    return new Request(
      `${TEST_ORIGIN}/entries/nmk_00000000000000000000000000000000`,
      { headers },
    );
  }

  it("refuses a bare token, whatever it is shaped like", async () => {
    // A well-formed secret with no scheme in front of it used to authenticate,
    // which is what made the second format real. `nmk_x` is not well formed and
    // was already refused; the 43-character one is the case that changed.
    for (const value of ["nmk_x", `nmk_${"A".repeat(43)}`]) {
      const response = await send(read({ authorization: value }));
      expect([value, response.status]).toEqual([value, 401]);
      expect(await response.json()).toEqual({ error: "bad_key" });
    }
  });

  it("refuses another scheme's credential rather than reading it as a key", async () => {
    for (const value of [
      `Basic nmk_${"A".repeat(43)}`,
      `Token nmk_${"A".repeat(43)}`,
    ]) {
      const response = await send(read({ authorization: value }));
      expect([value, response.status]).toEqual([value, 401]);
      expect(await response.json()).toEqual({ error: "bad_key" });
    }
  });

  it("takes the one form, case-insensitively in the scheme", async () => {
    // Past the shape check and into the lookup, which is what says the header
    // was accepted: nobody holds this key, so the answer is unknown_key.
    for (const scheme of ["Bearer", "bearer", "BEARER"]) {
      const response = await send(
        read({ authorization: `${scheme} nmk_${"A".repeat(43)}` }),
      );
      expect([scheme, response.status]).toEqual([scheme, 401]);
      expect(await response.json()).toEqual({ error: "unknown_key" });
    }
  });

  it("refuses a bare token at the account doors too", async () => {
    const missing = await send(new Request(`${TEST_ORIGIN}/keys/me`));
    expect(missing.status).toBe(401);
    expect(await missing.json()).toEqual({ error: "missing_key" });

    const bare = await send(
      new Request(`${TEST_ORIGIN}/keys/me`, {
        headers: { authorization: `nmk_${"A".repeat(43)}` },
      }),
    );
    expect(bare.status).toBe(401);
    expect(await bare.json()).toEqual({ error: "bad_key" });
  });
});
