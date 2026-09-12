/**
 * HEAD everywhere, and one refusal for a wrong method (the QA of 2026-09-12).
 *
 * Two things the QA measured on the live demo are held here. Every JSON door
 * answered 405 to a HEAD, which is wrong twice over: a HEAD is a GET without the
 * body, it is how a client asks what a read would cost and whether anything has
 * changed without paying for the bytes, and a door that refuses it says nothing
 * is there. And a wrong method on a path a page and an endpoint share fell
 * through the whole router to the final not-found, so the same mistake was
 * answered 404 `{"ok":false,"error":"not_found"}` on one path and 405
 * `{"error":"method_not_allowed"}` on the next.
 *
 * A real migrated D1 with nothing in it, because what is checked is the router's
 * shape rather than any record: a door that answers 404 to the GET answers 404
 * to the HEAD, and that parity is the whole rule. The clock is injected, as
 * everywhere else.
 */

import { afterAll, beforeAll, describe, expect, it } from "vitest";

import type { Env } from "../src/worker/env.js";
import { handleRequest } from "../src/worker/index.js";
import { openTestDatabase, type TestDatabase } from "./helpers/d1.js";

const NOW = new Date("2026-09-12T00:00:00.000Z");
const ORIGIN = "https://app.nomankind.ai";

/** A well-formed id the empty log does not hold, and a well-formed hash. */
const ENTRY_ID = "nmk_00112233445566778899aabbccddeeff";
const HASH = "1".repeat(64);

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

function send(
  path: string,
  method: string,
  accept = "application/json",
): Promise<Response> {
  return handleRequest(
    new Request(`${ORIGIN}${path}`, { method, headers: { accept } }),
    env,
    { now: NOW },
  );
}

/** Every JSON door that answers a read, in the order the router mounts them. */
const READ_DOORS: readonly string[] = [
  "/health",
  "/policy",
  "/operators",
  `/operators/${ENTRY_ID}`,
  `/agents/${ENTRY_ID}`,
  `/entries/${ENTRY_ID}`,
  `/captures/${HASH}`,
  "/read?entry_id=" + ENTRY_ID,
  "/sync?from=0",
  "/events",
  "/seals",
  "/seals/0",
  "/events/0/proof",
  "/anchors",
  "/anchors/2026-09-12",
  "/standing",
  "/ledger",
  "/status",
  "/mirror/latest",
  "/keys/tiers",
  "/keys/me",
  "/attestations",
  `/attestations/${ENTRY_ID}`,
  `/operators/${ENTRY_ID}/attestations`,
  `/entries/${ENTRY_ID}/confidence-inputs`,
];

describe("a HEAD is the GET without the body", () => {
  for (const path of READ_DOORS) {
    it(`answers HEAD ${path} exactly as it answers the GET`, async () => {
      const get = await send(path, "GET");
      const head = await send(path, "HEAD");

      expect(head.status).toBe(get.status);
      expect(head.body).toBeNull();
      for (const header of ["content-type", "cache-control", "vary", "allow"]) {
        expect([header, head.headers.get(header)]).toEqual([
          header,
          get.headers.get(header),
        ]);
      }
      // Never the refusal the QA measured on every one of these.
      expect(head.status).not.toBe(405);
    }, 60_000);
  }

  it("names both methods when it refuses one", async () => {
    for (const [path, allow] of [
      ["/events", "GET, HEAD"],
      ["/seals", "GET, HEAD"],
      ["/status", "GET, HEAD"],
      ["/mirror/latest", "GET, HEAD"],
      ["/standing", "GET, HEAD"],
      ["/ledger", "GET, HEAD"],
      ["/keys/tiers", "GET, HEAD"],
      ["/sync", "GET, HEAD"],
      ["/read", "GET, HEAD"],
      // The two doors that take a write as well as a read.
      ["/operators", "GET, HEAD, POST"],
      ["/attestations", "GET, HEAD, POST"],
    ] as const) {
      const response = await send(path, "PUT");
      expect([path, response.status, response.headers.get("allow")]).toEqual([
        path,
        405,
        allow,
      ]);
      expect(await response.json()).toEqual({ error: "method_not_allowed" });
    }
  }, 60_000);
});

/**
 * Every path a page and an endpoint share, and the methods neither of them
 * takes. POST is left off the three paths that have a write door of their own —
 * a submission, a registration and a genesis naming are not wrong methods.
 */
const SHARED_PATHS: readonly { path: string; methods: readonly string[] }[] = [
  { path: "/", methods: ["POST", "PUT", "PATCH", "DELETE", "OPTIONS"] },
  { path: "/landing", methods: ["POST", "PUT", "PATCH", "DELETE", "OPTIONS"] },
  { path: "/policy", methods: ["POST", "PUT", "PATCH", "DELETE", "OPTIONS"] },
  { path: "/api", methods: ["POST", "PUT", "PATCH", "DELETE", "OPTIONS"] },
  { path: "/docs", methods: ["POST", "PUT", "PATCH", "DELETE", "OPTIONS"] },
  { path: "/docs/fork", methods: ["POST", "PUT", "DELETE", "OPTIONS"] },
  { path: "/docs/whitepaper", methods: ["POST", "PUT", "DELETE", "OPTIONS"] },
  { path: "/docs/summary", methods: ["POST", "PUT", "DELETE", "OPTIONS"] },
  { path: "/dry-run", methods: ["POST", "PUT", "PATCH", "DELETE", "OPTIONS"] },
  {
    path: "/how-it-works",
    methods: ["POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
  },
  { path: "/domains", methods: ["POST", "PUT", "PATCH", "DELETE", "OPTIONS"] },
  { path: "/status", methods: ["POST", "PUT", "PATCH", "DELETE", "OPTIONS"] },
  {
    path: "/mirror/latest",
    methods: ["POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
  },
  { path: "/entries", methods: ["PUT", "PATCH", "DELETE", "OPTIONS"] },
  { path: `/entries/${ENTRY_ID}`, methods: ["POST", "PUT", "DELETE", "OPTIONS"] },
  { path: "/operators", methods: ["PUT", "PATCH", "DELETE", "OPTIONS"] },
  {
    path: `/operators/${ENTRY_ID}`,
    methods: ["POST", "PUT", "DELETE", "OPTIONS"],
  },
  { path: "/genesis", methods: ["PUT", "PATCH", "DELETE", "OPTIONS"] },
];

describe("one refusal for a wrong method", () => {
  for (const { path, methods } of SHARED_PATHS) {
    for (const method of methods) {
      it(`refuses ${method} ${path} with 405 and the handlers' envelope`, async () => {
        for (const accept of ["text/html", "application/json"]) {
          const response = await send(path, method, accept);
          expect([path, method, accept, response.status]).toEqual([
            path,
            method,
            accept,
            405,
          ]);
          expect(response.headers.get("allow")).not.toBeNull();
          expect(response.headers.get("content-type")).toBe("application/json");
          expect(await response.json()).toEqual({
            error: "method_not_allowed",
          });
        }
      }, 60_000);
    }
  }

  it("keeps the final not-found for a path nothing answers", async () => {
    const missing = await send("/nothing-here", "PUT");
    expect(missing.status).toBe(404);
    expect(await missing.json()).toEqual({ ok: false, error: "not_found" });
  }, 60_000);
});

describe("vary: Accept on the paths that answer both", () => {
  const NEGOTIATED: readonly string[] = [
    "/policy",
    "/operators",
    `/operators/${ENTRY_ID}`,
    `/entries/${ENTRY_ID}`,
    "/status",
    "/mirror/latest",
  ];

  for (const path of NEGOTIATED) {
    it(`sets it on both variants of ${path}`, async () => {
      for (const accept of ["text/html", "application/json"]) {
        const response = await send(path, "GET", accept);
        expect([path, accept, response.headers.get("vary")]).toEqual([
          path,
          accept,
          "Accept",
        ]);
      }
      // And on the refusal, which is the same path answering.
      const refused = await send(path, "PUT");
      expect(refused.headers.get("vary")).toBe("Accept");
    }, 60_000);
  }
});
