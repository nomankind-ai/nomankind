/**
 * The key doors end to end, under decision D-127: a key is free.
 *
 * "The record is free, no money anywhere." Nothing is bought, so the checkout,
 * the claim, the portal and the provider's webhook are gone, addresses and all,
 * and answer the 404 any unknown path answers without touching storage on the
 * way; what replaces them is one door, `POST /keys/free`, which
 * hands a client one key per UTC day. A key is still an identity the log counts
 * under, so the three things a holder could always do — see the key, see what it
 * read day by day, and page its own receipts by counter — go on working exactly
 * as they did.
 *
 * This drives the real router: miniflare's D1 with the real migrations applied,
 * the real key doors, the clock injected, and no payment provider constructed
 * anywhere, because there is nothing left to construct one for.
 *
 * The three things it holds hardest. A key is handed over exactly once and
 * stored as a hash, so a secret appears in exactly one response body, ever. One
 * client gets one key a day and the second ask is 429, which is the whole of
 * what stands between a free identity and an identity factory. And a removed
 * door is a removed door: 404, and not one read of the database on the way.
 */

import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { keyHash } from "../src/keys.js";
import { RATE_TIERS } from "../src/policy.js";
import { keyByHash } from "../src/storage/keys.js";
import type { Env } from "../src/worker/env.js";
import { resolveAccess } from "../src/worker/access.js";
import { handleRequest, type RequestDeps } from "../src/worker/index.js";
import { openTestDatabase, type TestDatabase } from "./helpers/d1.js";

const ORIGIN = "https://nomankind.ai";
const NOW = new Date("2026-09-11T12:00:00.000Z");
const UNIX = Math.floor(NOW.getTime() / 1000);
const DAY = "2026-09-11";

/**
 * Two client addresses, because "one key per client per day" is a claim with two
 * sides: the same address twice is refused, and a different address is not.
 * The Worker hashes these before they reach any row (src/keys.ts); nothing here
 * or in the table is the address itself.
 */
const CLIENT = "203.0.113.7";
const OTHER_CLIENT = "203.0.113.8";

let store: TestDatabase;
let env: Env;
let deps: RequestDeps;

beforeAll(async () => {
  store = await openTestDatabase();
  env = {
    DB: store.db,
    CAPTURES: store.captures,
    ENVIRONMENT: "local",
    MAINTAINER_AGENT_ID: "",
  };
  deps = { now: NOW };
}, 600_000);

afterAll(async () => {
  await store?.dispose();
}, 600_000);

function send(
  request: Request,
  override?: Partial<RequestDeps>,
): Promise<Response> {
  return handleRequest(request, env, { ...deps, ...override });
}

function get(path: string, headers: Record<string, string> = {}): Request {
  return new Request(`${ORIGIN}${path}`, { headers });
}

/**
 * The same database, with every statement it is asked to prepare counted.
 *
 * A removed door must cost the log nothing at all: not a row, and not a read
 * either. Counting rows written would pass a route that read `api_keys` and
 * then answered 404, so what is counted is what reaches D1 in the first place.
 */
function counting(db: TestDatabase["db"]): {
  db: TestDatabase["db"];
  statements: () => number;
} {
  let seen = 0;
  return {
    db: {
      prepare(sql: string) {
        seen += 1;
        return db.prepare(sql);
      },
      batch: (statements) => db.batch(statements),
      exec: (sql: string) => db.exec(sql),
    },
    statements: () => seen,
  };
}

/** The header the platform names a client with, which is what a day is counted on. */
function from(ip: string): Record<string, string> {
  return { "cf-connecting-ip": ip };
}

function post(
  path: string,
  body: unknown,
  headers: Record<string, string> = {},
): Request {
  return new Request(`${ORIGIN}${path}`, {
    method: "POST",
    headers: { "content-type": "application/json", ...headers },
    body: typeof body === "string" ? body : JSON.stringify(body),
  });
}

/** Everything these doors answer must be uncacheable. */
function noStore(response: Response): void {
  expect(response.headers.get("cache-control")).toBe("no-store");
}

// ---------------------------------------------------------------------------
// What a tier allows, and nothing about what it costs
// ---------------------------------------------------------------------------

describe("GET /keys/tiers", () => {
  it("publishes the caps, with no price and no share beside them", async () => {
    const response = await send(get("/keys/tiers"));
    expect(response.status).toBe(200);
    noStore(response);
    // Exactly one key in the object: a reader who went looking for a price here
    // must find that there is not one rather than find a zero.
    expect(await response.json()).toEqual({
      tiers: JSON.parse(JSON.stringify(RATE_TIERS)),
    });
  }, 600_000);

  it("is served without a key, which is the whole point of it", async () => {
    expect((await send(get("/keys/tiers"))).status).toBe(200);
  }, 600_000);

  it("takes a GET and nothing else", async () => {
    const response = await send(post("/keys/tiers", {}));
    expect(response.status).toBe(405);
    expect(response.headers.get("allow")).toBe("GET, HEAD");
  }, 600_000);
});

// ---------------------------------------------------------------------------
// The free door: one key, one client, one day
// ---------------------------------------------------------------------------

let secret = "";
let keyId = "";

describe("POST /keys/free", () => {
  it("hands the key over once, and stores only its hash", async () => {
    const response = await send(post("/keys/free", {}, from(CLIENT)));
    expect(response.status).toBe(201);
    noStore(response);
    const body = (await response.json()) as Record<string, string>;
    expect(body).toEqual({
      key: expect.stringMatching(/^nmk_[A-Za-z0-9_-]{43}$/),
      id: expect.stringMatching(/^key_[0-9a-f]{16}$/),
      tier: "standard",
      status: "active",
      limit: RATE_TIERS["standard"]!.reads_per_day,
      created_at: NOW.toISOString(),
    });
    secret = body["key"]!;
    keyId = body["id"]!;

    // What the table holds is the hash and never the secret.
    const stored = await keyByHash(store.db, await keyHash(secret));
    expect(stored?.id).toBe(keyId);
    expect(stored?.counter).toBe(0);
    const raw = await store.db
      .prepare(`SELECT key_hash, client_day FROM api_keys WHERE id = ?`)
      .bind(keyId)
      .first<Record<string, string>>();
    expect(raw?.["key_hash"]).toBe(await keyHash(secret));
    expect(raw?.["key_hash"]).not.toBe(secret);
    // The provider's three columns are gone (migration 0023) and what carries
    // the daily rule is the client digest and the UTC day.
    expect(raw?.["client_day"]).toMatch(/^[0-9a-f]{64}:2026-09-11$/);
    // And the address itself is nowhere in it.
    expect(JSON.stringify(raw)).not.toContain(CLIENT);
  }, 600_000);

  it("refuses the same client a second key on the same day", async () => {
    for (const attempt of [2, 3]) {
      const response = await send(post("/keys/free", {}, from(CLIENT)));
      expect([attempt, response.status]).toEqual([attempt, 429]);
      expect(await response.json()).toEqual({ error: "key_today" });
    }
    const count = await store.db
      .prepare(`SELECT COUNT(*) AS n FROM api_keys`)
      .first<{ n: number }>();
    expect(count?.n).toBe(1);
  }, 600_000);

  it("gives another client its own key on the same day", async () => {
    const response = await send(post("/keys/free", {}, from(OTHER_CLIENT)));
    expect(response.status).toBe(201);
    const body = (await response.json()) as Record<string, string>;
    expect(body["id"]).not.toBe(keyId);
    expect(body["tier"]).toBe("standard");
    expect(body["status"]).toBe("active");
  }, 600_000);

  it("gives the first client another key the next day", async () => {
    const tomorrow = new Date("2026-09-12T00:00:01.000Z");
    const response = await send(post("/keys/free", {}, from(CLIENT)), {
      now: tomorrow,
    });
    expect(response.status).toBe(201);
    const body = (await response.json()) as Record<string, string>;
    expect(body["id"]).not.toBe(keyId);
    expect(body["created_at"]).toBe(tomorrow.toISOString());
  }, 600_000);

  it("needs no body, and refuses one that says anything", async () => {
    const bare = new Request(`${ORIGIN}/keys/free`, {
      method: "POST",
      headers: from("203.0.113.9"),
    });
    expect((await send(bare)).status).toBe(201);

    for (const body of ["not json", "[]", '"a string"', '{"tier":"high"}']) {
      const response = await send(
        post("/keys/free", body, from("203.0.113.10")),
      );
      expect([body, response.status]).toEqual([body, 400]);
      expect(await response.json()).toEqual({ error: "bad_body" });
    }
  }, 600_000);

  it("takes a POST and nothing else", async () => {
    const response = await send(get("/keys/free"));
    expect(response.status).toBe(405);
    expect(response.headers.get("allow")).toBe("POST");
  }, 600_000);
});

// ---------------------------------------------------------------------------
// The doors of the paid loop, gone
// ---------------------------------------------------------------------------

describe("the doors of the paid loop", () => {
  it("answers 404 at all four: a removed route is an unknown path", async () => {
    // D-127 item 2 took the checkout, the claim, the portal and the webhook
    // out with the money they were for. A removed route is not a special case:
    // it answers what any path nobody has ever heard of answers.
    const gone = [
      await send(post("/keys/checkout", { tier: "standard" })),
      await send(get("/keys/claim?session=cs_anything")),
      await send(
        post("/keys/me/portal", {}, { authorization: `Bearer ${secret}` }),
      ),
      await send(post("/stripe/webhook", { id: "evt_1" })),
    ];
    for (const response of gone) {
      expect(response.status).toBe(404);
    }
  }, 600_000);

  it("asks the database nothing at all on the way to the 404", async () => {
    const watched = counting(store.db);
    const watchedEnv = { ...env, DB: watched.db };
    const calls: Request[] = [
      post("/keys/checkout", { tier: "standard" }),
      get("/keys/claim?session=cs_anything"),
      post("/keys/me/portal", {}, { authorization: `Bearer ${secret}` }),
      post("/stripe/webhook", { id: "evt_3" }),
    ];
    for (const request of calls) {
      const response = await handleRequest(request, watchedEnv, deps);
      expect([request.url, response.status]).toEqual([request.url, 404]);
    }
    expect(watched.statements()).toBe(0);
  }, 600_000);

  it("writes nothing, and the provider's own table is not there to write to", async () => {
    const before = await store.db
      .prepare(`SELECT COUNT(*) AS n FROM api_keys`)
      .first<{ n: number }>();
    await send(post("/keys/checkout", { tier: "standard" }));
    await send(get("/keys/claim?session=cs_anything"));
    await send(post("/stripe/webhook", { id: "evt_2" }));
    const after = await store.db
      .prepare(`SELECT COUNT(*) AS n FROM api_keys`)
      .first<{ n: number }>();
    expect(after?.n).toBe(before?.n);
    await expect(
      store.db.prepare(`SELECT COUNT(*) AS n FROM stripe_events`).first(),
    ).rejects.toThrow();
  }, 600_000);
});

// ---------------------------------------------------------------------------
// What a holder can see
// ---------------------------------------------------------------------------

describe("the holder's own reads", () => {
  const withKey = (): Record<string, string> => ({
    authorization: `Bearer ${secret}`,
  });

  it("refuses without a key, with a malformed key, and with an unknown one", async () => {
    for (const [headers, status, error] of [
      [{}, 401, "missing_key"],
      [{ authorization: "Bearer nonsense" }, 401, "bad_key"],
      [
        { authorization: `Bearer nmk_${"A".repeat(43)}` },
        401,
        "unknown_key",
      ],
    ] as const) {
      const response = await send(get("/keys/me", headers));
      expect([error, response.status]).toEqual([error, status]);
      expect(await response.json()).toEqual({ error });
    }
  }, 600_000);

  it("shows the key without its hash or its secret", async () => {
    const response = await send(get("/keys/me", withKey()));
    expect(response.status).toBe(200);
    const body = await response.json();
    expect(body).toEqual({
      id: keyId,
      tier: "standard",
      status: "active",
      created_at: NOW.toISOString(),
      limit: RATE_TIERS["standard"]!.reads_per_day,
      used_today: 0,
      remaining_today: RATE_TIERS["standard"]!.reads_per_day,
      counter: 0,
    });
    const text = JSON.stringify(body);
    expect(text).not.toContain(secret);
    expect(text).not.toContain(await keyHash(secret));
  }, 600_000);

  it("shows a day per day, with nothing published yet", async () => {
    const response = await send(get("/keys/me/usage?days=3", withKey()));
    expect(response.status).toBe(200);
    expect(await response.json()).toEqual({
      key: keyId,
      days: [
        { date: "2026-09-09", reads: 0, published: null },
        { date: "2026-09-10", reads: 0, published: null },
        { date: DAY, reads: 0, published: null },
      ],
    });
  }, 600_000);

  it("shows what the log published about the key once it has", async () => {
    await store.db
      .prepare(
        `INSERT INTO events (seq, "at", type, entry_id, payload, prev_hash, hash)
         VALUES (?, ?, ?, ?, ?, ?, ?)`,
      )
      .bind(
        900,
        `${DAY}T23:59:00.000Z`,
        "read_count",
        null,
        JSON.stringify({
          date: DAY,
          reads: [],
          total: 11,
          counter_first: 1,
          counter_last: 11,
          paid: { reads: [], total: 6, keys: { [keyId]: 6 } },
        }),
        null,
        `sha256:${"b".repeat(64)}`,
      )
      .run();

    const response = await send(get("/keys/me/usage?days=1", withKey()));
    expect(await response.json()).toEqual({
      key: keyId,
      days: [{ date: DAY, reads: 0, published: { reads: 6, seq: 900 } }],
    });
  }, 600_000);

  it("refuses a window it does not publish", async () => {
    for (const days of ["0", "91", "-1", "half"]) {
      const response = await send(get(`/keys/me/usage?days=${days}`, withKey()));
      expect([days, response.status]).toEqual([days, 400]);
    }
  }, 600_000);

  it("shows the key's receipts, in the key's own counter order", async () => {
    for (let counter = 1; counter <= 2; counter += 1) {
      await store.db
        .prepare(
          `INSERT INTO receipts (id, kind, entry_id, seq, created_at, payload_json, key_id, key_counter)
           VALUES (?, 'read', ?, ?, ?, ?, ?, ?)`,
        )
        .bind(
          `rcpt_${500 + counter}`,
          "nmk_00000000000000000000000000000001",
          500 + counter,
          `${DAY}T0${counter}:00:00.000Z`,
          JSON.stringify({ counter: 500 + counter, key: keyId }),
          keyId,
          counter,
        )
        .run();
    }
    const response = await send(get("/keys/me/receipts?limit=1", withKey()));
    expect(response.status).toBe(200);
    const body = (await response.json()) as {
      key: string;
      receipts: { key_counter: number; counter: number }[];
    };
    expect(body.key).toBe(keyId);
    expect(body.receipts.map((row) => row.key_counter)).toEqual([1]);
    const next = await send(get("/keys/me/receipts?after=1", withKey()));
    const page = (await next.json()) as {
      receipts: { key_counter: number }[];
    };
    expect(page.receipts.map((row) => row.key_counter)).toEqual([2]);
  }, 600_000);
});
// ---------------------------------------------------------------------------
// What the doors do not own
// ---------------------------------------------------------------------------

describe("paths under /keys nobody answers", () => {
  it("leaves the Worker's own not_found exactly where it was", async () => {
    // Paths no door under /keys answers at all. `/keys/me/webhooks` is not one
    // of them any more: the alert door owns it, so it is pinned below instead.
    for (const path of ["/keys", "/keys/nope", "/keys/me/nope"]) {
      const response = await send(get(path));
      expect([path, response.status]).toEqual([path, 404]);
      expect(await response.json()).toEqual({ ok: false, error: "not_found" });
    }
  }, 600_000);

  it("hands the seam between the two doors to the alert door", async () => {
    // The key doors answer null for this path and the alert door answers it, so
    // a caller without a key is told which rule refused them rather than that
    // the path does not exist.
    const response = await send(get("/keys/me/webhooks"));
    expect(response.status).toBe(401);
    expect(await response.json()).toEqual({ error: "missing_key" });
  }, 600_000);
});
