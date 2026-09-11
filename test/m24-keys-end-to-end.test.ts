/**
 * M24 end to end: buying a key, claiming it once, and the door the provider
 * knocks on.
 *
 * Whitepaper Section 9, Money: "The log is free to read at low volume, forever.
 * Revenue comes from high-rate API access, structured feeds and webhooks,
 * change alerts." This drives the real router — miniflare's D1 with the real
 * migrations applied, the real key doors, the real webhook door — with the
 * clock injected and the payment provider mocked, because the one thing a test
 * of a paid loop must never do is reach a payment provider.
 *
 * The four things it holds hardest. A key is handed over exactly once: the
 * second and third attempt on the same checkout session are 409, whatever else
 * happens. The free tier is served on a deployment that cannot take money at
 * all, which is production's state until M25 — a Worker that refused everything
 * because it had no Stripe key would have broken the paper's "free to read at
 * low volume, forever". The webhook trusts nothing it is sent: a forged
 * signature and a stale one are both 400, and a retried message changes
 * nothing. And a secret appears in exactly one response body, ever.
 */

import { afterAll, beforeAll, describe, expect, it } from "vitest";

import {
  MockPaymentsAdapter,
  StripeAdapter,
  UnavailablePaymentsAdapter,
} from "../src/adapters/stripe.js";
import { keyHash } from "../src/keys.js";
import {
  CONTRIBUTOR_SHARE_FLOOR_PERCENT,
  CONTRIBUTOR_SHARE_PERCENT,
  RATE_TIERS,
  READ_PRICE_MICROS_PER_READ,
} from "../src/policy.js";
import { keyByHash, keyById } from "../src/storage/keys.js";
import type { Env } from "../src/worker/env.js";
import { resolveAccess } from "../src/worker/access.js";
import { handleRequest, type RequestDeps } from "../src/worker/index.js";
import { openTestDatabase, type TestDatabase } from "./helpers/d1.js";

const ORIGIN = "https://nomankind.ai";
const NOW = new Date("2026-09-11T12:00:00.000Z");
const UNIX = Math.floor(NOW.getTime() / 1000);
const DAY = "2026-09-11";

const WEBHOOK_SECRET = "whsec_the_signing_secret_and_it_must_never_leak";

/**
 * The sixteen hex characters the mock provider writes its ids on. A mock
 * session id carries the tier and this suffix and nothing else, which is what
 * lets the claim door read back a session a previous request made: the Worker
 * builds a fresh adapter per request and no map survives between them.
 */
const SUFFIX_ONE = "cafe0001cafe0001";
const SUFFIX_TWO = "cafe0002cafe0002";

let store: TestDatabase;
let env: Env;
let payments: MockPaymentsAdapter;
let deps: RequestDeps;

beforeAll(async () => {
  store = await openTestDatabase();
  env = {
    DB: store.db,
    CAPTURES: store.captures,
    ENVIRONMENT: "local",
    MAINTAINER_AGENT_ID: "",
  };
  payments = new MockPaymentsAdapter({ random: () => SUFFIX_ONE });
  deps = { now: NOW, payments };
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

/** Everything the paid loop answers must be uncacheable. */
function noStore(response: Response): void {
  expect(response.headers.get("cache-control")).toBe("no-store");
}

// ---------------------------------------------------------------------------
// What is on sale
// ---------------------------------------------------------------------------

describe("GET /keys/tiers", () => {
  it("publishes the tiers, the price and both contributor shares", async () => {
    const response = await send(get("/keys/tiers"));
    expect(response.status).toBe(200);
    noStore(response);
    expect(await response.json()).toEqual({
      tiers: JSON.parse(JSON.stringify(RATE_TIERS)),
      price_micros_per_read: READ_PRICE_MICROS_PER_READ,
      contributor_share_percent: CONTRIBUTOR_SHARE_PERCENT,
      contributor_share_floor_percent: CONTRIBUTOR_SHARE_FLOOR_PERCENT,
    });
  }, 600_000);

  it("is served without a key, which is the whole point of it", async () => {
    expect((await send(get("/keys/tiers"))).status).toBe(200);
  }, 600_000);

  it("takes a GET and nothing else", async () => {
    const response = await send(post("/keys/tiers", {}));
    expect(response.status).toBe(405);
    expect(response.headers.get("allow")).toBe("GET");
  }, 600_000);
});

// ---------------------------------------------------------------------------
// Buying, and claiming exactly once
// ---------------------------------------------------------------------------

let session = "";
let secret = "";
let keyId = "";

describe("POST /keys/checkout", () => {
  it("refuses a body that is not an object", async () => {
    for (const body of ["not json", "[]", '"a string"']) {
      const response = await send(post("/keys/checkout", body));
      expect([body, response.status]).toEqual([body, 400]);
      expect(await response.json()).toEqual({ error: "bad_body" });
    }
  }, 600_000);

  it("refuses a tier nobody publishes", async () => {
    const response = await send(post("/keys/checkout", { tier: "platinum" }));
    expect(response.status).toBe(422);
    expect(await response.json()).toEqual({ error: "unknown_tier" });
  }, 600_000);

  it("refuses to sell the tier that is free", async () => {
    const response = await send(post("/keys/checkout", { tier: "free" }));
    expect(response.status).toBe(422);
    expect(await response.json()).toEqual({ error: "free_tier_needs_no_key" });
  }, 600_000);

  it("hands back a session and the URL to pay at", async () => {
    const response = await send(
      post("/keys/checkout", { tier: "standard", email: "reader@example.com" }),
    );
    expect(response.status).toBe(200);
    noStore(response);
    const body = (await response.json()) as { session: string; url: string };
    expect(body.session).toBe(`mock_cs_standard_${SUFFIX_ONE}`);
    // The success URL is this Worker's own claim door, with the provider's
    // placeholder filled in.
    expect(body.url).toBe(
      `${ORIGIN}/keys/claim?session=mock_cs_standard_${SUFFIX_ONE}`,
    );
    session = body.session;
  }, 600_000);
});

describe("GET /keys/claim", () => {
  it("refuses without a session", async () => {
    const response = await send(get("/keys/claim"));
    expect(response.status).toBe(400);
    expect(await response.json()).toEqual({ error: "missing_session" });
  }, 600_000);

  it("refuses a session the provider never made", async () => {
    const response = await send(get("/keys/claim?session=mock_cs_nobody"));
    expect(response.status).toBe(404);
    expect(await response.json()).toEqual({ error: "unknown_session" });
  }, 600_000);

  it("hands the key over once, and stores only its hash", async () => {
    const response = await send(get(`/keys/claim?session=${session}`));
    expect(response.status).toBe(201);
    noStore(response);
    const body = (await response.json()) as Record<string, string>;
    expect(body).toEqual({
      key: expect.stringMatching(/^nmk_[A-Za-z0-9_-]{43}$/),
      id: expect.stringMatching(/^key_[0-9a-f]{16}$/),
      tier: "standard",
      status: "active",
      customer: `mock_cus_${SUFFIX_ONE}`,
      created_at: NOW.toISOString(),
    });
    secret = body["key"]!;
    keyId = body["id"]!;

    // What the table holds is the hash and never the secret.
    const stored = await keyByHash(store.db, await keyHash(secret));
    expect(stored?.id).toBe(keyId);
    expect(stored?.subscription).toBe(`mock_sub_${SUFFIX_ONE}`);
    expect(stored?.counter).toBe(0);
    const raw = await store.db
      .prepare(`SELECT key_hash FROM api_keys WHERE id = ?`)
      .bind(keyId)
      .first<{ key_hash: string }>();
    expect(raw?.key_hash).toBe(await keyHash(secret));
    expect(raw?.key_hash).not.toBe(secret);
  }, 600_000);

  it("refuses the second claim, and the third", async () => {
    for (const attempt of [2, 3]) {
      const response = await send(get(`/keys/claim?session=${session}`));
      expect([attempt, response.status]).toEqual([attempt, 409]);
      expect(await response.json()).toEqual({ error: "already_claimed" });
    }
    // And exactly one key came of that session, whatever was asked.
    const count = await store.db
      .prepare(`SELECT COUNT(*) AS n FROM api_keys WHERE checkout_session = ?`)
      .bind(session)
      .first<{ n: number }>();
    expect(count?.n).toBe(1);
  }, 600_000);

  it("shows a browser the same fields on a page, with the warning", async () => {
    // The provider's success redirect lands a person here, so a person gets a
    // readable page rather than a JSON blob they might close.
    const second = await send(post("/keys/checkout", { tier: "high" }), {
      payments: new MockPaymentsAdapter({ random: () => SUFFIX_TWO }),
    });
    expect(second.status).toBe(200);

    const browser = new MockPaymentsAdapter({ random: () => SUFFIX_TWO });
    await browser.createCheckout({
      price: "price_mock_high",
      tier: "high",
      environment: "local",
      successUrl: `${ORIGIN}/keys/claim?session={CHECKOUT_SESSION_ID}`,
      cancelUrl: `${ORIGIN}/api`,
    });
    const response = await send(
      get(`/keys/claim?session=mock_cs_high_${SUFFIX_TWO}`, {
        accept: "text/html",
      }),
      { payments: browser },
    );
    expect(response.status).toBe(201);
    expect(response.headers.get("content-type")).toContain("text/html");
    const page = await response.text();
    expect(page).toContain("This is the only time the key is shown");
    expect(page).toContain(`mock_cus_${SUFFIX_TWO}`);
    expect(page).toMatch(/nmk_[A-Za-z0-9_-]{43}/);
  }, 600_000);

  it("refuses a session that has not paid", async () => {
    const unpaid: MockPaymentsAdapter = new MockPaymentsAdapter();
    const open = {
      ...unpaid,
      kind: "mock" as const,
      ensurePrice: unpaid.ensurePrice.bind(unpaid),
      createCheckout: unpaid.createCheckout.bind(unpaid),
      createPortal: unpaid.createPortal.bind(unpaid),
      reportUsage: unpaid.reportUsage.bind(unpaid),
      verifyWebhook: unpaid.verifyWebhook.bind(unpaid),
      retrieveCheckout: async () => ({
        ok: true as const,
        value: {
          id: "cs_open",
          status: "open",
          mode: "subscription",
          customer: null,
          subscription: null,
          metadata: { tier: "standard" },
        },
      }),
    };
    const response = await send(get("/keys/claim?session=cs_open"), {
      payments: open,
    });
    expect(response.status).toBe(402);
    expect(await response.json()).toEqual({ error: "not_paid" });
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

  it("opens the provider's own billing page and holds no card of its own", async () => {
    const response = await send(post("/keys/me/portal", {}, withKey()));
    expect(response.status).toBe(200);
    expect(await response.json()).toEqual({ url: `${ORIGIN}/api` });
  }, 600_000);
});

// ---------------------------------------------------------------------------
// A deployment that cannot take money
// ---------------------------------------------------------------------------

describe("a deployment with no payment provider", () => {
  const unavailable = new UnavailablePaymentsAdapter();

  it("refuses a checkout with one word", async () => {
    const response = await handleRequest(
      post("/keys/checkout", { tier: "standard" }),
      { ...env, ENVIRONMENT: "production" },
      { now: NOW, payments: unavailable },
    );
    expect(response.status).toBe(503);
    expect(await response.json()).toEqual({ error: "payments_unavailable" });
  }, 600_000);

  it("still serves the free tier, which is the paper's promise", async () => {
    const response = await handleRequest(
      get("/keys/tiers"),
      { ...env, ENVIRONMENT: "production" },
      { now: NOW, payments: unavailable },
    );
    expect(response.status).toBe(200);
    expect(
      ((await response.json()) as { tiers: Record<string, unknown> }).tiers,
    ).toHaveProperty("free");
  }, 600_000);

  it("refuses the webhook rather than trusting an unsigned message", async () => {
    const response = await handleRequest(
      post("/stripe/webhook", { id: "evt_x", type: "invoice.paid" }),
      { ...env, ENVIRONMENT: "production" },
      { now: NOW, payments: unavailable },
    );
    expect(response.status).toBe(503);
    expect(await response.json()).toEqual({ error: "payments_unavailable" });
  }, 600_000);
});

// ---------------------------------------------------------------------------
// The provider's own door
// ---------------------------------------------------------------------------

/** The HMAC a provider signs with, computed here independently of the adapter. */
async function sign(timestamp: number, body: string): Promise<string> {
  const encoder = new TextEncoder();
  const key = await globalThis.crypto.subtle.importKey(
    "raw",
    encoder.encode(WEBHOOK_SECRET) as unknown as BufferSource,
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const digest = await globalThis.crypto.subtle.sign(
    "HMAC",
    key,
    encoder.encode(`${timestamp}.${body}`) as unknown as BufferSource,
  );
  return [...new Uint8Array(digest)]
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("");
}

/** The real adapter, with a webhook secret and a fetch it must never reach. */
function signed(): StripeAdapter {
  return new StripeAdapter({
    secretKey: "sk_test_never_used_here",
    webhookSecret: WEBHOOK_SECRET,
    fetch: (async (): Promise<Response> => {
      throw new Error("the webhook door must not reach the network");
    }) as typeof fetch,
  });
}

/** One signed message through the real door. */
async function webhook(
  event: unknown,
  options: { timestamp?: number; signature?: string } = {},
): Promise<Response> {
  const body = JSON.stringify(event);
  const timestamp = options.timestamp ?? UNIX;
  const signature = options.signature ?? (await sign(timestamp, body));
  return send(
    post(
      "/stripe/webhook",
      body,
      { "stripe-signature": `t=${timestamp},v1=${signature}` },
    ),
    { payments: signed() },
  );
}

describe("POST /stripe/webhook", () => {
  it("refuses a forged signature", async () => {
    const response = await webhook(
      { id: "evt_forged", type: "invoice.paid", created: UNIX, data: { object: {} } },
      { signature: "f".repeat(64) },
    );
    expect(response.status).toBe(400);
    expect(await response.json()).toEqual({ error: "bad_signature" });
  }, 600_000);

  it("refuses a signature older than the tolerance", async () => {
    const response = await webhook(
      { id: "evt_stale", type: "invoice.paid", created: UNIX, data: { object: {} } },
      { timestamp: UNIX - 3600 },
    );
    expect(response.status).toBe(400);
    expect(await response.json()).toEqual({ error: "bad_signature" });
  }, 600_000);

  it("refuses a message with no signature header at all", async () => {
    const response = await send(
      post("/stripe/webhook", { id: "evt_bare", type: "invoice.paid" }),
      { payments: signed() },
    );
    expect(response.status).toBe(400);
    expect(await response.json()).toEqual({ error: "bad_signature" });
  }, 600_000);

  it("records a message about a subscription nobody here holds", async () => {
    const response = await webhook({
      id: "evt_stranger",
      type: "customer.subscription.updated",
      created: UNIX,
      data: { object: { id: "sub_somebody_else", status: "past_due" } },
    });
    expect(response.status).toBe(200);
    expect(await response.json()).toEqual({
      received: true,
      outcome: "unknown_subscription",
    });
  }, 600_000);

  it("suspends a key when the subscription says the bill did not clear", async () => {
    const response = await webhook({
      id: "evt_past_due",
      type: "customer.subscription.updated",
      created: UNIX,
      data: { object: { id: `mock_sub_${SUFFIX_ONE}`, status: "past_due" } },
    });
    expect(response.status).toBe(200);
    expect(await response.json()).toEqual({ received: true, outcome: "applied" });
    expect((await keyById(store.db, keyId))?.status).toBe("past_due");
  }, 600_000);

  it("ignores a message it has already acted on", async () => {
    const response = await webhook({
      id: "evt_past_due",
      type: "customer.subscription.updated",
      created: UNIX,
      // A retry could carry anything; what stops it is the id, not the body.
      data: { object: { id: `mock_sub_${SUFFIX_ONE}`, status: "canceled" } },
    });
    expect(response.status).toBe(200);
    expect(await response.json()).toEqual({
      received: true,
      outcome: "duplicate",
    });
    expect((await keyById(store.db, keyId))?.status).toBe("past_due");
  }, 600_000);

  it("restores the key when the invoice is paid", async () => {
    const response = await webhook({
      id: "evt_paid",
      type: "invoice.paid",
      created: UNIX,
      data: { object: { id: "in_1", subscription: `mock_sub_${SUFFIX_ONE}` } },
    });
    expect(response.status).toBe(200);
    expect(await response.json()).toEqual({ received: true, outcome: "applied" });
    expect((await keyById(store.db, keyId))?.status).toBe("active");
  }, 600_000);

  it("ignores a checkout completion, because the claim door mints the key", async () => {
    const response = await webhook({
      id: "evt_checkout",
      type: "checkout.session.completed",
      created: UNIX,
      data: { object: { id: `mock_cs_standard_${SUFFIX_ONE}` } },
    });
    expect(response.status).toBe(200);
    expect(await response.json()).toEqual({ received: true, outcome: "ignored" });
  }, 600_000);

  it("cancels a key when the subscription is deleted", async () => {
    const response = await webhook({
      id: "evt_deleted",
      type: "customer.subscription.deleted",
      created: UNIX,
      data: { object: { id: `mock_sub_${SUFFIX_ONE}`, status: "canceled" } },
    });
    expect(response.status).toBe(200);
    expect(await response.json()).toEqual({ received: true, outcome: "applied" });
    expect((await keyById(store.db, keyId))?.status).toBe("canceled");
  }, 600_000);

  it("leaves the canceled key refused 402 at the gate the doors read", async () => {
    // The read and sync doors are another builder's to wire to the gate; the
    // gate itself is what a canceled subscription costs a key, and it is this.
    const resolved = await resolveAccess(
      store.db,
      get("/read/nmk_00000000000000000000000000000001", {
        authorization: `Bearer ${secret}`,
      }),
      NOW,
    );
    expect(resolved.ok).toBe(false);
    if (resolved.ok) return;
    expect([resolved.refusal.status, resolved.refusal.reason]).toEqual([
      402,
      "key_canceled",
    ]);
  }, 600_000);

  it("takes a POST and nothing else", async () => {
    const response = await send(get("/stripe/webhook"), { payments: signed() });
    expect(response.status).toBe(405);
    expect(response.headers.get("allow")).toBe("POST");
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
