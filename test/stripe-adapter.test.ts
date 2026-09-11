/**
 * The payments adapter, against a fake provider.
 *
 * Decision D-078: the paid loop runs over Stripe's REST API with `fetch`, form
 * bodies and signed webhooks, and no SDK. Nothing here reaches the network. The
 * fake replays Stripe-shaped JSON exactly as test/mirror-app.test.ts replays
 * GitHub's, and it asserts the four things a hand-written REST client gets
 * wrong: the method, the path, the credential header, and the keys of the form
 * body — plus the one thing that costs money when it is wrong, which is an
 * `Idempotency-Key` on every POST.
 *
 * What it watches hardest is the secret. The key and the webhook signing secret
 * must appear in exactly one header and one HMAC and in no refusal, no return
 * value and nothing a caller could log, so every refusal below is checked for
 * both.
 */

import { describe, expect, it } from "vitest";

import {
  MockPaymentsAdapter,
  StripeAdapter,
  UnavailablePaymentsAdapter,
  constantTimeEqual,
  parseSignatureHeader,
  paymentsAdapterFor,
  unitAmountDecimal,
} from "../src/adapters/stripe.js";
import { READ_PRICE_MICROS_PER_READ, STRIPE } from "../src/policy.js";

const SECRET_KEY = "sk_test_the_secret_key_and_it_must_never_leak";
const WEBHOOK_SECRET = "whsec_the_signing_secret_and_it_must_never_leak";
const IDEMPOTENCY = "fixed-idempotency-key";
const NOW = new Date("2026-09-11T12:00:00.000Z");
const UNIX = Math.floor(NOW.getTime() / 1000);

/** One call the fake saw, in the four parts a REST client can get wrong. */
interface Seen {
  readonly method: string;
  readonly path: string;
  readonly authorization: string | null;
  readonly idempotency: string | null;
  readonly contentType: string | null;
  readonly body: URLSearchParams | null;
}

/** What the fake answers one path with. */
interface Reply {
  readonly status?: number;
  readonly body: unknown;
}

/**
 * A fake provider: a script of replies keyed by `<METHOD> <path>`, and the log
 * of what was asked. A path nobody scripted is a failed assertion rather than a
 * silent 404, because a call this file did not expect is the thing under test.
 */
function fakeProvider(script: Record<string, Reply | Reply[]>): {
  fetch: typeof fetch;
  seen: Seen[];
} {
  const seen: Seen[] = [];
  const pending = new Map<string, Reply[]>();
  for (const [key, value] of Object.entries(script)) {
    pending.set(key, Array.isArray(value) ? [...value] : [value]);
  }

  const call = (async (
    input: RequestInfo | URL,
    init?: RequestInit,
  ): Promise<Response> => {
    const url = new URL(String(input));
    expect(url.origin).toBe(STRIPE.api);
    const method = init?.method ?? "GET";
    const headers = new Headers(init?.headers);
    const rawBody = init?.body;
    seen.push({
      method,
      path: `${url.pathname}${url.search}`,
      authorization: headers.get("authorization"),
      idempotency: headers.get("idempotency-key"),
      contentType: headers.get("content-type"),
      body:
        typeof rawBody === "string" ? new URLSearchParams(rawBody) : null,
    });

    const key = `${method} ${url.pathname}`;
    const replies = pending.get(key);
    expect(replies, `no reply scripted for ${key}`).toBeDefined();
    const reply = replies!.length > 1 ? replies!.shift()! : replies![0]!;
    return new Response(JSON.stringify(reply.body), {
      status: reply.status ?? 200,
      headers: { "content-type": "application/json" },
    });
  }) as typeof fetch;

  return { fetch: call, seen };
}

function adapter(fetchImpl: typeof fetch): StripeAdapter {
  return new StripeAdapter({
    secretKey: SECRET_KEY,
    webhookSecret: WEBHOOK_SECRET,
    fetch: fetchImpl,
    random: () => IDEMPOTENCY,
  });
}

/** Nothing a caller can see may carry either secret. */
function carriesNoSecret(value: unknown): void {
  const text = JSON.stringify(value) ?? String(value);
  expect(text).not.toContain(SECRET_KEY);
  expect(text).not.toContain(WEBHOOK_SECRET);
}

// ---------------------------------------------------------------------------
// The price
// ---------------------------------------------------------------------------

const LOOKUP_KEY = `${STRIPE.price_lookup_prefix}demo-standard`;

describe("ensurePrice", () => {
  it("uses the price already standing at the lookup key", async () => {
    const provider = fakeProvider({
      "GET /v1/prices": { body: { data: [{ id: "price_existing" }] } },
    });
    const result = await adapter(provider.fetch).ensurePrice("demo", "standard");
    expect(result).toEqual({ ok: true, value: { price: "price_existing" } });

    expect(provider.seen).toHaveLength(1);
    const call = provider.seen[0]!;
    expect(call.method).toBe("GET");
    expect(call.authorization).toBe(`Bearer ${SECRET_KEY}`);
    // A GET is not a write, so it carries no idempotency key and no body.
    expect(call.idempotency).toBeNull();
    expect(call.body).toBeNull();
    const query = new URLSearchParams(call.path.split("?")[1]);
    expect(query.get("lookup_keys[]")).toBe(LOOKUP_KEY);
    expect(query.get("active")).toBe("true");
    expect(query.get("limit")).toBe("1");
    expect(call.path.startsWith("/v1/prices?")).toBe(true);
  });

  it("makes the meter, the product and the price when none stands there", async () => {
    const provider = fakeProvider({
      "GET /v1/prices": { body: { data: [] } },
      "GET /v1/billing/meters": { body: { data: [] } },
      "POST /v1/billing/meters": { body: { id: "mtr_made" } },
      "POST /v1/products": { body: { id: "prod_made" } },
      "POST /v1/prices": { body: { id: "price_made" } },
    });
    const result = await adapter(provider.fetch).ensurePrice("demo", "standard");
    expect(result).toEqual({ ok: true, value: { price: "price_made" } });

    expect(provider.seen.map((call) => `${call.method} ${call.path.split("?")[0]}`)).toEqual([
      "GET /v1/prices",
      "GET /v1/billing/meters",
      "POST /v1/billing/meters",
      "POST /v1/products",
      "POST /v1/prices",
    ]);

    const [, meters, meter, product, price] = provider.seen;
    expect(meters!.path).toBe("/v1/billing/meters?status=active&limit=100");

    // Every POST is authenticated, form-encoded, and idempotent.
    for (const call of [meter!, product!, price!]) {
      expect(call.authorization).toBe(`Bearer ${SECRET_KEY}`);
      expect(call.idempotency).toBe(IDEMPOTENCY);
      expect(call.contentType).toBe("application/x-www-form-urlencoded");
    }

    expect([...meter!.body!.keys()].sort()).toEqual([
      "customer_mapping[event_payload_key]",
      "customer_mapping[type]",
      "default_aggregation[formula]",
      "display_name",
      "event_name",
      "value_settings[event_payload_key]",
    ]);
    expect(meter!.body!.get("event_name")).toBe(STRIPE.meter_event_name);
    expect(meter!.body!.get("default_aggregation[formula]")).toBe("sum");
    expect(meter!.body!.get("customer_mapping[type]")).toBe("by_id");

    expect([...product!.body!.keys()].sort()).toEqual([
      "metadata[environment]",
      "metadata[tier]",
      "name",
    ]);
    expect(product!.body!.get("name")).toBe("nomankind Standard tier (demo)");
    expect(product!.body!.get("metadata[tier]")).toBe("standard");

    expect([...price!.body!.keys()].sort()).toEqual([
      "billing_scheme",
      "currency",
      "lookup_key",
      "product",
      "recurring[interval]",
      "recurring[meter]",
      "recurring[usage_type]",
      "transfer_lookup_key",
      "unit_amount_decimal",
    ]);
    expect(price!.body!.get("product")).toBe("prod_made");
    expect(price!.body!.get("currency")).toBe(STRIPE.currency);
    expect(price!.body!.get("recurring[meter]")).toBe("mtr_made");
    expect(price!.body!.get("recurring[usage_type]")).toBe("metered");
    expect(price!.body!.get("lookup_key")).toBe(LOOKUP_KEY);
    expect(price!.body!.get("transfer_lookup_key")).toBe("true");
    // The price is policy's, converted: 500 micro-USD a read is 0.05 cents.
    expect(price!.body!.get("unit_amount_decimal")).toBe(
      unitAmountDecimal(READ_PRICE_MICROS_PER_READ),
    );
    expect(price!.body!.get("unit_amount_decimal")).toBe("0.05");
  });

  it("reuses a meter that already carries our event name", async () => {
    const provider = fakeProvider({
      "GET /v1/prices": { body: { data: [] } },
      "GET /v1/billing/meters": {
        body: {
          data: [
            { id: "mtr_other", event_name: "somebody_elses" },
            { id: "mtr_ours", event_name: STRIPE.meter_event_name },
          ],
        },
      },
      "POST /v1/products": { body: { id: "prod_made" } },
      "POST /v1/prices": { body: { id: "price_made" } },
    });
    await adapter(provider.fetch).ensurePrice("demo", "standard");
    expect(
      provider.seen.some((call) => call.path === "/v1/billing/meters"),
    ).toBe(false);
    const price = provider.seen.at(-1)!;
    expect(price.body!.get("recurring[meter]")).toBe("mtr_ours");
  });

  it("converts every micro price into cents without a float", () => {
    expect(unitAmountDecimal(500)).toBe("0.05");
    expect(unitAmountDecimal(10_000)).toBe("1");
    expect(unitAmountDecimal(12_345)).toBe("1.2345");
    expect(unitAmountDecimal(0)).toBe("0");
  });
});

// ---------------------------------------------------------------------------
// Checkout, the portal, and usage
// ---------------------------------------------------------------------------

describe("createCheckout", () => {
  it("asks for a metered subscription and carries the tier both ways", async () => {
    const provider = fakeProvider({
      "POST /v1/checkout/sessions": {
        body: { id: "cs_made", url: "https://checkout.example/cs_made" },
      },
    });
    const result = await adapter(provider.fetch).createCheckout({
      price: "price_made",
      tier: "standard",
      environment: "demo",
      successUrl: "https://demo.nomankind.ai/keys/claim?session={CHECKOUT_SESSION_ID}",
      cancelUrl: "https://demo.nomankind.ai/api",
      email: "reader@example.com",
    });
    expect(result).toEqual({
      ok: true,
      value: { id: "cs_made", url: "https://checkout.example/cs_made" },
    });

    const call = provider.seen[0]!;
    expect(call.method).toBe("POST");
    expect(call.path).toBe("/v1/checkout/sessions");
    expect(call.authorization).toBe(`Bearer ${SECRET_KEY}`);
    expect(call.idempotency).toBe(IDEMPOTENCY);
    expect([...call.body!.keys()].sort()).toEqual([
      "cancel_url",
      "customer_email",
      "line_items[0][price]",
      "metadata[environment]",
      "metadata[tier]",
      "mode",
      "subscription_data[metadata][environment]",
      "subscription_data[metadata][tier]",
      "success_url",
    ]);
    expect(call.body!.get("mode")).toBe("subscription");
    expect(call.body!.get("line_items[0][price]")).toBe("price_made");
    // The tier is on the session and on the subscription, because the claim
    // door reads one and the webhook door may only ever see the other.
    expect(call.body!.get("metadata[tier]")).toBe("standard");
    expect(call.body!.get("subscription_data[metadata][tier]")).toBe("standard");
  });

  it("leaves the email out when the caller gave none", async () => {
    const provider = fakeProvider({
      "POST /v1/checkout/sessions": { body: { id: "cs", url: "https://x/y" } },
    });
    await adapter(provider.fetch).createCheckout({
      price: "price_made",
      tier: "standard",
      environment: "demo",
      successUrl: "https://demo.nomankind.ai/keys/claim",
      cancelUrl: "https://demo.nomankind.ai/api",
    });
    expect(provider.seen[0]!.body!.has("customer_email")).toBe(false);
  });
});

describe("retrieveCheckout", () => {
  const SESSION = {
    id: "cs_made",
    status: "complete",
    mode: "subscription",
    subscription: { id: "sub_made", status: "active" },
    metadata: { tier: "standard", environment: "demo" },
  };

  it("reads a customer that arrived as an id", async () => {
    const provider = fakeProvider({
      "GET /v1/checkout/sessions/cs_made": {
        body: { ...SESSION, customer: "cus_made" },
      },
    });
    const result = await adapter(provider.fetch).retrieveCheckout("cs_made");
    expect(result).toEqual({
      ok: true,
      value: {
        id: "cs_made",
        status: "complete",
        mode: "subscription",
        customer: "cus_made",
        subscription: { id: "sub_made", status: "active" },
        metadata: { tier: "standard", environment: "demo" },
      },
    });
    const call = provider.seen[0]!;
    expect(call.method).toBe("GET");
    expect(call.path).toBe("/v1/checkout/sessions/cs_made?expand[]=subscription");
    expect(call.authorization).toBe(`Bearer ${SECRET_KEY}`);
    expect(call.idempotency).toBeNull();
  });

  it("reads a customer that arrived expanded", async () => {
    const provider = fakeProvider({
      "GET /v1/checkout/sessions/cs_made": {
        body: {
          ...SESSION,
          customer: { id: "cus_made", email: "reader@example.com" },
        },
      },
    });
    const result = await adapter(provider.fetch).retrieveCheckout("cs_made");
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.value.customer).toBe("cus_made");
    // The email came back on the wire and is not carried anywhere: this adapter
    // reads ids and statuses, and nothing about a person.
    expect(JSON.stringify(result.value)).not.toContain("reader@example.com");
  });

  it("reads an unpaid session as itself rather than guessing", async () => {
    const provider = fakeProvider({
      "GET /v1/checkout/sessions/cs_open": {
        body: {
          id: "cs_open",
          status: "open",
          mode: "subscription",
          customer: null,
          subscription: null,
          metadata: {},
        },
      },
    });
    const result = await adapter(provider.fetch).retrieveCheckout("cs_open");
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.value.status).toBe("open");
    expect(result.value.subscription).toBeNull();
    expect(result.value.customer).toBeNull();
  });

  it("refuses a body missing a field it needs", async () => {
    const provider = fakeProvider({
      "GET /v1/checkout/sessions/cs_odd": { body: { id: "cs_odd" } },
    });
    const result = await adapter(provider.fetch).retrieveCheckout("cs_odd");
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.refusal).toBe("bad_response");
    carriesNoSecret(result);
  });
});

describe("createPortal", () => {
  it("asks for the customer's own page and nothing else", async () => {
    const provider = fakeProvider({
      "POST /v1/billing_portal/sessions": {
        body: { url: "https://billing.example/session" },
      },
    });
    const result = await adapter(provider.fetch).createPortal(
      "cus_made",
      "https://demo.nomankind.ai/api",
    );
    expect(result).toEqual({
      ok: true,
      value: { url: "https://billing.example/session" },
    });
    const call = provider.seen[0]!;
    expect(call.method).toBe("POST");
    expect(call.path).toBe("/v1/billing_portal/sessions");
    expect(call.idempotency).toBe(IDEMPOTENCY);
    expect([...call.body!.keys()].sort()).toEqual(["customer", "return_url"]);
    expect(call.body!.get("customer")).toBe("cus_made");
  });
});

describe("reportUsage", () => {
  it("sends the day's reads with the identifier that makes it idempotent", async () => {
    const provider = fakeProvider({
      "POST /v1/billing/meter_events": {
        body: { identifier: "demo:2026-09-11:key_abc" },
      },
    });
    const result = await adapter(provider.fetch).reportUsage({
      customer: "cus_made",
      value: 42,
      identifier: "demo:2026-09-11:key_abc",
      timestamp: UNIX,
    });
    expect(result).toEqual({
      ok: true,
      value: { id: "demo:2026-09-11:key_abc" },
    });
    const call = provider.seen[0]!;
    expect(call.method).toBe("POST");
    expect(call.path).toBe("/v1/billing/meter_events");
    expect(call.idempotency).toBe(IDEMPOTENCY);
    expect([...call.body!.keys()].sort()).toEqual([
      "event_name",
      "identifier",
      "payload[stripe_customer_id]",
      "payload[value]",
      "timestamp",
    ]);
    expect(call.body!.get("event_name")).toBe(STRIPE.meter_event_name);
    expect(call.body!.get("payload[value]")).toBe("42");
    expect(call.body!.get("timestamp")).toBe(String(UNIX));
  });
});

// ---------------------------------------------------------------------------
// How it refuses
// ---------------------------------------------------------------------------

describe("refusals", () => {
  it("names the provider's error type and code and never its message", async () => {
    const provider = fakeProvider({
      "POST /v1/checkout/sessions": {
        status: 402,
        body: {
          error: {
            type: "card_error",
            code: "card_declined",
            message: `the card of reader@example.com was declined using ${SECRET_KEY}`,
          },
        },
      },
    });
    const result = await adapter(provider.fetch).createCheckout({
      price: "price_made",
      tier: "standard",
      environment: "demo",
      successUrl: "https://demo.nomankind.ai/keys/claim",
      cancelUrl: "https://demo.nomankind.ai/api",
    });
    expect(result).toEqual({
      ok: false,
      refusal: "provider_error",
      detail: "402 card_error:card_declined",
    });
    carriesNoSecret(result);
    expect(JSON.stringify(result)).not.toContain("reader@example.com");
  });

  it("says network and nothing at all when the fetch threw", async () => {
    const call = (async (): Promise<Response> => {
      throw new Error(`connect failed carrying authorization Bearer ${SECRET_KEY}`);
    }) as typeof fetch;
    const result = await adapter(call).createPortal("cus", "https://x/y");
    expect(result).toEqual({ ok: false, refusal: "network" });
    carriesNoSecret(result);
  });

  it("says bad_response when the body is not JSON", async () => {
    const call = (async (): Promise<Response> =>
      new Response("<html>gateway</html>", { status: 200 })) as typeof fetch;
    const result = await adapter(call).createPortal("cus", "https://x/y");
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.refusal).toBe("bad_response");
  });
});

// ---------------------------------------------------------------------------
// The webhook signature
// ---------------------------------------------------------------------------

const EVENT = {
  id: "evt_made",
  type: "customer.subscription.updated",
  created: UNIX,
  data: { object: { id: "sub_made", status: "past_due" } },
};
const RAW_BODY = JSON.stringify(EVENT);

/** The HMAC a provider would sign with, computed here independently. */
async function sign(
  secret: string,
  timestamp: number,
  body: string,
): Promise<string> {
  const encoder = new TextEncoder();
  const key = await globalThis.crypto.subtle.importKey(
    "raw",
    encoder.encode(secret) as unknown as BufferSource,
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

/** An adapter with a webhook secret and no fetch it could possibly need. */
function verifier(webhookSecret?: string): StripeAdapter {
  const call = (async (): Promise<Response> => {
    throw new Error("verifyWebhook must not reach the network");
  }) as typeof fetch;
  return new StripeAdapter({
    secretKey: SECRET_KEY,
    ...(webhookSecret === undefined ? {} : { webhookSecret }),
    fetch: call,
  });
}

describe("verifyWebhook", () => {
  it("accepts a message signed with the destination's secret", async () => {
    const header = `t=${UNIX},v1=${await sign(WEBHOOK_SECRET, UNIX, RAW_BODY)}`;
    const result = await verifier(WEBHOOK_SECRET).verifyWebhook(
      RAW_BODY,
      header,
      NOW,
    );
    expect(result).toEqual({ ok: true, value: EVENT });
  });

  it("accepts a header carrying two v1 signatures", async () => {
    // A destination rotating its secret signs with both for a while, and a
    // verifier that only read the first would refuse every message in that
    // window.
    const wrong = await sign("whsec_the_old_one", UNIX, RAW_BODY);
    const right = await sign(WEBHOOK_SECRET, UNIX, RAW_BODY);
    const result = await verifier(WEBHOOK_SECRET).verifyWebhook(
      RAW_BODY,
      `t=${UNIX},v1=${wrong},v1=${right}`,
      NOW,
    );
    expect(result.ok).toBe(true);
  });

  it("refuses a signature made with another secret", async () => {
    const header = `t=${UNIX},v1=${await sign("whsec_somebody_else", UNIX, RAW_BODY)}`;
    const result = await verifier(WEBHOOK_SECRET).verifyWebhook(
      RAW_BODY,
      header,
      NOW,
    );
    expect(result).toEqual({
      ok: false,
      refusal: "provider_error",
      detail: "bad_signature",
    });
    carriesNoSecret(result);
  });

  it("refuses a message whose body was edited after it was signed", async () => {
    const header = `t=${UNIX},v1=${await sign(WEBHOOK_SECRET, UNIX, RAW_BODY)}`;
    const edited = RAW_BODY.replace("past_due", "active");
    const result = await verifier(WEBHOOK_SECRET).verifyWebhook(
      edited,
      header,
      NOW,
    );
    expect(result.ok).toBe(false);
  });

  it("refuses a signature older than the tolerance", async () => {
    const stale = UNIX - STRIPE.webhook_tolerance_seconds - 1;
    const header = `t=${stale},v1=${await sign(WEBHOOK_SECRET, stale, RAW_BODY)}`;
    const result = await verifier(WEBHOOK_SECRET).verifyWebhook(
      RAW_BODY,
      header,
      NOW,
    );
    expect(result).toEqual({
      ok: false,
      refusal: "provider_error",
      detail: "stale_signature",
    });
  });

  it("accepts one right at the edge of the tolerance", async () => {
    const edge = UNIX - STRIPE.webhook_tolerance_seconds;
    const header = `t=${edge},v1=${await sign(WEBHOOK_SECRET, edge, RAW_BODY)}`;
    const result = await verifier(WEBHOOK_SECRET).verifyWebhook(
      RAW_BODY,
      header,
      NOW,
    );
    expect(result.ok).toBe(true);
  });

  it("refuses a missing or malformed header", async () => {
    for (const header of [null, "", "nonsense", `t=${UNIX}`, "v1=abc"]) {
      const result = await verifier(WEBHOOK_SECRET).verifyWebhook(
        RAW_BODY,
        header,
        NOW,
      );
      expect([header, result.ok]).toEqual([header, false]);
    }
  });

  it("is unavailable rather than trusting when there is no secret", async () => {
    const header = `t=${UNIX},v1=${await sign(WEBHOOK_SECRET, UNIX, RAW_BODY)}`;
    const result = await verifier().verifyWebhook(RAW_BODY, header, NOW);
    expect(result).toEqual({ ok: false, refusal: "payments_unavailable" });
  });

  it("parses the header's parts and compares in constant time", () => {
    expect(parseSignatureHeader(`t=5,v1=aa,v1=bb`)).toEqual({
      timestamp: 5,
      signatures: ["aa", "bb"],
    });
    expect(parseSignatureHeader("t=notanumber,v1=aa")).toBeNull();
    expect(constantTimeEqual("abcd", "abcd")).toBe(true);
    expect(constantTimeEqual("abcd", "abce")).toBe(false);
    expect(constantTimeEqual("abcd", "abcde")).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// The other two adapters, and the choice between all three
// ---------------------------------------------------------------------------

describe("MockPaymentsAdapter", () => {
  /** The sixteen hex characters a mock session and its customer are built on. */
  const SUFFIX = "abcd0000abcd0000";
  /** The id a standard checkout is handed: the tier, then that suffix. */
  const SESSION = `mock_cs_standard_${SUFFIX}`;

  it("carries one checkout through to a claimable session", async () => {
    const mock = new MockPaymentsAdapter({ random: () => SUFFIX });
    expect(await mock.ensurePrice("local", "standard")).toEqual({
      ok: true,
      value: { price: "price_mock_standard" },
    });

    const created = await mock.createCheckout({
      price: "price_mock_standard",
      tier: "standard",
      environment: "local",
      successUrl: "https://nomankind.ai/keys/claim?session={CHECKOUT_SESSION_ID}",
      cancelUrl: "https://nomankind.ai/api",
    });
    expect(created).toEqual({
      ok: true,
      value: {
        id: SESSION,
        url: `https://nomankind.ai/keys/claim?session=${SESSION}`,
      },
    });

    expect(await mock.retrieveCheckout(SESSION)).toEqual({
      ok: true,
      value: {
        id: SESSION,
        status: "complete",
        mode: "subscription",
        customer: `mock_cus_${SUFFIX}`,
        subscription: { id: `mock_sub_${SUFFIX}`, status: "active" },
        metadata: { tier: "standard" },
      },
    });
  });

  it("reads back a session a different instance made", async () => {
    // The Worker builds a fresh adapter for every request, so the instance that
    // answers the claim is never the instance that made the session. The id
    // carries everything the claim needs, so the second instance answers the
    // same thing the first one would have.
    const first = new MockPaymentsAdapter({ random: () => SUFFIX });
    const created = await first.createCheckout({
      price: "price_mock_high",
      tier: "high",
      environment: "local",
      successUrl: "https://nomankind.ai/keys/claim?session={CHECKOUT_SESSION_ID}",
      cancelUrl: "https://nomankind.ai/api",
    });
    expect(created.ok).toBe(true);
    if (!created.ok) return;

    const second = new MockPaymentsAdapter({ random: () => "ffffffffffffffff" });
    expect(await second.retrieveCheckout(created.value.id)).toEqual(
      await first.retrieveCheckout(created.value.id),
    );
    const claimed = await second.retrieveCheckout(created.value.id);
    expect(claimed.ok).toBe(true);
    if (!claimed.ok) return;
    expect(claimed.value.status).toBe("complete");
    expect(claimed.value.metadata).toEqual({ tier: "high" });
    expect(claimed.value.customer).toBe(`mock_cus_${SUFFIX}`);
  });

  it("reads an id that is not one of its own as expired", async () => {
    const mock = new MockPaymentsAdapter();
    // No suffix at all, and a suffix that is the wrong shape: neither is an id
    // this adapter ever wrote, so neither names a session.
    for (const id of ["mock_cs_nobody", "mock_cs_standard_nothex", "cs_live_1"]) {
      const result = await mock.retrieveCheckout(id);
      expect([id, result.ok]).toEqual([id, true]);
      if (!result.ok) continue;
      expect([id, result.value.status]).toEqual([id, "expired"]);
      expect(result.value.subscription).toBeNull();
    }
  });

  it("records every usage report and accepts only the fixture signature", async () => {
    const mock = new MockPaymentsAdapter();
    await mock.reportUsage({
      customer: "mock_cus_abcd",
      value: 9,
      identifier: "local:2026-09-11:key_abc",
      timestamp: UNIX,
    });
    expect(mock.reported).toEqual([
      {
        customer: "mock_cus_abcd",
        value: 9,
        identifier: "local:2026-09-11:key_abc",
        timestamp: UNIX,
      },
    ]);

    expect(await mock.verifyWebhook(RAW_BODY, "mock", NOW)).toEqual({
      ok: true,
      value: EVENT,
    });
    const refused = await mock.verifyWebhook(RAW_BODY, "t=1,v1=aa", NOW);
    expect(refused.ok).toBe(false);
  });

  it("hands a portal back to where the caller asked to return", async () => {
    const mock = new MockPaymentsAdapter();
    expect(await mock.createPortal("mock_cus_abcd", "https://x/api")).toEqual({
      ok: true,
      value: { url: "https://x/api" },
    });
  });
});

describe("UnavailablePaymentsAdapter", () => {
  it("refuses every call in one word", async () => {
    const stub = new UnavailablePaymentsAdapter();
    const refusal = { ok: false, refusal: "payments_unavailable" };
    expect(await stub.ensurePrice()).toEqual(refusal);
    expect(await stub.createCheckout()).toEqual(refusal);
    expect(await stub.retrieveCheckout()).toEqual(refusal);
    expect(await stub.createPortal()).toEqual(refusal);
    expect(await stub.reportUsage()).toEqual(refusal);
    expect(await stub.verifyWebhook()).toEqual(refusal);
  });
});

describe("paymentsAdapterFor", () => {
  it("takes the credential first, whatever the environment is called", () => {
    expect(
      paymentsAdapterFor({
        ENVIRONMENT: "production",
        STRIPE_SECRET_KEY: SECRET_KEY,
      }).kind,
    ).toBe("stripe");
    expect(
      paymentsAdapterFor({ ENVIRONMENT: "demo", STRIPE_SECRET_KEY: SECRET_KEY })
        .kind,
    ).toBe("stripe");
  });

  it("refuses on production without one, and mocks everywhere else", () => {
    expect(paymentsAdapterFor({ ENVIRONMENT: "production" }).kind).toBe(
      "unavailable",
    );
    // An empty secret is no secret: a binding set to "" must not be read as set.
    expect(
      paymentsAdapterFor({ ENVIRONMENT: "production", STRIPE_SECRET_KEY: "" })
        .kind,
    ).toBe("unavailable");
    expect(paymentsAdapterFor({ ENVIRONMENT: "demo" }).kind).toBe("mock");
    expect(paymentsAdapterFor({ ENVIRONMENT: "local" }).kind).toBe("mock");
  });
});
