/**
 * The payments adapter: the paid loop's one way out to a payment provider.
 *
 * Whitepaper Section 9, Money: "The log is free to read at low volume, forever.
 * Revenue comes from high-rate API access, structured feeds and webhooks,
 * change alerts." Somebody has to take the money for that, and decision D-078
 * says who and how: Stripe, in test mode from the start, over its REST API with
 * `fetch` and signed webhooks, with no SDK — the approved dependency baseline
 * (D-011) takes no new package and an SDK would be one.
 *
 * The shape is the mirror adapter's, for the same reasons. The kernel names the
 * interface; the implementations below do network I/O and nothing in the kernel
 * may. Nothing here throws: every failure is a named refusal the door reports,
 * because a checkout that did not happen is a thing to say out loud rather than
 * a stack trace in a log nobody reads. The secret key and the webhook signing
 * secret are Worker secrets (D-016): they appear in exactly one header and one
 * HMAC and in no refusal, no return value and nothing a caller could log — and
 * neither does a request header, because a fetch's own error can carry the
 * headers it sent and one of ours is the credential.
 *
 * The platform fetch goes out with no receiver, for the reason every adapter
 * here does it (workerd's "Illegal invocation", the M13 lesson). Bodies are
 * form-encoded with Stripe's bracket keys, every POST carries an
 * `Idempotency-Key`, and no `Stripe-Version` header is sent at all: the
 * account's own default applies, so the wire shape moves when the maintainer
 * moves it on the dashboard and never because a string in this file went stale.
 *
 * No policy number lives here: the addresses, the meter's event name, the
 * lookup-key prefix, the currency and the webhook tolerance are STRIPE's in
 * src/policy.ts, the price is READ_PRICE_MICROS_PER_READ, and the timeout is
 * FETCH_TIMEOUT_MS. WebCrypto only, never `node:crypto`.
 */

import { withDeadline } from "./timeout.js";
import {
  FETCH_TIMEOUT_MS,
  RATE_TIERS,
  READ_PRICE_MICROS_PER_READ,
  STRIPE,
} from "../policy.js";

/** Which payments track an environment runs. */
export type PaymentsKind = "stripe" | "mock" | "unavailable";

/**
 * What a call answers: the value, or a refusal in one of four words.
 *
 * `detail` is for a maintainer reading the status board, so it carries a status
 * and the provider's own error type and code and never a message: a message can
 * echo the request back, and the request carried a customer's email.
 */
export type PaymentsResult<T> =
  | { ok: true; value: T }
  | {
      ok: false;
      refusal: "payments_unavailable" | "provider_error" | "bad_response" | "network";
      detail?: string;
    };

/** A checkout session, in the fields the claim door actually reads. */
export interface CheckoutSession {
  id: string;
  /** open | complete | expired. */
  status: string;
  mode: string;
  customer: string | null;
  subscription: { id: string; status: string } | null;
  metadata: Record<string, string>;
}

/** One provider event, as the webhook door reads it. */
export interface ProviderEvent {
  id: string;
  type: string;
  created: number;
  data: { object: Record<string, unknown> };
}

/**
 * Everything the paid loop asks a payment provider for.
 *
 * Six calls and no more: make sure the price exists, start a checkout, read the
 * finished checkout, open the customer's own portal, report a day's metered
 * reads, and verify a webhook. Nothing here reads a balance, moves money, or
 * takes an instruction from the provider that is not one of those.
 */
export interface PaymentsAdapter {
  readonly kind: PaymentsKind;
  ensurePrice(
    environment: string,
    tier: string,
  ): Promise<PaymentsResult<{ price: string }>>;
  createCheckout(input: {
    price: string;
    tier: string;
    environment: string;
    successUrl: string;
    cancelUrl: string;
    email?: string;
  }): Promise<PaymentsResult<{ id: string; url: string }>>;
  retrieveCheckout(id: string): Promise<PaymentsResult<CheckoutSession>>;
  createPortal(
    customer: string,
    returnUrl: string,
  ): Promise<PaymentsResult<{ url: string }>>;
  reportUsage(input: {
    customer: string;
    value: number;
    identifier: string;
    /** Unix seconds. */
    timestamp: number;
  }): Promise<PaymentsResult<{ id: string }>>;
  verifyWebhook(
    rawBody: string,
    signatureHeader: string | null,
    now: Date,
  ): Promise<PaymentsResult<ProviderEvent>>;
}

// ---------------------------------------------------------------------------
// Shared shapes
// ---------------------------------------------------------------------------

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function unavailable<T>(): PaymentsResult<T> {
  return { ok: false, refusal: "payments_unavailable" };
}

function badResponse<T>(detail: string): PaymentsResult<T> {
  return { ok: false, refusal: "bad_response", detail };
}

/**
 * The price, in the unit Stripe's `unit_amount_decimal` takes: cents, with up to
 * four decimal places.
 *
 * READ_PRICE_MICROS_PER_READ is micro-USD per read, and a cent is ten thousand
 * micros, so the conversion is a division by 10000 — done in integers and
 * assembled as a string rather than through a float, because 500 / 10000 is
 * exactly the kind of number a float writes as 0.05000000000000001.
 */
export function unitAmountDecimal(micros: number): string {
  const CENTS_IN_MICROS = 10_000;
  const whole = Math.floor(micros / CENTS_IN_MICROS);
  const fraction = String(micros % CENTS_IN_MICROS)
    .padStart(4, "0")
    .replace(/0+$/, "");
  return fraction === "" ? String(whole) : `${whole}.${fraction}`;
}

/** A form body, in Stripe's bracket-key encoding. */
function form(fields: Record<string, string | number>): string {
  const body = new URLSearchParams();
  for (const [key, value] of Object.entries(fields)) {
    body.set(key, String(value));
  }
  return body.toString();
}

/** A metadata object, keeping only the string values a subscriber set. */
function stringMap(value: unknown): Record<string, string> {
  if (!isRecord(value)) return {};
  const out: Record<string, string> = {};
  for (const [key, entry] of Object.entries(value)) {
    if (typeof entry === "string") out[key] = entry;
  }
  return out;
}

// ---------------------------------------------------------------------------
// The provider
// ---------------------------------------------------------------------------

/** What the adapter is built with. The two secrets never leave the instance. */
export interface StripeOptions {
  /** The provider's secret key. A Worker secret; never logged or returned. */
  readonly secretKey: string;
  /** The event destination's signing secret, when this deployment has one. */
  readonly webhookSecret?: string;
  /** The fetch to call. Tests pass a fake; the Worker passes none. */
  readonly fetch?: typeof fetch;
  /** Where an `Idempotency-Key` comes from. Tests pin it; the Worker does not. */
  readonly random?: () => string;
  /**
   * How long one call to the provider may take. The policy number everywhere
   * but in a test, which passes a small window of its own rather than waiting
   * out the real one.
   */
  readonly timeoutMs?: number;
}

/** One call's answer: the parsed body, or the refusal that ends the caller. */
type Answer =
  | { ok: true; body: unknown }
  | { ok: false; refusal: PaymentsResult<never> };

/**
 * What a body that is not JSON reads as: a marker of its own, because `null`
 * and `undefined` are both bodies Stripe can really send.
 */
const UNPARSABLE = Symbol("unparsable");

export class StripeAdapter implements PaymentsAdapter {
  readonly kind = "stripe";

  readonly #secretKey: string;
  readonly #webhookSecret: string | null;
  readonly #fetch: typeof fetch;
  readonly #random: () => string;
  readonly #timeoutMs: number;

  constructor(options: StripeOptions) {
    this.#secretKey = options.secretKey;
    this.#webhookSecret =
      options.webhookSecret === undefined || options.webhookSecret === ""
        ? null
        : options.webhookSecret;
    this.#fetch = options.fetch ?? globalThis.fetch.bind(globalThis);
    this.#random =
      options.random ?? ((): string => globalThis.crypto.randomUUID());
    this.#timeoutMs = options.timeoutMs ?? FETCH_TIMEOUT_MS;
  }

  /**
   * Every call goes through here: the credential, the timeout, no receiver.
   *
   * A POST carries a form body, a content type and an `Idempotency-Key`, so a
   * retry of a call that may already have happened cannot make a second
   * subscription. A GET carries none of the three.
   */
  async #call(
    method: "GET" | "POST",
    path: string,
    body?: Record<string, string | number>,
  ): Promise<Answer> {
    const call = this.#fetch;
    // One window over the request and the body, on a timer that is cleared when
    // they are done: a pending `AbortSignal.timeout` cannot be cleared and holds
    // the whole invocation open on workerd (src/adapters/timeout.ts).
    let answered: { status: number; ok: boolean; parsed: unknown } | null;
    try {
      answered = await withDeadline(this.#timeoutMs, async (signal) => {
        const response = await call(`${STRIPE.api}${path}`, {
          method,
          headers: {
            authorization: `Bearer ${this.#secretKey}`,
            ...(body === undefined
              ? {}
              : {
                  "content-type": "application/x-www-form-urlencoded",
                  "idempotency-key": this.#random(),
                }),
          },
          ...(body === undefined ? {} : { body: form(body) }),
          signal,
        });
        const { status, ok } = response;
        try {
          return { status, ok, parsed: (await response.json()) as unknown };
        } catch {
          return { status, ok, parsed: UNPARSABLE };
        }
      });
    } catch {
      // Nothing about the throw travels: a fetch's error can carry the
      // request's own headers, and one of ours is the secret key.
      return { ok: false, refusal: { ok: false, refusal: "network" } };
    }

    const { status, ok, parsed } = answered;
    if (parsed === UNPARSABLE) {
      return {
        ok: false,
        refusal: badResponse(`${status} unparsable`),
      };
    }

    if (!ok) {
      return {
        ok: false,
        refusal: {
          ok: false,
          refusal: "provider_error",
          detail: providerDetail(status, parsed),
        },
      };
    }
    return { ok: true, body: parsed };
  }

  async ensurePrice(
    environment: string,
    tier: string,
  ): Promise<PaymentsResult<{ price: string }>> {
    const lookupKey = `${STRIPE.price_lookup_prefix}${environment}-${tier}`;

    const found = await this.#call(
      "GET",
      `/v1/prices?lookup_keys[]=${encodeURIComponent(lookupKey)}&active=true&limit=1`,
    );
    if (!found.ok) return found.refusal;
    const existing = firstDataId(found.body);
    if (existing === undefined) return badResponse("prices list");
    if (existing !== null) return { ok: true, value: { price: existing } };

    // Nothing at that lookup key yet, so the three objects a metered price
    // needs are made in order: the meter the usage is reported to, the product
    // the price hangs off, and the price itself.
    const meter = await this.#ensureMeter();
    if (typeof meter !== "string") return meter;

    const display = RATE_TIERS[tier]?.name ?? tier;
    const product = await this.#call("POST", "/v1/products", {
      name: `nomankind ${display} tier (${environment})`,
      "metadata[tier]": tier,
      "metadata[environment]": environment,
    });
    if (!product.ok) return product.refusal;
    const productId = idOf(product.body);
    if (productId === null) return badResponse("product");

    const price = await this.#call("POST", "/v1/prices", {
      product: productId,
      currency: STRIPE.currency,
      "recurring[interval]": "month",
      "recurring[usage_type]": "metered",
      "recurring[meter]": meter,
      billing_scheme: "per_unit",
      unit_amount_decimal: unitAmountDecimal(READ_PRICE_MICROS_PER_READ),
      lookup_key: lookupKey,
      transfer_lookup_key: "true",
    });
    if (!price.ok) return price.refusal;
    const priceId = idOf(price.body);
    if (priceId === null) return badResponse("price");
    return { ok: true, value: { price: priceId } };
  }

  /**
   * The meter every read is reported to, made once and found thereafter.
   *
   * Found by its event name rather than remembered in a table, because the
   * provider is the record of what exists there and a table of ours would be a
   * second one to keep in step.
   */
  async #ensureMeter(): Promise<string | PaymentsResult<never>> {
    const meters = await this.#call(
      "GET",
      "/v1/billing/meters?status=active&limit=100",
    );
    if (!meters.ok) return meters.refusal;
    const list = dataOf(meters.body);
    if (list === null) return badResponse("meters list");
    for (const row of list) {
      if (
        isRecord(row) &&
        row["event_name"] === STRIPE.meter_event_name &&
        typeof row["id"] === "string"
      ) {
        return row["id"];
      }
    }

    const made = await this.#call("POST", "/v1/billing/meters", {
      display_name: "nomankind reads",
      event_name: STRIPE.meter_event_name,
      "default_aggregation[formula]": "sum",
      "customer_mapping[event_payload_key]": "stripe_customer_id",
      "customer_mapping[type]": "by_id",
      "value_settings[event_payload_key]": "value",
    });
    if (!made.ok) return made.refusal;
    const id = idOf(made.body);
    return id === null ? badResponse("meter") : id;
  }

  async createCheckout(input: {
    price: string;
    tier: string;
    environment: string;
    successUrl: string;
    cancelUrl: string;
    email?: string;
  }): Promise<PaymentsResult<{ id: string; url: string }>> {
    const answer = await this.#call("POST", "/v1/checkout/sessions", {
      mode: "subscription",
      "line_items[0][price]": input.price,
      success_url: input.successUrl,
      cancel_url: input.cancelUrl,
      "metadata[tier]": input.tier,
      "metadata[environment]": input.environment,
      "subscription_data[metadata][tier]": input.tier,
      "subscription_data[metadata][environment]": input.environment,
      ...(input.email === undefined ? {} : { customer_email: input.email }),
    });
    if (!answer.ok) return answer.refusal;
    const body = answer.body;
    if (!isRecord(body)) return badResponse("checkout");
    const id = body["id"];
    const url = body["url"];
    if (typeof id !== "string" || typeof url !== "string") {
      return badResponse("checkout");
    }
    return { ok: true, value: { id, url } };
  }

  async retrieveCheckout(id: string): Promise<PaymentsResult<CheckoutSession>> {
    const answer = await this.#call(
      "GET",
      `/v1/checkout/sessions/${encodeURIComponent(id)}?expand[]=subscription`,
    );
    if (!answer.ok) return answer.refusal;
    return toCheckoutSession(answer.body);
  }

  async createPortal(
    customer: string,
    returnUrl: string,
  ): Promise<PaymentsResult<{ url: string }>> {
    const answer = await this.#call("POST", "/v1/billing_portal/sessions", {
      customer,
      return_url: returnUrl,
    });
    if (!answer.ok) return answer.refusal;
    const url = isRecord(answer.body) ? answer.body["url"] : undefined;
    if (typeof url !== "string") return badResponse("portal");
    return { ok: true, value: { url } };
  }

  async reportUsage(input: {
    customer: string;
    value: number;
    identifier: string;
    timestamp: number;
  }): Promise<PaymentsResult<{ id: string }>> {
    const answer = await this.#call("POST", "/v1/billing/meter_events", {
      event_name: STRIPE.meter_event_name,
      "payload[stripe_customer_id]": input.customer,
      "payload[value]": input.value,
      identifier: input.identifier,
      timestamp: input.timestamp,
    });
    if (!answer.ok) return answer.refusal;
    const body = answer.body;
    if (!isRecord(body)) return badResponse("meter event");
    // A meter event is named by the identifier it was sent with, and some
    // shapes also carry an id. Either names the thing that was accepted.
    const id = body["id"] ?? body["identifier"];
    if (typeof id !== "string") return badResponse("meter event");
    return { ok: true, value: { id } };
  }

  async verifyWebhook(
    rawBody: string,
    signatureHeader: string | null,
    now: Date,
  ): Promise<PaymentsResult<ProviderEvent>> {
    const secret = this.#webhookSecret;
    if (secret === null) return unavailable();
    return verifySignedWebhook(secret, rawBody, signatureHeader, now);
  }
}

/**
 * `<status> <type>:<code>` from the provider's own error object, and never its
 * message: a message echoes the request, and the request carried an email.
 */
function providerDetail(status: number, body: unknown): string {
  const error = isRecord(body) ? body["error"] : undefined;
  const type =
    isRecord(error) && typeof error["type"] === "string"
      ? error["type"]
      : "unknown";
  const code =
    isRecord(error) && typeof error["code"] === "string"
      ? error["code"]
      : "unknown";
  return `${status} ${type}:${code}`;
}

/** A list body's `data` array, or null when the body is not a list. */
function dataOf(body: unknown): unknown[] | null {
  if (!isRecord(body)) return null;
  const data = body["data"];
  return Array.isArray(data) ? data : null;
}

/**
 * The first id of a list body: a string when the list holds something, null
 * when it is empty, and undefined when the body was not a list at all — three
 * answers because "no price yet" and "that was not a price list" are different
 * things to do next.
 */
function firstDataId(body: unknown): string | null | undefined {
  const data = dataOf(body);
  if (data === null) return undefined;
  const first = data[0];
  if (first === undefined) return null;
  return isRecord(first) && typeof first["id"] === "string"
    ? first["id"]
    : undefined;
}

/** An object body's id. */
function idOf(body: unknown): string | null {
  if (!isRecord(body)) return null;
  const id = body["id"];
  return typeof id === "string" ? id : null;
}

/**
 * A checkout session body, in our shape.
 *
 * `customer` arrives as an id or as the expanded object depending on how the
 * session was made, so both are read. `subscription` is asked for expanded, so
 * an object is what a paid session gives; null is the honest answer for a
 * session that has not paid, and anything else is a body we did not understand.
 */
function toCheckoutSession(body: unknown): PaymentsResult<CheckoutSession> {
  if (!isRecord(body)) return badResponse("checkout session");
  const id = body["id"];
  const status = body["status"];
  const mode = body["mode"];
  if (
    typeof id !== "string" ||
    typeof status !== "string" ||
    typeof mode !== "string"
  ) {
    return badResponse("checkout session");
  }

  const rawCustomer = body["customer"];
  let customer: string | null = null;
  if (typeof rawCustomer === "string") customer = rawCustomer;
  else if (isRecord(rawCustomer) && typeof rawCustomer["id"] === "string") {
    customer = rawCustomer["id"];
  }

  const rawSubscription = body["subscription"];
  let subscription: { id: string; status: string } | null = null;
  if (rawSubscription !== null && rawSubscription !== undefined) {
    if (
      !isRecord(rawSubscription) ||
      typeof rawSubscription["id"] !== "string" ||
      typeof rawSubscription["status"] !== "string"
    ) {
      return badResponse("checkout subscription");
    }
    subscription = {
      id: rawSubscription["id"],
      status: rawSubscription["status"],
    };
  }

  return {
    ok: true,
    value: {
      id,
      status,
      mode,
      customer,
      subscription,
      metadata: stringMap(body["metadata"]),
    },
  };
}

// ---------------------------------------------------------------------------
// The webhook signature
// ---------------------------------------------------------------------------

/** The signature header, parsed: the timestamp and every v1 digest it carries. */
export function parseSignatureHeader(
  header: string,
): { timestamp: number; signatures: string[] } | null {
  let timestamp: number | null = null;
  const signatures: string[] = [];
  for (const part of header.split(",")) {
    const at = part.indexOf("=");
    if (at < 0) continue;
    const name = part.slice(0, at).trim();
    const value = part.slice(at + 1).trim();
    if (name === "t") {
      const parsed = Number(value);
      if (!Number.isFinite(parsed)) return null;
      timestamp = parsed;
    } else if (name === "v1") {
      signatures.push(value);
    }
  }
  if (timestamp === null || signatures.length === 0) return null;
  return { timestamp, signatures };
}

/** HMAC-SHA256 of the signed payload, as hex. WebCrypto, never `node:crypto`. */
async function hmacHex(secret: string, payload: string): Promise<string> {
  const encoder = new TextEncoder();
  const key = await globalThis.crypto.subtle.importKey(
    "raw",
    encoder.encode(secret) as unknown as BufferSource,
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const signature = await globalThis.crypto.subtle.sign(
    "HMAC",
    key,
    encoder.encode(payload) as unknown as BufferSource,
  );
  let hex = "";
  for (const byte of new Uint8Array(signature)) {
    hex += byte.toString(16).padStart(2, "0");
  }
  return hex;
}

/**
 * Equal, in time that does not depend on where they differ.
 *
 * A comparison that returned early on the first wrong character would tell a
 * caller, by how long it took, how much of a forged digest was right.
 */
export function constantTimeEqual(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let difference = 0;
  for (let index = 0; index < a.length; index += 1) {
    difference |= a.charCodeAt(index) ^ b.charCodeAt(index);
  }
  return difference === 0;
}

/**
 * Verify one webhook: the header's shape, the clock, the digest, and only then
 * the body.
 *
 * The tolerance is checked before the digest so a replay of a message that was
 * genuinely ours, years ago, is refused for being old rather than accepted for
 * being signed.
 */
async function verifySignedWebhook(
  secret: string,
  rawBody: string,
  signatureHeader: string | null,
  now: Date,
): Promise<PaymentsResult<ProviderEvent>> {
  if (signatureHeader === null) {
    return { ok: false, refusal: "provider_error", detail: "missing_signature" };
  }
  const parsed = parseSignatureHeader(signatureHeader);
  if (parsed === null) {
    return { ok: false, refusal: "provider_error", detail: "bad_signature" };
  }

  const skew = Math.abs(Math.floor(now.getTime() / 1000) - parsed.timestamp);
  if (skew > STRIPE.webhook_tolerance_seconds) {
    return { ok: false, refusal: "provider_error", detail: "stale_signature" };
  }

  const expected = await hmacHex(secret, `${parsed.timestamp}.${rawBody}`);
  const matched = parsed.signatures.some((candidate) =>
    constantTimeEqual(candidate, expected),
  );
  if (!matched) {
    return { ok: false, refusal: "provider_error", detail: "bad_signature" };
  }

  return toProviderEvent(rawBody);
}

/** The body, once it is known to be signed. */
function toProviderEvent(rawBody: string): PaymentsResult<ProviderEvent> {
  let parsed: unknown;
  try {
    parsed = JSON.parse(rawBody);
  } catch {
    return badResponse("event");
  }
  if (!isRecord(parsed)) return badResponse("event");
  const id = parsed["id"];
  const type = parsed["type"];
  const created = parsed["created"];
  const data = parsed["data"];
  if (
    typeof id !== "string" ||
    typeof type !== "string" ||
    typeof created !== "number" ||
    !isRecord(data) ||
    !isRecord(data["object"])
  ) {
    return badResponse("event");
  }
  return {
    ok: true,
    value: { id, type, created, data: { object: data["object"] } },
  };
}

// ---------------------------------------------------------------------------
// The mock, and the refusal
// ---------------------------------------------------------------------------

/** One `reportUsage` the mock was asked for, kept so a test can read it back. */
export interface ReportedUsage {
  readonly customer: string;
  readonly value: number;
  readonly identifier: string;
  readonly timestamp: number;
}

/**
 * A mock session id, read back apart: the tier it was bought for, and the
 * sixteen hex characters every id of the pair is built from.
 *
 * A tier slug is lowercase letters, digits and dashes and never an underscore
 * (RATE_TIERS's own keys), so the first underscore after the prefix is the one
 * separator and the parse is unambiguous.
 */
const MOCK_SESSION = /^mock_cs_([a-z][a-z0-9-]*)_([0-9a-f]{16})$/;

/**
 * The provider for a test and for a laptop: nothing leaves the process.
 *
 * The session id *is* the session: the tier it was bought for and the suffix
 * every other id of the pair is built from are written into it, so the claim
 * door reads back exactly what the checkout door made. That matters under
 * workerd rather than only in a test — the Worker builds a fresh adapter for
 * every request, so the claim of a session is answered by a different instance
 * than the one that made it, and an adapter remembering its sessions in a map
 * would answer `unknown_session` for a session it had just handed out.
 *
 * No money is involved at any point, and `verifyWebhook` accepts exactly the
 * header `mock` — a fixture signature, so a test drives the real webhook door
 * without a secret and no deployed adapter can be mistaken for this one.
 */
export class MockPaymentsAdapter implements PaymentsAdapter {
  readonly kind = "mock";

  /** Every metered report this adapter was asked for, in order. */
  readonly reported: ReportedUsage[] = [];

  readonly #random: () => string;

  constructor(options: { random?: () => string } = {}) {
    this.#random =
      options.random ??
      ((): string => globalThis.crypto.randomUUID().replace(/-/g, "").slice(0, 16));
  }

  async ensurePrice(
    _environment: string,
    tier: string,
  ): Promise<PaymentsResult<{ price: string }>> {
    return { ok: true, value: { price: `price_mock_${tier}` } };
  }

  async createCheckout(input: {
    price: string;
    tier: string;
    environment: string;
    successUrl: string;
    cancelUrl: string;
    email?: string;
  }): Promise<PaymentsResult<{ id: string; url: string }>> {
    const id = `mock_cs_${input.tier}_${this.#random()}`;
    return {
      ok: true,
      value: {
        id,
        url: input.successUrl.replace("{CHECKOUT_SESSION_ID}", id),
      },
    };
  }

  async retrieveCheckout(id: string): Promise<PaymentsResult<CheckoutSession>> {
    const parsed = MOCK_SESSION.exec(id);
    if (parsed === null) {
      return {
        ok: true,
        value: {
          id,
          status: "expired",
          mode: "subscription",
          customer: null,
          subscription: null,
          metadata: {},
        },
      };
    }
    const tier = parsed[1]!;
    const suffix = parsed[2]!;
    return {
      ok: true,
      value: {
        id,
        status: "complete",
        mode: "subscription",
        customer: `mock_cus_${suffix}`,
        subscription: { id: `mock_sub_${suffix}`, status: "active" },
        metadata: { tier },
      },
    };
  }

  async createPortal(
    _customer: string,
    returnUrl: string,
  ): Promise<PaymentsResult<{ url: string }>> {
    return { ok: true, value: { url: returnUrl } };
  }

  async reportUsage(input: {
    customer: string;
    value: number;
    identifier: string;
    timestamp: number;
  }): Promise<PaymentsResult<{ id: string }>> {
    this.reported.push({ ...input });
    return { ok: true, value: { id: `mock_mtr_${input.identifier}` } };
  }

  async verifyWebhook(
    rawBody: string,
    signatureHeader: string | null,
    _now: Date,
  ): Promise<PaymentsResult<ProviderEvent>> {
    if (signatureHeader !== "mock") {
      return { ok: false, refusal: "provider_error", detail: "bad_signature" };
    }
    return toProviderEvent(rawBody);
  }
}

/**
 * No key, no payments.
 *
 * It refuses rather than pretending, exactly as the mirror and payout stubs do
 * on production: a checkout that answered with a URL nobody can pay at would be
 * worse than a door that says the paid loop is not configured here.
 */
export class UnavailablePaymentsAdapter implements PaymentsAdapter {
  readonly kind = "unavailable";

  async ensurePrice(): Promise<PaymentsResult<{ price: string }>> {
    return unavailable();
  }

  async createCheckout(): Promise<PaymentsResult<{ id: string; url: string }>> {
    return unavailable();
  }

  async retrieveCheckout(): Promise<PaymentsResult<CheckoutSession>> {
    return unavailable();
  }

  async createPortal(): Promise<PaymentsResult<{ url: string }>> {
    return unavailable();
  }

  async reportUsage(): Promise<PaymentsResult<{ id: string }>> {
    return unavailable();
  }

  async verifyWebhook(): Promise<PaymentsResult<ProviderEvent>> {
    return unavailable();
  }
}

/** The secrets an environment can carry the payment provider's credential in. */
export interface PaymentsEnv {
  readonly ENVIRONMENT: string;
  readonly STRIPE_SECRET_KEY?: string;
  readonly STRIPE_WEBHOOK_SECRET?: string;
}

/** A secret that is actually set: a string, and not the empty one. */
function secret(value: string | undefined): string | null {
  return typeof value === "string" && value !== "" ? value : null;
}

/**
 * Which track this environment runs (decision D-013 as amended, D-078).
 *
 * The credential decides it first: a deployment holding a secret key talks to
 * the provider whatever it is called. Without one, production refuses — a
 * production that minted mock keys would be handing out credentials nobody paid
 * for — and every other environment gets the mock, so demo and a laptop can
 * drive the whole paid loop end to end without a network.
 */
export function paymentsAdapterFor(
  env: PaymentsEnv,
  fetchImpl?: typeof fetch,
): PaymentsAdapter {
  const secretKey = secret(env.STRIPE_SECRET_KEY);
  if (secretKey !== null) {
    const webhookSecret = secret(env.STRIPE_WEBHOOK_SECRET);
    return new StripeAdapter({
      secretKey,
      ...(webhookSecret === null ? {} : { webhookSecret }),
      ...(fetchImpl === undefined ? {} : { fetch: fetchImpl }),
    });
  }
  if (env.ENVIRONMENT === "production") return new UnavailablePaymentsAdapter();
  return new MockPaymentsAdapter();
}
