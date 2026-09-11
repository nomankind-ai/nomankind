/**
 * The webhook door: the one place the payment provider gets to tell us
 * something.
 *
 * Decision D-078: the provider's event destination posts here, signed. Nothing
 * arrives here that is trusted by default — the signature is checked against the
 * destination's own secret before the body is parsed at all, the timestamp is
 * checked against the tolerance so a captured message cannot be replayed a year
 * later, and the event id is checked against what we have already acted on so a
 * retry does not cancel a key that was paid for again in between.
 *
 * What a message may change is exactly one column: a key's status. Never a
 * tier, never a counter, never a quota, and never the log — a payment provider
 * has no business writing an event into nomankind's record, and this door
 * cannot. Ids and statuses are read out of the body and nothing else is.
 *
 * Every understood message answers 200, including the ones deliberately
 * ignored, because a provider that gets anything else retries and a retry of a
 * message we correctly ignored is noise forever. What it answers 200 with says
 * which it was, so the maintainer reading the provider's dashboard can tell an
 * applied message from an ignored one.
 *
 * No wall clock: `deps.now` is the instant the router read once. No policy
 * number lives here — the bare integers are HTTP status codes and the tolerance
 * is STRIPE's, applied inside the adapter.
 */

import type { PaymentsAdapter, ProviderEvent } from "../adapters/stripe.js";
import { keyStatusFromSubscription, type KeyStatus } from "../keys.js";
import { STRIPE } from "../policy.js";
import type { D1Like } from "../storage/d1.js";
import {
  keyBySubscription,
  putStripeEvent,
  setKeyStatus,
  stripeEventSeen,
} from "../storage/keys.js";
import type { Env } from "./env.js";
import {
  StorageUnreachable,
  guardDatabase,
  json,
  methodNotAllowed,
  refuse,
} from "./registry.js";

/** What this door takes besides its bindings: the instant and the provider. */
export interface StripeWebhookDeps {
  readonly now: Date;
  readonly payments: PaymentsAdapter;
}

/** What came of one message, as the `stripe_events` row records it. */
type Outcome = "applied" | "ignored" | "unknown_subscription";

/**
 * A subscription id out of an event's object, whether it arrived as an id or as
 * the expanded object. An invoice names its subscription; a subscription names
 * itself.
 */
function subscriptionId(
  object: Record<string, unknown>,
  field: "id" | "subscription",
): string | null {
  const value = object[field];
  if (typeof value === "string") return value;
  if (
    typeof value === "object" &&
    value !== null &&
    typeof (value as { id?: unknown }).id === "string"
  ) {
    return (value as { id: string }).id;
  }
  return null;
}

/**
 * Apply one verified, unseen event.
 *
 * Five types and a default, and the default is to ignore: a message type this
 * door has never heard of must not be guessed at, and `checkout.session.completed`
 * is ignored on purpose — the key is minted by the claim door, from a session
 * the reader is holding, never by a message arriving from outside.
 */
async function apply(
  db: D1Like,
  event: ProviderEvent,
  now: Date,
): Promise<Outcome> {
  const object = event.data.object;

  let subscription: string | null = null;
  let status: KeyStatus | null = null;

  switch (event.type) {
    case "customer.subscription.created":
    case "customer.subscription.updated": {
      subscription = subscriptionId(object, "id");
      const reported = object["status"];
      status =
        typeof reported === "string"
          ? keyStatusFromSubscription(reported)
          : null;
      break;
    }
    case "customer.subscription.deleted": {
      subscription = subscriptionId(object, "id");
      status = "canceled";
      break;
    }
    case "invoice.payment_failed": {
      subscription = subscriptionId(object, "subscription");
      status = "past_due";
      break;
    }
    case "invoice.paid": {
      subscription = subscriptionId(object, "subscription");
      // An invoice that cleared restores a key the bill had suspended, and says
      // nothing about a key that was canceled: a canceled subscription is over,
      // and a payment against it is not our business to reinstate.
      status = "active";
      break;
    }
    default:
      return "ignored";
  }

  if (subscription === null || status === null) return "ignored";

  const key = await keyBySubscription(db, subscription);
  if (key === null) return "unknown_subscription";

  if (event.type === "invoice.paid" && key.status !== "past_due") {
    return "ignored";
  }
  if (key.status === status) return "ignored";

  await setKeyStatus(db, key.id, status, now.toISOString());
  return "applied";
}

async function route(
  request: Request,
  db: D1Like,
  deps: StripeWebhookDeps,
): Promise<Response | null> {
  const { pathname } = new URL(request.url);
  if (pathname !== STRIPE.webhook_path) return null;
  if (request.method !== "POST") return methodNotAllowed("POST");

  if (deps.payments.kind === "unavailable") {
    return refuse(503, "payments_unavailable");
  }

  // The raw bytes, exactly as they arrived: the signature covers the body
  // verbatim, so parsing it first and re-serializing would break every
  // signature that was ever correct.
  const rawBody = await request.text();
  const verified = await deps.payments.verifyWebhook(
    rawBody,
    request.headers.get("stripe-signature"),
    deps.now,
  );
  if (!verified.ok) {
    if (verified.refusal === "payments_unavailable") {
      return refuse(503, "payments_unavailable");
    }
    // One word for every way a message failed to prove it was the provider's:
    // a forged digest, a stale timestamp and a header that was not a signature
    // are the same answer to whoever sent it.
    return refuse(400, "bad_signature");
  }

  const event = verified.value;
  if (await stripeEventSeen(db, event.id)) {
    return json({ received: true, outcome: "duplicate" }, 200);
  }

  const outcome = await apply(db, event, deps.now);
  await putStripeEvent(db, {
    id: event.id,
    type: event.type,
    receivedAt: deps.now.toISOString(),
    outcome,
  });
  return json({ received: true, outcome }, 200);
}

/**
 * Route one request to the webhook door, or answer null when the path is not
 * ours. Storage failures become the same JSON 503 every other route gives.
 */
export async function handleStripeWebhook(
  request: Request,
  env: Env,
  deps: StripeWebhookDeps,
): Promise<Response | null> {
  const db = guardDatabase(env.DB);
  try {
    return await route(request, db, deps);
  } catch (error) {
    if (error instanceof StorageUnreachable) {
      // The message only: no binding contents, no request data, no secret.
      console.error(`stripe: storage unreachable: ${error.message}`);
      return refuse(503, "storage_unreachable");
    }
    throw error;
  }
}
