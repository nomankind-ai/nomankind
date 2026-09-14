/**
 * The webhook door, retired.
 *
 * Decision D-127, "the record is free, no money anywhere": nothing on this
 * deployment is sold, so there is no subscription for a payment provider to
 * report on and no key status a message from outside may change. The door that
 * the provider's event destination used to post to (D-078) stays at its old
 * address and answers 410 Gone to every POST, which is what a retired door
 * says: the address was real, it is not coming back, and a caller should stop.
 *
 * It touches nothing on the way to that answer. No secret is read — the
 * signature is not checked because there is nothing behind the door to protect,
 * and reading a webhook secret to refuse a request would be the one place this
 * Worker still needed one. No body is read: a retired door must not be a place
 * anyone can push bytes through. And no storage is opened, so the answer costs
 * the log a router comparison and nothing else.
 *
 * `POST` alone, still, and every other method is the same 405 it always was: a
 * door that answered 410 to a GET would be saying something different about the
 * method than about the door.
 */

import type { Env } from "./env.js";
import { json, methodNotAllowed, refuse } from "./registry.js";

/**
 * Where the provider's event destination pointed.
 *
 * A literal here rather than a policy constant: this was `STRIPE.webhook_path`
 * while the record was sold, and STRIPE is not policy any more (D-127). What is
 * left is the address of a door that is gone, which belongs with the door.
 */
const RETIRED_WEBHOOK_PATH = "/stripe/webhook";

/** The one word every retired money door is refused in. */
export const RETIRED = "retired";

/**
 * Route one request to the retired webhook door, or answer null when the path
 * is not ours.
 *
 * No deps and no bindings are read, so the signature keeps only what the router
 * passes: a retired door that still asked for a database would still be able to
 * fail because one was missing.
 */
export function handleStripeWebhook(
  request: Request,
  env: Env,
): Response | null {
  void env;
  const { pathname } = new URL(request.url);
  if (pathname !== RETIRED_WEBHOOK_PATH) return null;
  if (request.method !== "POST") return methodNotAllowed("POST");
  return refuse(410, RETIRED);
}

/**
 * The same answer, for the key doors that were the other half of the paid loop.
 *
 * One function so the checkout, the claim, the portal and this door cannot
 * drift into four different refusals for one decision.
 */
export function retiredDoor(): Response {
  return json({ error: RETIRED }, 410);
}
