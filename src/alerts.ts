/**
 * Change alerts, as a kernel object.
 *
 * Whitepaper Section 9, Money: "Revenue comes from high-rate API access,
 * structured feeds and webhooks, change alerts" — and the paid product is
 * "being the fastest true copy, with sub-day freshness, signed receipts, and
 * alerts". An alert is a notification of a moment that is already in the sealed
 * log: six kinds, each one an event anybody can read at `/events`, delivered to
 * an endpoint a key subscribed. Nothing here is a fact of its own, and an alert
 * that was never delivered changes nothing about the record.
 *
 * Pure, except for the one HMAC, which goes through WebCrypto and never
 * `node:crypto` so this file runs unchanged on Workers. No storage, no clock,
 * no network: `src/storage/alerts.ts` holds the endpoints and the deliveries,
 * and `src/worker/alerts.ts` decides what is derived, matched and posted.
 *
 * No policy number lives here. The kinds are ALERT_KINDS's, the endpoint cap,
 * the timeout and the retry ladder are policy's, and this module holds a format
 * tag and nothing else.
 */

import type { Entry } from "./schema.js";
import type { Event } from "./events.js";
import type { AlertKind } from "./policy.js";

/**
 * What one endpoint asked to hear about. Every field is null for "any", so an
 * endpoint that named nothing hears every alert on every entry.
 *
 * The three strings are matched on equality and never on a prefix: a subject is
 * a name under the domain's own convention, and a filter that matched prefixes
 * would quietly subscribe an endpoint to subjects nobody had heard of when it
 * was registered.
 */
export interface AlertFilter {
  domain: string | null;
  subject: string | null;
  category: string | null;
  kinds: readonly AlertKind[] | null;
}

/** Whether one alert passes one endpoint's filter. */
export function alertMatches(
  filter: AlertFilter,
  alert: {
    domain: string;
    subject: string;
    category: string;
    kind: AlertKind;
  },
): boolean {
  if (filter.domain !== null && filter.domain !== alert.domain) return false;
  if (filter.subject !== null && filter.subject !== alert.subject) return false;
  if (filter.category !== null && filter.category !== alert.category) {
    return false;
  }
  if (filter.kinds !== null && !filter.kinds.includes(alert.kind)) return false;
  return true;
}

/**
 * The body one delivery carries, and the bytes the signature covers.
 *
 * Everything in it is public: the entry is already at `/entries/{id}` and the
 * event is already at `/events`. What the alert adds is the covering seal and
 * the two paths, so a subscriber woken at three in the morning can check the
 * claim it was told about without asking this Worker what it means.
 *
 * `links` are paths and not absolute URLs, because the sweep that builds a body
 * has no public origin to spell: a subscriber knows the host it subscribed to.
 */
export interface AlertBody {
  /** The delivery's own id, so a retry is recognisable as the same alert. */
  id: string;
  kind: AlertKind;
  entry_id: string;
  domain: string;
  subject: string;
  category: string;
  /** The entry's status as it was derived at the event's own position. */
  status: string;
  /** The hash of the entry's signed core, exactly as the sync stream carries it. */
  entry_hash: string;
  /** The event's position in the log. */
  seq: number;
  /** The seal covering that position: the proof this alert is about sealed history. */
  seal: { seq: number; root: string; sealed_at: string };
  /** The event's own `at`: when the log recorded the change, not when it was sent. */
  at: string;
  links: { entry: string; proof: string };
}

/**
 * Which alerts one sealed event calls for, given the entry derived at the
 * event's position and at the position before it.
 *
 * The rules are the six kinds and nothing else:
 *
 * - `entry_submitted` is `submitted`: a new claim entered the log as a draft.
 * - `validation` is `verified` or `rejected`, by the status the entry derives
 *   to at this event, and only when the status actually moved — a decision that
 *   left the entry where it was is not a change to alert anybody about, which is
 *   what `before` is here for. A verifying validation on an entry whose core
 *   names a `supersedes` target also alerts that target's subscribers
 *   `superseded`, because the fact they were following has just been replaced
 *   and the replacement is the thing they need.
 * - `reconfirmation` is `reconfirmed`, whatever the status: a reconfirmation
 *   never moves the status, it moves the freshness, and "this is still true" is
 *   exactly what a subscriber to a stale-able fact is waiting for.
 * - `dispute_upheld` is `overturned`. The event is scoped to the disputed entry
 *   (src/events.ts), so the entry derived here is the target; `target` is
 *   honoured when a caller passes one and the derived entry is used otherwise.
 * - Everything else is nothing. Registrations, pool snapshots, assignments and
 *   read counts are the log's own bookkeeping and no reader subscribed to them.
 */
export function alertsFromEvent(
  event: Event,
  derived: { before: Entry | null; after: Entry; target?: Entry | null },
): { kind: AlertKind; entry: Entry }[] {
  const after = derived.after;
  const target = derived.target ?? null;

  switch (event.type) {
    case "entry_submitted":
      return [{ kind: "submitted", entry: after }];

    case "validation": {
      const status = after["status"];
      const moved =
        derived.before === null || derived.before["status"] !== status;
      if (!moved) return [];
      const out: { kind: AlertKind; entry: Entry }[] = [];
      if (status === "verified") {
        out.push({ kind: "verified", entry: after });
        const supersedes = after["supersedes"];
        if (
          typeof supersedes === "string" &&
          target !== null &&
          target["id"] === supersedes &&
          target["status"] === "superseded"
        ) {
          out.push({ kind: "superseded", entry: target });
        }
      } else if (status === "rejected") {
        out.push({ kind: "rejected", entry: after });
      }
      return out;
    }

    case "reconfirmation":
      return [{ kind: "reconfirmed", entry: after }];

    case "dispute_upheld":
      return [{ kind: "overturned", entry: target ?? after }];

    default:
      return [];
  }
}

/**
 * Domain-separation tag for the alert signature. A format constant and not a
 * policy number: it names the construction, so a reader can say which recipe
 * the hex on a delivery was made with when a second one exists.
 */
export const HASH_TAG_ALERT = "nomankind-alert-v1";

/**
 * The bytes a delivery's signature covers: the timestamp, a dot, and the body
 * exactly as it was sent.
 *
 * The timestamp is inside the signature rather than beside it, so a delivery
 * captured off the wire cannot be replayed hours later under a fresh timestamp.
 * The body is the string that was sent, byte for byte, and never a
 * re-serialization of a parsed object: a verifier that re-encoded the JSON
 * would be checking a signature over bytes nobody sent.
 */
export function alertSigningBytes(timestamp: number, body: string): Uint8Array {
  return new TextEncoder().encode(`${timestamp}.${body}`);
}

/** HMAC-SHA256 of those bytes under the endpoint's shared secret, as hex. */
export async function signAlert(
  secret: string,
  timestamp: number,
  body: string,
): Promise<string> {
  const key = await globalThis.crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret) as unknown as BufferSource,
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const signature = await globalThis.crypto.subtle.sign(
    "HMAC",
    key,
    alertSigningBytes(timestamp, body) as unknown as BufferSource,
  );
  let hex = "";
  for (const byte of new Uint8Array(signature)) {
    hex += byte.toString(16).padStart(2, "0");
  }
  return hex;
}

/**
 * The signature header: `t=<timestamp>,v1=<hex>`.
 *
 * Deliberately the shape a payment provider's webhooks use, so a subscriber
 * that already has a verifier for one has a verifier for this: the parse is the
 * same, and only the secret and the tag differ.
 */
export function alertSignatureHeader(timestamp: number, hex: string): string {
  return `t=${timestamp},v1=${hex}`;
}

/**
 * Whether a value is a URL this system will post an alert to.
 *
 * https only, because an alert carries a subscriber's own filters and a plain
 * http endpoint would publish them to every hop. A dotted hostname and no
 * `localhost`, because a Worker's own fetch resolves names on the platform's
 * network and an endpoint naming a local address is either a mistake or an
 * attempt to make this Worker knock on a door of its own. No userinfo, for the
 * reason the source policy refuses it on a citation: credentials in a URL are a
 * secret in a column, and this column is already holding one.
 */
export function isAlertUrl(value: unknown): value is string {
  if (typeof value !== "string" || value.length === 0) return false;
  let parsed: URL;
  try {
    parsed = new URL(value);
  } catch {
    return false;
  }
  if (parsed.protocol !== "https:") return false;
  if (parsed.username !== "" || parsed.password !== "") return false;
  const host = parsed.hostname.toLowerCase();
  if (!host.includes(".")) return false;
  if (host === "localhost" || host.endsWith(".localhost")) return false;
  return true;
}
