/**
 * The API key, as a kernel object.
 *
 * Whitepaper Section 9, Money: "The log is free to read at low volume, forever.
 * Revenue comes from high-rate API access, structured feeds and webhooks,
 * change alerts." A key is what buys the high rate, and nothing else: it names
 * no reader, it grants no power over the log, and every door it opens is a door
 * the free tier already opens more slowly.
 *
 * Pure except for the randomness a new secret is made of, which comes through
 * `crypto.getRandomValues` and is injectable so a test can mint a key it knows
 * the bytes of. Nothing here touches the database, the network or the clock;
 * src/storage/keys.ts stores what this mints and src/worker/access.ts decides
 * what it opens.
 *
 * The secret is shown once and never stored. What the table holds is the
 * SHA-256 of the secret's UTF-8 bytes, so a copy of the key table cannot be used
 * to read as anybody — the same posture the nonce store and the sealing key
 * take, in the only place in this system where a bearer credential exists at
 * all. A plain digest and not a password hash: the secret is 32 bytes of
 * `getRandomValues`, so there is no dictionary to be slow against, and the
 * access gate reads it on every paid request.
 *
 * No policy number lives here — every cap is RATE_TIERS's, read through
 * `tierLimit`. WebCrypto only, never `node:crypto`, so this file runs unchanged
 * on Workers.
 */

import { base64urlEncode } from "./encoding.js";
import { sha256Hex } from "./hash.js";
import { RATE_TIERS } from "./policy.js";

/**
 * The secret's prefix: `nmk_` and 43 characters of unpadded base64url over 32
 * random bytes. Prefixed so a secret pasted into an issue or a log line is
 * recognisable as a credential at a glance, which is what makes a leaked one
 * revocable before it is used.
 */
export const KEY_PREFIX = "nmk_";

/** The id's prefix: `key_` and 16 lowercase hex. Public; it names no secret. */
export const KEY_ID_PREFIX = "key_";

/** How many random bytes a secret is made of. A format fact, not a policy number. */
const SECRET_BYTES = 32;

/** How many random bytes an id is made of: 8 bytes is the 16 hex the id shows. */
const ID_BYTES = 8;

/** The length of the base64url body of a secret: 32 bytes unpadded. */
const SECRET_BODY_LENGTH = 43;

/**
 * What the subscription behind a key says about it.
 *
 * Three words and not the provider's dozen: the gate has exactly three answers
 * — serve, refuse because the bill did not clear, refuse because it is over —
 * and mapping the provider's vocabulary to ours once, here, is what stops a
 * status nobody anticipated being read as "active" by accident.
 */
export type KeyStatus = "active" | "past_due" | "canceled";

/** One key, exactly as the table holds it. Never the hash and never the secret. */
export interface KeyRecord {
  id: string;
  tier: string;
  status: KeyStatus;
  customer: string;
  subscription: string;
  checkout_session: string;
  /** The key's own receipt counter: the last number it was issued. */
  counter: number;
  created_at: string;
  updated_at: string;
}

/** Random bytes, from the platform. The only impurity in this module. */
function defaultRandom(count: number): Uint8Array {
  return globalThis.crypto.getRandomValues(new Uint8Array(count));
}

/** Lowercase hex of some bytes. */
function hex(bytes: Uint8Array): string {
  let out = "";
  for (const byte of bytes) out += byte.toString(16).padStart(2, "0");
  return out;
}

/**
 * Mint one key: the id it is known by, the secret its holder is shown once, and
 * the hash the table stores.
 *
 * The id and the secret are drawn separately, so knowing one says nothing about
 * the other: an id appears in receipts, in the usage reads and in the ledger's
 * published per-key counts, and none of those may narrow a search for the
 * secret.
 */
export function mintKey(random: (n: number) => Uint8Array = defaultRandom): {
  id: string;
  secret: string;
  hash: Promise<string>;
} {
  const id = `${KEY_ID_PREFIX}${hex(random(ID_BYTES))}`;
  const secret = `${KEY_PREFIX}${base64urlEncode(random(SECRET_BYTES))}`;
  return { id, secret, hash: keyHash(secret) };
}

/** The stored form of a secret: SHA-256 hex of its UTF-8 bytes. */
export async function keyHash(secret: string): Promise<string> {
  return sha256Hex(secret);
}

/**
 * Whether a value is shaped like a secret this system mints.
 *
 * Never throws, and says nothing about whether the key exists: it is the cheap
 * check the access gate makes before it touches the database, so a header full
 * of somebody's password costs one string comparison rather than a query.
 */
export function looksLikeKey(value: unknown): value is string {
  if (typeof value !== "string") return false;
  if (!value.startsWith(KEY_PREFIX)) return false;
  const body = value.slice(KEY_PREFIX.length);
  return body.length === SECRET_BODY_LENGTH && /^[A-Za-z0-9_-]+$/.test(body);
}

/**
 * The provider's subscription status, in our three words.
 *
 * `trialing` is active because a trial that could not read would not be a
 * trial. `unpaid` joins `past_due` because both mean the same thing to a
 * reader: the key is theirs and the bill is not settled. Everything else —
 * `canceled`, `incomplete`, `incomplete_expired`, `paused`, and whatever the
 * provider adds next — is canceled, because the safe reading of a word we do
 * not know is the one that refuses.
 */
export function keyStatusFromSubscription(status: string): KeyStatus {
  if (status === "active" || status === "trialing") return "active";
  if (status === "past_due" || status === "unpaid") return "past_due";
  return "canceled";
}

/** The quota scope a key is counted under. */
export function quotaScopeForKey(id: string): string {
  return `key:${id}`;
}

/**
 * The quota scope a keyless reader is counted under: the client address,
 * hashed, or the one anonymous bucket when the platform gave us no address.
 *
 * Hashed because a rate counter that stored addresses would be a record of who
 * read what, and this system publishes counts and never readers. One bucket for
 * everybody without an address because the alternative — no limit at all — is
 * the free tier's cap being optional.
 */
export async function quotaScopeForClient(ip: string | null): Promise<string> {
  if (ip === null || ip === "") return "client:anonymous";
  return `client:${await sha256Hex(ip)}`;
}

/**
 * The daily cap of a tier, and 0 for a slug no tier is registered under — a
 * cap of zero refuses, which is the right answer for a key whose tier was
 * retired from policy.
 */
export function tierLimit(tier: string): number {
  const row = RATE_TIERS[tier];
  return row === undefined ? 0 : row.reads_per_day;
}

/**
 * Every word a key can be refused in, for the doors and the docs. One list so a
 * refusal the API documents and a refusal the gate returns cannot drift.
 */
export const KEY_REFUSALS = [
  "missing_key",
  "bad_key",
  "unknown_key",
  "key_canceled",
  "key_past_due",
  "rate_limited",
] as const;
