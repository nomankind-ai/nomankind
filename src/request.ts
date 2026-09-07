import { base64urlDecode, base64urlEncode } from "./encoding.js";
import { canonicalize } from "./hash.js";
import { publicKeyFromAgentId } from "./identity.js";
import {
  NONCE_RETENTION_SECONDS,
  REQUEST_CLOCK_SKEW_SECONDS,
} from "./policy.js";

/**
 * Request signing for the write path (decision D-014). A write request is
 * authenticated by an Ed25519 signature from the acting agent key over the JCS
 * canonical body, together with the HTTP method, the path, a timestamp and a
 * nonce. No passwords, no sessions.
 *
 * Method and path are inside the signed payload, so a captured signature cannot
 * be replayed against another endpoint. The timestamp bounds how long a capture
 * is worth replaying at all, and the nonce store refuses the replay outright.
 *
 * WebCrypto only (globalThis.crypto.subtle), never node:crypto, so the kernel
 * runs unchanged on Cloudflare Workers. Time is always supplied by the caller:
 * nothing here reads Date.now().
 */

/**
 * Domain-separation tag for the request signature. A format constant, not a
 * policy number: it names the signing construction, and changing it changes the
 * wire format rather than a published amount.
 */
export const REQUEST_SIGNATURE_TAG = "nomankind-request-v1";

/** The agent id of the signing key. */
export const HEADER_AGENT = "x-nomankind-agent";
/** The signed ISO 8601 timestamp. */
export const HEADER_TIMESTAMP = "x-nomankind-timestamp";
/** The signed single-use nonce. */
export const HEADER_NONCE = "x-nomankind-nonce";
/** The Ed25519 signature, unpadded base64url. */
export const HEADER_SIGNATURE = "x-nomankind-signature";

const encoder = new TextEncoder();

const ED25519 = { name: "Ed25519" } as const;

/** Nonce length in bytes. A format constant: the width of the random value. */
const NONCE_BYTES = 16;

/** ISO 8601 date-time with a seconds field and an explicit offset or Z. */
const ISO_DATE_TIME =
  /^\d{4}-\d{2}-\d{2}[Tt]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:[Zz]|[+-]\d{2}:\d{2})$/;

/** The string whose UTF-8 encoding is signed for a write request. */
export function requestSigningPayload(input: {
  method: string;
  path: string;
  body: unknown;
  timestamp: string;
  nonce: string;
}): string {
  return [
    REQUEST_SIGNATURE_TAG,
    input.method.toUpperCase(),
    input.path,
    input.timestamp,
    input.nonce,
    canonicalize(input.body),
  ].join("\n");
}

/** A fresh single-use nonce: sixteen random bytes, unpadded base64url. */
export function generateNonce(): string {
  const bytes = new Uint8Array(NONCE_BYTES);
  globalThis.crypto.getRandomValues(bytes);
  return base64urlEncode(bytes);
}

/**
 * The four authentication headers for a write request. The timestamp comes from
 * the caller's clock, never from Date.now() here.
 */
export async function signRequest(input: {
  method: string;
  path: string;
  body: unknown;
  agentId: string;
  privateKey: CryptoKey;
  timestamp: string;
  nonce?: string;
}): Promise<Record<string, string>> {
  const nonce = input.nonce ?? generateNonce();
  const payload = requestSigningPayload({
    method: input.method,
    path: input.path,
    body: input.body,
    timestamp: input.timestamp,
    nonce,
  });
  const signature = await globalThis.crypto.subtle.sign(
    ED25519,
    input.privateKey,
    encoder.encode(payload) as unknown as BufferSource,
  );
  return {
    [HEADER_AGENT]: input.agentId,
    [HEADER_TIMESTAMP]: input.timestamp,
    [HEADER_NONCE]: nonce,
    [HEADER_SIGNATURE]: base64urlEncode(new Uint8Array(signature)),
  };
}

/** A verifier's memory of spent nonces. */
export interface NonceStore {
  has(nonce: string): Promise<boolean> | boolean;
  add(nonce: string, expiresAt: Date): Promise<void> | void;
  prune(now: Date): Promise<void> | void;
}

/** A NonceStore held in memory, for a single process and for tests. */
export class InMemoryNonceStore implements NonceStore {
  readonly #expiries = new Map<string, number>();

  has(nonce: string): boolean {
    return this.#expiries.has(nonce);
  }

  add(nonce: string, expiresAt: Date): void {
    this.#expiries.set(nonce, expiresAt.getTime());
  }

  /** Drop every nonce whose retention has run out at `now`. */
  prune(now: Date): void {
    for (const [nonce, expiresAt] of this.#expiries) {
      if (expiresAt <= now.getTime()) {
        this.#expiries.delete(nonce);
      }
    }
  }
}

/** The outcome of verifying a signed write request. */
export type RequestVerdict =
  | { ok: true; agentId: string; nonce: string }
  | {
      ok: false;
      reason:
        | "missing_header"
        | "agent_mismatch"
        | "bad_timestamp"
        | "clock_skew"
        | "replay"
        | "bad_signature";
    };

/** Case-insensitive header lookup; empty values count as absent. */
function readHeader(
  headers: Record<string, string>,
  name: string,
): string | undefined {
  for (const [key, value] of Object.entries(headers)) {
    if (key.toLowerCase() === name && value !== "") {
      return value;
    }
  }
  return undefined;
}

/** Whether two byte strings have the same length and the same bytes. */
function bytesEqual(left: Uint8Array, right: Uint8Array): boolean {
  if (left.length !== right.length) {
    return false;
  }
  let difference = 0;
  for (let index = 0; index < left.length; index += 1) {
    difference |= (left[index] as number) ^ (right[index] as number);
  }
  return difference === 0;
}

/**
 * Verify a signed write request against the acting agent's raw public key.
 * Checks in order and stops at the first failure: headers present, the agent
 * header carrying exactly the given public key, timestamp well formed,
 * timestamp within the skew window, nonce unspent, signature valid. On success
 * the nonce is remembered for NONCE_RETENTION_SECONDS.
 *
 * The raw public key bytes come from the caller. The agent header is only ever
 * decoded to check that it names that same key (D-014): a verdict must never
 * report an identity the signature does not belong to, so an id that is
 * malformed or that carries different key bytes is agent_mismatch.
 */
export async function verifyRequest(input: {
  method: string;
  path: string;
  body: unknown;
  headers: Record<string, string>;
  publicKey: Uint8Array;
  now: Date;
  nonces: NonceStore;
}): Promise<RequestVerdict> {
  const agentId = readHeader(input.headers, HEADER_AGENT);
  const timestamp = readHeader(input.headers, HEADER_TIMESTAMP);
  const nonce = readHeader(input.headers, HEADER_NONCE);
  const signature = readHeader(input.headers, HEADER_SIGNATURE);
  if (
    agentId === undefined ||
    timestamp === undefined ||
    nonce === undefined ||
    signature === undefined
  ) {
    return { ok: false, reason: "missing_header" };
  }

  let headerKey: Uint8Array;
  try {
    headerKey = publicKeyFromAgentId(agentId);
  } catch {
    return { ok: false, reason: "agent_mismatch" };
  }
  if (!bytesEqual(headerKey, input.publicKey)) {
    return { ok: false, reason: "agent_mismatch" };
  }

  if (!ISO_DATE_TIME.test(timestamp)) {
    return { ok: false, reason: "bad_timestamp" };
  }
  const signedAt = Date.parse(timestamp);
  if (Number.isNaN(signedAt)) {
    return { ok: false, reason: "bad_timestamp" };
  }

  const skewSeconds = Math.abs(input.now.getTime() - signedAt) / 1000;
  if (skewSeconds > REQUEST_CLOCK_SKEW_SECONDS) {
    return { ok: false, reason: "clock_skew" };
  }

  if (await input.nonces.has(nonce)) {
    return { ok: false, reason: "replay" };
  }

  const payload = requestSigningPayload({
    method: input.method,
    path: input.path,
    body: input.body,
    timestamp,
    nonce,
  });
  let verified = false;
  try {
    const key = await globalThis.crypto.subtle.importKey(
      "raw",
      input.publicKey as unknown as BufferSource,
      ED25519,
      false,
      ["verify"],
    );
    verified = await globalThis.crypto.subtle.verify(
      ED25519,
      key,
      base64urlDecode(signature) as unknown as BufferSource,
      encoder.encode(payload) as unknown as BufferSource,
    );
  } catch {
    return { ok: false, reason: "bad_signature" };
  }
  if (!verified) {
    return { ok: false, reason: "bad_signature" };
  }

  await input.nonces.add(
    nonce,
    new Date(input.now.getTime() + NONCE_RETENTION_SECONDS * 1000),
  );
  return { ok: true, agentId, nonce };
}
