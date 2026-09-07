import jcs from "canonicalize";

import { extractCore } from "./core.js";

/**
 * Hashing for the log: RFC 8785 canonical JSON, SHA-256 through WebCrypto, and
 * the entry hash sealed into nomankind's 1F916 agent log.
 *
 * WebCrypto only (globalThis.crypto.subtle), never node:crypto, so the kernel
 * runs unchanged on Cloudflare Workers.
 */

/**
 * Domain-separation tag for the entry hash. A format constant, not a policy
 * number: it names the hash construction, and changing it changes the wire
 * format rather than a published amount.
 */
export const HASH_TAG_ENTRY = "nomankind-entry-v1";

const encoder = new TextEncoder();

/** RFC 8785 (JCS) canonical JSON string for a value. */
export function canonicalize(value: unknown): string {
  const canonical = jcs(value);
  if (canonical === undefined) {
    throw new Error("canonicalize: value has no JCS canonical form");
  }
  return canonical;
}

function toHex(buffer: ArrayBuffer): string {
  const bytes = new Uint8Array(buffer);
  let hex = "";
  for (const byte of bytes) {
    hex += byte.toString(16).padStart(2, "0");
  }
  return hex;
}

/** SHA-256 of the given bytes (or of the UTF-8 encoding of a string), as hex. */
export async function sha256Hex(bytes: Uint8Array | string): Promise<string> {
  const input = typeof bytes === "string" ? encoder.encode(bytes) : bytes;
  const digest = await globalThis.crypto.subtle.digest(
    "SHA-256",
    input as unknown as BufferSource,
  );
  return toHex(digest);
}

/**
 * Tagged SHA-256: the digest over UTF-8 of `<tag>` + "\n" + payload, so a hash
 * computed for one purpose can never be replayed as a hash for another.
 */
export async function taggedSha256Hex(
  tag: string,
  payload: string,
): Promise<string> {
  return sha256Hex(`${tag}\n${payload}`);
}

/**
 * The entry hash: the tagged SHA-256 over the JCS canonical form of the entry's
 * immutable core, prefixed "sha256:" to match the schema's hash pattern
 * (^sha256:[0-9a-f]{64}$). Derived fields and the signature never enter it, so
 * two entries differing only in state hash equal.
 */
export async function entryHash(entry: unknown): Promise<string> {
  const canonicalCore = canonicalize(extractCore(entry));
  const digest = await taggedSha256Hex(HASH_TAG_ENTRY, canonicalCore);
  return `sha256:${digest}`;
}
