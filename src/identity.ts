/**
 * Identity: 1F916 agent keys, Ed25519 through WebCrypto only.
 *
 * Whitepaper Section 5: every participant is a 1F916 agent, an Ed25519 key with
 * a public, witnessed, append-only history. nomankind consumes that identity
 * system rather than running one, so an agent id is nothing but its public key
 * in the encoding 1F916 draft-01 defines.
 *
 * Decision D-014: an agent id is the string "1F916:" followed by the unpadded
 * base64url of the raw 32-byte Ed25519 public key. The 1F916 draft binds keys
 * with exactly that encoding and defines no other handle syntax.
 *
 * Every operation goes through globalThis.crypto.subtle, never node:crypto, so
 * the kernel runs unchanged on Cloudflare Workers.
 */

import { base64urlDecode, base64urlEncode } from "./encoding.js";

/** The prefix every 1F916 agent id carries, matching the schema's ^1F916:.+$. */
export const AGENT_ID_PREFIX = "1F916:";

/** The WebCrypto algorithm name for the signature scheme of Section 5. */
export const ED25519 = "Ed25519";

/** Raw Ed25519 public keys are exactly this many bytes. */
const PUBLIC_KEY_BYTES = 32;

/**
 * Generate a fresh Ed25519 keypair, extractable so keygen (D-016) can write it
 * out once. The private key never leaves the application that generated it.
 */
export async function generateKeypair(): Promise<CryptoKeyPair> {
  return (await globalThis.crypto.subtle.generateKey(ED25519, true, [
    "sign",
    "verify",
  ])) as CryptoKeyPair;
}

/** Export a public key as its raw 32 bytes. */
export async function exportPublicKeyRaw(key: CryptoKey): Promise<Uint8Array> {
  const raw = await globalThis.crypto.subtle.exportKey("raw", key);
  return new Uint8Array(raw);
}

/** Export a private key in PKCS#8, the only form WebCrypto exports it in. */
export async function exportPrivateKeyPkcs8(
  key: CryptoKey,
): Promise<Uint8Array> {
  const pkcs8 = await globalThis.crypto.subtle.exportKey("pkcs8", key);
  return new Uint8Array(pkcs8);
}

/** Import a raw 32-byte public key, usable for verification only. */
export async function importPublicKeyRaw(raw: Uint8Array): Promise<CryptoKey> {
  return globalThis.crypto.subtle.importKey(
    "raw",
    raw as unknown as BufferSource,
    ED25519,
    true,
    ["verify"],
  );
}

/** Import a PKCS#8 private key, usable for signing only. */
export async function importPrivateKeyPkcs8(
  pkcs8: Uint8Array,
): Promise<CryptoKey> {
  return globalThis.crypto.subtle.importKey(
    "pkcs8",
    pkcs8 as unknown as BufferSource,
    ED25519,
    true,
    ["sign"],
  );
}

/** The D-014 agent id for a raw 32-byte public key. */
export function agentIdFromPublicKey(raw: Uint8Array): string {
  if (!(raw instanceof Uint8Array) || raw.length !== PUBLIC_KEY_BYTES) {
    throw new Error(
      `agentIdFromPublicKey: public key must be ${PUBLIC_KEY_BYTES} bytes`,
    );
  }
  return AGENT_ID_PREFIX + base64urlEncode(raw);
}

/**
 * Recover the raw public key an agent id carries. Throws unless the prefix
 * matches, the remainder is unpadded base64url, and it decodes to exactly 32
 * bytes: an id that does not carry a key is not an identity under D-014.
 */
export function publicKeyFromAgentId(agentId: string): Uint8Array {
  if (typeof agentId !== "string") {
    throw new Error("publicKeyFromAgentId: agent id must be a string");
  }
  if (!agentId.startsWith(AGENT_ID_PREFIX)) {
    throw new Error(
      `publicKeyFromAgentId: agent id must start with ${AGENT_ID_PREFIX}`,
    );
  }
  const raw = base64urlDecode(agentId.slice(AGENT_ID_PREFIX.length));
  if (raw.length !== PUBLIC_KEY_BYTES) {
    throw new Error(
      `publicKeyFromAgentId: public key must be ${PUBLIC_KEY_BYTES} bytes, got ${raw.length}`,
    );
  }
  return raw;
}

/** Whether a value is a well-formed D-014 agent id. */
export function isAgentId(value: unknown): value is string {
  if (typeof value !== "string") {
    return false;
  }
  try {
    publicKeyFromAgentId(value);
    return true;
  } catch {
    return false;
  }
}

/** Sign raw bytes with an Ed25519 private key. */
export async function signBytes(
  privateKey: CryptoKey,
  bytes: Uint8Array,
): Promise<Uint8Array> {
  const signature = await globalThis.crypto.subtle.sign(
    ED25519,
    privateKey,
    bytes as unknown as BufferSource,
  );
  return new Uint8Array(signature);
}

/**
 * Verify a signature over raw bytes with a raw public key.
 *
 * Returns false rather than throwing on a malformed key or signature: a caller
 * checking a signature is asking a question, and a garbage key is an answer of
 * "no", not an exception to handle at every call site.
 */
export async function verifyBytes(
  publicKeyRaw: Uint8Array,
  bytes: Uint8Array,
  signature: Uint8Array,
): Promise<boolean> {
  try {
    const key = await importPublicKeyRaw(publicKeyRaw);
    return await globalThis.crypto.subtle.verify(
      ED25519,
      key,
      signature as unknown as BufferSource,
      bytes as unknown as BufferSource,
    );
  } catch {
    return false;
  }
}
