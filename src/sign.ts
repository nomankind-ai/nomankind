/**
 * Signing an entry: the author's Ed25519 signature over the immutable core.
 *
 * The schema says `signature` is the "Author's Ed25519 signature over the
 * JCS-canonical immutable core. Base64." So the signed bytes are the UTF-8 of
 * the RFC 8785 canonical form of the seventeen core keys, and nothing else. No
 * derived field enters them: status, stale, and superseded_by are recomputed
 * from events, and an entry whose state moved on must still verify against the
 * signature its author produced.
 */

import { extractCore } from "./core.js";
import { base64Decode, base64Encode } from "./encoding.js";
import { publicKeyFromAgentId, signBytes, verifyBytes } from "./identity.js";
import { canonicalize } from "./hash.js";

const encoder = new TextEncoder();

/**
 * The exact bytes an author signs: UTF-8 of the JCS-canonical immutable core.
 */
export function coreSigningBytes(entry: unknown): Uint8Array {
  return encoder.encode(canonicalize(extractCore(entry)));
}

/**
 * Sign an entry's core, returning the standard base64 signature that goes in
 * the schema's `signature` field.
 */
export async function signCore(
  entry: unknown,
  privateKey: CryptoKey,
): Promise<string> {
  const signature = await signBytes(privateKey, coreSigningBytes(entry));
  return base64Encode(signature);
}

/**
 * Verify an entry's `signature` over its core.
 *
 * The key defaults to the one the entry's own `author` id carries (D-014), so
 * the common check needs no second argument. Returns false, never throws, on
 * any malformed input: a bad entry is an unverified entry, not a crash.
 */
export async function verifyEntrySignature(
  entry: unknown,
  publicKeyRaw?: Uint8Array,
): Promise<boolean> {
  try {
    if (typeof entry !== "object" || entry === null || Array.isArray(entry)) {
      return false;
    }
    const record = entry as Record<string, unknown>;
    const signature = record["signature"];
    if (typeof signature !== "string") {
      return false;
    }
    const key =
      publicKeyRaw ?? publicKeyFromAgentId(record["author"] as string);
    return await verifyBytes(
      key,
      coreSigningBytes(entry),
      base64Decode(signature),
    );
  } catch {
    return false;
  }
}
