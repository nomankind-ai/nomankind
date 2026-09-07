/**
 * Base64 and base64url, Workers-safe.
 *
 * No Buffer and no `node:` imports: only `btoa` / `atob`, which exist in Node 22
 * and on Cloudflare Workers alike, so the kernel runs unchanged in both.
 *
 * base64url here is the unpadded form of RFC 4648 section 5, the encoding
 * decision D-014 binds agent ids to. Decoding is strict in both alphabets: a
 * character outside the alphabet, padding where the alphabet forbids it, or a
 * length that no byte string could produce is an error rather than a silent
 * truncation.
 */

/** Standard base64: the RFC 4648 section 4 alphabet, padded to a multiple of 4. */
const BASE64_PATTERN = /^[A-Za-z0-9+/]*={0,2}$/;

/** base64url: the RFC 4648 section 5 alphabet, never padded. */
const BASE64URL_PATTERN = /^[A-Za-z0-9_-]*$/;

/** Chunked so a large input cannot overflow the argument list. */
const CHUNK_SIZE = 0x8000;

function bytesToBinary(bytes: Uint8Array): string {
  let binary = "";
  for (let offset = 0; offset < bytes.length; offset += CHUNK_SIZE) {
    const chunk = bytes.subarray(offset, offset + CHUNK_SIZE);
    binary += String.fromCharCode(...chunk);
  }
  return binary;
}

function binaryToBytes(binary: string): Uint8Array {
  const bytes = new Uint8Array(binary.length);
  for (let index = 0; index < binary.length; index += 1) {
    bytes[index] = binary.charCodeAt(index);
  }
  return bytes;
}

/** Standard base64 (RFC 4648 section 4), padded. */
export function base64Encode(bytes: Uint8Array): string {
  return btoa(bytesToBinary(bytes));
}

/** Decode standard, padded base64. Throws on anything else. */
export function base64Decode(text: string): Uint8Array {
  if (typeof text !== "string") {
    throw new Error("base64Decode: input must be a string");
  }
  if (!BASE64_PATTERN.test(text)) {
    throw new Error("base64Decode: input is not standard base64");
  }
  if (text.length % 4 !== 0) {
    throw new Error("base64Decode: input length is not a multiple of 4");
  }
  return binaryToBytes(atob(text));
}

/** base64url (RFC 4648 section 5), unpadded. */
export function base64urlEncode(bytes: Uint8Array): string {
  return base64Encode(bytes)
    .replaceAll("+", "-")
    .replaceAll("/", "_")
    .replaceAll("=", "");
}

/**
 * Decode unpadded base64url. Throws on padding, on a character outside the
 * URL-safe alphabet (`+` and `/` included), and on a length no byte string
 * could produce.
 */
export function base64urlDecode(text: string): Uint8Array {
  if (typeof text !== "string") {
    throw new Error("base64urlDecode: input must be a string");
  }
  if (!BASE64URL_PATTERN.test(text)) {
    throw new Error("base64urlDecode: input is not unpadded base64url");
  }
  const remainder = text.length % 4;
  if (remainder === 1) {
    throw new Error("base64urlDecode: input length is not a valid base64 length");
  }
  const padded =
    text.replaceAll("-", "+").replaceAll("_", "/") +
    (remainder === 0 ? "" : "=".repeat(4 - remainder));
  return binaryToBytes(atob(padded));
}
