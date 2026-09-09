/**
 * A tiny RFC 6962 log, built the way the specification defines it rather than
 * the way src/registry-proof.ts verifies it.
 *
 * The registry fixtures pin the verifier against the real registry's wire, but
 * they cannot cover one case: a witness countersigning an *earlier* head than
 * the one an inclusion proof was fetched against, bridged by a consistency
 * proof. The capture holds an inclusion proof at tree size 89 and a consistency
 * proof from 89 to 9128, and no inclusion proof against 9128, so that pairing
 * cannot be assembled from it.
 *
 * So this builds one. The definitions here are the RFC's recursions (MTH,
 * PATH and PROOF, sections 2.1, 2.1.1 and 2.1.2) written out directly — a
 * generator, not a second copy of the verifier's fold — which is what makes the
 * two agreeing worth anything. Tests only; nothing in src imports it.
 */

const encoder = new TextEncoder();

function hexToBytes(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2);
  for (let index = 0; index < bytes.length; index += 1) {
    bytes[index] = Number.parseInt(hex.slice(index * 2, index * 2 + 2), 16);
  }
  return bytes;
}

function bytesToHex(bytes: Uint8Array): string {
  let hex = "";
  for (const byte of bytes) hex += byte.toString(16).padStart(2, "0");
  return hex;
}

async function sha256Hex(bytes: Uint8Array): Promise<string> {
  const digest = await globalThis.crypto.subtle.digest(
    "SHA-256",
    bytes as unknown as BufferSource,
  );
  return bytesToHex(new Uint8Array(digest));
}

/** SHA-256(0x00 || the leaf's bytes), the registry's leaf. */
export async function leafOf(text: string): Promise<string> {
  const leaf = encoder.encode(text);
  const preimage = new Uint8Array(leaf.length + 1);
  preimage[0] = 0x00;
  preimage.set(leaf, 1);
  return sha256Hex(preimage);
}

/** SHA-256(0x01 || left || right). */
async function nodeOf(left: string, right: string): Promise<string> {
  const preimage = new Uint8Array(65);
  preimage[0] = 0x01;
  preimage.set(hexToBytes(left), 1);
  preimage.set(hexToBytes(right), 33);
  return sha256Hex(preimage);
}

/** The largest power of two strictly smaller than n (RFC 6962's k). */
function splitPoint(n: number): number {
  let k = 1;
  while (k * 2 < n) k *= 2;
  return k;
}

/** MTH: the Merkle tree hash of a list of leaf hashes. */
export async function rootOf(leaves: readonly string[]): Promise<string> {
  if (leaves.length === 0) return sha256Hex(new Uint8Array(0));
  if (leaves.length === 1) return leaves[0]!;
  const k = splitPoint(leaves.length);
  return nodeOf(await rootOf(leaves.slice(0, k)), await rootOf(leaves.slice(k)));
}

/** PATH: the audit path for the leaf at `index`. */
export async function pathOf(
  leaves: readonly string[],
  index: number,
): Promise<string[]> {
  if (leaves.length <= 1) return [];
  const k = splitPoint(leaves.length);
  if (index < k) {
    return [
      ...(await pathOf(leaves.slice(0, k), index)),
      await rootOf(leaves.slice(k)),
    ];
  }
  return [
    ...(await pathOf(leaves.slice(k), index - k)),
    await rootOf(leaves.slice(0, k)),
  ];
}

/** SUBPROOF, the recursion PROOF is defined in terms of. */
async function subproof(
  m: number,
  leaves: readonly string[],
  complete: boolean,
): Promise<string[]> {
  if (m === leaves.length) return complete ? [] : [await rootOf(leaves)];
  const k = splitPoint(leaves.length);
  if (m <= k) {
    return [
      ...(await subproof(m, leaves.slice(0, k), complete)),
      await rootOf(leaves.slice(k)),
    ];
  }
  return [
    ...(await subproof(m - k, leaves.slice(k), false)),
    await rootOf(leaves.slice(0, k)),
  ];
}

/** PROOF: the consistency proof between the first `m` leaves and all of them. */
export async function consistencyOf(
  leaves: readonly string[],
  m: number,
): Promise<string[]> {
  return subproof(m, leaves, true);
}
