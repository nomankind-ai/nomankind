/**
 * Merkle batching and inclusion proofs.
 *
 * Whitepaper Section 6, "Seal": every later event is hashed into a batch and
 * sealed, and "anyone can verify offline that an entry or event existed and has
 * not changed". A Merkle tree is what makes that offline check cheap: one root
 * commits to every leaf in the batch, and a path of sibling hashes proves one
 * leaf sits under that root without carrying the batch itself.
 *
 * The tree is RFC 6962's, exactly: for n > 1 the split is at the largest power
 * of two strictly less than n, and an odd node is never duplicated up a level.
 * That shape is what lets verification derive left from right out of the index
 * and the size alone, so a proof carries no direction flags to forge.
 *
 * Pure: no I/O, no storage, no clock. Hashing goes through src/hash.ts, which
 * uses WebCrypto only, so this runs unchanged on a Worker.
 */

import { canonicalize, taggedSha256Hex } from "./hash.js";

/**
 * Domain-separation tags for the two node kinds. Format constants, not policy
 * numbers: they name the hash construction. Separating leaf from interior is
 * what stops an interior node being replayed as a leaf, which would otherwise
 * let a prover claim membership for a value that was never a leaf.
 */
export const HASH_TAG_MERKLE_LEAF = "nomankind-merkle-leaf-v1";
export const HASH_TAG_MERKLE_NODE = "nomankind-merkle-node-v1";

/**
 * An inclusion proof: which leaf, out of how many, and the sibling hashes from
 * the leaf upward. No direction flags — RFC 6962 section 2.1.1 derives them
 * from `index` and `size`, so a proof cannot lie about which side a sibling sat
 * on.
 */
export interface InclusionProof {
  index: number;
  size: number;
  path: string[];
}

/** Every hash string in this codebase is "sha256:" + hex (the schema's pattern). */
function prefixed(digest: string): string {
  return `sha256:${digest}`;
}

/** The hash of one leaf. Leaves are event hash strings. */
export async function leafHash(leaf: string): Promise<string> {
  return prefixed(await taggedSha256Hex(HASH_TAG_MERKLE_LEAF, leaf));
}

/** The hash of an interior node over its two children, left first. */
export async function nodeHash(left: string, right: string): Promise<string> {
  return prefixed(await taggedSha256Hex(HASH_TAG_MERKLE_NODE, `${left}\n${right}`));
}

/**
 * The root of the empty tree. Defined so the function is total, but never
 * produced by a seal: src/seal.ts refuses to seal nothing.
 */
async function emptyRoot(): Promise<string> {
  return prefixed(await taggedSha256Hex(HASH_TAG_MERKLE_NODE, ""));
}

/** The largest power of two strictly less than n (n > 1). */
function splitPoint(n: number): number {
  let k = 1;
  while (k * 2 < n) k *= 2;
  return k;
}

async function rootOf(leaves: readonly string[]): Promise<string> {
  if (leaves.length === 0) return emptyRoot();
  if (leaves.length === 1) return leafHash(leaves[0]!);
  const k = splitPoint(leaves.length);
  const left = await rootOf(leaves.slice(0, k));
  const right = await rootOf(leaves.slice(k));
  return nodeHash(left, right);
}

/** The Merkle tree head over these leaves, in this order. */
export async function merkleRoot(leaves: readonly string[]): Promise<string> {
  return rootOf(leaves);
}

/** RFC 6962 PATH(m, D[n]): the sibling hashes from the leaf upward. */
async function pathOf(
  leaves: readonly string[],
  index: number,
): Promise<string[]> {
  if (leaves.length <= 1) return [];
  const k = splitPoint(leaves.length);
  if (index < k) {
    const below = await pathOf(leaves.slice(0, k), index);
    return [...below, await rootOf(leaves.slice(k))];
  }
  const below = await pathOf(leaves.slice(k), index - k);
  return [...below, await rootOf(leaves.slice(0, k))];
}

/**
 * The inclusion proof for one leaf of this batch.
 *
 * Throws RangeError on an index outside the tree: asking for a proof of
 * something that is not in the batch is a caller error, not a verdict.
 */
export async function inclusionProof(
  leaves: readonly string[],
  index: number,
): Promise<InclusionProof> {
  if (!Number.isInteger(index) || index < 0 || index >= leaves.length) {
    throw new RangeError(
      `inclusionProof: index ${index} outside a tree of ${leaves.length}`,
    );
  }
  return { index, size: leaves.length, path: await pathOf(leaves, index) };
}

/**
 * Verify a leaf against a root, offline.
 *
 * RFC 6962 section 2.1.1's verification, walking the path from the leaf while
 * `fn`/`sn` track the node's index and the last index at that level; the parity
 * of `fn` (and the `fn == sn` right-edge case) says which side the sibling sat
 * on, so no direction flag is trusted. Returns false — never throws — on a
 * malformed proof, an index outside the size, a path of the wrong length, or a
 * mismatch: a verifier reading someone else's proof gets a verdict, not an
 * exception.
 */
export async function verifyInclusion(
  leaf: string,
  proof: InclusionProof,
  root: string,
): Promise<boolean> {
  if (typeof leaf !== "string" || typeof root !== "string") return false;
  if (!isProofShape(proof)) return false;
  if (proof.index >= proof.size) return false;

  let fn = proof.index;
  let sn = proof.size - 1;
  let hash = await leafHash(leaf);

  for (const sibling of proof.path) {
    if (sn === 0) return false;
    if (fn % 2 === 1 || fn === sn) {
      hash = await nodeHash(sibling, hash);
      while (fn !== 0 && fn % 2 === 0) {
        fn = Math.floor(fn / 2);
        sn = Math.floor(sn / 2);
      }
    } else {
      hash = await nodeHash(hash, sibling);
    }
    fn = Math.floor(fn / 2);
    sn = Math.floor(sn / 2);
  }

  return sn === 0 && hash === root;
}

/**
 * The proof as the string the schema's `seal.inclusion_proof` carries: JCS
 * canonical JSON, so the same proof is the same bytes for every verifier.
 */
export function encodeProof(proof: InclusionProof): string {
  return canonicalize(proof);
}

function isProofShape(value: unknown): value is InclusionProof {
  if (typeof value !== "object" || value === null) return false;
  const candidate = value as Record<string, unknown>;
  const { index, size, path } = candidate;
  if (!Number.isInteger(index) || (index as number) < 0) return false;
  if (!Number.isInteger(size) || (size as number) < 0) return false;
  if ((index as number) >= (size as number)) return false;
  if (!Array.isArray(path)) return false;
  return path.every((step) => typeof step === "string");
}

/**
 * Read a proof back out of its encoded form. Null on anything that is not
 * exactly the shape — a verifier is handed proofs by strangers, so a garbage
 * string is an answer, not a crash.
 */
export function decodeProof(text: string): InclusionProof | null {
  if (typeof text !== "string") return null;
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    return null;
  }
  if (!isProofShape(parsed)) return null;
  const { index, size, path } = parsed;
  return { index, size, path: [...path] };
}
