/**
 * The founding registry's own proof formats.
 *
 * Whitepaper, "Lifecycle of an entry" (Seal): the seal's fingerprint is
 * submitted to nomankind's agent log at the 1F916 registry, and the witnesses
 * countersign the registry's checkpoint head under which that fingerprint is
 * included. Real witnesses never sign our seal hash — they sign the head — so a
 * countersignature only reaches our seal by way of the registry's own inclusion
 * and consistency proofs. This module is those proofs, and nothing else.
 *
 * The registry publishes RFC 6962 exactly: a leaf is SHA-256(0x00 || the leaf
 * bytes) where the leaf bytes are the event's lowercase-hex chain hash as UTF-8,
 * and a node is SHA-256(0x01 || left || right). That is deliberately *not*
 * src/merkle.ts's tree, which is nomankind's own tagged construction over its
 * own batches: two trees, two domains, and mixing them would let a proof from
 * one be replayed against the other. Neither module imports the other.
 *
 * Pure, and never a throw: a verifier reading a stranger's proof gets a verdict.
 * Every hash is checked as exactly 64 lowercase hex characters and every size
 * and index as a safe non-negative integer before any arithmetic, so a float, a
 * negative, an uppercase digest or a missing field is answered "no" rather than
 * folded into a hash. SHA-256 goes through WebCrypto, never node:crypto, so this
 * runs unchanged on Cloudflare Workers.
 */

/** The tag the registry's checkpoint signature covers. A format constant. */
export const REGISTRY_CHECKPOINT_TAG = "1f916.checkpoint.v1";

/** The tag a witness's countersignature over a head covers. A format constant. */
export const REGISTRY_WITNESS_TAG = "1f916.witness.v1";

const HEX_64 = /^[0-9a-f]{64}$/;

const encoder = new TextEncoder();

/**
 * Whether a value is exactly 64 lowercase hex characters — the shape every hash
 * on the registry's wire has. Uppercase is refused rather than folded: the
 * registry publishes lowercase, and accepting both would make two spellings of
 * one hash, one of which no proof was ever computed over.
 */
export function isHex64(text: unknown): text is string {
  return typeof text === "string" && HEX_64.test(text);
}

/** Whether a value is a safe, non-negative integer. Floats and NaN are not. */
function isSize(value: unknown): value is number {
  return typeof value === "number" && Number.isSafeInteger(value) && value >= 0;
}

/** A validated hex string as its bytes. */
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

async function sha256(bytes: Uint8Array): Promise<Uint8Array> {
  const digest = await globalThis.crypto.subtle.digest(
    "SHA-256",
    bytes as unknown as BufferSource,
  );
  return new Uint8Array(digest);
}

/**
 * The registry's leaf hash: SHA-256(0x00 || the event's chain hash, as the
 * lowercase-hex text the registry publishes, in UTF-8 bytes).
 *
 * The preimage is the hex *text*, not the 32 bytes it spells: the registry says
 * so in as many words ("the sealed rows' `hash` column values (lowercase hex, as
 * UTF-8 bytes)"), and hashing the decoded bytes instead would produce a leaf no
 * proof of theirs verifies against.
 */
export async function registryLeafHash(eventHashHex: string): Promise<string> {
  const leaf = encoder.encode(eventHashHex);
  const preimage = new Uint8Array(leaf.length + 1);
  preimage[0] = 0x00;
  preimage.set(leaf, 1);
  return bytesToHex(await sha256(preimage));
}

/** The registry's interior node: SHA-256(0x01 || left || right), both validated hex. */
async function registryNodeHash(left: string, right: string): Promise<string> {
  const preimage = new Uint8Array(65);
  preimage[0] = 0x01;
  preimage.set(hexToBytes(left), 1);
  preimage.set(hexToBytes(right), 33);
  return bytesToHex(await sha256(preimage));
}

/** One event's inclusion in one head. */
export interface RegistryInclusion {
  /** The leaf hash, already computed by `registryLeafHash`. */
  leafHash: string;
  /** The leaf's index in the log, zero-based. */
  leafIndex: number;
  /** The head's tree size, in leaves. */
  treeSize: number;
  /** The audit path, root-ward. */
  path: readonly string[];
  /** The head's root. */
  root: string;
}

/**
 * RFC 6962 section 2.1.1: fold the leaf hash up the audit path and compare.
 *
 * `fn` and `sn` track the node's index and the last index at its level, and
 * their parity (with the `fn === sn` right-edge case) says which side each
 * sibling sat on, so no direction flag from the wire is trusted. Every division
 * is an integer division rather than a bit shift: a tree size beyond 2^31 would
 * make `>>>` wrap, and the registry's log is not promised to stay small.
 */
export async function verifyRegistryInclusion(
  inclusion: RegistryInclusion,
): Promise<boolean> {
  if (typeof inclusion !== "object" || inclusion === null) return false;
  const { leafHash, leafIndex, treeSize, path, root } = inclusion;
  if (!isHex64(leafHash) || !isHex64(root)) return false;
  if (!isSize(leafIndex) || !isSize(treeSize)) return false;
  if (leafIndex >= treeSize) return false;
  if (!Array.isArray(path) || !path.every(isHex64)) return false;

  let fn = leafIndex;
  let sn = treeSize - 1;
  let hash = leafHash;

  for (const sibling of path) {
    if (sn === 0) return false;
    if (fn % 2 === 1 || fn === sn) {
      hash = await registryNodeHash(sibling, hash);
      while (fn !== 0 && fn % 2 === 0) {
        fn = Math.floor(fn / 2);
        sn = Math.floor(sn / 2);
      }
    } else {
      hash = await registryNodeHash(hash, sibling);
    }
    fn = Math.floor(fn / 2);
    sn = Math.floor(sn / 2);
  }

  return sn === 0 && hash === root;
}

/** Two heads of one log, and the proof that the later one only appended. */
export interface RegistryConsistency {
  fromSize: number;
  fromRoot: string;
  toSize: number;
  toRoot: string;
  path: readonly string[];
}

/**
 * Whether a size is an exact power of two (the complete-subtree case). By
 * division rather than `size & (size - 1)`, for the same reason the fold uses
 * integer division: a bitwise operator truncates to 32 bits.
 */
function isPowerOfTwo(size: number): boolean {
  if (size <= 0) return false;
  let value = size;
  while (value % 2 === 0) value = value / 2;
  return value === 1;
}

/**
 * RFC 6962 section 2.1.2: the proof reconstructs *both* roots from the shared
 * prefix, which is what makes it a proof that the log only appended.
 *
 * The old size being an exact power of two means the old tree is itself a
 * complete subtree of the new one, and the registry omits its root from the path
 * because the verifier already holds it; RFC 9162 section 2.1.4.2 says to
 * prepend it, and that is the one wire-format subtlety here.
 *
 * Two degenerate cases are answered rather than folded: the same size is
 * consistent only when the roots are equal and nothing was sent to prove it, and
 * an empty old tree is consistent with anything — but only against an empty
 * path, because a path offered for a tree with no leaves is a claim about
 * something that does not exist.
 */
export async function verifyRegistryConsistency(
  consistency: RegistryConsistency,
): Promise<boolean> {
  if (typeof consistency !== "object" || consistency === null) return false;
  const { fromSize, fromRoot, toSize, toRoot, path } = consistency;
  if (!isHex64(fromRoot) || !isHex64(toRoot)) return false;
  if (!isSize(fromSize) || !isSize(toSize)) return false;
  if (!Array.isArray(path) || !path.every(isHex64)) return false;
  if (fromSize > toSize) return false;
  if (fromSize === toSize) return path.length === 0 && fromRoot === toRoot;
  if (fromSize === 0) return path.length === 0;

  const steps = isPowerOfTwo(fromSize) ? [fromRoot, ...path] : [...path];
  const seed = steps[0];
  if (seed === undefined) return false;

  let fn = fromSize - 1;
  let sn = toSize - 1;
  while (fn % 2 === 1) {
    fn = Math.floor(fn / 2);
    sn = Math.floor(sn / 2);
  }

  let fr = seed;
  let sr = seed;
  for (const sibling of steps.slice(1)) {
    if (sn === 0) return false;
    if (fn % 2 === 1 || fn === sn) {
      fr = await registryNodeHash(sibling, fr);
      sr = await registryNodeHash(sibling, sr);
      while (fn !== 0 && fn % 2 === 0) {
        fn = Math.floor(fn / 2);
        sn = Math.floor(sn / 2);
      }
    } else {
      sr = await registryNodeHash(sr, sibling);
    }
    fn = Math.floor(fn / 2);
    sn = Math.floor(sn / 2);
  }

  return sn === 0 && fr === fromRoot && sr === toRoot;
}

/** A signed head of one registry log. */
export interface RegistryCheckpointFields {
  log: string;
  tree_size: number;
  root: string;
  created_at: number;
}

/**
 * What the registry's own signature covers:
 * `1f916.checkpoint.v1:<log>:<tree_size>:<root>:<created_at>`, in UTF-8.
 */
export function registryCheckpointPayload(
  head: RegistryCheckpointFields,
): Uint8Array {
  return encoder.encode(
    `${REGISTRY_CHECKPOINT_TAG}:${head.log}:${head.tree_size}:${head.root}:${head.created_at}`,
  );
}

/** A head as a witness attests it: the registry origin, and no clock. */
export interface RegistryWitnessFields {
  registry: string;
  log: string;
  tree_size: number;
  root: string;
}

/**
 * What a witness's countersignature covers:
 * `1f916.witness.v1:<registry>:<log>:<tree_size>:<root>`, in UTF-8.
 *
 * `created_at` is absent on purpose, and the registry says why: the witness
 * attests the head it verified, not the registry's clock.
 */
export function registryWitnessPayload(
  head: RegistryWitnessFields,
): Uint8Array {
  return encoder.encode(
    `${REGISTRY_WITNESS_TAG}:${head.registry}:${head.log}:${head.tree_size}:${head.root}`,
  );
}
