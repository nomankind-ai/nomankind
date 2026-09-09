/**
 * The witness rule.
 *
 * Whitepaper, "Lifecycle of an entry" (Seal): the registry head is countersigned
 * by witnesses nomankind does not control. "Limitations" sets the bar for who
 * may countersign, and the schema's seal object states it in one line: "No two
 * witnesses under common control; nomankind ineligible."
 *
 * So a countersignature counts only when it comes from a witness in the pinned
 * set (decision D-033: nomankind pins a subset of the founding registry's
 * witness directory), under an operator that is not the maintainer's, and under
 * an operator no earlier accepted signature already used. Two keys held by one
 * operator are one witness, not two, and the second is a refusal.
 *
 * Pure and data-only: the pinned set and the maintainer's operators arrive as a
 * context, never fetched here. Ed25519 goes through WebCrypto, never
 * node:crypto, so this runs unchanged on Cloudflare Workers.
 *
 * How many witnesses a seal needs is deliberately not decided here; whether a
 * seal counts as witnessed is a later milestone's verdict.
 */

import { base64urlDecode, base64urlEncode } from "./encoding.js";
import { publicKeyFromAgentId, signBytes, verifyBytes } from "./identity.js";
import {
  isHex64,
  registryCheckpointPayload,
  registryLeafHash,
  registryWitnessPayload,
  verifyRegistryConsistency,
  verifyRegistryInclusion,
} from "./registry-proof.js";
/**
 * One countersignature: the witness's agent id and the unpadded base64url of
 * its Ed25519 signature, the same encoding header and request signatures use.
 *
 * The shape belongs to the seal — a seal carries its countersignatures — so it
 * is imported as a type rather than declared twice, and the package's star
 * re-exports name one WitnessSignature, not two.
 */
import type { Seal, WitnessSignature } from "./seal.js";

/**
 * Domain-separation tag for a witness countersignature. A format constant, not
 * a policy number: it names what the signature is over, so a signature made to
 * countersign a seal can never be replayed as any other signature.
 */
export const HASH_TAG_WITNESS = "nomankind-witness-v1";

/**
 * One row of the pinned witness set: a witness is a 1F916 agent (its public key
 * is inside the id) that belongs to an operator.
 */
export interface Witness {
  agent: string;
  operator: string;
}

/** The pinned set, who is ineligible, and the pinned registry. Data only, no I/O. */
export interface WitnessContext {
  witnesses: readonly Witness[];
  maintainerOperators: ReadonlySet<string>;
  /**
   * Nomankind's own agent ids: the maintainer agent and the sealing agent. The
   * paper makes nomankind ineligible, and an operator name is not enough to
   * enforce that — the sealing agent countersigning its own seal would be
   * nomankind witnessing itself whatever operator the directory files it under.
   */
  ineligibleAgents: ReadonlySet<string>;
  /**
   * The pinned registry: its origin and its Ed25519 public key, unpadded
   * base64url. Null on a set that only ever signs the direct form (the mock),
   * and a head offered against a null registry is refused: there is no key to
   * check the head's own signature with, so nothing about it is known.
   */
  registry: { origin: string; public_key: string } | null;
}

const encoder = new TextEncoder();

/** The bytes a witness signs to countersign a seal: the tag, a newline, the seal hash. */
export function witnessSigningBytes(sealHash: string): Uint8Array {
  return encoder.encode(`${HASH_TAG_WITNESS}\n${sealHash}`);
}

/**
 * Countersign a seal hash. Used by tests now and by the mock witness later; the
 * real witnesses run this construction in their own code, not ours.
 */
export async function signWitness(
  privateKey: CryptoKey,
  sealHash: string,
): Promise<string> {
  const signature = await signBytes(privateKey, witnessSigningBytes(sealHash));
  return base64urlEncode(signature);
}

/** Every reason a countersignature can be refused, in the order they are checked. */
export const WITNESS_REFUSALS = [
  "unknown_witness",
  "maintainer_witness",
  "duplicate_operator",
  "bad_signature",
  "bad_evidence",
] as const;

export type WitnessRefusal = (typeof WITNESS_REFUSALS)[number];

export type WitnessCheck =
  | { ok: true; witnesses: Witness[] }
  | { ok: false; reason: WitnessRefusal; agent: string };

/** One signature's verdict: the witness it came from, or why it was refused. */
type SignatureCheck =
  | { ok: true; witness: Witness }
  | { ok: false; reason: WitnessRefusal };

/** The consistency field a witness line carries when it really checked one. */
const VERIFIED_FROM = "verified from";

/**
 * The evidence half of the registry form: does this countersigned head actually
 * cover our seal's fingerprint?
 *
 * The witness signed a head, not our seal, so the head is only worth anything
 * once three things hold. The head is the registry we pinned. The witness
 * checked append-only-ness rather than merely observing a log for the first time
 * — a "first observation" line attests nothing about what came before it, which
 * is exactly the guarantee we are borrowing. And our event is a leaf under the
 * head the inclusion proof was fetched against, with a consistency proof closing
 * the gap to the countersigned head whenever the two differ.
 *
 * The countersigned head may sit on either side of the proof's head. The
 * registry answers an inclusion proof under the earliest checkpoint that covers
 * the event, and a witness countersigns whatever head was current when it ran,
 * so the countersigned head is usually the later of the two; either way the
 * consistency path is checked from the smaller tree into the larger, because
 * that is the only direction an append-only proof exists in, and it is empty
 * exactly when the two heads are one head. What the rule asks is unchanged: the
 * countersigned head must cover our leaf, and continuity between the two heads
 * has to be proven rather than assumed.
 */
async function checkEvidence(
  entry: WitnessSignature,
  context: WitnessContext,
): Promise<boolean> {
  const head = entry.head;
  const evidence = entry.evidence;
  if (head === undefined || evidence === undefined) return false;
  if (context.registry === null) return false;
  if (head.registry !== context.registry.origin) return false;
  if (typeof evidence.consistency !== "string") return false;
  if (!evidence.consistency.startsWith(VERIFIED_FROM)) return false;
  if (!Number.isSafeInteger(evidence.leaf_index)) return false;
  if (evidence.leaf_index < 0 || evidence.leaf_index >= head.tree_size) {
    return false;
  }
  if (!isHex64(evidence.event_hash)) return false;

  const provedAt = evidence.proved_at;
  if (typeof provedAt !== "object" || provedAt === null) return false;

  const included = await verifyRegistryInclusion({
    leafHash: await registryLeafHash(evidence.event_hash),
    leafIndex: evidence.leaf_index,
    treeSize: provedAt.tree_size,
    path: evidence.proof,
    root: provedAt.root,
  });
  if (!included) return false;

  // The same head proved it: there is nothing to bridge, and evidence that
  // carries a path anyway is not evidence of this pair of heads. An unchecked
  // path there would be a place to hide one, so it has to be empty.
  if (head.tree_size === provedAt.tree_size && head.root === provedAt.root) {
    return (
      Array.isArray(evidence.consistency_proof) &&
      evidence.consistency_proof.length === 0
    );
  }

  // Otherwise the bridge runs from whichever head is the smaller tree, which the
  // two sizes already in the evidence say; no field on the wire is trusted to
  // name the direction, and no direction is assumed.
  const forward = head.tree_size > provedAt.tree_size;
  return verifyRegistryConsistency({
    fromSize: forward ? provedAt.tree_size : head.tree_size,
    fromRoot: forward ? provedAt.root : head.root,
    toSize: forward ? head.tree_size : provedAt.tree_size,
    toRoot: forward ? head.root : provedAt.root,
    path: evidence.consistency_proof,
  });
}

/**
 * One countersignature against the pinned set, in WITNESS_REFUSALS order.
 *
 * `usedOperators` is what the caller has already counted; a check made without
 * one (the count below) asks only about this signature on its own.
 */
async function checkSignature(
  sealHash: string,
  entry: WitnessSignature,
  context: WitnessContext,
  usedOperators: ReadonlySet<string>,
): Promise<SignatureCheck> {
  const witness = context.witnesses.find(
    (candidate) => candidate.agent === entry.agent,
  );
  if (witness === undefined) return { ok: false, reason: "unknown_witness" };

  // An id that does not carry a key is not an identity: refuse rather than
  // throw, so one malformed row cannot take down the whole check.
  let publicKeyRaw: Uint8Array;
  try {
    publicKeyRaw = publicKeyFromAgentId(witness.agent);
  } catch {
    return { ok: false, reason: "unknown_witness" };
  }

  if (
    context.maintainerOperators.has(witness.operator) ||
    context.ineligibleAgents.has(witness.agent)
  ) {
    return { ok: false, reason: "maintainer_witness" };
  }

  if (usedOperators.has(witness.operator)) {
    return { ok: false, reason: "duplicate_operator" };
  }

  let signature: Uint8Array;
  try {
    signature = base64urlDecode(entry.signature);
  } catch {
    return { ok: false, reason: "bad_signature" };
  }

  const head = entry.head;
  if (head === undefined) {
    // The direct form: the witness signed our seal hash itself.
    const bytes = witnessSigningBytes(sealHash);
    if (!(await verifyBytes(publicKeyRaw, bytes, signature))) {
      return { ok: false, reason: "bad_signature" };
    }
    return { ok: true, witness };
  }

  // The registry form. Without a pinned registry there is no key to check the
  // head's own signature with, so the head is unverifiable rather than merely
  // unproven: that is a signature failure, not an evidence failure.
  if (context.registry === null) return { ok: false, reason: "bad_signature" };

  const countersigned = await verifyBytes(
    publicKeyRaw,
    registryWitnessPayload({
      registry: head.registry,
      log: head.log,
      tree_size: head.tree_size,
      root: head.root,
    }),
    signature,
  );
  if (!countersigned) return { ok: false, reason: "bad_signature" };

  let registrySignature: Uint8Array;
  try {
    registrySignature = base64urlDecode(head.registry_sig);
  } catch {
    return { ok: false, reason: "bad_signature" };
  }

  let registryKey: Uint8Array;
  try {
    registryKey = base64urlDecode(context.registry.public_key);
  } catch {
    return { ok: false, reason: "bad_signature" };
  }

  const headIsTheRegistrys = await verifyBytes(
    registryKey,
    registryCheckpointPayload({
      log: head.log,
      tree_size: head.tree_size,
      root: head.root,
      created_at: head.created_at,
    }),
    registrySignature,
  );
  if (!headIsTheRegistrys) return { ok: false, reason: "bad_signature" };

  if (!(await checkEvidence(entry, context))) {
    return { ok: false, reason: "bad_evidence" };
  }
  return { ok: true, witness };
}

/**
 * Check countersignatures against the pinned set.
 *
 * Signatures are taken in the order given; each is checked in WITNESS_REFUSALS
 * order and the first refusal wins, so a maintainer's witness whose signature is
 * also bad is refused maintainer_witness, naming the harder truth about who
 * signed rather than the softer one about how. Evidence is asked last for the
 * same reason from the other end: a head nobody signed is not evidence of
 * anything, so there is no point asking what it covers.
 *
 * Both forms are accepted per signature. The direct form countersigns our seal
 * hash; the registry form countersigns the registry's head, and carries the
 * evidence that our seal's fingerprint sits under it.
 *
 * An empty list is ok with no witnesses: nothing was offered and nothing was
 * wrong. Whether a seal with no witnesses counts as witnessed is not asked here.
 */
export async function checkWitnesses(
  sealHash: string,
  signatures: readonly WitnessSignature[],
  context: WitnessContext,
): Promise<WitnessCheck> {
  const accepted: Witness[] = [];
  const usedOperators = new Set<string>();

  for (const entry of signatures) {
    const result = await checkSignature(sealHash, entry, context, usedOperators);
    if (!result.ok) {
      return { ok: false, reason: result.reason, agent: entry.agent };
    }
    accepted.push(result.witness);
    usedOperators.add(result.witness.operator);
  }

  return { ok: true, witnesses: accepted };
}

/**
 * How many distinct operators countersigned this seal and passed.
 *
 * Unlike `checkWitnesses`, one bad signature does not end the count: a seal
 * offered four countersignatures of which one is forged still has three real
 * ones, and refusing to count them would let anyone unwitness a seal by
 * appending garbage to it. Operators, not signatures — two keys under one
 * operator are one witness (D-033) — so the answer is the size of the set.
 *
 * How many are enough is deliberately not decided here: that number is policy,
 * and policy numbers live in src/policy.ts.
 */
export async function witnessedCount(
  seal: Seal,
  context: WitnessContext,
): Promise<number> {
  const operators = new Set<string>();
  for (const entry of seal.witnesses) {
    // The empty set: each signature is judged on its own, and the distinctness
    // of operators is what the set below records.
    const result = await checkSignature(seal.hash, entry, context, new Set());
    if (result.ok) operators.add(result.witness.operator);
  }
  return operators.size;
}
