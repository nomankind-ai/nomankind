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
/**
 * One countersignature: the witness's agent id and the unpadded base64url of
 * its Ed25519 signature, the same encoding header and request signatures use.
 *
 * The shape belongs to the seal — a seal carries its countersignatures — so it
 * is imported as a type rather than declared twice, and the package's star
 * re-exports name one WitnessSignature, not two.
 */
import type { WitnessSignature } from "./seal.js";

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

/** The pinned set and the maintainer's own operators. Data only, no I/O. */
export interface WitnessContext {
  witnesses: readonly Witness[];
  maintainerOperators: ReadonlySet<string>;
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
] as const;

export type WitnessRefusal = (typeof WITNESS_REFUSALS)[number];

export type WitnessCheck =
  | { ok: true; witnesses: Witness[] }
  | { ok: false; reason: WitnessRefusal; agent: string };

/**
 * Check countersignatures against the pinned set.
 *
 * Signatures are taken in the order given; each is checked in WITNESS_REFUSALS
 * order and the first refusal wins, so a maintainer's witness whose signature is
 * also bad is refused maintainer_witness, naming the harder truth about who
 * signed rather than the softer one about how.
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
  const bytes = witnessSigningBytes(sealHash);

  for (const entry of signatures) {
    const witness = context.witnesses.find(
      (candidate) => candidate.agent === entry.agent,
    );
    if (witness === undefined) {
      return { ok: false, reason: "unknown_witness", agent: entry.agent };
    }

    // An id that does not carry a key is not an identity: refuse rather than
    // throw, so one malformed row cannot take down the whole check.
    let publicKeyRaw: Uint8Array;
    try {
      publicKeyRaw = publicKeyFromAgentId(witness.agent);
    } catch {
      return { ok: false, reason: "unknown_witness", agent: entry.agent };
    }

    if (context.maintainerOperators.has(witness.operator)) {
      return { ok: false, reason: "maintainer_witness", agent: entry.agent };
    }

    if (usedOperators.has(witness.operator)) {
      return { ok: false, reason: "duplicate_operator", agent: entry.agent };
    }

    let signature: Uint8Array;
    try {
      signature = base64urlDecode(entry.signature);
    } catch {
      return { ok: false, reason: "bad_signature", agent: entry.agent };
    }

    if (!(await verifyBytes(publicKeyRaw, bytes, signature))) {
      return { ok: false, reason: "bad_signature", agent: entry.agent };
    }

    accepted.push(witness);
    usedOperators.add(witness.operator);
  }

  return { ok: true, witnesses: accepted };
}
