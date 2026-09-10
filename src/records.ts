/**
 * Record signatures: the bytes a validator or a reconfirmer signs.
 *
 * Decision D-034 puts the signature beside the record in the event payload
 * rather than inside the record, because the schema's `approvers[]` and
 * `reconfirmations[]` items have no field for it: the entry carries the
 * decision, the log carries the proof of who made it. What that signature is
 * over was left open, and this module closes it.
 *
 * The construction mirrors the witness countersignature (src/witness.ts): a
 * domain-separation tag, a newline, and the RFC 8785 canonical JSON of what is
 * being signed. The entry id and the kind are inside the signed bytes, so a
 * validation record signed for one entry can never be replayed as a
 * reconfirmation, or onto another entry.
 *
 * Ed25519 goes through WebCrypto only (src/identity.ts), so this runs unchanged
 * on Cloudflare Workers. Nothing here reads a clock or does I/O.
 */

import { base64urlDecode, base64urlEncode } from "./encoding.js";
import { canonicalize } from "./hash.js";
import { publicKeyFromAgentId, signBytes, verifyBytes } from "./identity.js";

/**
 * Domain-separation tag for a record signature. A format constant, not a policy
 * number: it names what the signature is over, so a signature made to sign a
 * decision can never be replayed as an entry, event, seal or witness signature.
 */
export const HASH_TAG_RECORD = "nomankind-record-v1";

/**
 * The kinds of signed record, named exactly as their event types are — with
 * `attestation_score` named for its event `attestation_scored`, in the noun form
 * the payload's own `record` field takes.
 *
 * An attestation is not about an entry, so an `attestation_score` puts the
 * ATTESTATION ID in the `entryId` slot of the signing bytes. The slot is a
 * domain separator either way: what it carries is whatever the record is about,
 * and the ids cannot collide because an entry id is `nmk_` and an attestation id
 * is `att_`. A score signed for one attestation therefore cannot be replayed
 * onto another, and the kind keeps it from being replayed as a validation.
 */
export type RecordKind =
  | "validation"
  | "reconfirmation"
  | "attestation_score";

const encoder = new TextEncoder();

/**
 * The exact bytes a signer signs: the tag, a newline, and the canonical JSON of
 * the entry id, the kind, and the record itself.
 */
export function recordSigningBytes(
  entryId: string,
  kind: RecordKind,
  record: unknown,
): Uint8Array {
  const canonical = canonicalize({ entry_id: entryId, kind, record });
  return encoder.encode(`${HASH_TAG_RECORD}\n${canonical}`);
}

/**
 * Sign a record, returning the unpadded base64url signature the event payload
 * carries — the same encoding the witness and request signatures use.
 */
export async function signRecord(
  entryId: string,
  kind: RecordKind,
  record: unknown,
  privateKey: CryptoKey,
): Promise<string> {
  const signature = await signBytes(
    privateKey,
    recordSigningBytes(entryId, kind, record),
  );
  return base64urlEncode(signature);
}

/**
 * Verify a record signature against the key inside the record's own `agent` id
 * (D-014: an agent id is its public key).
 *
 * Returns false, never throws, on any malformed input: a record that is not an
 * object, an agent id that carries no key, a signature that is not base64url. A
 * verifier reading someone else's log gets a verdict, not an exception.
 */
export async function verifyRecordSignature(
  entryId: string,
  kind: RecordKind,
  record: unknown,
  signature: string,
): Promise<boolean> {
  try {
    if (typeof record !== "object" || record === null || Array.isArray(record)) {
      return false;
    }
    if (typeof signature !== "string") {
      return false;
    }
    const agent = (record as Record<string, unknown>)["agent"];
    if (typeof agent !== "string") {
      return false;
    }
    return await verifyBytes(
      publicKeyFromAgentId(agent),
      recordSigningBytes(entryId, kind, record),
      base64urlDecode(signature),
    );
  } catch {
    return false;
  }
}
