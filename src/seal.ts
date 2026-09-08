/**
 * The seal: batches of events committed to a Merkle root, chained.
 *
 * Whitepaper Section 6, "Seal": everything gets sealed, drafts and rejections
 * included; the entry hash is sealed as a fingerprint at submission; every later
 * event is hashed into a batch and sealed; the seal is self-performed but
 * unrewritable, and anyone can verify offline that an entry or event existed and
 * has not changed.
 *
 * Self-performed but unrewritable is the whole design here. Nomankind seals its
 * own log, so nothing stops it writing a seal — but each seal names the previous
 * seal's hash and commits to a contiguous run of event seqs, so rewriting an
 * event changes its hash, changes the batch root, changes the seal hash, and
 * breaks every seal after it. The witnesses countersign the seal hash and never
 * enter it, which is why they can be gathered after the fact without changing
 * what was sealed. Gathering them is another module's job (the witness rule and
 * the daily anchor), not this one's.
 *
 * Pure: the only time input is the injected clock, and nothing here does I/O.
 * Rule refusals are verdicts, never throws, as everywhere else in the kernel.
 */

import type { Clock } from "./derive.js";
import type { Event } from "./events.js";
import { canonicalize, taggedSha256Hex } from "./hash.js";
import {
  encodeProof,
  inclusionProof,
  merkleRoot,
  type InclusionProof,
} from "./merkle.js";

/**
 * Domain-separation tag for the seal hash. A format constant, not a policy
 * number: a seal hash can never be replayed as an event or entry hash.
 */
export const HASH_TAG_SEAL = "nomankind-seal-v1";

/**
 * One witness's countersignature over a seal. Declared here so the seal shape is
 * complete; the witness rule that fills it in (no two witnesses under common
 * control, nomankind ineligible) belongs to a later milestone.
 */
export interface WitnessSignature {
  agent: string;
  signature: string;
}

/** A sealed batch: a contiguous run of event seqs, committed and chained. */
export interface Seal {
  /** 0 for the first seal, then previous + 1. */
  seq: number;
  /** First event seq in the batch, inclusive. */
  first_seq: number;
  /** Last event seq in the batch, inclusive. */
  last_seq: number;
  /** last_seq - first_seq + 1. */
  size: number;
  /** Merkle root over the batch's event hashes, in seq order. */
  root: string;
  /** The injected clock's now. */
  sealed_at: string;
  /** The previous seal's hash; null for the first seal. */
  prev_hash: string | null;
  /** "sha256:" + hex of the tagged digest over the fields above. */
  hash: string;
  /** Countersignatures over `hash`. Empty when the seal is made. */
  witnesses: WitnessSignature[];
}

/** Why a seal was refused. */
export const SEAL_REFUSALS = ["nothing_new", "gap"] as const;
export type SealRefusal = (typeof SEAL_REFUSALS)[number];

export type SealResult =
  | { ok: true; seal: Seal }
  | { ok: false; reason: SealRefusal };

/** The fields the seal hash commits to: everything but the hash and the witnesses. */
type SealCore = Omit<Seal, "hash" | "witnesses">;

/**
 * The seal hash: the tagged SHA-256 over the JCS canonical form of the sealed
 * fields, prefixed "sha256:". The witnesses are excluded on purpose — they
 * countersign this hash, so a seal's identity has to exist before any of them
 * signs, and gathering one more witness later must not change what was sealed.
 */
export async function sealHash(fields: SealCore): Promise<string> {
  const canonical = canonicalize({
    seq: fields.seq,
    first_seq: fields.first_seq,
    last_seq: fields.last_seq,
    size: fields.size,
    root: fields.root,
    sealed_at: fields.sealed_at,
    prev_hash: fields.prev_hash,
  });
  return `sha256:${await taggedSha256Hex(HASH_TAG_SEAL, canonical)}`;
}

/** Events in seq order, without mutating the caller's array. */
function inSeqOrder(events: readonly Event[]): readonly Event[] {
  return [...events].sort((left, right) => left.seq - right.seq);
}

/**
 * Seal every event the previous seal did not cover.
 *
 * The batch runs from previous.last_seq + 1 (from 0 when there is no previous
 * seal) through the head, and refuses rather than papering over a hole: an
 * inclusion proof only means something if the batch is exactly the run it claims
 * to be. Never produces an empty seal — sealing nothing would chain a seal that
 * commits to nothing and still moves the chain forward.
 */
export async function buildSeal(
  events: readonly Event[],
  previous: Seal | null,
  clock: Clock,
): Promise<SealResult> {
  const start = previous === null ? 0 : previous.last_seq + 1;
  const batch = inSeqOrder(events).filter((event) => event.seq >= start);
  if (batch.length === 0) return { ok: false, reason: "nothing_new" };

  for (let index = 0; index < batch.length; index += 1) {
    if (batch[index]!.seq !== start + index) {
      return { ok: false, reason: "gap" };
    }
  }

  const fields: SealCore = {
    seq: previous === null ? 0 : previous.seq + 1,
    first_seq: start,
    last_seq: start + batch.length - 1,
    size: batch.length,
    root: await merkleRoot(batch.map((event) => event.hash)),
    sealed_at: clock.now,
    prev_hash: previous === null ? null : previous.hash,
  };
  return { ok: true, seal: { ...fields, hash: await sealHash(fields), witnesses: [] } };
}

/**
 * The batch's leaves, in seq order, or null when the log is missing one of the
 * events the seal claims to cover.
 */
function leavesFor(events: readonly Event[], seal: Seal): string[] | null {
  const bySeq = new Map<number, Event>();
  for (const event of events) {
    if (event.seq < seal.first_seq || event.seq > seal.last_seq) continue;
    if (bySeq.has(event.seq)) return null;
    bySeq.set(event.seq, event);
  }
  const leaves: string[] = [];
  for (let seq = seal.first_seq; seq <= seal.last_seq; seq += 1) {
    const event = bySeq.get(seq);
    if (event === undefined) return null;
    leaves.push(event.hash);
  }
  return leaves;
}

/**
 * Verify a seal offline: the events it names are all here, the batch is the size
 * it claims, their hashes recompute the root, the chain link matches, and the
 * seal hash recomputes. Editing any earlier event changes its hash and so the
 * root, which is exactly what this catches.
 */
export async function verifySeal(
  events: readonly Event[],
  seal: Seal,
  previous: Seal | null,
): Promise<boolean> {
  if (seal.size !== seal.last_seq - seal.first_seq + 1) return false;
  if (seal.prev_hash !== (previous === null ? null : previous.hash)) return false;

  const leaves = leavesFor(events, seal);
  if (leaves === null || leaves.length !== seal.size) return false;
  if ((await merkleRoot(leaves)) !== seal.root) return false;

  const { hash, witnesses: _witnesses, ...fields } = seal;
  return (await sealHash(fields)) === hash;
}

/** The seal covering an event seq, or null when nothing covers it yet. */
export function sealFor(seals: readonly Seal[], seq: number): Seal | null {
  for (const seal of seals) {
    if (seq >= seal.first_seq && seq <= seal.last_seq) return seal;
  }
  return null;
}

/**
 * The entry's `seal` object, exactly the schema's shape (additionalProperties
 * false, required log, inclusion_proof, sealed_at).
 */
export interface EntrySeal {
  log: "1F916";
  inclusion_proof: string;
  position: number;
  witnesses: string[];
  sealed_at: string;
}

/** The submission event for an entry, by the id inside its sealed core. */
function submissionEventOf(
  events: readonly Event[],
  entryId: string,
): Event<"entry_submitted"> | null {
  for (const event of inSeqOrder(events)) {
    if (event.type !== "entry_submitted") continue;
    const submitted = event as Event<"entry_submitted">;
    if (submitted.payload.core["id"] !== entryId) continue;
    return submitted;
  }
  return null;
}

async function entrySealFrom(
  events: readonly Event[],
  seals: readonly Seal[],
  submitted: Event<"entry_submitted">,
): Promise<EntrySeal | null> {
  const seal = sealFor(seals, submitted.seq);
  if (seal === null) return null;
  const leaves = leavesFor(events, seal);
  if (leaves === null) return null;

  let proof: InclusionProof;
  try {
    proof = await inclusionProof(leaves, submitted.seq - seal.first_seq);
  } catch {
    return null;
  }
  return {
    log: "1F916",
    inclusion_proof: encodeProof(proof),
    // The monotonic sealed coordinate the delta stream orders by: the event's
    // own seq, not its offset inside the batch, so it keeps growing across seals.
    position: submitted.seq,
    witnesses: seal.witnesses.map((witness) => witness.signature),
    sealed_at: seal.sealed_at,
  };
}

/**
 * The seal object for one entry: the inclusion proof of its `entry_submitted`
 * event within the batch that sealed it. Null when no seal covers that event
 * yet, and null when the log holds no submission for the id.
 *
 * Section 6: the entry hash is sealed as a fingerprint at submission, and the
 * submission event is what carries the signed core, so its inclusion is the
 * entry's proof of existence. Drafts and rejections are sealed like everything
 * else — nothing here asks the entry's status.
 */
export async function entrySeal(
  events: readonly Event[],
  seals: readonly Seal[],
  entryId: string,
): Promise<EntrySeal | null> {
  const submitted = submissionEventOf(events, entryId);
  if (submitted === null) return null;
  return entrySealFrom(events, seals, submitted);
}

/** Every submitted entry that is sealed, keyed by entry id. */
export async function sealsForEntries(
  events: readonly Event[],
  seals: readonly Seal[],
): Promise<Map<string, EntrySeal>> {
  const sealed = new Map<string, EntrySeal>();
  for (const event of inSeqOrder(events)) {
    if (event.type !== "entry_submitted") continue;
    const submitted = event as Event<"entry_submitted">;
    const entryId = submitted.payload.core["id"] as string;
    if (sealed.has(entryId)) continue;
    const built = await entrySealFrom(events, seals, submitted);
    if (built !== null) sealed.set(entryId, built);
  }
  return sealed;
}
