/**
 * The release window: when a sealed event's content becomes public.
 *
 * Decision D-100, and the whitepaper as it amends it — Section 8's "training on
 * the data itself is free" is free *on release*, Section 10's "free to read at
 * low volume, forever" is free to read at low volume *once released*, forever,
 * and the paid product is the window. One rule, written once, here: an event's
 * release date is its covering seal's `sealed_at` plus RELEASE_WINDOW_DAYS
 * (D-101, thirty days, the maintainer's published number), an entry's release
 * date is its `entry_submitted` event's, and an unsealed event is not released
 * at all. The same rule on every environment, with no override anywhere.
 *
 * What the window covers is content and only content. The proof is public from
 * the first minute and this module never touches it: every event keeps its seq,
 * instant, type, entry id, prev_hash and hash, and every entry keeps its id,
 * domain, subject, category, status, effective tier, entry hash, seal object,
 * signers, the hashes inside its records and its release date. A withheld event
 * is a hash line — the same event with `payload: null` and `withheld: true`
 * beside it — so the chain still links, the seal's Merkle root is still over the
 * same leaves, and a reader who cannot yet see what happened can still prove
 * that it happened, in that order, at that instant.
 *
 * Pure, and over one argument each. No clock is read here: `now` is the instant
 * the caller's injected clock gave, which is what lets a test stand on either
 * side of a boundary. No storage, no network, no policy number but the window,
 * which is src/policy.ts's. `withholdEntry` is the one asynchronous function
 * here, and only because a digest is: it hashes the whole core before it nulls
 * anything, so the proof a withheld entry travels with is the hash the log
 * sealed rather than a hash of the holes.
 */

import type { Sidecar } from "./derive.js";
import type { Event } from "./events.js";
import { entryHash } from "./hash.js";
import { RELEASE_WINDOW_DAYS } from "./policy.js";
import type { Entry } from "./schema.js";
import type { Seal } from "./seal.js";

/** How many milliseconds a day is. Not a policy number: it is what a day is. */
const MILLISECONDS_PER_DAY = 86_400_000;

/**
 * The core fields that are content rather than proof, which is what a withheld
 * entry has nulled.
 *
 * The seven of the eighteen core keys that say what the world is: the claim
 * itself, what it changed from and to, when it took effect, where it was read,
 * and the evidence and observation behind it. Everything else in the core —
 * the id, the subject, the category, the domain, the tier, the snapshot hash,
 * the norm version, what it supersedes, the author, its operator and the
 * instant it was submitted — is proof, and proof is never withheld.
 */
export const CONTENT_CORE_KEYS: readonly string[] = Object.freeze([
  "claim",
  "before",
  "after",
  "effective_at",
  "citation",
  "evidence",
  "observation",
]);

/**
 * The one field of a decision record that is content: the words a validator or
 * a reconfirmer wrote. The agent, the operator, the decision, the hashes and
 * the instants are proof and stay exactly as they are.
 */
const CONTENT_RECORD_KEY = "reason";

/** The record arrays of an entry whose `reason` is withheld before release. */
const RECORD_ARRAYS: readonly string[] = Object.freeze([
  "approvers",
  "reconfirmations",
]);

/**
 * The instant a seal's events become public: its `sealed_at` plus the window.
 *
 * Computed rather than stored, exactly as the M24c disclosure date is, so that
 * changing the published window changes every release date at once and no row
 * anywhere carries a date the policy no longer agrees with.
 */
export function releaseDateOf(sealedAt: string): string {
  const at = Date.parse(sealedAt);
  if (Number.isNaN(at)) {
    throw new TypeError(`releaseDateOf: not an instant: ${sealedAt}`);
  }
  return new Date(at + RELEASE_WINDOW_DAYS * MILLISECONDS_PER_DAY).toISOString();
}

/**
 * Whether something sealed at `sealedAt` is released at `now`.
 *
 * Null is not released: an event the log has not sealed yet has no release date
 * to have reached, and the window starts at the seal rather than at the
 * submission. The boundary is inclusive — released exactly at the window — for
 * the same reason a cap resets at the start of a day rather than after it.
 */
export function isReleased(sealedAt: string | null, now: Date): boolean {
  if (sealedAt === null) return false;
  return now.getTime() >= Date.parse(releaseDateOf(sealedAt));
}

/** The fields of a seal this module needs: when it was made, and what it covers. */
export type ReleaseSeal = Pick<Seal, "last_seq" | "sealed_at">;

/**
 * The highest position whose content is public at `now`: the largest `last_seq`
 * among the seals whose release date has arrived, or null when none has.
 *
 * The largest rather than the last of the list, for the reason `buildMirror`
 * takes the newest seal by seq: a caller that paged the chain out of two reads
 * could hand it over in any order, and the boundary a free reader is served to
 * must not depend on that.
 */
export function releasedHead(
  seals: readonly ReleaseSeal[],
  now: Date,
): number | null {
  let head: number | null = null;
  for (const seal of seals) {
    if (!isReleased(seal.sealed_at, now)) continue;
    if (head === null || seal.last_seq > head) head = seal.last_seq;
  }
  return head;
}

/**
 * One event as a hash line: everything but what happened.
 *
 * The payload goes to null and `withheld: true` stands beside it, in that order,
 * so the line reads as the event it is and says why it is short. The hash is the
 * event's own and is never recomputed over the shortened line — it is the hash
 * the log committed to and the leaf the seal's root is over, and a reader
 * checking the chain checks the links and the roots rather than re-digesting a
 * payload nobody handed them.
 *
 * Idempotent: withholding a hash line again is the same hash line, which is what
 * lets an export built from an already-withheld read be byte-identical to one
 * built from the whole log.
 */
export interface WithheldEvent {
  readonly seq: number;
  readonly at: string;
  readonly type: Event["type"];
  readonly entry_id: string | null;
  readonly payload: null;
  readonly prev_hash: string | null;
  readonly hash: string;
  readonly withheld: true;
}

/** The event with its payload replaced by null and `withheld: true` beside it. */
export function withholdEvent(event: Event): WithheldEvent {
  return {
    seq: event.seq,
    at: event.at,
    type: event.type,
    entry_id: event.entry_id,
    payload: null,
    prev_hash: event.prev_hash,
    hash: event.hash,
    withheld: true,
  };
}

/** Whether a line read back out of a mirror or a door is a withheld one. */
export function isWithheld(event: unknown): boolean {
  if (typeof event !== "object" || event === null) return false;
  return (event as Record<string, unknown>)["withheld"] === true;
}

/**
 * An unreleased entry as it is served and mirrored: the proof, the sidecar, and
 * the date the rest of it opens.
 *
 * `release_date` is at the top level and never inside the entry object: the
 * schema's shape is what a released entry is served under, and an extra key
 * inside it would make every reader's validator refuse the one document the
 * window exists to still be able to serve. A withheld entry travels under
 * `proof` rather than `entry` for the same reason — a reader must not be able to
 * mistake a nulled claim for the claim.
 */
export interface WithheldEntry {
  /** The entry with its content fields nulled; every proof field untouched. */
  readonly proof: Entry;
  /** Unchanged: every sidecar key is derived from proof (D-100). */
  readonly sidecar: Sidecar;
  /**
   * The entry hash, over the whole core, exactly as the log sealed it.
   *
   * The one number that makes a withheld entry checkable at all: the proof is
   * the claim that this record exists at this position under this seal, and a
   * reader handed a nulled core has nothing to digest for themselves. So it is
   * computed here, before a single field is nulled, and travels in the envelope
   * — which is what lets a reader who buys the content later, or waits for the
   * window, confirm that what they are handed is the entry they were promised.
   */
  readonly entry_hash: string;
  /** The instant the content opens: the covering seal's, through the window. */
  readonly release_date: string;
}

/**
 * The entry with its content fields set to null, its approvers' and
 * reconfirmers' reasons with them, and the release date beside it.
 *
 * Nulled where present and never added where absent: a change entry carries
 * `before` and `after` and a stated one does not, and a withheld copy that grew
 * a key would be a different document from the one the log proves.
 *
 * Asynchronous for one reason: the entry hash beside the proof is a SHA-256 and
 * WebCrypto's digest is a promise. It is taken over `entry` before the nulling,
 * so it equals the hash of the released entry to the byte.
 */
export async function withholdEntry(
  entry: Entry,
  sidecar: Sidecar,
  releaseDate: string,
): Promise<WithheldEntry> {
  // Over the entry as it came in, and never over `proof`: the hash is the one
  // the core was signed and sealed under, and a digest taken after the nulling
  // would be a digest of this function's own output.
  const hash = await entryHash(entry);
  const proof: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(entry)) {
    if (CONTENT_CORE_KEYS.includes(key)) {
      proof[key] = null;
      continue;
    }
    if (RECORD_ARRAYS.includes(key) && Array.isArray(value)) {
      proof[key] = value.map((record) => withholdRecord(record));
      continue;
    }
    proof[key] = value;
  }
  return {
    proof: proof as Entry,
    sidecar,
    entry_hash: hash,
    release_date: releaseDate,
  };
}

/** One decision record with its `reason` withheld, if it carries one at all. */
function withholdRecord(record: unknown): unknown {
  if (typeof record !== "object" || record === null || Array.isArray(record)) {
    return record;
  }
  const held = record as Record<string, unknown>;
  if (!Object.prototype.hasOwnProperty.call(held, CONTENT_RECORD_KEY)) {
    return record;
  }
  const copy: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(held)) {
    copy[key] = key === CONTENT_RECORD_KEY ? null : value;
  }
  return copy;
}
