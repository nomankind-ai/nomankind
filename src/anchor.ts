/**
 * The daily anchor.
 *
 * Whitepaper, "Lifecycle of an entry" (Seal): anchoring each day's batch hash
 * into an external timestamping chain makes the existence proof independent of
 * the identity layer. If every witness vanished tomorrow, an anchored day still
 * proves the roots existed by then.
 *
 * An anchor is one record over one UTC calendar day: the roots of that day's
 * seals in seal order, the seq range they cover, and a hash over the pair. Pure
 * and self-contained: seals arrive typed structurally, so nothing is imported
 * from the seal module, and `buildAnchor` always leaves the external receipt
 * null — posting the hash is I/O, and an adapter's job.
 *
 * The receipt never enters the anchor hash (D-037, item 5). It is fetched after
 * the day's roots are fixed, and a hash that moved when the receipt arrived
 * would be a different anchor from the one that was posted.
 */

import { canonicalize, taggedSha256Hex } from "./hash.js";

/**
 * Domain-separation tag for the anchor hash. A format constant, not a policy
 * number.
 */
export const HASH_TAG_ANCHOR = "nomankind-anchor-v1";

/**
 * The little a seal must have for a day to be anchored: its sequence number,
 * its Merkle root, and when it was sealed. Structural on purpose, so this module
 * imports nothing from the seal module.
 */
export interface SealLike {
  seq: number;
  root: string;
  sealed_at: string;
}

/**
 * The external timestamp receipt, or null until one exists.
 *
 * One kind for now, named rather than left open: OpenTimestamps, the calendar
 * the hash was submitted to, when it was submitted, and the proof it returned.
 * A second chain later is a second member of this union, not a reshaping of it.
 */
export type AnchorExternal = {
  kind: "opentimestamps";
  calendar: string;
  submitted_at: string;
  proof: string;
} | null;

/**
 * What the anchor step needs of the outside world: post the day's hash and
 * bring back the receipt. Implementations live in src/adapters, because posting
 * is network I/O and nothing in the kernel may do any.
 */
export interface AnchorAdapter {
  anchor(anchor: Anchor): Promise<AnchorExternal>;
}

/** One day's anchor record. */
export interface Anchor {
  /** The UTC calendar day, "YYYY-MM-DD". */
  date: string;
  first_seal_seq: number | null;
  last_seal_seq: number | null;
  /** The day's seal roots, in seal seq order. */
  roots: string[];
  hash: string;
  /**
   * The external timestamp receipt, null until the hash was posted. Outside the
   * anchor hash: `anchorHash` covers the date and the roots and nothing else.
   */
  external: AnchorExternal;
}

const DATE_PATTERN = /^\d{4}-\d{2}-\d{2}$/;

/**
 * The UTC calendar day of an ISO 8601 date-time. The day is always the UTC one,
 * never the local one, so a seal written at 04:00+05:30 anchors to the previous
 * UTC day and every operator in the world agrees which day a seal belongs to.
 */
export function utcDay(dateTime: string): string {
  if (typeof dateTime !== "string") {
    throw new RangeError("utcDay: date-time must be a string");
  }
  const milliseconds = Date.parse(dateTime);
  if (Number.isNaN(milliseconds)) {
    throw new RangeError(`utcDay: unparsable date-time ${dateTime}`);
  }
  return new Date(milliseconds).toISOString().slice(0, 10);
}

/** Whether a string is exactly "YYYY-MM-DD" of a real calendar day. */
function isCalendarDate(date: string): boolean {
  if (typeof date !== "string" || !DATE_PATTERN.test(date)) {
    return false;
  }
  // Round-trip through UTC: only a real day survives unchanged, so 2026-02-30
  // (which would roll to March) is refused rather than quietly moved.
  const parsed = new Date(`${date}T00:00:00Z`);
  if (Number.isNaN(parsed.getTime())) {
    return false;
  }
  return parsed.toISOString().slice(0, 10) === date;
}

/** The anchor hash a verifier recomputes: tagged SHA-256 over the canonical { date, roots }. */
export async function anchorHash(
  date: string,
  roots: readonly string[],
): Promise<string> {
  const canonical = canonicalize({ date, roots });
  const digest = await taggedSha256Hex(HASH_TAG_ANCHOR, canonical);
  return `sha256:${digest}`;
}

/** Every reason an anchor can be refused. */
export const ANCHOR_REFUSALS = ["no_seals", "bad_date"] as const;

export type AnchorRefusal = (typeof ANCHOR_REFUSALS)[number];

export type AnchorResult =
  | { ok: true; anchor: Anchor }
  | { ok: false; reason: AnchorRefusal };

/** The day's seals, in seq order. */
function sealsOnDay(
  seals: readonly SealLike[],
  date: string,
): SealLike[] {
  return seals
    .filter((seal) => utcDay(seal.sealed_at) === date)
    .sort((left, right) => left.seq - right.seq);
}

/**
 * Build the anchor for one UTC day.
 *
 * A day with no seals is refused rather than anchored empty: an anchor asserts
 * that these roots existed, and an anchor over nothing asserts nothing while
 * looking like evidence.
 */
export async function buildAnchor(
  seals: readonly SealLike[],
  date: string,
): Promise<AnchorResult> {
  if (!isCalendarDate(date)) {
    return { ok: false, reason: "bad_date" };
  }

  const day = sealsOnDay(seals, date);
  if (day.length === 0) {
    return { ok: false, reason: "no_seals" };
  }

  const roots = day.map((seal) => seal.root);
  const hash = await anchorHash(date, roots);

  return {
    ok: true,
    anchor: {
      date,
      first_seal_seq: day[0]!.seq,
      last_seal_seq: day[day.length - 1]!.seq,
      roots,
      hash,
      external: null,
    },
  };
}

/**
 * Whether an anchor still tells the truth about the seals it covers: the same
 * roots in the same order, the same seq bounds, and a hash that recomputes.
 *
 * A seal added to an anchored day afterwards makes the anchor false rather than
 * stale: the day it claimed to cover is no longer the day it covers.
 *
 * Returns false rather than throwing; a verifier is asking a question, and
 * malformed input is an answer of "no".
 */
export async function verifyAnchor(
  anchor: Anchor,
  seals: readonly SealLike[],
): Promise<boolean> {
  try {
    if (!isCalendarDate(anchor.date)) {
      return false;
    }

    const day = sealsOnDay(seals, anchor.date);
    if (day.length === 0 || day.length !== anchor.roots.length) {
      return false;
    }
    for (let index = 0; index < day.length; index += 1) {
      if (day[index]!.root !== anchor.roots[index]) {
        return false;
      }
    }
    if (
      anchor.first_seal_seq !== day[0]!.seq ||
      anchor.last_seal_seq !== day[day.length - 1]!.seq
    ) {
      return false;
    }

    return anchor.hash === (await anchorHash(anchor.date, anchor.roots));
  } catch {
    return false;
  }
}
