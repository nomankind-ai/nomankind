/**
 * The frozen reader: what may be asked, and which entry answers.
 *
 * Whitepaper Section 8, "The frozen reader". A reader asks for one fact and is
 * handed one entry, and every part of that choice is a rule rather than a
 * ranking: only a verified entry may be served, the reader may demand a
 * minimum evidence tier, and the reader may demand the answer be no older than
 * a stated number of days. An entry that fails any of the three is not served
 * at all — a stale or weakly-evidenced answer dressed up as an answer is worse
 * than no answer, because the reader cannot tell the difference.
 *
 * Pure: no I/O, no storage, and no wall clock. The candidate list comes from
 * the store, `now` is injected, and nothing here derives a field — status,
 * `last_confirmed` and the sidecar's `effective_tier` are read exactly as
 * src/derive.ts computed them.
 *
 * The category and tier enums are read from the entry schema itself, never
 * copied into TypeScript: the schema is the single source of truth for both,
 * and a query is refused against the published enum rather than against a list
 * that might have drifted from it.
 */

import entrySchema from "../schema/nomankind-entry-schema.json" with { type: "json" };

import { utcDay } from "./anchor.js";
import type { EntryStatus, Sidecar } from "./derive.js";
import type { EvidenceTier } from "./evidence.js";
import type { Category } from "./policy.js";
import type { Entry } from "./schema.js";

/** The schema's category enum. */
const CATEGORIES: readonly string[] = entrySchema.properties.category.enum;

/** The schema's evidence_tier enum. */
const EVIDENCE_TIERS: readonly string[] =
  entrySchema.properties.evidence_tier.enum;

/** Every query parameter a read may carry, and nothing else. */
export const READ_QUERY_PARAMETERS: readonly string[] = Object.freeze([
  "entry_id",
  "subject",
  "category",
  "min_tier",
  "max_age",
]);

/**
 * What a reader asked for: one named entry, or the current answer about one
 * subject in one category.
 *
 * The two are separate shapes rather than one bag of optional fields because
 * they are different questions. Naming an entry asks for that entry; naming a
 * subject asks nomankind to choose, and only then do the tier and age demands
 * mean anything.
 */
export type ReadQuery =
  | { readonly by: "entry"; readonly entry_id: string }
  | {
      readonly by: "subject";
      readonly subject: string;
      readonly category: Category;
      readonly min_tier?: EvidenceTier;
      /** Whole calendar days. Absent means the reader set no age demand. */
      readonly max_age?: number;
    };

/** Every reason a read query can be refused, in the order they are checked. */
export const READ_QUERY_REFUSALS = [
  "unknown_parameter",
  "bad_entry_id",
  "mixed_query",
  "missing_subject",
  "missing_category",
  "bad_category",
  "bad_min_tier",
  "bad_max_age",
] as const;

export type ReadQueryRefusal = (typeof READ_QUERY_REFUSALS)[number];

export type ReadQueryResult =
  | { ok: true; query: ReadQuery }
  | { ok: false; reason: ReadQueryRefusal };

/** The schema's `id` pattern, narrowed to the ids nomankind actually mints. */
const ENTRY_ID_PATTERN = /^nmk_[0-9a-f]{32}$/;

/** A non-negative safe integer written in plain decimal, with no sign or padding. */
const MAX_AGE_PATTERN = /^(0|[1-9][0-9]*)$/;

/** A unit constant, not a policy number: a day, stated in milliseconds. */
const MILLISECONDS_PER_DAY = 86_400_000;

/**
 * Read one query out of a URL's parameters.
 *
 * Refuses rather than ignores. An unknown parameter is refused because a reader
 * who misspelt `min_tier` would otherwise be handed an answer that quietly
 * ignored their demand, and a query mixing `entry_id` with a search is refused
 * because there is no honest way to answer both.
 *
 * The checks run in the declared order, so the same malformed query always gets
 * the same reason.
 */
export function parseReadQuery(params: URLSearchParams): ReadQueryResult {
  const known = new Set(READ_QUERY_PARAMETERS);
  for (const key of params.keys()) {
    if (!known.has(key)) return { ok: false, reason: "unknown_parameter" };
  }

  const entryId = params.get("entry_id");
  if (entryId !== null) {
    if (!ENTRY_ID_PATTERN.test(entryId)) {
      return { ok: false, reason: "bad_entry_id" };
    }
    for (const key of params.keys()) {
      if (key !== "entry_id") return { ok: false, reason: "mixed_query" };
    }
    return { ok: true, query: { by: "entry", entry_id: entryId } };
  }

  const subject = params.get("subject");
  if (subject === null || subject.length === 0) {
    return { ok: false, reason: "missing_subject" };
  }

  const category = params.get("category");
  if (category === null || category.length === 0) {
    return { ok: false, reason: "missing_category" };
  }
  if (!CATEGORIES.includes(category)) {
    return { ok: false, reason: "bad_category" };
  }

  const minTier = params.get("min_tier");
  if (minTier !== null && !EVIDENCE_TIERS.includes(minTier)) {
    return { ok: false, reason: "bad_min_tier" };
  }

  const maxAge = params.get("max_age");
  if (maxAge !== null && !MAX_AGE_PATTERN.test(maxAge)) {
    return { ok: false, reason: "bad_max_age" };
  }
  const maxAgeDays = maxAge === null ? undefined : Number(maxAge);
  if (maxAgeDays !== undefined && !Number.isSafeInteger(maxAgeDays)) {
    return { ok: false, reason: "bad_max_age" };
  }

  return {
    ok: true,
    query: {
      by: "subject",
      subject,
      category: category as Category,
      ...(minTier === null ? {} : { min_tier: minTier as EvidenceTier }),
      ...(maxAgeDays === undefined ? {} : { max_age: maxAgeDays }),
    },
  };
}

/**
 * Whether an entry's effective tier meets the reader's demand.
 *
 * Two tiers of evidence (Section 3): an observed entry rests on a measurement
 * someone made and receipted, a stated one on a document that said it. Observed
 * is the stronger, so it satisfies a demand for either; stated satisfies only a
 * demand for stated.
 *
 * The tier compared is the *effective* one — what the entry actually verified
 * at, sidecar.effective_tier — not the tier its signed core claims. An observed
 * entry whose test a majority of validators rejected verified as a document,
 * and a reader demanding a measurement must not be handed it.
 *
 * A null effective tier fails any demand. Null means the entry never verified,
 * or that nothing recorded what it verified at; either way there is no
 * measurement to promise, and answering "probably" to a reader who asked for
 * observed evidence is the one thing this function must never do.
 */
export function tierSatisfies(
  effectiveTier: EvidenceTier | null,
  minTier: EvidenceTier | undefined,
): boolean {
  if (minTier === undefined) return true;
  if (effectiveTier === null) return false;
  if (minTier === "stated") return true;
  return effectiveTier === "observed";
}

/**
 * Whether an entry was last confirmed recently enough for the reader's demand.
 *
 * Section 7, Freshness and decay: an entry carries the date it was last
 * confirmed, and a reader may refuse anything older than a number of days. The
 * comparison is on whole UTC calendar days — the same day boundary the anchor
 * uses — so every reader in the world agrees which day a confirmation belongs
 * to, and the answer does not move with the reader's timezone or the hour they
 * asked.
 *
 * The bound is inclusive: an entry confirmed exactly `maxAgeDays` days ago is
 * still within a demand for that many days. Dates are compared as text, which
 * for "YYYY-MM-DD" is chronological, and the arithmetic is done on whole day
 * numbers rather than on instants, so no floating point ever touches it.
 *
 * Counting in days is also what keeps an absurd demand harmless. A reader may
 * write any non-negative safe integer, and a cutoff instant that far before now
 * is outside what a Date can hold; asking for one would throw where a query
 * should merely be answered. So the subtraction happens on day numbers, and a
 * cutoff at or before the epoch is answered by the rule rather than by a date:
 * every date the schema accepts is on or after 1970-01-01, so nothing can be
 * older than such a cutoff and every candidate passes. This function never
 * throws, for any `maxAgeDays` the parser lets through.
 */
export function withinMaxAge(
  lastConfirmed: string,
  now: Date,
  maxAgeDays: number | undefined,
): boolean {
  if (maxAgeDays === undefined) return true;
  const nowDay = Math.floor(now.getTime() / MILLISECONDS_PER_DAY);
  const cutoffDay = nowDay - maxAgeDays;
  if (cutoffDay <= 0) return true;
  const cutoff = utcDay(new Date(cutoffDay * MILLISECONDS_PER_DAY).toISOString());
  return lastConfirmed >= cutoff;
}

/**
 * Whether an entry's status lets it be served at all.
 *
 * Only "verified". Draft has not been checked, rejected was checked and failed,
 * superseded has a newer answer that should be served instead, and overturned
 * was found to have never been true. Section 8 promises the reader an answer
 * the log stands behind, and those four are exactly the states it does not.
 */
export function isReadable(status: EntryStatus | string): boolean {
  return status === "verified";
}

/** One entry the store offered, with the sidecar that carries its effective tier. */
export interface ReadCandidate {
  readonly entry: Entry;
  readonly sidecar: Sidecar;
}

/**
 * Choose the entry to serve, or null when nothing qualifies.
 *
 * The caller passes candidates newest submission first, and this takes the
 * first that clears all three gates: verified, tier as demanded, and young
 * enough. Newest-first plus first-match is the whole ranking — there is no
 * score, and nothing here weighs one entry against another. If no candidate
 * clears the gates the reader is told nothing was found, never handed the best
 * of a bad set.
 */
export function chooseReadable(
  candidates: readonly ReadCandidate[],
  query: ReadQuery,
  now: Date,
): ReadCandidate | null {
  const minTier = query.by === "subject" ? query.min_tier : undefined;
  const maxAge = query.by === "subject" ? query.max_age : undefined;

  for (const candidate of candidates) {
    const record = candidate.entry as unknown as Record<string, unknown>;
    if (!isReadable(record["status"] as string)) continue;
    if (!tierSatisfies(candidate.sidecar.effective_tier, minTier)) continue;
    if (!withinMaxAge(record["last_confirmed"] as string, now, maxAge)) {
      continue;
    }
    return candidate;
  }
  return null;
}
