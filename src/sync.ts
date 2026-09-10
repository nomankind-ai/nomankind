/**
 * The delta stream: what a training run may ask for, and which of the log's
 * events it is handed.
 *
 * Whitepaper Section 8, "The delta stream". A trainer does not re-download the
 * corpus; it asks for everything the log learned after a position it already
 * has, and is handed those events strictly in sealed order. Three things make
 * the stream usable rather than merely available:
 *
 * - Order is the sealed position and nothing else, so two trainers resuming
 *   from the same `from` get the same events in the same order, forever.
 * - `flatten` collapses a supersession chain to its newest entry. The chain
 *   stays reachable — the newest entry's signed core names what it supersedes —
 *   so nothing is hidden, but a trainer that only wants today's answer is not
 *   made to fold five years of corrections itself.
 * - An overturned entry is not silently dropped. It is delivered as an unlearn
 *   item, because a trainer that already ingested the entry has to be told the
 *   log now says it was never true; a stream that merely stopped mentioning it
 *   would leave the wrong fact in the model.
 *
 * Section 9, Money, is why the receipt is here too: "each delivered verified
 * entry counts as a read", so a sync is paid for exactly as a read is, and the
 * one signed sync receipt covering the whole response is what the trainer keeps
 * to check the day's published count against (src/receipt.ts).
 *
 * Pure: no I/O, no storage, no clock. The events come from the store, and
 * nothing here derives a field — a status or an effective tier is read exactly
 * as src/derive.ts computed it at the sealed head.
 *
 * The evidence tier enum is read from the entry schema itself, never copied
 * into TypeScript, exactly as src/read.ts reads it: the schema is the single
 * source of truth, and a query is refused against the published enum rather
 * than against a list that might have drifted from it.
 */

import entrySchema from "../schema/nomankind-entry-schema.json" with { type: "json" };

import type { EntryStatus } from "./derive.js";
import type { Event } from "./events.js";
import type { EvidenceTier } from "./evidence.js";
import { DEFAULT_DOMAIN, LIST_PAGE_LIMIT } from "./policy.js";
import { tierSatisfies } from "./read.js";
import {
  MIN_SOURCE_VALUES,
  sourceClassSatisfies,
  type SourceClass,
} from "./sources.js";

/** The schema's evidence_tier enum. */
const EVIDENCE_TIERS: readonly string[] =
  entrySchema.properties.evidence_tier.enum;

/** The schema's domain enum: every registered domain, from the schema itself. */
const DOMAINS: readonly string[] = entrySchema.properties.domain.enum;

/** Every query parameter a sync may carry, and nothing else. */
export const SYNC_QUERY_PARAMETERS: readonly string[] = Object.freeze([
  "from",
  "limit",
  "flatten",
  "min_tier",
  "min_source",
  "domain",
]);

/** Every reason a sync query can be refused, in the order they are checked. */
export const SYNC_QUERY_REFUSALS = [
  "unknown_parameter",
  "bad_from",
  "bad_limit",
  "bad_flatten",
  "bad_min_tier",
  "bad_min_source",
  "unknown_domain",
] as const;

export type SyncQueryRefusal = (typeof SYNC_QUERY_REFUSALS)[number];

/**
 * What a trainer asked for.
 *
 * Every field has a default, because a bare `/sync` is a legitimate question:
 * the whole log from the beginning, one page at a time. `min_tier` is null
 * rather than absent so the shape of the answer never depends on whether the
 * trainer wrote the parameter.
 */
export interface SyncQuery {
  /** The sealed position already held: the stream resumes strictly after it. */
  readonly from: number;
  readonly limit: number;
  readonly flatten: boolean;
  readonly min_tier: EvidenceTier | null;
  /**
   * The weakest source class the stream will carry (decision D-080): official,
   * recognized, or null for no demand. A different question from the tier — the
   * tier is how the claim was checked, the class is who said it — and a trainer
   * building a corpus of provider-stated facts asks this one.
   */
  readonly min_source: SourceClass | null;
  /**
   * The registered domain to stream. Null means every domain, which is what a
   * trainer replaying the whole log asks for.
   */
  readonly domain: string | null;
}

export type SyncQueryResult =
  | { ok: true; query: SyncQuery }
  | { ok: false; refusal: SyncQueryRefusal };

/** A non-negative safe integer in plain decimal, with no sign and no padding. */
const INTEGER_PATTERN = /^(0|[1-9][0-9]*)$/;

/**
 * Read one sync query out of a URL's parameters.
 *
 * Refuses rather than ignores, for the same reason the reader's parser does: a
 * trainer who misspelt `min_tier` would otherwise be handed a stream that
 * quietly ignored the demand and told itself it had filtered. A parameter given
 * twice is its own refusal — two values are two questions, and picking one of
 * them is guessing.
 *
 * The checks run in the declared order, so the same malformed query always gets
 * the same refusal.
 */
export function parseSyncQuery(params: URLSearchParams): SyncQueryResult {
  const known = new Set(SYNC_QUERY_PARAMETERS);
  for (const key of params.keys()) {
    if (!known.has(key)) return { ok: false, refusal: "unknown_parameter" };
  }

  const from = params.getAll("from");
  if (from.length > 1) return { ok: false, refusal: "bad_from" };
  const fromValue = from.length === 0 ? 0 : Number(from[0]);
  if (
    from.length === 1 &&
    (!INTEGER_PATTERN.test(from[0]!) || !Number.isSafeInteger(fromValue))
  ) {
    return { ok: false, refusal: "bad_from" };
  }

  const limit = params.getAll("limit");
  if (limit.length > 1) return { ok: false, refusal: "bad_limit" };
  const limitValue = limit.length === 0 ? LIST_PAGE_LIMIT : Number(limit[0]);
  if (
    limit.length === 1 &&
    (!INTEGER_PATTERN.test(limit[0]!) ||
      limitValue < 1 ||
      limitValue > LIST_PAGE_LIMIT)
  ) {
    return { ok: false, refusal: "bad_limit" };
  }

  const flatten = params.getAll("flatten");
  if (flatten.length > 1) return { ok: false, refusal: "bad_flatten" };
  if (flatten.length === 1 && flatten[0] !== "true" && flatten[0] !== "false") {
    return { ok: false, refusal: "bad_flatten" };
  }
  const flattenValue = flatten.length === 1 && flatten[0] === "true";

  const minTier = params.getAll("min_tier");
  if (minTier.length > 1) return { ok: false, refusal: "bad_min_tier" };
  if (minTier.length === 1 && !EVIDENCE_TIERS.includes(minTier[0]!)) {
    return { ok: false, refusal: "bad_min_tier" };
  }

  const minSource = params.getAll("min_source");
  if (minSource.length > 1) return { ok: false, refusal: "bad_min_source" };
  if (
    minSource.length === 1 &&
    !(MIN_SOURCE_VALUES as readonly string[]).includes(minSource[0]!)
  ) {
    return { ok: false, refusal: "bad_min_source" };
  }

  const domain = params.getAll("domain");
  if (domain.length > 1) return { ok: false, refusal: "unknown_domain" };
  if (domain.length === 1 && !DOMAINS.includes(domain[0]!)) {
    return { ok: false, refusal: "unknown_domain" };
  }

  return {
    ok: true,
    query: {
      from: fromValue,
      limit: limitValue,
      flatten: flattenValue,
      min_tier: minTier.length === 0 ? null : (minTier[0] as EvidenceTier),
      min_source:
        minSource.length === 0 ? null : (minSource[0] as SourceClass),
      domain: domain.length === 0 ? null : (domain[0] as string),
    },
  };
}

/**
 * What one delivered event is, to a trainer.
 *
 * An "entry" carries a fact to learn; an "unlearn" says a fact already learnt
 * was never true; an "event" is everything else the log recorded — a registry
 * change, a pool snapshot, a day's read count — which a trainer replaying the
 * log needs but which is about no single entry.
 */
export type SyncItemKind = "entry" | "unlearn" | "event";

/**
 * Which of the three an event is.
 *
 * `dispute_upheld` is the unlearn, and it is the only one: Section 6's dispute
 * is the single way the log says an entry was never true, and src/derive.ts
 * folds exactly that event into status "overturned" with `overturned_by` set.
 */
export function syncItemKind(event: Event): SyncItemKind {
  if (event.entry_id === null) return "event";
  if (event.type === "dispute_upheld") return "unlearn";
  return "entry";
}

/** An entry as derived at the sealed head, which is all the filters ask about. */
export interface SyncEntryState {
  readonly status: EntryStatus;
  readonly effective_tier: EvidenceTier | null;
  /**
   * The entry's domain, from its signed core (`domainOf`). Absent reads as the
   * default domain, exactly as a legacy v0.6 core does.
   */
  readonly domain?: string;
  /**
   * The class the entry's citation earned, off the sidecar derivation wrote
   * (decision D-080). Absent or null is a class the caller did not supply, and
   * it fails any demand — `sourceClassSatisfies` says why.
   */
  readonly source_class?: SourceClass | null;
}

/**
 * Whether one delivered item survives the query's filters.
 *
 * The entry filters only ever narrow entries. An unlearn is never filtered out —
 * a trainer that filtered its stream to observed evidence still ingested the
 * entry when it qualified, and must still be told it was overturned — and a
 * registry or read-count event is not about an entry at all, so no entry filter
 * can have an opinion about it. Filtering either would leave a trainer holding
 * a fact the log has withdrawn, which is the one failure the delta stream
 * exists to prevent.
 *
 * `flatten` drops a superseded entry, because the newest entry of the chain is
 * delivered instead and its signed core's `supersedes` keeps the chain
 * reachable. `min_tier` drops anything not verified, and anything whose
 * *effective* tier — what it actually verified at, never what its core claimed
 * — does not meet the demand, by the reader's own `tierSatisfies`. `min_source`
 * does the same for the class the entry's citation earned (decision D-080).
 *
 * A null state for an "entry" item is a programming error, not a refusal: the
 * caller read the event out of the log and failed to derive the entry it names.
 */
export function keepSyncItem(
  kind: SyncItemKind,
  state: SyncEntryState | null,
  query: SyncQuery,
): boolean {
  if (kind === "event") return true;

  // The domain filter is the one filter an unlearn is subject to, and for the
  // reason the others are not: an entry of another domain was never delivered
  // to this trainer, so being told it was overturned is noise about a fact it
  // does not hold. The head still advances past both (the caller's job), so a
  // filtered stream resumes exactly where an unfiltered one would.
  const demanded = query.domain ?? null;
  if (
    demanded !== null &&
    state !== null &&
    (state.domain ?? DEFAULT_DOMAIN) !== demanded
  ) {
    return false;
  }

  if (kind !== "entry") return true;
  if (state === null) {
    throw new Error("keepSyncItem: an entry item has no derived state");
  }
  if (query.flatten && state.status === "superseded") return false;
  if (query.min_tier !== null) {
    if (state.status !== "verified") return false;
    if (!tierSatisfies(state.effective_tier, query.min_tier)) return false;
  }
  // The source demand is the tier demand's twin and is applied beside it,
  // verified check and all: a trainer that asked where a fact came from is
  // asking for facts to learn, and an unverified entry is not one of those
  // whatever its citation says.
  if (query.min_source !== null) {
    if (state.status !== "verified") return false;
    if (!sourceClassSatisfies(state.source_class ?? null, query.min_source)) {
      return false;
    }
  }
  return true;
}

/** One entry the sync receipt covers: which entry, which version, what status. */
export interface SyncReceiptEntry {
  entry_id: string;
  entry_hash: string;
  status: EntryStatus;
}

/** One delivered item, as much of it as the receipt needs to name. */
export interface SyncItem {
  readonly kind: SyncItemKind;
  readonly entry_id: string | null;
  readonly entry_hash: string | null;
  readonly status: EntryStatus | null;
}

/**
 * The distinct entries a response delivered, in first-delivery order.
 *
 * Distinct, because one entry can be touched by several events in one page — a
 * submission and two validations — and a receipt that named it three times
 * would be a bill for three reads of one entry. First-delivery order, because
 * the stream's order is the sealed order and the receipt should read in the
 * same direction as the page it covers.
 *
 * `entry_hash` is the entry's core hash, so the receipt names the version that
 * was delivered: an entry later superseded cannot be passed off as the one this
 * trainer received.
 */
export function syncReceiptEntries(
  items: readonly SyncItem[],
): SyncReceiptEntry[] {
  const byId = new Map<string, SyncReceiptEntry>();
  for (const item of items) {
    if (item.kind === "event") continue;
    if (
      item.entry_id === null ||
      item.entry_hash === null ||
      item.status === null
    ) {
      throw new Error(
        `syncReceiptEntries: a ${item.kind} item names no entry, hash or status`,
      );
    }
    if (byId.has(item.entry_id)) continue;
    byId.set(item.entry_id, {
      entry_id: item.entry_id,
      entry_hash: item.entry_hash,
      status: item.status,
    });
  }
  return [...byId.values()];
}
