/**
 * What an entries listing may be asked, and what it refuses.
 *
 * The same posture as the frozen reader (src/read.ts): a query is checked
 * against the published enums and refused by name, never coerced into something
 * close enough. An unknown parameter is a refusal rather than a shrug, because a
 * reader who mistyped `catagory=pricing` and got the unfiltered list back would
 * believe they had filtered it.
 *
 * The category, status and tier enums are read from the entry schema itself and
 * never copied into TypeScript. The schema is the single source of truth for all
 * three, and a list retyped here is a list that will drift from it. The source
 * classes come from src/sources.ts for the same reason: there is one list of
 * them and this is not a second.
 *
 * Pure: no I/O, no storage, no clock.
 */

import entrySchema from "../../schema/nomankind-entry-schema.json" with { type: "json" };

import { SOURCE_CLASSES } from "../sources.js";
import type { EntriesFilter } from "./types.js";

/** The schema's category enum. */
export const ENTRY_CATEGORIES: readonly string[] = Object.freeze([
  ...entrySchema.properties.category.enum,
]);

/** The schema's domain enum: every registered domain, from the schema itself. */
export const ENTRY_DOMAINS: readonly string[] = Object.freeze([
  ...entrySchema.properties.domain.enum,
]);

/** The schema's status enum. */
export const ENTRY_STATUSES: readonly string[] = Object.freeze([
  ...entrySchema.properties.status.enum,
]);

/** The schema's evidence_tier enum. The listing filters the effective tier. */
export const ENTRY_TIERS: readonly string[] = Object.freeze([
  ...entrySchema.properties.evidence_tier.enum,
]);

/**
 * The three source classes (decision D-080). Not a schema enum either: the class
 * is derived from the entry's citation against the domain's published tables
 * (src/policy.ts, src/sources.ts), so this is that list and never a second copy
 * of it. `other` is a value here where it is not one for the reader's
 * `min_source`, because a chip is an exact class and not a minimum: a reader
 * looking for the entries nobody has published an authority for asks for
 * exactly those.
 */
export const ENTRY_SOURCES: readonly string[] = Object.freeze([
  ...SOURCE_CLASSES,
]);

/**
 * The freshness filter's two values. Not a schema enum: `stale` is a derived
 * boolean (src/derive.ts), so this is the two ways of asking about it and
 * nothing more.
 */
export const FRESHNESS_VALUES: readonly ["fresh", "stale"] = Object.freeze([
  "fresh",
  "stale",
]);

/** Every parameter an entries listing may carry, and nothing else. */
export const ENTRIES_QUERY_PARAMETERS: readonly string[] = Object.freeze([
  "category",
  "status",
  "domain",
  "tier",
  "source",
  "fresh",
  "before",
]);

/**
 * Why a query was refused, in the order the checks run. The order is part of the
 * contract: a query wrong in two ways is reported by its first fault, so the
 * refusal a reader sees does not depend on how the parser happens to be written.
 */
export const ENTRIES_QUERY_REFUSALS = [
  "unknown_parameter",
  "repeated_parameter",
  "bad_category",
  "bad_status",
  "unknown_domain",
  "bad_tier",
  "bad_source",
  "bad_fresh",
  "bad_before",
] as const;

export type EntriesQueryRefusal = (typeof ENTRIES_QUERY_REFUSALS)[number];

/**
 * The filter a listing applies. `domain` is carried beside the fields
 * src/ui/types.ts already declares (decision D-071): a chip group filters the
 * listing and the counters by domain, and "all" is the absent value.
 */
export type EntriesQueryFilter = EntriesFilter & {
  readonly domain: string | null;
};

export type EntriesQueryResult =
  | { ok: true; filter: EntriesQueryFilter; before: number | null }
  | { ok: false; reason: EntriesQueryRefusal };

/**
 * One enum-valued parameter: absent, or a value the enum holds. An empty value
 * (`?category=`) is a refusal and not an absence — the reader asked for a
 * category and named none, which is a mistake, not the unfiltered list.
 */
function readEnum(
  params: URLSearchParams,
  name: string,
  allowed: readonly string[],
): { ok: true; value: string | null } | { ok: false } {
  if (!params.has(name)) return { ok: true, value: null };
  const value = params.get(name) ?? "";
  if (!allowed.includes(value)) return { ok: false };
  return { ok: true, value };
}

/**
 * Parse an entries query.
 *
 * `before` is the keyset cursor: rows strictly before this sealed position, so
 * a page is an index seek whose cost does not grow with how far in it is and an
 * entry appended between two pages cannot shift a row across the boundary. Zero
 * is a legitimate position, so the bound is non-negative rather than positive.
 */
export function parseEntriesQuery(params: URLSearchParams): EntriesQueryResult {
  for (const name of params.keys()) {
    if (!ENTRIES_QUERY_PARAMETERS.includes(name)) {
      return { ok: false, reason: "unknown_parameter" };
    }
  }
  for (const name of ENTRIES_QUERY_PARAMETERS) {
    if (params.getAll(name).length > 1) {
      return { ok: false, reason: "repeated_parameter" };
    }
  }

  const category = readEnum(params, "category", ENTRY_CATEGORIES);
  if (!category.ok) return { ok: false, reason: "bad_category" };
  const status = readEnum(params, "status", ENTRY_STATUSES);
  if (!status.ok) return { ok: false, reason: "bad_status" };
  const domain = readEnum(params, "domain", ENTRY_DOMAINS);
  if (!domain.ok) return { ok: false, reason: "unknown_domain" };
  const tier = readEnum(params, "tier", ENTRY_TIERS);
  if (!tier.ok) return { ok: false, reason: "bad_tier" };
  const source = readEnum(params, "source", ENTRY_SOURCES);
  if (!source.ok) return { ok: false, reason: "bad_source" };
  const fresh = readEnum(params, "fresh", FRESHNESS_VALUES);
  if (!fresh.ok) return { ok: false, reason: "bad_fresh" };

  let before: number | null = null;
  if (params.has("before")) {
    const text = params.get("before") ?? "";
    if (!/^\d+$/.test(text)) return { ok: false, reason: "bad_before" };
    const value = Number(text);
    if (!Number.isSafeInteger(value)) return { ok: false, reason: "bad_before" };
    before = value;
  }

  return {
    ok: true,
    filter: {
      category: category.value,
      status: status.value,
      domain: domain.value,
      tier: tier.value,
      source: source.value,
      fresh: fresh.value as "fresh" | "stale" | null,
    },
    before,
  };
}
