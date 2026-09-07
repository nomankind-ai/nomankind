/**
 * The immutable core: the seventeen keys the author signs.
 *
 * The schema's top-level $comment names the set: "IMMUTABLE CORE (never edited,
 * and the bytes the author signs), in this exact key set: ...". Every core field
 * is always present; evidence, observation, supersedes, and author_operator are
 * explicitly null when unused, never absent, so the JCS canonical JSON the
 * author signs is unambiguous.
 */

/** The seventeen core key names, in the schema's order. */
export const CORE_KEYS = [
  "id",
  "subject",
  "category",
  "claim",
  "before",
  "after",
  "effective_at",
  "evidence_tier",
  "evidence",
  "observation",
  "citation",
  "snapshot_hash",
  "norm_version",
  "supersedes",
  "author",
  "author_operator",
  "submitted_at",
] as const;

export type CoreKey = (typeof CORE_KEYS)[number];

/** The core object: exactly the seventeen keys, always present. */
export type Core = Record<CoreKey, unknown>;

/**
 * Core keys that are explicitly null when unused rather than absent. Every
 * other core key is required, and a missing one is an error naming the key.
 */
const NULLABLE_CORE_KEYS: readonly CoreKey[] = [
  "evidence",
  "observation",
  "supersedes",
  "author_operator",
];

/**
 * Extract the immutable core from an entry-shaped value.
 *
 * Returns a fresh object holding exactly CORE_KEYS, in that order. Any other
 * key on the input (signature, status, approvers, a derived field, anything
 * unknown) is dropped rather than carried through. The input is never mutated.
 */
export function extractCore(entry: unknown): Core {
  if (typeof entry !== "object" || entry === null || Array.isArray(entry)) {
    throw new Error("extractCore: entry must be an object");
  }
  const source = entry as Record<string, unknown>;
  const core: Record<string, unknown> = {};
  for (const key of CORE_KEYS) {
    const value = source[key];
    if (value === undefined) {
      if (NULLABLE_CORE_KEYS.includes(key)) {
        core[key] = null;
        continue;
      }
      throw new Error(`extractCore: missing required core key: ${key}`);
    }
    core[key] = value;
  }
  return core as Core;
}
