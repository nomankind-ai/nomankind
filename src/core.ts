/**
 * The immutable core: the eighteen keys the author signs.
 *
 * The schema's top-level $comment names the set: "IMMUTABLE CORE (never edited,
 * and the bytes the author signs), in this exact key set: ...". Every core field
 * is always present; evidence, observation, supersedes, and author_operator are
 * explicitly null when unused, never absent, so the JCS canonical JSON the
 * author signs is unambiguous.
 *
 * Schema v0.7 (decision D-071) added `domain` as the eighteenth key. It is a
 * key of the core rather than a field beside it because a fact filed in one
 * domain must never be re-homed into another: the id, the entry hash and the
 * author's signature all cover the whole core, so moving the field would rename
 * the entry and break the signature. Every core sealed under v0.6 carries
 * seventeen keys and keeps exactly the hash and signature it always had --
 * `extractCore` never adds the key it did not find (see below).
 */

import { DEFAULT_DOMAIN } from "./policy.js";

/** The eighteen core key names, in the schema's order. */
export const CORE_KEYS = [
  "id",
  "subject",
  "category",
  "domain",
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

/**
 * The core object: exactly the keys of the version it was sealed under -- the
 * eighteen of v0.7, or the seventeen of a legacy v0.6 core, which carries no
 * `domain` at all. `domain` is therefore typed as possibly absent and read
 * through `domainOf`, never off the object.
 */
export type Core = Omit<Record<CoreKey, unknown>, "domain"> & {
  domain?: unknown;
};

/**
 * The core key a legacy (v0.6) core does not carry at all.
 *
 * Absent is not null here and must never become null: a v0.6 core was signed as
 * seventeen keys, and adding an eighteenth -- with any value, null included --
 * would change its canonical form, its hash, its id and its signature. So
 * `extractCore` of a seventeen-key object returns seventeen keys.
 */
const LEGACY_ABSENT_CORE_KEY: CoreKey = "domain";

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
 *
 * The copy is deep (M1 reviewer note, decision D-041). A shallow copy left the
 * nested core values — the evidence and observation objects — aliasing the
 * caller's entry, so a later edit to the entry silently changed a core that had
 * already been extracted, hashed, or signed. structuredClone is available on
 * Node 22 and on Workers alike, so the kernel keeps running unchanged.
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
      if (key === LEGACY_ABSENT_CORE_KEY) {
        // A v0.6 core. The key is left out, not nulled: see the constant.
        continue;
      }
      if (NULLABLE_CORE_KEYS.includes(key)) {
        core[key] = null;
        continue;
      }
      throw new Error(`extractCore: missing required core key: ${key}`);
    }
    core[key] = value;
  }
  return structuredClone(core) as Core;
}

/**
 * The schema version a core was sealed under, read off the core itself and off
 * no table: `domain` is exactly what v0.7 added, so its presence is the version
 * and there is nothing else to consult. A reader holding one core can say which
 * rules it was signed under without holding the log.
 */
export function coreVersion(core: unknown): "v0.6" | "v0.7" {
  if (typeof core !== "object" || core === null || Array.isArray(core)) {
    return "v0.6";
  }
  return (core as Record<string, unknown>)["domain"] === undefined
    ? "v0.6"
    : "v0.7";
}

/**
 * The domain a core belongs to.
 *
 * A v0.7 core says so in its own signed bytes. A legacy v0.6 core says nothing,
 * and reads as the default domain -- not as a guess, but because ai-ecosystem
 * was the only domain there was when it was signed (src/policy.ts,
 * `DEFAULT_DOMAIN`). Every rule keyed by domain reads it through here, so the
 * legacy answer is given in one place rather than in twenty.
 */
export function domainOf(core: unknown): string {
  if (typeof core !== "object" || core === null || Array.isArray(core)) {
    return DEFAULT_DOMAIN;
  }
  const domain = (core as Record<string, unknown>)["domain"];
  return typeof domain === "string" ? domain : DEFAULT_DOMAIN;
}
