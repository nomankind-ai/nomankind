/**
 * Duplicate claims: the same fact filed twice (decision D-085).
 *
 * Whitepaper section 6, Submit: the log refuses the mechanical case at the
 * door. Two entries are the same claim when they name the same domain, the
 * same subject and the same category and assert the same value — the `after`
 * of the core, normalized under step 4 of norm-v1.2 so that whitespace and
 * case-in-whitespace differences do not buy a second copy of a fact.
 *
 * What is deliberately NOT decided here is the judgment case. Whether two
 * differently worded claims mean the same thing, or whether the same value at a
 * different `effective_at` is a restatement or a fresh observation, is a
 * question about meaning, and the paper gives it to the validators under a
 * published rejection form (src/duplicate-reason.ts). This module answers only
 * the mechanical question, and answers it the same way for every domain.
 *
 * A fact may be refiled after it stops standing: `rejected`, `superseded` and
 * `overturned` entries are not live, so a new entry with the same key is
 * accepted. A live entry may still be replaced — that is what `supersedes` is
 * for — so the entry a core names as its target is never counted against it.
 *
 * Pure and synchronous: no I/O, no clock, no policy numbers, and it never
 * throws. A refusal is a value, so a caller can report it to the submitter
 * unchanged. The one exception is `duplicateKeyHash` at the bottom, which is
 * async because WebCrypto is: it is still a pure function of its argument, and
 * it is here rather than in the store so that the key the index holds and the
 * key the rule compares are the same key by construction.
 */

import { domainOf, type Core } from "./core.js";
import { canonicalize, sha256Hex } from "./hash.js";
import { normalizeText } from "./normalize.js";

/**
 * The identity of a claim for the mechanical rule: where it was filed, what it
 * is about, what kind of fact it is, and what it asserts.
 */
export type DuplicateKey = {
  domain: string;
  subject: string;
  category: string;
  value: string;
};

/**
 * The key of one core. `value` is the core's `after` read as a string and
 * normalized under step 4 of norm-v1.2, the same rule the snapshot hash uses,
 * so two claims differing only in whitespace share a key.
 */
export function duplicateKey(core: Core): DuplicateKey {
  return {
    domain: domainOf(core),
    subject: String(core["subject"]),
    category: String(core["category"]),
    value: normalizeText(String(core["after"])),
  };
}

/** Whether two keys name the same claim. */
export function sameDuplicateKey(a: DuplicateKey, b: DuplicateKey): boolean {
  return (
    a.domain === b.domain &&
    a.subject === b.subject &&
    a.category === b.category &&
    a.value === b.value
  );
}

/**
 * The statuses under which an entry still stands, and so still occupies its
 * claim. `rejected`, `superseded` and `overturned` are not here: after any of
 * them the fact may be filed again.
 */
export const LIVE_STATUSES: readonly string[] = Object.freeze([
  "draft",
  "verified",
] as const);

/** Every reason the duplicate rule can refuse a submission. */
export const DUPLICATE_REFUSALS: readonly string[] = Object.freeze([
  "duplicate_claim",
] as const);

/** One entry the new core is checked against. */
export type DuplicateCandidate = {
  id: string;
  core: Core;
  status: string;
};

/** Accepted, or refused naming the entry already holding the claim. */
export type DuplicateVerdict =
  | { ok: true }
  | { ok: false; reason: "duplicate_claim"; duplicate_of: string };

/**
 * Check one core against the entries already filed for its domain, subject and
 * category.
 *
 * `candidates` arrives newest submission first, as `readCandidates` returns
 * them, and the first live candidate with an equal key wins — the newest one,
 * which is the entry a submitter would be told to look at. The core's own id
 * is skipped (a resubmission of the same sealed entry is not a duplicate of
 * itself), and so is the entry it names in `supersedes`, because superseding is
 * the sanctioned way to refile a live claim.
 */
export function checkDuplicate(
  core: Core,
  candidates: readonly DuplicateCandidate[],
): DuplicateVerdict {
  const key = duplicateKey(core);
  const ownId = core["id"];
  const supersedes = core["supersedes"];

  for (const candidate of candidates) {
    if (candidate.id === ownId) {
      continue;
    }
    if (supersedes !== null && supersedes !== undefined) {
      if (candidate.id === supersedes) {
        continue;
      }
    }
    if (!LIVE_STATUSES.includes(candidate.status)) {
      continue;
    }
    if (sameDuplicateKey(key, duplicateKey(candidate.core))) {
      return {
        ok: false,
        reason: "duplicate_claim",
        duplicate_of: candidate.id,
      };
    }
  }

  return { ok: true };
}

/**
 * The key of one core as one string: the SHA-256, in lowercase hex, of the JCS
 * of `{category, domain, subject, value}` — the same four fields
 * `sameDuplicateKey` compares, with `value` normalized under step 4 of
 * norm-v1.2 exactly as `duplicateKey` normalizes it.
 *
 * Why a hash and not the four fields in four columns: the QA of 2026-09-12
 * found the duplicate door reading a subject's whole live history on every
 * submission — 669 rows at 667 live entries, about 130 MB at a hundred thousand
 * — because the rule it had to apply lived in this file and not in the database.
 * Now it lives in both, and this function is the bridge: one column, one index,
 * one seek. A hash rather than the concatenation because `value` is arbitrary
 * text of arbitrary length, and a key made by joining fields with a separator
 * is a key two different claims can collide in.
 *
 * RFC 8785 because every other canonical form in this system is, so the bytes
 * hashed here are decided by the same rule that decides an entry hash, in one
 * place, for every runtime: a fork that recomputes this key gets the same hex.
 * The normalization is `duplicateKey`'s own and is never repeated here — two
 * copies of the norm rule would be exactly the drift this column exists to make
 * impossible.
 */
export async function duplicateKeyHash(core: Core): Promise<string> {
  return duplicateKeyHashOf(duplicateKey(core));
}

/** The same hash, over a key already computed. */
export async function duplicateKeyHashOf(key: DuplicateKey): Promise<string> {
  return sha256Hex(
    canonicalize({
      category: key.category,
      domain: key.domain,
      subject: key.subject,
      value: key.value,
    }),
  );
}
