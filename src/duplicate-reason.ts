/**
 * The published form a validator rejects a duplicate in, and how to read it back.
 *
 * Whitepaper Section 6, Validate: a validator checks the entry and signs approve
 * or reject with a reason. Decision D-085 splits duplicates in two. The
 * mechanical case — the same domain, subject, category and normalized value,
 * already live and not superseded — is refused at the submit door before
 * anything is fetched or written (src/duplicate.ts). Everything else is a
 * judgment: two entries can say the same thing in different words, or at a
 * different `effective_at`, and no string comparison decides that. That case
 * belongs to the validators, and this module is the one thing the log asks of
 * them in return — that they say so in a form a reader can follow.
 *
 * The form is the reason `duplicate_claim:<entry id>`. Nothing new is signed and
 * nothing in the schema changed: the validate door takes it as it takes any
 * other reason, the `approvers[].reason` string is exactly what the validator
 * put its key to, and the id inside it is the entry this one is said to
 * duplicate. What the log adds is reading: the entry page turns the id into a
 * link, and the confidence inputs publish it raw, so a learner can see that an
 * entry was rejected as a duplicate and of what, rather than reading a sentence
 * of prose and guessing.
 *
 * Pure, synchronous and never throwing. Every function here answers over rows a
 * public route serves, some of them written by an older Worker, so a field that
 * is not there reads as absent rather than as an exception. A reason that does
 * not parse is not an error either: it is an ordinary rejection reason, which is
 * what most of them are.
 */

/** The prefix a duplicate rejection's reason carries, verbatim. */
export const DUPLICATE_REASON_PREFIX = "duplicate_claim:";

/**
 * An entry id: `nmk_` and exactly 32 lowercase hex characters.
 *
 * Anchored and case-sensitive on purpose. The id is a link the page renders, so
 * a reason carrying something that merely looks like an id — a truncated one, an
 * uppercased one, a second id after a comma — parses as nothing at all and the
 * reason stays the plain text the validator signed. A form that nearly holds is
 * not the form.
 */
const ENTRY_ID = /^nmk_[0-9a-f]{32}$/;

/** A record on the entry, read by the schema's own field names. */
type SchemaRecord = Record<string, unknown>;

/**
 * The entry id a rejection reason names, or null when it names none.
 *
 * `unknown` rather than `string`, because the callers are reading stored rows:
 * the schema's `reason` is nullable and an older row may hold anything at all.
 */
export function parseDuplicateReason(reason: unknown): string | null {
  if (typeof reason !== "string") return null;
  if (!reason.startsWith(DUPLICATE_REASON_PREFIX)) return null;
  const id = reason.slice(DUPLICATE_REASON_PREFIX.length);
  return ENTRY_ID.test(id) ? id : null;
}

/** The entry's decisions, in the order the schema holds them. */
function approvers(entry: unknown): readonly SchemaRecord[] {
  if (typeof entry !== "object" || entry === null) return [];
  const value = (entry as SchemaRecord)["approvers"];
  if (!Array.isArray(value)) return [];
  return value.filter(
    (item): item is SchemaRecord =>
      typeof item === "object" && item !== null && !Array.isArray(item),
  );
}

/** Whether one decision is a rejection in the published duplicate form. */
function rejectedAsDuplicate(record: SchemaRecord): string | null {
  if (record["decision"] !== "reject") return null;
  return parseDuplicateReason(record["reason"]);
}

/**
 * The entry this one was rejected as a duplicate of, or null.
 *
 * The first such rejection in the schema's own order, not the last and not a
 * tally: `approvers[]` is append-only, so the first validator to say it is the
 * one who said it first, and a second rejection naming a different entry is a
 * disagreement a reader should see rather than have resolved for them (the
 * count is beside it, in `duplicateRejections`).
 *
 * A decision of `approve` is ignored even when its reason parses. An approval
 * that carries the string is an approval: it says the entry stands, and reading
 * a duplicate claim out of it would turn a vote for the entry into a mark
 * against it.
 */
export function duplicateOf(entry: unknown): string | null {
  for (const record of approvers(entry)) {
    const id = rejectedAsDuplicate(record);
    if (id !== null) return id;
  }
  return null;
}

/** How many of the entry's rejections carry the published duplicate form. */
export function duplicateRejections(entry: unknown): number {
  let count = 0;
  for (const record of approvers(entry)) {
    if (rejectedAsDuplicate(record) !== null) count += 1;
  }
  return count;
}
