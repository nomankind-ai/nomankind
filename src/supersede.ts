/**
 * Supersession: whether a new entry's claim to replace an older one may stand.
 *
 * Whitepaper, "Freshness and decay": "A superseding entry must share its
 * target's subject and category, and its claim must address the same attribute
 * ... The link is the submitter's assertion, the approvals are the check."
 *
 * Two of those three conditions are mechanical, and this module checks them:
 * same subject, same category. The third is not. Whether the new claim
 * addresses the same attribute — the price of the same thing, the same rate
 * limit on the same endpoint — is a judgment about meaning, and the paper gives
 * that judgment to the validators: the link is asserted by the submitter and
 * checked by the approvals on the superseding entry. So the attribute match is
 * deliberately NOT checked here, and never will be: an approval is the record
 * of that check, and a string comparison would only pretend to be one.
 *
 * The target's own status is not checked either. An entry may name a draft, a
 * stale, or an already-superseded target; what a superseder does to the old
 * entry is derivation's question (src/derive.ts flips the old entry only once
 * the new one has verified), and a later milestone may refine which targets a
 * submitter may name at the door.
 *
 * This module is pure and synchronous: no I/O, no clock, no policy numbers, and
 * it never throws for a rule refusal. A refusal is a value, so a caller can
 * report the reason to the submitter unchanged. `lookup` is query-shaped —
 * one id in, one core or null out — so a caller backed by a real registry
 * fetches one row rather than loading the log.
 */

import type { Core } from "./core.js";

/** Every reason a supersession link can be refused. One string per rule. */
export type SupersessionRefusal =
  | "self_supersession"
  | "target_missing"
  | "subject_mismatch"
  | "category_mismatch";

/** Every refusal, in check order. */
export const SUPERSESSION_REFUSALS: readonly SupersessionRefusal[] =
  Object.freeze([
    "self_supersession",
    "target_missing",
    "subject_mismatch",
    "category_mismatch",
  ] as const);

/**
 * Accepted, carrying the target core — null when the entry supersedes nothing —
 * or refused, carrying the reason.
 */
export type SupersessionVerdict =
  | { ok: true; target: Core | null }
  | { ok: false; reason: SupersessionRefusal };

/**
 * Check one core's `supersedes` link.
 *
 * In order: a null link is fine and names no target; an entry may not supersede
 * itself; the named target has to exist; it has to share this entry's subject;
 * it has to share this entry's category. The first refusal wins.
 */
export function checkSupersedes(
  core: Core,
  lookup: (entryId: string) => Core | null,
): SupersessionVerdict {
  const supersedes = core["supersedes"];
  // The schema writes an unused core slot as null, never absent; undefined is
  // treated the same way rather than mistaken for an id.
  if (supersedes === null || supersedes === undefined) {
    return { ok: true, target: null };
  }

  const targetId = supersedes as string;
  if (targetId === core["id"]) {
    return { ok: false, reason: "self_supersession" };
  }

  const target = lookup(targetId);
  if (target === null) {
    return { ok: false, reason: "target_missing" };
  }

  if (target["subject"] !== core["subject"]) {
    return { ok: false, reason: "subject_mismatch" };
  }
  if (target["category"] !== core["category"]) {
    return { ok: false, reason: "category_mismatch" };
  }

  return { ok: true, target };
}
