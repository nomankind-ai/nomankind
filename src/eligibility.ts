/**
 * Who is too close to judge an entry: the seven exclusions, in one place.
 *
 * Whitepaper Section 5, "Identity and operators", Section 6, "Dispute", and
 * decisions D-071 and D-096 each bar somebody from validating a particular
 * entry, and every one of those bars is asked in two places at once — at the
 * validation door, which refuses a record and has to name which rule refused
 * it, and inside derivation, which recomputes the same question about a record
 * the log already holds and only needs a yes or a no.
 *
 * The QA of 2026-09-12 found three copies of the rule that did not agree, and
 * `mayValidateEntry` (src/derive.ts) put derivation's two back together. The QA
 * of 2026-09-13 found the third still standing: the door kept its own copy of
 * all seven, so the rules could drift apart again in exactly the way that had
 * just been fixed. This module is the predicate both of them ask.
 *
 * It is a predicate over resolved facts and never over the log, because the two
 * callers resolve those facts from different places and must: the door is
 * handed a context gathered at the decision's position by src/worker/validate.ts,
 * and derivation reads the events itself. What they may not differ about is the
 * rules, their order, or their names — which is what lives here.
 *
 * Pure, synchronous, no clock, no policy number: DEFAULT_DOMAIN is src/policy.ts's
 * and is the only constant named.
 */

import { DEFAULT_DOMAIN } from "./policy.js";

/**
 * The exclusions, in the door's own check order and its own refusal names.
 *
 * 1. `unregistered_operator` — Section 5, "only verified operators can
 *    validate", so an operator the log has not registered at this position is
 *    nobody.
 * 2. `submitter_operator` — Identity and operators: "No agent under the
 *    submitter's operator may validate that submitter's entry." A bare-key
 *    submitter has no operator and bars none.
 * 3. `original_signer` — Section 6, "Dispute": a challenge passes through the
 *    same validation with "one extra exclusion: no operator that signed the
 *    original, submitter or validator, may validate the challenge against it."
 *    Empty for an ordinary entry, which is why every entry that is not a
 *    challenge is judged exactly as it always was.
 * 4. `maintainer_operator` — Section 5: verification comes from outside the
 *    maintainer.
 * 5. `provider_operator` — Section 10 and D-096: the domain's excluded parties
 *    may not be operators in it at all, so they may not judge its entries.
 * 6. `subject_authority` — D-096: the authority the entry's subject names is
 *    the party the entry is about. Empty for every domain whose
 *    `subject_authority` is false (ai-ecosystem) and for every subject with no
 *    authority row.
 * 7. `operator_not_in_domain` — D-071: the independence attestation is per
 *    domain, so eligibility is too.
 */
export type EligibilityRefusal =
  | "unregistered_operator"
  | "submitter_operator"
  | "original_signer"
  | "maintainer_operator"
  | "provider_operator"
  | "subject_authority"
  | "operator_not_in_domain";

/** The seven in check order, so a caller can enumerate or document them. */
export const ELIGIBILITY_REFUSALS: readonly EligibilityRefusal[] = Object.freeze(
  [
    "unregistered_operator",
    "submitter_operator",
    "original_signer",
    "maintainer_operator",
    "provider_operator",
    "subject_authority",
    "operator_not_in_domain",
  ] as const,
);

/**
 * Everything the seven rules read, resolved by the caller at the decision's own
 * position in the log.
 *
 * `originalSigners` is a thunk because it is the one fact that costs something:
 * answering it means walking the challenged entry, and for the overwhelming
 * majority of entries — every one that is not a correction filed as a dispute —
 * there is nothing to walk. It is called at most once, and only once the three
 * cheaper rules above it have let the operator through.
 */
export interface EligibilityFacts {
  /** Whether the log had registered this operator at the decision's position. */
  readonly registered: boolean;
  /** The entry's `author_operator`, or null for a bare-key submitter. */
  readonly authorOperator: string | null;
  /** The operators that signed the entry this one challenges, or none. */
  readonly originalSigners: () => readonly string[];
  /** Whether the registry names this operator the maintainer. */
  readonly maintainer: boolean;
  /** Whether the entry's domain bars this operator as an excluded party. */
  readonly provider: boolean;
  /** The official hosts of the authority the entry's subject names. */
  readonly authorityHosts: readonly string[];
  /** The entry's own domain, read from its signed core. */
  readonly domain: string;
  /**
   * Every domain this operator is attested in. Undefined for a registration
   * sealed before v0.7, which carries none and reads as the default domain —
   * which is what that registration meant.
   */
  readonly attestedIn?: readonly string[] | undefined;
}

/**
 * Which of the seven bars this operator from validating this entry, or null
 * when none of them does.
 *
 * The first refusal wins and the order is fixed, so a record that breaks
 * several rules always reports the same one and an operator's client can fix
 * them one at a time and see progress.
 */
export function eligibilityRefusal(
  operator: string,
  facts: EligibilityFacts,
): EligibilityRefusal | null {
  if (!facts.registered) return "unregistered_operator";
  if (facts.authorOperator !== null && operator === facts.authorOperator) {
    return "submitter_operator";
  }
  if (facts.originalSigners().includes(operator)) return "original_signer";
  if (facts.maintainer) return "maintainer_operator";
  if (facts.provider) return "provider_operator";
  for (const host of facts.authorityHosts) {
    if (underHost(operator, host)) return "subject_authority";
  }
  const attestedIn = facts.attestedIn ?? [DEFAULT_DOMAIN];
  if (!attestedIn.includes(facts.domain)) return "operator_not_in_domain";
  return null;
}

/**
 * Whether an operator's own domain is a listed host, or a subdomain of one.
 *
 * `eu.example.europa.eu` is under `europa.eu`; `europa.eu.evil.tld` is not, and
 * the dot is the whole point -- a bare suffix test would hand every lookalike
 * domain in the world the exclusion, and, worse, would miss none of them while
 * excluding strangers.
 */
export function underHost(operator: string, host: string): boolean {
  const listed = host.toLowerCase();
  const own = operator.toLowerCase();
  return own === listed || own.endsWith(`.${listed}`);
}
