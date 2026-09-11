/**
 * Who may validate an entry, and what a decision must carry.
 *
 * Whitepaper Section 5, "Identity and operators": every agent under an operator
 * counts as one for validation, only verified operators validate, no agent
 * under the submitter's operator may validate that submitter's entry, and no
 * model provider may register as an operator at all. Operators, not agents, are
 * therefore the unit of validation: an assignment names an operator, and a
 * record satisfies an assignment when its operator equals the assignment's.
 *
 * Whitepaper Section 6, "Lifecycle of an entry": each validator fetches the
 * live source itself and records its own snapshot hash in its signed record, so
 * an approval without one is not a validation; a rejection signs a reason.
 *
 * This module is a pure check. It never throws for a rule refusal, never reads
 * a clock, and holds no policy numbers: a refusal is a value, so a caller can
 * report the reason to the submitter unchanged. It answers only "may this
 * record join this entry"; counting decisions into a status is derivation's
 * job (src/derive.ts), which recomputes it from the events every time.
 */

import type { ApproverRecord } from "./events.js";
import { DEFAULT_DOMAIN } from "./policy.js";

/**
 * What the registry knows about an operator at the decision's position in the
 * log. `domains` is every domain the operator is attested in (src/derive.ts,
 * `operatorDomainsAt`); a context built before v0.7 carries none and reads as
 * the default domain, which is what its registration meant.
 */
export type OperatorInfo = {
  readonly maintainer: boolean;
  readonly provider: boolean;
  readonly domains?: readonly string[];
};

/**
 * Everything the check needs, gathered by the caller at the decision's position
 * in the log. The check itself reads nothing else.
 */
export interface ValidationContext {
  /** From the core: author and author_operator (null for a bare-key submitter). */
  readonly submitter: { readonly agent: string; readonly operator: string | null };
  /** Registered agent id -> its operator (the registry supplies this from M12; tests build it). */
  readonly agentOperators: Readonly<Record<string, string>>;
  /** Registered operators as of the decision's position. */
  readonly operators: Readonly<Record<string, OperatorInfo>>;
  /**
   * The entry's domain, read from its signed core (`domainOf(core)`). Absent
   * reads as the default domain, exactly as a legacy v0.6 core does.
   */
  readonly domain?: string;
  /** Decisions already on this entry, in log order. */
  readonly priorRecords: readonly ApproverRecord[];
  /** The open assignment for this entry, or null. */
  readonly openAssignment: { readonly operator: string } | null;
  /**
   * Operators barred from validating this particular entry beyond the standing
   * rules above. Empty by default, so the offline verifier and every caller
   * that had no extra exclusion is unchanged.
   *
   * Whitepaper Section 6, "Dispute": a challenge "passes through the same
   * validation process with one extra exclusion: no operator that signed the
   * original, submitter or validator, may validate the challenge against it."
   * The list is src/dispute.ts's `disputeExclusions`, computed from the
   * challenged entry; this module only applies it.
   */
  readonly excludedOperators?: readonly string[];
  /**
   * The official hosts of the authority this entry's subject names
   * (`authorityHostsFor` in src/policy.ts). Empty by default, so every caller
   * that had no such exclusion -- and every entry in a domain whose
   * `subject_authority` is false -- is unchanged.
   *
   * Decision D-096: the body that issued the instrument, or published the
   * commitment, is the party the record is checking, and it is named by the
   * entry's own subject rather than by a list. An operator whose own domain is
   * one of these hosts, or a subdomain of one, is too close to judge this
   * particular entry.
   */
  readonly authority_hosts?: readonly string[];
}

/** Every reason a record can be refused. One string per rule, in check order. */
export type ValidationRefusal =
  | "unregistered_agent"
  | "operator_mismatch"
  | "unregistered_operator"
  | "submitter_agent"
  | "submitter_operator"
  | "original_signer"
  | "maintainer_operator"
  | "provider_operator"
  | "subject_authority"
  | "operator_not_in_domain"
  | "missing_snapshot_hash"
  | "missing_reason"
  | "duplicate_operator"
  | "assigned_random_without_assignment"
  | "assignment_without_assigned_random";

/** The refusals in check order, so a caller can enumerate or document them. */
export const VALIDATION_REFUSALS: readonly ValidationRefusal[] = Object.freeze([
  "unregistered_agent",
  "operator_mismatch",
  "unregistered_operator",
  "submitter_agent",
  "submitter_operator",
  "original_signer",
  "maintainer_operator",
  "provider_operator",
  "subject_authority",
  "operator_not_in_domain",
  "missing_snapshot_hash",
  "missing_reason",
  "duplicate_operator",
  "assigned_random_without_assignment",
  "assignment_without_assigned_random",
] as const);

/** Accepted, carrying the record itself; or refused, carrying the reason. */
export type ValidationVerdict =
  | { ok: true; record: ApproverRecord }
  | { ok: false; reason: ValidationRefusal };

/** The schema's snapshot_hash pattern, as the approvers[] item states it. */
const SNAPSHOT_HASH = /^sha256:[0-9a-f]{64}$/;

/**
 * Check one validation decision against the entry it wants to join.
 *
 * Synchronous and pure: same inputs, same verdict, no I/O and no clock. On
 * success the record comes back as the same object, uncopied and unnormalised,
 * so the bytes the validator signed are the bytes the caller appends.
 *
 * Rules are checked in a fixed order and the first refusal wins, so a record
 * that breaks several rules always reports the same one: an operator's client
 * can fix them one at a time and see progress.
 */
export function checkValidation(
  record: ApproverRecord,
  context: ValidationContext,
): ValidationVerdict {
  // 1-3. The signer must be a registered agent, claiming the operator the
  // registry has for it, and that operator must itself be registered. A record
  // may not name an operator the agent does not belong to.
  const registeredOperator = Object.prototype.hasOwnProperty.call(
    context.agentOperators,
    record.agent,
  )
    ? context.agentOperators[record.agent]
    : undefined;
  if (registeredOperator === undefined) return refuse("unregistered_agent");
  if (record.operator !== registeredOperator) return refuse("operator_mismatch");

  const operator = Object.prototype.hasOwnProperty.call(
    context.operators,
    record.operator,
  )
    ? context.operators[record.operator]
    : undefined;
  if (operator === undefined) return refuse("unregistered_operator");

  // 4-5. Section 5: no agent under the submitter's operator may validate that
  // submitter's entry, so the signatures that make a fact verified always come
  // from outside the party that submitted it. A bare-key submitter has no
  // operator to exclude, so only the agent itself is barred.
  if (record.agent === context.submitter.agent) return refuse("submitter_agent");
  if (
    context.submitter.operator !== null &&
    record.operator === context.submitter.operator
  ) {
    return refuse("submitter_operator");
  }

  // 6. Section 6, "Dispute": a challenge passes through the same validation
  // process "with one extra exclusion: no operator that signed the original,
  // submitter or validator, may validate the challenge against it." The list is
  // the caller's, computed from the challenged entry (src/dispute.ts), and is
  // empty for an ordinary entry — which is why every other caller is unchanged.
  // It sits here, after the submitter rules and before the maintainer ones,
  // because it is the same kind of rule: who is too close to judge.
  if (context.excludedOperators !== undefined) {
    for (const excluded of context.excludedOperators) {
      if (record.operator === excluded) return refuse("original_signer");
    }
  }

  // 7-8. Section 5: verification comes from outside the maintainer, and no
  // model provider may register as an operator at all.
  if (operator.maintainer) return refuse("maintainer_operator");
  if (operator.provider) return refuse("provider_operator");

  // 8a. Decision D-096: the authority the entry's subject names is the party
  // the entry is about, so an operator under one of its official hosts is
  // barred from judging it. The hosts are the caller's, computed from policy
  // (`authorityHostsFor`), and empty for every domain and every subject that
  // excludes nobody -- which is why ai-ecosystem is untouched. It sits beside
  // the provider rule because it is the same kind of rule, one entry wide
  // instead of one domain wide.
  if (context.authority_hosts !== undefined) {
    for (const host of context.authority_hosts) {
      if (underHost(record.operator, host)) return refuse("subject_authority");
    }
  }

  // 8b. Decision D-071: the independence attestation is per domain, so
  // eligibility is too. An operator judges an entry only in a domain it has
  // signed that domain's attestation for -- and an operator excluded from one
  // domain stays eligible in another, which is exactly what a per-domain check
  // and a global one differ about.
  const entryDomain = context.domain ?? DEFAULT_DOMAIN;
  const attestedIn = operator.domains ?? [DEFAULT_DOMAIN];
  if (!attestedIn.includes(entryDomain)) {
    return refuse("operator_not_in_domain");
  }

  // 9-10. Section 6: an approval carries the validator's own snapshot hash, so
  // the capture at submission is never the only witness to what the page said;
  // a rejection carries the reason it is rejected. A rejection may carry a
  // snapshot hash too, but nothing forces it to.
  if (record.decision === "approve") {
    if (
      typeof record.snapshot_hash !== "string" ||
      !SNAPSHOT_HASH.test(record.snapshot_hash)
    ) {
      return refuse("missing_snapshot_hash");
    }
  } else if (
    typeof record.reason !== "string" ||
    record.reason.trim().length === 0
  ) {
    return refuse("missing_reason");
  }

  // 11. Section 5: every agent under an operator counts as one. One signature
  // per operator per entry, so an entity cannot fill an entry's approvals with
  // its own agents.
  for (const prior of context.priorRecords) {
    if (prior.operator === record.operator) return refuse("duplicate_operator");
  }

  // 12. Section 6: exactly one validator is drawn at random, and the flag has
  // to match the log. Claiming the draw without holding it, or holding it and
  // signing as a volunteer, both misreport who the entry's judges were.
  const assigned =
    context.openAssignment !== null &&
    context.openAssignment.operator === record.operator;
  if (record.assigned_random && !assigned) {
    return refuse("assigned_random_without_assignment");
  }
  if (!record.assigned_random && assigned) {
    return refuse("assignment_without_assigned_random");
  }

  return { ok: true, record };
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

function refuse(reason: ValidationRefusal): ValidationVerdict {
  return { ok: false, reason };
}
