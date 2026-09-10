/**
 * Who may reconfirm an entry, and what a reconfirmation must carry.
 *
 * Whitepaper Section 6, "Revalidate": any trusted operator can reconfirm a
 * stale entry by taking a fresh snapshot hash and signing an attestation that
 * the source still says what the entry says. The one exception mirrors
 * validation: no agent under the submitter's own operator may reconfirm the
 * entry. Reconfirmation appends a fresh attestation, advances the derived
 * last-confirmed date and reopens the freshness window.
 *
 * Whitepaper Section 4, "Behavior and misbehavior": reconfirmation for these
 * entries means reproduction. The window is reopened by rerunning the frozen
 * prompt under the same n-of-k rule and attesting that the predicate still
 * holds, or the entry is superseded if it no longer does.
 *
 * The schema's `reconfirmations` says the same in field terms: "For stated
 * entries the attestation is a fresh snapshot_hash. For behavior and
 * misbehavior entries it is a fresh reproduction under the same n-of-k rule;
 * for observed entries in other categories, a fresh measurement."
 *
 * Whitepaper Section 5, "Freshness and decay": past its window an entry stays
 * verified but shows as stale. Staleness is therefore not a gate here; only a
 * verified entry can be reconfirmed, and a stale one is still verified.
 *
 * This module is a pure check. It never throws for a rule refusal, never reads
 * a clock, and holds no policy numbers of its own: n and k reach it only
 * through src/evidence.ts, which reads them from src/policy.ts. A refusal is a
 * value, so a caller can report the reason to the reconfirmer unchanged.
 * Advancing last_confirmed, reopening the window and rotating the read-share
 * slot all stay derivation's job (src/derive.ts), recomputed from the events.
 */

import { domainOf, type Core } from "./core.js";
import type { EntryStatus } from "./derive.js";
import type { ReconfirmationRecord } from "./events.js";
import {
  isTranscriptCategory,
  isWellFormedMeasurement,
  measurementPasses,
  type EvidenceTier,
} from "./evidence.js";
import { DEFAULT_DOMAIN } from "./policy.js";

/**
 * Everything the check needs, gathered by the caller at the record's position
 * in the log. The check itself reads nothing else.
 */
export interface ReconfirmationContext {
  /** From the core: author and author_operator (null for a bare-key submitter). */
  readonly submitter: { readonly agent: string; readonly operator: string | null };
  /** Registered agent id -> its operator, as of the record's position. */
  readonly agentOperators: Readonly<Record<string, string>>;
  /** The trusted pool as of the record's position. The maintainer's operator is never in it. */
  readonly trustedOperators: readonly string[];
  /**
   * The domains this reconfirmer's operator is attested in (src/derive.ts,
   * `operatorDomainsAt`). Absent reads as the default domain, which is what a
   * registration sealed before v0.7 meant.
   */
  readonly operatorDomains?: readonly string[];
  /** The entry's derived status at that position. */
  readonly status: EntryStatus;
  /** The entry's sidecar effective_tier at that position (null only while unverified). */
  readonly effectiveTier: EvidenceTier | null;
}

/** Every reason a reconfirmation can be refused. One string per rule, in check order. */
export type ReconfirmationRefusal =
  | "entry_not_verified"
  | "unregistered_agent"
  | "operator_mismatch"
  | "submitter_agent"
  | "submitter_operator"
  | "untrusted_operator"
  | "operator_not_in_domain"
  | "missing_snapshot_hash"
  | "unexpected_reproduction"
  | "unexpected_observation"
  | "missing_reproduction"
  | "bad_reproduction"
  | "failed_reproduction"
  | "missing_observation"
  | "bad_observation"
  | "failed_observation";

/** Every refusal, in check order. */
export const RECONFIRMATION_REFUSALS: readonly ReconfirmationRefusal[] = Object.freeze([
  "entry_not_verified",
  "unregistered_agent",
  "operator_mismatch",
  "submitter_agent",
  "submitter_operator",
  "untrusted_operator",
  "operator_not_in_domain",
  "missing_snapshot_hash",
  "unexpected_reproduction",
  "unexpected_observation",
  "missing_reproduction",
  "bad_reproduction",
  "failed_reproduction",
  "missing_observation",
  "bad_observation",
  "failed_observation",
] as const);

/** Accepted, carrying the record itself; or refused, carrying the reason. */
export type ReconfirmationVerdict =
  | { ok: true; record: ReconfirmationRecord }
  | { ok: false; reason: ReconfirmationRefusal };

/** The schema's snapshot_hash pattern, as the reconfirmations[] item states it. */
const SNAPSHOT_HASH = /^sha256:[0-9a-f]{64}$/;

/** Present means non-null and not absent; the schema writes an unused slot as null. */
function present(value: unknown): boolean {
  return value !== null && value !== undefined;
}

function refuse(reason: ReconfirmationRefusal): ReconfirmationVerdict {
  return { ok: false, reason };
}

/**
 * Check one reconfirmation against the entry it wants to refresh.
 *
 * Synchronous and pure: same inputs, same verdict, no I/O and no clock. On
 * success the record comes back as the same object, uncopied and unnormalised,
 * so the bytes the reconfirmer signed are the bytes the caller appends.
 *
 * Rules are checked in a fixed order and the first refusal wins, so a record
 * that breaks several rules always reports the same one: an operator's client
 * can fix them one at a time and see progress.
 */
export function checkReconfirmation(
  record: ReconfirmationRecord,
  core: Core,
  context: ReconfirmationContext,
): ReconfirmationVerdict {
  // 1. Only a verified entry has a freshness window to reopen. A draft has not
  // earned one yet; rejected, superseded and overturned entries have no window
  // worth refreshing. A stale entry is still verified (Section 5: past its
  // window an entry stays verified but shows as stale) and may be reconfirmed.
  if (context.status !== "verified") return refuse("entry_not_verified");

  // 2-3. The signer must be a registered agent claiming the operator the
  // registry has for it. A record may not name an operator the agent does not
  // belong to.
  const registeredOperator = Object.prototype.hasOwnProperty.call(
    context.agentOperators,
    record.agent,
  )
    ? context.agentOperators[record.agent]
    : undefined;
  if (registeredOperator === undefined) return refuse("unregistered_agent");
  if (record.operator !== registeredOperator) return refuse("operator_mismatch");

  // 4-5. Section 6: the one exception mirrors validation, so no agent under the
  // submitter's own operator may reconfirm the entry. A bare-key submitter has
  // no operator to exclude, so only the agent itself is barred.
  if (record.agent === context.submitter.agent) return refuse("submitter_agent");
  if (
    context.submitter.operator !== null &&
    record.operator === context.submitter.operator
  ) {
    return refuse("submitter_operator");
  }

  // 6. Section 6: any trusted operator can reconfirm, and only a trusted one.
  // The pool the caller passes already excludes the maintainer's operator.
  if (!context.trustedOperators.includes(record.operator)) {
    return refuse("untrusted_operator");
  }

  // 6a. Decision D-071: eligibility is per domain, because the independence
  // attestation is. A trusted operator refreshes an entry only in a domain it
  // has attested in; being trusted is not being attested everywhere.
  const entryDomain = domainOf(core);
  const attestedIn = context.operatorDomains ?? [DEFAULT_DOMAIN];
  if (!attestedIn.includes(entryDomain)) {
    return refuse("operator_not_in_domain");
  }

  // 7. Section 6: the attestation rests on a fresh snapshot hash, over the
  // fetched source or over the reconfirmer's own transcript or receipt. Every
  // shape carries one; for a stated entry it is the whole attestation.
  if (
    typeof record.snapshot_hash !== "string" ||
    !SNAPSHOT_HASH.test(record.snapshot_hash)
  ) {
    return refuse("missing_snapshot_hash");
  }

  // 8. The evidence the attestation has to carry, by the entry's category and
  // the tier it verified at. The measurement's remaining fields (model, output,
  // method, receipt_hash, observed_at) belong to the schema validator; only the
  // n-of-k counts are a rule.
  const hasReproduction = present(record.reproduction);
  const hasObservation = present(record.observation);

  if (isTranscriptCategory(entryDomain, core.category)) {
    // Section 4: reconfirmation for behavior and misbehavior means reproduction,
    // rerunning the frozen prompt under the same n-of-k rule. That holds at
    // either effective tier: a transcript entry that verified as stated on a
    // provider statement still reopens its window by rerunning the prompt.
    if (hasObservation) return refuse("unexpected_observation");
    if (!hasReproduction) return refuse("missing_reproduction");
    if (!isWellFormedMeasurement(record.reproduction)) return refuse("bad_reproduction");
    if (!measurementPasses(record.reproduction)) return refuse("failed_reproduction");
    return { ok: true, record };
  }

  if (context.effectiveTier === "observed") {
    // The schema: a fresh measurement, in the observation slot its category uses.
    if (hasReproduction) return refuse("unexpected_reproduction");
    if (!hasObservation) return refuse("missing_observation");
    if (!isWellFormedMeasurement(record.observation)) return refuse("bad_observation");
    if (!measurementPasses(record.observation)) return refuse("failed_observation");
    return { ok: true, record };
  }

  // A stated entry, or one not yet carrying a tier: the schema says the
  // attestation is the fresh snapshot_hash, and nothing else. Neither
  // measurement slot is the reconfirmer's to fill.
  if (hasReproduction) return refuse("unexpected_reproduction");
  if (hasObservation) return refuse("unexpected_observation");
  return { ok: true, record };
}
