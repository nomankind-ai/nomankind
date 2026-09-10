/**
 * Two tiers of evidence, and the rules that decide which tier an entry earns.
 *
 * Whitepaper Section 4, "Two tiers of evidence": a stated entry rests on a
 * document that said it; an observed entry rests on a measurement someone made
 * and receipted. An observed entry carries a proposed test, frozen with the
 * claim. Validators first judge whether running that test decides the claim
 * (decision D-031: the judgment is theirs, recorded as test_accepted; this
 * module checks presence and shape only, never judgment). If a majority answers
 * no, the entry is validated as a document and its effective tier falls to
 * stated. An accepted test is then rerun under the n-of-k rule: n runs, and the
 * claim holds when the predicate held in at least k of them.
 *
 * Whitepaper Section 4, "Behavior and misbehavior": these two categories are
 * always observed and always carry a frozen transcript artifact in `evidence`.
 * The predicate travels with the artifact, because a bare transcript with an
 * implied conclusion is rejected at draft. The observed badge on such an entry
 * is earned by an independent reproduction and nothing else: a provider
 * statement can verify the entry, but it reads as stated, and the frozen
 * artifact standing alone verifies nothing.
 *
 * This module is pure: no I/O, no clock, no wall time, and no policy numbers of
 * its own. Every number it applies comes from src/policy.ts. It never throws for
 * a rule refusal; a refusal is a value the caller can report unchanged. Counting
 * decisions into a status stays derivation's job (src/derive.ts), which
 * recomputes it from the events every time.
 */

import { domainOf, type Core } from "./core.js";
import type { ApproverRecord } from "./events.js";
import {
  isTranscriptCategory,
  REPRODUCTION_HOLDS,
  REPRODUCTION_RUNS,
} from "./policy.js";

/**
 * Which categories carry a transcript is a domain's table and not a global one
 * (decision D-071): it is published per domain in
 * schema/nomankind-domain-registry-v1.md and held in src/policy.ts's `DOMAINS`.
 * The accessor is re-exported here because this is the module the rule belongs
 * to; the table it reads is policy's, as every number here already was.
 */
export { isTranscriptCategory };

/** The two tiers the schema's evidence_tier enum names. */
export type EvidenceTier = "stated" | "observed";

/**
 * The rejection reason a validator writes when rejecting at draft because the
 * proposed test or predicate is absent. Whitepaper Section 4: a bare transcript
 * with an implied conclusion is rejected at draft.
 */
export const NO_PREDICATE = "no_predicate";

/** A plain object, or null for anything else (arrays included). */
function asObject(value: unknown): Record<string, unknown> | null {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    return null;
  }
  return value as Record<string, unknown>;
}

/** The trimmed text, or null when missing, non-string, or blank. */
function text(value: unknown): string | null {
  if (typeof value !== "string") {
    return null;
  }
  return value.trim().length === 0 ? null : value;
}

/**
 * The text validators judge: `evidence.predicate` for a transcript category,
 * `observation.test` for an observed entry in any other category, null for a
 * stated entry. Missing, non-string, or blank after trim counts as absent and
 * returns null. Presence only, never judgment (D-031).
 */
export function proposedTest(core: Core): string | null {
  if (isTranscriptCategory(domainOf(core), core.category)) {
    return text(asObject(core.evidence)?.predicate);
  }
  if (core.evidence_tier !== "observed") {
    return null;
  }
  return text(asObject(core.observation)?.test);
}

export type CoreEvidenceRefusal = "provider_statement_mismatch" | "no_predicate";

/** The core-side refusals in check order, so a caller can enumerate them. */
export const CORE_EVIDENCE_REFUSALS: readonly CoreEvidenceRefusal[] = Object.freeze([
  "provider_statement_mismatch",
  "no_predicate",
] as const);

export type CoreEvidenceVerdict = { ok: true } | { ok: false; reason: CoreEvidenceRefusal };

/**
 * The submit-side shape check on a core's evidence.
 *
 * provider_statement_mismatch: `evidence.provider_statement` is non-null and not
 * the entry's citation. The schema states the rule outright: "When non-null it
 * must equal 'citation'."
 *
 * no_predicate: the entry is observed and carries no proposed test at all.
 *
 * A stated entry passes. The first refusal wins.
 */
export function checkCoreEvidence(core: Core): CoreEvidenceVerdict {
  const evidence = asObject(core.evidence);
  if (evidence !== null) {
    const statement = evidence.provider_statement;
    if (statement !== null && statement !== undefined && statement !== core.citation) {
      return { ok: false, reason: "provider_statement_mismatch" };
    }
  }
  if (core.evidence_tier === "observed" && proposedTest(core) === null) {
    return { ok: false, reason: NO_PREDICATE };
  }
  return { ok: true };
}

/** The n-of-k counts a reproduction or an observation carries. */
export type Measurement = { readonly runs: number; readonly holds: number };

/**
 * Shape only: an object whose runs and holds are integers, runs at least one and
 * holds between zero and runs. The bounds are the schema's own minima for these
 * fields, not policy numbers. Extra keys are fine: the schema's reproduction and
 * observation objects carry method, receipt_hash, output and more besides.
 */
export function isWellFormedMeasurement(value: unknown): value is Measurement {
  const measurement = asObject(value);
  if (measurement === null) {
    return false;
  }
  const { runs, holds } = measurement;
  if (!Number.isInteger(runs) || !Number.isInteger(holds)) {
    return false;
  }
  return (runs as number) >= 1 && (holds as number) >= 0 && (holds as number) <= (runs as number);
}

/**
 * The n-of-k rule. Whitepaper Section 4: the validator reruns the frozen prompt
 * n times and approves only if the predicate held in at least k of them. The
 * count is exact: a measurement at some other n is not the rule the paper names.
 */
export function measurementPasses(measurement: Measurement): boolean {
  return measurement.runs === REPRODUCTION_RUNS && measurement.holds >= REPRODUCTION_HOLDS;
}

/** A measurement that is present, well formed, and passes the n-of-k rule. */
function passingMeasurement(value: unknown): boolean {
  return value !== null && value !== undefined && isWellFormedMeasurement(value) && measurementPasses(value);
}

export type RecordEvidenceRefusal =
  | "missing_test_accepted"
  | "unexpected_test_accepted"
  | "misplaced_measurement"
  | "bad_measurement"
  | "missing_observation";

/** The record-side refusals in check order. */
export const RECORD_EVIDENCE_REFUSALS: readonly RecordEvidenceRefusal[] = Object.freeze([
  "missing_test_accepted",
  "unexpected_test_accepted",
  "misplaced_measurement",
  "bad_measurement",
  "missing_observation",
] as const);

export type RecordEvidenceVerdict =
  | { ok: true; record: ApproverRecord }
  | { ok: false; reason: RecordEvidenceRefusal };

/** Present means non-null and not absent; the schema writes an unused slot as null. */
function present(value: unknown): boolean {
  return value !== null && value !== undefined;
}

/**
 * The evidence fields of one approver record, checked against the entry's core.
 *
 * This stands beside M4's checkValidation at the door and the application runs
 * both; it never repeats M4's rules (registration, the exclusions,
 * snapshot_hash, reason, duplicates, assigned_random).
 *
 * missing_test_accepted: an observed entry needs this validator's judgment of
 * the test, on a rejection as much as on an approval, so the majority can be
 * counted. unexpected_test_accepted: a stated entry has no test to judge.
 * misplaced_measurement: the measurement has to sit in the slot its category
 * uses, and a stated entry has no measurement at all. bad_measurement: the
 * counts must be countable before the n-of-k rule can read them.
 * missing_observation: the schema requires the validator's own measurement on an
 * approval when the entry is observed, the category is not a transcript one, and
 * this validator accepted the test.
 *
 * The first refusal wins; on success the same record object comes back.
 */
export function checkRecordEvidence(record: ApproverRecord, core: Core): RecordEvidenceVerdict {
  const observed = core.evidence_tier === "observed";
  const transcript = isTranscriptCategory(domainOf(core), core.category);

  if (observed) {
    if (typeof record.test_accepted !== "boolean") {
      return { ok: false, reason: "missing_test_accepted" };
    }
  } else if (present(record.test_accepted)) {
    return { ok: false, reason: "unexpected_test_accepted" };
  }

  const hasReproduction = present(record.reproduction);
  const hasObservation = present(record.observation);
  const reproductionMisplaced = hasReproduction && (!observed || !transcript);
  const observationMisplaced = hasObservation && (!observed || transcript);
  if (reproductionMisplaced || observationMisplaced) {
    return { ok: false, reason: "misplaced_measurement" };
  }

  if (
    (hasReproduction && !isWellFormedMeasurement(record.reproduction)) ||
    (hasObservation && !isWellFormedMeasurement(record.observation))
  ) {
    return { ok: false, reason: "bad_measurement" };
  }

  if (
    observed &&
    !transcript &&
    record.decision === "approve" &&
    record.test_accepted === true &&
    !hasObservation
  ) {
    return { ok: false, reason: "missing_observation" };
  }

  return { ok: true, record };
}

/** What the validators decided about the proposed test itself. */
export type TestVerdict = "accepted" | "rejected" | "undecided";

/**
 * The majority over the records' test_accepted judgments. Approvals and
 * rejections count alike: the question is whether running the test decides the
 * claim, which is independent of whether the claim held. A tie, or no judgment
 * at all, is undecided; a non-boolean value is not a judgment and is ignored.
 */
export function testVerdict(records: readonly ApproverRecord[]): TestVerdict {
  let accepted = 0;
  let rejected = 0;
  for (const record of records) {
    if (record.test_accepted === true) {
      accepted += 1;
    } else if (record.test_accepted === false) {
      rejected += 1;
    }
  }
  if (accepted > rejected) {
    return "accepted";
  }
  if (rejected > accepted) {
    return "rejected";
  }
  return "undecided";
}

export interface EvidenceGate {
  /** null for a stated entry: there is no test to judge. */
  readonly test_verdict: TestVerdict | null;
  /** Whether the entry may verify on this evidence, the consensus count aside. */
  readonly verifiable: boolean;
  /** The tier it verifies at when verifiable; null otherwise. */
  readonly effective_tier: EvidenceTier | null;
}

/**
 * The tier rule at one position in the log.
 *
 * `records` are the decisions counted so far, approvals and rejections alike,
 * one per distinct eligible operator exactly as derivation counts them; the
 * caller decides which records count, this function only reads them.
 *
 * A stated entry verifies as a document and its tier is stated. An observed
 * entry in a non-transcript category verifies as observed only when a majority
 * of its approvals carry a passing n-of-k measurement; if the majority rejected
 * the test, the entry still verifies, as a document. A transcript entry earns
 * the observed badge from a reproduction and nothing else, verifies as stated on
 * a provider statement, and verifies on nothing at all when it has neither.
 */
export function evidenceGate(core: Core, records: readonly ApproverRecord[]): EvidenceGate {
  if (core.evidence_tier !== "observed") {
    return { test_verdict: null, verifiable: true, effective_tier: "stated" };
  }

  const verdict = testVerdict(records);
  const approvals = records.filter((record) => record.decision === "approve");

  if (!isTranscriptCategory(domainOf(core), core.category)) {
    if (verdict === "rejected") {
      return { test_verdict: verdict, verifiable: true, effective_tier: "stated" };
    }
    if (verdict === "undecided") {
      return { test_verdict: verdict, verifiable: false, effective_tier: null };
    }
    const passing = approvals.filter((record) => passingMeasurement(record.observation)).length;
    const verifiable = passing > approvals.length - passing;
    return {
      test_verdict: verdict,
      verifiable,
      effective_tier: verifiable ? "observed" : null,
    };
  }

  const reproduced =
    verdict !== "rejected" &&
    approvals.some((record) => passingMeasurement(record.reproduction));
  if (reproduced) {
    return { test_verdict: verdict, verifiable: true, effective_tier: "observed" };
  }

  const statement = asObject(core.evidence)?.provider_statement;
  if (typeof statement === "string") {
    return { test_verdict: verdict, verifiable: true, effective_tier: "stated" };
  }

  return { test_verdict: verdict, verifiable: false, effective_tier: null };
}
