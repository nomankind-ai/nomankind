/**
 * The confidence field, and the receipts it would have been computed from.
 *
 * The training path, "The confidence field": "Tier feeds the confidence field, a
 * number derived by formula from evidence tier, reproduction counts, age against
 * the freshness window, and dispute history. It is a summary of receipts, never
 * a vote. The formula is not published at launch, on purpose, and until it is,
 * the field is null ... A bad formula would be the most damaging thing in the
 * system, because learners weight on it, and there is nothing to calibrate it
 * against until the log holds enough dispute and failure-report history. Until
 * then the field is null and every input to it is exposed raw, so a learner can
 * build its own weighting from the receipts rather than trust a number nobody
 * has tested."
 *
 * This module is the second half of that sentence. It computes no confidence and
 * it must not: `confidence` and `formula` are both null here, unconditionally
 * and by construction rather than by a flag someone could flip, and there is no
 * code path in the system that returns a number. What it does is collect the
 * inputs the paper names — tier, test acceptance, reproduction and observation
 * counts, age against the window, disputes, failure reports — and hand them over
 * unweighted, so a reader can do the weighting the maintainer has not earned the
 * right to do yet.
 *
 * Pure and synchronous. Nothing is derived here: every field is read from the
 * stored entry and its sidecar by the schema's own names, and the arithmetic is
 * counting and summing what derivation already wrote. The only time input is
 * `now`, injected by the caller.
 */

import type { EvidenceTier, TestVerdict } from "./evidence.js";
import type { Sidecar } from "./derive.js";
import type { Entry } from "./schema.js";
import { isSourceClass, type SourceClass } from "./sources.js";

/** A unit constant, not a policy number. */
const MILLISECONDS_PER_DAY = 86_400_000;

/** What the validators said about the entry's proposed test. */
export interface TestAcceptance {
  readonly accepted: number;
  readonly rejected: number;
}

/**
 * The n-of-k evidence across every record that carried a reproduction: how many
 * records, and the runs and holds they add up to (the schema's reproduction
 * shape, `runs` and `holds`).
 */
export interface ReproductionCounts {
  readonly records: number;
  readonly runs: number;
  readonly holds: number;
}

/** How much checking the entry has actually had. */
export interface EvidenceCounts {
  readonly approvals: number;
  readonly rejections: number;
  readonly reproductions: ReproductionCounts;
  readonly observations: number;
  readonly reconfirmations: number;
}

/**
 * The entry's age against its freshness window, as two numbers and never as the
 * ratio itself.
 *
 * A ratio would be a weighting, and weighting is exactly what this module has no
 * mandate to do: 40 days into a 90-day window and 40 days into a 30-day one are
 * different facts, and which of them matters more is the reader's call until
 * conf-v1 is published and calibrated.
 */
export interface AgeRatio {
  readonly days: number;
  readonly window_days: number;
}

/** The dispute history, by outcome. */
export interface DisputeCounts {
  readonly open: number;
  readonly upheld: number;
  readonly failed: number;
  readonly total: number;
}

/**
 * The failure-report history. `distinct_operators` counts only reports from a
 * verified operator, distinct, because that is the count Section 8's threshold
 * turns on: "The threshold that auto-opens revalidation counts distinct verified
 * operators only", so a flood of bare-key reports moves `total` and nothing else.
 */
export interface ReportCounts {
  readonly total: number;
  readonly distinct_operators: number;
}

/** Every published input to the confidence field, and the null field itself. */
export interface ConfidenceInputs {
  /** Null for every entry: conf-v1 is unpublished. */
  readonly confidence: null;
  /** Null for the same reason: there is no formula to name. */
  readonly formula: null;
  readonly evidence_tier: EvidenceTier | null;
  readonly effective_tier: EvidenceTier | null;
  /**
   * Where the claim came from (decision D-080): the class the entry's citation
   * earned, and the listed host that matched it.
   *
   * An input and never a weight, like every other field here. The paper names
   * tier, reproduction counts, age and dispute history as the inputs conf-v1
   * would read; the source class is the same kind of receipt — a fact about the
   * entry that a learner may weight for itself — and publishing it raw is what
   * lets a learner prefer provider-stated pricing over a blog without waiting
   * for a formula nobody has calibrated.
   *
   * Null for an entry whose sidecar carries no class at all, which is a row
   * written before the key existed and read by a caller that did not default it.
   */
  readonly source_class: SourceClass | null;
  readonly source_matched_host: string | null;
  readonly test_verdict: TestVerdict | null;
  readonly test_acceptance: TestAcceptance;
  readonly counts: EvidenceCounts;
  readonly age_ratio: AgeRatio | null;
  readonly stale: boolean;
  readonly dispute_count: DisputeCounts;
  readonly report_count: ReportCounts;
  readonly superseded: boolean;
  readonly overturned: boolean;
  readonly status: string;
}

/** A record on the entry, read by the schema's own field names. */
type SchemaRecord = Record<string, unknown>;

/** An array field on the entry, or an empty list when it holds none. */
function arrayField(entry: Entry, name: string): readonly SchemaRecord[] {
  const value = (entry as Record<string, unknown>)[name];
  if (!Array.isArray(value)) return [];
  return value.filter(
    (item): item is SchemaRecord =>
      typeof item === "object" && item !== null && !Array.isArray(item),
  );
}

/** A nested object field on a record, or null. */
function objectField(record: SchemaRecord, name: string): SchemaRecord | null {
  const value = record[name];
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    return null;
  }
  return value as SchemaRecord;
}

/** An integer field on a measurement, or zero when it is not one. */
function countField(record: SchemaRecord, name: string): number {
  const value = record[name];
  return typeof value === "number" && Number.isInteger(value) ? value : 0;
}

function startOfDayMs(date: string): number {
  return Date.parse(`${date}T00:00:00.000Z`);
}

/** The UTC calendar day an instant falls on. */
function utcDayOf(timestamp: string): string {
  return new Date(Date.parse(timestamp)).toISOString().slice(0, 10);
}

/**
 * Whole UTC days from `from` (a date) to `now` (an instant), never negative.
 *
 * Calendar arithmetic and not an instant subtraction: `last_confirmed` is a
 * date, so the age is a count of days that turned over and not of elapsed hours,
 * which is exactly the comparison derivation makes when it decides whether an
 * entry is stale. Never negative, because a `last_confirmed` ahead of the clock
 * is a clock problem and a negative age would be read as a very fresh entry.
 */
function daysBetween(from: string, now: string): number {
  const days = Math.round(
    (startOfDayMs(utcDayOf(now)) - startOfDayMs(from)) / MILLISECONDS_PER_DAY,
  );
  return days < 0 ? 0 : days;
}

/**
 * The raw inputs to the confidence field for one stored entry.
 *
 * `entry` is what `deriveEntry` produced and the store holds verbatim, read by
 * the schema's own field names; `sidecar` carries the three the schema cannot
 * (`effective_tier`, `test_verdict` and `source`), two of which the paper's
 * first sentence names first: tier is what feeds the field, and the tier that
 * matters is the one the entry actually verified at, not the one its core
 * claims. The source class is D-080's addition to the same list of receipts.
 *
 * `age_ratio` is null unless the entry is verified and carries a window. An
 * event-category entry has no window to age against — "once they happened they
 * stay true" — and an entry that has not verified has nothing whose age would
 * mean anything.
 *
 * Never throws: a field the entry does not carry reads as absent rather than as
 * an exception, because this answers a public endpoint over rows that may have
 * been written by an older Worker.
 */
export function confidenceInputs(input: {
  entry: Entry;
  sidecar: Sidecar;
  now: string;
}): ConfidenceInputs {
  const entry = input.entry as Record<string, unknown>;
  const approvers = arrayField(input.entry, "approvers");
  const reconfirmations = arrayField(input.entry, "reconfirmations");
  const disputes = arrayField(input.entry, "disputes");
  const reports = arrayField(input.entry, "failure_reports");

  let accepted = 0;
  let rejected = 0;
  let approvals = 0;
  let rejections = 0;
  for (const approver of approvers) {
    if (approver["decision"] === "approve") approvals += 1;
    if (approver["decision"] === "reject") rejections += 1;
    if (approver["test_accepted"] === true) accepted += 1;
    if (approver["test_accepted"] === false) rejected += 1;
  }

  // A reproduction or an observation counts wherever it was carried: an
  // approval and a reconfirmation are both a record of somebody having run the
  // thing, and the paper counts "reproduction counts" without distinguishing.
  let reproductionRecords = 0;
  let runs = 0;
  let holds = 0;
  let observations = 0;
  for (const record of [...approvers, ...reconfirmations]) {
    const reproduction = objectField(record, "reproduction");
    if (reproduction !== null) {
      reproductionRecords += 1;
      runs += countField(reproduction, "runs");
      holds += countField(reproduction, "holds");
    }
    if (objectField(record, "observation") !== null) observations += 1;
  }

  let open = 0;
  let upheld = 0;
  let failed = 0;
  for (const dispute of disputes) {
    if (dispute["outcome"] === "open") open += 1;
    if (dispute["outcome"] === "upheld") upheld += 1;
    if (dispute["outcome"] === "failed") failed += 1;
  }

  const reportOperators = new Set<string>();
  for (const report of reports) {
    const operator = report["operator"];
    if (typeof operator === "string") reportOperators.add(operator);
  }

  const status = typeof entry["status"] === "string" ? entry["status"] : "";
  const window = entry["staleness_window_days"];
  const lastConfirmed = entry["last_confirmed"];
  const ageRatio: AgeRatio | null =
    status === "verified" &&
    typeof window === "number" &&
    typeof lastConfirmed === "string"
      ? { days: daysBetween(lastConfirmed, input.now), window_days: window }
      : null;

  return {
    confidence: null,
    formula: null,
    evidence_tier:
      typeof entry["evidence_tier"] === "string"
        ? (entry["evidence_tier"] as EvidenceTier)
        : null,
    effective_tier: input.sidecar.effective_tier,
    source_class: isSourceClass(input.sidecar.source?.class)
      ? input.sidecar.source.class
      : null,
    source_matched_host:
      typeof input.sidecar.source?.matched_host === "string"
        ? input.sidecar.source.matched_host
        : null,
    test_verdict: input.sidecar.test_verdict,
    test_acceptance: { accepted, rejected },
    counts: {
      approvals,
      rejections,
      reproductions: { records: reproductionRecords, runs, holds },
      observations,
      reconfirmations: reconfirmations.length,
    },
    age_ratio: ageRatio,
    stale: entry["stale"] === true,
    dispute_count: {
      open,
      upheld,
      failed,
      total: disputes.length,
    },
    report_count: {
      total: reports.length,
      distinct_operators: reportOperators.size,
    },
    superseded: entry["superseded_by"] !== null && entry["superseded_by"] !== undefined,
    overturned: entry["overturned_by"] !== null && entry["overturned_by"] !== undefined,
    status,
  };
}
