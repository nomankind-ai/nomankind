/**
 * Drift attestation: the scorer draw, the window, the refusals, and the fold.
 *
 * The training path, "Drift attestation": "A probe set is drawn from verified,
 * observed, fresh entries by public randomness ... The model answers the probes.
 * Three operators from the trusted pool, none under the model's operator, score
 * its answers against the log and sign the result, and the score and the probe
 * hash are sealed with a date. The attestation says one thing in public. As of
 * this date, this model's beliefs about the AI ecosystem agree with the verified
 * record to this degree, judged by parties its lab does not control."
 *
 * So the attestation is a small lifecycle of its own — requested, answered,
 * scored, or expired — and it is derived from the log exactly as an entry's
 * status is: `deriveAttestation` folds the four events and nothing here is ever
 * written directly. The probe set itself is src/probe.ts's; this module is the
 * half about who scores, by when, and what the score comes out as.
 *
 * Pure, and no wall clock: time arrives as ISO 8601 strings and through the
 * injected `Clock`. Hashing is WebCrypto via src/hash.ts, so this runs unchanged
 * on a Worker, and every policy number comes from src/policy.ts.
 */

import { canonicalize, taggedSha256Hex } from "./hash.js";
import {
  ATTESTATION_SCORERS,
  ATTESTATION_WINDOW_HOURS,
  DEFAULT_DOMAIN,
} from "./policy.js";
import type { Beacon, PoolSnapshot } from "./assign.js";
import type { Clock } from "./derive.js";
import type {
  AttestationScorer,
  AttestationScoreRecord,
  Event,
  EventPayloads,
  EventType,
  Probe,
} from "./events.js";

/**
 * Domain-separation tags. Format constants, not policy numbers: they name the
 * hash constructions, so a scorer draw can never be replayed as a validator draw
 * and an attestation id can never be an entry hash.
 */
export const HASH_TAG_SCORER_DRAW = "nomankind-scorer-draw-v1";
export const HASH_TAG_ATTESTATION_ID = "nomankind-attestation-id-v1";

/** The prefix every attestation id carries, as `nmk_` is an entry's. */
export const ATTESTATION_ID_PREFIX = "att_";

/**
 * How many hex characters of the id digest the id keeps: thirty-two, which is
 * 128 bits. A format constant and not a policy number — it names the id's shape,
 * the way the `sha256:` prefix names a hash's, and moving it would change the
 * wire format rather than a published amount.
 */
const ATTESTATION_ID_HEX = 32;

/** A unit constant, not a policy number. */
const MILLISECONDS_PER_HOUR = 3_600_000;

/**
 * The attestation id: `att_` and the first thirty-two hex of the tagged hash
 * over the model, the snapshot position, the beacon round and the probe hash.
 *
 * Which is what makes "one model attests at most once per beacon round" a fact
 * about the id rather than a rule someone has to remember: two requests by the
 * same model against the same snapshot and the same round draw the same probes,
 * so they hash to the same id and the second one collides with the first in
 * storage instead of opening a parallel attestation nobody drew.
 */
export async function attestationId(input: {
  model: string;
  pool_snapshot_seq: number;
  beacon_round: number;
  probe_hash: string;
}): Promise<string> {
  const digest = await taggedSha256Hex(
    HASH_TAG_ATTESTATION_ID,
    canonicalize({
      model: input.model,
      pool_snapshot_seq: input.pool_snapshot_seq,
      beacon_round: input.beacon_round,
      probe_hash: input.probe_hash,
    }),
  );
  return `${ATTESTATION_ID_PREFIX}${digest.slice(0, ATTESTATION_ID_HEX)}`;
}

/**
 * The deadline for an attestation requested at `at`: ATTESTATION_WINDOW_HOURS
 * later, as an ISO 8601 date-time with milliseconds. One window covers both the
 * model's answers and the scorers' scores, so an attestation has one deadline
 * and not two.
 */
export function attestationDeadline(at: string): string {
  const deadline =
    Date.parse(at) + ATTESTATION_WINDOW_HOURS * MILLISECONDS_PER_HOUR;
  return new Date(deadline).toISOString();
}

// ---------------------------------------------------------------------------
// The scorer draw
// ---------------------------------------------------------------------------

/** Why no scorers were drawn, in the order the checks run. */
export type ScorerDrawRefusal =
  | "snapshot_after_beacon"
  | "empty_pool"
  | "insufficient_scorers";

/** The refusals in check order, so a caller reports them in the same one. */
export const SCORER_DRAW_REFUSALS: readonly ScorerDrawRefusal[] = Object.freeze([
  "snapshot_after_beacon",
  "empty_pool",
  "insufficient_scorers",
]);

export type ScorerDrawResult =
  | { ok: true; scorers: readonly string[] }
  | { ok: false; reason: ScorerDrawRefusal };

/** Sorted, de-duplicated, default string order: the pool's canonical form. */
function canonicalPool(operators: readonly string[]): string[] {
  return [...new Set(operators)].sort();
}

/**
 * Draw the scorers: ATTESTATION_SCORERS distinct operators from the trusted
 * pool, none of them the model's own and none of them a maintainer.
 *
 * "Three operators from the trusted pool, none under the model's operator" is
 * the whole rule, and `exclude` is how it is enforced: the caller puts the
 * model's operator in it (when the model's agent is bound to one) together with
 * the maintainer operators, for the same reason validation excludes them — a
 * judgement nomankind signs about a model is not a judgement "by parties its lab
 * does not control" if nomankind is one of the parties. A model provider cannot
 * appear at all: the snapshot is the TRUSTED pool, and Section 10's door refuses
 * a registration by an excluded party outright (src/policy.ts, the domain's
 * `excluded_parties`), so
 * no provider is ever in a pool snapshot to be drawn from.
 *
 * The draw is sequential and without replacement: each round digests the model,
 * the probe hash, the operators still eligible, the beacon round and its
 * randomness, and the round's own index, takes the digest as a big integer
 * modulo how many are left, and removes the one it picked. Distinct operators
 * fall out of the removal rather than out of a retry loop, so the draw always
 * terminates and always terminates in the same place.
 *
 * A rule refusal is a verdict, never a throw.
 */
export async function drawScorers(input: {
  model: string;
  probe_hash: string;
  snapshot: PoolSnapshot;
  beacon: Beacon;
  exclude: readonly string[];
}): Promise<ScorerDrawResult> {
  // The same commitment ordering as every other draw: the snapshot is sealed
  // before the round it uses, and equal times are not before.
  if (!(Date.parse(input.snapshot.at) < Date.parse(input.beacon.at))) {
    return { ok: false, reason: "snapshot_after_beacon" };
  }

  const pool = canonicalPool(input.snapshot.operators);
  if (pool.length === 0) return { ok: false, reason: "empty_pool" };

  const excluded = new Set(input.exclude);
  let eligible = pool.filter((operator) => !excluded.has(operator));
  if (eligible.length < ATTESTATION_SCORERS) {
    return { ok: false, reason: "insufficient_scorers" };
  }

  const scorers: string[] = [];
  for (let index = 0; index < ATTESTATION_SCORERS; index += 1) {
    const hex = await taggedSha256Hex(
      HASH_TAG_SCORER_DRAW,
      canonicalize({
        model: input.model,
        probe_hash: input.probe_hash,
        pool: eligible,
        beacon_round: input.beacon.round,
        beacon_randomness: input.beacon.randomness,
        index,
      }),
    );
    const at = Number(BigInt(`0x${hex}`) % BigInt(eligible.length));
    const drawn = eligible[at] as string;
    scorers.push(drawn);
    eligible = eligible.filter((operator) => operator !== drawn);
  }

  return { ok: true, scorers };
}

// ---------------------------------------------------------------------------
// The derived attestation
// ---------------------------------------------------------------------------

/** One scorer's verdict, as the fold read it out of the log. */
export interface AttestationScore {
  readonly operator: string;
  readonly agent: string;
  readonly agreed: number;
  /** Position of the `attestation_scored` event in the log. */
  readonly seq: number;
  readonly signed_at: string;
}

/** The attestation's own status, derived and never written. */
export type AttestationStatus = "open" | "answered" | "scored" | "expired";

/**
 * The score the attestation publishes: how many probes the model agreed with the
 * log on, out of how many were asked.
 *
 * Two numbers rather than one, deliberately. "The attestation says one thing in
 * public" — and a bare fraction would say two things at once, because 3/3 from a
 * genesis-thin probe set and 30/30 from a full one are not the same claim. The
 * reader gets both and weights for itself, exactly as it does with the
 * confidence field's raw inputs (src/confidence.ts).
 */
export interface AttestationScoreValue {
  readonly agreed: number;
  readonly probe_count: number;
}

/** One attestation, folded from the four events that carry its id. */
export interface DerivedAttestation {
  readonly id: string;
  /** The domain the probes were drawn from and the scorers are attested in. */
  readonly domain: string;
  readonly model: string;
  readonly model_operator: string | null;
  readonly probes: readonly Probe[];
  readonly probe_hash: string;
  readonly probe_count: number;
  readonly pool_snapshot_seq: number;
  readonly beacon_round: number;
  readonly scorers: readonly AttestationScorer[];
  /** Position of the `attestation_requested` event in the log. */
  readonly requested_seq: number;
  readonly requested_at: string;
  readonly deadline: string;
  readonly answers_hash: string | null;
  readonly answered_at: string | null;
  readonly scores: readonly AttestationScore[];
  readonly score: AttestationScoreValue | null;
  readonly status: AttestationStatus;
  readonly scored_at: string | null;
  /** The UTC day the last score landed: the date the attestation is "as of". */
  readonly date: string | null;
}

/** Events in seq order, without mutating the caller's array (as derive.ts). */
function inSeqOrder(events: readonly Event[]): readonly Event[] {
  return [...events].sort((left, right) => left.seq - right.seq);
}

function isType<T extends EventType>(event: Event, type: T): event is Event<T> {
  return event.type === type;
}

/**
 * The median of the scorers' `agreed` values.
 *
 * With ATTESTATION_SCORERS at three this is the middle of three, which is the
 * point of scoring three times: one scorer who read the log wrong, or scored
 * generously, moves nothing. An even count takes the lower of the two middle
 * values rather than their mean, because the score is a count of probes and a
 * half-probe is not a thing that can have been agreed with.
 */
function median(values: readonly number[]): number {
  const sorted = [...values].sort((left, right) => left - right);
  return sorted[Math.floor((sorted.length - 1) / 2)] as number;
}

/** The UTC calendar day an instant falls on. */
function utcDayOf(timestamp: string): string {
  return new Date(Date.parse(timestamp)).toISOString().slice(0, 10);
}

/**
 * Fold one attestation out of the log.
 *
 * `events` is every event carrying this attestation's id — the caller reads them
 * with `eventsForAttestation` — and the fold is over those alone, so an
 * attestation's whole story is a sub-sequence of the log exactly as an entry's
 * is. Throws when no `attestation_requested` is among them: there is nothing to
 * derive, and a made-up empty attestation would be a lie.
 *
 * The status is read from the events and never from the clock, which is why the
 * `clock` this takes decides nothing here: expiry is an `attestation_expired`
 * event the sweep appends (`attestationDue` is what decides one is owed), so an
 * attestation whose window has quietly run out still reads `open` until the log
 * says otherwise. That is the point — the log, and not the reader's wall clock,
 * is what a score is checked against years later. The parameter stays because
 * every derivation in the kernel takes one and a fold that took no clock would
 * be the odd one out the day a field does need it.
 *
 * `scored` means every drawn scorer scored, counted by operator: Section 5's
 * rule that the operator is the unit holds here too, so two agents under one
 * scoring operator are one score and not two.
 */
export function deriveAttestation(
  events: readonly Event[],
  clock: Clock,
): DerivedAttestation {
  void clock;
  const ordered = inSeqOrder(events);

  let requested: Event<"attestation_requested"> | null = null;
  for (const event of ordered) {
    if (isType(event, "attestation_requested")) {
      requested = event;
      break;
    }
  }
  if (requested === null) {
    throw new Error("deriveAttestation: no attestation_requested event");
  }
  const opened = requested.payload;
  const id = opened.attestation;

  let answersHashValue: string | null = null;
  let answeredAt: string | null = null;
  let expired = false;
  const drawn = new Set(opened.scorers.map((scorer) => scorer.operator));
  const byOperator = new Map<string, AttestationScore>();

  for (const event of ordered) {
    if (event.seq <= requested.seq) continue;
    if (isType(event, "attestation_answered")) {
      if (event.payload.attestation !== id) continue;
      // A second answer replaces the first: the fold takes the log at its word
      // and the route is what refuses one (`checkAnswer`, `not_open`).
      answersHashValue = event.payload.answers_hash;
      answeredAt = event.at;
      continue;
    }
    if (isType(event, "attestation_scored")) {
      if (event.payload.attestation !== id) continue;
      const record = event.payload.record;
      if (!drawn.has(record.operator)) continue;
      byOperator.set(record.operator, {
        operator: record.operator,
        agent: record.agent,
        agreed: record.agreed,
        seq: event.seq,
        signed_at: record.signed_at,
      });
      continue;
    }
    if (isType(event, "attestation_expired")) {
      if (event.payload.attestation !== id) continue;
      expired = true;
    }
  }

  // In the order the scorers were drawn, so the published list of who scored
  // reads against the published list of who was asked.
  const scores: AttestationScore[] = [];
  for (const scorer of opened.scorers) {
    const score = byOperator.get(scorer.operator);
    if (score !== undefined) scores.push(score);
  }

  const complete =
    opened.scorers.length > 0 && scores.length === opened.scorers.length;

  let status: AttestationStatus = "open";
  if (answersHashValue !== null) status = "answered";
  if (complete) status = "scored";
  // An expiry is the last word: the sweep appends it only to an attestation
  // that is still open or answered, so it can never sit on top of a full score.
  if (expired) status = "expired";

  const lastScore =
    scores.length === 0
      ? null
      : scores.reduce((latest, score) =>
          score.seq > latest.seq ? score : latest,
        );
  const scoredAt =
    status === "scored" && lastScore !== null
      ? (ordered.find((event) => event.seq === lastScore.seq)?.at ?? null)
      : null;

  return {
    id,
    domain: opened.domain ?? DEFAULT_DOMAIN,
    model: opened.model,
    model_operator: opened.model_operator,
    probes: opened.probes,
    probe_hash: opened.probe_hash,
    probe_count: opened.probe_count,
    pool_snapshot_seq: opened.pool_snapshot_seq,
    beacon_round: opened.beacon_round,
    scorers: opened.scorers,
    requested_seq: requested.seq,
    requested_at: requested.at,
    deadline: opened.deadline,
    answers_hash: answersHashValue,
    answered_at: answeredAt,
    scores,
    score:
      status === "scored"
        ? {
            agreed: median(scores.map((score) => score.agreed)),
            probe_count: opened.probe_count,
          }
        : null,
    status,
    scored_at: scoredAt,
    date: scoredAt === null ? null : utcDayOf(scoredAt),
  };
}

// ---------------------------------------------------------------------------
// The refusals
// ---------------------------------------------------------------------------

/** Why an answer is refused, in the order the checks run. */
export type AnswerRefusal = "not_model" | "not_open" | "deadline_passed";

export const ANSWER_REFUSALS: readonly AnswerRefusal[] = Object.freeze([
  "not_model",
  "not_open",
  "deadline_passed",
]);

export type AnswerVerdict =
  | { ok: true }
  | { ok: false; reason: AnswerRefusal };

/**
 * Whether this agent may answer this attestation now.
 *
 * Only the model itself answers: the probes were drawn for it and an answer from
 * anyone else would be someone else's beliefs scored as the model's. The
 * deadline is strictly past, so the deadline instant itself is still inside the
 * window — the same rule `isAssignmentMissed` holds for a drawn validator.
 */
export function checkAnswer(input: {
  attestation: DerivedAttestation;
  agent: string;
  now: string;
}): AnswerVerdict {
  if (input.agent !== input.attestation.model) {
    return { ok: false, reason: "not_model" };
  }
  if (input.attestation.status !== "open") {
    return { ok: false, reason: "not_open" };
  }
  if (Date.parse(input.now) > Date.parse(input.attestation.deadline)) {
    return { ok: false, reason: "deadline_passed" };
  }
  return { ok: true };
}

/** Why a score is refused, in the order the checks run. */
export type ScoreRefusal =
  | "not_open"
  | "deadline_passed"
  | "not_a_scorer"
  | "operator_mismatch"
  | "model_operator"
  | "operator_not_in_domain"
  | "duplicate_scorer"
  | "probe_hash_mismatch"
  | "answers_hash_mismatch"
  | "bad_agreed";

export const SCORE_REFUSALS: readonly ScoreRefusal[] = Object.freeze([
  "not_open",
  "deadline_passed",
  "not_a_scorer",
  "operator_mismatch",
  "model_operator",
  "operator_not_in_domain",
  "duplicate_scorer",
  "probe_hash_mismatch",
  "answers_hash_mismatch",
  "bad_agreed",
]);

export type ScoreVerdict = { ok: true } | { ok: false; reason: ScoreRefusal };

/**
 * Whether this scorer may score this attestation now.
 *
 * The order is the order of the rules, widest first. There is nothing to score
 * until the model has answered, which is why `not_open` is "status is not
 * `answered`" and covers an attestation still open, one already fully scored,
 * and one expired. Then the window. Then who is signing: a drawn scorer's agent,
 * the operator the registry says answers for that agent, not the model's own
 * operator, and not one that has already scored. Only then the contents of the
 * record, which are the cheapest checks and the least interesting refusals.
 *
 * `scorerOperator` is the operator the caller resolved for the signing agent
 * (`operatorForAgent`), which this module cannot resolve because it does not
 * read the log. `operator_mismatch` therefore holds the record's claim against
 * both the registry's answer and the operator the draw actually picked: a record
 * that names an operator other than the one behind its own key is refused, and
 * so is one whose key is a drawn scorer's while its operator is somebody else's.
 *
 * `agreed` must be a whole number of probes between none and all of them: a
 * score of 11 out of 10, or of 2.5, is not a count of anything.
 */
export function checkScore(input: {
  attestation: DerivedAttestation;
  record: AttestationScoreRecord;
  scorerOperator: string | null;
  /**
   * The domains the scorer's operator is attested in (src/derive.ts,
   * `operatorDomainsAt`). Absent reads as the default domain.
   */
  scorerDomains?: readonly string[];
  now: string;
}): ScoreVerdict {
  const { attestation, record } = input;

  if (attestation.status !== "answered") {
    return { ok: false, reason: "not_open" };
  }
  if (Date.parse(input.now) > Date.parse(attestation.deadline)) {
    return { ok: false, reason: "deadline_passed" };
  }

  const scorer = attestation.scorers.find(
    (drawn) => drawn.agent === record.agent,
  );
  if (scorer === undefined) return { ok: false, reason: "not_a_scorer" };

  if (
    record.operator !== scorer.operator ||
    record.operator !== input.scorerOperator
  ) {
    return { ok: false, reason: "operator_mismatch" };
  }
  if (
    attestation.model_operator !== null &&
    record.operator === attestation.model_operator
  ) {
    return { ok: false, reason: "model_operator" };
  }
  // Decision D-071: the attestation belongs to a domain, and a scorer signs
  // about it only in a domain it has attested in. The draw is domain-blind by
  // construction (the caller excludes the rest of the pool), so this is the
  // check that says so out loud on the record itself.
  const scorerDomains = input.scorerDomains ?? [DEFAULT_DOMAIN];
  if (!scorerDomains.includes(attestation.domain)) {
    return { ok: false, reason: "operator_not_in_domain" };
  }
  if (attestation.scores.some((score) => score.operator === record.operator)) {
    return { ok: false, reason: "duplicate_scorer" };
  }

  if (record.probe_hash !== attestation.probe_hash) {
    return { ok: false, reason: "probe_hash_mismatch" };
  }
  if (record.answers_hash !== attestation.answers_hash) {
    return { ok: false, reason: "answers_hash_mismatch" };
  }
  if (
    !Number.isInteger(record.agreed) ||
    record.agreed < 0 ||
    record.agreed > attestation.probe_count
  ) {
    return { ok: false, reason: "bad_agreed" };
  }
  return { ok: true };
}

/**
 * Whether the attestation's window has run out, and who never scored.
 *
 * The mirror of `isAssignmentMissed` for the training path, and the sweep's one
 * question: an attestation still open or answered, strictly past its deadline,
 * is owed an `attestation_expired`, and the payload it is owed names the scorer
 * operators that never answered. Null when nothing is owed.
 *
 * An expiry is not a failing score and claims nothing about drift — a model
 * whose scorers went quiet has not drifted, it has not been scored. Which is why
 * `missing` is published: an attestation that expired with three scorers missing
 * is a scorer problem, and one that expired with none missing is a model that
 * never answered.
 */
export function attestationDue(
  attestation: DerivedAttestation,
  now: string,
): EventPayloads["attestation_expired"] | null {
  if (attestation.status !== "open" && attestation.status !== "answered") {
    return null;
  }
  if (!(Date.parse(now) > Date.parse(attestation.deadline))) return null;

  const scored = new Set(attestation.scores.map((score) => score.operator));
  return {
    attestation: attestation.id,
    missing: attestation.scorers
      .map((scorer) => scorer.operator)
      .filter((operator) => !scored.has(operator)),
  };
}
