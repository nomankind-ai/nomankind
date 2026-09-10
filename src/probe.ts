/**
 * The probe set: which entries an attestation asks about, and what the answers
 * hash to.
 *
 * The training path, "Drift attestation": "A probe set is drawn from verified,
 * observed, fresh entries by public randomness, the same beacon-and-snapshot
 * construction as validator assignment (Section 6), so neither the model's
 * operator nor the maintainer picks the questions ... That set size is published
 * policy, and the observed tier will be thin at genesis (Section 12)."
 *
 * "The same construction as validator assignment" is meant literally, so this
 * module borrows src/assign.ts's own `PoolSnapshot` and `Beacon` rather than
 * declaring a second pair that could drift from them, and it enforces the same
 * commitment ordering: the snapshot is sealed before the beacon round it uses,
 * or there is no draw. The one difference is what the randomness is spent on. An
 * assignment picks one operator out of a pool; a probe set picks ten entries out
 * of every candidate, which is a ranking rather than a modulus — every candidate
 * gets a digest of its own and the lowest ten win.
 *
 * Pure: no I/O, no storage, and no wall clock. Which entries are candidates is
 * the caller's question (src/storage/repository.ts, `probeCandidates`), because
 * "verified, observed, fresh" are stored fields and reading them is not a rule.
 * Hashing is WebCrypto via src/hash.ts, so this runs unchanged on a Worker, and
 * every policy number comes from src/policy.ts.
 */

import { canonicalize, taggedSha256Hex } from "./hash.js";
import { PROBE_SET_MIN_CANDIDATES, PROBE_SET_SIZE } from "./policy.js";
import type { Beacon, PoolSnapshot } from "./assign.js";
import type { Probe } from "./events.js";

/**
 * Domain-separation tags. Format constants, not policy numbers: they name the
 * hash constructions, so a probe's rank digest can never be replayed as a probe
 * hash, an answers hash, an assignment draw, or an entry or event hash.
 */
export const HASH_TAG_PROBE = "nomankind-probe-v1";
export const HASH_TAG_PROBE_SET = "nomankind-probe-set-v1";
export const HASH_TAG_ANSWERS = "nomankind-answers-v1";

/** An entry the draw may pick, as the store hands it over. */
export interface ProbeCandidate {
  readonly entry_id: string;
  readonly entry_hash: string;
}

/** One answer the model gave, against the probe it answers. */
export interface ProbeAnswer {
  readonly entry_id: string;
  readonly answer: string;
}

/** Why no probe set was drawn, in the order the checks run. */
export type ProbeSetRefusal = "snapshot_after_beacon" | "insufficient_candidates";

/** The refusals in check order, so a caller can report them in the same one. */
export const PROBE_SET_REFUSALS: readonly ProbeSetRefusal[] = Object.freeze([
  "snapshot_after_beacon",
  "insufficient_candidates",
]);

export type ProbeSetResult =
  | { ok: true; probes: readonly Probe[]; probe_hash: string }
  | { ok: false; reason: ProbeSetRefusal };

/** Sorted, de-duplicated, default string order: the pool's canonical form. */
function canonicalPool(operators: readonly string[]): string[] {
  return [...new Set(operators)].sort();
}

/**
 * One candidate's rank digest: the tagged hash over the entry id, the whole
 * canonical pool, and the beacon round and its randomness.
 *
 * The pool is inside the digest for the reason `drawValidator` gives: it is the
 * published commitment, and a draw that digested only the entry and the beacon
 * would be recomputable by anyone before the snapshot was ever sealed. The
 * entry hash is deliberately NOT inside it — a reconfirmation between the
 * snapshot and the round would move a candidate's rank, and the draw would stop
 * being a function of the two things the paper says it is a function of.
 */
async function rankOf(
  entryId: string,
  pool: readonly string[],
  beacon: Beacon,
): Promise<string> {
  return taggedSha256Hex(
    HASH_TAG_PROBE,
    canonicalize({
      entry_id: entryId,
      pool,
      beacon_round: beacon.round,
      beacon_randomness: beacon.randomness,
    }),
  );
}

/**
 * The probe set hash: the tagged hash over the canonical form of the sorted
 * probes, prefixed "sha256:" to match the schema's hash pattern, exactly as
 * every other hash the log seals is.
 *
 * Exported because the score record carries the probe hash and a scorer that
 * wants to check it recomputes it from the probes it was served rather than
 * trusting the number beside them.
 */
export async function probeSetHash(probes: readonly Probe[]): Promise<string> {
  const sorted = [...probes]
    .map((probe) => ({ entry_id: probe.entry_id, entry_hash: probe.entry_hash }))
    .sort((left, right) =>
      left.entry_id < right.entry_id ? -1 : left.entry_id > right.entry_id ? 1 : 0,
    );
  return `sha256:${await taggedSha256Hex(HASH_TAG_PROBE_SET, canonicalize(sorted))}`;
}

/**
 * Draw the probe set.
 *
 * A rule refusal is a verdict, never a throw: the caller gets a reason it can
 * report. The two refusals run in the order they are declared — the commitment
 * ordering first, because a snapshot sealed after the round it uses means the
 * draw was never legitimate whatever the candidates were, and only then the
 * floor.
 *
 * Between PROBE_SET_MIN_CANDIDATES and PROBE_SET_SIZE every candidate is drawn.
 * That is Section 12's thin observed tier, taken at its word: at genesis there
 * may be three observed entries, and refusing to attest until there are ten
 * would leave the whole training path dark for as long as the tier stays thin. A
 * three-probe attestation is a weak attestation and says so — every score is
 * published as `agreed` out of `probe_count` and never as a bare fraction.
 *
 * Ties break by entry_id, so two candidates whose digests collide are ordered by
 * something total rather than by whatever order the store returned them in, and
 * the answer stays the same across two calls with the same inputs.
 */
export async function probeSet(input: {
  candidates: readonly ProbeCandidate[];
  snapshot: PoolSnapshot;
  beacon: Beacon;
}): Promise<ProbeSetResult> {
  // The snapshot is committed before the beacon round it uses; equal times are
  // not before, so they are refused too (src/assign.ts holds the same rule).
  if (!(Date.parse(input.snapshot.at) < Date.parse(input.beacon.at))) {
    return { ok: false, reason: "snapshot_after_beacon" };
  }
  if (input.candidates.length < PROBE_SET_MIN_CANDIDATES) {
    return { ok: false, reason: "insufficient_candidates" };
  }

  const pool = canonicalPool(input.snapshot.operators);
  const ranked: Array<{ probe: Probe; rank: string }> = [];
  for (const candidate of input.candidates) {
    ranked.push({
      probe: {
        entry_id: candidate.entry_id,
        entry_hash: candidate.entry_hash,
      },
      rank: await rankOf(candidate.entry_id, pool, input.beacon),
    });
  }

  ranked.sort((left, right) => {
    if (left.rank !== right.rank) return left.rank < right.rank ? -1 : 1;
    return left.probe.entry_id < right.probe.entry_id ? -1 : 1;
  });

  const probes = ranked
    .slice(0, PROBE_SET_SIZE)
    .map((entry) => entry.probe)
    .sort((left, right) => (left.entry_id < right.entry_id ? -1 : 1));

  return { ok: true, probes, probe_hash: await probeSetHash(probes) };
}

/**
 * The answers hash: the tagged hash over the canonical form of the answers,
 * sorted by entry_id, prefixed "sha256:" like every other hash in the log.
 *
 * Sorted rather than taken in the order the model replied, so three scorers
 * holding the same answers reach the same hash however the answers reached them.
 */
export async function answersHash(
  answers: readonly ProbeAnswer[],
): Promise<string> {
  const sorted = [...answers]
    .map((answer) => ({ entry_id: answer.entry_id, answer: answer.answer }))
    .sort((left, right) =>
      left.entry_id < right.entry_id ? -1 : left.entry_id > right.entry_id ? 1 : 0,
    );
  return `sha256:${await taggedSha256Hex(HASH_TAG_ANSWERS, canonicalize(sorted))}`;
}

/** The one thing that can be wrong with a set of answers. */
export type AnswersRefusal = "bad_answers";

export type AnswersVerdict =
  | { ok: true }
  | { ok: false; reason: AnswersRefusal };

/**
 * Whether the answers answer exactly these probes: one string answer per probe,
 * and the ids exactly the probe ids — no probe unanswered, none answered twice,
 * and nothing answered that was never asked.
 *
 * One refusal rather than several, deliberately: a model that answered nine of
 * ten probes and a model that answered eleven have both failed to answer the
 * set, and telling them apart would only invite a client to work out which
 * near-miss the endpoint tolerates. Never throws.
 */
export function checkAnswers(
  probes: readonly Probe[],
  answers: unknown,
): AnswersVerdict {
  const bad: AnswersVerdict = { ok: false, reason: "bad_answers" };
  if (!Array.isArray(answers)) return bad;
  if (answers.length !== probes.length) return bad;

  const asked = new Set(probes.map((probe) => probe.entry_id));
  const seen = new Set<string>();
  for (const answer of answers as readonly unknown[]) {
    if (typeof answer !== "object" || answer === null || Array.isArray(answer)) {
      return bad;
    }
    const entryId = (answer as Record<string, unknown>)["entry_id"];
    const text = (answer as Record<string, unknown>)["answer"];
    if (typeof entryId !== "string" || typeof text !== "string") return bad;
    if (!asked.has(entryId)) return bad;
    if (seen.has(entryId)) return bad;
    seen.add(entryId);
  }
  return seen.size === asked.size ? { ok: true } : bad;
}
