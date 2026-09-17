/**
 * Independence made visible (decision D-121).
 *
 * Whitepaper "Limitations" ("The identity layer is young"): "The seal is
 * exactly as unrewritable as the countersigners are independent", and the bar
 * published for who may countersign is a published key, no two under common
 * control, nomankind ineligible, and — D-121 — no pinned witness an operator of
 * the record or under the control of one. The question a reader of the demo
 * actually asked is the one this module answers: which two sets are those, and
 * do they overlap.
 *
 * So the record publishes both sets and what falls between them, rather than
 * asserting the bar and stopping. The validator set is every registered
 * operator, trusted or not, because an operator that is not in the pool today
 * can be named into it tomorrow and a set that showed only the pool would be
 * the smaller claim. The witness set is src/policy.ts's WITNESS_PIN, by
 * directory id, operator handle and public key.
 *
 * The comparison made here is stated rather than implied, because the two sets
 * are not named in the same alphabet: an operator id is a DNS name the registry
 * verified, a witness is a 1F916 handle with its key inside it, and a string
 * equality between the two would almost always be false and would prove
 * nothing. What is honest to check is a binding the log itself holds — a
 * witness whose key is bound as an agent of a registered operator, or whose
 * handle is a registered operator's own id — and that is exactly what
 * `overlap` looks for. Anything past it, a shared owner behind two names, a
 * contract nobody published, is not visible to the record at all: the bar and
 * this intersection are what the record can show, and the paper says so where
 * it says the exclusion is honest rather than airtight.
 *
 * `external_witness_outside_validator_and_subject_provider_control` is the flag
 * morty-synctzn asked for, in the field name they asked for. It is true while
 * at least one pinned witness is outside the intersection *and* has a
 * countersignature the record actually counted — a live feed, not a name in a
 * list — because a pinned witness that never signs is an intention and the flag
 * is supposed to be a fact. "Outside the subject's and the provider's control"
 * is the part no code can decide: what is checked is the published pin, the
 * binding above and whether the countersignature was counted, and the sentence
 * on the page says that in words.
 *
 * Pure and data-only: the sets, the bindings and the newest seal's
 * countersignatures arrive as an input, and nothing here reads a store, a clock
 * or the network.
 */

import { AGENT_ID_PREFIX } from "./identity.js";

/** One registered operator, as the validator set carries it. */
export interface ValidatorEntry {
  readonly operator: string;
  readonly trusted: boolean;
  readonly maintainer: boolean;
  readonly provider: boolean;
  /** Every registered domain this operator is attested in, in the log's order. */
  readonly domains: readonly string[];
  /**
   * The perimeter the maintainer disclosed when it named this operator into the
   * trusted pool, or null (decision D-128).
   *
   * Section 11's genesis is "a bootstrap exception to the earned-record rule,
   * stated as such". Stating it is what this field is for: the maintainer's own
   * grouping is published beside the operator rather than left for a reader to
   * infer from the domain names, so a set that looks like six independent
   * parties and is one is readable as one.
   *
   * Disclosed and never enforced. No rule anywhere refuses a validation because
   * of a perimeter; what it changes is what the record is willing to claim.
   */
  readonly perimeter: string | null;
}

/** The head a countersignature covered: the registry's tree, at a size. */
export interface CountersignedHead {
  readonly tree_size: number;
  readonly root: string;
}

/** One pinned witness, with what the newest seal says about it. */
export interface WitnessEntry {
  readonly id: number;
  readonly operator: string;
  readonly public_key: string;
  /** The 1F916 agent id the key makes, which is what a countersignature names. */
  readonly agent: string;
  /**
   * Whether the newest seal counted a countersignature from this witness: the
   * feed is live, rather than pinned and silent.
   */
  readonly counted: boolean;
  /**
   * The head that countersignature covered, or null on a signature in the
   * direct form (the mock witness signs the seal hash and there is no head).
   */
  readonly head: CountersignedHead | null;
  /** The registered operator this witness's key is bound to, or null. */
  readonly bound_operator: string | null;
}

/** One witness that is also in the validator set, and how the record knows. */
export interface OverlapEntry {
  readonly witness: string;
  readonly agent: string;
  readonly operator: string;
  /** Which of the two checks matched: the bound key, or the handle itself. */
  readonly matched: "agent_bound_to_operator" | "handle_is_operator_id";
}

/** What one kind of signature is made over, in the record's own field names. */
export interface CoveredObjectEntry {
  readonly covers: string;
  readonly fields: readonly string[];
  readonly signed_by: string;
  readonly note: string;
}

/** Where one part of this report is computed from. Data, not policy. */
export interface DerivedFromEntry {
  /** The published rows the answer is folded out of, named as rows. */
  readonly rows: readonly string[];
  /** Where a reader can fetch those rows for themselves. */
  readonly published_at: readonly string[];
  readonly note: string;
}

/** The whole answer, and the JSON twin's exact shape. */
export interface IndependenceReport {
  readonly validator_set: readonly ValidatorEntry[];
  /**
   * The disclosed perimeters, each naming the operators inside it, in the
   * validator set's own order (decision D-128).
   *
   * Beside the two sets rather than folded into the claim, because it is the
   * fact the claim is a reading of: a reader who disagrees with the words below
   * can see the grouping and decide for themselves. An empty object is the
   * ordinary case — no perimeter disclosed on any operator — and not a
   * statement that none exists.
   */
  readonly validator_perimeters: Readonly<Record<string, readonly string[]>>;
  readonly witness_set: readonly WitnessEntry[];
  readonly intersection: readonly OverlapEntry[];
  readonly covered_object: Readonly<Record<string, CoveredObjectEntry>>;
  /**
   * Which published rows each part of this report was computed from (D-132).
   *
   * The page asserted two sets and a verdict and left a reader to find out for
   * themselves where either came from. This is the answer, per set, in the
   * names of the rows and the addresses they are published at, so
   * `npm run independence` and a reader with curl are doing the same thing.
   */
  readonly derived_from: Readonly<Record<string, DerivedFromEntry>>;
  readonly external_witness_outside_validator_and_subject_provider_control: boolean;
  /** The claim the record will make out loud, in the words below. */
  readonly claim: string;
  /** The seal the witness readings came from, null before the first one. */
  readonly seal_seq: number | null;
}

/**
 * The four claims, and the rule that picks one.
 *
 * A non-empty intersection is the strongest thing that can be said about it and
 * it is not "independent": the keys are still distinct keys, and the perimeter
 * they share is disclosed on the page rather than hidden, so the label says
 * exactly that and no more. An empty intersection with a live outside witness
 * is the claim the design is for. An empty intersection with nothing counted is
 * neither, and the record says so rather than borrowing the first label.
 *
 * The fourth is M25e's (decision D-128) and is about the other set. A witness
 * outside the validators says the seal is countersigned from outside; it says
 * nothing about who judged the facts under it, and at genesis the answer to
 * that is "the operators the maintainer named, all of them inside one
 * perimeter it disclosed". That is a weaker record than external independent
 * confirmation and the label has to be able to say so, which is why this claim
 * is picked ahead of CLAIM_EXTERNAL rather than beside it.
 *
 * The flag is untouched by any of this: it answers exactly the question
 * morty-synctzn asked, about the witness set, and it goes on answering it.
 */
export const CLAIM_EXTERNAL = "external independent confirmation";
export const CLAIM_SHARED_PERIMETER =
  "confirmation by independent keys under a disclosed shared perimeter";
export const CLAIM_SINGLE_PERIMETER =
  "every validator inside one disclosed perimeter";
export const CLAIM_NONE_COUNTED = "no external countersignature counted yet";

/** What each kind of signature in this record is made over. Data, not policy. */
export const COVERED_OBJECT: Readonly<Record<string, CoveredObjectEntry>> =
  Object.freeze({
    validation: Object.freeze({
      covers: "the entry's record",
      fields: Object.freeze([
        "agent",
        "operator",
        "decision",
        "reason",
        "snapshot_hash",
        "signed_at",
      ]),
      signed_by: "the validator's own agent key",
      note: "One approver record for one entry id, under the kind validation. It says what this operator judged about this entry and nothing about any other.",
    }),
    seal: Object.freeze({
      covers: "a batch of events",
      fields: Object.freeze([
        "seq",
        "first_seq",
        "last_seq",
        "size",
        "root",
        "sealed_at",
        "prev_hash",
        "hash",
      ]),
      signed_by: "nomankind's own sealing agent",
      note: "A contiguous run of event seqs committed to one Merkle root and chained to the seal before it. Self-performed, which is why the two signatures below exist.",
    }),
    witness_countersignature: Object.freeze({
      covers: "a registry head",
      fields: Object.freeze([
        "registry",
        "log",
        "tree_size",
        "root",
        "created_at",
        "registry_sig",
      ]),
      signed_by: "a pinned witness's own key",
      note: "Never the event and never the seal: the witness signs the registry's head, and the seal's evidence — leaf_index, proof, proved_at, consistency_proof — is what proves our memory.seal event is included under it. A countersignature with no such path proves nothing about this record.",
    }),
    anchor: Object.freeze({
      covers: "a day's seal roots",
      fields: Object.freeze(["date", "roots", "hash", "calendar", "receipt"]),
      signed_by: "an external timestamping calendar",
      note: "One UTC day of roots offered to OpenTimestamps, which is what makes the existence proof independent of the identity layer.",
    }),
  });

/**
 * Where each part of this report comes from, named row by row (D-132).
 *
 * The page published two sets and a verdict and said nothing about what they
 * were computed from, which made it an assertion in exactly the place an
 * assertion is worth least. These are the rows, and the addresses they are
 * published at, so `npm run independence -- <mirror>` and a reader with curl
 * recompute the same answer from the same bytes.
 *
 * Data and not policy: every number the rules use is src/policy.ts's, and
 * nothing here is read by any rule. It is a map of the record, kept beside the
 * code that draws it so the two move together.
 */
export const DERIVED_FROM: Readonly<Record<string, DerivedFromEntry>> =
  Object.freeze({
    validator_set: Object.freeze({
      rows: Object.freeze([
        "operator_registered",
        "agent_bound",
        "operator_joined_domain",
        "operator_trusted (the genesis naming)",
      ]),
      published_at: Object.freeze([
        "/operators",
        "/operators/{id}",
        "the mirror's operators.json",
      ]),
      note: "Every registered operator, trusted or not. The rows are the log's own registry events; the directory and the mirror are the same rows indexed.",
    }),
    validator_perimeters: Object.freeze({
      rows: Object.freeze(["operator_trusted.perimeter"]),
      published_at: Object.freeze([
        "/operators",
        "/operators/{id}",
        "the mirror's operators.json",
      ]),
      note: "The perimeter the maintainer disclosed when it named an operator into the trusted pool (decision D-128). Sealed in the naming event, so it is re-derivable from the log and is not a row anybody could edit.",
    }),
    witness_set: Object.freeze({
      rows: Object.freeze(["WITNESS_PIN"]),
      published_at: Object.freeze(["src/policy.ts", "/policy"]),
      note: "A module constant and not a table: the pin is the maintainer's published choice, it costs no query, and a reader checks it against the repository.",
    }),
    counted_and_head: Object.freeze({
      rows: Object.freeze([
        "witnesses",
        "head",
        "leaf_index",
        "proof",
        "proved_at",
        "consistency_proof",
      ]),
      published_at: Object.freeze(["/seals/{seq}", "the mirror's seals.jsonl"]),
      note: "The newest seal's own countersignature rows. A witness is counted when that seal carries its countersignature; the head is the (tree_size, root) it covered, and the evidence beside it is what proves our seal event is included under that head.",
    }),
    intersection: Object.freeze({
      rows: Object.freeze(["agent_bound_to_operator", "handle_is_operator_id"]),
      published_at: Object.freeze(["/operators/{id}", "src/independence.ts"]),
      note: "The two checks, and only those two. A shared owner behind two names is not a row anywhere, so it is not in the intersection and the page says so in words.",
    }),
    claim_and_flag: Object.freeze({
      rows: Object.freeze([
        "intersection",
        "validator_perimeters",
        "witness_set[].counted",
      ]),
      published_at: Object.freeze(["/independence", "src/independence.ts"]),
      note: "By the published rule and nothing else: claimFor picks the claim from the three above, and the flag is true while a pinned witness outside the intersection has a countersignature the newest seal counted.",
    }),
  });

/** What the report is built from: two sets, the bindings, and the newest seal. */
export interface IndependenceInput {
  readonly validators: readonly ValidatorEntry[];
  readonly pin: readonly Readonly<{
    id: number;
    operator: string;
    public_key: string;
    url: string;
  }>[];
  /**
   * The countersignatures the newest seal carries, by the agent that made each
   * and the head it covered. An empty list is "nothing counted yet".
   */
  readonly counted: readonly {
    readonly agent: string;
    readonly head: CountersignedHead | null;
  }[];
  /**
   * The registered operator each witness agent id is bound to, for the agent
   * ids that are bound to one at all. The lookup is the caller's because it is
   * a read of the log; the rule it feeds is here.
   */
  readonly boundOperators: ReadonlyMap<string, string>;
  readonly sealSeq: number | null;
}

/** The 1F916 agent id a pinned public key makes. */
export function witnessAgentId(publicKey: string): string {
  return AGENT_ID_PREFIX + publicKey;
}

/**
 * The two checks that can honestly put a witness in the validator set.
 *
 * The bound key is the real one: the log knows which operator each agent
 * answers for, so a pinned witness whose key is a registered operator's agent
 * is that operator, whatever the directory calls it. The handle comparison is
 * kept beside it and will almost never match — an operator id is a DNS name —
 * but leaving it out would mean the page claimed a comparison it had not made.
 */
function overlap(
  witness: WitnessEntry,
  validators: ReadonlySet<string>,
): OverlapEntry | null {
  if (witness.bound_operator !== null) {
    return {
      witness: witness.operator,
      agent: witness.agent,
      operator: witness.bound_operator,
      matched: "agent_bound_to_operator",
    };
  }
  if (validators.has(witness.operator)) {
    return {
      witness: witness.operator,
      agent: witness.agent,
      operator: witness.operator,
      matched: "handle_is_operator_id",
    };
  }
  return null;
}

/**
 * The perimeters the validator set discloses, each naming its operators.
 *
 * Keyed by the word the maintainer published and never by anything derived
 * from it, so the page groups by the same string the naming event carries. An
 * operator with no perimeter is in no group, which is the ordinary case and is
 * not a group of its own.
 */
export function validatorPerimeters(
  validators: readonly ValidatorEntry[],
): Record<string, string[]> {
  const grouped: Record<string, string[]> = {};
  for (const validator of validators) {
    const perimeter = validator.perimeter;
    if (perimeter === null) continue;
    (grouped[perimeter] ??= []).push(validator.operator);
  }
  return grouped;
}

/**
 * The one perimeter every validator sits inside, or null.
 *
 * Null when the set is empty, when any operator has no perimeter, and when two
 * of them have different ones — three different facts that are the same answer
 * to the only question asked here, which is whether the whole validator set is
 * one disclosed grouping.
 */
export function singleValidatorPerimeter(
  validators: readonly ValidatorEntry[],
): string | null {
  if (validators.length === 0) return null;
  const first = validators[0]!.perimeter;
  if (first === null) return null;
  return validators.every((each) => each.perimeter === first) ? first : null;
}

/**
 * The claim, from the intersection, the flag and the disclosed perimeters.
 *
 * In that order, strongest fact about the record first: a witness that is also
 * an operator, then a validator set that is one disclosed grouping, then a live
 * outside countersignature, then nothing counted at all.
 */
export function claimFor(
  overlaps: number,
  external: boolean,
  singlePerimeter: string | null = null,
): string {
  if (overlaps > 0) return CLAIM_SHARED_PERIMETER;
  if (singlePerimeter !== null) return CLAIM_SINGLE_PERIMETER;
  return external ? CLAIM_EXTERNAL : CLAIM_NONE_COUNTED;
}

/** The report: both sets, what falls between them, and what each signature covers. */
export function independenceReport(
  input: IndependenceInput,
): IndependenceReport {
  const countedBy = new Map(
    input.counted.map((each) => [each.agent, each.head] as const),
  );
  const validators = new Set(input.validators.map((each) => each.operator));

  const witnesses: WitnessEntry[] = input.pin.map((pin) => {
    const agent = witnessAgentId(pin.public_key);
    return {
      id: pin.id,
      operator: pin.operator,
      public_key: pin.public_key,
      agent,
      counted: countedBy.has(agent),
      head: countedBy.get(agent) ?? null,
      bound_operator: input.boundOperators.get(agent) ?? null,
    };
  });

  const intersection: OverlapEntry[] = [];
  const inside = new Set<string>();
  for (const witness of witnesses) {
    const found = overlap(witness, validators);
    if (found === null) continue;
    intersection.push(found);
    inside.add(witness.agent);
  }

  // A live feed outside the set, which is what the flag is about: pinned and
  // silent is an intention, and an intention is not a countersignature.
  const external = witnesses.some(
    (witness) => witness.counted && !inside.has(witness.agent),
  );

  return {
    validator_set: input.validators,
    validator_perimeters: validatorPerimeters(input.validators),
    witness_set: witnesses,
    intersection,
    covered_object: COVERED_OBJECT,
    derived_from: DERIVED_FROM,
    external_witness_outside_validator_and_subject_provider_control: external,
    claim: claimFor(
      intersection.length,
      external,
      singleValidatorPerimeter(input.validators),
    ),
    seal_seq: input.sealSeq,
  };
}
