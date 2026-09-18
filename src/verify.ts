/**
 * The offline verifier: two files and one script.
 *
 * Whitepaper, Goals and non-goals, goal 4: "Tamper-evidence ... anyone can
 * check the proof offline with two files and one script." This module is the
 * check itself. The two files are the entry and the log bundle beside it; the
 * script (a later builder's) does nothing but read them and print what this
 * returns.
 *
 * Pure: no `node:` imports, no wall clock, no I/O. It takes parsed JSON and
 * gives back a report. A malformed file is a diff, never an exception: a
 * verifier is handed files by strangers, so garbage is an answer.
 *
 * Every check runs the checks after it where it still can, so one hand-edited
 * field does not hide a second one. Only a bundle or an entry that leaves
 * nothing to work with stops the run early, and then the report says what was
 * learned before it stopped.
 *
 * Nothing here reimplements the kernel: the chain, the signatures, derivation,
 * the seal and the snapshot rule are all asked of the modules that own them, so
 * the verifier and the writer can never drift apart.
 *
 * The record is free from the seal (decision D-127). Every sealed event is
 * exported with its payload, to everybody, so there is no held-back line here
 * to make an exception for: a bundle is checked whole, always, and the entry
 * file beside it is an entry rather than a promise that one exists.
 */

import { certificateIssuer, verifyCertificate } from "./certificate.js";
import { openAssignment } from "./assign.js";
import { buildTranscriptArtifact, transcriptArtifactHash } from "./artifact.js";
import {
  attestationId,
  deriveAttestation,
  type AttestationStatus,
  type DerivedAttestation,
} from "./attest.js";
import {
  canonicalConfirmationLine,
  carriesBothVerdicts,
  confirmationFingerprint,
  confirmationPayloadOf,
  pinnedConfirmationTrust,
  verifyConfirmationProof,
  type ConfirmationTrust,
} from "./confirm.js";
import { CORE_KEYS, coreVersion, domainOf, extractCore } from "./core.js";
import {
  countedOperatorsFor,
  deriveEntry,
  registeredOperatorsAt,
  trustedOperatorsAt,
} from "./derive.js";
import { disputeExclusions } from "./dispute.js";
import { base64Decode, base64urlDecode } from "./encoding.js";
import { isTranscriptCategory } from "./evidence.js";
import {
  eventHash,
  verifyChain,
  type ApproverRecord,
  type AttestationScorer,
  type Event,
} from "./events.js";
import { canonicalize } from "./hash.js";
import { decodeProof, verifyInclusion } from "./merkle.js";
import { snapshotHash } from "./normalize.js";
import {
  ACCOUNT_BINDING_SUNSET,
  ACCOUNT_BINDING_TIERS,
  authorityHostsFor,
  CONFIRMATION_VENUES,
  COUNTING_BINDING_KINDS,
  DEFAULT_DOMAIN,
  NORM_VERSION,
  PERIMETER_WORD,
  SCHEMA_VERSION,
  voteQuestion,
} from "./policy.js";
import {
  isPerimeterOperator,
  parseCommunityOperatorId,
} from "./registry.js";
import { validateEntry } from "./schema.js";
import {
  sealFor,
  sealHash,
  sealsForEntries,
  verifySeal,
  type Seal,
} from "./seal.js";
import { AGENT_ID_PREFIX, verifyBytes } from "./identity.js";
import { verifyAttestation } from "./registry.js";
import { retiredAgentsAt } from "./rotation.js";
import { verifyEntrySignature } from "./sign.js";
import { checkValidation, type OperatorInfo } from "./validate.js";
import { verifyRecordSignature } from "./records.js";
import { standingAt, tierOf } from "./standing.js";
import { tallyOf, verifyVoteSignature, type Tally } from "./vote.js";

/** An archived capture: the bytes the snapshot hash was taken over, and how they were served. */
export interface Capture {
  content_type: string | null;
  body_base64: string;
}

/** Who the log's agents and operators are, as the verifier is told them. */
export interface Registry {
  /** Agent id -> its operator. */
  agents: Record<string, string>;
  operators: Record<
    string,
    {
      maintainer: boolean;
      provider: boolean;
      /**
       * Every domain the operator is attested in (decision D-071). Absent reads
       * as ai-ecosystem: that is what a registry exported before v0.7 meant, and
       * what the operator's registration attested to.
       */
      domains?: readonly string[];
    }
  >;
}

/** The second file: everything an entry has to be checked against. */
export interface LogBundle {
  /** ISO 8601 date-time: the clock the entry was exported under. */
  as_of: string;
  /** The whole log. Seq order is not required; derivation sorts. */
  events: Event[];
  registry: Registry;
  /** Every seal. Seq order is not required. */
  seals: Seal[];
  /** Captures, keyed by the snapshot hash each claims to produce. */
  captures: Record<string, Capture>;
  /**
   * Whether this bundle is bounded to one entry's seals rather than the whole
   * log (decision D-120).
   *
   * Absent on the bundle `npm run export` has always written, which is why a
   * full bundle is checked exactly as it always was. Present and true on the
   * bundle `--bounded` writes: the entry's own events with an inclusion proof
   * each, the seals those proofs are against and the seal before each of them,
   * the registry, and the captures. What that costs is named rather than
   * assumed -- `not_run` on the report says which checks had no inputs here.
   */
  bounded?: true;
  /**
   * The log's event head at the moment a bounded bundle was taken.
   *
   * A bounded bundle is a window onto a log that goes on without it, so the
   * moment has to be in the file: `as_of` says when it was taken and this says
   * how far the log had got. Null where the log held no events at all.
   */
  head?: number | null;
  /**
   * One inclusion proof per included event, keyed by the event's seq as a
   * decimal string, exactly as `GET /events/{seq}/proof` serves it.
   *
   * The bounded bundle's replacement for the chain walk: a bounded bundle holds
   * a handful of events out of the middle of a log, so seq 0 is not here to
   * walk from and `prev_hash` links nothing that is. What is here instead is
   * each event's own hash and the path from it to the root its seal committed
   * to, which is the same tamper-evidence over a shorter read. An event nothing
   * has sealed yet carries no proof and is not here.
   */
  proofs?: Record<string, BundleProof>;
}

/**
 * One event's place under its seal: which seal covers it, and the path from its
 * hash to that seal's root.
 *
 * The shape `GET /events/{seq}/proof` already serves, minus the fields the
 * bundle carries elsewhere -- the root and the witnesses are on the seal, so
 * copying them here would be a second place for them to disagree.
 */
export interface BundleProof {
  /** The seq of the seal whose root the proof is against. */
  seal_seq: number;
  /** The encoded Merkle path (src/merkle.ts, `encodeProof`). */
  inclusion_proof: string;
}

/** An entry's checks, in the order they run. */
export type EntryCheck =
  | "bundle"
  | "schema"
  | "chain"
  | "proof"
  | "signature"
  | "core"
  | "records"
  | "community_binding"
  | "key_rotation"
  | "exclusions"
  | "derived"
  | "snapshot"
  | "seals"
  | "seal";

/**
 * An attestation's checks, in the order they run (`verifyAttestations`).
 *
 * Separate names rather than a reuse of the entry's, because an attestation is
 * not an entry: it has no core, no seal of its own and no snapshot, and a
 * report that said `records` for a score signature would send a reader looking
 * for an approver that does not exist.
 */
export type AttestationCheck =
  | "attestation_id"
  | "attestation_signature"
  | "attestation_scorer"
  | "attestation_hashes"
  | "attestation_derived";

/**
 * A vote's checks, in the order they run (`verifyVotes`, decision D-130 item 4).
 *
 * Three, because there are three ways a vote can be wrong that the log itself
 * can settle: it was not signed by the key it names, it was cast by an operator
 * that was not senior at the position it was sealed at, and it is a second vote
 * by an operator or by a perimeter that had already voted. Everything else
 * about a vote — which question, which option — is either in the signed bytes
 * or is not counted by the fold.
 */
export type VoteCheck =
  | "vote_signature"
  | "vote_eligibility"
  | "vote_duplicate";

/** Every check any of the verifiers can name. */
export type Check = EntryCheck | AttestationCheck | VoteCheck;

/**
 * A check a bundle carried no inputs for, named rather than quietly skipped.
 *
 * `attestations` is the whole of `verifyAttestations` and not one of its five
 * steps: an attestation is not entry-scoped (src/events.ts), so a bundle bounded
 * to one entry holds none of its events and there is nothing to run any step
 * against. Naming the five would say five things where the bundle says one.
 */
export type SkippedCheck = EntryCheck | "attestations";

/**
 * What a bounded bundle carries no inputs for (decision D-120), in CHECKS
 * order with the attestations last.
 *
 * A list and not a computation: these four are not run because of what a bounded
 * bundle IS, not because of anything that happened to be missing from one, and
 * a reader comparing two reports should see the same four words every time.
 * Every one of them is a fold over the whole log — the chain from seq 0, the
 * exclusions replayed against who was registered and assigned at each decision's
 * position, the derived view refolded out of every event, and the attestations,
 * which are about a model rather than about any one entry.
 *
 * The record signatures are not among them, and that is the door's doing:
 * `GET /entries/{id}/events` answers one entry's own events, so a bounded bundle
 * carries the decisions it was signed by and every signature on them is checked
 * exactly as it is on a full bundle (decision D-120).
 */
const BOUNDED_NOT_RUN: readonly SkippedCheck[] = Object.freeze([
  "chain",
  // The community bindings (decision D-138) are the fifth: a validation's own
  // proof travels on its event, but the registration that made its author an
  // operator and the domain it attested in are registry events, which a bundle
  // bounded to one entry does not carry. Half a check reported as a whole one
  // would be worse than a named absence.
  "community_binding",
  // The rotations (D-095, D-097 item 3, D-140 item 5) are the sixth, and for
  // exactly the same reason: a `key_rotated` is a registry event, and which
  // keys had been retired by a given position cannot be read off one entry's
  // own events.
  "key_rotation",
  "exclusions",
  "derived",
  "attestations",
]);

/** A full bundle skips nothing, which is what makes the two reports comparable. */
const NOTHING_SKIPPED: readonly SkippedCheck[] = Object.freeze([]);

/** Every entry check, in run order. */
export const CHECKS: readonly EntryCheck[] = Object.freeze([
  "bundle",
  "schema",
  "chain",
  "proof",
  "signature",
  "core",
  "records",
  "community_binding",
  "key_rotation",
  "exclusions",
  "derived",
  "snapshot",
  "seals",
  "seal",
] as const);

/**
 * The six ways an account-bound line can be wrong (decisions D-142, D-144).
 *
 * Named here rather than written inline where they are raised, because each one
 * is a different sentence to the reader holding the bundle and a report that
 * blurred them would send that reader looking for the wrong thing:
 *
 * `account_binding_proof_invalid` — the captures do not check out: a hash the
 * binding names is not in the bundle, or the bytes under it are not the comment
 * or the profile the binding says they are.
 * `account_binding_out_of_scope` — the entry's tier is not one the rung may
 * count toward (`ACCOUNT_BINDING_TIERS`, `stated` alone).
 * `account_binding_too_new` — the account was created at or after the entry was
 * submitted, so it was made for this entry as far as the record can tell.
 * `account_binding_after_sunset` — the promoting decision was signed at or
 * after `ACCOUNT_BINDING_SUNSET`, where the rung no longer forms a consensus.
 * `perimeter_line_counted` — a line from one of nomankind's own accounts
 * (`PERIMETER_ACCOUNTS`) was counted into a consensus. Sealing and showing such
 * a line is correct; counting it is the record verifying itself.
 * `confirmation_form_counted` — the comment the counted line was read from
 * carries BOTH of that entry's lines, approve and reject (decision D-144). A
 * text holding both is the published ask, or a quotation of it, and not
 * anybody's statement about the entry; counting it is the record reading its
 * own words back as an answer.
 *
 * All six are raised under the existing `community_binding` check: an account
 * binding is a community binding, and a seventh check name would say a reader
 * has two things to look at where it has one. D-142 and D-144: logic in the
 * kernel pass.
 */
export const ACCOUNT_BINDING_REFUSALS = Object.freeze({
  proof_invalid: "account_binding_proof_invalid",
  out_of_scope: "account_binding_out_of_scope",
  too_new: "account_binding_too_new",
  after_sunset: "account_binding_after_sunset",
  perimeter_counted: "perimeter_line_counted",
  form_counted: "confirmation_form_counted",
} as const);

export type AccountBindingRefusal =
  (typeof ACCOUNT_BINDING_REFUSALS)[keyof typeof ACCOUNT_BINDING_REFUSALS];

/** Every attestation check, in run order. */
export const ATTESTATION_CHECKS: readonly AttestationCheck[] = Object.freeze([
  "attestation_id",
  "attestation_signature",
  "attestation_scorer",
  "attestation_hashes",
  "attestation_derived",
] as const);

/**
 * One named difference between what the entry says and what the log proves.
 *
 * `field` is a JSON-pointer-like path into the entry or the bundle, `reason` a
 * short snake_case word, and `expected` / `actual` are small and
 * JSON-serializable — a hash, a status, a count — never a whole object.
 */
export interface Diff {
  check: Check;
  field: string;
  expected: unknown;
  actual: unknown;
  reason: string;
}

/** The verdict: clean, or the named diffs that make it dirty. */
export interface VerifyReport {
  ok: boolean;
  entry_id: string | null;
  diffs: Diff[];
  /**
   * Whether the bundle was bounded to this entry's seals (decision D-120).
   *
   * An `ok` over a bounded bundle is a narrower sentence than an `ok` over the
   * whole log, and a reader is owed the difference rather than left to infer
   * it. False for every bundle `npm run export` wrote before `--bounded`
   * existed and for every one it writes without it.
   */
  bounded: boolean;
  /**
   * The checks this bundle held no inputs for, in CHECKS order.
   *
   * Empty for a full bundle, which is what makes the two verdicts comparable:
   * a report with nothing here checked everything the verifier knows how to
   * check. A bounded bundle names what it cost — the chain cannot be walked
   * from a seq 0 that is not here, the exclusions cannot be replayed against a
   * registry history that is not here, the derived view cannot be refolded out
   * of events that are not here, and there are no attestation events to read.
   */
  not_run: readonly SkippedCheck[];
}

/**
 * Whether one edit to the core would account for the whole report.
 *
 * A hand-edited content field fails several checks at once and they are one
 * fault: the signature is over the core, so changing a field of it breaks the
 * signature, and the same change is a mismatch against what the log sealed —
 * the core itself for a core field, the snapshot for the captured source. (The
 * derived view is recomputed from the core, so it usually differs too; it is
 * not what this is decided on, because a derived difference alone is a question
 * about the log.) A reader who has not read src/verify.ts counts the lines and
 * goes looking for that many causes.
 *
 * So the checks stay exactly as they are — each one really did fail, and a
 * report that hid two of them would be a report that decided which one mattered
 * — and the caller is given one sentence to print beside them. True only when
 * both halves are there: a bad signature with no mismatch behind it is a key
 * question, and a mismatch with a good signature is a log question, and neither
 * is the edit this names.
 */
export function oneEditExplains(report: VerifyReport): boolean {
  const signature = report.diffs.some(
    (diff) => diff.check === "signature" && diff.reason === "bad_signature",
  );
  const content = report.diffs.some(
    (diff) => diff.check === "core" || diff.check === "snapshot",
  );
  return signature && content;
}

/** How much of a canonical form a diff may carry. */
const BRIEF_LIMIT = 120;

type Json = Record<string, unknown>;

function isRecord(value: unknown): value is Json {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/** The canonical form, or a sentinel for a value that has none (undefined). */
function safeCanonical(value: unknown): string {
  try {
    return canonicalize(value);
  } catch {
    return "<undefined>";
  }
}

function truncate(text: string): string {
  return text.length <= BRIEF_LIMIT ? text : `${text.slice(0, BRIEF_LIMIT)}...`;
}

/** A scalar as itself; anything else as its canonical form, truncated. */
function briefValue(value: unknown): unknown {
  if (value === undefined) return null;
  if (
    value === null ||
    typeof value === "string" ||
    typeof value === "number" ||
    typeof value === "boolean"
  ) {
    return value;
  }
  return truncate(safeCanonical(value));
}

/** As briefValue, but an array shows its length: a diff names the count, not the contents. */
function briefDerived(value: unknown): unknown {
  if (Array.isArray(value)) return value.length;
  return briefValue(value);
}

class Report {
  readonly diffs: Diff[] = [];

  add(
    check: Check,
    field: string,
    reason: string,
    expected: unknown = null,
    actual: unknown = null,
  ): void {
    this.diffs.push({ check, field, expected, actual, reason });
  }

  finish(
    entryId: string | null,
    bounded = false,
    notRun: readonly SkippedCheck[] = [],
  ): VerifyReport {
    return {
      ok: this.diffs.length === 0,
      entry_id: entryId,
      diffs: this.diffs,
      bounded,
      not_run: notRun,
    };
  }
}

/**
 * Every field the verifier reads off an event before anything is replayed.
 *
 * The checks below index into events by hand — a seq, a type, a payload — so an
 * element that is not an event at all has to be caught here, at the door.
 * Nothing further in the run touches an event that did not pass this.
 */
function isEventShape(value: unknown): boolean {
  if (!isRecord(value)) return false;
  return (
    Number.isInteger(value["seq"]) &&
    typeof value["type"] === "string" &&
    (typeof value["entry_id"] === "string" || value["entry_id"] === null) &&
    (typeof value["prev_hash"] === "string" || value["prev_hash"] === null) &&
    typeof value["hash"] === "string" &&
    isRecord(value["payload"])
  );
}

/** The same, for a seal: every field the seal checks and the entry seal read. */
function isSealShape(value: unknown): boolean {
  if (!isRecord(value)) return false;
  return (
    Number.isInteger(value["seq"]) &&
    Number.isInteger(value["first_seq"]) &&
    Number.isInteger(value["last_seq"]) &&
    Number.isInteger(value["size"]) &&
    typeof value["root"] === "string" &&
    typeof value["sealed_at"] === "string" &&
    (typeof value["prev_hash"] === "string" || value["prev_hash"] === null) &&
    typeof value["hash"] === "string" &&
    Array.isArray(value["witnesses"])
  );
}

/** What a malformed element is, in one word a diff can carry. */
function shapeOf(value: unknown): string {
  if (value === null) return "null";
  if (Array.isArray(value)) return "array";
  return typeof value;
}

/**
 * Read the bundle's five keys, reporting the ones that are absent or the wrong
 * shape. Returns null when what is left cannot be verified against at all — no
 * events, no clock to derive under, or an element that is not the record the
 * rest of the run reads fields off.
 */
function readBundle(value: unknown, report: Report): LogBundle | null {
  if (!isRecord(value)) {
    report.add("bundle", "/", "shape", "object", typeof value);
    return null;
  }

  const asOf = value["as_of"];
  let clockOk = true;
  if (asOf === undefined) {
    report.add("bundle", "/as_of", "missing");
    clockOk = false;
  } else if (typeof asOf !== "string" || Number.isNaN(Date.parse(asOf))) {
    report.add("bundle", "/as_of", "shape", "date-time", briefValue(asOf));
    clockOk = false;
  }

  const events = value["events"];
  let eventsOk = true;
  if (events === undefined) {
    report.add("bundle", "/events", "missing");
    eventsOk = false;
  } else if (!Array.isArray(events)) {
    report.add("bundle", "/events", "shape", "array", typeof events);
    eventsOk = false;
  } else {
    for (let index = 0; index < events.length; index += 1) {
      if (isEventShape(events[index])) continue;
      report.add(
        "bundle",
        `/events/${index}`,
        "shape",
        "event",
        shapeOf(events[index]),
      );
      eventsOk = false;
    }
  }

  const registry = value["registry"];
  let agents: Record<string, string> = {};
  let operators: Registry["operators"] = {};
  if (registry === undefined) {
    report.add("bundle", "/registry", "missing");
  } else if (!isRecord(registry)) {
    report.add("bundle", "/registry", "shape", "object", typeof registry);
  } else {
    if (!isRecord(registry["agents"])) {
      report.add("bundle", "/registry/agents", "shape", "object", null);
    } else {
      agents = registry["agents"] as Record<string, string>;
    }
    if (!isRecord(registry["operators"])) {
      report.add("bundle", "/registry/operators", "shape", "object", null);
    } else {
      operators = registry["operators"] as Registry["operators"];
    }
  }

  const seals = value["seals"];
  let sealList: Seal[] = [];
  let sealsOk = true;
  if (seals === undefined) {
    report.add("bundle", "/seals", "missing");
  } else if (!Array.isArray(seals)) {
    report.add("bundle", "/seals", "shape", "array", typeof seals);
  } else {
    for (let index = 0; index < seals.length; index += 1) {
      if (isSealShape(seals[index])) continue;
      report.add(
        "bundle",
        `/seals/${index}`,
        "shape",
        "seal",
        shapeOf(seals[index]),
      );
      sealsOk = false;
    }
    sealList = seals as Seal[];
  }

  const captures = value["captures"];
  let captureMap: Record<string, Capture> = {};
  if (captures === undefined) {
    report.add("bundle", "/captures", "missing");
  } else if (!isRecord(captures)) {
    report.add("bundle", "/captures", "shape", "object", typeof captures);
  } else {
    captureMap = captures as Record<string, Capture>;
  }

  // The bounded marker and what it brings with it (decision D-120). Read last
  // and read strictly: a bundle that says it is bounded is checked by a
  // different set of rules, so `bounded: true` has to be the value the exporter
  // writes and not any truthy thing, and the proofs it is checked through have
  // to be the shape the proof route serves.
  const boundedMark = value["bounded"];
  let bounded = false;
  if (boundedMark !== undefined) {
    if (boundedMark !== true) {
      report.add("bundle", "/bounded", "shape", true, briefValue(boundedMark));
    } else {
      bounded = true;
    }
  }

  const head = value["head"];
  if (head !== undefined && head !== null && !Number.isInteger(head)) {
    report.add("bundle", "/head", "shape", "integer", shapeOf(head));
  }

  const proofs = value["proofs"];
  let proofMap: Record<string, BundleProof> = {};
  if (proofs !== undefined) {
    if (!isRecord(proofs)) {
      report.add("bundle", "/proofs", "shape", "object", shapeOf(proofs));
    } else {
      for (const [seq, proof] of Object.entries(proofs)) {
        if (isBundleProofShape(proof)) continue;
        report.add("bundle", `/proofs/${seq}`, "shape", "proof", shapeOf(proof));
      }
      proofMap = proofs as Record<string, BundleProof>;
    }
  }

  if (!clockOk || !eventsOk || !sealsOk) return null;

  return {
    as_of: asOf as string,
    events: events as Event[],
    registry: { agents, operators },
    seals: sealList,
    captures: captureMap,
    ...(bounded ? { bounded: true as const } : {}),
    ...(head === undefined ? {} : { head: head as number | null }),
    ...(proofs === undefined ? {} : { proofs: proofMap }),
  };
}

/** The same door as `isEventShape` and `isSealShape`, for one inclusion proof. */
function isBundleProofShape(value: unknown): boolean {
  if (!isRecord(value)) return false;
  return (
    Number.isInteger(value["seal_seq"]) &&
    typeof value["inclusion_proof"] === "string"
  );
}

/** Events in seq order, without mutating the bundle's array. */
function inSeqOrder(events: readonly Event[]): Event[] {
  return [...events].sort((left, right) => left.seq - right.seq);
}

/** The entry's submission event: the first, in seq order, whose sealed core carries the id. */
function submissionOf(
  events: readonly Event[],
  entryId: string,
): Event<"entry_submitted"> | null {
  for (const event of inSeqOrder(events)) {
    if (event?.type !== "entry_submitted") continue;
    const submitted = event as Event<"entry_submitted">;
    if (!isRecord(submitted.payload)) continue;
    const core = (submitted.payload as Json)["core"];
    if (!isRecord(core) || core["id"] !== entryId) continue;
    return submitted;
  }
  return null;
}

/** The entry's validation events, in seq order. */
function validationsOf(
  events: readonly Event[],
  entryId: string,
): Event<"validation">[] {
  return inSeqOrder(events).filter(
    (event) => event?.type === "validation" && event.entry_id === entryId,
  ) as Event<"validation">[];
}

/**
 * c. The hash chain, exactly as src/events.ts verifies it.
 *
 * The kernel's own `verifyChain` and nothing else: every event the bundle
 * carries carries its payload (D-127), so seq runs from 0 without a gap, every
 * prev_hash is the hash before it, and every hash recomputes.
 */
async function checkChain(
  bundle: LogBundle,
  report: Report,
): Promise<void> {
  let result;
  try {
    result = await verifyChain(bundle.events);
  } catch {
    report.add("chain", "/events", "unverifiable", null, bundle.events.length);
    return;
  }
  if (!result.ok) {
    report.add("chain", `/events/${result.seq}`, result.reason);
  }
}

/**
 * c (bounded). The same tamper-evidence over a bundle that has no seq 0 to walk
 * from: every event's own hash, and the path from it to the root its seal
 * committed to (decision D-120).
 *
 * The chain and this prove the same thing by different routes. A full bundle
 * holds every event, so an edited one is caught by `prev_hash` no longer
 * linking and by its hash no longer recomputing. A bounded bundle holds a
 * handful out of the middle, where `prev_hash` points at events that are not
 * here — so what is checked is the hash itself, and then the Merkle path from
 * that hash to a root the seal chain already committed to, which is what makes
 * an edit here as loud as an edit there.
 *
 * An event no
 * seal in the bundle covers carries no proof and is not missing one: it is an
 * event nothing had sealed when the bundle was taken, and a later export of the
 * same entry proves it. An event a seal here DOES cover and has no proof for is
 * a missing proof and is named.
 */
async function checkProofs(
  bundle: LogBundle,
  seals: readonly Seal[],
  report: Report,
): Promise<void> {
  const proofs = bundle.proofs ?? {};
  const bySeq = new Map<number, Seal>();
  for (const seal of seals) bySeq.set(seal.seq, seal);

  for (const event of inSeqOrder(bundle.events)) {
    const field = `/events/${event.seq}`;
    {
      const { hash, ...fields } = event;
      let recomputed: string;
      try {
        recomputed = await eventHash(fields);
      } catch {
        report.add("proof", field, "unverifiable");
        continue;
      }
      if (recomputed !== hash) {
        report.add("proof", field, "bad_hash");
        continue;
      }
    }

    const proof = proofs[String(event.seq)];
    if (proof === undefined) {
      // Only a seal the bundle carries can make a missing proof a fault: a seal
      // it does not carry is the `seal_missing` below, and no seal at all is an
      // unsealed event.
      if (sealFor(seals, event.seq) !== null) {
        report.add("proof", field, "proof_missing");
      }
      continue;
    }

    const covering = bySeq.get(proof.seal_seq);
    if (covering === undefined) {
      report.add("proof", field, "seal_missing", proof.seal_seq, null);
      continue;
    }

    if (event.seq < covering.first_seq || event.seq > covering.last_seq) {
      report.add("proof", field, "wrong_seal", proof.seal_seq, event.seq);
      continue;
    }
    const decoded = decodeProof(proof.inclusion_proof);
    if (decoded === null) {
      report.add("proof", field, "malformed");
      continue;
    }
    let included = false;
    try {
      included = await verifyInclusion(event.hash, decoded, covering.root);
    } catch {
      included = false;
    }
    if (!included) {
      report.add("proof", field, "bad_proof", covering.root, null);
    }
  }
}

/**
 * h (bounded). The seals a bounded bundle carries: each one's own hash, and the
 * link to the seal before it where that seal is here too.
 *
 * `verifySeal` cannot run here and must not: it rebuilds the batch's root out
 * of the batch's leaves, and a bounded bundle holds a few of them on purpose,
 * so an honest seal would be called broken. What can still be asked of a seal
 * on its own is asked — the hash commits to the range, the size and the link
 * (src/seal.ts, `sealHash`), so a seal whose range was widened to swallow a
 * forged event no longer hashes to its own name — and the link is checked
 * against the seal before it, which is what the export brings along.
 *
 * The predecessor is required of the seals that cover this bundle's events and
 * of no others. A seal is here for one of two reasons: because an event's proof
 * is against its root, or because it is the seal before one of those — and
 * asking the second kind for a predecessor of its own would walk the chain back
 * to seq 0, which is the walk a bounded bundle exists not to carry.
 */
async function checkSealLinks(
  bundle: LogBundle,
  covering: ReadonlySet<number>,
  report: Report,
): Promise<Seal[]> {
  const ordered = [...bundle.seals].sort(
    (left, right) => (left?.seq ?? 0) - (right?.seq ?? 0),
  );
  const bySeq = new Map<number, Seal>();
  for (const seal of ordered) bySeq.set(seal.seq, seal);

  for (const seal of ordered) {
    const field = `/seals/${seal.seq}`;
    if (seal.size !== seal.last_seq - seal.first_seq + 1) {
      report.add("seals", field, "bad_size", seal.last_seq - seal.first_seq + 1, seal.size);
      continue;
    }
    const { hash, witnesses: _witnesses, registry: _registry, ...fields } = seal;
    let recomputed: string;
    try {
      recomputed = await sealHash(fields);
    } catch {
      report.add("seals", field, "unverifiable");
      continue;
    }
    if (recomputed !== hash) {
      report.add("seals", field, "bad_seal_hash");
      continue;
    }
    const previous = seal.seq === 0 ? null : bySeq.get(seal.seq - 1) ?? null;
    if (seal.seq === 0) {
      if (seal.prev_hash !== null) {
        report.add("seals", field, "bad_seal_link", null, briefValue(seal.prev_hash));
      }
      continue;
    }
    // The predecessor is the one the export was asked to bring along; a bundle
    // that dropped it is a bundle missing a seal, and is named as one rather
    // than passing quietly.
    if (previous === null) {
      if (covering.has(seal.seq)) {
        report.add("seals", field, "seal_missing", seal.seq - 1, null);
      }
      continue;
    }
    if (seal.prev_hash !== previous.hash) {
      report.add("seals", field, "bad_seal_link", briefValue(previous.hash), briefValue(seal.prev_hash));
    }
  }
  return ordered;
}

/** e. The signed core, key by key, against the core the log sealed. */
function checkCore(entry: Json, logCore: Json, report: Report): void {
  let entryCore: Record<string, unknown>;
  try {
    entryCore = extractCore(entry) as unknown as Record<string, unknown>;
  } catch {
    report.add("core", "/", "missing");
    return;
  }
  for (const key of CORE_KEYS) {
    const fromLog = logCore[key];
    const fromEntry = entryCore[key];
    if (safeCanonical(fromLog) === safeCanonical(fromEntry)) continue;
    report.add(
      "core",
      `/${key}`,
      "mismatch",
      briefValue(fromLog),
      briefValue(fromEntry),
    );
  }
}

/** f. Every record signature on this entry, against the key in the record's own agent id. */
async function checkRecords(
  bundle: LogBundle,
  entryId: string,
  trust: ConfirmationTrust,
  report: Report,
): Promise<void> {
  for (const event of inSeqOrder(bundle.events)) {
    // A public confirmation carries no record and no record signature. What a
    // *counted* one carries is the proof that the confirmer's own key sealed
    // this line's fingerprint into the founding registry's log, under a head
    // the pinned witnesses countersigned (decision D-136). So it is checked
    // here, beside the signatures, by the same rule the door applied before it
    // sealed it, and in three parts:
    //
    // The fingerprint is recomputed from the line's own fields — the entry, the
    // verdict, the check — and must be the one the event carries. A proof of a
    // seal of some other sentence is not a proof of this one.
    //
    // A counted event's proof must verify. A line the reader cannot recheck is
    // a line they must not take as outside confirmation of anything, whatever
    // the log says about it.
    //
    // An uncounted event is valid with no proof at all, and only with none: it
    // is an account statement, the board's word for who typed it, and it clears
    // nothing. Evidence hanging off a statement that claims not to count would
    // be evidence nothing checks, so it is refused rather than ignored.
    if ((event?.type as string) === "public_confirmation") {
      const confirmation = confirmationPayloadOf(event);
      if (confirmation === null) {
        report.add("records", `/events/${event.seq}`, "confirmation_proof_invalid");
        continue;
      }
      if (event.entry_id !== entryId && confirmation.entry_id !== entryId) {
        continue;
      }

      const expected = await confirmationFingerprint(confirmation);
      const wrongFingerprint = confirmation.fingerprint !== expected;
      // Bound to the handle that spoke and to the line it spoke about, both
      // read off this event: a valid proof of some other leaf in the
      // registry's log — another citizen's seal, or a seal of another line —
      // is a proof of something else and is refused here.
      const proved = confirmation.counted
        ? await verifyConfirmationProof(confirmation.registry_proof, trust, {
            handle: confirmation.handle,
            fingerprint: expected,
          })
        : confirmation.registry_proof === null;
      if (wrongFingerprint || !proved) {
        report.add(
          "records",
          `/events/${event.seq}`,
          "confirmation_proof_invalid",
        );
      }
      continue;
    }
    if (event?.type !== "validation" && event?.type !== "reconfirmation") {
      continue;
    }
    if (event.entry_id !== entryId) continue;
    const payload = isRecord(event.payload) ? (event.payload as Json) : {};
    const ok = await verifyRecordSignature(
      entryId,
      event.type,
      payload["record"],
      payload["signature"] as string,
    );
    if (!ok) {
      report.add("records", `/events/${event.seq}`, "bad_signature");
    }
  }
}

/**
 * g (community_binding). Every community validation of this entry, rechecked
 * from the bundle alone (decision D-138 item 5).
 *
 * "Verifiable by anyone" is the whole of this decision's cost: a key bound to
 * an account on an agent community is a validator here, so a reader has to be
 * able to check the binding for themselves, years later, offline, with no
 * account anywhere. Four things are checked for each validation, and each of
 * them is a way the claim could be false:
 *
 * The fingerprint is recomputed from the line's own fields — the entry, the
 * decision, the check and the attestation token — and must be the one the event
 * carries. The token is inside the preimage, so a validation cannot be made out
 * of a confirmation that never attested, or the other way round.
 *
 * The binding proof holds. A `registry` binding is judged by exactly the rule a
 * public confirmation's proof is judged by (src/confirm.ts): the leaf is this
 * handle's `memory.seal` of this fingerprint, it is in the pinned registry's
 * log, the registry signed the head and the pinned witnesses countersigned it.
 * A `profile` binding is the agent's own Ed25519 signature over the canonical
 * line's bytes, by the key the profile published — and the capture of that
 * profile has to be in the bundle, under the hash the binding names, with the
 * key in its bytes. Neither is anybody's assertion.
 *
 * The author was an operator before it validated: a
 * `community_operator_registered` event for the same operator, naming the same
 * agent and the same kind of binding, at a position before this validation.
 *
 * And it was attested in this entry's domain, by its registration or by a later
 * join. `operator_not_in_domain` is the rule (D-071); this is the offline half
 * of it.
 */
async function checkCommunityBindings(
  bundle: LogBundle,
  entryId: string,
  entryDomain: string,
  /**
   * The entry's own signed core, for the two facts the account rung is judged
   * against (decision D-142 item 3): the tier it claims, and the instant it was
   * submitted. The core and not the stored entry, because both are fields the
   * author signed — a rule read off a field nobody signed would be a rule an
   * edit could switch off.
   */
  entryCore: Json,
  trust: ConfirmationTrust,
  report: Report,
): Promise<void> {
  const claimedTier = entryCore["evidence_tier"];
  const tierInScope =
    typeof claimedTier === "string" &&
    (ACCOUNT_BINDING_TIERS as readonly string[]).includes(claimedTier);
  const submittedAt = entryCore["submitted_at"];
  /**
   * The operators this entry's consensus counted, off the bundle's own fold
   * (decision D-142, the review of #105).
   *
   * Every rule below that is about a COUNTED line asks this first, because the
   * rules are about counting. A line the fold did not count is a line that
   * moved nothing — an account statement, sealed and shown — and judging it by
   * the rules for counted lines would refuse a bundle for holding a comment
   * that changed nothing, which is not a fault a clone can have.
   *
   * It is the same fold derivation runs, so the verifier and the record cannot
   * disagree about which lines were in the room.
   */
  const counted = new Set(countedOperatorsFor(bundle.events, entryId));
  /**
   * When this entry's consensus closed, recomputed rather than read: the
   * promoting decision's own instant, which is where the sunset is asked
   * (D-142 item 4). Null while the entry has verified nothing, and then there
   * is no promoting decision for the sunset to be read at.
   */
  const promotedAt = promotingInstantOf(bundle, entryId);
  const ordered = inSeqOrder(bundle.events);
  for (const event of ordered) {
    if ((event?.type as string) !== "community_validation") continue;
    const payload = isRecord(event.payload) ? (event.payload as Json) : {};
    const target = payload["entry_id"];
    if (event.entry_id !== entryId && target !== entryId) continue;
    const field = `/events/${event.seq}`;

    // Both halves have to name this entry. A `community_validation` carries the
    // id twice — the envelope's scope and the payload's own — and an event
    // whose halves disagree is an event about two entries at once: derivation
    // counts it for neither (src/derive.ts) and the verifier says so rather
    // than checking whichever half it happened to read first.
    if (event.entry_id !== entryId || target !== entryId) {
      report.add(
        "community_binding",
        field,
        "community_binding_invalid",
        briefValue(entryId),
        briefValue(target),
      );
      continue;
    }

    const operator = payload["operator"];
    const handle = payload["handle"];
    const agent = payload["agent"];
    const decision = payload["decision"];
    const version = payload["attestation_version"];
    const check = payload["check"];
    if (
      typeof operator !== "string" ||
      typeof handle !== "string" ||
      typeof agent !== "string" ||
      typeof version !== "string" ||
      (decision !== "approve" && decision !== "reject") ||
      !isRecord(check)
    ) {
      report.add("community_binding", field, "community_binding_invalid");
      continue;
    }

    const line: Parameters<typeof canonicalConfirmationLine>[0] = {
      entry_id: entryId,
      verdict: decision,
      check: check as unknown as Parameters<
        typeof canonicalConfirmationLine
      >[0]["check"],
      attestation_version: version,
    };
    const expected = await confirmationFingerprint(line);
    if (payload["fingerprint"] !== expected) {
      report.add(
        "community_binding",
        field,
        "community_binding_invalid",
        briefValue(expected),
        briefValue(payload["fingerprint"]),
      );
      continue;
    }

    const proof = payload["binding_proof"];

    // The registration comes first, because it is what the proof has to be a
    // proof OF. Registered before it validated, under the same agent and the
    // same kind of binding: a validation whose registration the log does not
    // hold is a validation by nobody, whatever its own proof verifies.
    let registration: Json | null = null;
    // The key and the binding the operator is judged by AT THIS POSITION: the
    // registration's, or the newest rotation's where the operator's key has
    // followed its profile (D-140 item 5). The operator is the fixed point and
    // the key is not — which is the whole of what a rotation says — so a
    // validation after one is judged by the key the log moved to, and every
    // validation before it is still judged by the key it was made under.
    let boundAgent: string | null = null;
    let boundBinding: Json | null = null;
    for (const earlier of ordered) {
      if (earlier.seq >= event.seq) break;
      const kind = earlier?.type as string;
      if (kind === "community_operator_registered") {
        const fields = isRecord(earlier.payload)
          ? (earlier.payload as Json)
          : {};
        if (fields["operator"] !== operator) continue;
        const binding = fields["binding"];
        if (!isRecord(binding)) continue;
        registration = fields;
        boundAgent = typeof fields["agent"] === "string" ? fields["agent"] : null;
        boundBinding = binding;
        continue;
      }
      // The upgrade off the account rung (decision D-142), folded here for the
      // reason the rotation below is: what a line is judged by is the binding
      // the log held for its operator AT ITS OWN POSITION, and an account that
      // published a key after this line was written did not publish it before.
      if (kind === "community_operator_bound") {
        const fields = isRecord(earlier.payload)
          ? (earlier.payload as Json)
          : {};
        if (fields["operator"] !== operator) continue;
        const binding = fields["binding"];
        if (!isRecord(binding)) continue;
        if (!isKeyBinding(binding)) continue;
        boundAgent =
          typeof fields["agent"] === "string" ? fields["agent"] : null;
        boundBinding = binding;
        continue;
      }
      if (kind !== "key_rotated") continue;
      const fields = isRecord(earlier.payload) ? (earlier.payload as Json) : {};
      if (fields["operator"] !== operator) continue;
      const binding = fields["binding"];
      // A domain operator's rotation carries no binding and says nothing about
      // a community operator; an event about another kind of operator is not
      // this one's to read.
      if (!isRecord(binding)) continue;
      boundAgent =
        typeof fields["new_agent"] === "string" ? fields["new_agent"] : null;
      boundBinding = binding;
    }
    // Registered before it validated, under the key the log holds for it at
    // this position and the same kind of binding: a validation whose
    // registration the log does not hold is a validation by nobody, whatever
    // its own proof verifies.
    if (
      registration === null ||
      boundBinding === null ||
      boundAgent !== agent ||
      !isRecord(proof) ||
      boundBinding["kind"] !== proof["kind"]
    ) {
      report.add("community_binding", field, "community_operator_unregistered");
      continue;
    }
    const registered = boundBinding;

    // Nomankind's own accounts (decision D-142). A line from one of them is
    // sealed, shown, and counted toward nothing — and the fault this names is
    // the last of those failing: a perimeter operator among the operators the
    // consensus counted.
    //
    // Only among the counted ones. A perimeter line sitting uncounted beside a
    // consensus is the rule working, and every such line sealed before D-142
    // carries no perimeter word because the field did not exist — so a check
    // on the word alone would fail every published mirror for rows that are
    // exactly as they should be (the review of #105). What the word is for is
    // the disclosure on the page; what this is for is the counting.
    //
    // With this build's fold the set can never hold one, because the fold
    // refuses a perimeter operator before it reads the rung. That is the point:
    // this is the invariant stated where a reader can see it, and it fires
    // against a fork whose fold lost it. A record that really did verify an
    // entry on its own account fails the `derived` check beside this one, on
    // the status and the verified_at it cannot reproduce.
    if (isPerimeterOperator(operator) && counted.has(operator)) {
      report.add(
        "community_binding",
        field,
        ACCOUNT_BINDING_REFUSALS.perimeter_counted,
        briefValue(PERIMETER_WORD),
        briefValue(payload["perimeter"]),
      );
      continue;
    }

    // The account rung. The captures are checked on every line that stands on
    // it — they are what the rung IS, and a binding nobody can recheck is a
    // fault whatever the line went on to do — and the three scope rules are
    // checked only on the lines the consensus counted, because every one of
    // them is a rule about counting. An out-of-scope line the fold left
    // uncounted is the rules working, not a clone somebody edited (the review
    // of #105); the door will stop sealing those at ingestion
    // (`communityLineDisposition`), and a mirror written before it did is not
    // wrong about anything.
    if (registered["kind"] === "account") {
      if (
        !(await accountCapturesHold(
          bundle,
          registered,
          proof,
          typeof payload["venue"] === "string"
            ? (payload["venue"] as string)
            : "",
          handle,
          entryId,
        ))
      ) {
        report.add(
          "community_binding",
          field,
          ACCOUNT_BINDING_REFUSALS.proof_invalid,
        );
        continue;
      }
      if (counted.has(operator)) {
        // The form (decision D-144). The comment those captures hold is the
        // evidence the rung rests on, so a reader can ask of it the one
        // question the door now asks before it takes anything: does this text
        // carry BOTH of this entry's lines? A text that does is the ask this
        // record posts on every batch thread, or a quotation of it, and nobody
        // approves and rejects the same fact in the same breath — so a
        // consensus that counted it counted the record's own words.
        //
        // Scoped exactly as `perimeter_line_counted` above is, and for the same
        // reason (the review of #105). A line the fold left uncounted moved
        // nothing: production's own seq 16 to 35 are lines the door read off
        // the ask before this rule existed, sealed at the perimeter and counted
        // toward nothing, and a check that fired on them would refuse a mirror
        // for holding comments that changed nothing. What names the fault is
        // the counting.
        //
        // Read off the capture and not off the sealed payload, because the
        // payload holds one line's verdict and the fault is what the COMMENT
        // held. The bytes are the ones `accountCapturesHold` just re-hashed, so
        // this asks nothing the bundle has not already proved — and the ONE
        // comment inside them is found by the id this validation sealed, never
        // the capture whole, because two of the three venues archive the whole
        // thread and a batch thread's own post is the ask.
        if (
          captureCarriesBothVerdicts(
            bundle,
            (proof as Json)["comment_capture_hash"],
            payload["comment_id"],
            entryId,
          )
        ) {
          report.add(
            "community_binding",
            field,
            ACCOUNT_BINDING_REFUSALS.form_counted,
            briefValue(entryId),
            briefValue((proof as Json)["comment_capture_hash"]),
          );
          continue;
        }
        if (!tierInScope) {
          report.add(
            "community_binding",
            field,
            ACCOUNT_BINDING_REFUSALS.out_of_scope,
            briefValue([...ACCOUNT_BINDING_TIERS].join(",")),
            briefValue(claimedTier),
          );
          continue;
        }
        const createdAt = registered["account_created_at"];
        if (
          typeof submittedAt !== "string" ||
          typeof createdAt !== "string" ||
          !isBefore(createdAt, submittedAt)
        ) {
          report.add(
            "community_binding",
            field,
            ACCOUNT_BINDING_REFUSALS.too_new,
            briefValue(submittedAt),
            briefValue(createdAt),
          );
          continue;
        }
        // The sunset, read at the promoting decision's own instant and nowhere
        // else (D-142 item 4) — the same instant the fold reads it at, because
        // it is one rule. A line posted years before a consensus that closed
        // after the rung did is still a line that counted toward a consensus
        // the rules refuse, and reading the sunset on the line instead would
        // have called that bundle clean.
        if (promotedAt !== null && !isBefore(promotedAt, ACCOUNT_BINDING_SUNSET)) {
          report.add(
            "community_binding",
            field,
            ACCOUNT_BINDING_REFUSALS.after_sunset,
            briefValue(ACCOUNT_BINDING_SUNSET),
            briefValue(promotedAt),
          );
          continue;
        }
      }
    }

    let bound = false;
    if (isRecord(proof) && proof["kind"] === "registry") {
      bound = await verifyConfirmationProof(proof["proof"], trust, {
        handle,
        fingerprint: expected,
      });
    } else if (isRecord(proof) && proof["kind"] === "profile") {
      bound = await verifyProfileBinding(
        bundle,
        proof,
        registered,
        canonicalConfirmationLine(line),
      );
    } else if (isRecord(proof) && proof["kind"] === "account") {
      // Already settled above, and settled harder than this line could be: the
      // captures were checked against the binding and against the bundle. What
      // is NOT here is a signature, and its absence is the rung — nobody signed
      // this, which is exactly what "the board authenticated the author and
      // nothing else did" means.
      bound = true;
    }
    if (!bound) {
      report.add("community_binding", field, "community_binding_invalid");
      continue;
    }

    const attestation = registration["attestation"];
    let attested =
      isRecord(attestation) && attestation["domain"] === entryDomain;
    if (!attested) {
      for (const earlier of ordered) {
        if (earlier.seq >= event.seq) break;
        if ((earlier?.type as string) !== "community_operator_joined_domain") {
          continue;
        }
        const fields = isRecord(earlier.payload)
          ? (earlier.payload as Json)
          : {};
        if (fields["operator"] !== operator) continue;
        if (fields["domain"] !== entryDomain) continue;
        attested = true;
      }
    }
    if (!attested) {
      report.add("community_binding", field, "community_domain_unattested");
    }
  }

  // The upgrades (decision D-142), checked like the registrations they amend.
  // An operator's id is its account, so the only thing an upgrade can say is
  // that the same account now stands on a key — and the three ways of lying
  // about that are all here: an operator the log never registered, a binding
  // that is not stronger than the one it replaces, and a key nobody published
  // on a page this bundle carries.
  for (const event of ordered) {
    if ((event?.type as string) !== "community_operator_bound") continue;
    const payload = isRecord(event.payload) ? (event.payload as Json) : {};
    const field = `/events/${event.seq}`;
    const operator = payload["operator"];
    const agent = payload["agent"];
    const binding = payload["binding"];
    if (
      typeof operator !== "string" ||
      typeof agent !== "string" ||
      !isRecord(binding) ||
      !isHash(payload["fingerprint"])
    ) {
      report.add("community_binding", field, "community_binding_invalid");
      continue;
    }
    let registered = false;
    for (const earlier of ordered) {
      if (earlier.seq >= event.seq) break;
      if ((earlier?.type as string) !== "community_operator_registered") {
        continue;
      }
      const fields = isRecord(earlier.payload) ? (earlier.payload as Json) : {};
      if (fields["operator"] === operator) registered = true;
    }
    if (!registered) {
      report.add("community_binding", field, "community_operator_unregistered");
      continue;
    }
    // Stronger, and only stronger: `registry` or `profile`. An upgrade naming
    // an account binding says nothing the registration did not, and D-142 has
    // no rung below account for one to fall to.
    if (!isKeyBinding(binding)) {
      report.add(
        "community_binding",
        field,
        "community_binding_invalid",
        briefValue([...COUNTING_BINDING_KINDS].join(",")),
        briefValue(binding["kind"]),
      );
      continue;
    }
    // And on a proof of the same kind, checked. Without one an upgrade is the
    // record's own word that a key exists somewhere, which is the thing a
    // binding exists to replace and which no reader could falsify (the review
    // of #105). The fold refuses such an event too (src/derive.ts,
    // `communityOperatorsAt`), so the rung does not lift on either side.
    const upgradeProof = payload["proof"];
    if (!isRecord(upgradeProof) || upgradeProof["kind"] !== binding["kind"]) {
      report.add(
        "community_binding",
        field,
        "community_binding_invalid",
        briefValue(binding["kind"]),
        briefValue(isRecord(upgradeProof) ? upgradeProof["kind"] : null),
      );
      continue;
    }

    if (binding["kind"] === "registry") {
      // A registry upgrade's proof is a registry proof and is checked by the
      // same code a line's is, against the same pin: a witnessed leaf in the
      // founding registry's log, for this handle, naming this event's own
      // fingerprint.
      const parsed = parseCommunityOperatorId(operator);
      const bound = await verifyConfirmationProof(
        upgradeProof["proof"],
        trust,
        {
          handle: parsed === null ? operator : parsed.handle,
          fingerprint: payload["fingerprint"] as string,
        },
      );
      if (!bound) {
        report.add("community_binding", field, "community_binding_invalid");
      }
      continue;
    }

    // A profile binding is a key on a page, so the page has to be in the
    // bundle under the hash the binding names, with that key in its bytes —
    // the same two facts `verifyProfileBinding` asks of a registration's.
    const captureHash = payload["capture_hash"];
    const capture =
      typeof captureHash === "string"
        ? bundle.captures?.[captureHash]
        : undefined;
    let shows = false;
    try {
      const publicKey = binding["public_key"];
      if (capture !== undefined && typeof publicKey === "string") {
        const bytes = base64Decode(
          (capture as unknown as Json)["body_base64"] as string,
        );
        shows = new TextDecoder().decode(bytes).includes(publicKey);
      }
    } catch {
      shows = false;
    }
    if (!shows) {
      report.add("community_binding", field, "community_binding_invalid");
    }
  }
}

/**
 * When this entry's consensus closed, off the bundle's own fold.
 *
 * The promoting decision's `verified_at`, recomputed and never read from the
 * stored entry: the sunset is a rule about when a consensus formed, and reading
 * the instant off the row being checked would let the row choose its own
 * deadline. Null while the entry has verified nothing.
 */
function promotingInstantOf(bundle: LogBundle, entryId: string): string | null {
  try {
    const derived = deriveEntry(bundle.events, entryId, { now: bundle.as_of });
    const at = (derived.entry as unknown as Json)["verified_at"];
    return typeof at === "string" && at !== "" ? at : null;
  } catch {
    return null;
  }
}

/**
 * Whether a binding is one of the two the world can recheck against a key.
 *
 * `COUNTING_BINDING_KINDS` in src/policy.ts, asked of a payload rather than of
 * a type: this side reads a stranger's bytes.
 */
function isKeyBinding(binding: Json): boolean {
  return (
    typeof binding["kind"] === "string" &&
    (COUNTING_BINDING_KINDS as readonly string[]).includes(
      binding["kind"] as string,
    )
  );
}

/** Whether a hash is one this record could have written: `sha256:<64 hex>`. */
function isHash(value: unknown): value is string {
  return typeof value === "string" && /^sha256:[0-9a-f]{64}$/.test(value);
}

/**
 * Whether an archived capture's bytes really hash to the hash it is filed
 * under, recomputed under the same normalization a citation's snapshot is.
 *
 * The whole of what an account binding proves, so it is recomputed rather than
 * read: a capture map is a stranger's object, and a key in it is a claim until
 * the bytes under it are hashed again.
 */
async function captureHashes(capture: unknown, claimed: string): Promise<boolean> {
  if (!isRecord(capture)) return false;
  let bytes: Uint8Array;
  try {
    bytes = base64Decode(capture["body_base64"] as string);
  } catch {
    return false;
  }
  const contentType = capture["content_type"];
  const result = await snapshotHash(
    bytes,
    typeof contentType === "string" ? contentType : null,
  );
  return result.ok && result.hash === claimed;
}

/** Whether one instant is strictly earlier than another, both parsed. */
function isBefore(value: string, limit: string): boolean {
  const at = Date.parse(value);
  const bound = Date.parse(limit);
  if (Number.isNaN(at) || Number.isNaN(bound)) return false;
  return at < bound;
}

/**
 * An account binding's two captures, rechecked against the bundle (D-142).
 *
 * The rung carries no key and therefore no signature, so what a reader can
 * check is what was archived and who it was archived from:
 *
 * - two hashes this record could have written, both present in the bundle and
 *   both hashing back to their own bytes — the profile's named identically by
 *   the binding and by the proof, because the profile is the operator's and is
 *   fixed at its registration, and the comment's read off the proof, because
 *   every line has a comment of its own;
 * - the comment capture's bytes naming this entry, so the page under that hash
 *   is the page the line was read from and not some other page of the same
 *   board;
 * - the profile capture's bytes naming this handle, so the account the rung is
 *   about is the account the capture is of;
 * - and both URLs under the venue's own origin (`CONFIRMATION_VENUES`), so a
 *   binding cannot point at a page on a site the record never reads.
 *
 * The entry id and the handle, and not the canonical confirm line itself: a
 * capture is whatever the venue's public door answered, and on two of the three
 * venues that is a JSON rendering of the comment rather than its raw text
 * (D-138 item 2, and K2's adapters), so the line's exact bytes may be escaped,
 * re-wrapped or split across fields. The entry id and the handle are opaque
 * tokens that survive every rendering of the same content, which is what makes
 * them the two things worth asking for. So the claim is: these bytes are a page
 * of this venue, about this entry and this account, archived under these
 * hashes, and nobody signed any of it.
 *
 * Never throws: a stranger's proof is always answered with a verdict.
 */
async function accountCapturesHold(
  bundle: LogBundle,
  binding: Json,
  proof: unknown,
  venue: string,
  handle: string,
  entryId: string,
): Promise<boolean> {
  try {
    if (!isRecord(proof)) return false;

    // The profile is the OPERATOR'S and is fixed at the registration, so the
    // proof may not name one of its own: the account the rung is about is the
    // account the registration captured, and a line is by that operator or by
    // nobody.
    const profile = binding["profile_capture_hash"];
    if (!isHash(profile)) return false;
    if (proof["profile_capture_hash"] !== profile) return false;

    // The comment is the LINE'S, and every line has its own, so it is read off
    // the proof. What ties it to this operator is the profile beside it and the
    // registration behind both; what ties it to this entry is its own bytes.
    const comment = proof["comment_capture_hash"];
    if (!isHash(comment)) return false;

    // Both of the registration's pages on the venue's own site. The origin is
    // policy's (`CONFIRMATION_VENUES`), so a venue this build does not publish
    // has no origin to be under and the binding is refused rather than waved
    // through.
    const origin = venueOrigin(venue);
    if (origin === null) return false;
    if (!isUnder(binding["comment_url"], origin)) return false;
    if (!isUnder(binding["profile_url"], origin)) return false;

    for (const [hash, names] of [
      [comment, entryId],
      [profile, handle],
    ] as const) {
      const capture = bundle.captures?.[hash];
      if (capture === undefined) return false;
      if (!(await captureHashes(capture, hash))) return false;
      if (!captureNames(capture, names)) return false;
    }
    return true;
  } catch {
    return false;
  }
}

/** The origin a venue's public doors answer on, or null for one we do not publish. */
function venueOrigin(venue: string): string | null {
  const row = CONFIRMATION_VENUES.find((each) => each.venue === venue);
  return row === undefined ? null : row.origin;
}

/**
 * Whether a URL is on an origin, parsed rather than matched as a prefix.
 *
 * `https://example.test.evil.com/` starts with no origin it is not on, and a
 * prefix test would have said otherwise.
 */
function isUnder(value: unknown, origin: string): boolean {
  if (typeof value !== "string") return false;
  try {
    return new URL(value).origin === new URL(origin).origin;
  } catch {
    return false;
  }
}

/** Whether an archived capture's bytes name a token: the id, or the handle. */
function captureNames(capture: unknown, token: string): boolean {
  if (!isRecord(capture) || token === "") return false;
  try {
    const bytes = base64Decode(capture["body_base64"] as string);
    return new TextDecoder().decode(bytes).includes(token);
  } catch {
    return false;
  }
}

/**
 * Whether the ONE comment a binding names carries both of one entry's lines
 * (decision D-144).
 *
 * The capture is not the comment. Only GitHub has a per-comment door
 * (`/repos/<repo>/issues/comments/<id>`, so those bytes are that comment and
 * nothing else); The Colony's comment door is a post's whole context and
 * 1F916's is the whole post, so a capture from either holds the thread's own
 * post beside every comment on it — and on a batch thread the thread's post IS
 * the ask this record published, which carries both lines for every entry it
 * names (src/cli/batch-post.ts). Asking the rule of those bytes would refuse
 * every honest counted line on every Colony and 1F916 thread, and would let one
 * bystander who pasted the block make every other line on the thread
 * permanently unverifiable — captures are content-addressed and the log is
 * append-only, so there would be no way back. That is the fault this locates
 * around.
 *
 * So the comment is found first, by the id the validation sealed, and the rule
 * is asked of its body alone (`carriesBothVerdicts`, src/confirm.ts) with no
 * rule of this file's own: the door and the verifier have to agree about what a
 * form is, and a second reading here would be a second rule.
 *
 * False whenever the comment cannot be located — a hash the bundle holds
 * nothing under, bytes that do not decode, a rendering this build does not
 * recognise, an id that is not in the document. Under-firing is the safe
 * direction: a reader refusing somebody's mirror is owed a fault that is
 * certain, and a missing capture is not evidence that a comment was a form.
 */
function captureCarriesBothVerdicts(
  bundle: LogBundle,
  hash: unknown,
  commentId: unknown,
  entryId: string,
): boolean {
  if (typeof hash !== "string") return false;
  const capture = bundle.captures?.[hash];
  if (!isRecord(capture)) return false;
  try {
    const bytes = base64Decode(capture["body_base64"] as string);
    const body = commentBodyIn(new TextDecoder().decode(bytes), commentId);
    if (body === null) return false;
    return carriesBothVerdicts(body, entryId);
  } catch {
    return false;
  }
}

/**
 * One comment's body inside an archived capture, or null when it is not
 * findable there (decision D-144).
 *
 * The three renderings this record's own adapters document (src/adapters/board.ts)
 * and no guess beyond them:
 *
 * - a post's context or a whole post, `{..., comments: [...]}`, where the row
 *   is the one whose `id` — or `comment_id`, which is 1F916's other spelling —
 *   is this comment's. The Colony's ids are UUIDs and 1F916's are integers, so
 *   they are compared as the strings the payload and the document both spell
 *   them with. The thread's own post is never fallen back to: on a batch thread
 *   that post is the ask, and reading it as somebody's comment is the whole
 *   fault this exists to avoid. The FIRST row with the wanted id and no other,
 *   which is deliberate: the capture's bytes are sealed and content-addressed,
 *   so a comment cannot grow a sibling row after the fact, and picking between
 *   two rows of one archived document would be this reader choosing which of
 *   them somebody wrote.
 * - one comment on its own door, `{..., id, body: "..."}`, which is GitHub's
 *   shape and the fixture board's. The id has to be there and has to be this
 *   comment's.
 *
 * The second reading is a positive id match and nothing looser, and a document
 * carrying a `post` or a `comments` key at all never reaches it (the review of
 * #107). Both rules exist for the same case: a whole-post rendering whose
 * comments were omitted, or given as an object rather than an array, or whose
 * own id is missing, must not have its own `body` — the ask — read as somebody's
 * comment. A thread's post is a comment of nobody's.
 *
 * Anything else is null, and null is not a refusal: a rendering this build does
 * not recognise is a reading it cannot make, not evidence of a fault.
 *
 * The text is parsed as JSON and read for two fields. Nothing in it is followed
 * and nothing else in it is looked at, which is the stance every reading of a
 * stranger's bytes in this record takes.
 */
function commentBodyIn(text: string, commentId: unknown): string | null {
  if (commentId === undefined || commentId === null) return null;
  const wanted = String(commentId);
  if (wanted === "") return null;
  let document: unknown;
  try {
    document = JSON.parse(text);
  } catch {
    return null;
  }
  if (!isRecord(document)) return null;

  // A document that speaks of a thread is read as one or not at all.
  if ("comments" in document || "post" in document) {
    const rows = document["comments"];
    if (!Array.isArray(rows)) return null;
    for (const each of rows) {
      if (!isRecord(each)) continue;
      const id = each["id"] ?? each["comment_id"];
      if (id === undefined || id === null) continue;
      if (String(id) !== wanted) continue;
      return typeof each["body"] === "string" ? each["body"] : null;
    }
    return null;
  }

  const own = document["id"];
  if (own === undefined || own === null) return null;
  if (String(own) !== wanted) return null;
  return typeof document["body"] === "string" ? document["body"] : null;
}

/**
 * h (key_rotation). Every rotation in the bundle, rechecked, and every decision
 * a retired key took after its retirement, named (decisions D-095, D-097 item
 * 3, D-140 item 5).
 *
 * Whitepaper Section 5: standing, trust and marks are the operator's, and a key
 * is how an operator speaks. A rotation is therefore a claim with two halves
 * that a reader has to be able to check alone: that the new key is really this
 * operator's, and that the old one stopped speaking exactly where the log says
 * it did.
 *
 * The first half, by the kind of operator:
 *
 * - A domain rotation carries the new key's own independence attestation, and
 *   it is verified exactly as `agent_bound`'s is — the operator, the new agent
 *   and the fixed sentence of the operator's domain, under the NEW key's
 *   signature. A rotation whose attestation is by anything else is
 *   `bad_attestation`: the old key's word that a new key exists is not evidence
 *   that it does.
 * - A community rotation carries no attestation and a profile binding instead
 *   (D-140 item 5). The capture the binding names has to be IN the bundle,
 *   under its own hash, with the new key in its bytes, and the event's
 *   `new_agent` has to be that key — which is what makes the key public rather
 *   than merely claimed, archived exactly as a citation's snapshot is.
 *
 * The second half is `agent_retired`, and it is the reason this check exists at
 * all rather than being a line in `records`: every decision and every
 * reconfirmation in the bundle is asked whether its own key had been retired at
 * its own position. Before the rotation, nothing is said — those signatures are
 * as good as they ever were, and a record that invalidated its own past would
 * be a record anybody could rewrite by losing a key. At or after it, the
 * decision is named, because derivation counts it for nobody (src/derive.ts,
 * `mayValidateEntry`) and a report that stayed quiet would leave a reader
 * unable to see why the entry derives as it does.
 *
 * The whole log or nothing, like the exclusions beside it: a rotation is a
 * registry event, and which keys had been retired by a position cannot be read
 * off one entry's own events.
 */
async function checkKeyRotations(
  bundle: LogBundle,
  entryId: string,
  report: Report,
): Promise<void> {
  const ordered = inSeqOrder(bundle.events);

  for (const event of ordered) {
    if ((event?.type as string) !== "key_rotated") continue;
    const payload = isRecord(event.payload) ? (event.payload as Json) : {};
    const field = `/events/${event.seq}`;
    const operator = payload["operator"];
    const newAgent = payload["new_agent"];
    const retired = payload["retired_agent"];
    if (
      typeof operator !== "string" ||
      typeof newAgent !== "string" ||
      typeof retired !== "string"
    ) {
      report.add("key_rotation", field, "rotation_invalid");
      continue;
    }

    const attestation = payload["attestation"];
    if (isRecord(attestation)) {
      // A domain rotation: the new key's own attestation, for the operator it
      // is joining, verified by the same function the registration door uses.
      if (!(await verifyAttestation(operator, newAgent, attestation))) {
        report.add("key_rotation", field, "bad_attestation");
      }
      continue;
    }

    // A community rotation: the profile capture that publishes the new key.
    const binding = payload["binding"];
    const captureHash = payload["capture_hash"];
    if (
      !isRecord(binding) ||
      binding["kind"] !== "profile" ||
      typeof binding["public_key"] !== "string" ||
      typeof captureHash !== "string" ||
      binding["capture_hash"] !== captureHash
    ) {
      report.add("key_rotation", field, "rotation_invalid");
      continue;
    }
    const publicKey = binding["public_key"];
    // The agent and the key are two spellings of one fact, and an event whose
    // two spellings disagree names two keys at once.
    if (newAgent !== AGENT_ID_PREFIX + publicKey) {
      report.add(
        "key_rotation",
        field,
        "rotation_invalid",
        briefValue(AGENT_ID_PREFIX + publicKey),
        briefValue(newAgent),
      );
      continue;
    }
    const capture = bundle.captures?.[captureHash];
    if (capture === undefined) {
      // A bundle carries the captures ITS OWN entry's records needed, and a
      // rotation is a registry event: a log with two entries has rotations in
      // both bundles and the profile page in only one. So a capture that is not
      // here is not a fault of this rotation — it is a page this bundle was
      // never going to carry, and the bundle that did carry it checked it.
      //
      // Nothing is lost by the silence. The rotation's real proof is the
      // `community_validation` sealed beside it, whose `community_binding`
      // check demands the capture, finds the key in its bytes and verifies the
      // line's signature under it — and that check runs in the bundle where the
      // page actually is.
      continue;
    }
    let carries = false;
    try {
      carries = new TextDecoder()
        .decode(base64Decode(capture.body_base64))
        .includes(publicKey);
    } catch {
      carries = false;
    }
    if (!carries) {
      report.add("key_rotation", field, "rotation_invalid", briefValue(captureHash));
    }
  }

  // Every decision and reconfirmation this entry took, against the retirements
  // above. `retiredAgentsAt` is asked at each record's own position, so the
  // answer is what the log said at that moment and never what it says now.
  for (const event of ordered) {
    const type = event?.type as string;
    if (type !== "validation" && type !== "reconfirmation") continue;
    if (event.entry_id !== entryId) continue;
    const payload = isRecord(event.payload) ? (event.payload as Json) : {};
    const record = payload["record"];
    if (!isRecord(record)) continue;
    const agent = record["agent"];
    if (typeof agent !== "string") continue;
    const at = retiredAgentsAt(bundle.events, event.seq).get(agent);
    if (at === undefined) continue;
    report.add(
      "key_rotation",
      `/events/${event.seq}`,
      "agent_retired",
      briefValue(at),
      briefValue(agent),
    );
  }
}

/**
 * A profile binding, rechecked against the key the *registration* bound.
 *
 * The key on the proof is the claimant's own word, and a check made against it
 * would verify every forgery ever written: an attacker signs the line with a
 * keypair it made a moment ago, offers that key beside the signature, hands in
 * a page it fabricated naming the same key, and all three agree with each
 * other and with nothing else. So the registration is what the signature is
 * judged by. The key and the capture the operator was registered under are the
 * fixed points; the proof must name both of them, and the signature must be
 * that key's.
 *
 * Three things, all of which must hold:
 *
 * 1. The proof's `public_key` and `capture_hash` are the registration's own. A
 *    proof naming another key is a proof about another operator.
 * 2. The signature over the canonical line verifies under that registered key.
 * 3. The capture the registration named is in the bundle and its bytes carry
 *    that key — which is what makes the key public rather than merely claimed,
 *    archived under its own hash exactly as a citation's snapshot is.
 *
 * Never throws: a stranger's proof is always answered with a verdict.
 */
async function verifyProfileBinding(
  bundle: LogBundle,
  proof: Json,
  registered: Json,
  canonicalLine: string,
): Promise<boolean> {
  try {
    const publicKey = registered["public_key"];
    const captureHash = registered["capture_hash"];
    const signature = proof["signature"];
    if (typeof publicKey !== "string") return false;
    if (typeof captureHash !== "string") return false;
    if (typeof signature !== "string") return false;
    // The proof may not name a key or a page of its own: the operator was
    // registered under these, and a validation is by the operator or by
    // nobody.
    if (proof["public_key"] !== publicKey) return false;
    if (proof["capture_hash"] !== captureHash) return false;

    const signed = await verifyBytes(
      base64urlDecode(publicKey),
      new TextEncoder().encode(canonicalLine),
      base64urlDecode(signature),
    );
    if (!signed) return false;

    const capture = bundle.captures?.[captureHash];
    if (capture === undefined) return false;
    const bytes = base64Decode(capture.body_base64);
    const text = new TextDecoder().decode(bytes);
    return text.includes(publicKey);
  } catch {
    return false;
  }
}

/**
 * The dispute this entry was filed as, as it stood before `seq`, or null.
 *
 * The mirror of src/worker/validate.ts's `disputedTarget`, read off the events
 * instead of off the `dispute_of` column the door has: the filing is scoped to
 * the TARGET entry and names the correction, so the correction's own events say
 * nothing about it and the whole log has to be asked. Null three ways, exactly
 * as the door's is: no filing names this entry, the filing has already been
 * settled, or the target it names is not an entry.
 *
 * Settled is measured before `seq` and not at the head, because a dispute is
 * settled BY the decisions this replays: at the moment each decision was taken
 * the filing was still open, which is the position the door judged it from.
 */
function disputeFilingFor(
  events: readonly Event[],
  correctionId: string,
): Event<"dispute_filed"> | null {
  const settled = new Set<string>();
  for (const event of events) {
    if (event.type !== "dispute_upheld" && event.type !== "dispute_failed") {
      continue;
    }
    const payload = isRecord(event.payload) ? (event.payload as Json) : {};
    const id = payload["correction_entry_id"];
    if (typeof id === "string") settled.add(id);
  }
  if (settled.has(correctionId)) return null;

  let filed: Event<"dispute_filed"> | null = null;
  for (const event of inSeqOrder(events)) {
    if (event.type !== "dispute_filed") continue;
    const payload = isRecord(event.payload) ? (event.payload as Json) : {};
    if (payload["correction_entry_id"] !== correctionId) continue;
    filed = event as Event<"dispute_filed">;
  }
  return filed;
}

/**
 * The operators barred from validating this entry beyond the standing rules.
 *
 * Whitepaper Section 6, "Dispute": a challenge "passes through the same
 * validation process with one extra exclusion: no operator that signed the
 * original, submitter or validator, may validate the challenge against it."
 * Empty for an ordinary entry, which is why every entry that is not a challenge
 * replays exactly as it always did.
 *
 * The target is derived at the filing's own position, so who "signed the
 * original" is who had signed it when the challenge was filed — the same
 * answer the door reaches, since a challenged entry is verified and closed and
 * gains no further approver after it.
 */
function disputeExclusionsFor(
  bundle: LogBundle,
  entryId: string,
  seq: number,
): readonly string[] {
  const before = bundle.events.filter((event) => event.seq < seq);
  const filed = disputeFilingFor(before, entryId);
  if (filed === null) return [];
  const targetId = filed.entry_id;
  if (typeof targetId !== "string") return [];

  try {
    const target = deriveEntry(
      before.filter((event) => event.seq <= filed.seq),
      targetId,
      { now: bundle.as_of },
    ).entry as unknown as Json;
    const approvers = target["approvers"];
    return disputeExclusions({
      author_operator: (target["author_operator"] as string | null) ?? null,
      approvers: (Array.isArray(approvers)
        ? approvers
        : []) as readonly ApproverRecord[],
    });
  } catch {
    // A target the bundle does not carry, or carries unusably: the derived
    // check is what names a missing entry, and inventing an exclusion list out
    // of nothing would refuse decisions the log gives no reason to refuse.
    return [];
  }
}

/**
 * g. The exclusions, replayed.
 *
 * Each validation is put back through the door it came in at (src/validate.ts)
 * with the context as it stood at that event's position: who was registered
 * then, which decisions were already on the entry, which assignment was still
 * open, and — where the entry is a challenge — which operators signed the entry
 * it challenges. A record the door would have refused is named by its index
 * among the entry's decisions.
 */
function checkExclusions(
  bundle: LogBundle,
  entryId: string,
  logCore: Json,
  report: Report,
): void {
  const validations = validationsOf(bundle.events, entryId);
  const submitter = {
    agent: logCore["author"] as string,
    operator: (logCore["author_operator"] as string | null) ?? null,
  };

  for (let index = 0; index < validations.length; index += 1) {
    const event = validations[index]!;
    const payload = isRecord(event.payload) ? (event.payload as Json) : {};
    const record = payload["record"];
    if (!isRecord(record)) {
      report.add("exclusions", `/approvers/${index}`, "missing");
      continue;
    }

    const priorRecords = validations
      .slice(0, index)
      .map((prior) => (prior.payload as Json)["record"] as ApproverRecord);

    const before = bundle.events.filter((other) => other.seq < event.seq);
    const open = openAssignment(before, entryId);

    const registered = registeredOperatorsAt(bundle.events, event.seq);
    const operators: Record<string, OperatorInfo> = {};
    for (const operator of registered.operators) {
      const known = bundle.registry.operators[operator];
      operators[operator] = {
        maintainer: registered.maintainers.has(operator),
        provider: known?.provider === true,
        domains: known?.domains ?? [DEFAULT_DOMAIN],
      };
    }

    const verdict = checkValidation(record as unknown as ApproverRecord, {
      submitter,
      agentOperators: bundle.registry.agents,
      operators,
      domain: domainOf(logCore),
      // Decision D-096: computed here from the published tables, exactly as the
      // door computes it, so a bundle carrying a decision the door would have
      // refused as `subject_authority` names that refusal offline too. Nothing
      // new is asked of the bundle: the domain and the subject are in the
      // signed core it already carries.
      authority_hosts: authorityHostsFor(domainOf(logCore), logCore["subject"]),
      priorRecords,
      openAssignment: open === null ? null : { operator: open.operator },
      excludedOperators: disputeExclusionsFor(bundle, entryId, event.seq),
    });
    if (!verdict.ok) {
      report.add(
        "exclusions",
        `/approvers/${index}`,
        verdict.reason,
        null,
        briefValue(record["operator"]),
      );
    }
  }
}

/** h (seals). Every seal in the bundle, chained, before anything is derived from them. */
async function checkSeals(bundle: LogBundle, report: Report): Promise<Seal[]> {
  const ordered = [...bundle.seals].sort(
    (left, right) => (left?.seq ?? 0) - (right?.seq ?? 0),
  );
  let previous: Seal | null = null;
  for (const seal of ordered) {
    let ok = false;
    try {
      ok = await verifySeal(bundle.events, seal, previous);
    } catch {
      ok = false;
    }
    if (!ok) {
      report.add("seals", `/seals/${seal?.seq ?? 0}`, "bad_seal");
    }
    previous = seal;
  }
  return ordered;
}

/** h (derived). Recompute the whole entry from the log and diff it key by key. */
async function checkDerived(
  bundle: LogBundle,
  entry: Json,
  entryId: string,
  seals: readonly Seal[],
  report: Report,
): Promise<void> {
  let recomputed: Json;
  try {
    const entrySeals = await sealsForEntries(bundle.events, seals);
    recomputed = deriveEntry(bundle.events, entryId, { now: bundle.as_of }, entrySeals)
      .entry as Json;
  } catch {
    report.add("derived", "/", "underivable");
    return;
  }

  for (const key of Object.keys(recomputed)) {
    if (!Object.prototype.hasOwnProperty.call(entry, key)) {
      report.add("derived", `/${key}`, "missing_key", briefDerived(recomputed[key]));
      continue;
    }
    if (safeCanonical(recomputed[key]) === safeCanonical(entry[key])) continue;
    report.add(
      "derived",
      `/${key}`,
      "mismatch",
      briefDerived(recomputed[key]),
      briefDerived(entry[key]),
    );
  }
  for (const key of Object.keys(entry)) {
    if (Object.prototype.hasOwnProperty.call(recomputed, key)) continue;
    report.add("derived", `/${key}`, "unexpected_key", null, briefDerived(entry[key]));
  }
}

/**
 * Recompute one snapshot hash from the archived capture and compare.
 *
 * Absence of a capture is a diff only where the entry's own hash is concerned;
 * a validator's capture is optional, and the caller says which this is.
 */
async function checkCapture(
  bundle: LogBundle,
  claimed: unknown,
  field: string,
  required: boolean,
  report: Report,
): Promise<void> {
  if (typeof claimed !== "string") {
    if (required) report.add("snapshot", field, "missing");
    return;
  }
  const capture = bundle.captures[claimed];
  if (capture === undefined || !isRecord(capture)) {
    if (required) report.add("snapshot", field, "capture_missing", claimed);
    return;
  }

  let bytes: Uint8Array;
  try {
    bytes = base64Decode(capture["body_base64"] as string);
  } catch {
    report.add("snapshot", field, "bad_base64", claimed);
    return;
  }

  const contentType = capture["content_type"];
  const result = await snapshotHash(
    bytes,
    typeof contentType === "string" ? contentType : null,
  );
  if (!result.ok) {
    report.add("snapshot", field, result.reason, claimed);
    return;
  }
  if (result.hash !== claimed) {
    report.add("snapshot", field, "mismatch", claimed, result.hash);
  }
}

/**
 * i. The snapshot hash, recomputed under the entry's norm_version.
 *
 * The kernel implements exactly one norm version. An entry signed under another
 * one is refused rather than checked against rules it never claimed: the
 * paper's "recompute under the entry's norm_version" is honored by saying so,
 * not by pretending.
 */
async function checkSnapshot(
  bundle: LogBundle,
  entry: Json,
  report: Report,
): Promise<void> {
  if (entry["norm_version"] !== NORM_VERSION) {
    report.add(
      "snapshot",
      "/norm_version",
      "unsupported_norm_version",
      NORM_VERSION,
      briefValue(entry["norm_version"]),
    );
    return;
  }

  if (isTranscriptCategory(domainOf(entry), entry["category"])) {
    const evidence = entry["evidence"];
    const source = isRecord(evidence) ? evidence : {};
    const artifact = buildTranscriptArtifact(
      evidence,
      source["output"] as string,
      source["observed_at"] as string,
    );
    const hashed = await transcriptArtifactHash(artifact);
    if (!hashed.ok) {
      report.add("snapshot", "/snapshot_hash", hashed.reason, briefValue(entry["snapshot_hash"]));
    } else if (hashed.hash !== entry["snapshot_hash"]) {
      report.add(
        "snapshot",
        "/snapshot_hash",
        "mismatch",
        briefValue(entry["snapshot_hash"]),
        hashed.hash,
      );
    }
  } else {
    await checkCapture(bundle, entry["snapshot_hash"], "/snapshot_hash", true, report);
  }

  const approvers = entry["approvers"];
  if (Array.isArray(approvers)) {
    for (let index = 0; index < approvers.length; index += 1) {
      const record = approvers[index];
      if (!isRecord(record)) continue;
      await checkCapture(
        bundle,
        record["snapshot_hash"],
        `/approvers/${index}/snapshot_hash`,
        false,
        report,
      );
    }
  }

  const reconfirmations = entry["reconfirmations"];
  if (Array.isArray(reconfirmations)) {
    for (let index = 0; index < reconfirmations.length; index += 1) {
      const record = reconfirmations[index];
      if (!isRecord(record)) continue;
      await checkCapture(
        bundle,
        record["snapshot_hash"],
        `/reconfirmations/${index}/snapshot_hash`,
        false,
        report,
      );
    }
  }
}

/** j. The entry's own seal: the proof that its submission event was sealed. */
async function checkEntrySeal(
  bundle: LogBundle,
  entry: Json,
  seals: readonly Seal[],
  submission: Event<"entry_submitted">,
  report: Report,
): Promise<void> {
  const sealValue = entry["seal"];
  // An unsealed entry carries seal null, explicitly. Whether a seal should have
  // covered it is derivation's answer, and the derived check already gave it.
  if (sealValue === null || sealValue === undefined) return;
  if (!isRecord(sealValue)) {
    report.add("seal", "/seal", "shape", "object", typeof sealValue);
    return;
  }

  const proof = decodeProof(sealValue["inclusion_proof"] as string);
  if (proof === null) {
    report.add("seal", "/seal/inclusion_proof", "malformed");
  }

  const position = sealValue["position"];
  if (typeof position !== "number") {
    report.add("seal", "/seal/position", "missing", null, briefValue(position));
    return;
  }

  const covering = sealFor(seals, position);
  if (covering === null) {
    report.add("seal", "/seal/position", "no_seal", null, position);
    return;
  }

  const event = bundle.events.find((candidate) => candidate?.seq === position);
  if (event === undefined) {
    report.add("seal", "/seal/position", "missing", null, position);
    return;
  }
  if (event.hash !== submission.hash) {
    report.add("seal", "/seal/position", "mismatch", submission.seq, position);
    return;
  }

  if (proof !== null) {
    let included = false;
    try {
      included = await verifyInclusion(event.hash, proof, covering.root);
    } catch {
      included = false;
    }
    if (!included) {
      report.add("seal", "/seal/inclusion_proof", "bad_proof", covering.root, null);
    }
  }

  const claimed = Array.isArray(sealValue["witnesses"])
    ? (sealValue["witnesses"] as unknown[])
    : [];
  const actual = Array.isArray(covering.witnesses)
    ? covering.witnesses.map((witness) => witness?.signature)
    : [];
  const same =
    claimed.length === actual.length &&
    claimed.every((signature, index) => signature === actual[index]);
  if (!same) {
    report.add("seal", "/seal/witnesses", "mismatch", actual.length, claimed.length);
  }
}

/**
 * What a caller may hand the verifier besides the two files.
 *
 * One thing, and it is not a knob: who a public confirmation's registry proof
 * is judged against (decision D-136). Absent — which is every caller in src/,
 * the CLI included — it is the pin in src/policy.ts and nothing else. It exists
 * because a test cannot forge the founding registry's key, and a check nobody
 * can test a refusal of is a check nobody has checked.
 */
export interface VerifyOptions {
  readonly confirmations?: ConfirmationTrust;
}

/**
 * Check one entry against the log bundle beside it, offline.
 *
 * The checks run in CHECKS order and each appends its own diffs; a check that
 * can still say something runs even after an earlier one failed, so a
 * hand-edited status and a dropped approver both appear in one report.
 */
export async function verifyOffline(
  entry: unknown,
  bundle: unknown,
  options: VerifyOptions = {},
): Promise<VerifyReport> {
  try {
    return await runChecks(entry, bundle, options);
  } catch (error) {
    // The promise holds even for a case nobody thought of: a stranger's file
    // can always be answered with a verdict, never with a stack trace.
    return {
      ok: false,
      entry_id: null,
      diffs: [
        {
          check: "bundle",
          field: "/",
          expected: null,
          actual: truncate(
            error instanceof Error ? error.message : String(error),
          ),
          reason: "internal_error",
        },
      ],
      bounded: false,
      not_run: [],
    };
  }
}

async function runChecks(
  entry: unknown,
  bundle: unknown,
  options: VerifyOptions,
): Promise<VerifyReport> {
  const report = new Report();

  // a. The bundle.
  const log = readBundle(bundle, report);

  // b. The schema.
  const schema = validateEntry(entry);
  if (!schema.ok) {
    for (const error of schema.errors) {
      report.add(
        "schema",
        error.path.length === 0 ? "/" : error.path,
        "schema_violation",
        error.message,
      );
    }
  }

  // b (continued). The schema version the entry was sealed under. A core
  // without `domain` is a v0.6 core: still served, listed and synced exactly as
  // it always was, but not checkable against v0.7's rules, so the verifier says
  // which version it checks against rather than pretending -- exactly as
  // `unsupported_norm_version` does for the normalization rule.
  if (isRecord(entry) && coreVersion(entry) !== SCHEMA_VERSION) {
    report.add(
      "schema",
      "/domain",
      "unsupported_schema_version",
      SCHEMA_VERSION,
      coreVersion(entry),
    );
  }

  if (!isRecord(entry)) {
    return report.finish(null);
  }
  const entryId = entry["id"];
  if (typeof entryId !== "string") {
    return report.finish(null);
  }
  if (log === null) {
    return report.finish(entryId);
  }

  // Every line the reader was handed is a line they may read (D-127), so the
  // chain, the seals and every fold below are over one and the same log.
  const readable = log;

  // The bounded bundle (decision D-120). One flag, read once, and every branch
  // below is the same two checks swapped for two others: what a bounded bundle
  // holds is this entry's events with a proof each and the seals those proofs
  // are against, so the chain walk and the whole-batch seal rebuild have no
  // inputs and the proofs and the seal links do. Nothing else moves — the
  // signature, the core, the records, the captures and the entry's own seal all
  // read exactly the same fields out of exactly the same events.
  const bounded = log.bounded === true;
  const notRun = bounded ? BOUNDED_NOT_RUN : NOTHING_SKIPPED;

  // c. The hash chain, over every line — or, bounded, each event's own hash and
  // its path to the root its seal committed to.
  const coveringSeals = new Set<number>();
  if (bounded) {
    for (const event of log.events) {
      const cover = sealFor(log.seals, event.seq);
      if (cover !== null) coveringSeals.add(cover.seq);
    }
    await checkSealLinks(log, coveringSeals, report);
    await checkProofs(log, log.seals, report);
  } else {
    await checkChain(log, report);
  }

  // d. The author's signature over the core.
  if (!(await verifyEntrySignature(entry))) {
    report.add("signature", "/signature", "bad_signature");
  }

  // e. The core, against the core the log sealed.
  const submission = submissionOf(readable.events, entryId);
  if (submission === null) {
    report.add("core", "/id", "not_submitted", null, entryId);
    await checkSnapshot(readable, entry, report);
    return report.finish(entryId, bounded, notRun);
  }
  const logCore = (submission.payload as Json)["core"] as Json;
  checkCore(entry, logCore, report);
  if (entry["signature"] !== (submission.payload as Json)["signature"]) {
    report.add(
      "core",
      "/signature",
      "mismatch",
      briefValue((submission.payload as Json)["signature"]),
      briefValue(entry["signature"]),
    );
  }

  // f. Every record signature on this entry. A bounded bundle carries the
  // decisions' own events (D-120), so this runs on both.
  await checkRecords(
    readable,
    entryId,
    options.confirmations ?? pinnedConfirmationTrust(),
    report,
  );

  // g (community_binding). Every community validation's binding, rechecked
  // from the bundle alone (D-138 item 5). The whole log or nothing, for the
  // reason the exclusions are: the registration that made the author an
  // operator is a registry event.
  if (!bounded) {
    await checkCommunityBindings(
      readable,
      entryId,
      domainOf(logCore as unknown as Parameters<typeof domainOf>[0]),
      logCore as Json,
      options.confirmations ?? pinnedConfirmationTrust(),
      report,
    );
  }

  // g (key_rotation). Every rotation, and every decision by a key that had
  // already been retired (D-095, D-097 item 3, D-140 item 5). The whole log or
  // nothing, for the reason the exclusions below are.
  if (!bounded) await checkKeyRotations(readable, entryId, report);

  // g. The exclusions, replayed at each decision's position.
  //
  // The whole log or nothing: the door judged each decision against who was
  // registered, who was assigned and what had already been decided at that
  // moment, and a bundle holding one entry's events knows none of those. Naming
  // it as not run is the honest answer; replaying it against a bounded bundle
  // would refuse decisions the log gives no reason to refuse.
  if (!bounded) checkExclusions(readable, entryId, logCore, report);

  // h. The seals, then every derived field.
  //
  // The derived view is the whole log or nothing for the same reason the
  // exclusions are: it is a fold over everything that happened, and a fold over
  // a few of the events would differ from the entry in every field the rest of
  // them decided.
  const seals = bounded
    ? [...log.seals].sort((left, right) => (left?.seq ?? 0) - (right?.seq ?? 0))
    : await checkSeals(log, report);
  const readableSealList = [...seals];
  if (!bounded) {
    await checkDerived(readable, entry, entryId, readableSealList, report);
  }

  // i. The snapshot hash, under the entry's own norm version.
  await checkSnapshot(readable, entry, report);

  // j. The entry's seal and its inclusion proof.
  await checkEntrySeal(readable, entry, readableSealList, submission, report);

  return report.finish(entryId, bounded, notRun);
}

// ---------------------------------------------------------------------------
// The attestations
// ---------------------------------------------------------------------------

/**
 * One attestation's verdict: what the log derives it as, and every difference
 * between what its events claim and what they prove.
 *
 * `status` is the derived status (src/attest.ts), or null where the events left
 * nothing to derive — so a reader can tell "this attestation is expired" from
 * "this attestation could not be read at all", which a bare diff list cannot.
 */
export interface AttestationVerdict {
  id: string;
  status: AttestationStatus | null;
  diffs: Diff[];
}

/** The verdict over every attestation the bundle carries. */
export interface AttestationReport {
  ok: boolean;
  attestations: AttestationVerdict[];
}

/** The four event types an attestation's whole story is told in. */
const ATTESTATION_EVENT_TYPES: ReadonlySet<string> = new Set([
  "attestation_requested",
  "attestation_answered",
  "attestation_scored",
  "attestation_expired",
]);

/** The attestation id an event carries, or null for an event that carries none. */
function attestationOf(event: Event): string | null {
  const payload = isRecord(event.payload) ? (event.payload as Json) : {};
  const id = payload["attestation"];
  return typeof id === "string" ? id : null;
}

/**
 * The median of the scorers' counts, as src/attest.ts's fold takes it: the
 * middle of three, and the LOWER of the two middle values for an even count,
 * because a score is a count of probes and half a probe is not a thing that can
 * have been agreed with.
 *
 * Recomputed here rather than read off the fold, because "the score is the
 * median" is exactly what this check is checking.
 */
function medianOf(values: readonly number[]): number | null {
  if (values.length === 0) return null;
  const sorted = [...values].sort((left, right) => left - right);
  return sorted[Math.floor((sorted.length - 1) / 2)] as number;
}

function own(record: Readonly<Record<string, unknown>>, key: unknown): boolean {
  return (
    typeof key === "string" &&
    Object.prototype.hasOwnProperty.call(record, key)
  );
}

/**
 * Check one attestation's events against each other and against the registry.
 *
 * The order is the order of the checks: the id the events are filed under, then
 * each score's signature, its signer, and the hashes it pins, and last the
 * derived status and score. Everything runs; a bad signature does not hide a
 * scorer under the model's own operator.
 */
async function checkAttestation(
  bundle: LogBundle,
  id: string,
  request: Event<"attestation_requested">,
  related: readonly Event[],
): Promise<AttestationVerdict> {
  const report = new Report();
  let derived: DerivedAttestation | null = null;

  try {
    derived = deriveAttestation(related, { now: bundle.as_of });
    const opened = request.payload;

    // 1. The id is a fact about the request and not a name somebody chose: one
    // model, one snapshot, one beacon round and one probe set hash to exactly
    // one id (src/attest.ts, `attestationId`).
    const expected = await attestationId({
      model: opened.model,
      pool_snapshot_seq: opened.pool_snapshot_seq,
      beacon_round: opened.beacon_round,
      probe_hash: opened.probe_hash,
    });
    if (expected !== id) {
      report.add("attestation_id", "/id", "mismatch", expected, id);
    }

    const scorers: readonly AttestationScorer[] = Array.isArray(opened.scorers)
      ? opened.scorers.filter(
          (scorer): scorer is AttestationScorer =>
            isRecord(scorer) &&
            typeof scorer["operator"] === "string" &&
            typeof scorer["agent"] === "string",
        )
      : [];
    const drawn = new Set(scorers.map((scorer) => scorer.operator));
    const scored = inSeqOrder(related).filter(
      (event) => event.type === "attestation_scored",
    ) as Event<"attestation_scored">[];

    // The counts, by operator and last one wins, exactly as the fold reads
    // them: two agents under one scoring operator are one score and not two.
    const agreedByOperator = new Map<string, number>();

    for (let index = 0; index < scored.length; index += 1) {
      const event = scored[index]!;
      const payload = isRecord(event.payload) ? (event.payload as Json) : {};
      const record = payload["record"];
      if (!isRecord(record)) {
        report.add(
          "attestation_signature",
          `/scores/${index}/record`,
          "shape",
          "object",
          shapeOf(record),
        );
        continue;
      }

      // 2. The signature, over the `attestation_score` kind with the
      // attestation id in the entry id's slot (src/records.ts), so a score
      // signed for one attestation cannot be moved onto another.
      const signed = await verifyRecordSignature(
        id,
        "attestation_score",
        record,
        payload["signature"] as string,
      );
      if (!signed) {
        report.add(
          "attestation_signature",
          `/scores/${index}/signature`,
          "bad_signature",
        );
      }

      // 3. Who signed it. The first refusal wins, as the door's own check does
      // (src/attest.ts, `checkScore`): a record that breaks several rules
      // always reports the same one.
      const agent = record["agent"];
      const operator = record["operator"];
      const seat = scorers.find((scorer) => scorer.agent === agent);
      const registered = own(bundle.registry.agents, agent)
        ? bundle.registry.agents[agent as string]
        : undefined;
      const info = own(bundle.registry.operators, operator)
        ? bundle.registry.operators[operator as string]
        : undefined;
      if (seat === undefined) {
        report.add(
          "attestation_scorer",
          `/scores/${index}/agent`,
          "not_a_scorer",
          null,
          briefValue(agent),
        );
      } else if (operator !== seat.operator) {
        report.add(
          "attestation_scorer",
          `/scores/${index}/operator`,
          "operator_mismatch",
          seat.operator,
          briefValue(operator),
        );
      } else if (registered === undefined) {
        report.add(
          "attestation_scorer",
          `/scores/${index}/agent`,
          "unregistered_agent",
          null,
          briefValue(agent),
        );
      } else if (registered !== operator) {
        report.add(
          "attestation_scorer",
          `/scores/${index}/operator`,
          "operator_mismatch",
          registered,
          briefValue(operator),
        );
      } else if (info === undefined) {
        report.add(
          "attestation_scorer",
          `/scores/${index}/operator`,
          "unregistered_operator",
          null,
          briefValue(operator),
        );
      } else if (info.maintainer === true) {
        // Section 8: the score is "judged by parties its lab does not control",
        // and a judgment nomankind signs about a model is nomankind's own.
        report.add(
          "attestation_scorer",
          `/scores/${index}/operator`,
          "maintainer_operator",
          null,
          briefValue(operator),
        );
      } else if (
        opened.model_operator !== null &&
        operator === opened.model_operator
      ) {
        report.add(
          "attestation_scorer",
          `/scores/${index}/operator`,
          "model_operator",
          null,
          briefValue(operator),
        );
      }

      // 4. What was scored: the probe set the request drew and the answers the
      // model gave, so a score can never be moved onto other questions or
      // other answers.
      if (record["probe_hash"] !== opened.probe_hash) {
        report.add(
          "attestation_hashes",
          `/scores/${index}/probe_hash`,
          "mismatch",
          briefValue(opened.probe_hash),
          briefValue(record["probe_hash"]),
        );
      }
      if (record["answers_hash"] !== derived.answers_hash) {
        report.add(
          "attestation_hashes",
          `/scores/${index}/answers_hash`,
          "mismatch",
          briefValue(derived.answers_hash),
          briefValue(record["answers_hash"]),
        );
      }

      if (typeof operator === "string" && drawn.has(operator)) {
        agreedByOperator.set(operator, record["agreed"] as number);
      }
    }

    // 5. The status and the score, recomputed from the events rather than
    // taken from the fold. An expiry over a full score is the tamper this
    // catches: the sweep appends one only to an attestation still open or
    // answered, so an `expired` sitting on top of every drawn scorer's
    // signature is a claim the events themselves contradict.
    const answered = related.some(
      (event) =>
        event.type === "attestation_answered" && event.seq > request.seq,
    );
    const expired = related.some(
      (event) => event.type === "attestation_expired" && event.seq > request.seq,
    );
    const complete =
      scorers.length > 0 && agreedByOperator.size === scorers.length;
    const status: AttestationStatus = complete
      ? "scored"
      : expired
        ? "expired"
        : answered
          ? "answered"
          : "open";
    if (status !== derived.status) {
      report.add("attestation_derived", "/status", "mismatch", status, derived.status);
    }

    const counts = scorers
      .map((scorer) => agreedByOperator.get(scorer.operator))
      .filter((agreed): agreed is number => typeof agreed === "number");
    const score = complete
      ? { agreed: medianOf(counts), probe_count: opened.probe_count }
      : null;
    if (safeCanonical(score) !== safeCanonical(derived.score)) {
      report.add(
        "attestation_derived",
        "/score",
        "mismatch",
        briefValue(score),
        briefValue(derived.score),
      );
    }
  } catch (error) {
    // As verifyOffline's: a stranger's file is always answered with a verdict.
    report.add(
      "attestation_derived",
      "/",
      "internal_error",
      null,
      truncate(error instanceof Error ? error.message : String(error)),
    );
  }

  return { id, status: derived === null ? null : derived.status, diffs: report.diffs };
}

/**
 * Check every attestation the bundle carries, offline.
 *
 * Whitepaper Section 8, "Drift attestation": "Three operators from the trusted
 * pool, none under the model's operator, score its answers against the log and
 * sign the result, and the score and the probe hash are sealed with a date."
 * Every clause of that is checkable from the log alone, and this is the check:
 * the id the request hashes to, each score's signature and signer, the probe
 * and answers hashes it pins, and the status and score the four events fold to.
 *
 * Pure and total, exactly as `verifyOffline` is: no I/O, no clock beyond the
 * bundle's own `as_of`, and never a throw — an unforeseen one becomes a single
 * `internal_error` diff on the attestation it happened under.
 */
export async function verifyAttestations(
  bundle: LogBundle,
): Promise<AttestationReport> {
  try {
    return await runAttestations(bundle);
  } catch (error) {
    return {
      ok: false,
      attestations: [
        {
          id: "",
          status: null,
          diffs: [
            {
              check: "attestation_derived",
              field: "/",
              expected: null,
              actual: truncate(
                error instanceof Error ? error.message : String(error),
              ),
              reason: "internal_error",
            },
          ],
        },
      ],
    };
  }
}

async function runAttestations(bundle: LogBundle): Promise<AttestationReport> {
  const events = Array.isArray(bundle?.events)
    ? bundle.events.filter((event) => isEventShape(event))
    : [];

  // Every attestation's events, grouped by the id they carry: an attestation's
  // whole story is a sub-sequence of the log, exactly as an entry's is.
  const byId = new Map<string, Event[]>();
  const requests = new Map<string, Event<"attestation_requested">>();
  for (const event of inSeqOrder(events)) {
    if (!ATTESTATION_EVENT_TYPES.has(event.type)) continue;
    const id = attestationOf(event);
    if (id === null) continue;
    const bucket = byId.get(id);
    if (bucket === undefined) byId.set(id, [event]);
    else bucket.push(event);
    if (event.type === "attestation_requested" && !requests.has(id)) {
      requests.set(id, event as Event<"attestation_requested">);
    }
  }

  const attestations: AttestationVerdict[] = [];
  for (const [id, related] of byId) {
    const request = requests.get(id);
    if (request === undefined) {
      // Scores or an expiry for an attestation nobody opened: there is nothing
      // to derive them against, and every check here is a check against the
      // request. Saying so is the answer; deriving an empty attestation to hang
      // them on would be inventing one.
      attestations.push({
        id,
        status: null,
        diffs: [
          {
            check: "attestation_derived",
            field: "/",
            expected: null,
            actual: related.length,
            reason: "not_requested",
          },
        ],
      });
      continue;
    }
    attestations.push(await checkAttestation(bundle, id, request, related));
  }

  return {
    ok: attestations.every((one) => one.diffs.length === 0),
    attestations,
  };
}

// ---------------------------------------------------------------------------
// The certificate check (decision D-127, D-130)
// ---------------------------------------------------------------------------

/**
 * What a reader is told about one standing certificate.
 *
 * `ok` is the signature's verdict and nothing else. Everything beside it is
 * read off the document so the reader can see what they just verified — above
 * all `issuer`, which they compare against the record's own sealing agent: a
 * certificate signs itself, and a document signed by a key nobody knows is a
 * valid signature over a claim by a stranger.
 */
export interface CertificateReport {
  readonly ok: boolean;
  readonly issuer: string | null;
  /** The subject in one line: the operator id, or the agent and its operator. */
  readonly subject: string | null;
  readonly standing: number | null;
  readonly tier: string | null;
  /** The sealed position the numbers are the answer at. */
  readonly sealed_position: number | null;
  readonly issued_at: string | null;
  /** Why it failed, or null when it verified. */
  readonly reason: string | null;
}

/** The subject line, or null when the document names no subject we can read. */
function certificateSubjectLine(certificate: unknown): string | null {
  if (typeof certificate !== "object" || certificate === null) return null;
  const subject = (certificate as Record<string, unknown>)["subject"];
  if (typeof subject !== "object" || subject === null) return null;
  const fields = subject as Record<string, unknown>;
  if (fields["kind"] === "operator" && typeof fields["id"] === "string") {
    return fields["id"];
  }
  if (
    fields["kind"] === "agent" &&
    typeof fields["agent"] === "string" &&
    typeof fields["operator"] === "string"
  ) {
    return `${fields["agent"]} (${fields["operator"]})`;
  }
  return null;
}

/** A field of the certificate, when it is of the type the document promises. */
function certificateField(certificate: unknown, name: string): unknown {
  if (typeof certificate !== "object" || certificate === null) return undefined;
  return (certificate as Record<string, unknown>)[name];
}

/**
 * Check one signed standing certificate, offline.
 *
 * Decision D-127's non-monetary reward, "verifiable offline": the whole check
 * is the Ed25519 signature over the RFC 8785 form of the document under its own
 * tag, against the key inside the issuer's 1F916 id — no log, no network, no
 * clock. `issuer` is what the reader expects nomankind's sealing agent to be;
 * without it the check answers that the document is internally consistent,
 * which is a narrower sentence and is reported as such by printing the issuer
 * the file names.
 *
 * Pure and total, exactly as `verifyOffline` is: a stranger's file gets a
 * verdict and never a throw.
 */
export async function verifySignedCertificate(
  signed: unknown,
  issuer?: string,
): Promise<CertificateReport> {
  const certificate = certificateField(signed, "certificate");
  const standing = certificateField(certificate, "standing");
  const tier = certificateField(certificate, "tier");
  const position = certificateField(certificate, "sealed_position");
  const issuedAt = certificateField(certificate, "issued_at");
  const named = certificateIssuer(signed);

  const ok = await verifyCertificate(signed, issuer);
  return {
    ok,
    issuer: named,
    subject: certificateSubjectLine(certificate),
    standing: typeof standing === "number" ? standing : null,
    tier: typeof tier === "string" ? tier : null,
    sealed_position: typeof position === "number" ? position : null,
    issued_at: typeof issuedAt === "string" ? issuedAt : null,
    reason: ok
      ? null
      : issuer !== undefined && named !== null && named !== issuer
        ? "issuer_mismatch"
        : "bad_signature",
  };
}

// ---------------------------------------------------------------------------
// The votes (decision D-130 item 4)
// ---------------------------------------------------------------------------

/** One question's verdict: every difference the log itself can settle. */
export interface VoteVerdict {
  question_id: string;
  /** The tally as this bundle's events fold to, or null when the id is unknown. */
  tally: Tally | null;
  diffs: Diff[];
}

/** The verdict over every question the bundle carries votes on. */
export interface VoteReport {
  ok: boolean;
  questions: VoteVerdict[];
}

/**
 * Check every vote the bundle carries, offline.
 *
 * Decision D-130 item 4 gives the vote three properties a reader has to be able
 * to check for themselves, and this checks all three:
 *
 *  - the signature, under the `nomankind-vote-v1` tag, against the key inside
 *    the voting agent's own id — a vote nobody can attribute is not a vote;
 *  - the voter's tier AT THE VOTE'S OWN POSITION, folded by `standingAt` and
 *    read by `tierOf`, because the electorate is senior operators and standing
 *    moves: a vote is judged by what was true when it was cast, exactly as
 *    every other retrospective question in this system is;
 *  - one vote per operator and one per disclosed perimeter per question, which
 *    is the rule the door refuses a second vote by and the fold counts by.
 *
 * The perimeter is taken from the vote's own sealed payload, because that is
 * what the door snapshotted at the vote's position: a check that re-read
 * today's registry would fail a vote that was right when it was cast.
 *
 * Pure and total, exactly as `verifyOffline` and `verifyAttestations` are: no
 * I/O, no clock beyond the bundle's own `as_of`, and never a throw — an
 * unforeseen one becomes a single `internal_error` diff.
 */
export async function verifyVotes(bundle: LogBundle): Promise<VoteReport> {
  try {
    return await runVotes(bundle);
  } catch (error) {
    return {
      ok: false,
      questions: [
        {
          question_id: "",
          tally: null,
          diffs: [
            {
              check: "vote_duplicate",
              field: "/",
              expected: null,
              actual: truncate(
                error instanceof Error ? error.message : String(error),
              ),
              reason: "internal_error",
            },
          ],
        },
      ],
    };
  }
}

async function runVotes(bundle: LogBundle): Promise<VoteReport> {
  const events = Array.isArray(bundle?.events)
    ? inSeqOrder(bundle.events.filter((event) => isEventShape(event)))
    : [];
  const votes = events.filter((event) => event.type === "vote_cast");
  if (votes.length === 0) return { ok: true, questions: [] };

  const asOf =
    typeof bundle?.as_of === "string" ? new Date(bundle.as_of) : new Date(0);

  /** Question id -> its verdict, in the order the log first mentions each. */
  const byQuestion = new Map<string, VoteVerdict>();
  const verdictFor = (questionId: string): VoteVerdict => {
    const held = byQuestion.get(questionId);
    if (held !== undefined) return held;
    const question = voteQuestion(questionId);
    const created: VoteVerdict = {
      question_id: questionId,
      tally: question === null ? null : tallyOf(events, question, asOf),
      diffs: [],
    };
    byQuestion.set(questionId, created);
    return created;
  };

  /** Who has already voted on each question, by operator and by perimeter. */
  const voted = new Map<string, Set<string>>();
  const perimeters = new Map<string, Set<string>>();
  const seen = (map: Map<string, Set<string>>, key: string): Set<string> => {
    const held = map.get(key);
    if (held !== undefined) return held;
    const created = new Set<string>();
    map.set(key, created);
    return created;
  };

  for (const event of votes) {
    const payload = isRecord(event.payload) ? (event.payload as Json) : {};
    const questionId =
      typeof payload["question_id"] === "string" ? payload["question_id"] : "";
    const verdict = verdictFor(questionId);
    const field = `/events/${event.seq}`;

    const operator =
      typeof payload["operator"] === "string" ? payload["operator"] : "";
    const agent = typeof payload["agent"] === "string" ? payload["agent"] : "";
    const choice =
      typeof payload["choice"] === "string" ? payload["choice"] : "";
    const signedAt =
      typeof payload["signed_at"] === "string" ? payload["signed_at"] : "";
    const signature =
      typeof payload["signature"] === "string" ? payload["signature"] : "";
    const perimeter =
      typeof payload["perimeter"] === "string" ? payload["perimeter"] : null;

    const signed = await verifyVoteSignature(
      {
        question_id: questionId,
        choice,
        operator,
        agent,
        signed_at: signedAt,
      },
      signature,
    );
    if (!signed) {
      verdict.diffs.push({
        check: "vote_signature",
        field,
        expected: agent,
        actual: truncate(signature),
        reason: "vote_signature_invalid",
      });
    }

    // The tier at this vote's own position: everything the log had sealed up to
    // and including the vote, which is what the door read when it took it.
    const standing = standingAt(events, event.seq).get(operator);
    const trusted = trustedOperatorsAt(events, event.seq).has(operator);
    const tier = tierOf(standing?.standing ?? 0, trusted);
    if (tier !== "senior") {
      verdict.diffs.push({
        check: "vote_eligibility",
        field,
        expected: "senior",
        actual: tier,
        reason: "vote_ineligible",
      });
    }

    const operatorsVoted = seen(voted, questionId);
    if (operatorsVoted.has(operator)) {
      verdict.diffs.push({
        check: "vote_duplicate",
        field,
        expected: null,
        actual: operator,
        reason: "vote_duplicate",
      });
    }
    operatorsVoted.add(operator);

    if (perimeter !== null) {
      const perimetersVoted = seen(perimeters, questionId);
      if (perimetersVoted.has(perimeter)) {
        verdict.diffs.push({
          check: "vote_duplicate",
          field,
          expected: null,
          actual: perimeter,
          reason: "vote_duplicate",
        });
      }
      perimetersVoted.add(perimeter);
    }
  }

  const questions = [...byQuestion.values()];
  return {
    ok: questions.every((one) => one.diffs.length === 0),
    questions,
  };
}
