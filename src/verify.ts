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
 */

import { openAssignment } from "./assign.js";
import { buildTranscriptArtifact, transcriptArtifactHash } from "./artifact.js";
import {
  attestationId,
  deriveAttestation,
  type AttestationStatus,
  type DerivedAttestation,
} from "./attest.js";
import { CORE_KEYS, coreVersion, domainOf, extractCore } from "./core.js";
import { deriveEntry, registeredOperatorsAt } from "./derive.js";
import { disputeExclusions } from "./dispute.js";
import { base64Decode } from "./encoding.js";
import { isTranscriptCategory } from "./evidence.js";
import {
  verifyChain,
  type ApproverRecord,
  type AttestationScorer,
  type Event,
} from "./events.js";
import { canonicalize } from "./hash.js";
import { decodeProof, verifyInclusion } from "./merkle.js";
import { snapshotHash } from "./normalize.js";
import { DEFAULT_DOMAIN, NORM_VERSION, SCHEMA_VERSION } from "./policy.js";
import { validateEntry } from "./schema.js";
import { sealFor, sealsForEntries, verifySeal, type Seal } from "./seal.js";
import { verifyEntrySignature } from "./sign.js";
import { checkValidation, type OperatorInfo } from "./validate.js";
import { verifyRecordSignature } from "./records.js";

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
}

/** An entry's checks, in the order they run. */
export type EntryCheck =
  | "bundle"
  | "schema"
  | "chain"
  | "signature"
  | "core"
  | "records"
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

/** Every check either verifier can name. */
export type Check = EntryCheck | AttestationCheck;

/** Every entry check, in run order. */
export const CHECKS: readonly EntryCheck[] = Object.freeze([
  "bundle",
  "schema",
  "chain",
  "signature",
  "core",
  "records",
  "exclusions",
  "derived",
  "snapshot",
  "seals",
  "seal",
] as const);

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

  finish(entryId: string | null): VerifyReport {
    return { ok: this.diffs.length === 0, entry_id: entryId, diffs: this.diffs };
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

  if (!clockOk || !eventsOk || !sealsOk) return null;

  return {
    as_of: asOf as string,
    events: events as Event[],
    registry: { agents, operators },
    seals: sealList,
    captures: captureMap,
  };
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

/** c. The hash chain, exactly as src/events.ts verifies it. */
async function checkChain(bundle: LogBundle, report: Report): Promise<void> {
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
  report: Report,
): Promise<void> {
  for (const event of inSeqOrder(bundle.events)) {
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
 * Check one entry against the log bundle beside it, offline.
 *
 * The checks run in CHECKS order and each appends its own diffs; a check that
 * can still say something runs even after an earlier one failed, so a
 * hand-edited status and a dropped approver both appear in one report.
 */
export async function verifyOffline(
  entry: unknown,
  bundle: unknown,
): Promise<VerifyReport> {
  try {
    return await runChecks(entry, bundle);
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
    };
  }
}

async function runChecks(
  entry: unknown,
  bundle: unknown,
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

  // c. The hash chain.
  await checkChain(log, report);

  // d. The author's signature over the core.
  if (!(await verifyEntrySignature(entry))) {
    report.add("signature", "/signature", "bad_signature");
  }

  // e. The core, against the core the log sealed.
  const submission = submissionOf(log.events, entryId);
  if (submission === null) {
    report.add("core", "/id", "not_submitted", null, entryId);
    await checkSnapshot(log, entry, report);
    return report.finish(entryId);
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

  // f. Every record signature on this entry.
  await checkRecords(log, entryId, report);

  // g. The exclusions, replayed at each decision's position.
  checkExclusions(log, entryId, logCore, report);

  // h. The seals, then every derived field.
  const seals = await checkSeals(log, report);
  await checkDerived(log, entry, entryId, seals, report);

  // i. The snapshot hash, under the entry's own norm version.
  await checkSnapshot(log, entry, report);

  // j. The entry's seal and its inclusion proof.
  await checkEntrySeal(log, entry, seals, submission, report);

  return report.finish(entryId);
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
