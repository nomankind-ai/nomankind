/**
 * The public-confirmation door's pure half: the form, and the proof.
 *
 * Whitepaper Section 11 makes genesis "a bootstrap exception to the
 * earned-record rule, stated as such", and decision D-136 is the way out of it:
 * somebody outside the maintainer's own perimeter checks an entry, says so on a
 * public thread at the founding registry, and the record hears it. This module
 * is everything about that which is a function of bytes — reading one line of
 * somebody's comment, and rechecking the proof that the handle behind it is a
 * key the registry's log carries under a witnessed head.
 *
 * Two rules it exists to keep.
 *
 * The text is untrusted data. A comment on a public board is written by
 * strangers and may say anything, including things shaped like instructions.
 * So it is parsed and never interpreted: the door reads line by line, acts only
 * on lines that hold the published form exactly, refuses a line rather than
 * guessing at it, bounds the free text it keeps, and follows nothing. A line
 * that is off-form is not an error and not a refusal of the comment — it is
 * prose, which is what most of a thread is.
 *
 * A confirmation never changes a status. Nothing in this module derives,
 * promotes or demotes anything: it produces a parsed line and a yes-or-no about
 * a proof. What a confirmation does to an entry is exactly one thing and it
 * happens in src/derive.ts — it can clear the bootstrap label. The paper's
 * "What verified means" is the reason: status is what the counted validators
 * decided, and a comment is not a validation.
 *
 * Pure: no I/O, no clock, no policy of its own beyond the constants it reads
 * from src/policy.ts. Ed25519 and SHA-256 go through WebCrypto, never
 * node:crypto, so this runs unchanged on a Worker.
 */

import type {
  ConfirmationCheck,
  ConfirmationCountersignature,
  ConfirmationLeaf,
  ConfirmationProof,
  ConfirmationVerdict,
  Event,
} from "./events.js";
import {
  CONFIRMATION_ATTESTATION_TOKEN_PREFIX,
  CONFIRMATION_FORM_PREFIX,
  CONFIRMATION_REASON_MAX_CHARS,
  CONFIRMATION_SIGNATURE_TOKEN_PREFIX,
  PROFILE_KEY_PREFIX,
  REGISTRY,
  WITNESS_PIN,
  WITNESSES_REQUIRED,
} from "./policy.js";
import { ATTESTATION_VERSION } from "./registry.js";
import {
  isHex64,
  registryCheckpointPayload,
  registryLeafHash,
  verifyRegistryInclusion,
} from "./registry-proof.js";
import { AGENT_ID_PREFIX, verifyBytes } from "./identity.js";
import { base64urlDecode } from "./encoding.js";
import { sha256Hex } from "./hash.js";
import type { WitnessSignature } from "./seal.js";
import { checkWitnesses, type Witness } from "./witness.js";

/** The entry id the schema's core declares, spelled here for the parser alone. */
const ENTRY_ID = /^nmk_[A-Za-z0-9]+$/;

/** The snapshot hash the schema declares, likewise. */
const SNAPSHOT_HASH = /^sha256:[0-9a-f]{64}$/;

/**
 * Whether a seal row's detail line names this fingerprint.
 *
 * The registry writes one line per seal,
 * `label='<label>' sha256=<hex>, signed by <public key>`, and the hex is
 * matched on with its key so a fingerprint cannot be met by some other hex in
 * the line. The label is not matched on: a citizen files its seals under
 * whatever label it likes, and the fingerprint is already a digest of a line
 * that begins with this record's own form prefix.
 */
function isSealOf(detail: string, fingerprint: string): boolean {
  const hex = fingerprint.startsWith("sha256:")
    ? fingerprint.slice("sha256:".length)
    : fingerprint;
  if (!/^[0-9a-f]{64}$/.test(hex)) return false;
  return detail.includes(`sha256=${hex}`);
}

/** The two span words the form accepts, and what each says. */
const SPAN_WORDS: Readonly<Record<string, "present" | "absent">> =
  Object.freeze({
    "span-present": "present",
    "span-absent": "absent",
  });

/** One well-formed line, as the door read it. */
export interface ConfirmationLine {
  /** Which line of the comment, zero-based, counting lines the door ignored. */
  readonly line: number;
  readonly entry_id: string;
  readonly verdict: ConfirmationVerdict;
  readonly check: ConfirmationCheck;
  /**
   * The independence attestation this line carries, by version, or null
   * (decision D-138).
   *
   * The whole of a community operator's registration: an agent that writes
   * `attest:<version>` into the line is signing this record's attestation at
   * that version with the same key and in the same breath as the confirmation,
   * so there is no form to fill in and no door to walk through. Only
   * `ATTESTATION_VERSION` is accepted; a line naming another version is a plain
   * confirmation whose reason begins with a word this build does not know,
   * which is what it is.
   */
  readonly attestation_version: string | null;
  /**
   * The author's own signature over the canonical line, base64url, or null
   * (decision D-138 item 2).
   *
   * A venue that binds a key through the author's public profile signs nothing
   * on their behalf — the board attributes a comment to an account and stops
   * there — so the author signs the canonical line itself and writes the
   * signature into the line. Always the last token and always before the free
   * text, and never part of the canonical line: a signature inside its own
   * preimage is not a signature of anything.
   *
   * Parsed here and judged nowhere near here. What it is checked against is the
   * key the author's profile published, which is a fact about a fetched page
   * and not about these bytes (`verifyLineSignature`, and the sweep's profile
   * path).
   */
  readonly signature: string | null;
  /** The rest of the line, trimmed and bounded, or null when there was none. */
  readonly reason: string | null;
}

/**
 * Every well-formed line of one comment, in the order they were written.
 *
 * `isKnownEntry` asks the log's own set: an entry id nobody submitted is a
 * refusal for that line and nothing more, because a confirmation of a fact this
 * record does not hold is not a fact about this record. Everything else that is
 * not the published form — a line with too few words, an unknown verdict, a
 * hash that is not a hash, a second confirmation crammed onto one line — is
 * refused the same way, line by line, so one bad line never takes a good one
 * with it.
 *
 * Whitespace is tolerated and nothing else is: any run of spaces or tabs
 * separates the words, and the line may be indented. Case is not tolerated —
 * the form is a wire format, not prose — and neither is a prefix the line
 * merely contains rather than begins with, because a sentence quoting the form
 * is a sentence about it and not an instance of it.
 */
export function parseConfirmationComment(
  body: unknown,
  isKnownEntry: (entryId: string) => boolean,
): ConfirmationLine[] {
  if (typeof body !== "string") return [];
  const lines: ConfirmationLine[] = [];
  const rows = body.split("\n");
  for (let index = 0; index < rows.length; index += 1) {
    const parsed = parseConfirmationLine(rows[index]!, index, isKnownEntry);
    if (parsed !== null) lines.push(parsed);
  }
  return lines;
}

/** One line, or null when it is not the form. */
export function parseConfirmationLine(
  raw: string,
  index: number,
  isKnownEntry: (entryId: string) => boolean,
): ConfirmationLine | null {
  // A carriage return is whitespace here: a comment written on one machine and
  // read on another must not hold the form on one and miss it on the other.
  const trimmed = raw.trim();
  if (trimmed === "") return null;

  // The prefix has to be the first word, and the rest of the line is split on
  // whitespace runs. `reason` is taken from the raw text rather than from the
  // words, so the sentence a stranger wrote is kept as they wrote it.
  const words = trimmed.split(/[ \t]+/);
  if (words[0] !== CONFIRMATION_FORM_PREFIX) return null;

  const entryId = words[1];
  const verdictWord = words[2];
  const checkWord = words[3];
  if (entryId === undefined || verdictWord === undefined) return null;
  if (checkWord === undefined) return null;

  if (!ENTRY_ID.test(entryId)) return null;
  if (!isKnownEntry(entryId)) return null;

  if (verdictWord !== "approve" && verdictWord !== "reject") return null;
  const verdict: ConfirmationVerdict = verdictWord;

  let check: ConfirmationCheck;
  if (SNAPSHOT_HASH.test(checkWord)) {
    check = { kind: "hash", value: checkWord };
  } else if (checkWord in SPAN_WORDS) {
    check = { kind: "span", value: SPAN_WORDS[checkWord]! };
  } else {
    return null;
  }

  // The attestation token, when the next word is one (D-138). Only this
  // build's own version is taken: a token naming another version is left where
  // it was written, in the reason, because a record that quietly accepted an
  // attestation text it has never seen would be accepting a promise it cannot
  // read. The token is optional and always in this one place, so a line that
  // carries none is read exactly as it was before the decision.
  const fifth = words[4];
  const carriesToken =
    fifth !== undefined &&
    fifth.startsWith(CONFIRMATION_ATTESTATION_TOKEN_PREFIX) &&
    fifth.slice(CONFIRMATION_ATTESTATION_TOKEN_PREFIX.length) ===
      ATTESTATION_VERSION;
  const attestationVersion = carriesToken ? ATTESTATION_VERSION : null;

  // The signature token, when the next word is one (D-138 item 2). One more
  // optional token in the one place it may be — after the attestation token if
  // there is one, before the reason always — so a line that carries none is
  // read exactly as it was before the decision, byte for byte.
  //
  // The token is taken on its shape and never on its validity: an empty or
  // malformed signature is a signature that will not verify, which is the same
  // outcome by a shorter road and one the parser must not decide, because the
  // parser has no key.
  const afterToken = carriesToken ? 5 : 4;
  const next = words[afterToken];
  const carriesSignature =
    next !== undefined &&
    next.startsWith(CONFIRMATION_SIGNATURE_TOKEN_PREFIX) &&
    next.length > CONFIRMATION_SIGNATURE_TOKEN_PREFIX.length;
  const signature = carriesSignature
    ? next.slice(CONFIRMATION_SIGNATURE_TOKEN_PREFIX.length)
    : null;

  const rest = words
    .slice(carriesSignature ? afterToken + 1 : afterToken)
    .join(" ")
    .trim();
  const reason =
    rest === "" ? null : rest.slice(0, CONFIRMATION_REASON_MAX_CHARS);

  return {
    line: index,
    entry_id: entryId,
    verdict,
    check,
    attestation_version: attestationVersion,
    signature,
    reason,
  };
}

/**
 * The key a profile publishes, or null when its bytes publish none.
 *
 * The whole of what a `profile` binding reads out of a page (decision D-138
 * item 2): the first `nomankind-key:<base64url>` in the text the venue's
 * profile door answered. The text is a stranger's and is treated as one — it is
 * scanned for exactly this token and read for nothing else, and what is around
 * it is never parsed, rendered or followed.
 *
 * The FIRST occurrence and no other, and nothing is merged: a profile naming
 * two keys has published one key and something else, and picking between them
 * would be this record choosing an identity on somebody's behalf. A key that
 * does not decode, or that is not an Ed25519 key's length, is no key at all.
 */
export function profileKeyIn(text: unknown): string | null {
  if (typeof text !== "string") return null;
  const at = text.indexOf(PROFILE_KEY_PREFIX);
  if (at < 0) return null;
  const rest = text.slice(at + PROFILE_KEY_PREFIX.length);
  const match = /^[A-Za-z0-9_-]+/.exec(rest);
  if (match === null) return null;
  const key = match[0];
  try {
    return base64urlDecode(key).byteLength === ED25519_KEY_BYTES ? key : null;
  } catch {
    return null;
  }
}

/** How many bytes a raw Ed25519 public key is. */
const ED25519_KEY_BYTES = 32;

/**
 * Whether a line's own signature is by this key, over the canonical line.
 *
 * The other half of a `profile` binding, and the same shape every other check
 * in this module has: bytes in, a verdict out, no I/O and no throw. The
 * preimage is the canonical line's UTF-8 — the prefix, the entry, the verdict,
 * the check and the attestation token when there is one, and never the
 * signature token or the reason — so two agents that checked the same fact and
 * wrote different sentences about it sign the same bytes.
 */
export async function verifyLineSignature(
  publicKey: string,
  canonicalLine: string,
  signature: string,
): Promise<boolean> {
  try {
    return await verifyBytes(
      base64urlDecode(publicKey),
      new TextEncoder().encode(canonicalLine),
      base64urlDecode(signature),
    );
  } catch {
    return false;
  }
}

/**
 * The line, spelled the one way everybody spells it: the prefix, the entry id,
 * the verdict and the check, one space between each, and nothing else.
 *
 * The reason is left out on purpose. It is the confirmer's free text and no
 * part of what they are attesting to — two agents that checked the same fact
 * and wrote different sentences about it have made the same statement — so the
 * fingerprint below is over the claim and not over the prose around it. A
 * confirmer who seals their sentence as well seals a different fingerprint and
 * their confirmation simply does not count, which is the safe direction.
 */
export function canonicalConfirmationLine(
  line: Pick<ConfirmationLine, "entry_id" | "verdict" | "check"> &
    Partial<Pick<ConfirmationLine, "attestation_version">>,
): string {
  const check =
    line.check.kind === "hash" ? line.check.value : `span-${line.check.value}`;
  const base = `${CONFIRMATION_FORM_PREFIX} ${line.entry_id} ${line.verdict} ${check}`;
  // The attestation token is part of the claim and so is inside the signature
  // (D-138): a line that attests says more than a line that does not, and a
  // confirmer must not be able to have their attestation added to or taken
  // away from a sentence they already signed. A line carrying none is the
  // string it always was, byte for byte, so every fingerprint sealed under
  // D-136 stays valid.
  const version = line.attestation_version ?? null;
  if (version === null) return base;
  return `${base} ${CONFIRMATION_ATTESTATION_TOKEN_PREFIX}${version}`;
}

/**
 * What a confirmer seals into their own citizen record to make a comment count:
 * the SHA-256 of the canonical line's UTF-8 bytes, as `sha256:<hex>`.
 *
 * This is the whole binding (decision D-136, as amended). The board attributes
 * a comment to a handle and signs nothing, so a comment on its own is an
 * account statement. What makes it a *key's* statement is that the same agent
 * sealed this fingerprint into the founding registry's log through its own
 * seal door, under its own key — an identity event with a hash, a position and
 * an inclusion proof under a witnessed head, exactly as nomankind's own seals
 * are (src/adapters/witness.ts). The comment is then only the pointer that
 * tells the sweep where to look.
 *
 * Domain-separated by the form's own prefix, which is the first thing inside
 * the digest: a fingerprint of a confirmation can never be a fingerprint of
 * anything else this record hashes.
 */
export async function confirmationFingerprint(
  line: Pick<ConfirmationLine, "entry_id" | "verdict" | "check"> &
    Partial<Pick<ConfirmationLine, "attestation_version">>,
): Promise<string> {
  return `sha256:${await sha256Hex(canonicalConfirmationLine(line))}`;
}

/**
 * Who a confirmation's proof is judged against: the registry whose head it
 * claims, and the witnesses whose countersignature counts.
 *
 * Handed in rather than read from policy inside the check, for the reason every
 * other rule in the kernel takes its inputs: a function that reached for a
 * global could not be tested against anything but the real registry's key, and
 * a test that cannot forge a key cannot test a refusal either. Every caller in
 * src/ passes `pinnedConfirmationTrust()`, which is the pin and nothing else.
 */
export interface ConfirmationTrust {
  readonly registry: { origin: string; log: string; public_key: string };
  readonly witnesses: readonly Witness[];
  /** How many distinct witness operators must have countersigned. */
  readonly required: number;
}

/**
 * The pinned set, from src/policy.ts: the founding registry and the witnesses
 * decision D-054 pinned, on every environment.
 *
 * Every environment, unlike the seal's witness set: a seal on demo is sealed
 * into no registry and countersigned by mocks, but a confirmation is a statement
 * on the *real* board by a *real* citizen, so the head its proof names is the
 * real registry's head wherever the Worker happens to run. Judging it against a
 * mock would be judging it against nothing.
 */
export function pinnedConfirmationTrust(): ConfirmationTrust {
  return {
    registry: {
      origin: REGISTRY.origin,
      log: REGISTRY.log,
      public_key: REGISTRY.public_key,
    },
    witnesses: WITNESS_PIN.map((row) => ({
      agent: AGENT_ID_PREFIX + row.public_key,
      operator: row.operator,
    })),
    required: WITNESSES_REQUIRED,
  };
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function isSize(value: unknown): value is number {
  return typeof value === "number" && Number.isSafeInteger(value) && value >= 0;
}

function isHexPath(value: unknown): value is string[] {
  return Array.isArray(value) && value.every(isHex64);
}

/** Whether a value has the shape of a head the registry signed. */
function isHead(value: unknown): value is ConfirmationProof["checkpoint"] {
  if (!isRecord(value)) return false;
  return (
    isSize(value["tree_size"]) &&
    isHex64(value["root"]) &&
    isSize(value["created_at"]) &&
    typeof value["registry_sig"] === "string"
  );
}

/** The one event kind a confirmation's leaf may be. */
const MEMORY_SEAL = "memory.seal";

/** Whether a value has the shape of a record row. */
function isLeaf(value: unknown): value is ConfirmationLeaf {
  if (!isRecord(value)) return false;
  return (
    typeof value["citizen"] === "string" &&
    isSize(value["event_id"]) &&
    typeof value["kind"] === "string" &&
    typeof value["detail"] === "string" &&
    isSize(value["created_at"])
  );
}

/** Whether a value has the shape of one countersignature. */
function isCountersignature(
  value: unknown,
): value is ConfirmationCountersignature {
  if (!isRecord(value)) return false;
  return (
    typeof value["agent"] === "string" &&
    typeof value["signature"] === "string" &&
    isHead(value["head"]) &&
    typeof value["consistency"] === "string" &&
    isHexPath(value["consistency_proof"])
  );
}

/**
 * Whether a value has the shape of a confirmation proof.
 *
 * A shape check and never a verdict: every field it accepts is checked again
 * below by cryptography, and the only thing this buys is that the check below
 * reads fields rather than guesses at them.
 */
export function isConfirmationProof(
  value: unknown,
): value is ConfirmationProof {
  if (!isRecord(value)) return false;
  if (typeof value["registry"] !== "string") return false;
  if (typeof value["log"] !== "string") return false;
  if (!isHex64(value["event_hash"])) return false;
  if (!isLeaf(value["leaf"])) return false;
  if (!isSize(value["leaf_index"])) return false;
  if (!isHexPath(value["proof"])) return false;
  if (!isHead(value["checkpoint"])) return false;
  const witnesses = value["witnesses"];
  return Array.isArray(witnesses) && witnesses.every(isCountersignature);
}

/**
 * One countersignature as the witness rule reads one: the registry form, with
 * the evidence that ties the countersigned head back to our leaf.
 *
 * Built here rather than carried on the wire twice, which is what makes the two
 * agree by construction: the leaf, the path and the proved-at head are the
 * proof's own, so a countersignature cannot be evidence about some other leaf
 * than the one this confirmation names.
 */
function asWitnessSignature(
  proof: ConfirmationProof,
  countersignature: ConfirmationCountersignature,
): WitnessSignature {
  return {
    agent: countersignature.agent,
    signature: countersignature.signature,
    head: {
      registry: proof.registry,
      log: proof.log,
      tree_size: countersignature.head.tree_size,
      root: countersignature.head.root,
      created_at: countersignature.head.created_at,
      registry_sig: countersignature.head.registry_sig,
    },
    evidence: {
      consistency: countersignature.consistency,
      leaf_index: proof.leaf_index,
      event_hash: proof.event_hash,
      proof: [...proof.proof],
      proved_at: {
        tree_size: proof.checkpoint.tree_size,
        root: proof.checkpoint.root,
        created_at: proof.checkpoint.created_at,
        registry_sig: proof.checkpoint.registry_sig,
      },
      consistency_proof: [...countersignature.consistency_proof],
    },
  };
}

/**
 * What a proof has to be a proof OF: whose seal, of which line.
 *
 * Without it a proof is only "some leaf is in the registry's log", which is
 * true of every leaf in it and says nothing about this confirmation. The
 * caller always knows both — the door from the comment it read, the verifier
 * from the event's own fields — so both are always asked for.
 */
export interface ConfirmationBinding {
  /** The handle that made the statement. */
  readonly handle: string;
  /** The fingerprint of the canonical line, `sha256:<hex>`. */
  readonly fingerprint: string;
}

/**
 * Whether a confirmation's proof holds: the leaf is this handle's seal of this
 * line, it is in the log, the head is the registry's, and enough pinned
 * witnesses countersigned a head that covers it.
 *
 * Five things, in the order a reader would ask them:
 *
 * 0. The leaf is the row it claims to be: a `memory.seal`, in the record of
 *    the handle that made the statement, whose detail names this line's
 *    fingerprint. This is the binding, and without it a valid proof of any
 *    other leaf in the log — another citizen's seal, or the same citizen's
 *    seal of a different line — could be pasted onto a confirmation and would
 *    verify. The row's own hash cannot be recomputed from its fields offline,
 *    because the registry publishes its leaf and checkpoint construction but
 *    not its chain-hash construction, so the row-to-hash binding is the
 *    registry's assertion as the door read it. That is the exact limit of the
 *    offline claim and the entry page states it in those words.
 *
 * 1. The head belongs to the registry and the log we pinned. A proof about some
 *    other registry's log is a proof about somebody else's record.
 * 2. The leaf folds to the head's root, by RFC 6962 (src/registry-proof.ts).
 * 3. The registry itself signed that head, under the pinned key.
 * 4. The pinned witnesses countersigned, judged by the very rule a seal's
 *    countersignatures are judged by (src/witness.ts) — the same key set, the
 *    same distinctness of operators, the same evidence bridge between the
 *    countersigned head and the head the path was fetched against. One bad
 *    countersignature refuses the whole proof rather than being dropped: a
 *    confirmation is offered to us whole by whoever collected it, and a
 *    forgery inside it is a reason to disbelieve the collection.
 *
 * Never throws: a stranger's bytes are always answered with a verdict.
 */
export async function verifyConfirmationProof(
  proof: unknown,
  trust: ConfirmationTrust,
  binding: ConfirmationBinding,
): Promise<boolean> {
  try {
    if (!isConfirmationProof(proof)) return false;
    if (proof.registry !== trust.registry.origin) return false;
    if (proof.log !== trust.registry.log) return false;

    // The binding, first: everything below is about a leaf, and this is what
    // says the leaf is ours.
    if (proof.leaf.kind !== MEMORY_SEAL) return false;
    if (proof.leaf.citizen !== binding.handle) return false;
    if (!isSealOf(proof.leaf.detail, binding.fingerprint)) return false;

    const included = await verifyRegistryInclusion({
      leafHash: await registryLeafHash(proof.event_hash),
      leafIndex: proof.leaf_index,
      treeSize: proof.checkpoint.tree_size,
      path: proof.proof,
      root: proof.checkpoint.root,
    });
    if (!included) return false;

    let registryKey: Uint8Array;
    let registrySignature: Uint8Array;
    try {
      registryKey = base64urlDecode(trust.registry.public_key);
      registrySignature = base64urlDecode(proof.checkpoint.registry_sig);
    } catch {
      return false;
    }
    const headIsTheRegistrys = await verifyBytes(
      registryKey,
      registryCheckpointPayload({
        log: proof.log,
        tree_size: proof.checkpoint.tree_size,
        root: proof.checkpoint.root,
        created_at: proof.checkpoint.created_at,
      }),
      registrySignature,
    );
    if (!headIsTheRegistrys) return false;

    const countersigned = await checkWitnesses(
      // No seal hash: every countersignature here is in the registry form, and
      // the direct form — a witness signing a seal hash — is not a statement
      // about the registry's log at all. An entry offered without a head is
      // refused by `checkWitnesses` for want of a signature over these bytes.
      "",
      proof.witnesses.map((each) => asWitnessSignature(proof, each)),
      {
        witnesses: trust.witnesses,
        // Nobody is excluded by name: the pinned set holds no operator of this
        // record and no key of nomankind's (D-054, D-121), and the page at
        // /independence is where that is checked rather than asserted.
        maintainerOperators: new Set<string>(),
        ineligibleAgents: new Set<string>(),
        registry: {
          origin: trust.registry.origin,
          public_key: trust.registry.public_key,
        },
      },
    );
    if (!countersigned.ok) return false;

    const operators = new Set(
      countersigned.witnesses.map((witness) => witness.operator),
    );
    return operators.size >= trust.required;
  } catch {
    return false;
  }
}

/**
 * A `public_confirmation` payload, read off an event by name.
 *
 * By name and not by cast: the fold has to read events sealed by builds other
 * than this one, and a payload that does not hold the shape is an event this
 * reader says nothing about rather than one it trusts. The same reading
 * src/derive.ts does for the label, in one place both can share.
 */
export interface ConfirmationPayload {
  readonly entry_id: string;
  readonly venue: string;
  readonly handle: string;
  readonly comment_id: number | string;
  /** The identity event that carries the sealed fingerprint, or -1 when none. */
  readonly registry_event_id: number;
  readonly registry_proof: unknown;
  /** The canonical line's fingerprint, as the confirmer would have sealed it. */
  readonly fingerprint: string | null;
  /**
   * The attestation version the line carried, or null (decision D-138).
   *
   * Read here because the fingerprint above is taken over the canonical line
   * WITH the token in it: a reader that recomputed the fingerprint without
   * knowing whether the line attested would compute a different one and refuse
   * a confirmation the door sealed correctly. An event that does not say reads
   * as null, which is what every line sealed under D-136 alone was.
   */
  readonly attestation_version: string | null;
  /**
   * Whether the confirmer's own key sealed this line's fingerprint into the
   * registry's log, proved at ingestion. False is an account statement: the
   * board's word for who typed it, and nothing signed.
   */
  readonly counted: boolean;
  readonly verdict: ConfirmationVerdict;
  readonly check: ConfirmationCheck;
  readonly reason: string | null;
  readonly posted_at: string;
  readonly line: number;
}

/** The check a payload names, or null when it names none this build knows. */
function checkOf(value: unknown): ConfirmationCheck | null {
  if (!isRecord(value)) return null;
  const check = value["value"];
  if (typeof check !== "string") return null;
  if (value["kind"] === "hash") {
    return SNAPSHOT_HASH.test(check) ? { kind: "hash", value: check } : null;
  }
  if (value["kind"] === "span") {
    return check === "present" || check === "absent"
      ? { kind: "span", value: check }
      : null;
  }
  return null;
}

/** The payload of one `public_confirmation` event, or null when it is not one. */
export function confirmationPayloadOf(
  event: Event,
): ConfirmationPayload | null {
  if ((event.type as string) !== "public_confirmation") return null;
  const payload = event.payload as unknown;
  if (!isRecord(payload)) return null;

  const entryId = payload["entry_id"] ?? event.entry_id;
  const verdict = payload["verdict"];
  const check = checkOf(payload["check"]);
  if (typeof entryId !== "string" || entryId === "") return null;
  if (verdict !== "approve" && verdict !== "reject") return null;
  if (check === null) return null;
  if (typeof payload["venue"] !== "string") return null;
  if (typeof payload["handle"] !== "string") return null;
  if (typeof payload["posted_at"] !== "string") return null;

  const reason = payload["reason"];
  const fingerprint = payload["fingerprint"];
  const version = payload["attestation_version"];
  return {
    entry_id: entryId,
    venue: payload["venue"],
    handle: payload["handle"],
    // Integer or string, exactly as the board spelled it, and -1 for an event
    // that names none: the id is a key and a pointer here, never a number to
    // count with (D-138 item 2).
    comment_id:
      isSize(payload["comment_id"]) || typeof payload["comment_id"] === "string"
        ? (payload["comment_id"] as number | string)
        : -1,
    registry_event_id: isSize(payload["registry_event_id"])
      ? payload["registry_event_id"]
      : -1,
    registry_proof: payload["registry_proof"] ?? null,
    fingerprint: typeof fingerprint === "string" ? fingerprint : null,
    attestation_version: typeof version === "string" ? version : null,
    // Absent reads as false, which is the only safe reading: an event that does
    // not say its fingerprint was sealed has not said it was.
    counted: payload["counted"] === true,
    verdict,
    check,
    reason: typeof reason === "string" ? reason : null,
    posted_at: payload["posted_at"],
    line: isSize(payload["line"]) ? payload["line"] : 0,
  };
}
