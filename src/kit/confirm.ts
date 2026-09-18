/**
 * The confirmer's half of a public confirmation, as one command's worth of
 * pure work.
 *
 * Whitepaper Section 11's joining steps, as amended by decision D-138: somebody
 * outside the maintainer's own perimeter checks an entry for themselves, says
 * so on a public thread, and binds the saying to a key. D-138 item 6 asks for
 * one command that generates or loads that key, signs the line and prints the
 * comment and the profile line; this module is everything about it that is a
 * function of bytes and one fetch.
 *
 * What it does, in order:
 *
 *   1. Reads the entry from the public entry door. An id this record does not
 *      hold is a refusal and not a line.
 *   2. Makes the check itself. Under `hash` it fetches the entry's own citation
 *      and hashes it under norm-v1.2 through the very functions the validator
 *      uses (`snapshotHash`), and reports whether its own hash reproduces the
 *      entry's `snapshot_hash`. Under `span-present` or `span-absent` it asks
 *      the validator's own `containsSpan` whether the capture carries the
 *      entry's claim verbatim. The verdict follows the check unless the caller
 *      forced one.
 *   3. Composes the canonical line — `canonicalConfirmationLine`, and never a
 *      second spelling of it — with the `attest:` token when the confirmer is
 *      registering as a community operator in the same breath.
 *   4. Binds it. A `profile` venue's key signs the canonical line and the
 *      signature rides the comment as a `sig:` token, with the public half
 *      printed as the `nomankind-key:` line for the venue's bio. A `registry`
 *      venue binds through the founding registry instead, so the line carries
 *      no signature and what is printed is the fingerprint and the seal request
 *      the citizen posts under its own credential.
 *
 * Nothing is posted and nothing is sent anywhere but the cited source. The
 * private key is read or generated, used, and never printed — the caller is
 * given the public half and the signature, which are the only two halves
 * anybody else can check.
 *
 * The reason is the confirmer's free text and no part of what is signed, which
 * is `canonicalConfirmationLine`'s own rule. It is bounded here at the length
 * the door keeps, and it may not carry an email address: the boards refuse a
 * comment that does, and a command that composed one would be composing a line
 * its author could not post.
 */

import { WebFetcher, type SnapshotFetcher } from "../adapters/fetch.js";
import {
  canonicalConfirmationLine,
  confirmationFingerprint,
} from "../confirm.js";
import type {
  ConfirmationCheck,
  ConfirmationVerdict,
} from "../events.js";
import { base64urlDecode, base64urlEncode } from "../encoding.js";
import { importPrivateKeyPkcs8, signBytes } from "../identity.js";
import { normalizeText, snapshotHash } from "../normalize.js";
import {
  CONFIRMATION_REASON_MAX_CHARS,
  CONFIRMATION_SIGNATURE_TOKEN_PREFIX,
  CONFIRMATION_VENUES,
  PROFILE_KEY_PREFIX,
  type ConfirmationVenue,
} from "../policy.js";
import { ATTESTATION_VERSION } from "../registry.js";

/**
 * The label a confirmation's fingerprint is filed under in the founding
 * registry, and the tag the seal's own signature is domain-separated by.
 *
 * Both are the registry's wire format and not this record's rules, which is why
 * they are named here rather than in src/policy.ts: they are how the seal door
 * spells a request, exactly as `.tools/confirm-1f916.mjs` spells one.
 */
export const SEAL_LABEL = "nomankind-confirm";
export const SEAL_TAG = "1f916.seal.v1";

/** The checks a confirmer may make, as the command's flag spells them. */
export const CHECK_WORDS = ["hash", "span-present", "span-absent"] as const;
export type CheckWord = (typeof CHECK_WORDS)[number];

/**
 * Whether a value is one of the three check words.
 *
 * A guard and never a cast, and in this file rather than at each caller: an
 * unknown word that reached `prepareConfirmation` would fall through the
 * composer's own two branches and be composed as `span-absent`, which is a
 * confirmation nobody made. One narrowing, used by the command and by the MCP
 * server, is the way that cannot happen.
 */
export function isCheckWord(value: unknown): value is CheckWord {
  return (
    typeof value === "string" &&
    (CHECK_WORDS as readonly string[]).includes(value)
  );
}

/** Whether a value is one of the venues the policy table publishes. */
export function isVenueName(value: unknown): value is string {
  return (
    typeof value === "string" &&
    CONFIRMATION_VENUES.some((venue) => venue.venue === value)
  );
}

/** Whether a value is a verdict, which is the only other word a line takes. */
export function isVerdictWord(value: unknown): value is ConfirmationVerdict {
  return value === "approve" || value === "reject";
}

/** Every refusal this command names, so a caller can enumerate them. */
export const CONFIRM_REFUSALS = [
  "unknown_entry",
  "unknown_venue",
  "unknown_check",
  "unreachable_source",
  "no_citation",
  "reason_has_email",
  "reason_too_long",
  "key_required",
  "key_unused",
  "key_in_tree",
  "bad_key_file",
] as const;

export type ConfirmRefusal = (typeof CONFIRM_REFUSALS)[number];

/** A refusal with the record's own word for it. */
export class ConfirmRefused extends Error {
  readonly reason: ConfirmRefusal;
  readonly detail: string | null;

  constructor(reason: ConfirmRefusal, detail: string | null = null) {
    super(detail === null ? reason : `${reason}: ${detail}`);
    this.name = "ConfirmRefused";
    this.reason = reason;
    this.detail = detail;
  }
}

/**
 * What one confirmation is asked for.
 *
 * `verdict` is null when the check decides it, which is the ordinary case: a
 * confirmer runs the check and says what it found. A forced verdict is the
 * confirmer overruling their own tooling on purpose, and the result says so.
 */
export interface ConfirmRequest {
  readonly baseUrl: string;
  readonly entryId: string;
  readonly venue: string;
  readonly verdict: ConfirmationVerdict | null;
  readonly check: CheckWord | null;
  readonly attest: boolean;
  readonly reason: string | null;
  /** The key file's parsed contents, or null for a registry venue. */
  readonly key: ConfirmKey | null;
}

/** A key file, read: the public half, and the private one that never prints. */
export interface ConfirmKey {
  readonly agent_id: string | null;
  readonly public_key: string;
  readonly private_key_pkcs8: string;
}

/** The seal request a 1F916 citizen posts, as a shape and not as a call. */
export interface SealRequest {
  readonly method: "POST";
  readonly url: string;
  readonly body: {
    readonly hash: string;
    readonly label: string;
    readonly signature: string;
  };
  /**
   * What the citizen's own key signs to make that `signature`, with `<handle>`
   * standing for the citizen's registry handle.
   */
  readonly signature_preimage: string;
}

/** Everything one confirmation produced. */
export interface ConfirmResult {
  readonly entry_id: string;
  readonly venue: string;
  readonly binding: ConfirmationVenue["binding"];
  readonly verdict: ConfirmationVerdict;
  readonly check: ConfirmationCheck;
  /** True when the caller named the verdict rather than the check deciding it. */
  readonly forced: boolean;
  /**
   * Whether the confirmer's own work bore the check out: the hash reproduced,
   * or the span was where the check said it would be.
   */
  readonly reproduced: boolean;
  /** This confirmer's own hash of the cited source, under norm-v1.2. */
  readonly own_hash: string;
  /** The entry's own snapshot hash, for the two to be read side by side. */
  readonly entry_hash: string;
  /** What is signed and what is fingerprinted: no signature, no reason. */
  readonly canonical_line: string;
  /** What is posted on the thread. */
  readonly comment_line: string;
  /** The line for the venue's profile bio, or null for a registry venue. */
  readonly profile_line: string | null;
  /** `sha256:<hex>` of the canonical line, or null for a profile venue. */
  readonly fingerprint: string | null;
  readonly seal_request: SealRequest | null;
}

/** The venue by name, or a refusal. Venue names are the policy table's. */
export function venueByName(name: string): ConfirmationVenue {
  const venue = CONFIRMATION_VENUES.find((row) => row.venue === name);
  if (venue === undefined) {
    throw new ConfirmRefused(
      "unknown_venue",
      `${name} (known: ${CONFIRMATION_VENUES.map((row) => row.venue).join(", ")})`,
    );
  }
  return venue;
}

/**
 * Whether a reason carries an email address.
 *
 * Deliberately broad. The boards refuse a comment carrying one, so a false
 * positive costs a confirmer one reworded sentence and a false negative costs
 * them a post that will not go through — and the check is on text the confirmer
 * wrote themselves, which is the one place being strict is free.
 */
export function hasEmailAddress(reason: string): boolean {
  return /[^\s@]+@[^\s@]+\.[^\s@]+/.test(reason);
}

/** A key file's contents, shape-checked, or a refusal naming the file. */
export function readKeyContents(parsed: unknown, path: string): ConfirmKey {
  if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
    throw new ConfirmRefused("bad_key_file", path);
  }
  const record = parsed as Record<string, unknown>;
  const publicKey = record["public_key"];
  const privateKey = record["private_key_pkcs8"];
  if (typeof publicKey !== "string" || typeof privateKey !== "string") {
    throw new ConfirmRefused("bad_key_file", path);
  }
  const agentId = record["agent_id"];
  return {
    agent_id: typeof agentId === "string" ? agentId : null,
    public_key: publicKey,
    private_key_pkcs8: privateKey,
  };
}

/** The entry object the entry door answered, or a refusal naming the id. */
function entryOf(status: number, body: unknown, entryId: string): Record<string, unknown> {
  if (status !== 200 || typeof body !== "object" || body === null) {
    throw new ConfirmRefused("unknown_entry", entryId);
  }
  return body as Record<string, unknown>;
}

/** A string field off the entry, or null. */
function field(entry: Record<string, unknown>, name: string): string | null {
  const value = entry[name];
  return typeof value === "string" ? value : null;
}

/**
 * Compose the comment line: the canonical line, the signature when there is
 * one, and the reason when there is one, in that order and no other.
 *
 * The order is the parser's (src/confirm.ts): a `sig:` token is always the last
 * token and always before the free text, so a line composed here is a line the
 * door reads back the way it was meant.
 */
export function commentLine(
  canonical: string,
  signature: string | null,
  reason: string | null,
): string {
  const signed =
    signature === null
      ? canonical
      : `${canonical} ${CONFIRMATION_SIGNATURE_TOKEN_PREFIX}${signature}`;
  return reason === null || reason === "" ? signed : `${signed} ${reason}`;
}

/**
 * Whether this venue and this key belong together, as a posting confirmer's
 * command asks it.
 *
 * A profile venue binds through a key the confirmer publishes, so there has to
 * be one; a registry venue binds through the registry's own log, so a key
 * handed to it would be a key doing nothing, which is worse than no key at all
 * — the confirmer would believe they had signed something.
 *
 * The command's rule and not the composer's: a caller that only wants to see
 * the line a venue takes (the MCP server's `confirm_line`, which holds no key
 * and must not) composes it unsigned and says so.
 */
export function checkKeyForVenue(
  venue: ConfirmationVenue,
  key: ConfirmKey | null,
): void {
  if (venue.binding === "profile" && key === null) {
    throw new ConfirmRefused("key_required", venue.venue);
  }
  if (venue.binding !== "profile" && key !== null) {
    throw new ConfirmRefused("key_unused", venue.venue);
  }
}

/** The profile line a `profile` venue's bio carries. */
export function profileLine(publicKey: string): string {
  return `${PROFILE_KEY_PREFIX}${publicKey}`;
}

/** The confirmer's own signature over the canonical line, base64url. */
export async function signCanonicalLine(
  key: ConfirmKey,
  canonical: string,
): Promise<string> {
  let privateKey;
  try {
    privateKey = await importPrivateKeyPkcs8(
      base64urlDecode(key.private_key_pkcs8),
    );
  } catch {
    throw new ConfirmRefused("bad_key_file", "private_key_pkcs8");
  }
  return base64urlEncode(
    await signBytes(privateKey, new TextEncoder().encode(canonical)),
  );
}

/** The seal request a citizen posts for this fingerprint. */
export function sealRequestFor(
  venue: ConfirmationVenue,
  fingerprint: string,
): SealRequest {
  const hex = fingerprint.startsWith("sha256:")
    ? fingerprint.slice("sha256:".length)
    : fingerprint;
  return {
    method: "POST",
    url: new URL("/api/seal", venue.origin).toString(),
    body: {
      hash: hex,
      label: SEAL_LABEL,
      // Not made here: the citizen's own key makes it, under the citizen's own
      // credential, and this command holds neither. What is printed is what
      // that signature is over.
      signature: "<the citizen's Ed25519 signature over signature_preimage>",
    },
    signature_preimage: `${SEAL_TAG}:<handle>:${SEAL_LABEL}:${hex}`,
  };
}

/**
 * Check one entry and compose the line that says what was found.
 *
 * The fetch is the confirmer's own, through the same adapter and the same norm
 * rule the validator runs: a confirmation whose check was made some other way
 * would be a confirmation of a different question.
 */
export async function prepareConfirmation(
  request: ConfirmRequest,
  deps: {
    readonly get: (path: string) => Promise<{ status: number; body: unknown }>;
    readonly fetcher?: SnapshotFetcher;
  },
): Promise<ConfirmResult> {
  const venue = venueByName(request.venue);

  if (request.reason !== null) {
    if (request.reason.length > CONFIRMATION_REASON_MAX_CHARS) {
      throw new ConfirmRefused(
        "reason_too_long",
        `${request.reason.length} characters; the door keeps ${CONFIRMATION_REASON_MAX_CHARS}`,
      );
    }
    if (hasEmailAddress(request.reason)) {
      throw new ConfirmRefused("reason_has_email", null);
    }
  }

  const answer = await deps.get(
    `/entries/${encodeURIComponent(request.entryId)}`,
  );
  const entry = entryOf(answer.status, answer.body, request.entryId);
  const entryId = field(entry, "id") ?? request.entryId;

  const citation = field(entry, "citation");
  if (citation === null) throw new ConfirmRefused("no_citation", entryId);
  const entryHash = field(entry, "snapshot_hash") ?? "";

  const fetcher = deps.fetcher ?? new WebFetcher();
  const fetched = await fetcher.fetch(citation);
  if (!fetched.ok) {
    throw new ConfirmRefused("unreachable_source", `${citation}: ${fetched.reason}`);
  }
  const hashed = await snapshotHash(
    fetched.bytes,
    fetched.headers["content-type"] ?? null,
  );
  if (!hashed.ok) {
    throw new ConfirmRefused("unreachable_source", `${citation}: ${hashed.reason}`);
  }
  const ownHash = hashed.hash;

  // The validator's own reading of "verbatim": both sides in the norm rule's
  // spelling, the capture because `snapshotHash` extracted and normalized it
  // and the claim because it goes through the same `normalizeText`.
  const claim = field(entry, "claim");
  const wanted = claim === null ? "" : normalizeText(claim);
  const spanPresent =
    hashed.extracted !== null && wanted.length > 0
      ? hashed.extracted.includes(wanted)
      : false;

  // Exhaustive on the three words and never on "not hash": the type says there
  // are three, and a fourth reaching here is a caller that got past its own
  // narrowing, which is a bug to name rather than a line to compose.
  const word: CheckWord = request.check ?? "hash";
  let check: ConfirmationCheck;
  let reproduced: boolean;
  if (word === "hash") {
    check = { kind: "hash", value: ownHash };
    reproduced = ownHash === entryHash;
  } else if (word === "span-present") {
    check = { kind: "span", value: "present" };
    reproduced = spanPresent;
  } else if (word === "span-absent") {
    check = { kind: "span", value: "absent" };
    reproduced = !spanPresent;
  } else {
    throw new ConfirmRefused("unknown_check", String(word));
  }

  const verdict: ConfirmationVerdict =
    request.verdict ?? (reproduced ? "approve" : "reject");

  const line = {
    entry_id: entryId,
    verdict,
    check,
    attestation_version: request.attest ? ATTESTATION_VERSION : null,
  };
  const canonical = canonicalConfirmationLine(line);

  const signature =
    request.key === null
      ? null
      : await signCanonicalLine(request.key, canonical);
  const fingerprint =
    venue.binding === "profile" ? null : await confirmationFingerprint(line);

  return {
    entry_id: entryId,
    venue: venue.venue,
    binding: venue.binding,
    verdict,
    check,
    forced: request.verdict !== null,
    reproduced,
    own_hash: ownHash,
    entry_hash: entryHash,
    canonical_line: canonical,
    comment_line: commentLine(canonical, signature, request.reason),
    profile_line:
      request.key === null ? null : profileLine(request.key.public_key),
    fingerprint,
    seal_request:
      fingerprint === null ? null : sealRequestFor(venue, fingerprint),
  };
}
