/**
 * Submit: naming an entry, building the core its author signs, and the gate the
 * log puts in front of a submission.
 *
 * Whitepaper Section 6, "Submit": an agent posts a signed entry; the source is
 * snapshotted at the moment of submission and its normalized hash frozen into
 * the record. Two halves of that sentence live here, and nothing else does.
 *
 * `buildSubmittedCore` is the client-side half, run before signing: it fills in
 * the fields the submitter does not choose — the id, the submission time, the
 * norm version in force, the default tier — so that every one of the eighteen
 * core keys is present and the JCS canonical form the author signs is
 * unambiguous. It never signs; the key stays with the caller.
 *
 * `checkSubmission` is the server-side half, run before anything is written: it
 * says whether a signed core may enter the log at all. It is synchronous and
 * takes a data-only context, so the route computes the expected id (which needs
 * a hash, and so an await) and hands it in.
 *
 * What is deliberately not here: signing (src/sign.ts), signature verification
 * (src/sign.ts), schema validation (src/schema.ts), supersession (src/
 * supersede.ts), fetching and hashing the citation (src/normalize.ts), and every
 * form of storage. The Worker route does those around this module. Nothing here
 * reads the clock, the network, or the disk, and no policy number is written
 * here: every number comes from src/policy.ts.
 */

import type { Core } from "./core.js";
import type { Clock } from "./derive.js";
import {
  checkCoreEvidence,
  isTranscriptCategory,
  type CoreEvidenceRefusal,
  type EvidenceTier,
} from "./evidence.js";
import { canonicalize, taggedSha256Hex } from "./hash.js";
import {
  isDomainCategory,
  isRegisteredDomain,
  NORM_VERSION,
  REQUEST_CLOCK_SKEW_SECONDS,
} from "./policy.js";
import { checkSource, type SourceRefusal } from "./sources.js";

/**
 * Domain-separation tag for the entry id. A format constant, not a policy
 * number: it names the hash construction, and changing it renames every entry
 * rather than moving a published amount.
 */
export const HASH_TAG_ENTRY_ID = "nomankind-entry-id-v1";

/**
 * The number of hex characters of the tagged digest an id carries. A format
 * constant: 128 bits, wide enough that two distinct cores never collide by
 * accident, short enough to read out loud.
 */
const ID_HEX_LENGTH = 32;

/** The prefix the schema's id pattern requires (`^nmk_[A-Za-z0-9]+$`). */
const ID_PREFIX = "nmk_";

/**
 * The id a core names itself by: `nmk_` and the first 32 hex characters of the
 * tagged SHA-256 over the JCS canonical form of the core with `id` set to null.
 *
 * The id is a function of the signed content and of nothing else, so the same
 * claim, cited the same way, by the same author, at the same instant, always
 * names the same entry: a resubmission is recognisable as the one it repeats
 * rather than landing as a second entry. `id` is nulled rather than dropped
 * because the core is always seventeen keys; leaving it out would hash a shape
 * that never exists.
 */
export async function entryIdFor(core: Core): Promise<string> {
  const digest = await taggedSha256Hex(
    HASH_TAG_ENTRY_ID,
    canonicalize({ ...core, id: null }),
  );
  return `${ID_PREFIX}${digest.slice(0, ID_HEX_LENGTH)}`;
}

/**
 * What a submitter chooses: the core, less the three fields submission itself
 * fills in (`id`, `submitted_at`, `norm_version`).
 *
 * `evidence_tier` is optional because the schema says stated is "the default the
 * submit tool fills in"; supply it to override the default. The four nullable
 * core keys are optional too and become explicit nulls.
 */
export interface SubmissionProposal {
  readonly subject: string;
  readonly category: string;
  /**
   * The registered domain the fact belongs to. Required and never defaulted:
   * the domain is part of the signed core, so it is the author's own assertion
   * about where the fact is filed and not something a tool fills in for them
   * (decision D-071).
   */
  readonly domain: string;
  readonly claim: string;
  readonly before: string;
  readonly after: string;
  readonly effective_at: string;
  readonly evidence_tier?: EvidenceTier;
  readonly evidence?: unknown;
  readonly observation?: unknown;
  readonly citation: string;
  readonly snapshot_hash: string;
  readonly supersedes?: string | null;
  readonly author: string;
  readonly author_operator?: string | null;
}

/** A nullable core value: absent and undefined alike become an explicit null. */
function orNull(value: unknown): unknown {
  return value === undefined ? null : value;
}

/**
 * The tier an entry earns when its submitter names none.
 *
 * Whitepaper Section 4: behavior and misbehavior are always observed, and they
 * carry their measurement as a frozen transcript in `evidence`. Every other
 * category that carries an `observation` rests on a measurement too, and so is
 * observed as well; a category with neither rests on the cited document, and is
 * stated.
 */
function defaultTier(proposal: SubmissionProposal): EvidenceTier {
  if (
    isRegisteredDomain(proposal.domain) &&
    isTranscriptCategory(proposal.domain, proposal.category)
  ) {
    return "observed";
  }
  return orNull(proposal.observation) === null ? "stated" : "observed";
}

/**
 * Build the core the author is about to sign, from what the submitter chose.
 *
 * Returns all eighteen keys in the schema's order, with the four nullable ones
 * explicitly null when absent. `submitted_at` is the injected clock and nothing
 * else, `norm_version` is the version in force from policy (the kernel
 * implements exactly one), and `id` is derived from the finished core, so the
 * name and the content can never disagree.
 *
 * An `evidence_tier` the submitter supplied is kept exactly as given, even where
 * the default would differ: the tier is part of the signed core and is the
 * submitter's assertion, which the validators then check.
 */
export async function buildSubmittedCore(
  proposal: SubmissionProposal,
  clock: Clock,
): Promise<Core> {
  const core: Core = {
    id: null,
    subject: proposal.subject,
    category: proposal.category,
    domain: proposal.domain,
    claim: proposal.claim,
    before: proposal.before,
    after: proposal.after,
    effective_at: proposal.effective_at,
    evidence_tier: proposal.evidence_tier ?? defaultTier(proposal),
    evidence: orNull(proposal.evidence),
    observation: orNull(proposal.observation),
    citation: proposal.citation,
    snapshot_hash: proposal.snapshot_hash,
    norm_version: NORM_VERSION,
    supersedes: orNull(proposal.supersedes),
    author: proposal.author,
    author_operator: orNull(proposal.author_operator),
    submitted_at: clock.now,
  };
  return { ...core, id: await entryIdFor(core) };
}

/** Every reason a submission can be refused at the door. */
export type SubmissionRefusal =
  | "bad_id"
  | "bad_norm_version"
  | "missing_domain"
  | "unregistered_domain"
  | "category_not_in_domain"
  | SourceRefusal
  | "bad_submitted_at"
  | "author_mismatch"
  | "author_operator_mismatch"
  | CoreEvidenceRefusal;

/** Every refusal, in check order: the first one wins. */
export const SUBMISSION_REFUSALS: readonly SubmissionRefusal[] = Object.freeze([
  "bad_id",
  "bad_norm_version",
  "missing_domain",
  "unregistered_domain",
  "category_not_in_domain",
  "unknown_provider",
  "source_not_official",
  "bad_submitted_at",
  "author_mismatch",
  "author_operator_mismatch",
  "provider_statement_mismatch",
  "no_predicate",
] as const);

/**
 * What the route knows about the request the core arrived on. Data only, so the
 * gate stays synchronous and testable: `expectedId` is `entryIdFor(core)`,
 * computed by the caller because hashing is asynchronous.
 */
export interface SubmissionContext {
  /** The verifier's clock, as an ISO 8601 date-time. */
  readonly now: string;
  /** The agent id the signed request authenticated as (D-014). */
  readonly requestAgent: string;
  /** The operator behind that key at submission; null for a bare key. */
  readonly authorOperator: string | null;
  /** `entryIdFor(core)`, computed by the caller. */
  readonly expectedId: string;
}

/** Accepted, or refused with the one reason that decided it. */
export type SubmissionVerdict =
  | { ok: true }
  | { ok: false; reason: SubmissionRefusal };

/** ISO 8601 date-time with a seconds field and an explicit offset or Z. */
const ISO_DATE_TIME =
  /^\d{4}-\d{2}-\d{2}[Tt]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:[Zz]|[+-]\d{2}:\d{2})$/;

/** The instant a date-time names, or NaN when it names none. */
function instant(value: unknown): number {
  if (typeof value !== "string" || !ISO_DATE_TIME.test(value)) {
    return Number.NaN;
  }
  return Date.parse(value);
}

/**
 * The gate a submission passes before anything is written.
 *
 * In order, first refusal winning:
 *
 * bad_id: the core does not name itself. The id is derived from the signed
 * content, so a mismatch means the name and the bytes disagree.
 *
 * bad_norm_version: the core was normalized under some other rule version. The
 * kernel implements exactly one, and an entry is refused rather than checked
 * against rules it never claimed.
 *
 * missing_domain: a seventeen-key core, sealed under schema v0.6. Such a core is
 * still served, listed and synced exactly as it always was, but nothing new
 * enters the log without naming its domain: a new entry is a v0.7 entry.
 *
 * unregistered_domain: a slug no domain registry entry names
 * (schema/nomankind-domain-registry-v1.md). A domain is added by decision, never
 * by a submission that invents one.
 *
 * category_not_in_domain: a category the schema's union enum holds but this
 * domain does not admit. The schema cannot express a per-domain enum, so this is
 * where that rule is actually enforced.
 *
 * unknown_provider and source_not_official: the source policy (decision D-080,
 * src/sources.ts). A category with an authoritative source by nature -- pricing,
 * limit, deprecation, release, outage -- must cite the subject's own official
 * source. The subject's provider must have a published row, and the citation
 * must be one of its hosts over https. A correction entry is a submission like
 * any other and passes here too -- under its own category, which no domain
 * requires an official source for, so nothing here gates it. What makes a
 * correction of a pricing claim cite the official source a pricing claim does is
 * the dispute door's own second call, against the challenged entry's category
 * (src/worker/dispute.ts).
 *
 * Both are checked here rather than at derivation because they are the one part
 * of the policy that is a gate: an entry that fails them never enters the log,
 * which is what stops a site made yesterday from carrying a pricing claim to
 * verified. Everything else the policy says is a label the sidecar publishes.
 *
 * bad_submitted_at: not a date-time at all, or further from the verifier's clock
 * than the skew window allows, in either direction. The paper has the source
 * snapshotted at the moment of submission, so a submission time far from now
 * describes a capture that is not this one.
 *
 * author_mismatch: the signed request came from some other key than the entry's
 * author. The author field is the claim about who made the claim.
 *
 * author_operator_mismatch: the entry names an operator the registry does not
 * put behind this key at submission (null for a bare key, on both sides).
 *
 * Then the two evidence-shape verdicts of src/evidence.ts, passed through under
 * their own names: provider_statement_mismatch and no_predicate.
 *
 * Not checked here, on purpose: the signature (src/sign.ts), the schema (src/
 * schema.ts), the supersession link (src/supersede.ts), and whether the
 * snapshot_hash matches a fresh capture of the citation (src/normalize.ts). The
 * Worker route runs those around this call.
 */
export function checkSubmission(
  core: Core,
  context: SubmissionContext,
): SubmissionVerdict {
  if (core.id !== context.expectedId) {
    return { ok: false, reason: "bad_id" };
  }
  if (core.norm_version !== NORM_VERSION) {
    return { ok: false, reason: "bad_norm_version" };
  }

  if (core.domain === undefined) {
    return { ok: false, reason: "missing_domain" };
  }
  if (!isRegisteredDomain(core.domain)) {
    return { ok: false, reason: "unregistered_domain" };
  }
  if (!isDomainCategory(core.domain, core.category)) {
    return { ok: false, reason: "category_not_in_domain" };
  }

  const source = checkSource(
    core.domain,
    core.category,
    core.subject,
    core.citation,
  );
  if (!source.ok) {
    return { ok: false, reason: source.reason };
  }

  const submittedAt = instant(core.submitted_at);
  const now = instant(context.now);
  if (Number.isNaN(submittedAt) || Number.isNaN(now)) {
    return { ok: false, reason: "bad_submitted_at" };
  }
  if (Math.abs(now - submittedAt) / 1000 > REQUEST_CLOCK_SKEW_SECONDS) {
    return { ok: false, reason: "bad_submitted_at" };
  }

  if (core.author !== context.requestAgent) {
    return { ok: false, reason: "author_mismatch" };
  }
  if (core.author_operator !== context.authorOperator) {
    return { ok: false, reason: "author_operator_mismatch" };
  }

  return checkCoreEvidence(core);
}
