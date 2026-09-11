/**
 * The submit routes: the door an entry comes in through, and the two reads that
 * show what came in with it.
 *
 * Whitepaper Section 6, "Submit": "An agent signs and submits an entry with a
 * citation. The source is snapshotted and hashed at that moment. The entry
 * appears immediately, marked draft." Section 5: "Anyone can submit with a bare
 * agent key." Both sentences are this file. The signature proves who is
 * speaking; an unregistered key is refused nothing, and its entry simply carries
 * a null author_operator, signed by the author like every other core field.
 *
 * The snapshot is taken here and now, by us, under the norm rule the entry
 * names: the submitter's snapshot_hash is checked against a capture this Worker
 * fetched, and an entry whose hash does not match the page it cites never
 * enters the log. The raw capture and its sidecar go into the archive as
 * evidence, which is what makes the hash checkable years later by someone who
 * was not here.
 *
 * Order matters and is deliberate. Structure, then the author's signature, then
 * the cheap data checks, then the store, then the one step that reaches outside
 * this process, and only then derivation, the schema, and the write. Nothing is
 * written until every check has passed: a refusal leaves the log exactly where
 * it was, and a refused entry is not a draft entry.
 *
 * Status is never set here. The entry that is stored is exactly what
 * src/derive.ts produced from the events, and it is draft because a fresh log
 * has no validations in it, not because this file said so.
 *
 * No policy number lives here: the bare integers are HTTP status codes, and
 * every amount the capture obeys is src/policy.ts's, applied in
 * src/adapters/fetch.ts. Both patterns below are read out of the entry schema
 * rather than copied into TypeScript.
 */

import entrySchema from "../../schema/nomankind-entry-schema.json" with { type: "json" };

import type { SnapshotFetcher } from "../adapters/fetch.js";
import {
  buildTranscriptArtifact,
  checkReceiptArtifact,
  checkTranscriptRedaction,
  disclosurePlaceholders,
  receiptArtifactHash,
  transcriptArtifactHash,
} from "../artifact.js";
import { CORE_KEYS, domainOf, extractCore, type Core } from "../core.js";
import { deriveEntry, type DerivedEntry } from "../derive.js";
import { checkDuplicate, type DuplicateCandidate } from "../duplicate.js";
import { appendEvent, type Event } from "../events.js";
import { isTranscriptCategory } from "../evidence.js";
import { canonicalize, sha256Hex } from "../hash.js";
import { archiveAddress, mediaType, snapshotHash } from "../normalize.js";
import {
  disclosureWindowDays,
  isDisclosureCategory,
  LIST_PAGE_LIMIT,
} from "../policy.js";
import { withholdEntry } from "../release.js";
import { validateEntry } from "../schema.js";
import { verifyEntrySignature } from "../sign.js";
import type { D1Like } from "../storage/d1.js";
import {
  EventAppendError,
  capturesForHash,
  eventBySeq,
  eventsForEntry,
  entriesNewestFirst,
  getEntry,
  headSeq,
  operatorForAgent,
  submitEntry,
  type CaptureRecord,
  type StoredEntry,
} from "../storage/repository.js";
import {
  archiveCapture,
  readCapture,
  readSidecar,
  type R2Like,
  type Sidecar,
} from "../storage/r2.js";
import { checkSubmission, entryIdFor } from "../submit.js";
import { checkSupersedes } from "../supersede.js";
import { readerAccess, type ReaderAccess } from "./access.js";
import type { Env } from "./env.js";
import { entryRelease, refusalResponse } from "./read.js";
import {
  StorageUnreachable,
  authenticate,
  guardDatabase,
  json,
  methodNotAllowed,
  refuse,
} from "./registry.js";

/**
 * What these routes are given besides their bindings: the instant this request
 * is being served at, and the way out to the network. Both injected, so a test
 * drives the real router with a fixed clock and a fixture page, and so nothing
 * under src/ reads a clock or reaches the internet of its own accord.
 */
export interface SubmitDeps {
  readonly now: Date;
  readonly fetcher: SnapshotFetcher;
}

/** The schema's own id and hash patterns. The schema is the only source. */
const ENTRY_ID_PATTERN = new RegExp(entrySchema.properties.id.pattern);
const HASH_PATTERN = new RegExp(entrySchema.properties.snapshot_hash.pattern);

/** The archive's own suffix on the capture route. */
const SIDECAR_PATH = "/sidecar";

/** The prefix an archive address carries before its hex. */
const HASH_PREFIX = "sha256:";

/**
 * The headers that make an archived capture inert in a browser.
 *
 * Section 5 lets anyone submit with a bare agent key, and step 2 of the norm
 * rule archives the raw response body, so an HTML capture is a stranger's
 * script sitting at our own origin. The stored media type is still served,
 * because a reader checking a hash needs to know what the bytes claim to be;
 * these three say the bytes are a download and not a page, that the type on
 * them is the last word, and that nothing in them may run or load anything.
 */
const CAPTURE_INERT_HEADERS: Readonly<Record<string, string>> = Object.freeze({
  "x-content-type-options": "nosniff",
  "content-security-policy": "default-src 'none'; sandbox",
});

/** An archive address as a filename: its hex, without the algorithm prefix. */
function archiveFilename(archiveHash: string): string {
  return archiveHash.startsWith(HASH_PREFIX)
    ? archiveHash.slice(HASH_PREFIX.length)
    : archiveHash;
}

const encoder = new TextEncoder();

/** The media type an artifact is archived under: it is JSON, canonically. */
const ARTIFACT_MEDIA_TYPE = "application/json";

/** What a body with no usable Content-Type is stored as. */
const UNKNOWN_MEDIA_TYPE = "application/octet-stream";

// ---------------------------------------------------------------------------
// The archive boundary
// ---------------------------------------------------------------------------

/**
 * A call into R2 threw.
 *
 * The registry answers 503 rather than 500 when D1 does not answer, and these
 * routes owe a caller the same for the archive: a bucket that is unreachable is
 * our outage, not the submitter's mistake. Marked where it happens, for the
 * same reason StorageUnreachable is: a TypeError from our own reading of what
 * R2 returned stays a bug of ours and still reaches the platform as a 500.
 */
export class ArchiveUnreachable extends Error {
  constructor(reason: unknown) {
    super(reason instanceof Error ? reason.message : String(reason));
    this.name = "ArchiveUnreachable";
  }
}

/** Run an archive call, marking anything it throws as an archive failure. */
async function throughArchive<T>(call: () => Promise<T>): Promise<T> {
  try {
    return await call();
  } catch (error) {
    throw new ArchiveUnreachable(error);
  }
}

// ---------------------------------------------------------------------------
// Reading the body
// ---------------------------------------------------------------------------

/** A submission's body: the signed entry, the receipt and the disclosure. */
interface SubmitBody {
  readonly entry: Record<string, unknown>;
  readonly receipt: Record<string, unknown> | undefined;
  /**
   * The original values a redacted transcript's placeholders stand for, keyed
   * by RFC 6901 pointer (decision D-096). Undefined for every submission that
   * redacts nothing, which is every submission before this milestone.
   */
  readonly disclosure: Record<string, unknown> | undefined;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/**
 * The wire shape of a submission, checked before anything is read out of it.
 *
 * The entry carries exactly the seventeen core keys and the signature: no
 * derived field, no approvers, nothing extra. A submitter does not get to
 * propose a status, and an entry that arrived with one would be an entry whose
 * author signed something other than what it says.
 */
function parseSubmitBody(body: unknown): SubmitBody | null {
  if (!isRecord(body)) return null;
  for (const key of Object.keys(body)) {
    if (key !== "entry" && key !== "receipt" && key !== "disclosure") return null;
  }

  const entry = body["entry"];
  if (!isRecord(entry)) return null;
  const expected = new Set<string>([...CORE_KEYS, "signature"]);
  const present = Object.keys(entry);
  if (present.length !== expected.size) return null;
  for (const key of present) {
    if (!expected.has(key)) return null;
  }
  if (typeof entry["signature"] !== "string") return null;

  let receipt: Record<string, unknown> | undefined;
  if ("receipt" in body) {
    const value = body["receipt"];
    if (!isRecord(value)) return null;
    receipt = value;
  }

  let disclosure: Record<string, unknown> | undefined;
  if ("disclosure" in body) {
    const value = body["disclosure"];
    if (!isRecord(value)) return null;
    disclosure = value;
  }

  return { entry, receipt, disclosure };
}

// ---------------------------------------------------------------------------
// The capture a submission rests on
// ---------------------------------------------------------------------------

/** One capture, ready for the archive and for its row. */
export interface PreparedCapture {
  readonly role: CaptureRecord["role"];
  readonly contentHash: string;
  readonly archiveHash: string;
  readonly kind: string;
  readonly mediaType: string;
  readonly bytes: Uint8Array;
  readonly sidecar: Sidecar;
}

/** A prepared capture, or the reason the source could not be pinned. */
type CaptureAttempt =
  | { ok: true; capture: PreparedCapture }
  | { ok: false; reason: string };

/**
 * The sidecar of something that was never fetched.
 *
 * A deviation from the norm rule, documented in src/storage/r2.ts: the rule
 * writes a sidecar for a fetched page, and an artifact is evidence that was
 * computed rather than retrieved. It goes to the archive at its own address
 * with a sidecar that says so, because a record saying "nobody fetched this" is
 * truer than no record.
 */
function unfetchedSidecar(at: string, fetcher: string): Sidecar {
  return {
    final_url: null,
    status: null,
    headers: {},
    fetched_at: at,
    fetcher,
  };
}

/** The canonical UTF-8 bytes of an artifact: exactly what its hash covers. */
function artifactBytes(artifact: unknown): Uint8Array {
  return encoder.encode(canonicalize(artifact));
}

/**
 * The snapshot of a behavior or misbehavior entry.
 *
 * The norm rule: for these two categories the snapshot_hash is over the frozen
 * transcript artifact, not over a page, so there is nothing to fetch. The
 * artifact is rebuilt from the entry's own evidence and its hash has to be the
 * hash the author signed; the canonical bytes of it are then the capture, so
 * the measurement the claim rests on is in the archive beside every other kind
 * of evidence.
 */
async function transcriptCapture(
  core: Core,
  at: string,
  fetcher: string,
): Promise<CaptureAttempt> {
  const evidence = isRecord(core["evidence"]) ? core["evidence"] : {};
  const artifact = buildTranscriptArtifact(
    evidence,
    evidence["output"] as string,
    evidence["observed_at"] as string,
  );
  // Decision D-096: a placeholder object may stand inside the artifact's
  // request, and only where the entry's own domain published a disclosure rule
  // naming its category. Anywhere else it is the load-bearing redaction it has
  // always been, and the artifact is refused before it is hashed or archived.
  const redaction = checkTranscriptRedaction(artifact, {
    disclosure: isDisclosureCategory(domainOf(core), core["category"]),
  });
  if (!redaction.ok) return { ok: false, reason: redaction.reason };

  // The hash is over the artifact as submitted, placeholders included, so the
  // snapshot_hash the author signed verifies against the archived artifact
  // unchanged and the offline verifier never asks for the payload at all.
  const hashed = await transcriptArtifactHash(artifact);
  if (!hashed.ok) return { ok: false, reason: hashed.reason };
  if (hashed.hash !== core["snapshot_hash"]) {
    return { ok: false, reason: "snapshot_mismatch" };
  }

  const bytes = artifactBytes(artifact);
  return {
    ok: true,
    capture: {
      role: "snapshot",
      contentHash: hashed.hash,
      archiveHash: await archiveAddress(bytes),
      kind: "transcript",
      mediaType: ARTIFACT_MEDIA_TYPE,
      bytes,
      sidecar: unfetchedSidecar(at, fetcher),
    },
  };
}

/**
 * One page, pinned under the norm rule: steps 1 to 5 in order — fetch under the
 * fixed headers, keep the raw body, extract by media type, normalize, hash.
 *
 * The URL checks come first, so a citation that is not http(s) is refused
 * before the network is reached; then the fetch's own five refusals, unchanged;
 * then the rule's two, so a page that needs JavaScript or is not the JSON it
 * claims is refused with the rule's own reason and is never archived.
 *
 * No hash comparison lives here. What a caller does with the capture is the
 * caller's: the snapshot is compared against the hash the author signed, and
 * the provider statement is compared against nothing at all, because the author
 * signed no hash of it.
 */
async function capturedFromUrl(
  target: unknown,
  role: CaptureRecord["role"],
  deps: SubmitDeps,
  at: string,
  fetcher: string,
): Promise<CaptureAttempt> {
  if (typeof target !== "string") {
    return { ok: false, reason: "unsupported_citation" };
  }
  let url: URL;
  try {
    url = new URL(target);
  } catch {
    return { ok: false, reason: "unsupported_citation" };
  }
  if (url.protocol !== "http:" && url.protocol !== "https:") {
    return { ok: false, reason: "unsupported_citation" };
  }

  const fetched = await deps.fetcher.fetch(target);
  if (!fetched.ok) return { ok: false, reason: fetched.reason };

  const contentType = fetched.headers["content-type"] ?? null;
  const hashed = await snapshotHash(fetched.bytes, contentType);
  if (!hashed.ok) return { ok: false, reason: hashed.reason };

  return {
    ok: true,
    capture: {
      role,
      contentHash: hashed.hash,
      archiveHash: await archiveAddress(fetched.bytes),
      kind: hashed.kind,
      mediaType: mediaType(contentType) ?? UNKNOWN_MEDIA_TYPE,
      bytes: fetched.bytes,
      sidecar: {
        final_url: fetched.finalUrl,
        status: fetched.status,
        headers: fetched.headers,
        fetched_at: at,
        fetcher,
      },
    },
  };
}

/**
 * The snapshot of every other entry: the cited page, fetched now.
 *
 * The norm rule, and then the one comparison the whole route exists for: the
 * hash of what we just fetched against the hash the author signed.
 */
async function fetchedCapture(
  core: Core,
  deps: SubmitDeps,
  at: string,
  fetcher: string,
): Promise<CaptureAttempt> {
  const attempt = await capturedFromUrl(
    core["citation"],
    "snapshot",
    deps,
    at,
    fetcher,
  );
  if (!attempt.ok) return attempt;
  if (attempt.capture.contentHash !== core["snapshot_hash"]) {
    return { ok: false, reason: "snapshot_mismatch" };
  }
  return attempt;
}

/**
 * The provider statement a transcript entry points at, fetched now.
 *
 * Section 4 makes a provider's own statement the verification basis of a
 * behavior or misbehavior entry: an operator confirms the transcript against
 * what the provider published. The page that says it is a page, and pages
 * change — so it is captured at submit under the same norm rule as any
 * citation, and the capture is the record of what the statement said at the
 * moment the claim was made. Before this, a validator fetched what they were
 * checking, months later, and nobody could tell a changed page from a wrong
 * claim.
 *
 * There is no hash of it in the signed core, so there is no comparison and no
 * mismatch refusal: a statement capture can only fail the way any fetch fails.
 * It is a storage pointer like every other capture row — served by
 * GET /captures/{hash}, listed by capturesForEntry — and it goes into no
 * sidecar, no derived field and no event.
 *
 * When `provider_statement` is null there is nothing to fetch: the transcript
 * is the whole snapshot, as it was.
 */
async function statementCapture(
  core: Core,
  deps: SubmitDeps,
  at: string,
  fetcher: string,
): Promise<CaptureAttempt | null> {
  const evidence = isRecord(core["evidence"]) ? core["evidence"] : {};
  const statement = evidence["provider_statement"];
  if (typeof statement !== "string") return null;
  return capturedFromUrl(statement, "statement", deps, at, fetcher);
}

/**
 * The observation receipt of an observed entry outside the transcript
 * categories. The norm rule: "The raw receipt object is stored in the snapshot
 * archive at that hash. Storing it there is the application's step at submit
 * and validation time." This is that step.
 */
async function receiptCapture(
  core: Core,
  receipt: Record<string, unknown> | undefined,
  at: string,
  fetcher: string,
): Promise<CaptureAttempt> {
  if (receipt === undefined) return { ok: false, reason: "missing_receipt" };

  const check = checkReceiptArtifact(receipt);
  if (!check.ok) return { ok: false, reason: check.reason };
  const hashed = await receiptArtifactHash(receipt);
  if (!hashed.ok) return { ok: false, reason: hashed.reason };

  const observation = core["observation"] as Record<string, unknown>;
  if (hashed.hash !== observation["receipt_hash"]) {
    return { ok: false, reason: "receipt_mismatch" };
  }

  const bytes = artifactBytes(receipt);
  return {
    ok: true,
    capture: {
      role: "receipt",
      contentHash: hashed.hash,
      archiveHash: await archiveAddress(bytes),
      kind: "receipt",
      mediaType: ARTIFACT_MEDIA_TYPE,
      bytes,
      sidecar: unfetchedSidecar(at, fetcher),
    },
  };
}

/**
 * The transcript artifact of a core, rebuilt exactly as `transcriptCapture`
 * builds it, so the pointers a disclosure is checked against are pointers into
 * the object that was hashed and archived.
 */
function transcriptArtifactOf(core: Core): unknown {
  const evidence = isRecord(core["evidence"]) ? core["evidence"] : {};
  return buildTranscriptArtifact(
    evidence,
    evidence["output"] as string,
    evidence["observed_at"] as string,
  );
}

/** `sha256:` and the SHA-256 of the RFC 8785 canonical form of one value. */
async function jcsHash(value: unknown): Promise<string> {
  return `sha256:${await sha256Hex(canonicalize(value))}`;
}

/**
 * The delayed-disclosure payload of a redacted transcript, or the refusal that
 * stopped it (decision D-096).
 *
 * The body's `disclosure` maps each placeholder's RFC 6901 pointer to the
 * original value, and the two have to agree exactly: every placeholder needs
 * its pointer, and every pointer needs its placeholder -- a disclosure of
 * something the artifact never redacted is a value nobody asked for, archived
 * where a reader would take it for evidence. That, a `disclosure` on an entry
 * whose domain and category publish no disclosure rule, and a redaction with no
 * disclosure at all are all `disclosure_missing`; a value whose canonical hash
 * is not the one the placeholder committed to is `disclosure_mismatch`.
 *
 * Both are refused before anything is written and after the artifact checks, so
 * a submission that fails here leaves the log and the archive exactly where
 * they were.
 *
 * The payload is archived at its own content address, as every artifact is: the
 * canonical bytes, `application/json`, and the sidecar that says nobody fetched
 * it. Its capture row carries the role `disclosure`, which is what the read
 * gate below looks for.
 */
async function disclosureCapture(
  core: Core,
  transcript: boolean,
  disclosure: Record<string, unknown> | undefined,
  at: string,
  fetcher: string,
): Promise<
  { ok: true; capture: PreparedCapture | null } | { ok: false; reason: string }
> {
  const allowed = isDisclosureCategory(domainOf(core), core["category"]);
  const placeholders = transcript
    ? disclosurePlaceholders(transcriptArtifactOf(core))
    : [];

  if (placeholders.length === 0 || !allowed) {
    // Nothing was redacted, or nothing may be: a disclosure here discloses
    // nothing, and an entry that carried one meant something the log cannot
    // honour.
    if (disclosure !== undefined) return { ok: false, reason: "disclosure_missing" };
    return { ok: true, capture: null };
  }
  if (disclosure === undefined) {
    return { ok: false, reason: "disclosure_missing" };
  }

  const pointers = new Set(placeholders.map((each) => each.pointer));
  for (const pointer of Object.keys(disclosure)) {
    if (!pointers.has(pointer)) return { ok: false, reason: "disclosure_missing" };
  }
  for (const placeholder of placeholders) {
    if (!Object.prototype.hasOwnProperty.call(disclosure, placeholder.pointer)) {
      return { ok: false, reason: "disclosure_missing" };
    }
    const hash = await jcsHash(disclosure[placeholder.pointer]);
    if (hash !== placeholder.hash) {
      return { ok: false, reason: "disclosure_mismatch" };
    }
  }

  const bytes = artifactBytes(disclosure);
  const address = await archiveAddress(bytes);
  return {
    ok: true,
    capture: {
      role: "disclosure",
      contentHash: address,
      archiveHash: address,
      kind: "disclosure",
      mediaType: ARTIFACT_MEDIA_TYPE,
      bytes,
      sidecar: unfetchedSidecar(at, fetcher),
    },
  };
}

// ---------------------------------------------------------------------------
// POST /entries
// ---------------------------------------------------------------------------

/** The log's last event, or nothing when the log is empty. */
async function tail(db: D1Like): Promise<Event[]> {
  const head = await headSeq(db);
  if (head === null) return [];
  const event = await eventBySeq(db, head);
  return event === null ? [] : [event];
}

/**
 * One submission that has passed every check, ready to be archived and written.
 *
 * `event` is the `entry_submitted` sealed onto the head this request read, not
 * yet written; `derived` is what src/derive.ts made of a log holding it, already
 * past the published schema. The writer is the caller's: POST /entries stores it
 * with `submitEntry`, and the dispute door stores it with `recordDisputeFiling`
 * beside the challenge it is filed as.
 */
export interface PreparedSubmission {
  readonly core: Core;
  readonly id: string;
  readonly event: Event;
  readonly derived: DerivedEntry;
  readonly captures: readonly PreparedCapture[];
  /** The capture rows exactly as `submitEntry` takes them. */
  readonly captureRows: readonly CaptureRecord[];
  /** The instant every one of the above was built at. */
  readonly at: string;
}

/** A prepared submission, or the refusal that stopped it, ready to return. */
export type SubmissionAttempt =
  | { ok: true; prepared: PreparedSubmission }
  | { ok: false; response: Response };

/** One stored row in the shape `checkDuplicate` reads. */
function asCandidate(stored: StoredEntry): DuplicateCandidate {
  return {
    id: stored.entry["id"] as string,
    core: extractCore(stored.entry),
    status: String(stored.entry["status"]),
  };
}

/**
 * Every entry this core could be a duplicate of, newest submission first.
 *
 * The read is `entriesNewestFirst` rather than `readCandidates`: that one
 * answers reads and so returns `status = 'verified'` only, by design
 * (Section 8), while this door must also see the drafts, which hold their
 * claim just as much as a verified entry does.
 *
 * One page is not enough. A subject and category may hold more entries than a
 * page, and a truncated page would let the hundred-and-first duplicate through,
 * so this pages down by submitted_seq until the pages run out. It stops early
 * on the first page that yields a verdict: the candidates arrive newest first
 * and every page before this one was checked in the same order, so the match
 * found here is the newest live one holding the key, which is the entry the
 * submitter is told to look at. What is returned is everything read so far,
 * still in order, so the caller's own `checkDuplicate` reaches exactly that
 * entry and names it.
 *
 * Exported because the dispute door runs the same check at its own place in
 * its own order.
 */
export async function duplicateCandidates(
  db: D1Like,
  core: Core,
): Promise<DuplicateCandidate[]> {
  const seen: DuplicateCandidate[] = [];
  let beforeSubmittedSeq: number | undefined = undefined;

  for (;;) {
    const page = await entriesNewestFirst(db, {
      domain: domainOf(core),
      subject: core["subject"] as string,
      category: core["category"] as string,
      limit: LIST_PAGE_LIMIT,
      ...(beforeSubmittedSeq === undefined ? {} : { beforeSubmittedSeq }),
    });
    const candidates = page.map(asCandidate);
    seen.push(...candidates);

    if (page.length < LIST_PAGE_LIMIT) return seen;
    if (!checkDuplicate(core, candidates).ok) return seen;
    beforeSubmittedSeq = page[page.length - 1]!.submittedSeq;
  }
}

/**
 * The whole POST /entries pipeline, from the parsed body to a submission ready
 * to write.
 *
 * Whitepaper Section 6, "Dispute": "A challenge is itself an entry, in the
 * correction category ... It passes through the same validation process". The
 * word is *same*, so the dispute door does not get a second, thinner pipeline of
 * its own: it hands its correction entry to this function and gets back exactly
 * what POST /entries would have got, refusals included, in the same order.
 *
 * The order of the refusals, which is the order of what each one costs: the
 * author's signature, the kernel's submission checks (the source policy among
 * them, see below), the supersession checks, `duplicate_entry`,
 * `fetcher_not_configured`, the duplicate lookup (D-085), the capture of the
 * cited page under the norm rule, the receipt's shape, and the event and the
 * schema over the derived entry. Nothing is written and nothing is archived: a
 * refusal here leaves the log and the archive exactly where they were.
 *
 * `duplicate_entry` is one keyed read of this entry's own id and needs nothing
 * of the environment, so it keeps its place ahead of both: an entry the log
 * already holds is told so whatever else is true.
 *
 * `fetcher_not_configured` comes before the duplicate lookup because it is a
 * fact about the environment rather than about this claim: an environment
 * shaped like production, which can archive nothing, says so first and reads
 * no candidates.
 *
 * The source policy (decision D-080) needs nothing of its own here, which is the
 * point of putting it in `checkSubmission`: `unknown_authority` and
 * `source_not_official` are two more of that function's verdicts, refused in its
 * own order — after `category_not_in_domain`, before `bad_submitted_at` — and
 * mapped to 422 by the same rule every other verdict but `author_mismatch` is.
 * So a pricing claim citing a host nobody published is refused before the
 * citation is fetched, before the capture is taken, and before anything is
 * written. A dispute's correction entry comes through this same function and is
 * checked here the same way — but under its own category, `correction`, which no
 * domain requires an official source for, so this call passes it. The rule that
 * a challenge to an official-required claim cites an official source is the
 * dispute door's, run against the challenged entry's own domain and category
 * after the filing rules (src/worker/dispute.ts).
 *
 * `skipDuplicateCheck` is that same door's other exception: D-066 put
 * `dispute_open` ahead of everything a second challenge could be wrong about,
 * so the dispute door turns the duplicate lookup off here and runs it itself,
 * after its filing refusals, with `duplicateCandidates` over the same query.
 */
export async function prepareSubmission(
  env: Env,
  deps: SubmitDeps,
  requestAgent: string,
  raw: unknown,
  options: { readonly skipDuplicateCheck?: boolean } = {},
): Promise<SubmissionAttempt> {
  const refused = (response: Response): SubmissionAttempt => ({
    ok: false,
    response,
  });

  const body = parseSubmitBody(raw);
  if (body === null) return refused(refuse(400, "bad_body"));

  // The author's signature over the core, before anything else is believed.
  if (!(await verifyEntrySignature(body.entry))) {
    return refused(refuse(401, "bad_signature"));
  }

  const core = extractCore(body.entry);
  const at = deps.now.toISOString();
  const author = core["author"] as string;
  // Section 5: anyone can submit with a bare agent key, and null is then the
  // signed truth about who stands behind it.
  const authorOperator = await operatorForAgent(env.DB, author);

  const submission = checkSubmission(core, {
    now: at,
    requestAgent,
    authorOperator,
    expectedId: await entryIdFor(core),
  });
  if (!submission.ok) {
    // A key submitting in someone else's name was understood, and the answer is
    // still no; every other refusal is a well-formed request whose contents do
    // not hold up.
    const status = submission.reason === "author_mismatch" ? 403 : 422;
    return refused(refuse(status, submission.reason));
  }

  const id = core["id"] as string;

  const supersedes = core["supersedes"];
  let target: Core | null = null;
  if (typeof supersedes === "string") {
    const stored = await getEntry(env.DB, supersedes);
    target = stored === null ? null : extractCore(stored.entry);
  }
  const link = checkSupersedes(core, (entryId) =>
    entryId === supersedes ? target : null,
  );
  if (!link.ok) return refused(refuse(422, link.reason));

  // An id the log already holds. One keyed read about this request alone, so
  // it comes before the environment's own answer and before any candidate is
  // read: a resubmission of a sealed entry is told so whatever else is true.
  if ((await getEntry(env.DB, id)) !== null) {
    return refused(refuse(409, "duplicate_entry"));
  }

  // The sidecar names the 1F916 identity that fetched, and ours is the
  // maintainer's own key (D-016). An unconfigured maintainer cannot sign the
  // provenance of a capture, so it does not take one: production says so and
  // refuses rather than archiving evidence nobody stands behind.
  //
  // Before the duplicate lookup, because a log that cannot take a capture at
  // all has nothing to say about this particular claim: an environment shaped
  // like production answers 503 first, whatever the claim is.
  const fetcher = env.MAINTAINER_AGENT_ID;
  if (fetcher === "") return refused(refuse(503, "fetcher_not_configured"));

  // The same fact filed twice (decision D-085). After the refusals that need
  // no read and before anything is fetched or archived, because a duplicate
  // that costs the log a capture has already cost it something.
  //
  // The entries checked against are this core's own domain, subject and
  // category — the rest of the key is the normalized value, compared in
  // src/duplicate.ts — read newest first and paged to the end by
  // `duplicateCandidates` above, so a subject with more live entries than one
  // page cannot hide one.
  //
  // The dispute door hands its correction entry to this same function, but
  // with `skipDuplicateCheck`: its own filing refusals are older than this one
  // (D-066 put `dispute_open` ahead of everything a second challenge could be
  // wrong about), so it runs the same check itself, after them.
  if (!options.skipDuplicateCheck) {
    const duplicate = checkDuplicate(
      core,
      await duplicateCandidates(env.DB, core),
    );
    if (!duplicate.ok) {
      return refused(
        json(
          { error: duplicate.reason, duplicate_of: duplicate.duplicate_of },
          422,
        ),
      );
    }
  }

  // Which categories carry a transcript is the entry's own domain's table
  // (decision D-071), read off the signed core rather than off a global.
  const transcript = isTranscriptCategory(domainOf(core), core["category"]);
  const snapshot = transcript
    ? await transcriptCapture(core, at, fetcher)
    : await fetchedCapture(core, deps, at, fetcher);
  if (!snapshot.ok) return refused(refuse(422, snapshot.reason));
  const captures: PreparedCapture[] = [snapshot.capture];

  // The provider statement, after the transcript is accepted and before the
  // receipt, and like every other refusal here before anything is written. The
  // dispute door comes through this same function, and a correction's category
  // is never a transcript category, so a challenge reaches neither branch.
  if (transcript) {
    const statement = await statementCapture(core, deps, at, fetcher);
    if (statement !== null) {
      if (!statement.ok) return refused(refuse(422, statement.reason));
      captures.push(statement.capture);
    }
  }

  if (core["observation"] !== null) {
    const receipt = await receiptCapture(core, body.receipt, at, fetcher);
    if (!receipt.ok) return refused(refuse(422, receipt.reason));
    captures.push(receipt.capture);
  } else if (body.receipt !== undefined) {
    // A receipt with nothing to receipt: the core says this entry rests on a
    // document, and an unreferenced artifact would enter the archive attached
    // to nothing.
    return refused(refuse(400, "bad_body"));
  }

  // Decision D-096: the originals behind a redacted transcript's placeholders.
  // After the artifact checks and before any write, so a submission refused
  // here archives nothing at all.
  const disclosure = await disclosureCapture(
    core,
    transcript,
    body.disclosure,
    at,
    fetcher,
  );
  if (!disclosure.ok) return refused(refuse(422, disclosure.reason));
  if (disclosure.capture !== null) captures.push(disclosure.capture);

  // The would-be event, built on the current head but not yet written, so the
  // entry can be derived and validated exactly as it will be stored.
  const previous = await tail(env.DB);
  const appended = await appendEvent(previous, {
    at,
    type: "entry_submitted",
    entry_id: id,
    payload: { core, signature: body.entry["signature"] as string },
  });
  const event = appended[appended.length - 1]!;
  const events = [...(await eventsForEntry(env.DB, id)), event];
  const derived = deriveEntry(events, id, { now: at });

  // The whole object, against the schema, before any write. An entry that does
  // not validate is not stored and its capture is not archived.
  const validation = validateEntry(derived.entry);
  if (!validation.ok) {
    return refused(json({ error: "schema_invalid", errors: validation.errors }, 422));
  }

  return {
    ok: true,
    prepared: {
      core,
      id,
      event,
      derived,
      captures,
      captureRows: captures.map((capture) => ({
        entryId: id,
        role: capture.role,
        contentHash: capture.contentHash,
        archiveHash: capture.archiveHash,
        normVersion: core["norm_version"] as string,
        kind: capture.kind,
        mediaType: capture.mediaType,
        size: capture.bytes.byteLength,
        fetchedAt: at,
      })),
      at,
    },
  };
}

/**
 * Put a prepared submission's evidence in the archive.
 *
 * Always before the batch that stores it: the objects are content addressed and
 * immutable, so a batch that then fails leaves a capture nothing points at
 * rather than a row pointing at nothing. A bucket that does not answer throws
 * `ArchiveUnreachable`, which both doors turn into a 503.
 */
export async function archivePrepared(
  env: Env,
  prepared: PreparedSubmission,
): Promise<void> {
  for (const capture of prepared.captures) {
    await throughArchive(() =>
      archiveCapture(env.CAPTURES, {
        archiveHash: capture.archiveHash,
        bytes: capture.bytes,
        mediaType: capture.mediaType,
        sidecar: capture.sidecar,
      }),
    );
  }
}

async function submit(
  request: Request,
  env: Env,
  deps: SubmitDeps,
  path: string,
): Promise<Response> {
  const auth = await authenticate(request, env, deps, path);
  if (!auth.ok) return auth.response;

  const attempt = await prepareSubmission(env, deps, auth.agent, auth.body);
  if (!attempt.ok) return attempt.response;
  const { prepared } = attempt;

  // Every check has passed. The evidence goes to the archive first, then the
  // event, the entry row and the capture rows in one atomic batch.
  await archivePrepared(env, prepared);

  try {
    await submitEntry(env.DB, {
      events: [prepared.event],
      entry: prepared.derived.entry,
      sidecar: prepared.derived.sidecar,
      derivedThroughSeq: prepared.event.seq,
      captures: prepared.captureRows,
    });
  } catch (error) {
    if (error instanceof EventAppendError) {
      // Another request appended between the head we read and this write. The
      // submission is not refused on its merits and can be sent again.
      return refuse(409, "chain_moved");
    }
    throw error;
  }

  return json(prepared.derived.entry, 201, {
    location: `/entries/${prepared.id}`,
  });
}

// ---------------------------------------------------------------------------
// Reads
// ---------------------------------------------------------------------------

async function entryById(
  env: Env,
  deps: SubmitDeps,
  reader: ReaderAccess,
  id: string,
): Promise<Response> {
  if (!ENTRY_ID_PATTERN.test(id)) return refuse(400, "bad_id");
  const stored = await getEntry(env.DB, id);
  if (stored === null) return refuse(404, "not_found");

  // A key and a signed operator are served the entry itself, and so is anybody
  // once it has released: the body is the entry object exactly as this route
  // has always answered it, so nothing that parses this door has to change.
  if (reader.kind !== "free") return json(stored.entry, 200);
  const release = await entryRelease(env.DB, stored.submittedSeq, deps.now);
  if (release.released) return json(stored.entry, 200);

  // Withheld (decision D-100): the proof under its own key, never under
  // `entry`, so a reader cannot mistake a nulled claim for the claim, and the
  // date beside it at the top level rather than inside the entry, so the
  // schema's shape is the one thing the window never bends. `release_date` is
  // null while nothing has sealed the submission: there is no date to name yet.
  //
  // `entry_hash` is the whole point of calling this proof at all: it is taken
  // over the core before anything is nulled, so a keyless reader is handed the
  // one number that identifies the entry the log sealed, and can hold whatever
  // they are served later against it. Without it the proof names a record
  // nobody outside the door could pin down.
  const withheld = await withholdEntry(
    stored.entry,
    stored.sidecar,
    release.release_date ?? "",
  );
  return json(
    {
      proof: withheld.proof,
      sidecar: withheld.sidecar,
      entry_hash: withheld.entry_hash,
      release_date: release.release_date,
    },
    200,
  );
}

/**
 * The instant `days` after another. Arithmetic on the submitted instant and not
 * on the calendar day it fell on: the window is "ninety days after the entry's
 * submitted_at", and an entry submitted in the evening opens in the evening.
 */
function instantPlusDays(at: string, days: number): string {
  return new Date(
    Date.parse(at) + days * 24 * 60 * 60 * 1000,
  ).toISOString();
}

/**
 * The delayed-disclosure gate (decision D-096), or null when there is none.
 *
 * A capture whose every index row carries the role `disclosure` is the payload
 * of a redacted transcript, and it is public only from `disclose_after`: the
 * entry's own `submitted_at` plus the domain's `disclosure.window_days`,
 * computed here from the entry row and src/policy.ts rather than stored, so
 * changing the published window changes every payload's date at once.
 *
 * Before that day it is served to a request carrying the M2 signed-request
 * headers from an agent bound to a registered operator -- any operator, because
 * the validators are the readers who need the payload to reproduce the
 * observation -- and refused to everyone else with 403 `undisclosed` and the
 * date it opens. A capture also referenced under another role is some entry's
 * evidence as well, and is served as it always was.
 */
async function undisclosed(
  env: Env,
  deps: SubmitDeps,
  reader: ReaderAccess,
  rows: readonly CaptureRecord[],
): Promise<Response | null> {
  if (rows.length === 0) return null;
  if (!rows.every((row) => row.role === "disclosure")) return null;

  const stored = await getEntry(env.DB, rows[0]!.entryId);
  if (stored === null) return refuse(404, "not_found");
  const core = extractCore(stored.entry);
  const window = disclosureWindowDays(domainOf(core));
  if (window === null) return null;

  const submittedAt = core["submitted_at"];
  if (typeof submittedAt !== "string") return null;
  const submitted = Date.parse(submittedAt);
  if (Number.isNaN(submitted)) return null;
  const discloseAfter = instantPlusDays(submittedAt, window);
  if (deps.now.getTime() >= Date.parse(discloseAfter)) return null;

  // The same rule as before, asked of the one reader this request resolved: a
  // signed request from an agent bound to a registered operator opens the
  // payload, and nothing else does. One signature check per request, because a
  // nonce is single use and a second verification of the same headers would be
  // a replay of the reader's own request.
  if (reader.kind === "operator") return null;
  return json({ error: "undisclosed", disclose_after: discloseAfter }, 403);
}

/**
 * The release window on a capture (decision D-100), or null when this reader
 * may have the bytes.
 *
 * A capture is evidence, and evidence is the content of the entry that rests on
 * it: a capture whose every index row belongs to an entry that has not released
 * is served only to a key or a signed operator, and refused to a free reader
 * with the earliest date any of those entries opens. One row belonging to a
 * released entry is enough to serve it — the bytes are that entry's public
 * evidence, and no other entry citing the same hash can take that back.
 */
async function unreleasedCapture(
  env: Env,
  deps: SubmitDeps,
  reader: ReaderAccess,
  rows: readonly CaptureRecord[],
): Promise<Response | null> {
  if (reader.kind !== "free") return null;
  if (rows.length === 0) return null;

  let earliest: string | null = null;
  for (const row of rows) {
    const stored = await getEntry(env.DB, row.entryId);
    // A capture row whose entry is not there points at nothing this door can
    // date; it cannot release the bytes, and it cannot put a date on them.
    if (stored === null) continue;
    const release = await entryRelease(env.DB, stored.submittedSeq, deps.now);
    if (release.released) return null;
    const date = release.release_date;
    if (date !== null && (earliest === null || date < earliest)) earliest = date;
  }
  return json({ error: "unreleased", release_date: earliest }, 403);
}

/**
 * The capture behind a hash: the raw bytes, exactly as they were fetched.
 *
 * The hash asked for is the content hash the entry carries, not the archive
 * address, because that is the value a reader has in front of them. The archive
 * address travels back in a header, so a reader can check for themselves that
 * these bytes hash to the address they were stored at.
 */
async function captureByHash(
  env: Env,
  deps: SubmitDeps,
  reader: ReaderAccess,
  hash: string,
): Promise<Response> {
  if (!HASH_PATTERN.test(hash)) return refuse(400, "bad_hash");
  const rows = await capturesForHash(env.DB, hash);
  const record = rows[0] ?? null;
  if (record === null) return refuse(404, "not_found");
  const gate = await undisclosed(env, deps, reader, rows);
  if (gate !== null) return gate;
  const window = await unreleasedCapture(env, deps, reader, rows);
  if (window !== null) return window;

  const stored = await throughArchive(() =>
    readCapture(env.CAPTURES, record.archiveHash),
  );
  if (stored === null) return refuse(404, "not_found");

  return new Response(stored.bytes as unknown as BodyInit, {
    status: 200,
    headers: {
      "content-type": record.mediaType,
      "content-disposition": `attachment; filename="${archiveFilename(record.archiveHash)}"`,
      ...CAPTURE_INERT_HEADERS,
      "cache-control": "no-store",
      "x-nomankind-archive-hash": record.archiveHash,
    },
  });
}

async function sidecarByHash(
  env: Env,
  deps: SubmitDeps,
  reader: ReaderAccess,
  hash: string,
): Promise<Response> {
  if (!HASH_PATTERN.test(hash)) return refuse(400, "bad_hash");
  const rows = await capturesForHash(env.DB, hash);
  const record = rows[0] ?? null;
  if (record === null) return refuse(404, "not_found");
  // The sidecar says when and how the payload was archived, which is a fact
  // about the payload: it waits for the same date the bytes do.
  const gate = await undisclosed(env, deps, reader, rows);
  if (gate !== null) return gate;
  const window = await unreleasedCapture(env, deps, reader, rows);
  if (window !== null) return window;

  const sidecar = await throughArchive(() =>
    readSidecar(env.CAPTURES, record.archiveHash),
  );
  if (sidecar === null) return refuse(404, "not_found");
  return json(sidecar, 200, { "x-nomankind-archive-hash": record.archiveHash });
}

// ---------------------------------------------------------------------------
// The router
// ---------------------------------------------------------------------------

/**
 * The one path segment after `prefix`, or null when the path is not that shape.
 * A path with a further slash is not a member of this collection and falls
 * through rather than being trimmed into one.
 */
function segmentAfter(path: string, prefix: string): string | null {
  if (!path.startsWith(prefix)) return null;
  const rest = path.slice(prefix.length);
  if (rest === "" || rest.includes("/")) return null;
  try {
    return decodeURIComponent(rest);
  } catch {
    return null;
  }
}

/**
 * Route one request to the submit paths, or answer null when the path is not
 * one of ours, which leaves the Worker's own not_found untouched.
 *
 * The one place a storage or archive failure is turned into an answer: D1 is
 * reached through the wrapped handle and R2 through `throughArchive`, so a
 * database or a bucket that does not answer becomes a JSON 503 naming which of
 * the two it was, instead of a raw 500. Nothing else is caught: a refusal is a
 * value these routes return, and a bug of ours still escapes.
 */
export async function handleSubmit(
  request: Request,
  env: Env,
  deps: SubmitDeps,
): Promise<Response | null> {
  try {
    return await route(request, { ...env, DB: guardDatabase(env.DB) }, deps);
  } catch (error) {
    if (error instanceof StorageUnreachable) {
      // The message only: no binding contents, no request data.
      console.error(`submit: storage unreachable: ${error.message}`);
      return refuse(503, "storage_unreachable");
    }
    if (error instanceof ArchiveUnreachable) {
      console.error(`submit: archive unreachable: ${error.message}`);
      return refuse(503, "archive_unreachable");
    }
    throw error;
  }
}

async function route(
  request: Request,
  env: Env,
  deps: SubmitDeps,
): Promise<Response | null> {
  const path = new URL(request.url).pathname;

  if (path === "/entries") {
    if (request.method !== "POST") return methodNotAllowed("POST");
    return submit(request, env, deps, path);
  }

  const entryId = segmentAfter(path, "/entries/");
  if (entryId !== null) {
    if (request.method !== "GET") return methodNotAllowed("GET");
    const granted = await reading(request, env, deps);
    if (!granted.ok) return granted.response;
    return entryById(env, deps, granted.reader, entryId);
  }

  if (path.startsWith("/captures/")) {
    const rest = path.slice("/captures/".length);
    const sidecar = rest.endsWith(SIDECAR_PATH);
    const raw = sidecar ? rest.slice(0, -SIDECAR_PATH.length) : rest;
    const hash = segmentAfter(`/${raw}`, "/");
    if (hash !== null) {
      if (request.method !== "GET") return methodNotAllowed("GET");
      const granted = await reading(request, env, deps);
      if (!granted.ok) return granted.response;
      return sidecar
        ? sidecarByHash(env, deps, granted.reader, hash)
        : captureByHash(env, deps, granted.reader, hash);
    }
  }

  return null;
}

/**
 * Who is reading, resolved once for the request and passed to every gate under
 * it (decision D-100).
 *
 * Only the reads below it: a submission carries an M2 signature over its own
 * body and is authenticated by `authenticate`, so putting it through a gate
 * that verifies a GET over a null body would refuse every write door there is.
 */
async function reading(
  request: Request,
  env: Env,
  deps: SubmitDeps,
): Promise<
  { ok: true; reader: ReaderAccess } | { ok: false; response: Response }
> {
  const granted = await readerAccess(request, env, env.DB, deps.now);
  return granted.ok
    ? { ok: true, reader: granted.reader }
    : { ok: false, response: refusalResponse(granted.refusal) };
}
