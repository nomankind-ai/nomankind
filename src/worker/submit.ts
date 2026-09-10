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
  receiptArtifactHash,
  transcriptArtifactHash,
} from "../artifact.js";
import { CORE_KEYS, domainOf, extractCore, type Core } from "../core.js";
import { deriveEntry, type DerivedEntry } from "../derive.js";
import { appendEvent, type Event } from "../events.js";
import { isTranscriptCategory } from "../evidence.js";
import { canonicalize } from "../hash.js";
import { archiveAddress, mediaType, snapshotHash } from "../normalize.js";
import { validateEntry } from "../schema.js";
import { verifyEntrySignature } from "../sign.js";
import type { D1Like } from "../storage/d1.js";
import {
  EventAppendError,
  captureForHash,
  eventBySeq,
  eventsForEntry,
  getEntry,
  headSeq,
  operatorForAgent,
  submitEntry,
  type CaptureRecord,
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
import type { Env } from "./env.js";
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

/** A submission's body: the signed entry, and the receipt when it has one. */
interface SubmitBody {
  readonly entry: Record<string, unknown>;
  readonly receipt: Record<string, unknown> | undefined;
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
    if (key !== "entry" && key !== "receipt") return null;
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

  return { entry, receipt };
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
 * The snapshot of every other entry: the cited page, fetched now.
 *
 * Steps 1 to 5 of the norm rule in order — fetch under the fixed headers,
 * archive the raw body, extract by media type, normalize, hash — and then the
 * one comparison the whole route exists for: the hash of what we just fetched
 * against the hash the author signed. A page that needs JavaScript is refused
 * with the rule's own reason and is never archived as a snapshot.
 */
async function fetchedCapture(
  core: Core,
  deps: SubmitDeps,
  at: string,
  fetcher: string,
): Promise<CaptureAttempt> {
  const citation = core["citation"];
  if (typeof citation !== "string") {
    return { ok: false, reason: "unsupported_citation" };
  }
  let url: URL;
  try {
    url = new URL(citation);
  } catch {
    return { ok: false, reason: "unsupported_citation" };
  }
  if (url.protocol !== "http:" && url.protocol !== "https:") {
    return { ok: false, reason: "unsupported_citation" };
  }

  const fetched = await deps.fetcher.fetch(citation);
  if (!fetched.ok) return { ok: false, reason: fetched.reason };

  const contentType = fetched.headers["content-type"] ?? null;
  const hashed = await snapshotHash(fetched.bytes, contentType);
  if (!hashed.ok) return { ok: false, reason: hashed.reason };
  if (hashed.hash !== core["snapshot_hash"]) {
    return { ok: false, reason: "snapshot_mismatch" };
  }

  return {
    ok: true,
    capture: {
      role: "snapshot",
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
 * The author's signature, the kernel's submission and supersession checks, the
 * duplicate lookup, the capture of the cited page under the norm rule, and the
 * schema over the derived entry. Nothing is written and nothing is archived: a
 * refusal here leaves the log and the archive exactly where they were.
 */
export async function prepareSubmission(
  env: Env,
  deps: SubmitDeps,
  requestAgent: string,
  raw: unknown,
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

  if ((await getEntry(env.DB, id)) !== null) {
    return refused(refuse(409, "duplicate_entry"));
  }

  // The sidecar names the 1F916 identity that fetched, and ours is the
  // maintainer's own key (D-016). An unconfigured maintainer cannot sign the
  // provenance of a capture, so it does not take one: production says so and
  // refuses rather than archiving evidence nobody stands behind.
  const fetcher = env.MAINTAINER_AGENT_ID;
  if (fetcher === "") return refused(refuse(503, "fetcher_not_configured"));

  // Which categories carry a transcript is the entry's own domain's table
  // (decision D-071), read off the signed core rather than off a global.
  const snapshot = isTranscriptCategory(domainOf(core), core["category"])
    ? await transcriptCapture(core, at, fetcher)
    : await fetchedCapture(core, deps, at, fetcher);
  if (!snapshot.ok) return refused(refuse(422, snapshot.reason));
  const captures: PreparedCapture[] = [snapshot.capture];

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

async function entryById(env: Env, id: string): Promise<Response> {
  if (!ENTRY_ID_PATTERN.test(id)) return refuse(400, "bad_id");
  const stored = await getEntry(env.DB, id);
  if (stored === null) return refuse(404, "not_found");
  return json(stored.entry, 200);
}

/**
 * The capture behind a hash: the raw bytes, exactly as they were fetched.
 *
 * The hash asked for is the content hash the entry carries, not the archive
 * address, because that is the value a reader has in front of them. The archive
 * address travels back in a header, so a reader can check for themselves that
 * these bytes hash to the address they were stored at.
 */
async function captureByHash(env: Env, hash: string): Promise<Response> {
  if (!HASH_PATTERN.test(hash)) return refuse(400, "bad_hash");
  const record = await captureForHash(env.DB, hash);
  if (record === null) return refuse(404, "not_found");

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

async function sidecarByHash(env: Env, hash: string): Promise<Response> {
  if (!HASH_PATTERN.test(hash)) return refuse(400, "bad_hash");
  const record = await captureForHash(env.DB, hash);
  if (record === null) return refuse(404, "not_found");

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
    return entryById(env, entryId);
  }

  if (path.startsWith("/captures/")) {
    const rest = path.slice("/captures/".length);
    const sidecar = rest.endsWith(SIDECAR_PATH);
    const raw = sidecar ? rest.slice(0, -SIDECAR_PATH.length) : rest;
    const hash = segmentAfter(`/${raw}`, "/");
    if (hash !== null) {
      if (request.method !== "GET") return methodNotAllowed("GET");
      return sidecar ? sidecarByHash(env, hash) : captureByHash(env, hash);
    }
  }

  return null;
}
