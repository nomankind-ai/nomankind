/**
 * The seals, the proofs and the anchors, read from the outside.
 *
 * Whitepaper, Lifecycle of an entry (Seal): "Anyone can verify, offline, that an
 * entry or event existed, who signed it, and that it has not changed." The log's
 * own page (src/worker/events.ts) serves the events; these five routes serve the
 * evidence about them — the seal chain, one seal, the inclusion proof for one
 * event, and the daily anchors that put the day's roots outside this system
 * altogether.
 *
 * Reads only, and derived from nothing: a seal goes out exactly as it was
 * stored, and the proof is recomputed from the covering seal's own event range
 * so a reader can check it against the root without trusting this Worker to have
 * kept it. The proof is checked here before it is served, because a proof that
 * does not verify is not an answer.
 *
 * Keyset paging, like every listing in this system: the caller keeps the last
 * seal seq (or the last day) it saw and asks for what came after.
 *
 * No policy number lives here: the bare integers are HTTP status codes and the
 * page size is LIST_PAGE_LIMIT from src/policy.ts.
 */

import type { Event } from "../events.js";
import { encodeProof, inclusionProof, verifyInclusion } from "../merkle.js";
import { LIST_PAGE_LIMIT } from "../policy.js";
import type { Seal } from "../seal.js";
import type { D1Like } from "../storage/d1.js";
import {
  anchorsAfter,
  eventBySeq,
  eventsInRange,
  getAnchor,
  latestSeal,
  sealBySeq,
  sealCovering,
  sealsAfter,
} from "../storage/repository.js";
import type { Env } from "./env.js";
import {
  StorageUnreachable,
  guardDatabase,
  json,
  READ_METHODS,
  isRead,
  methodNotAllowed,
  refuse,
} from "./registry.js";

/** A non-negative integer position, in the log or in the seal chain. */
const NON_NEGATIVE_INTEGER = /^(?:0|[1-9][0-9]*)$/;

/** A positive integer page size. */
const POSITIVE_INTEGER = /^[1-9][0-9]*$/;

/** A UTC calendar day, exactly as an anchor is keyed by one. */
const CALENDAR_DATE = /^\d{4}-\d{2}-\d{2}$/;

/**
 * `after` is exclusive and seq 0 is a real position, so the start of the chain
 * is "after -1". A caller never writes that: they omit `after` instead.
 */
const BEFORE_THE_CHAIN = -1;

/** The first day of no day at all: every real day sorts after the empty string. */
const BEFORE_ANY_DAY = "";

/** The `after` and `limit` a listing takes, or the refusal they earned. */
type Page = { after: string; limit: number } | Response;

function pageOf(url: URL, first: string, integer: boolean): Page {
  const rawAfter = url.searchParams.get("after");
  let after = first;
  if (rawAfter !== null) {
    const shape = integer ? NON_NEGATIVE_INTEGER : CALENDAR_DATE;
    if (!shape.test(rawAfter)) return refuse(400, "bad_query");
    if (integer && !Number.isSafeInteger(Number(rawAfter))) {
      return refuse(400, "bad_query");
    }
    after = rawAfter;
  }

  const rawLimit = url.searchParams.get("limit");
  let limit = LIST_PAGE_LIMIT;
  if (rawLimit !== null) {
    if (!POSITIVE_INTEGER.test(rawLimit)) return refuse(400, "bad_query");
    limit = Number(rawLimit);
    if (limit > LIST_PAGE_LIMIT) return refuse(400, "bad_query");
  }

  return { after, limit };
}

/**
 * The seal chain, paged.
 *
 * `head` is the newest seal's seq, read after the page, so a caller whose last
 * seal is the head is caught up on a chain that had not moved underneath them.
 */
async function seals(url: URL, db: D1Like): Promise<Response> {
  const page = pageOf(url, String(BEFORE_THE_CHAIN), true);
  if (page instanceof Response) return page;

  const listed = await sealsAfter(db, Number(page.after), page.limit);
  const head = await latestSeal(db);
  return json({ seals: listed, head: head === null ? null : head.seq }, 200);
}

/** One seal by its own sequence number. */
async function seal(raw: string, db: D1Like): Promise<Response> {
  if (!NON_NEGATIVE_INTEGER.test(raw)) return refuse(400, "bad_id");
  const seq = Number(raw);
  if (!Number.isSafeInteger(seq)) return refuse(400, "bad_id");
  const found = await sealBySeq(db, seq);
  if (found === null) return refuse(404, "not_found");
  return json(found, 200);
}

/**
 * The encoded inclusion proof for one sealed event, or null when it cannot be
 * built or does not verify.
 *
 * Factored out of the proof route because the delta stream serves the very same
 * proof beside every event it delivers (src/worker/sync.ts), and two
 * recomputations of one proof are two chances to disagree about it. The reads
 * stay with the caller: the proof route wants one event's covering seal, while
 * a sync page walks a run of events sharing a handful of seals and reads each
 * one once.
 *
 * Null rather than a throw, and null on a batch whose size is not the seal's,
 * because either way the answer is the same refusal: a proof that does not
 * verify against the root the seal committed to is not an answer, whatever the
 * reason.
 */
export async function buildInclusionProof(
  event: Event,
  covering: Seal,
  batch: readonly Event[],
): Promise<string | null> {
  if (batch.length !== covering.size) return null;
  try {
    const built = await inclusionProof(
      batch.map((leaf) => leaf.hash),
      event.seq - covering.first_seq,
    );
    if (!(await verifyInclusion(event.hash, built, covering.root))) return null;
    return encodeProof(built);
  } catch {
    return null;
  }
}

/**
 * The inclusion proof for one event.
 *
 * Two reads, because a proof needs the whole batch: the seal covering the event,
 * and the events of that seal's range, which are the leaves the proof is
 * computed over. Bounded by the seal, so no page size is involved.
 *
 * An event nothing has sealed yet is a 404 naming `unsealed` rather than
 * `not_found`: the event exists and its proof does not, which is a different
 * thing for a reader to be told, and a later run will have sealed it.
 */
async function proof(raw: string, db: D1Like): Promise<Response> {
  if (!NON_NEGATIVE_INTEGER.test(raw)) return refuse(400, "bad_id");
  const seq = Number(raw);
  if (!Number.isSafeInteger(seq)) return refuse(400, "bad_id");

  const event = await eventBySeq(db, seq);
  if (event === null) return refuse(404, "not_found");

  const covering = await sealCovering(db, seq);
  if (covering === null) return refuse(404, "unsealed");

  const batch = await eventsInRange(db, covering.first_seq, covering.last_seq);
  const included = await buildInclusionProof(event, covering, batch);
  if (included === null) return refuse(500, "bad_proof");

  return json(
    {
      seq: event.seq,
      hash: event.hash,
      seal: {
        seq: covering.seq,
        root: covering.root,
        hash: covering.hash,
        sealed_at: covering.sealed_at,
      },
      inclusion_proof: included,
      witnesses: covering.witnesses,
    },
    200,
  );
}

/** The daily anchors, paged by day. */
async function anchors(url: URL, db: D1Like): Promise<Response> {
  const page = pageOf(url, BEFORE_ANY_DAY, false);
  if (page instanceof Response) return page;
  return json({ anchors: await anchorsAfter(db, page.after, page.limit) }, 200);
}

/** One day's anchor. */
async function anchor(raw: string, db: D1Like): Promise<Response> {
  if (!CALENDAR_DATE.test(raw)) return refuse(400, "bad_id");
  const found = await getAnchor(db, raw);
  if (found === null) return refuse(404, "not_found");
  return json(found, 200);
}

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

/** The event seq in `/events/{seq}/proof`, or null when the path is not that. */
function proofPathSeq(path: string): string | null {
  const PREFIX = "/events/";
  const SUFFIX = "/proof";
  if (!path.startsWith(PREFIX) || !path.endsWith(SUFFIX)) return null;
  const raw = path.slice(PREFIX.length, path.length - SUFFIX.length);
  if (raw === "" || raw.includes("/")) return null;
  try {
    return decodeURIComponent(raw);
  } catch {
    return null;
  }
}

async function route(
  request: Request,
  db: D1Like,
): Promise<Response | null> {
  const url = new URL(request.url);
  const path = url.pathname;

  if (path === "/seals") {
    if (!isRead(request)) return methodNotAllowed(READ_METHODS);
    return seals(url, db);
  }

  const sealSeq = segmentAfter(path, "/seals/");
  if (sealSeq !== null) {
    if (!isRead(request)) return methodNotAllowed(READ_METHODS);
    return seal(sealSeq, db);
  }

  const eventSeq = proofPathSeq(path);
  if (eventSeq !== null) {
    if (!isRead(request)) return methodNotAllowed(READ_METHODS);
    return proof(eventSeq, db);
  }

  if (path === "/anchors") {
    if (!isRead(request)) return methodNotAllowed(READ_METHODS);
    return anchors(url, db);
  }

  const date = segmentAfter(path, "/anchors/");
  if (date !== null) {
    if (!isRead(request)) return methodNotAllowed(READ_METHODS);
    return anchor(date, db);
  }

  return null;
}

/**
 * Route one request to the seal, proof and anchor pages, or answer null when the
 * path is not ours, which leaves the Worker's own not_found untouched. Storage
 * failures become the same JSON 503 every other route gives.
 */
export async function handleSeals(
  request: Request,
  env: Env,
): Promise<Response | null> {
  try {
    return await route(request, guardDatabase(env.DB));
  } catch (error) {
    if (error instanceof StorageUnreachable) {
      // The message only: no binding contents, no request data.
      console.error(`seals: storage unreachable: ${error.message}`);
      return refuse(503, "storage_unreachable");
    }
    throw error;
  }
}
