/**
 * The log, paged.
 *
 * Whitepaper, Lifecycle of an entry, Seal: "Anyone can verify, offline, that an
 * entry or event existed, who signed it, and that it has not changed." That
 * promise needs a way to read the log from the outside, and this is it: the
 * events after a position the caller already has, in order, with the head so the
 * caller knows how far behind they are. It is the read the checkpoint export and
 * the public mirror page through, and the read a delta stream resumes from.
 *
 * Keyset, never offset: the caller keeps the last seq it saw and asks for what
 * came after, so the cost of a page does not grow with how far in it is and an
 * event appended between two pages cannot shift a row across the boundary.
 *
 * Nothing here derives or filters anything. The events go out as they are
 * stored, hash chain and all, because a reader that cannot recompute the chain
 * cannot check anything.
 *
 * A page is a read and is charged as one: the caller's own bucket, one unit,
 * after the page was built, and the same 429 every other door gives when the
 * bucket is empty. The inclusion proof beside it is not — proof is public from
 * the first minute, whoever is asking.
 *
 * No policy number lives here: the bare integers are HTTP status codes and the
 * page size is LIST_PAGE_LIMIT from src/policy.ts.
 */

import type { Event } from "../events.js";
import { LIST_PAGE_LIMIT } from "../policy.js";
import {
  isEventReleased,
  withholdEvent,
  type WithheldEvent,
} from "../release.js";
import type { Seal } from "../seal.js";
import { eventsAfter, headSeq, sealsBetween } from "../storage/repository.js";
import {
  accessHeaders,
  chargeReads,
  readerAccess,
  type Access,
} from "./access.js";
import type { Env } from "./env.js";
import { checkParameters, readLimit, readPosition } from "../params.js";
import { refusalResponse } from "./read.js";
import {
  StorageUnreachable,
  guardDatabase,
  json,
  READ_METHODS,
  isRead,
  methodNotAllowed,
  refuse,
} from "./registry.js";

/**
 * Every parameter this door takes, and nothing else.
 *
 * It used to take anything and read two of them, so `?limt=5` was served as an
 * unbounded page and `?after=1&after=900` was served as the first of the two —
 * where the delta stream and the entries listing both refuse each (the QA of
 * 2026-09-12). One reader, `checkParameters`, applies both rules now.
 */
const EVENTS_QUERY_PARAMETERS: readonly string[] = Object.freeze([
  "after",
  "limit",
]);

/**
 * `after` is exclusive and seq 0 is a real position, so the start of the log is
 * "after -1". A caller never writes that: they omit `after` instead.
 */
const BEFORE_THE_LOG = -1;

/** This door has one word for a query it cannot read, and has always had it. */
const EVENTS_QUERY_WORDS = {
  unknown: "bad_query",
  repeated: "bad_query",
} as const;

/**
 * The page as a free reader sees it: every event the window has not opened yet
 * as a hash line (decision D-100).
 *
 * Per event and by its own seal rather than by a single boundary, because the
 * question the window asks is about the seal that covers the event: an event
 * nothing has sealed is not released either, and it is a hash line too. The
 * hash, the links, the type, the instant and the entry id all stay, so a reader
 * who cannot yet see what happened can still prove that it happened, in that
 * order, at that instant — which is the whole of what `GET /events` is for.
 *
 * Which events wait is src/release.ts's to say and not this door's: the mirror
 * export asks the same function, so a page read here and a seal file cloned
 * from the mirror hold the same lines. The registry never waits, which is why
 * this door no longer withholds the naming that `GET /operators` publishes.
 */
function withhold(
  events: readonly Event[],
  seals: readonly Seal[],
  now: Date,
): (Event | WithheldEvent)[] {
  return events.map((event) => {
    const seal = seals.find(
      (candidate) =>
        event.seq >= candidate.first_seq && event.seq <= candidate.last_seq,
    );
    const sealedAt = seal === undefined ? null : seal.sealed_at;
    return isEventReleased(event, sealedAt, now) ? event : withholdEvent(event);
  });
}

async function page(
  url: URL,
  env: Env,
  access: Access,
  free: boolean,
  now: Date,
): Promise<Response> {
  const checked = checkParameters(
    url.searchParams,
    EVENTS_QUERY_PARAMETERS,
    EVENTS_QUERY_WORDS,
  );
  if (!checked.ok) return refuse(400, checked.reason);

  const position = readPosition(
    url.searchParams,
    "after",
    BEFORE_THE_LOG,
    EVENTS_QUERY_WORDS,
  );
  if (!position.ok) return refuse(400, position.reason);
  const after = position.value;

  const page = readLimit(url.searchParams, LIST_PAGE_LIMIT, EVENTS_QUERY_WORDS);
  if (!page.ok) return refuse(400, page.reason);
  const limit = page.value;

  const events = await eventsAfter(env.DB, after, limit);
  // The seals covering exactly the events on this page, read once: a page is a
  // contiguous run, so one range read answers the window for every event in it.
  const seals =
    free && events.length > 0
      ? await sealsBetween(
          env.DB,
          events[0]!.seq,
          events[events.length - 1]!.seq,
        )
      : [];
  // The head is read after the page, so a caller that sees head === the last
  // event's seq is caught up on a log that had not moved on underneath them.
  // It is the true head whoever is asking: a position is proof, and proof is
  // public from the first minute.
  const head = await headSeq(env.DB);
  // One unit for the page, charged after it was built and never before it, like
  // every other door (the QA of 2026-09-12: this one was free, so a walk of the
  // whole log cost a reader nothing and the log everything). The page and not
  // the events on it, because a page is what the caller asked for and what the
  // read cost; `GET /events/{seq}/proof` and the entry's own page stay
  // uncharged, because proof is public from the first minute.
  await chargeReads(env.DB, access, 1);
  return json(
    {
      events: free ? withhold(events, seals, now) : events,
      head,
    },
    200,
    accessHeaders(access, access.limit - access.used - 1),
  );
}

/**
 * Route one request to the log, or answer null when the path is not ours, which
 * leaves the Worker's own not_found untouched. Storage failures become the same
 * JSON 503 every other route gives.
 */
export async function handleEvents(
  request: Request,
  env: Env,
  deps: { now: Date },
): Promise<Response | null> {
  const url = new URL(request.url);
  if (url.pathname !== "/events") return null;
  if (!isRead(request)) return methodNotAllowed(READ_METHODS);

  try {
    const guarded: Env = { ...env, DB: guardDatabase(env.DB) };
    // Once for the request (decision D-100), and its refusals are the gate's
    // own: a mistyped key is 401 `bad_key` and a signature that does not verify
    // is 401 `bad_signature`, never a quiet free read of the hash lines.
    const granted = await readerAccess(request, guarded, guarded.DB, deps.now);
    if (!granted.ok) return refusalResponse(granted.refusal);
    return await page(
      url,
      guarded,
      granted.reader.access,
      granted.reader.kind === "free",
      deps.now,
    );
  } catch (error) {
    if (error instanceof StorageUnreachable) {
      // The message only: no binding contents, no request data.
      console.error(`events: storage unreachable: ${error.message}`);
      return refuse(503, "storage_unreachable");
    }
    throw error;
  }
}
