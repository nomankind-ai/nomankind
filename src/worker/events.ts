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
 * No policy number lives here: the bare integers are HTTP status codes and the
 * page size is LIST_PAGE_LIMIT from src/policy.ts.
 */

import { LIST_PAGE_LIMIT } from "../policy.js";
import { eventsAfter, headSeq } from "../storage/repository.js";
import type { Env } from "./env.js";
import {
  StorageUnreachable,
  guardDatabase,
  json,
  methodNotAllowed,
  refuse,
} from "./registry.js";

/** A non-negative integer position in the log. */
const NON_NEGATIVE_INTEGER = /^(?:0|[1-9][0-9]*)$/;

/** A positive integer page size. */
const POSITIVE_INTEGER = /^[1-9][0-9]*$/;

/**
 * `after` is exclusive and seq 0 is a real position, so the start of the log is
 * "after -1". A caller never writes that: they omit `after` instead.
 */
const BEFORE_THE_LOG = -1;

async function page(url: URL, env: Env): Promise<Response> {
  const rawAfter = url.searchParams.get("after");
  let after = BEFORE_THE_LOG;
  if (rawAfter !== null) {
    if (!NON_NEGATIVE_INTEGER.test(rawAfter)) return refuse(400, "bad_query");
    after = Number(rawAfter);
    if (!Number.isSafeInteger(after)) return refuse(400, "bad_query");
  }

  const rawLimit = url.searchParams.get("limit");
  let limit = LIST_PAGE_LIMIT;
  if (rawLimit !== null) {
    if (!POSITIVE_INTEGER.test(rawLimit)) return refuse(400, "bad_query");
    limit = Number(rawLimit);
    if (limit > LIST_PAGE_LIMIT) return refuse(400, "bad_query");
  }

  const events = await eventsAfter(env.DB, after, limit);
  // The head is read after the page, so a caller that sees head === the last
  // event's seq is caught up on a log that had not moved on underneath them.
  return json({ events, head: await headSeq(env.DB) }, 200);
}

/**
 * Route one request to the log, or answer null when the path is not ours, which
 * leaves the Worker's own not_found untouched. Storage failures become the same
 * JSON 503 every other route gives.
 */
export async function handleEvents(
  request: Request,
  env: Env,
): Promise<Response | null> {
  const url = new URL(request.url);
  if (url.pathname !== "/events") return null;
  if (request.method !== "GET") return methodNotAllowed("GET");

  try {
    return await page(url, { ...env, DB: guardDatabase(env.DB) });
  } catch (error) {
    if (error instanceof StorageUnreachable) {
      // The message only: no binding contents, no request data.
      console.error(`events: storage unreachable: ${error.message}`);
      return refuse(503, "storage_unreachable");
    }
    throw error;
  }
}
