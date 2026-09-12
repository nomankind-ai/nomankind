/**
 * The change-alert doors and the step that delivers them.
 *
 * Whitepaper Section 9, Money: "Revenue comes from high-rate API access,
 * structured feeds and webhooks, change alerts", and the paid product is "being
 * the fastest true copy, with sub-day freshness, signed receipts, and alerts".
 * A key registers an endpoint, the sweep walks the sealed log, and every sealed
 * change matching an endpoint's filter is posted to it, signed with the
 * endpoint's own secret.
 *
 * Sealed and never live. The step reads events up to the sealed head and no
 * further, exactly as the delta stream does, so an alert is always about
 * something that carries an inclusion proof: a subscriber woken by one can
 * check it against the covering seal in the body rather than taking this
 * Worker's word for what happened.
 *
 * Nothing is decided here. What an alert is and how one is signed is
 * src/alerts.ts's, the entry is re-derived through src/worker/world.ts at the
 * event's own position, the store is query-shaped (src/storage/alerts.ts), and
 * every number — the endpoint cap, the timeout, the retry ladder, the page
 * bound — is src/policy.ts's. No wall clock: `deps.now` on the doors and
 * `input.now` in the step are the instant the caller read once.
 *
 * The endpoint's secret leaves this module exactly once, in the 201 that
 * created it. It is in no listing, in no delivery record, and in no log line:
 * a console.error that named it would publish a credential to a log nobody
 * rotates.
 */

import {
  alertMatches,
  alertSignatureHeader,
  alertsFromEvent,
  isAlertUrl,
  signAlert,
  staleDeliveryId,
  type AlertBody,
  type AlertFilter,
} from "../alerts.js";
import { domainOf, extractCore, type Core } from "../core.js";
import { base64urlEncode } from "../encoding.js";
import type { Event } from "../events.js";
import { entryHash } from "../hash.js";
import {
  ALERT_ENDPOINTS_PER_KEY,
  ALERT_KINDS,
  ALERT_RETRY_MINUTES,
  ALERT_TIMEOUT_MS,
  LIST_PAGE_LIMIT,
  isRegisteredDomain,
  type AlertKind,
} from "../policy.js";
import type { Entry } from "../schema.js";
import type { Seal } from "../seal.js";
import {
  alertCursor,
  alertEndpoint,
  alertEndpointsForKey,
  deliveriesForEndpoint,
  disableAlertEndpoint,
  dueDeliveries,
  enabledAlertEndpoints,
  markDelivery,
  putAlertDeliveries,
  putAlertDeliveriesIfNew,
  putAlertEndpoint,
  setAlertCursor,
  setStaleAlertCursor,
  staleAlertCursor,
  staleAlertsDue,
  type AlertDeliveryInput,
  type AlertEndpointRecord,
} from "../storage/alerts.js";
import type { D1Like } from "../storage/d1.js";
import { eventsAfter, getEntry, sealCovering } from "../storage/repository.js";
import { keyHash, looksLikeKey, type KeyRecord } from "../keys.js";
import { keyByHash } from "../storage/keys.js";
import type { Env } from "./env.js";
import {
  StorageUnreachable,
  guardDatabase,
  json,
  methodNotAllowed,
  refuse,
} from "./registry.js";
import {
  entryWorld,
  rederive,
  worldAt,
  worldCache,
  type WorldCache,
} from "./world.js";

/** How many random bytes an id is made of: 8 bytes is the 16 hex an id shows. */
const ID_BYTES = 8;

/** How many random bytes a shared secret is made of. A format fact. */
const SECRET_BYTES = 32;

/** How many milliseconds a minute is. Not a policy number: it is what a minute is. */
const MILLISECONDS_PER_MINUTE = 60_000;

/** And what a day is. The stale cursor counts these from 1970-01-01. */
const MILLISECONDS_PER_DAY = 86_400_000;

/** How many characters of an ISO 8601 timestamp are its calendar date. */
const DATE_LENGTH = 10;

/** A UTC calendar date, "YYYY-MM-DD", as days since 1970-01-01. */
function dayNumber(date: string): number {
  return Math.floor(
    Date.parse(`${date}T00:00:00.000Z`) / MILLISECONDS_PER_DAY,
  );
}

/** The date a day number names. Day -1 is the day before the epoch. */
function dayDate(day: number): string {
  return new Date(day * MILLISECONDS_PER_DAY)
    .toISOString()
    .slice(0, DATE_LENGTH);
}

/** Random bytes, from the platform. */
function randomHex(count: number): string {
  const bytes = globalThis.crypto.getRandomValues(new Uint8Array(count));
  let hex = "";
  for (const byte of bytes) hex += byte.toString(16).padStart(2, "0");
  return hex;
}

function endpointId(): string {
  return `hook_${randomHex(ID_BYTES)}`;
}

function deliveryId(): string {
  return `alert_${randomHex(ID_BYTES)}`;
}

function newSecret(): string {
  return base64urlEncode(
    globalThis.crypto.getRandomValues(new Uint8Array(SECRET_BYTES)),
  );
}

/** One endpoint's filter, as the kernel takes it. */
function filterOf(endpoint: AlertEndpointRecord): AlertFilter {
  return {
    domain: endpoint.domain,
    subject: endpoint.subject,
    category: endpoint.category,
    kinds: endpoint.kinds,
  };
}

/** One endpoint as its holder sees it. Never the secret. */
function endpointView(endpoint: AlertEndpointRecord): Record<string, unknown> {
  return {
    id: endpoint.id,
    url: endpoint.url,
    filter: {
      domain: endpoint.domain,
      subject: endpoint.subject,
      category: endpoint.category,
      kinds: endpoint.kinds,
    },
    created_at: endpoint.created_at,
  };
}

// ---------------------------------------------------------------------------
// The doors
// ---------------------------------------------------------------------------

/**
 * The key a request presented, or the refusal it earned.
 *
 * The identity checks only, exactly as the account doors in src/worker/keys.ts
 * make them, and for the same reason: these are a holder's own subscription
 * pages, not reading doors. A key at its daily cap must still be able to see
 * and remove its endpoints, and a key whose bill did not clear must be able to
 * turn off the alerts it is no longer paying for — a door that refused
 * `key_past_due` here would hold somebody to a subscription they cannot cancel.
 * A canceled key is refused, because the subscription is over.
 *
 * The quota is never charged by these doors: an endpoint is not a read.
 */
async function keyOf(
  db: D1Like,
  request: Request,
): Promise<{ ok: true; key: KeyRecord } | { ok: false; response: Response }> {
  const header = request.headers.get("authorization");
  if (header === null) {
    return { ok: false, response: refuse(401, "missing_key") };
  }
  const PREFIX = "bearer ";
  const presented = header.toLowerCase().startsWith(PREFIX)
    ? header.slice(PREFIX.length).trim()
    : header.trim();
  if (!looksLikeKey(presented)) {
    return { ok: false, response: refuse(401, "bad_key") };
  }
  const key = await keyByHash(db, await keyHash(presented));
  if (key === null) {
    return { ok: false, response: refuse(401, "unknown_key") };
  }
  if (key.status === "canceled") {
    return { ok: false, response: refuse(402, "key_canceled") };
  }
  return { ok: true, key };
}

/** What a registration body may carry, once it has been read. */
interface Subscription {
  readonly url: string;
  readonly domain: string | null;
  readonly subject: string | null;
  readonly category: string | null;
  readonly kinds: readonly AlertKind[] | null;
}

/** A string field that may be absent or null, or the refusal its shape earned. */
function optionalText(
  fields: Record<string, unknown>,
  name: string,
): { ok: true; value: string | null } | { ok: false } {
  const value = fields[name];
  if (value === undefined || value === null) return { ok: true, value: null };
  if (typeof value !== "string" || value === "") return { ok: false };
  return { ok: true, value };
}

/**
 * Register one endpoint.
 *
 * Every check before the write, and the cap is counted from the rows rather
 * than from anything the caller sent. The secret is minted here, stored, and
 * handed back once: there is no door that shows it again, which is what makes a
 * leaked one revocable by deleting the endpoint.
 */
async function subscribe(
  request: Request,
  db: D1Like,
  key: KeyRecord,
  now: Date,
): Promise<Response> {
  let body: unknown;
  try {
    body = JSON.parse(await request.text());
  } catch {
    return refuse(400, "bad_body");
  }
  if (typeof body !== "object" || body === null || Array.isArray(body)) {
    return refuse(400, "bad_body");
  }

  const fields = body as Record<string, unknown>;
  const url = fields["url"];
  if (typeof url !== "string") return refuse(400, "bad_body");

  const domain = optionalText(fields, "domain");
  const subject = optionalText(fields, "subject");
  const category = optionalText(fields, "category");
  if (!domain.ok || !subject.ok || !category.ok) return refuse(400, "bad_body");

  let kinds: readonly AlertKind[] | null = null;
  const rawKinds = fields["kinds"];
  if (rawKinds !== undefined && rawKinds !== null) {
    if (!Array.isArray(rawKinds) || rawKinds.length === 0) {
      return refuse(400, "bad_body");
    }
    for (const kind of rawKinds) {
      if (typeof kind !== "string") return refuse(400, "bad_body");
      if (!(ALERT_KINDS as readonly string[]).includes(kind)) {
        return refuse(422, "unknown_kind");
      }
    }
    kinds = rawKinds as AlertKind[];
  }

  if (!isAlertUrl(url)) return refuse(422, "bad_url");
  if (domain.value !== null && !isRegisteredDomain(domain.value)) {
    return refuse(422, "unknown_domain");
  }

  const standing = await alertEndpointsForKey(
    db,
    key.id,
    ALERT_ENDPOINTS_PER_KEY,
  );
  if (standing.length >= ALERT_ENDPOINTS_PER_KEY) {
    return refuse(409, "endpoint_limit");
  }

  const stored = await putAlertEndpoint(db, {
    id: endpointId(),
    keyId: key.id,
    url,
    secret: newSecret(),
    domain: domain.value,
    subject: subject.value,
    category: category.value,
    kinds,
    createdAt: now.toISOString(),
  });

  return json({ ...endpointView(stored), secret: stored.secret }, 201);
}

/** The key's live endpoints. No secrets: they were shown once. */
async function listEndpoints(db: D1Like, key: KeyRecord): Promise<Response> {
  const rows = await alertEndpointsForKey(db, key.id, ALERT_ENDPOINTS_PER_KEY);
  return json({ key: key.id, endpoints: rows.map(endpointView) }, 200);
}

/**
 * Turn one endpoint off.
 *
 * 404 when the id names nobody and 404 when it names somebody else's endpoint:
 * one answer for both, because a holder learning that an id exists but is not
 * theirs has learned something about another customer.
 */
async function unsubscribe(
  db: D1Like,
  key: KeyRecord,
  id: string,
  now: Date,
): Promise<Response> {
  const endpoint = await alertEndpoint(db, id);
  if (
    endpoint === null ||
    endpoint.key_id !== key.id ||
    endpoint.disabled_at !== null
  ) {
    return refuse(404, "not_found");
  }
  await disableAlertEndpoint(db, id, now.toISOString());
  return new Response(null, {
    status: 204,
    headers: { "cache-control": "no-store" },
  });
}

/**
 * What happened to one endpoint's alerts, newest first.
 *
 * The bodies go out whole, because they are public: every field in one is
 * already at `/entries/{id}` or `/events`. What is not in them is the
 * endpoint's secret, which is in no delivery record at all.
 */
async function deliveries(
  db: D1Like,
  key: KeyRecord,
  id: string,
  url: URL,
): Promise<Response> {
  const endpoint = await alertEndpoint(db, id);
  if (endpoint === null || endpoint.key_id !== key.id) {
    return refuse(404, "not_found");
  }

  const after = url.searchParams.get("after");

  const rawLimit = url.searchParams.get("limit");
  let limit = LIST_PAGE_LIMIT;
  if (rawLimit !== null) {
    const parsed = Number(rawLimit);
    if (!Number.isInteger(parsed) || parsed < 1 || parsed > LIST_PAGE_LIMIT) {
      return refuse(400, "bad_limit");
    }
    limit = parsed;
  }

  const rows = await deliveriesForEndpoint(db, endpoint.id, after, limit);
  return json(
    {
      key: key.id,
      endpoint: endpoint.id,
      deliveries: rows.map((row) => ({
        id: row.id,
        event_seq: row.event_seq,
        kind: row.kind,
        entry_id: row.entry_id,
        status: row.status,
        attempts: row.attempts,
        next_at: row.next_at,
        delivered_at: row.delivered_at,
        last_status: row.last_status,
        last_error: row.last_error,
        created_at: row.created_at,
        body: row.body,
      })),
    },
    200,
  );
}

/** The endpoint id in `/keys/me/webhooks/{id}[/deliveries]`, or null. */
function endpointPath(
  path: string,
): { id: string; deliveries: boolean } | null {
  const PREFIX = "/keys/me/webhooks/";
  if (!path.startsWith(PREFIX)) return null;
  const rest = path.slice(PREFIX.length);
  if (rest === "") return null;
  const SUFFIX = "/deliveries";
  const wantsDeliveries = rest.endsWith(SUFFIX);
  const raw = wantsDeliveries ? rest.slice(0, rest.length - SUFFIX.length) : rest;
  if (raw === "" || raw.includes("/")) return null;
  try {
    return { id: decodeURIComponent(raw), deliveries: wantsDeliveries };
  } catch {
    return null;
  }
}

async function route(
  request: Request,
  db: D1Like,
  deps: { now: Date },
): Promise<Response | null> {
  const url = new URL(request.url);
  const path = url.pathname;

  if (path === "/keys/me/webhooks") {
    if (request.method !== "POST" && request.method !== "GET") {
      return methodNotAllowed("GET, POST");
    }
    const held = await keyOf(db, request);
    if (!held.ok) return held.response;
    return request.method === "POST"
      ? subscribe(request, db, held.key, deps.now)
      : listEndpoints(db, held.key);
  }

  const member = endpointPath(path);
  if (member !== null) {
    if (member.deliveries) {
      if (request.method !== "GET") return methodNotAllowed("GET");
      const held = await keyOf(db, request);
      return held.ok
        ? deliveries(db, held.key, member.id, url)
        : held.response;
    }
    if (request.method !== "DELETE") return methodNotAllowed("DELETE");
    const held = await keyOf(db, request);
    return held.ok
      ? unsubscribe(db, held.key, member.id, deps.now)
      : held.response;
  }

  return null;
}

/**
 * `/keys/me/webhooks` and the paths under it. Null for everything else, which
 * leaves the Worker's own not_found exactly where it was.
 */
export async function handleAlerts(
  request: Request,
  env: Env,
  deps: { now: Date },
): Promise<Response | null> {
  const db = guardDatabase(env.DB);
  try {
    return await route(request, db, deps);
  } catch (error) {
    if (error instanceof StorageUnreachable) {
      // The message only: no binding contents, no request data, no secret.
      console.error(`alerts: storage unreachable: ${error.message}`);
      return refuse(503, "storage_unreachable");
    }
    throw error;
  }
}

// ---------------------------------------------------------------------------
// The step
// ---------------------------------------------------------------------------

/** What one run of the alert step did. */
export interface AlertStepReport {
  readonly created: number;
  readonly delivered: number;
  readonly failed: number;
  readonly retried: number;
}

/** One alert, once the entry behind it has been re-derived. */
interface DerivedAlert {
  readonly kind: AlertKind;
  readonly entry: Entry;
  readonly core: Core;
  readonly entry_hash: string;
}

/** Re-derive one entry at one sealed position, or null when it cannot be. */
function deriveAt(
  world: Awaited<ReturnType<typeof entryWorld>>,
  entryId: string,
  position: number,
  now: Date,
): Entry | null {
  try {
    return rederive(worldAt(world, position), entryId, now).entry;
  } catch {
    // No submission event at or before this position: the entry did not exist
    // yet, which is exactly what "nothing before" means.
    return null;
  }
}

/**
 * The alerts one sealed event calls for.
 *
 * The entry is re-derived at the event's own position and at the position
 * before it, through the same gathering every writer uses, so an alert says
 * what the log said at that moment and never what it says now. A second run
 * over the same event would build the same body.
 *
 * `cache` is one run's reading of the registry, shared by every gathering the
 * run makes: a page of a hundred events read the same six paged queries a
 * hundred times over to arrive at the same registry, which is most of a run's
 * subrequest budget spent on one unchanging answer.
 */
async function alertsFor(
  db: D1Like,
  event: Event,
  now: Date,
  cache: WorldCache,
): Promise<DerivedAlert[]> {
  const entryId = event.entry_id;
  if (entryId === null) return [];
  // The cheap guard first: three quarters of the log is events no alert kind is
  // derived from, and each of the others costs a gathering of the entry's world.
  if (
    event.type !== "entry_submitted" &&
    event.type !== "validation" &&
    event.type !== "reconfirmation" &&
    event.type !== "dispute_upheld"
  ) {
    return [];
  }

  const world = await entryWorld(db, entryId, cache);
  const after = deriveAt(world, entryId, event.seq, now);
  if (after === null) return [];
  const before =
    event.seq === 0 ? null : deriveAt(world, entryId, event.seq - 1, now);

  let target: Entry | null = null;
  const supersedes = after["supersedes"];
  if (event.type === "validation" && typeof supersedes === "string") {
    const targetWorld = await entryWorld(db, supersedes, cache);
    target = deriveAt(targetWorld, supersedes, event.seq, now);
  }

  const out: DerivedAlert[] = [];
  for (const alert of alertsFromEvent(event, { before, after, target })) {
    const core = extractCore(alert.entry);
    out.push({
      kind: alert.kind,
      entry: alert.entry,
      core,
      entry_hash: await entryHash(core),
    });
  }
  return out;
}

/**
 * The body one endpoint is sent, as the object that is stored and signed.
 *
 * `position` is the moment the alert is about: an event's own seq and `at` for
 * the six kinds derived from the log, and the entry's submission seq with the
 * day its window closed for a `stale` one, which no event carries. Either way
 * the seal is the one covering that seq, so the proof link and the root a
 * subscriber checks against are about the same position.
 */
function bodyFor(
  id: string,
  alert: DerivedAlert,
  position: { seq: number; at: string },
  seal: Seal,
  origin: string,
): AlertBody {
  const entryId = String(alert.core["id"]);
  return {
    id,
    kind: alert.kind,
    entry_id: entryId,
    domain: domainOf(alert.core),
    subject: String(alert.core["subject"]),
    category: String(alert.core["category"]),
    status: String(alert.entry["status"]),
    entry_hash: alert.entry_hash,
    seq: position.seq,
    seal: { seq: seal.seq, root: seal.root, sealed_at: seal.sealed_at },
    at: position.at,
    links: {
      entry: `${origin}/entries/${entryId}`,
      proof: `${origin}/events/${position.seq}/proof`,
    },
  };
}

/**
 * Walk the sealed events past the cursor and write the deliveries they call
 * for, then move the cursor.
 *
 * Bounded by LIST_PAGE_LIMIT events per run, like every other step that walks
 * the log: a backlog is caught up over runs and never in one unbounded read.
 * The cursor moves to the last event examined, so the next run starts where
 * this one stopped whether or not any of those events alerted anybody.
 */
async function createDeliveries(
  db: D1Like,
  input: { now: Date; sealedHead: number; origin: string },
  endpoints: readonly AlertEndpointRecord[],
): Promise<number> {
  const cursor = await alertCursor(db);
  if (cursor >= input.sealedHead) return 0;

  const page = await eventsAfter(db, cursor, LIST_PAGE_LIMIT);
  const events = page.filter((event) => event.seq <= input.sealedHead);
  if (events.length === 0) return 0;

  const at = input.now.toISOString();
  // One reading of the registry for the whole run, handed to every gathering.
  const cache = worldCache();
  const batch: AlertDeliveryInput[] = [];
  for (const event of events) {
    const alerts = await alertsFor(db, event, input.now, cache);
    if (alerts.length === 0) continue;
    const seal = await sealCovering(db, event.seq);
    // Below the sealed head there is always a covering seal; an event without
    // one is not sealed history, and an alert about it would carry no proof.
    if (seal === null) continue;

    for (const alert of alerts) {
      const view = {
        domain: domainOf(alert.core),
        subject: String(alert.core["subject"]),
        category: String(alert.core["category"]),
        kind: alert.kind,
      };
      for (const endpoint of endpoints) {
        if (!alertMatches(filterOf(endpoint), view)) continue;
        const id = deliveryId();
        batch.push({
          id,
          endpointId: endpoint.id,
          eventSeq: event.seq,
          kind: alert.kind,
          entryId: String(alert.core["id"]),
          body: bodyFor(
            id,
            alert,
            { seq: event.seq, at: event.at },
            seal,
            input.origin,
          ) as unknown as Record<string, unknown>,
          nextAt: at,
          createdAt: at,
        });
      }
    }
  }

  await putAlertDeliveries(db, batch);
  await setAlertCursor(db, events[events.length - 1]!.seq);
  return batch.length;
}

/**
 * Tell the subscribers about the windows that closed, and move the day cursor.
 *
 * The seventh kind, and the only one no event carries: Section 7, "Past its
 * window an entry stays verified but shows as stale", which is a fact about the
 * calendar rather than something anybody signs. So the pass is keyed by a day
 * instead of a position — the entries whose `expires_at` falls after the day
 * the last pass covered and on or before today — and the sweep runs its
 * staleness step before this one, so a window that closed overnight is told
 * about in the run that noticed it.
 *
 * The body is about the entry's own submission: that seq is what the seal in it
 * covers and what the proof link recomputes against, and `at` is the day the
 * window ran out. The id is derived from the entry, that day and the endpoint
 * (`staleDeliveryId`), and the write is `INSERT OR IGNORE`, so a pass rerun
 * against a cursor somebody moved back creates nothing twice.
 */
async function createStaleDeliveries(
  db: D1Like,
  input: { now: Date; origin: string },
  endpoints: readonly AlertEndpointRecord[],
): Promise<number> {
  const runDay = dayNumber(input.now.toISOString().slice(0, DATE_LENGTH));
  const cursor = await staleAlertCursor(db);
  if (cursor >= runDay) return 0;

  const after = dayDate(cursor);
  const through = dayDate(runDay);
  const at = input.now.toISOString();
  const batch: AlertDeliveryInput[] = [];

  let afterExpiresAt: string | undefined;
  let afterId: string | undefined;
  for (;;) {
    const page = await staleAlertsDue(
      db,
      afterExpiresAt === undefined || afterId === undefined
        ? { after, through, limit: LIST_PAGE_LIMIT }
        : { after, through, limit: LIST_PAGE_LIMIT, afterExpiresAt, afterId },
    );
    if (page.length === 0) break;

    for (const due of page) {
      const stored = await getEntry(db, due.id);
      // A row in the index with no entry behind it is not this step's to
      // explain; there is nothing to say about an entry it cannot read.
      if (stored === null) continue;
      const core = extractCore(stored.entry);
      const view = {
        domain: domainOf(core),
        subject: String(core["subject"]),
        category: String(core["category"]),
        kind: "stale" as const,
      };
      const matching = endpoints.filter((endpoint) =>
        alertMatches(filterOf(endpoint), view),
      );
      // Nothing matched, so nothing is derived: the hash and the seal below are
      // work nobody asked for.
      if (matching.length === 0) continue;

      // The same rule the sealed pass keeps: an alert whose position is not
      // sealed yet carries no proof, so it waits for the run that seals it.
      const seal = await sealCovering(db, stored.submittedSeq);
      if (seal === null) continue;

      const alert: DerivedAlert = {
        kind: "stale",
        entry: stored.entry,
        core,
        entry_hash: await entryHash(core),
      };
      for (const endpoint of matching) {
        const id = await staleDeliveryId(due.id, due.expires_at, endpoint.id);
        batch.push({
          id,
          endpointId: endpoint.id,
          eventSeq: stored.submittedSeq,
          kind: "stale",
          entryId: due.id,
          body: bodyFor(
            id,
            alert,
            { seq: stored.submittedSeq, at: due.expires_at },
            seal,
            input.origin,
          ) as unknown as Record<string, unknown>,
          nextAt: at,
          createdAt: at,
        });
      }
    }

    afterExpiresAt = page[page.length - 1]!.expires_at;
    afterId = page[page.length - 1]!.id;
    if (page.length < LIST_PAGE_LIMIT) break;
  }

  await putAlertDeliveriesIfNew(db, batch);
  await setStaleAlertCursor(db, runDay);
  return batch.length;
}

/**
 * Post one delivery, and write what came of it.
 *
 * 2xx is delivered. Anything else is one more attempt: the ladder in
 * ALERT_RETRY_MINUTES says when the next one is, and past its last entry the
 * delivery is failed rather than retried forever. A fetch that threw records
 * the error's name and nothing else — a thrown error's message can carry the
 * URL it was thrown about, and that URL is the subscriber's.
 */
async function deliver(
  db: D1Like,
  delivery: {
    id: string;
    endpoint_id: string;
    attempts: number;
    body: Record<string, unknown>;
    kind: AlertKind;
  },
  input: { now: Date; fetch: typeof fetch },
): Promise<"delivered" | "retried" | "failed"> {
  const at = input.now.toISOString();
  const endpoint = await alertEndpoint(db, delivery.endpoint_id);
  if (endpoint === null || endpoint.disabled_at !== null) {
    // The holder turned it off after this alert was built. Nothing is posted,
    // and the row says why rather than sitting pending forever.
    await markDelivery(db, delivery.id, {
      status: "failed",
      attempts: delivery.attempts,
      nextAt: at,
      deliveredAt: null,
      lastStatus: null,
      lastError: "endpoint_disabled",
    });
    return "failed";
  }

  const body = JSON.stringify(delivery.body);
  const timestamp = Math.floor(input.now.getTime() / 1000);
  const signature = alertSignatureHeader(
    timestamp,
    await signAlert(endpoint.secret, timestamp, body),
  );

  const attempts = delivery.attempts + 1;
  const call = input.fetch;
  let response: Response;
  try {
    response = await call(endpoint.url, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "x-nomankind-alert": delivery.id,
        "x-nomankind-kind": delivery.kind,
        "x-nomankind-signature": signature,
      },
      body,
      signal: AbortSignal.timeout(ALERT_TIMEOUT_MS),
    });
  } catch (error) {
    const name = error instanceof Error ? error.name : "Error";
    return retry(db, delivery.id, attempts, input.now, null, name);
  }

  if (response.status >= 200 && response.status < 300) {
    await markDelivery(db, delivery.id, {
      status: "delivered",
      attempts,
      nextAt: at,
      deliveredAt: at,
      lastStatus: response.status,
      lastError: null,
    });
    return "delivered";
  }

  return retry(db, delivery.id, attempts, input.now, response.status, null);
}

/** Schedule the next attempt, or give up once the ladder is exhausted. */
async function retry(
  db: D1Like,
  id: string,
  attempts: number,
  now: Date,
  lastStatus: number | null,
  lastError: string | null,
): Promise<"retried" | "failed"> {
  const minutes = ALERT_RETRY_MINUTES[attempts - 1];
  if (minutes === undefined) {
    await markDelivery(db, id, {
      status: "failed",
      attempts,
      nextAt: now.toISOString(),
      deliveredAt: null,
      lastStatus,
      lastError,
    });
    return "failed";
  }
  await markDelivery(db, id, {
    status: "pending",
    attempts,
    nextAt: new Date(
      now.getTime() + minutes * MILLISECONDS_PER_MINUTE,
    ).toISOString(),
    deliveredAt: null,
    lastStatus,
    lastError,
  });
  return "retried";
}

/**
 * Derive the alerts the newly sealed events call for, add the windows that
 * closed, and deliver what is due.
 *
 * A deployment nobody subscribed to does no derivation at all: both cursors
 * jump forward — the position one to the sealed head, the day one to today —
 * and the step skips `alerts_no_endpoint`, so the first endpoint ever
 * registered hears about what happens next rather than about everything that
 * ever happened. Deliveries are still attempted in that case,
 * because an endpoint turned off between the two halves of a run left rows
 * behind that have to be closed.
 *
 * `origin` is the public origin for links in alert bodies, and the empty string
 * is what the sweep passes: the bodies carry paths (`/entries/<id>`) and the
 * reader knows which host they subscribed to.
 */
export async function runAlertStep(
  db: D1Like,
  input: {
    now: Date;
    sealedHead: number;
    fetch: typeof fetch;
    origin: string;
  },
  skip: (reason: string) => void,
): Promise<AlertStepReport> {
  let created = 0;
  const endpoints = await enabledAlertEndpoints(db, null, LIST_PAGE_LIMIT);
  if (endpoints.length === 0) {
    await setAlertCursor(db, input.sealedHead);
    await setStaleAlertCursor(
      db,
      dayNumber(input.now.toISOString().slice(0, DATE_LENGTH)),
    );
    skip("alerts_no_endpoint");
  } else {
    created = await createDeliveries(db, input, endpoints);
    created += await createStaleDeliveries(db, input, endpoints);
  }

  let delivered = 0;
  let failed = 0;
  let retried = 0;
  for (const row of await dueDeliveries(
    db,
    input.now.toISOString(),
    LIST_PAGE_LIMIT,
  )) {
    const outcome = await deliver(db, row, input);
    if (outcome === "delivered") delivered += 1;
    else if (outcome === "failed") failed += 1;
    else retried += 1;
  }

  return { created, delivered, failed, retried };
}
