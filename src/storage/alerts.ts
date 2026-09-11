/**
 * The query-shaped store for change alerts.
 *
 * Whitepaper Section 9, Money: "Revenue comes from high-rate API access,
 * structured feeds and webhooks, change alerts." This module holds the
 * endpoints a key subscribed and the deliveries made to them — the tables
 * migrations/0015_paid_access.sql created.
 *
 * The same discipline as the two storage modules beside it: every read is a
 * primary-key lookup, a bounded range or a keyset page, every list takes the
 * caller's own explicit limit, and no policy number lives here.
 *
 * The endpoint's secret is in this module because it has to be — a delivery
 * signs with it — and it leaves through exactly one door, once, at
 * registration. Nothing here logs it, and `AlertDeliveryRecord` has no field it
 * could reach.
 */

import type { AlertKind } from "../policy.js";
import {
  readInteger,
  readJson,
  readNullableInteger,
  readNullableText,
  readText,
  writeBoolean,
  writeJson,
  type D1Like,
  type D1LikeStatement,
  type Row,
} from "./d1.js";
import { ledgerCursor, setLedgerCursor } from "./repository.js";

/**
 * `LIMIT 1` is not a page size and not a policy number: it says "the one row
 * this lookup can return". No other numeric literal appears in this module.
 */
const ONE_ROW = "LIMIT 1";

/** The alert step's cursor row in `ledger_state`, seeded by migration 0015. */
const ALERT_CURSOR = "alerts";

/**
 * The stale pass's own cursor row in `ledger_state`, holding a UTC day rather
 * than a position: nothing is appended when a freshness window closes, so there
 * is no seq to remember. No migration seeds it — `ledgerCursor` answers null
 * for a row that is not there and `setLedgerCursor` upserts — which is what
 * `STALE_ALERT_CURSOR_UNSET` below is for.
 */
const STALE_ALERT_CURSOR = "alerts_stale";

const ENDPOINT_COLUMNS = `id, key_id, url, secret, domain, subject, category, kinds_json, created_at, disabled_at`;

const DELIVERY_COLUMNS = `id, endpoint_id, event_seq, kind, entry_id, body_json, status, attempts, next_at, delivered_at, last_status, last_error, created_at`;

/** One subscribed endpoint. The secret is the delivery signature's key. */
export interface AlertEndpointRecord {
  id: string;
  key_id: string;
  url: string;
  /** The shared secret, base64url. Never returned by a door after the first. */
  secret: string;
  /** The filters, each null for "any". */
  domain: string | null;
  subject: string | null;
  category: string | null;
  kinds: readonly AlertKind[] | null;
  created_at: string;
  /** When it was turned off; null while it is live. */
  disabled_at: string | null;
}

/** One attempt to tell one endpoint about one sealed change. */
export interface AlertDeliveryRecord {
  id: string;
  endpoint_id: string;
  event_seq: number;
  kind: AlertKind;
  entry_id: string;
  /** The body that was signed and sent, verbatim. */
  body: Record<string, unknown>;
  status: "pending" | "delivered" | "failed";
  attempts: number;
  next_at: string;
  delivered_at: string | null;
  /** The last HTTP status, or null when the fetch itself failed. */
  last_status: number | null;
  last_error: string | null;
  created_at: string;
}

function toEndpoint(row: Row): AlertEndpointRecord {
  const kinds = readNullableText(row, "kinds_json");
  return {
    id: readText(row, "id"),
    key_id: readText(row, "key_id"),
    url: readText(row, "url"),
    secret: readText(row, "secret"),
    domain: readNullableText(row, "domain"),
    subject: readNullableText(row, "subject"),
    category: readNullableText(row, "category"),
    kinds: kinds === null ? null : (JSON.parse(kinds) as AlertKind[]),
    created_at: readText(row, "created_at"),
    disabled_at: readNullableText(row, "disabled_at"),
  };
}

function toDelivery(row: Row): AlertDeliveryRecord {
  return {
    id: readText(row, "id"),
    endpoint_id: readText(row, "endpoint_id"),
    event_seq: readInteger(row, "event_seq"),
    kind: readText(row, "kind") as AlertKind,
    entry_id: readText(row, "entry_id"),
    body: readJson<Record<string, unknown>>(row, "body_json"),
    status: readText(row, "status") as AlertDeliveryRecord["status"],
    attempts: readInteger(row, "attempts"),
    next_at: readText(row, "next_at"),
    delivered_at: readNullableText(row, "delivered_at"),
    last_status: readNullableInteger(row, "last_status"),
    last_error: readNullableText(row, "last_error"),
    created_at: readText(row, "created_at"),
  };
}

// ---------------------------------------------------------------------------
// Endpoints
// ---------------------------------------------------------------------------

/** What one key asked for, before it exists as a row. */
export interface AlertEndpointInput {
  readonly id: string;
  readonly keyId: string;
  readonly url: string;
  readonly secret: string;
  readonly domain: string | null;
  readonly subject: string | null;
  readonly category: string | null;
  readonly kinds: readonly AlertKind[] | null;
  readonly createdAt: string;
}

/** Store one endpoint, and answer it back as the record it became. */
export async function putAlertEndpoint(
  db: D1Like,
  input: AlertEndpointInput,
): Promise<AlertEndpointRecord> {
  await db
    .prepare(
      `INSERT INTO alert_endpoints (${ENDPOINT_COLUMNS}) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, NULL)`,
    )
    .bind(
      input.id,
      input.keyId,
      input.url,
      input.secret,
      input.domain,
      input.subject,
      input.category,
      input.kinds === null ? null : writeJson(input.kinds),
      input.createdAt,
    )
    .run();
  return {
    id: input.id,
    key_id: input.keyId,
    url: input.url,
    secret: input.secret,
    domain: input.domain,
    subject: input.subject,
    category: input.category,
    kinds: input.kinds,
    created_at: input.createdAt,
    disabled_at: null,
  };
}

/**
 * One key's live endpoints, oldest first.
 *
 * Enabled only, and that is what the cap counts and what the holder's own
 * listing shows: an endpoint that was deleted is gone as far as its holder is
 * concerned, and the row survives only so the deliveries that name it keep
 * naming something. Bounded by the key's own cap rather than by a page size,
 * which the caller passes as its limit.
 */
export async function alertEndpointsForKey(
  db: D1Like,
  keyId: string,
  limit: number,
): Promise<AlertEndpointRecord[]> {
  const rows = await db
    .prepare(
      `SELECT ${ENDPOINT_COLUMNS} FROM alert_endpoints
       WHERE key_id = ? AND disabled_at IS NULL ORDER BY created_at, id LIMIT ?`,
    )
    .bind(keyId, limit)
    .all<Row>();
  return rows.results.map(toEndpoint);
}

/** One endpoint by its id, enabled or not, or null. */
export async function alertEndpoint(
  db: D1Like,
  id: string,
): Promise<AlertEndpointRecord | null> {
  const row = await db
    .prepare(
      `SELECT ${ENDPOINT_COLUMNS} FROM alert_endpoints WHERE id = ? ${ONE_ROW}`,
    )
    .bind(id)
    .first<Row>();
  return row === null ? null : toEndpoint(row);
}

/**
 * Turn one endpoint off.
 *
 * Disabled and never deleted: the deliveries already attempted name it, and a
 * holder asking what happened to an endpoint it removed is asking a question
 * the log of attempts can still answer. Writing `disabled_at` a second time is
 * refused by the WHERE rather than allowed to move the date.
 */
export async function disableAlertEndpoint(
  db: D1Like,
  id: string,
  at: string,
): Promise<void> {
  await db
    .prepare(
      `UPDATE alert_endpoints SET disabled_at = ? WHERE id = ? AND disabled_at IS NULL`,
    )
    .bind(at, id)
    .run();
}

/**
 * A page of every key's live endpoints, in id order.
 *
 * What the alert step matches each derived alert against. Keyset on the primary
 * key, so a deployment with more endpoints than one page holds is walked rather
 * than truncated by whatever the database felt like returning first.
 */
export async function enabledAlertEndpoints(
  db: D1Like,
  after: string | null,
  limit: number,
): Promise<AlertEndpointRecord[]> {
  const statement =
    after === null
      ? db
          .prepare(
            `SELECT ${ENDPOINT_COLUMNS} FROM alert_endpoints
             WHERE disabled_at IS NULL ORDER BY id LIMIT ?`,
          )
          .bind(limit)
      : db
          .prepare(
            `SELECT ${ENDPOINT_COLUMNS} FROM alert_endpoints
             WHERE disabled_at IS NULL AND id > ? ORDER BY id LIMIT ?`,
          )
          .bind(after, limit);
  const rows = await statement.all<Row>();
  return rows.results.map(toEndpoint);
}

/** How many endpoints are enabled, across every key. */
export async function countAlertEndpoints(db: D1Like): Promise<number> {
  const row = await db
    .prepare(
      `SELECT COUNT(*) AS n FROM alert_endpoints WHERE disabled_at IS NULL`,
    )
    .first<Row>();
  return row === null ? 0 : readInteger(row, "n");
}

// ---------------------------------------------------------------------------
// Deliveries
// ---------------------------------------------------------------------------

/** One delivery as the alert step builds it, before anything was attempted. */
export interface AlertDeliveryInput {
  readonly id: string;
  readonly endpointId: string;
  readonly eventSeq: number;
  readonly kind: AlertKind;
  readonly entryId: string;
  /** The body, as the object; the stored JSON is what is signed and sent. */
  readonly body: Record<string, unknown>;
  readonly nextAt: string;
  readonly createdAt: string;
}

/**
 * Store a run of pending deliveries in one batch.
 *
 * One batch and not a loop, because a step that examined a page of events and
 * then wrote half its deliveries would have to be able to say which half: the
 * cursor moves in the same run, and a partial write under a moved cursor is an
 * alert nobody will ever be told about.
 */
export async function putAlertDeliveries(
  db: D1Like,
  batch: readonly AlertDeliveryInput[],
): Promise<void> {
  await insertDeliveries(db, batch, "INSERT");
}

/**
 * The same batch, written `INSERT OR IGNORE`.
 *
 * What the stale pass uses, because its ids are derived from the entry, the day
 * its window closed and the endpoint rather than drawn at random: a pass that
 * saw the same row twice would otherwise tell a subscriber twice about one day.
 * The clash is on the primary key, so an id that is already there is left
 * exactly as it is — attempts, status and all — and never reset to pending.
 */
export async function putAlertDeliveriesIfNew(
  db: D1Like,
  batch: readonly AlertDeliveryInput[],
): Promise<void> {
  await insertDeliveries(db, batch, "INSERT OR IGNORE");
}

async function insertDeliveries(
  db: D1Like,
  batch: readonly AlertDeliveryInput[],
  verb: "INSERT" | "INSERT OR IGNORE",
): Promise<void> {
  if (batch.length === 0) return;
  const statements: D1LikeStatement[] = batch.map((delivery) =>
    db
      .prepare(
        `${verb} INTO alert_deliveries (${DELIVERY_COLUMNS})
         VALUES (?, ?, ?, ?, ?, ?, 'pending', 0, ?, NULL, NULL, NULL, ?)`,
      )
      .bind(
        delivery.id,
        delivery.endpointId,
        delivery.eventSeq,
        delivery.kind,
        delivery.entryId,
        writeJson(delivery.body),
        delivery.nextAt,
        delivery.createdAt,
      ),
  );
  await db.batch(statements);
}

/**
 * The pending deliveries due at or before an instant, oldest first.
 *
 * A bounded range on the (status, next_at) index from 0015 and never a scan of
 * every delivery ever attempted. Oldest first so a backlog drains in the order
 * it built up.
 */
export async function dueDeliveries(
  db: D1Like,
  now: string,
  limit: number,
): Promise<AlertDeliveryRecord[]> {
  const rows = await db
    .prepare(
      `SELECT ${DELIVERY_COLUMNS} FROM alert_deliveries
       WHERE status = 'pending' AND next_at <= ? ORDER BY next_at, id LIMIT ?`,
    )
    .bind(now, limit)
    .all<Row>();
  return rows.results.map(toDelivery);
}

/** How many pending deliveries are due at or before this instant. */
export async function countDueDeliveries(
  db: D1Like,
  now: string,
): Promise<number> {
  const row = await db
    .prepare(
      `SELECT COUNT(*) AS n FROM alert_deliveries
       WHERE status = 'pending' AND next_at <= ?`,
    )
    .bind(now)
    .first<Row>();
  return row === null ? 0 : readInteger(row, "n");
}

/** How many deliveries gave up. Not a failing light: the endpoint's problem. */
export async function countFailedDeliveries(db: D1Like): Promise<number> {
  const row = await db
    .prepare(`SELECT COUNT(*) AS n FROM alert_deliveries WHERE status = 'failed'`)
    .first<Row>();
  return row === null ? 0 : readInteger(row, "n");
}

/** What one attempt made of a delivery. */
export interface AlertDeliveryOutcome {
  readonly status: AlertDeliveryRecord["status"];
  readonly attempts: number;
  readonly nextAt: string;
  readonly deliveredAt: string | null;
  /** The HTTP status, or null when the fetch itself never answered. */
  readonly lastStatus: number | null;
  /** The error's name only — never its message, which can carry the URL. */
  readonly lastError: string | null;
}

/** Write what one attempt made of one delivery. */
export async function markDelivery(
  db: D1Like,
  id: string,
  outcome: AlertDeliveryOutcome,
): Promise<void> {
  await db
    .prepare(
      `UPDATE alert_deliveries
       SET status = ?, attempts = ?, next_at = ?, delivered_at = ?,
           last_status = ?, last_error = ?
       WHERE id = ?`,
    )
    .bind(
      outcome.status,
      outcome.attempts,
      outcome.nextAt,
      outcome.deliveredAt,
      outcome.lastStatus,
      outcome.lastError,
      id,
    )
    .run();
}

/**
 * One endpoint's deliveries, newest first, one keyset page.
 *
 * `after` is the id of the last row the caller saw, and the page continues from
 * that row's own position — the (created_at, id) pair, so two deliveries built
 * in the same run of the step cannot hide each other. An `after` naming no row
 * of this endpoint starts at the top rather than answering nothing, because a
 * cursor from another endpoint is a caller's mistake and not an empty page.
 */
export async function deliveriesForEndpoint(
  db: D1Like,
  endpointId: string,
  after: string | null,
  limit: number,
): Promise<AlertDeliveryRecord[]> {
  let cursor: { createdAt: string; id: string } | null = null;
  if (after !== null) {
    const row = await db
      .prepare(
        `SELECT created_at, id FROM alert_deliveries
         WHERE id = ? AND endpoint_id = ? ${ONE_ROW}`,
      )
      .bind(after, endpointId)
      .first<Row>();
    if (row !== null) {
      cursor = { createdAt: readText(row, "created_at"), id: readText(row, "id") };
    }
  }

  const statement =
    cursor === null
      ? db
          .prepare(
            `SELECT ${DELIVERY_COLUMNS} FROM alert_deliveries
             WHERE endpoint_id = ? ORDER BY created_at DESC, id DESC LIMIT ?`,
          )
          .bind(endpointId, limit)
      : db
          .prepare(
            `SELECT ${DELIVERY_COLUMNS} FROM alert_deliveries
             WHERE endpoint_id = ?
               AND (created_at < ? OR (created_at = ? AND id < ?))
             ORDER BY created_at DESC, id DESC LIMIT ?`,
          )
          .bind(endpointId, cursor.createdAt, cursor.createdAt, cursor.id, limit);

  const rows = await statement.all<Row>();
  return rows.results.map(toDelivery);
}

// ---------------------------------------------------------------------------
// The step's cursor
// ---------------------------------------------------------------------------

/**
 * How far the alert step has read over the sealed log: ledger_state 'alerts'.
 *
 * -1 is "before the first event", which is what migration 0015 seeds and what a
 * row somebody dropped reads as: seq 0 is a real position, so a cursor of 0
 * would mean the first event had already been examined.
 */
export async function alertCursor(db: D1Like): Promise<number> {
  return (await ledgerCursor(db, ALERT_CURSOR)) ?? -1;
}

/** Move it. The same row every other step's cursor lives in. */
export async function setAlertCursor(db: D1Like, seq: number): Promise<void> {
  await setLedgerCursor(db, ALERT_CURSOR, seq);
}

/**
 * The day the stale pass last ran, as days since 1970-01-01, or -1 when no row
 * exists yet.
 *
 * -1 rather than 0, for the reason the position cursor above uses it: day 0 is
 * a real day, and a missing row has to read as "before every day there is".
 */
export async function staleAlertCursor(db: D1Like): Promise<number> {
  return (await ledgerCursor(db, STALE_ALERT_CURSOR)) ?? -1;
}

/** Move it, to the day the run happened on. */
export async function setStaleAlertCursor(
  db: D1Like,
  day: number,
): Promise<void> {
  await setLedgerCursor(db, STALE_ALERT_CURSOR, day);
}

// ---------------------------------------------------------------------------
// The entries whose window closed
// ---------------------------------------------------------------------------

/** Which stale rows one pass is about, and where it resumes. */
export interface StaleAlertsQuery {
  /** Strictly after this date, "YYYY-MM-DD": the day the last pass covered. */
  readonly after: string;
  /** Up to and including this date: the day this run is happening on. */
  readonly through: string;
  /** The caller's own page size. There is no default. */
  readonly limit: number;
  /** Resume strictly after this (expires_at, id); omit both for the first page. */
  readonly afterExpiresAt?: string;
  readonly afterId?: string;
}

/**
 * The entries the staleness step has marked stale whose window ran out inside
 * one span of days.
 *
 * The mirror image of `staleDue` in src/storage/repository.ts, which finds the
 * rows a window has closed on and leaves them marked; this finds the rows that
 * are already marked, so it runs after that step in the same sweep and sees the
 * day's work. The span is half-open on the left because the cursor names a day
 * that was already covered, and closed on the right because today's expiries
 * are this run's to tell somebody about.
 *
 * Keyset by (expires_at, id) like every other page here, with the caller's own
 * limit: a deployment where a thousand windows closed at once is walked rather
 * than truncated. `expires_at IS NOT NULL` leaves out the categories that carry
 * no window, which can never be stale and whose column would compare as null
 * anyway.
 */
export async function staleAlertsDue(
  db: D1Like,
  query: StaleAlertsQuery,
): Promise<Array<{ id: string; expires_at: string }>> {
  const bindings: unknown[] = [writeBoolean(true), query.after, query.through];
  let cursor = "";
  if (query.afterExpiresAt !== undefined && query.afterId !== undefined) {
    cursor = "AND (expires_at > ? OR (expires_at = ? AND id > ?)) ";
    bindings.push(query.afterExpiresAt, query.afterExpiresAt, query.afterId);
  }
  bindings.push(query.limit);

  const rows = await db
    .prepare(
      `SELECT id, expires_at FROM entries
       WHERE stale = ? AND expires_at IS NOT NULL
         AND expires_at > ? AND expires_at <= ? ${cursor}ORDER BY expires_at, id LIMIT ?`,
    )
    .bind(...bindings)
    .all<Row>();
  return rows.results.map((row) => ({
    id: readText(row, "id"),
    expires_at: readText(row, "expires_at"),
  }));
}
