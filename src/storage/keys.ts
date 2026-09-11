/**
 * The query-shaped store for paid access: keys, the day's quota, the provider's
 * events, and the receipts one key holds.
 *
 * The same discipline as src/storage/repository.ts, and beside it rather than
 * inside it because this is a different subject: the repository holds the log
 * and everything derived from it, and nothing here is derived from the log at
 * all. A key is a credential, a quota row is a counter, and a provider event is
 * a note that we have already acted on a message. Drop every table this module
 * reads and the log is untouched.
 *
 * Every read is a primary-key lookup, a bounded range, or a keyset page, and
 * every list takes the caller's own explicit limit: this module holds no page
 * size and no policy number. Every function takes the database first; there is
 * no class, no connection state and no cache.
 *
 * The secret of a key is never here. `putKey` takes the hash the kernel made
 * and nothing else, and no function in this module returns it: a caller that
 * wanted to compare two secrets would have to hash one, which is the point.
 */

import type { Event, EventType } from "../events.js";
import type { KeyRecord, KeyStatus } from "../keys.js";
import type { ReadReceipt, SyncReceipt } from "../receipt.js";
import {
  readInteger,
  readJson,
  readNullableText,
  readText,
  type D1Like,
  type Row,
} from "./d1.js";

/**
 * `LIMIT 1` is not a page size and not a policy number: it says "the one row
 * this lookup can return". No other numeric literal appears in this module.
 */
const ONE_ROW = "LIMIT 1";

const KEY_COLUMNS = `id, key_hash, tier, status, customer, subscription, checkout_session, counter, created_at, updated_at`;

/** The event type the published daily read count is written under. */
const READ_COUNT: EventType = "read_count";

function toKeyRecord(row: Row): KeyRecord {
  return {
    id: readText(row, "id"),
    tier: readText(row, "tier"),
    status: readText(row, "status") as KeyStatus,
    customer: readText(row, "customer"),
    subscription: readText(row, "subscription"),
    checkout_session: readText(row, "checkout_session"),
    counter: readInteger(row, "counter"),
    created_at: readText(row, "created_at"),
    updated_at: readText(row, "updated_at"),
  };
}

/**
 * A key that is already claimed.
 *
 * A checkout session mints one key however many times its success URL is
 * opened, and a subscription pays for one. The guard is the pair of unique
 * indexes in migrations/0015_paid_access.sql and not the check the door made
 * before it wrote: two tabs opened at the same instant both see nothing and
 * both insert, and exactly one of them succeeds. This is what the other one
 * means, and the door answers it 409.
 */
export class KeyClaimConflictError extends Error {
  override readonly name = "KeyClaimConflictError";
  readonly checkoutSession: string;

  constructor(checkoutSession: string, options?: { cause?: unknown }) {
    super(`putKey: checkout session ${checkoutSession} is already claimed`, options);
    this.checkoutSession = checkoutSession;
  }
}

/**
 * Store one minted key.
 *
 * The hash goes in and the secret does not exist here: it was shown to its
 * holder once, by the door, and this module has never seen it.
 *
 * Throws `KeyClaimConflictError` when this session or this subscription already
 * has a key. The table is asked rather than the driver's message read, exactly
 * as `putReadReceipt` asks: a row now standing at this session is what the
 * conflict means, and any other failure is not ours to rename.
 */
export async function putKey(
  db: D1Like,
  input: {
    readonly id: string;
    readonly keyHash: string;
    readonly tier: string;
    readonly status: KeyStatus;
    readonly customer: string;
    readonly subscription: string;
    readonly checkoutSession: string;
    readonly createdAt: string;
  },
): Promise<KeyRecord> {
  try {
    await db
      .prepare(
        `INSERT INTO api_keys (${KEY_COLUMNS}) VALUES (?, ?, ?, ?, ?, ?, ?, 0, ?, ?)`,
      )
      .bind(
        input.id,
        input.keyHash,
        input.tier,
        input.status,
        input.customer,
        input.subscription,
        input.checkoutSession,
        input.createdAt,
        input.createdAt,
      )
      .run();
  } catch (cause) {
    const standing = await keyByCheckoutSession(db, input.checkoutSession);
    if (standing !== null) {
      throw new KeyClaimConflictError(input.checkoutSession, { cause });
    }
    const bySubscription = await keyBySubscription(db, input.subscription);
    if (bySubscription !== null) {
      throw new KeyClaimConflictError(input.checkoutSession, { cause });
    }
    throw cause;
  }
  return {
    id: input.id,
    tier: input.tier,
    status: input.status,
    customer: input.customer,
    subscription: input.subscription,
    checkout_session: input.checkoutSession,
    counter: 0,
    created_at: input.createdAt,
    updated_at: input.createdAt,
  };
}

/** One key by the hash of the secret a caller presented, or null. */
export async function keyByHash(
  db: D1Like,
  hash: string,
): Promise<KeyRecord | null> {
  const row = await db
    .prepare(`SELECT ${KEY_COLUMNS} FROM api_keys WHERE key_hash = ? ${ONE_ROW}`)
    .bind(hash)
    .first<Row>();
  return row === null ? null : toKeyRecord(row);
}

/** One key by its public id, or null. */
export async function keyById(
  db: D1Like,
  id: string,
): Promise<KeyRecord | null> {
  const row = await db
    .prepare(`SELECT ${KEY_COLUMNS} FROM api_keys WHERE id = ? ${ONE_ROW}`)
    .bind(id)
    .first<Row>();
  return row === null ? null : toKeyRecord(row);
}

/**
 * One key by the provider's subscription id, or null.
 *
 * What the webhook door asks: a message names a subscription and nothing else,
 * and a subscription nobody here holds a key for is a message about somebody
 * else's account.
 */
export async function keyBySubscription(
  db: D1Like,
  subscription: string,
): Promise<KeyRecord | null> {
  const row = await db
    .prepare(
      `SELECT ${KEY_COLUMNS} FROM api_keys WHERE subscription = ? ${ONE_ROW}`,
    )
    .bind(subscription)
    .first<Row>();
  return row === null ? null : toKeyRecord(row);
}

/** One key by the checkout session it was claimed from, or null. */
export async function keyByCheckoutSession(
  db: D1Like,
  checkoutSession: string,
): Promise<KeyRecord | null> {
  const row = await db
    .prepare(
      `SELECT ${KEY_COLUMNS} FROM api_keys WHERE checkout_session = ? ${ONE_ROW}`,
    )
    .bind(checkoutSession)
    .first<Row>();
  return row === null ? null : toKeyRecord(row);
}

/**
 * Move one key's status.
 *
 * The only column the webhook door writes. Status is not derived from the log
 * here because it is not in the log: it is what the payment provider says about
 * a subscription, and the log's own record of it is the receipts the key was
 * able to draw while it was active.
 */
export async function setKeyStatus(
  db: D1Like,
  id: string,
  status: KeyStatus,
  updatedAt: string,
): Promise<void> {
  await db
    .prepare(`UPDATE api_keys SET status = ?, updated_at = ? WHERE id = ?`)
    .bind(status, updatedAt, id)
    .run();
}

// ---------------------------------------------------------------------------
// Quota
// ---------------------------------------------------------------------------

/** How many reads this scope has already had today, and 0 when it has had none. */
export async function quotaOn(
  db: D1Like,
  scope: string,
  day: string,
): Promise<number> {
  const row = await db
    .prepare(`SELECT reads FROM quota WHERE scope = ? AND day = ? ${ONE_ROW}`)
    .bind(scope, day)
    .first<Row>();
  return row === null ? 0 : readInteger(row, "reads");
}

/**
 * Add to a scope's day, creating the row if it is the first read.
 *
 * One statement, because two — a SELECT and then an INSERT or an UPDATE — is a
 * race every busy key would lose: two isolates would both read the same number
 * and both write it back plus one. The UPSERT adds to the stored value inside
 * the database, so the count is the database's arithmetic and not ours.
 */
export async function addQuota(
  db: D1Like,
  scope: string,
  day: string,
  reads: number,
): Promise<void> {
  if (reads === 0) return;
  await db
    .prepare(
      `INSERT INTO quota (scope, day, reads) VALUES (?, ?, ?)
       ON CONFLICT (scope, day) DO UPDATE SET reads = reads + excluded.reads`,
    )
    .bind(scope, day, reads)
    .run();
}

/** One row of a scope's usage history. */
export interface QuotaDay {
  readonly day: string;
  readonly reads: number;
}

/**
 * A scope's quota rows over a closed range of days, oldest first.
 *
 * A bounded range on the primary key, never a scan: the caller names both ends
 * and the usage door's window is its own, from the caller's `days`.
 */
export async function quotaDays(
  db: D1Like,
  scope: string,
  fromDay: string,
  toDay: string,
): Promise<QuotaDay[]> {
  const rows = await db
    .prepare(
      `SELECT day, reads FROM quota
       WHERE scope = ? AND day >= ? AND day <= ? ORDER BY day`,
    )
    .bind(scope, fromDay, toDay)
    .all<Row>();
  return rows.results.map((row) => ({
    day: readText(row, "day"),
    reads: readInteger(row, "reads"),
  }));
}

// ---------------------------------------------------------------------------
// The provider's events
// ---------------------------------------------------------------------------

/** Whether this provider event has already been acted on. */
export async function stripeEventSeen(
  db: D1Like,
  id: string,
): Promise<boolean> {
  const row = await db
    .prepare(`SELECT id FROM stripe_events WHERE id = ? ${ONE_ROW}`)
    .bind(id)
    .first<Row>();
  return row !== null;
}

/**
 * Record that a provider event was handled, and what came of it.
 *
 * The primary key is the guard against a retry, so this is written for every
 * event the door understood — including the ones it deliberately ignored.
 */
export async function putStripeEvent(
  db: D1Like,
  input: {
    readonly id: string;
    readonly type: string;
    readonly receivedAt: string;
    readonly outcome: "applied" | "ignored" | "unknown_subscription";
  },
): Promise<void> {
  await db
    .prepare(
      `INSERT INTO stripe_events (id, type, received_at, outcome) VALUES (?, ?, ?, ?)
       ON CONFLICT (id) DO NOTHING`,
    )
    .bind(input.id, input.type, input.receivedAt, input.outcome)
    .run();
}

// ---------------------------------------------------------------------------
// What the log already published
// ---------------------------------------------------------------------------

/**
 * The `read_count` event for one UTC day, or null when none has been published.
 *
 * By type and by the date inside the payload, which is an index seek on the
 * (type, seq) index from 0001 followed by a JSON read of the few rows that type
 * has — never a scan of the log, which is what a usage page asking for thirty
 * days would otherwise cost thirty times over.
 *
 * The newest such event wins, because a day republished is a day corrected.
 */
export async function readCountEventOn(
  db: D1Like,
  date: string,
): Promise<Event | null> {
  const row = await db
    .prepare(
      `SELECT seq, "at", type, entry_id, payload, prev_hash, hash FROM events
       WHERE type = ? AND json_extract(payload, '$.date') = ?
       ORDER BY seq DESC ${ONE_ROW}`,
    )
    .bind(READ_COUNT, date)
    .first<Row>();
  if (row === null) return null;
  return {
    seq: readInteger(row, "seq"),
    at: readText(row, "at"),
    type: readText(row, "type") as EventType,
    entry_id: readNullableText(row, "entry_id"),
    payload: readJson<Event["payload"]>(row, "payload"),
    prev_hash: readNullableText(row, "prev_hash"),
    hash: readText(row, "hash"),
  };
}

// ---------------------------------------------------------------------------
// One key's receipts
// ---------------------------------------------------------------------------

/** One receipt as a key's own reads page shows it. */
export interface KeyReceiptRow {
  readonly kind: string;
  readonly key_counter: number;
  /** The log-wide running counter the receipt carries. */
  readonly counter: number;
  readonly created_at: string;
  readonly receipt: ReadReceipt | SyncReceipt;
}

/**
 * A page of one key's receipts, in the key's own counter order.
 *
 * Keyset, not offset: the caller passes back the last `key_counter` it saw. The
 * partial unique index on (key_id, key_counter) from 0015 is what makes this a
 * seek, and the receipt goes out verbatim — the bytes that were signed, not a
 * summary of them.
 */
export async function receiptsForKey(
  db: D1Like,
  keyId: string,
  afterKeyCounter: number,
  limit: number,
): Promise<KeyReceiptRow[]> {
  const rows = await db
    .prepare(
      `SELECT kind, key_counter, seq, created_at, payload_json FROM receipts
       WHERE key_id = ? AND key_counter > ?
       ORDER BY key_counter LIMIT ?`,
    )
    .bind(keyId, afterKeyCounter, limit)
    .all<Row>();
  return rows.results.map((row) => ({
    kind: readText(row, "kind"),
    key_counter: readInteger(row, "key_counter"),
    counter: readInteger(row, "seq"),
    created_at: readText(row, "created_at"),
    receipt: readJson<ReadReceipt | SyncReceipt>(row, "payload_json"),
  }));
}
