/**
 * The query-shaped store for keyed access: keys, the day's quota, and the
 * receipts one key holds.
 *
 * The same discipline as src/storage/repository.ts, and beside it rather than
 * inside it because this is a different subject: the repository holds the log
 * and everything derived from it, and nothing here is derived from the log at
 * all. A key is a credential and a quota row is a counter. Drop every table
 * this module reads and the log is untouched.
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

const KEY_COLUMNS = `id, key_hash, tier, status, client_day, counter, created_at, updated_at`;

/** The event type the published daily read count is written under. */
const READ_COUNT: EventType = "read_count";

function toKeyRecord(row: Row): KeyRecord {
  return {
    id: readText(row, "id"),
    tier: readText(row, "tier"),
    status: readText(row, "status") as KeyStatus,
    counter: readInteger(row, "counter"),
    created_at: readText(row, "created_at"),
    updated_at: readText(row, "updated_at"),
  };
}

/**
 * A client that already holds today's key.
 *
 * One key per client per UTC day (D-127). The guard is the unique index on
 * `client_day` in migrations/0023_money_removed.sql and not the check the door
 * made before it wrote: two requests at the same instant both see nothing and
 * both insert, and exactly one of them succeeds. This is what the other one
 * means, and the door answers it 429.
 */
export class KeyDayConflictError extends Error {
  override readonly name = "KeyDayConflictError";
  readonly clientDay: string;

  constructor(clientDay: string, options?: { cause?: unknown }) {
    super(`putKey: ${clientDay} already holds today's key`, options);
    this.clientDay = clientDay;
  }
}

/**
 * Store one minted key.
 *
 * The hash goes in and the secret does not exist here: it was shown to its
 * holder once, by the door, and this module has never seen it.
 *
 * Throws `KeyDayConflictError` when this client already has today's key. The
 * table is asked rather than the driver's message read, exactly as
 * `putReadReceipt` asks: a row now standing at this client-day is what the
 * conflict means, and any other failure is not ours to rename.
 */
export async function putKey(
  db: D1Like,
  input: {
    readonly id: string;
    readonly keyHash: string;
    readonly tier: string;
    readonly status: KeyStatus;
    /** The client and the UTC day this key was minted for: the daily guard. */
    readonly clientDay: string;
    readonly createdAt: string;
  },
): Promise<KeyRecord> {
  try {
    await db
      .prepare(
        `INSERT INTO api_keys (${KEY_COLUMNS}) VALUES (?, ?, ?, ?, ?, 0, ?, ?)`,
      )
      .bind(
        input.id,
        input.keyHash,
        input.tier,
        input.status,
        input.clientDay,
        input.createdAt,
        input.createdAt,
      )
      .run();
  } catch (cause) {
    const standing = await keyByClientDay(db, input.clientDay);
    if (standing !== null) {
      throw new KeyDayConflictError(input.clientDay, { cause });
    }
    throw cause;
  }
  return {
    id: input.id,
    tier: input.tier,
    status: input.status,
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
 * One key by the client and UTC day it was minted for, or null.
 *
 * What the free door asks before it mints: one standard key per client per day,
 * answered courteously here and enforced by the unique index behind it.
 */
export async function keyByClientDay(
  db: D1Like,
  clientDay: string,
): Promise<KeyRecord | null> {
  const row = await db
    .prepare(
      `SELECT ${KEY_COLUMNS} FROM api_keys WHERE client_day = ? ${ONE_ROW}`,
    )
    .bind(clientDay)
    .first<Row>();
  return row === null ? null : toKeyRecord(row);
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
