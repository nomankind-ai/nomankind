/**
 * Read receipts, sync receipts, and the day's published count.
 *
 * Whitepaper Section 8, "The frozen reader": a read returns "a signed read
 * receipt naming the entry, the time, and a running counter". Section 9, the
 * accounting paragraph: "Read counts are published to the sealed log daily",
 * so "any reader can compare the receipts they hold against the published
 * counts". Those two sentences are the whole contract of this module: a
 * receipt a reader can keep and check years later, and a day's total the
 * receipts have to add up to.
 *
 * The counter is what makes the comparison bite. It is a single running number
 * across every read, so a receipt is not only "this entry was read" but "this
 * was the nth read nomankind served" — a serving side that under-published a
 * day would have to leave a hole in the sequence, and the reader holding the
 * receipt on either side of it can see the hole.
 *
 * The signature construction mirrors src/records.ts: a domain-separation tag, a
 * newline, and the RFC 8785 canonical JSON of exactly the fields being signed.
 * The tag is what stops a read receipt from ever being replayed as an entry,
 * event, seal, witness or record signature.
 *
 * Pure: no I/O, no storage, no clock. The caller supplies `read_at` from the
 * injected clock and the counter from the store. Ed25519 goes through WebCrypto
 * only (src/identity.ts), so this runs unchanged on Cloudflare Workers.
 */

import { base64urlDecode, base64urlEncode } from "./encoding.js";
import type { EventPayloads, ReadCountRow } from "./events.js";
import { canonicalize } from "./hash.js";
import { publicKeyFromAgentId, signBytes, verifyBytes } from "./identity.js";
import type { SyncReceiptEntry } from "./sync.js";

/**
 * Domain-separation tag for a read receipt. A format constant, not a policy
 * number: it names what the signature is over.
 */
export const HASH_TAG_READ_RECEIPT = "nomankind-read-receipt-v1";

/**
 * One signed read receipt.
 *
 * `entry_hash` is the entry's core hash exactly as `entryHash` gives it
 * ("sha256:<hex>"), so the receipt names not just the entry but the version of
 * it that was served: an entry that is later superseded cannot be passed off as
 * the one this reader paid for.
 */
export interface ReadReceipt {
  entry_id: string;
  entry_hash: string;
  /** ISO 8601 date-time, from the injected clock. */
  read_at: string;
  /** The running counter: a safe integer, 1 for the first read ever served. */
  counter: number;
  /** The signing agent's 1F916 id (D-014: an agent id is its public key). */
  issuer: string;
  /** Unpadded base64url, the encoding every other kernel signature uses. */
  signature: string;
}

/** A receipt before it is signed: the five fields the signature covers. */
export type ReadReceiptFields = Omit<ReadReceipt, "signature">;

const encoder = new TextEncoder();

/**
 * The exact bytes an issuer signs: the tag, a newline, and the canonical JSON
 * of the five fields. The signature is never over itself, so a verifier
 * rebuilds these bytes from the receipt it holds and asks the key named inside
 * it.
 */
export function readReceiptSigningBytes(fields: ReadReceiptFields): Uint8Array {
  const canonical = canonicalize({
    entry_id: fields.entry_id,
    entry_hash: fields.entry_hash,
    read_at: fields.read_at,
    counter: fields.counter,
    issuer: fields.issuer,
  });
  return encoder.encode(`${HASH_TAG_READ_RECEIPT}\n${canonical}`);
}

/** Sign a receipt, returning the whole record the reader is handed. */
export async function signReadReceipt(
  fields: ReadReceiptFields,
  privateKey: CryptoKey,
): Promise<ReadReceipt> {
  const signature = await signBytes(
    privateKey,
    readReceiptSigningBytes(fields),
  );
  return { ...fields, signature: base64urlEncode(signature) };
}

/** Whether a value is a plain object rather than null or an array. */
function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/**
 * Verify a read receipt against the key inside its own `issuer` id.
 *
 * Returns false, never throws, on any malformed input: a receipt that is not an
 * object, an issuer that carries no key, a counter that is not a safe integer,
 * a signature that is not base64url. A reader checking their own shoebox of
 * receipts gets a verdict, not an exception.
 */
export async function verifyReadReceipt(receipt: unknown): Promise<boolean> {
  try {
    if (!isRecord(receipt)) return false;
    const { entry_id, entry_hash, read_at, counter, issuer, signature } =
      receipt;
    if (
      typeof entry_id !== "string" ||
      typeof entry_hash !== "string" ||
      typeof read_at !== "string" ||
      typeof issuer !== "string" ||
      typeof signature !== "string"
    ) {
      return false;
    }
    if (!Number.isSafeInteger(counter)) return false;
    return await verifyBytes(
      publicKeyFromAgentId(issuer),
      readReceiptSigningBytes({
        entry_id,
        entry_hash,
        read_at,
        counter: counter as number,
        issuer,
      }),
      base64urlDecode(signature),
    );
  } catch {
    return false;
  }
}

// ---------------------------------------------------------------------------
// Sync receipts
// ---------------------------------------------------------------------------

/**
 * Domain-separation tag for a sync receipt. Its own tag, not the read
 * receipt's: the two cover different fields, and a signature over one must
 * never be replayable as the other.
 */
export const HASH_TAG_SYNC_RECEIPT = "nomankind-sync-receipt-v1";

/**
 * One signed receipt covering a whole delta-stream response.
 *
 * Whitepaper Section 8, "The delta stream": the response carries the new head
 * and one signed receipt covering every delivered entry. One receipt rather
 * than one per entry, because a trainer syncing a page of a thousand events is
 * having one conversation, and a thousand signatures would be a thousand
 * things to keep and check for a single exchange.
 *
 * `from` and `head` are what make the receipt resumable evidence: together they
 * say exactly which stretch of sealed positions the trainer was served, so two
 * receipts held side by side show whether anything between them was skipped.
 * `event_count` is how many events that stretch delivered — filtered items
 * included, because the trainer was served the page, not the entries — while
 * `entries` names only the distinct entries it touched. `counter` is the same
 * running counter the read receipt carries, shared across both kinds, so a
 * trainer and a reader can place their receipts in one stream of everything
 * nomankind served (Section 9's accounting paragraph).
 */
export interface SyncReceipt {
  /** The sealed position the trainer resumed from. */
  from: number;
  /** The sealed head this response leaves the trainer at. */
  head: number;
  /** The distinct entries delivered, in first-delivery order. */
  entries: SyncReceiptEntry[];
  /** How many events the response delivered. */
  event_count: number;
  /** ISO 8601 date-time, from the injected clock. */
  issued_at: string;
  /** The running counter, shared with read receipts. */
  counter: number;
  /** The signing agent's 1F916 id (D-014: an agent id is its public key). */
  issuer: string;
  /** Unpadded base64url, the encoding every other kernel signature uses. */
  signature: string;
}

/** A receipt before it is signed: the seven fields the signature covers. */
export type SyncReceiptFields = Omit<SyncReceipt, "signature">;

/**
 * The exact bytes an issuer signs: the tag, a newline, and the canonical JSON
 * of the seven fields.
 *
 * The entries are rebuilt field by field rather than passed through, exactly as
 * the read receipt's five fields are: the signature covers the three fields
 * that name an entry and its version, and nothing a caller happened to hang off
 * the objects it handed in.
 */
export function syncReceiptSigningBytes(fields: SyncReceiptFields): Uint8Array {
  const canonical = canonicalize({
    from: fields.from,
    head: fields.head,
    entries: fields.entries.map((entry) => ({
      entry_id: entry.entry_id,
      entry_hash: entry.entry_hash,
      status: entry.status,
    })),
    event_count: fields.event_count,
    issued_at: fields.issued_at,
    counter: fields.counter,
    issuer: fields.issuer,
  });
  return encoder.encode(`${HASH_TAG_SYNC_RECEIPT}\n${canonical}`);
}

/** Sign a sync receipt, returning the whole record the trainer is handed. */
export async function signSyncReceipt(
  fields: SyncReceiptFields,
  privateKey: CryptoKey,
): Promise<SyncReceipt> {
  const signature = await signBytes(
    privateKey,
    syncReceiptSigningBytes(fields),
  );
  return { ...fields, signature: base64urlEncode(signature) };
}

/** Whether a value is one entry of a sync receipt and nothing else. */
function isSyncReceiptEntry(value: unknown): value is SyncReceiptEntry {
  if (!isRecord(value)) return false;
  return (
    typeof value["entry_id"] === "string" &&
    typeof value["entry_hash"] === "string" &&
    typeof value["status"] === "string"
  );
}

/**
 * Verify a sync receipt against the key inside its own `issuer` id.
 *
 * Returns false, never throws, on any malformed input, exactly as
 * `verifyReadReceipt` does: a trainer checking the receipts it kept from last
 * year's syncs gets a verdict, not an exception.
 */
export async function verifySyncReceipt(receipt: unknown): Promise<boolean> {
  try {
    if (!isRecord(receipt)) return false;
    const {
      from,
      head,
      entries,
      event_count,
      issued_at,
      counter,
      issuer,
      signature,
    } = receipt;
    if (typeof issued_at !== "string" || typeof issuer !== "string") {
      return false;
    }
    if (typeof signature !== "string") return false;
    if (
      !Number.isSafeInteger(from) ||
      !Number.isSafeInteger(head) ||
      !Number.isSafeInteger(event_count) ||
      !Number.isSafeInteger(counter)
    ) {
      return false;
    }
    if (!Array.isArray(entries) || !entries.every(isSyncReceiptEntry)) {
      return false;
    }
    return await verifyBytes(
      publicKeyFromAgentId(issuer),
      syncReceiptSigningBytes({
        from: from as number,
        head: head as number,
        entries: entries as SyncReceiptEntry[],
        event_count: event_count as number,
        issued_at,
        counter: counter as number,
        issuer,
      }),
      base64urlDecode(signature),
    );
  } catch {
    return false;
  }
}

/** Every reason a day's read count can be refused. */
export const READ_COUNT_REFUSALS = [
  "bad_date",
  "duplicate_entry_id",
  "bad_count",
] as const;

export type ReadCountRefusal = (typeof READ_COUNT_REFUSALS)[number];

const DATE_PATTERN = /^\d{4}-\d{2}-\d{2}$/;

/** Whether a string is exactly "YYYY-MM-DD" of a real calendar day. */
function isCalendarDate(date: unknown): date is string {
  if (typeof date !== "string" || !DATE_PATTERN.test(date)) return false;
  const parsed = new Date(`${date}T00:00:00Z`);
  if (Number.isNaN(parsed.getTime())) return false;
  return parsed.toISOString().slice(0, 10) === date;
}

/**
 * Build the payload of one day's `read_count` event.
 *
 * Refuses rather than repairs. A duplicate entry_id would make the total
 * disagree with the rows a reader adds up; a count below one would be a row
 * claiming a read that produced no receipt; a date that is not a real UTC day
 * names no day at all. Each is a bug in whoever grouped the receipts, and a
 * published count that quietly papered over one would be exactly the thing
 * Section 9 asks readers to check.
 *
 * The rows are sorted by entry_id here, so the canonical form of the payload —
 * and therefore the event hash — never depends on what order the store
 * returned. `total` is the sum, and zero is allowed: a day nobody read is a
 * true thing to publish, and it is the day with no counters, so both bounds are
 * null.
 */
export function buildReadCountPayload(
  date: string,
  rows: readonly ReadCountRow[],
  counterFirst: number | null,
  counterLast: number | null,
): EventPayloads["read_count"] {
  if (!isCalendarDate(date)) {
    throw new RangeError(
      `buildReadCountPayload: bad_date: ${String(date)} is not a UTC calendar day`,
    );
  }

  const seen = new Set<string>();
  let total = 0;
  for (const row of rows) {
    if (seen.has(row.entry_id)) {
      throw new RangeError(
        `buildReadCountPayload: duplicate_entry_id: ${row.entry_id}`,
      );
    }
    seen.add(row.entry_id);
    if (!Number.isSafeInteger(row.count) || row.count < 1) {
      throw new RangeError(
        `buildReadCountPayload: bad_count: ${row.entry_id} has ${String(row.count)}`,
      );
    }
    total += row.count;
  }

  const reads = rows
    .map((row) => ({ entry_id: row.entry_id, count: row.count }))
    .sort((left, right) => (left.entry_id < right.entry_id ? -1 : 1));

  return {
    date,
    reads,
    total,
    counter_first: total === 0 ? null : counterFirst,
    counter_last: total === 0 ? null : counterLast,
  };
}
