/**
 * The query-shaped store.
 *
 * Whitepaper Section 11, Deployment and status, and the PoC retrospective's
 * DEPLOY-1: the PoC loaded the whole log into memory and flushed it back, which
 * worked until it did not. Nothing here does that. Every read is a primary-key
 * lookup, a bounded range, or a keyset page, and every list takes the caller's
 * own explicit limit — this module holds no page size, no policy number, and no
 * default anywhere. Policy numbers live in src/policy.ts and nowhere else.
 *
 * Every function takes the database as its first argument. There is no class,
 * no connection state, and no cache: a Worker isolate that handles two requests
 * must not carry anything from the first into the second.
 *
 * The repository never computes or alters a derived field. Status, staleness,
 * the sidecar, the seal — all of it is recomputed from events by src/derive.ts
 * and src/seal.ts, and this module stores the result verbatim. Delete every
 * table but `events` and the rest can be rebuilt; that is the point.
 */

import { utcDay, type Anchor, type AnchorExternal } from "../anchor.js";
import type { OpenAssignment } from "../assign.js";
import { domainOf } from "../core.js";
import { DEFAULT_DOMAIN, LIST_PAGE_LIMIT } from "../policy.js";
import type { DerivedAttestation } from "../attest.js";
import type { BountyAccrual } from "../bounty.js";
import type { Sidecar } from "../derive.js";
import type { LedgerRow } from "../ledger.js";
import type { ProbeAnswer } from "../probe.js";
import {
  appendEvent,
  type Attestation,
  type AttestationScorer,
  type Event,
  type EventInput,
  type EventType,
  type ReadCountRow,
} from "../events.js";
import type { ReadReceipt, SyncReceipt } from "../receipt.js";
import type { StakeRecord } from "../stake.js";
import type { Entry } from "../schema.js";
import type { RegistrySeal, Seal, WitnessSignature } from "../seal.js";
import {
  isSourceClass,
  sourceClassOf,
  type SourceClassification,
} from "../sources.js";
import {
  readBoolean,
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

/**
 * `LIMIT 1` below is not a page size and not a policy number: it says "the one
 * row this lookup can return", which is a fact about the query, not a knob. No
 * other numeric literal appears in this module.
 */
const ONE_ROW = "LIMIT 1";

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/**
 * An append that would break the chain.
 *
 * Section 6, "Seal": the log is append-only and hash-chained, so a batch that
 * does not start exactly where the log ends is refused rather than written and
 * repaired later. `reason` names which of the two links failed, in the same
 * words `verifyChain` uses.
 */
export class EventAppendError extends Error {
  override readonly name = "EventAppendError";
  readonly reason: "bad_seq" | "bad_prev_hash";
  readonly seq: number;

  constructor(reason: "bad_seq" | "bad_prev_hash", seq: number, detail: string) {
    super(`appendEvents: ${reason} at seq ${seq}: ${detail}`);
    this.reason = reason;
    this.seq = seq;
  }
}

/**
 * A seal written where one already stands.
 *
 * Two timers racing to seal the same range must not both succeed: the second
 * would either overwrite a seal the first already chained to, or chain a second
 * seal over the same events. The insert is plain, the unique key refuses the
 * second, and the caller reports it rather than repairing it.
 */
export class SealConflictError extends Error {
  override readonly name = "SealConflictError";
  readonly seq: number;

  constructor(seq: number, options?: { cause?: unknown }) {
    super(`recordSeal: a seal already stands at seq ${seq}`, options);
    this.seq = seq;
  }
}

/** An entry stored with no `entry_submitted` event behind it in the log. */
export class MissingSubmissionError extends Error {
  override readonly name = "MissingSubmissionError";
  readonly entryId: string;

  constructor(entryId: string) {
    super(`putEntry: no entry_submitted event for ${entryId}`);
    this.entryId = entryId;
  }
}

// ---------------------------------------------------------------------------
// Events
// ---------------------------------------------------------------------------

const EVENT_COLUMNS = `seq, "at", type, entry_id, payload, prev_hash, hash`;

function toEvent(row: Row): Event {
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

/** The log's head: the last event's seq and hash, or null on an empty log. */
async function head(db: D1Like): Promise<{ seq: number; hash: string } | null> {
  const row = await db
    .prepare(`SELECT seq, hash FROM events ORDER BY seq DESC ${ONE_ROW}`)
    .first<Row>();
  if (row === null) return null;
  return { seq: readInteger(row, "seq"), hash: readText(row, "hash") };
}

/**
 * The head event itself, or null on an empty log.
 *
 * The writers below seal their event onto this one rather than onto a seq and a
 * hash read apart from it, so the event they append is computed from exactly the
 * row the chain check is then made against.
 */
async function headEvent(db: D1Like): Promise<Event | null> {
  const row = await db
    .prepare(`SELECT ${EVENT_COLUMNS} FROM events ORDER BY seq DESC ${ONE_ROW}`)
    .first<Row>();
  return row === null ? null : toEvent(row);
}

/** The last event's seq, or null when the log is empty. */
export async function headSeq(db: D1Like): Promise<number | null> {
  const at = await head(db);
  return at === null ? null : at.seq;
}

/**
 * Append a run of events in one batch.
 *
 * Refused when the first event does not continue the stored log: its seq must
 * be head + 1 (or 0 on an empty log) and its prev_hash must be the head's hash
 * (or null). The rest of the run is checked to link to the one before it, so a
 * batch that is internally broken is refused before any of it is written rather
 * than half-written. The batch is atomic, so a refusal from D1 leaves the log
 * exactly as it was.
 *
 * Nothing here hashes anything: the events arrive already sealed by
 * `appendEvent`, and re-deriving a hash on the way in would let a storage bug
 * pass for a valid log.
 */
const EVENT_INSERT = `INSERT INTO events (${EVENT_COLUMNS}) VALUES (?, ?, ?, ?, ?, ?, ?)`;

/**
 * Check that a run of events continues the log from `at`, and build the
 * statements that write it.
 *
 * The one place the chain rule is enforced. Every write that appends events
 * goes through this, so the atomic registry writes below cannot drift into a
 * weaker check than a plain append does: the first event's seq must be head + 1
 * (or 0 on an empty log), its prev_hash must be the head's hash (or null), and
 * each later event must link to the one before it. Nothing here hashes
 * anything — the events arrive already sealed by `appendEvent`, and re-deriving
 * a hash on the way in would let a storage bug pass for a valid log.
 */
function eventStatements(
  db: D1Like,
  events: readonly Event[],
  at: { seq: number; hash: string } | null,
): D1LikeStatement[] {
  let expectedSeq = at === null ? 0 : at.seq + 1;
  let expectedPrev: string | null = at === null ? null : at.hash;

  for (const event of events) {
    if (event.seq !== expectedSeq) {
      throw new EventAppendError(
        "bad_seq",
        event.seq,
        `expected seq ${expectedSeq}`,
      );
    }
    if (event.prev_hash !== expectedPrev) {
      throw new EventAppendError(
        "bad_prev_hash",
        event.seq,
        `expected prev_hash ${String(expectedPrev)}`,
      );
    }
    expectedSeq = event.seq + 1;
    expectedPrev = event.hash;
  }

  return events.map((event) =>
    db
      .prepare(EVENT_INSERT)
      .bind(
        event.seq,
        event.at,
        event.type,
        event.entry_id,
        writeJson(event.payload),
        event.prev_hash,
        event.hash,
      ),
  );
}

export async function appendEvents(
  db: D1Like,
  events: readonly Event[],
): Promise<void> {
  if (events.length === 0) return;
  await db.batch(eventStatements(db, events, await head(db)));
}

/** One event by its position in the log. */
export async function eventBySeq(
  db: D1Like,
  seq: number,
): Promise<Event | null> {
  const row = await db
    .prepare(`SELECT ${EVENT_COLUMNS} FROM events WHERE seq = ? ${ONE_ROW}`)
    .bind(seq)
    .first<Row>();
  return row === null ? null : toEvent(row);
}

/**
 * One entry's whole lifecycle: the sub-sequence of the log bearing its id, in
 * seq order. Bounded by the entry, not by the log, and served by the
 * (entry_id, seq) index.
 */
export async function eventsForEntry(
  db: D1Like,
  entryId: string,
): Promise<Event[]> {
  const rows = await db
    .prepare(
      `SELECT ${EVENT_COLUMNS} FROM events WHERE entry_id = ? ORDER BY seq`,
    )
    .bind(entryId)
    .all<Row>();
  return rows.results.map(toEvent);
}

/** A contiguous slice of the log, both ends inclusive, in seq order. */
export async function eventsInRange(
  db: D1Like,
  fromSeq: number,
  toSeqInclusive: number,
): Promise<Event[]> {
  const rows = await db
    .prepare(
      `SELECT ${EVENT_COLUMNS} FROM events WHERE seq >= ? AND seq <= ? ORDER BY seq`,
    )
    .bind(fromSeq, toSeqInclusive)
    .all<Row>();
  return rows.results.map(toEvent);
}

/**
 * The next page of the log after a known position. This is the delta stream's
 * read: the caller keeps the last seq it saw and asks for what came after.
 */
export async function eventsAfter(
  db: D1Like,
  afterSeq: number,
  limit: number,
): Promise<Event[]> {
  const rows = await db
    .prepare(
      `SELECT ${EVENT_COLUMNS} FROM events WHERE seq > ? ORDER BY seq LIMIT ?`,
    )
    .bind(afterSeq, limit)
    .all<Row>();
  return rows.results.map(toEvent);
}

/** The same page, narrowed to one event type. Served by (type, seq). */
export async function eventsOfType(
  db: D1Like,
  type: EventType,
  afterSeq: number,
  limit: number,
): Promise<Event[]> {
  const rows = await db
    .prepare(
      `SELECT ${EVENT_COLUMNS} FROM events WHERE type = ? AND seq > ? ORDER BY seq LIMIT ?`,
    )
    .bind(type, afterSeq, limit)
    .all<Row>();
  return rows.results.map(toEvent);
}

// ---------------------------------------------------------------------------
// Entries
// ---------------------------------------------------------------------------

/**
 * A stored entry: what derivation produced, and where in the log it was
 * produced from. `submittedSeq` is a log coordinate rather than a derived
 * field — it is the position of the entry's own `entry_submitted` event — and
 * it is what every listing orders and pages by.
 */
export interface StoredEntry {
  readonly entry: Entry;
  readonly sidecar: Sidecar;
  readonly submittedSeq: number;
  readonly derivedThroughSeq: number;
}

/**
 * The sidecar as the row holds it, with the keys a later milestone added
 * defaulted rather than left undefined.
 *
 * `revalidations` arrived in M20 and 0009 backfills every stored row with it,
 * but the window between that migration and the deploy belongs to the previous
 * Worker, which writes rows without the key. A reader that trusted the JSON
 * would hand a page `undefined.length`. Defaulting here is not a second
 * derivation: for a row written before the key existed there is no revalidation
 * to fold, so the empty list is the same answer rederiving would give.
 *
 * `source` arrived in M23b (decision D-080) and is defaulted the same way, for
 * the same reason and with the same guarantee: the class is a pure function of
 * the stored core's domain, subject and citation, so computing it here from the
 * row's own entry gives the identical answer `deriveEntry` would. No migration,
 * and a page never sees the key missing.
 *
 * The same default carries D-081's rename: a row written between M23b and that
 * decision holds `source.provider` and no `authority`, so the key check is for
 * the key this code reads and not merely for a class. Such a row is recomputed
 * from its own core, which is what the old key held anyway, and the stale key
 * goes with the object it was on -- again no migration.
 */
function toSidecar(row: Row, entry: Entry): Sidecar {
  const stored = readJson<Sidecar>(row, "sidecar_json");
  const sidecar = Array.isArray(stored.revalidations)
    ? stored
    : { ...stored, revalidations: [] };
  const source = sidecar.source as SourceClassification | undefined;
  const usable =
    source !== undefined && isSourceClass(source.class) && "authority" in source;
  if (usable) return sidecar;
  const core = entry as unknown as Record<string, unknown>;
  return {
    ...sidecar,
    source: sourceClassOf(domainOf(core), core["subject"], core["citation"]),
  };
}

function toStoredEntry(row: Row): StoredEntry {
  const entry = readJson<Entry>(row, "entry_json");
  return {
    entry,
    sidecar: toSidecar(row, entry),
    submittedSeq: readInteger(row, "submitted_seq"),
    derivedThroughSeq: readInteger(row, "derived_through_seq"),
  };
}

const ENTRY_COLUMNS = `entry_json, sidecar_json, submitted_seq, derived_through_seq`;

/** A required string field on the entry, read by the schema's own field name. */
function entryField(entry: Entry, field: string): string {
  const value = (entry as Record<string, unknown>)[field];
  if (typeof value !== "string") {
    throw new TypeError(`putEntry: entry.${field} must be a string`);
  }
  return value;
}

/**
 * A field the schema declares present but nullable — `expires_at` on an
 * event-category entry, `supersedes` on an entry that supersedes nothing. Absent
 * is not the same as null and is refused: the schema writes an unused slot as
 * null, never by leaving it out.
 */
function entryNullableField(entry: Entry, field: string): string | null {
  const value = (entry as Record<string, unknown>)[field];
  if (value === null) return null;
  if (typeof value !== "string") {
    throw new TypeError(`putEntry: entry.${field} must be a string or null`);
  }
  return value;
}

/** A required boolean field on the entry. */
function entryBooleanField(entry: Entry, field: string): boolean {
  const value = (entry as Record<string, unknown>)[field];
  if (typeof value !== "boolean") {
    throw new TypeError(`putEntry: entry.${field} must be a boolean`);
  }
  return value;
}

/** The position of the entry's submission event. */
async function submittedSeqOf(db: D1Like, entryId: string): Promise<number> {
  const row = await db
    .prepare(
      `SELECT seq FROM events WHERE entry_id = ? AND type = 'entry_submitted' ORDER BY seq ${ONE_ROW}`,
    )
    .bind(entryId)
    .first<Row>();
  if (row === null) throw new MissingSubmissionError(entryId);
  return readInteger(row, "seq");
}

/**
 * Store one derived entry, replacing whatever was there.
 *
 * `entry` is exactly what `deriveEntry` returned and is written verbatim; the
 * columns beside it are copies of fields already inside it, kept out so the
 * listings can filter and order without parsing every row. They are never a
 * second source of truth: rederiving from the events and storing again
 * rewrites them together.
 */
export async function putEntry(
  db: D1Like,
  entry: Entry,
  sidecar: Sidecar,
  derivedThroughSeq: number,
): Promise<void> {
  const submittedSeq = await submittedSeqOf(db, entryField(entry, "id"));
  await entryStatement(db, entry, sidecar, submittedSeq, derivedThroughSeq).run();
}

/**
 * The upsert that stores one derived entry row. Taken as a statement rather
 * than run on the spot so a submission can write the entry, its events and its
 * captures in one atomic batch (`submitEntry` below), and so both paths write
 * exactly the same row.
 */
function entryStatement(
  db: D1Like,
  entry: Entry,
  sidecar: Sidecar,
  submittedSeq: number,
  derivedThroughSeq: number,
): D1LikeStatement {
  return db
    .prepare(
      `INSERT INTO entries (
         id, subject, category, domain, status, submitted_at, submitted_seq,
         author, stale, expires_at, supersedes,
         entry_json, sidecar_json, derived_through_seq
       ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
       ON CONFLICT (id) DO UPDATE SET
         subject = excluded.subject,
         category = excluded.category,
         domain = excluded.domain,
         status = excluded.status,
         submitted_at = excluded.submitted_at,
         submitted_seq = excluded.submitted_seq,
         author = excluded.author,
         stale = excluded.stale,
         expires_at = excluded.expires_at,
         supersedes = excluded.supersedes,
         entry_json = excluded.entry_json,
         sidecar_json = excluded.sidecar_json,
         derived_through_seq = excluded.derived_through_seq`,
    )
    .bind(
      entryField(entry, "id"),
      entryField(entry, "subject"),
      entryField(entry, "category"),
      // The signed core's own eighteenth key, or ai-ecosystem for a legacy v0.6
      // entry that carries none: `domainOf` is the one place that reads it.
      domainOf(entry),
      entryField(entry, "status"),
      entryField(entry, "submitted_at"),
      submittedSeq,
      entryField(entry, "author"),
      writeBoolean(entryBooleanField(entry, "stale")),
      entryNullableField(entry, "expires_at"),
      entryNullableField(entry, "supersedes"),
      writeJson(entry),
      writeJson(sidecar),
      derivedThroughSeq,
    );
}

/** One entry by id, with its sidecar, or null. */
export async function getEntry(
  db: D1Like,
  id: string,
): Promise<StoredEntry | null> {
  const row = await db
    .prepare(`SELECT ${ENTRY_COLUMNS} FROM entries WHERE id = ? ${ONE_ROW}`)
    .bind(id)
    .first<Row>();
  return row === null ? null : toStoredEntry(row);
}

/** What a listing may narrow by, and where it resumes. */
export interface ListEntriesQuery {
  readonly subject?: string;
  readonly category?: string;
  /** The registered domain (decision D-071); omit for every domain. */
  readonly domain?: string;
  readonly status?: string;
  /** The caller's own page size. There is no default. */
  readonly limit: number;
  /** Resume strictly after this submitted_seq; omit for the first page. */
  readonly afterSubmittedSeq?: number;
}

/**
 * A page of entries in submitted_seq order.
 *
 * Keyset, not offset: the caller passes back the last submitted_seq it saw, so
 * the page is an index seek whose cost does not grow with how far in it is, and
 * an entry appended between two pages cannot shift a row across the boundary.
 */
export async function listEntries(
  db: D1Like,
  query: ListEntriesQuery,
): Promise<StoredEntry[]> {
  const conditions: string[] = [];
  const bindings: unknown[] = [];

  if (query.subject !== undefined) {
    conditions.push("subject = ?");
    bindings.push(query.subject);
  }
  if (query.category !== undefined) {
    conditions.push("category = ?");
    bindings.push(query.category);
  }
  if (query.domain !== undefined) {
    conditions.push("domain = ?");
    bindings.push(query.domain);
  }
  if (query.status !== undefined) {
    conditions.push("status = ?");
    bindings.push(query.status);
  }
  if (query.afterSubmittedSeq !== undefined) {
    conditions.push("submitted_seq > ?");
    bindings.push(query.afterSubmittedSeq);
  }
  bindings.push(query.limit);

  const where = conditions.length === 0 ? "" : `WHERE ${conditions.join(" AND ")} `;
  const rows = await db
    .prepare(
      `SELECT ${ENTRY_COLUMNS} FROM entries ${where}ORDER BY submitted_seq LIMIT ?`,
    )
    .bind(...bindings)
    .all<Row>();
  return rows.results.map(toStoredEntry);
}

/**
 * The entries that declare they supersede this one, oldest submission first.
 *
 * `supersedes` is part of the signed core — "Id of the earlier entry this one
 * supersedes, declared by the submitter and checked by validators" — so this
 * reads what submitters declared, not what derivation concluded. Which of them
 * actually took effect is derivation's answer (the target's `superseded_by`),
 * and the rule that picks it lives in src/derive.ts, not here.
 *
 * The caller's limit is explicit and there is no default: this module holds no
 * page size. Served by the partial `entries_supersedes` index
 * (migrations/0005_freshness.sql).
 */
export async function supersedersOf(
  db: D1Like,
  entryId: string,
  limit: number,
): Promise<string[]> {
  const rows = await db
    .prepare(
      `SELECT id FROM entries WHERE supersedes = ? ORDER BY submitted_seq LIMIT ?`,
    )
    .bind(entryId, limit)
    .all<Row>();
  return rows.results.map((row) => readText(row, "id"));
}

/** One version sibling: the entry's id and the subject it names. */
export interface VersionSibling {
  readonly id: string;
  readonly subject: string;
}

/**
 * Every entry of one domain whose subject starts with a `<party>/<model>/`
 * prefix, oldest submission first (decision D-096).
 *
 * schema/nomankind-domain-registry-v1.md, "Staleness on a version change": an
 * observation goes stale when another entry about a later version of the same
 * model verifies, so derivation has to be handed those entries or it cannot see
 * the one that retires this one. This is the read that finds them: a prefix
 * match over the indexed `domain` and `subject` columns, bounded by the
 * caller's own limit, exactly as every other listing here is.
 *
 * A prefix and not a LIKE pattern: the three characters SQLite's LIKE treats as
 * special are escaped here, so a subject carrying a `%` or a `_` matches
 * itself and never everything.
 *
 * Which of the returned entries is actually a later version, and whether it
 * verified, is derivation's answer (src/derive.ts, `isVersionStale`) and is
 * never decided here.
 */
export async function versionSiblingsOf(
  db: D1Like,
  domain: string,
  prefix: string,
  limit: number,
): Promise<VersionSibling[]> {
  const escaped = `${prefix}/`.replace(/[\\%_]/g, (character) => `\\${character}`);
  const rows = await db
    .prepare(
      `SELECT id, subject FROM entries
       WHERE domain = ? AND subject LIKE ? ESCAPE '\\'
       ORDER BY submitted_seq LIMIT ?`,
    )
    .bind(domain, `${escaped}%`, limit)
    .all<Row>();
  return rows.results.map((row) => ({
    id: readText(row, "id"),
    subject: readText(row, "subject"),
  }));
}

/** Where a staleness sweep looks, and where it resumes. */
export interface StaleDueQuery {
  /**
   * The current UTC calendar day, "YYYY-MM-DD" (the schema's `date` format, the
   * same shape `expires_at` carries). Compared as text, which is chronological
   * because the format is fixed-width and zero-padded.
   */
  readonly today: string;
  /** The caller's own page size. There is no default. */
  readonly limit: number;
  /** Resume strictly after this (expires_at, id); omit both for the first page. */
  readonly afterExpiresAt?: string;
  readonly afterId?: string;
}

/**
 * The entries whose freshness window has run out but which are not yet marked
 * stale.
 *
 * Whitepaper Section 7, "Freshness and decay": "Past its window an entry stays
 * verified but shows as stale." The window closing is a fact about the calendar
 * rather than an event anyone appends, so something has to walk the entries the
 * day turned on and rederive them. This is that read.
 *
 * Strictly before today, matching derivation: src/derive.ts marks an entry stale
 * once the current day is past `expires_at`, so the expiry day itself is still
 * fresh and an entry expiring today is not due. `stale = 0` keeps an entry the
 * sweep already handled from coming back, and `expires_at IS NOT NULL` leaves
 * out the event categories, which carry no window and can never go stale.
 *
 * Keyset by (expires_at, id), not offset: the caller passes back the last pair
 * it saw, so a page is an index seek whose cost does not grow with how far in it
 * is, and an entry rewritten between two pages cannot shift a row across the
 * boundary. The id breaks the tie between two entries expiring on the same day,
 * so the order is total and no row is skipped or served twice. Served by the
 * partial `entries_stale_due` index (migrations/0005_freshness.sql).
 */
export async function staleDue(
  db: D1Like,
  query: StaleDueQuery,
): Promise<Array<{ id: string; expires_at: string }>> {
  const bindings: unknown[] = [query.today];
  let cursor = "";
  if (query.afterExpiresAt !== undefined && query.afterId !== undefined) {
    cursor = "AND (expires_at > ? OR (expires_at = ? AND id > ?)) ";
    bindings.push(query.afterExpiresAt, query.afterExpiresAt, query.afterId);
  }
  bindings.push(query.limit);

  const rows = await db
    .prepare(
      `SELECT id, expires_at FROM entries
       WHERE stale = 0 AND expires_at IS NOT NULL AND expires_at < ? ${cursor}ORDER BY expires_at, id LIMIT ?`,
    )
    .bind(...bindings)
    .all<Row>();
  return rows.results.map((row) => ({
    id: readText(row, "id"),
    expires_at: readText(row, "expires_at"),
  }));
}

// ---------------------------------------------------------------------------
// Captures
// ---------------------------------------------------------------------------

/**
 * The index into the snapshot archive (migrations/0003_captures.sql).
 *
 * `contentHash` is the hash the entry carries — computed under the norm rule,
 * over the extracted content and never over the raw bytes — and `archiveHash`
 * is the R2 key, which is the hash of the raw bytes. The two are the same value
 * only where the rule hashes the bytes themselves. Nothing here holds the bytes:
 * the archive does, and this is the pointer to them.
 */
export interface CaptureRecord {
  readonly entryId: string;
  /**
   * "snapshot" for the entry's snapshot_hash, "receipt" for its receipt_hash,
   * "statement" for the provider statement page a transcript entry cites, and
   * `report:<seq>` for the frozen artifact a failure report carries (Section 8:
   * "with its transcript frozen and hashed like any artifact").
   *
   * "statement" is the one role no signed hash stands behind: Section 4 makes a
   * provider's own statement the verification basis of a behavior claim, so the
   * page is captured at submit and this row is the record of what it said then.
   * Nothing compares it to anything; it is evidence, served like the rest.
   *
   * The table's key is (entry_id, role), and an entry has at most one snapshot,
   * one receipt and one statement — but any number of readers may report it, so
   * a report's role carries the position of its own `failure_report` event. That
   * makes each report's artifact its own row and keeps it from overwriting the
   * entry's own captures, which is what a plain "receipt" role would have done.
   *
   * "disclosure" is the delayed-disclosure payload of a redacted transcript
   * (decision D-096): the original values the artifact carries placeholders
   * for, archived at their own content address. An entry has at most one, and
   * it is the one role a read is gated on -- src/worker/submit.ts serves it to
   * a signed operator request, and to anybody once the domain's window has run
   * from the entry's `submitted_at`. The column is the existing one and this
   * value is a new string in it: no migration.
   */
  readonly role:
    | "snapshot"
    | "receipt"
    | "statement"
    | "disclosure"
    | `report:${number}`;
  readonly contentHash: string;
  readonly archiveHash: string;
  readonly normVersion: string;
  /** html, json, pdf, text, binary, transcript, receipt. */
  readonly kind: string;
  readonly mediaType: string;
  readonly size: number;
  readonly fetchedAt: string;
}

const CAPTURE_COLUMNS = `entry_id, role, content_hash, archive_hash, norm_version, kind, media_type, size, fetched_at`;

function toCapture(row: Row): CaptureRecord {
  return {
    entryId: readText(row, "entry_id"),
    role: readText(row, "role") as CaptureRecord["role"],
    contentHash: readText(row, "content_hash"),
    archiveHash: readText(row, "archive_hash"),
    normVersion: readText(row, "norm_version"),
    kind: readText(row, "kind"),
    mediaType: readText(row, "media_type"),
    size: readInteger(row, "size"),
    fetchedAt: readText(row, "fetched_at"),
  };
}

/** The upsert that stores one capture row. */
function captureStatement(
  db: D1Like,
  capture: CaptureRecord,
): D1LikeStatement {
  return db
    .prepare(
      `INSERT INTO captures (${CAPTURE_COLUMNS}) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
       ON CONFLICT (entry_id, role) DO UPDATE SET
         content_hash = excluded.content_hash,
         archive_hash = excluded.archive_hash,
         norm_version = excluded.norm_version,
         kind = excluded.kind,
         media_type = excluded.media_type,
         size = excluded.size,
         fetched_at = excluded.fetched_at`,
    )
    .bind(
      capture.entryId,
      capture.role,
      capture.contentHash,
      capture.archiveHash,
      capture.normVersion,
      capture.kind,
      capture.mediaType,
      capture.size,
      capture.fetchedAt,
    );
}

/** Store one capture, replacing whatever was there. */
export async function putCapture(
  db: D1Like,
  capture: CaptureRecord,
): Promise<void> {
  await captureStatement(db, capture).run();
}

/**
 * The capture a hash names, or null.
 *
 * This is the read behind the public capture route: a reader holding an entry's
 * snapshot_hash asks what was captured under it. Two entries may cite the same
 * page and carry the same hash, so the answer is the earliest capture of it,
 * and the entry id breaks a tie between two captures taken at the same instant:
 * the same question always gets the same answer. Served by the
 * (content_hash, fetched_at, entry_id) index.
 */
export async function captureForHash(
  db: D1Like,
  contentHash: string,
): Promise<CaptureRecord | null> {
  const row = await db
    .prepare(
      `SELECT ${CAPTURE_COLUMNS} FROM captures
       WHERE content_hash = ? ORDER BY fetched_at, entry_id ${ONE_ROW}`,
    )
    .bind(contentHash)
    .first<Row>();
  return row === null ? null : toCapture(row);
}

/**
 * Every index row that points at one content hash, oldest fetch first.
 *
 * `captureForHash` answers with the first of these, which is all a plain read
 * of the bytes needs. This answers with all of them, because whether a capture
 * may be served at all can depend on every role it is referenced under
 * (decision D-096): a disclosure payload that some other entry also cites as
 * its snapshot is that entry's evidence and is served as such, so the gate asks
 * about the whole set and not about whichever row sorted first.
 */
export async function capturesForHash(
  db: D1Like,
  contentHash: string,
  limit: number = LIST_PAGE_LIMIT,
): Promise<CaptureRecord[]> {
  const rows = await db
    .prepare(
      `SELECT ${CAPTURE_COLUMNS} FROM captures
       WHERE content_hash = ? ORDER BY fetched_at, entry_id LIMIT ?`,
    )
    .bind(contentHash, limit)
    .all<Row>();
  return rows.results.map(toCapture);
}

/**
 * Every capture one entry rests on, in role order, up to `limit` of them.
 *
 * Bounded by the entry — the table's key is (entry_id, role) — and bounded again
 * by an explicit limit, because `report:<seq>` roles accumulate one per failure
 * report and no read here may be open-ended. The number is the caller's;
 * `LIST_PAGE_LIMIT` stands behind the callers that want one entry's captures
 * whole, and it is src/policy.ts's number rather than one invented here.
 */
export async function capturesForEntry(
  db: D1Like,
  entryId: string,
  limit: number = LIST_PAGE_LIMIT,
): Promise<CaptureRecord[]> {
  const rows = await db
    .prepare(
      `SELECT ${CAPTURE_COLUMNS} FROM captures WHERE entry_id = ? ORDER BY role LIMIT ?`,
    )
    .bind(entryId, limit)
    .all<Row>();
  return rows.results.map(toCapture);
}

/**
 * Submit an entry: append its `entry_submitted` event and write the derived
 * entry and its capture rows, atomically.
 *
 * Whitepaper Section 6, "Submit": the entry appears immediately, marked draft,
 * and the source is snapshotted at that moment. The event is the record and
 * everything beside it is an index into the event, so an entries row without its
 * event would be an entry nobody can verify offline, and a capture row without
 * it would point at evidence for a submission that never happened. One `batch`
 * makes both impossible: D1 applies it whole or not at all.
 *
 * The events arrive already sealed by `appendEvent` and are checked against the
 * log's head by exactly the rule a plain append uses, so a run that does not
 * continue the chain is refused before anything is written. Nothing here derives
 * a field: `entry` is what `deriveEntry` returned, written verbatim.
 */
export async function submitEntry(
  db: D1Like,
  input: {
    readonly events: readonly Event[];
    readonly entry: Entry;
    readonly sidecar: Sidecar;
    readonly derivedThroughSeq: number;
    readonly captures: readonly CaptureRecord[];
  },
): Promise<void> {
  const id = entryField(input.entry, "id");
  const submission = input.events.find(
    (event) => event.type === "entry_submitted" && event.entry_id === id,
  );
  if (submission === undefined) throw new MissingSubmissionError(id);

  const statements = eventStatements(db, input.events, await head(db));
  statements.push(
    entryStatement(
      db,
      input.entry,
      input.sidecar,
      submission.seq,
      input.derivedThroughSeq,
    ),
  );
  for (const capture of input.captures) {
    statements.push(captureStatement(db, capture));
  }
  await db.batch(statements);
}

// ---------------------------------------------------------------------------
// Operators and agents
// ---------------------------------------------------------------------------

/**
 * A registered operator. Section 5, Identity and operators: the operator is the
 * unit of accountability, `maintainer` marks nomankind's own, and `provider`
 * marks the one party the door refuses. `details` carries whatever else the
 * registry holds, stored as JSON so a later milestone can add to it without a
 * migration that reshapes a live table.
 */
export interface OperatorRecord {
  readonly id: string;
  readonly maintainer: boolean;
  readonly provider: boolean;
  readonly registeredSeq: number;
  readonly details: Record<string, unknown>;
}

function toOperator(row: Row): OperatorRecord {
  return {
    id: readText(row, "id"),
    maintainer: readBoolean(row, "maintainer"),
    provider: readBoolean(row, "provider"),
    registeredSeq: readInteger(row, "registered_seq"),
    details: readJson<Record<string, unknown>>(row, "operator_json"),
  };
}

const OPERATOR_COLUMNS = `id, maintainer, provider, registered_seq, operator_json`;

/** The upsert that stores one operator row. */
function operatorStatement(
  db: D1Like,
  operator: OperatorRecord,
): D1LikeStatement {
  return db
    .prepare(
      `INSERT INTO operators (${OPERATOR_COLUMNS}) VALUES (?, ?, ?, ?, ?)
       ON CONFLICT (id) DO UPDATE SET
         maintainer = excluded.maintainer,
         provider = excluded.provider,
         registered_seq = excluded.registered_seq,
         operator_json = excluded.operator_json`,
    )
    .bind(
      operator.id,
      writeBoolean(operator.maintainer),
      writeBoolean(operator.provider),
      operator.registeredSeq,
      writeJson(operator.details),
    );
}

/** Store one operator, replacing whatever was there. */
export async function putOperator(
  db: D1Like,
  operator: OperatorRecord,
): Promise<void> {
  await operatorStatement(db, operator).run();
}

/** One operator by id, or null. */
export async function getOperator(
  db: D1Like,
  id: string,
): Promise<OperatorRecord | null> {
  const row = await db
    .prepare(`SELECT ${OPERATOR_COLUMNS} FROM operators WHERE id = ? ${ONE_ROW}`)
    .bind(id)
    .first<Row>();
  return row === null ? null : toOperator(row);
}

/** A page of operators in id order, resuming strictly after `afterId`. */
export async function listOperators(
  db: D1Like,
  query: { readonly limit: number; readonly afterId?: string },
): Promise<OperatorRecord[]> {
  const rows =
    query.afterId === undefined
      ? await db
          .prepare(`SELECT ${OPERATOR_COLUMNS} FROM operators ORDER BY id LIMIT ?`)
          .bind(query.limit)
          .all<Row>()
      : await db
          .prepare(
            `SELECT ${OPERATOR_COLUMNS} FROM operators WHERE id > ? ORDER BY id LIMIT ?`,
          )
          .bind(query.afterId, query.limit)
          .all<Row>();
  return rows.results.map(toOperator);
}

/**
 * One (operator, domain) row: the operator is attested in that domain, from the
 * position of the event that said so.
 *
 * Decision D-071: registration binds an operator to its first domain's
 * attestation and a join carries a later domain's. This row is the index into
 * those two events and never a second source of truth -- `operatorDomainsAt`
 * (src/derive.ts) folds the same answer out of the log.
 */
export interface OperatorDomainRecord {
  readonly operator: string;
  readonly domain: string;
  readonly seq: number;
  /** The signed attestation exactly as the event carried it; null when unknown. */
  readonly attestation: Attestation | null;
}

const OPERATOR_DOMAIN_COLUMNS = `operator, domain, seq, attestation_json`;

function toOperatorDomain(row: Row): OperatorDomainRecord {
  const attestation = readNullableText(row, "attestation_json");
  return {
    operator: readText(row, "operator"),
    domain: readText(row, "domain"),
    seq: readInteger(row, "seq"),
    attestation:
      attestation === null ? null : (JSON.parse(attestation) as Attestation),
  };
}

/** The upsert that stores one (operator, domain) row. */
function operatorDomainStatement(
  db: D1Like,
  record: OperatorDomainRecord,
): D1LikeStatement {
  return db
    .prepare(
      `INSERT INTO operator_domains (${OPERATOR_DOMAIN_COLUMNS}) VALUES (?, ?, ?, ?)
       ON CONFLICT (operator, domain) DO UPDATE SET
         seq = excluded.seq,
         attestation_json = excluded.attestation_json`,
    )
    .bind(
      record.operator,
      record.domain,
      record.seq,
      record.attestation === null ? null : writeJson(record.attestation),
    );
}

/**
 * Store one (operator, domain) row, replacing whatever was there.
 *
 * The registration and the join both write this row inside the batch that
 * appends their event (`registerOperator`, `recordDomainJoin`), because an
 * attestation without its event would be one nobody can verify offline. A replay
 * has the events already — `npm run import-mirror` appends the whole sealed log
 * before it writes a single row — so it needs the row on its own, and it writes
 * exactly the row those two writers write.
 */
export async function putOperatorDomain(
  db: D1Like,
  record: OperatorDomainRecord,
): Promise<void> {
  await operatorDomainStatement(db, record).run();
}

/**
 * The domains one operator is attested in, in the order it took them on.
 *
 * Registration first, then every join by the position of its event, which is
 * the order the log put them in and the order the operator page shows them.
 */
export async function operatorDomains(
  db: D1Like,
  operator: string,
): Promise<OperatorDomainRecord[]> {
  const rows = await db
    .prepare(
      `SELECT ${OPERATOR_DOMAIN_COLUMNS} FROM operator_domains
       WHERE operator = ? ORDER BY seq`,
    )
    .bind(operator)
    .all<Row>();
  return rows.results.map(toOperatorDomain);
}

/**
 * The operators attested in one domain, in id order.
 *
 * What the caller builds a draw's exclusion list from: the draw itself stays
 * domain-blind (src/assign.ts), so the Worker passes it every pool operator that
 * is not in here. The caller's limit is explicit and there is no default: this
 * module holds no page size. Served by the (domain, operator) index from 0012.
 */
export async function operatorsInDomain(
  db: D1Like,
  domain: string,
  limit: number,
): Promise<string[]> {
  const rows = await db
    .prepare(
      `SELECT operator FROM operator_domains
       WHERE domain = ? ORDER BY operator LIMIT ?`,
    )
    .bind(domain, limit)
    .all<Row>();
  return rows.results.map((row) => readText(row, "operator"));
}

/** An agent: a key, and the operator that answers for it. */
export interface AgentRecord {
  readonly agentId: string;
  readonly operatorId: string;
  readonly registeredSeq: number;
}

const AGENT_COLUMNS = `agent_id, operator_id, registered_seq`;

function toAgent(row: Row): AgentRecord {
  return {
    agentId: readText(row, "agent_id"),
    operatorId: readText(row, "operator_id"),
    registeredSeq: readInteger(row, "registered_seq"),
  };
}

/** The upsert that stores one agent row. */
function agentStatement(db: D1Like, agent: AgentRecord): D1LikeStatement {
  return db
    .prepare(
      `INSERT INTO agents (${AGENT_COLUMNS}) VALUES (?, ?, ?)
       ON CONFLICT (agent_id) DO UPDATE SET
         operator_id = excluded.operator_id,
         registered_seq = excluded.registered_seq`,
    )
    .bind(agent.agentId, agent.operatorId, agent.registeredSeq);
}

/** Store one agent, replacing whatever was there. */
export async function putAgent(db: D1Like, agent: AgentRecord): Promise<void> {
  await agentStatement(db, agent).run();
}

/**
 * The agents bound to one operator, oldest binding first.
 *
 * Section 5: "Every agent under an operator counts as one for validation", so
 * this is the read behind every rule that resolves an operator's agents. The
 * caller's limit is explicit and there is no default: this module holds no page
 * size (src/policy.ts holds LIST_PAGE_LIMIT). Served by the
 * (operator_id, registered_seq) index.
 */
export async function agentsForOperator(
  db: D1Like,
  operatorId: string,
  limit: number,
): Promise<AgentRecord[]> {
  const rows = await db
    .prepare(
      `SELECT ${AGENT_COLUMNS} FROM agents
       WHERE operator_id = ? ORDER BY registered_seq LIMIT ?`,
    )
    .bind(operatorId, limit)
    .all<Row>();
  return rows.results.map(toAgent);
}

/**
 * The operator behind an agent, or null when the agent is unknown. Every rule
 * that says "a distinct operator" resolves through this.
 */
export async function operatorForAgent(
  db: D1Like,
  agentId: string,
): Promise<string | null> {
  const row = await db
    .prepare(
      `SELECT operator_id FROM agents WHERE agent_id = ? ${ONE_ROW}`,
    )
    .bind(agentId)
    .first<Row>();
  return row === null ? null : readText(row, "operator_id");
}

// ---------------------------------------------------------------------------
// Registry writes
// ---------------------------------------------------------------------------

/**
 * Register an operator: append its events and write its rows, atomically.
 *
 * Section 5, Identity and operators, and Section 11's joining steps: the
 * binding is sealed into the log, and only then can the agent validate. The
 * events are the record and the rows are the index into it, so a row without
 * its event would be a registration nobody can verify offline, and an event
 * without its row would be a registration the Worker cannot see. One `batch`
 * makes both impossible: D1 applies it whole or not at all.
 *
 * The caller passes events already sealed by `appendEvent` — the
 * `operator_registered` and the `agent_bound`, in that order — and they are
 * checked against the log's head by exactly the rule a plain append uses, so a
 * run that does not continue the chain is refused before anything is written.
 */
export async function registerOperator(
  db: D1Like,
  input: {
    readonly events: readonly Event[];
    readonly operator: OperatorRecord;
    readonly agent: AgentRecord;
    /**
     * The domain the registration attested to, and the attestation itself
     * (decision D-071). Omitted, the operator is recorded in the default domain
     * with no attestation on the row -- which is exactly what a registration
     * sealed before v0.7 meant.
     */
    readonly domain?: { readonly domain: string; readonly attestation: Attestation | null };
  },
): Promise<void> {
  const statements = eventStatements(db, input.events, await head(db));
  statements.push(operatorStatement(db, input.operator));
  statements.push(agentStatement(db, input.agent));
  statements.push(
    operatorDomainStatement(db, {
      operator: input.operator.id,
      domain: input.domain?.domain ?? DEFAULT_DOMAIN,
      seq: input.operator.registeredSeq,
      attestation: input.domain?.attestation ?? null,
    }),
  );
  await db.batch(statements);
}

/**
 * Bind a second agent to an operator: append the `agent_bound` event and write
 * the agents row, atomically, for the reason `registerOperator` is atomic.
 *
 * Section 5: "An operator runs agents", and every agent under an operator counts
 * as one for validation. The event is the record and the row is the index into
 * it: a row without its event would be a key nobody can verify offline, and an
 * event without its row would be a key the Worker cannot resolve when a
 * validation names its operator. One `batch` makes both impossible.
 *
 * The row's `registeredSeq` is the binding event's own position, which is what
 * orders an operator's agents oldest binding first (`agentsForOperator`).
 */
export async function recordAgentBind(
  db: D1Like,
  input: EventInput<"agent_bound">,
): Promise<Event<"agent_bound">> {
  const { event, statements } = await sealOntoHead(db, input);
  const bound = event as Event<"agent_bound">;
  statements.push(
    agentStatement(db, {
      agentId: bound.payload.agent,
      operatorId: bound.payload.operator,
      registeredSeq: bound.seq,
    }),
  );
  await db.batch(statements);
  return bound;
}

/**
 * Record a domain join: append the `operator_joined_domain` event and write its
 * row, atomically, for the reason `registerOperator` is atomic. The event is the
 * record and the row is the index into it: a row without its event would be an
 * attestation nobody can verify offline, and an event without its row would be
 * an attestation the Worker cannot see when it builds a draw's exclusions.
 */
export async function recordDomainJoin(
  db: D1Like,
  input: EventInput<"operator_joined_domain">,
): Promise<Event<"operator_joined_domain">> {
  const { event, statements } = await sealOntoHead(db, input);
  const joined = event as Event<"operator_joined_domain">;
  statements.push(
    operatorDomainStatement(db, {
      operator: joined.payload.operator,
      domain: joined.payload.domain,
      seq: joined.seq,
      attestation: joined.payload.attestation,
    }),
  );
  await db.batch(statements);
  return joined;
}

/**
 * Trust an operator: append the `operator_trusted` event and replace its row,
 * atomically, for the same reason `registerOperator` is atomic.
 *
 * Section 11: trusted status is granted once at genesis and otherwise earned,
 * and either way the event is what grants it. The row here carries whatever the
 * caller recomputed alongside it; nothing about trust is derived in storage.
 */
export async function trustOperator(
  db: D1Like,
  input: { readonly event: Event; readonly operator: OperatorRecord },
): Promise<void> {
  const statements = eventStatements(db, [input.event], await head(db));
  statements.push(operatorStatement(db, input.operator));
  await db.batch(statements);
}

// ---------------------------------------------------------------------------
// Assignments
// ---------------------------------------------------------------------------

/**
 * What an assignment answers. 0009 added the column with 'validation' as its
 * default, so every row written before it keeps the meaning it already had.
 *
 * Not a policy number and not a knob: two literal values that name the two
 * kinds of draw the log makes. Section 6 draws a validator for a submission and
 * a checker for a revalidation request, and the two must never answer each
 * other's assignment.
 */
export type AssignmentPurpose = "validation" | "revalidation";

const VALIDATION: AssignmentPurpose = "validation";
const REVALIDATION: AssignmentPurpose = "revalidation";

/**
 * The upsert that stores one assignment row. `missed_seq` and `answered_seq`
 * start null: an assignment is open when it is made, and only an
 * `assignment_missed` or a `validation` closes it. Taken as a statement rather
 * than run on the spot so a draw can append its event and open its row in one
 * atomic batch (`recordAssignment` below), and so both paths write the same row.
 */
function assignmentStatement(
  db: D1Like,
  entryId: string,
  assignment: OpenAssignment,
  purpose: AssignmentPurpose = VALIDATION,
  requestSeq: number | null = null,
): D1LikeStatement {
  return db
    .prepare(
      `INSERT INTO assignments (entry_id, seq, operator_id, deadline, missed_seq, assignment_json, purpose, request_seq)
       VALUES (?, ?, ?, ?, NULL, ?, ?, ?)
       ON CONFLICT (seq) DO UPDATE SET
         entry_id = excluded.entry_id,
         operator_id = excluded.operator_id,
         deadline = excluded.deadline,
         assignment_json = excluded.assignment_json,
         purpose = excluded.purpose,
         request_seq = excluded.request_seq`,
    )
    .bind(
      entryId,
      assignment.seq,
      assignment.operator,
      assignment.deadline,
      writeJson(assignment),
      purpose,
      requestSeq,
    );
}

/** Store one assignment, replacing whatever was there. */
export async function putAssignment(
  db: D1Like,
  entryId: string,
  assignment: OpenAssignment,
): Promise<void> {
  await assignmentStatement(db, entryId, assignment).run();
}

/**
 * The entry's open assignment: the newest one that is neither missed nor
 * answered, or null.
 *
 * The newest assignment is the one in force, so an earlier one never reopens.
 * An assignment closes two ways — the window runs out, or the validator answers
 * — and both are a position in the log, so both are read here. Leaving the
 * answered ones open would have the sweep seal an `assignment_missed` against a
 * validator who responded inside their seventy-two hours.
 *
 * Served by the (entry_id, seq) index.
 */
export async function openAssignment(
  db: D1Like,
  entryId: string,
): Promise<OpenAssignment | null> {
  const row = await db
    .prepare(
      `SELECT assignment_json FROM assignments
       WHERE entry_id = ? AND purpose = ? AND missed_seq IS NULL AND answered_seq IS NULL
       ORDER BY seq DESC ${ONE_ROW}`,
    )
    .bind(entryId, VALIDATION)
    .first<Row>();
  return row === null ? null : readJson<OpenAssignment>(row, "assignment_json");
}

/**
 * Close an assignment by naming the `assignment_missed` event that closed it.
 * The miss is a position in the log, not a flag: the event stays the record and
 * this column is only the index into it.
 */
export async function markAssignmentMissed(
  db: D1Like,
  entryId: string,
  seq: number,
  missedSeq: number,
): Promise<void> {
  await db
    .prepare(
      `UPDATE assignments SET missed_seq = ? WHERE entry_id = ? AND seq = ?`,
    )
    .bind(missedSeq, entryId, seq)
    .run();
}

/**
 * Close an assignment by naming the `validation` event that answered it.
 *
 * The mirror of `markAssignmentMissed`: the answer is a position in the log, not
 * a flag, and the event stays the record. An assignment carrying either column
 * is closed, and `openAssignment` reads both.
 */
export async function markAssignmentAnswered(
  db: D1Like,
  entryId: string,
  seq: number,
  validationSeq: number,
): Promise<void> {
  await db
    .prepare(
      `UPDATE assignments SET answered_seq = ? WHERE entry_id = ? AND seq = ?`,
    )
    .bind(validationSeq, entryId, seq)
    .run();
}

/**
 * The assignments whose window has run out: still open, and past `before`.
 *
 * Lifecycle of an entry, Validate: "An assigned validator has seventy-two hours
 * to respond. A miss costs standing, and the next beacon round draws a
 * replacement." This is the sweep's one read, and the only query in the system
 * that starts from a deadline rather than from an entry.
 *
 * Strictly before, because the deadline instant itself is still inside the
 * seventy-two hours (src/assign.ts holds that rule and this matches it). Oldest
 * deadline first, so a sweep that can only get through so many in one run gets
 * through the longest-overdue ones. The limit is the caller's own and there is
 * no default: this module holds no page size. Served by the partial
 * `assignments_due` index (migrations/0004_assignments.sql).
 */
export async function dueAssignments(
  db: D1Like,
  before: string,
  limit: number,
): Promise<Array<{ entryId: string; assignment: OpenAssignment }>> {
  const rows = await db
    .prepare(
      `SELECT entry_id, assignment_json FROM assignments
       WHERE purpose = ? AND deadline < ? AND missed_seq IS NULL AND answered_seq IS NULL
       ORDER BY deadline LIMIT ?`,
    )
    .bind(VALIDATION, before, limit)
    .all<Row>();
  return rows.results.map((row) => ({
    entryId: readText(row, "entry_id"),
    assignment: readJson<OpenAssignment>(row, "assignment_json"),
  }));
}

/**
 * The entry's open revalidation check: the newest revalidation draw that is
 * neither missed nor answered, or null.
 *
 * The mirror of `openAssignment` for the other purpose. Whitepaper Section 6,
 * "Revalidate": a request "is assigned at random to a trusted operator", with the
 * same window and the same miss as a validation assignment — but it is a
 * different question, so it is a different lookup. A validation must never close
 * a revalidation check and a revalidation draw must never satisfy an entry's
 * validation assignment, which is exactly what the purpose column keeps apart.
 */
export async function openRevalidationAssignment(
  db: D1Like,
  entryId: string,
): Promise<OpenAssignment | null> {
  const row = await db
    .prepare(
      `SELECT assignment_json FROM assignments
       WHERE entry_id = ? AND purpose = ? AND missed_seq IS NULL AND answered_seq IS NULL
       ORDER BY seq DESC ${ONE_ROW}`,
    )
    .bind(entryId, REVALIDATION)
    .first<Row>();
  return row === null ? null : readJson<OpenAssignment>(row, "assignment_json");
}

/**
 * The revalidation checks whose window has run out: still open, and past
 * `before`.
 *
 * The mirror of `dueAssignments`, and the sweep's second deadline-first read.
 * Strictly before, oldest deadline first, and the limit is the caller's own:
 * this module holds no page size. Served by the partial `assignments_purpose_due`
 * index (migrations/0009_disputes.sql).
 */
export async function dueRevalidationAssignments(
  db: D1Like,
  before: string,
  limit: number,
): Promise<Array<{ entryId: string; assignment: OpenAssignment; requestSeq: number }>> {
  const rows = await db
    .prepare(
      `SELECT entry_id, assignment_json, request_seq FROM assignments
       WHERE purpose = ? AND deadline < ? AND missed_seq IS NULL AND answered_seq IS NULL
       ORDER BY deadline LIMIT ?`,
    )
    .bind(REVALIDATION, before, limit)
    .all<Row>();
  return rows.results.map((row) => ({
    entryId: readText(row, "entry_id"),
    assignment: readJson<OpenAssignment>(row, "assignment_json"),
    requestSeq: readInteger(row, "request_seq"),
  }));
}

// ---------------------------------------------------------------------------
// Validation writes
// ---------------------------------------------------------------------------

/**
 * An event sealed onto the stored head, and the statements that write it.
 *
 * The writers below take an `EventInput` rather than a sealed `Event` because
 * the log's head is here and not in the caller: a caller that sealed its own
 * event would have to read the head first, and two reads around one write is the
 * race this avoids. `appendEvent` does the sealing, exactly as every other path
 * does, and `eventStatements` then checks the result against the same head, so
 * these writes cannot drift into a weaker chain rule than a plain append.
 */
async function sealOntoHead(
  db: D1Like,
  input: EventInput,
): Promise<{ event: Event; statements: D1LikeStatement[] }> {
  const run = await sealRunOntoHead(db, [input]);
  return { event: run.events[0]!, statements: run.statements };
}

/**
 * A run of events sealed onto the stored head, in order, and the statements
 * that write them.
 *
 * The same rule as `sealOntoHead`, for the writes that seal more than one event
 * at once: a dispute filing is an `entry_submitted` for the correction and a
 * `dispute_filed` on the target, and both have to land or neither does. Each
 * event is chained onto the one before it, and `eventStatements` then checks the
 * whole run against the head exactly as a plain append is checked.
 *
 * `next` lets a later event in the run be built from an earlier sealed one — a
 * `dispute_upheld` naming a validation's seq, say — without the caller having to
 * guess a position that does not exist yet.
 */
async function sealRunOntoHead(
  db: D1Like,
  inputs: readonly EventInput[],
  next?: (sealed: readonly Event[]) => readonly EventInput[],
): Promise<{ events: Event[]; statements: D1LikeStatement[] }> {
  const previous = await headEvent(db);
  let chain: Event[] = previous === null ? [] : [previous];
  const base = chain.length;
  for (const input of inputs) chain = await appendEvent(chain, input);
  if (next !== undefined) {
    for (const input of next(chain.slice(base))) {
      chain = await appendEvent(chain, input);
    }
  }
  const events = chain.slice(base);
  const at = previous === null ? null : { seq: previous.seq, hash: previous.hash };
  return { events, statements: eventStatements(db, events, at) };
}

/**
 * The entry_id of an entry-scoped event. `appendEvent` refuses an entry-scoped
 * event with a null entry_id, so this only ever narrows the type.
 */
function scopedEntryId(event: Event): string {
  if (event.entry_id === null) {
    throw new TypeError(`${event.type}: expected an entry_id`);
  }
  return event.entry_id;
}

/**
 * Seal the trusted pool as it stands.
 *
 * Lifecycle of an entry, Validate: "The pool snapshot is committed to the sealed
 * log before the beacon round it uses", so this write is what a later draw is
 * recomputed against. One event and nothing beside it: the snapshot is the
 * record, and the pool it names is rebuilt from the registry events whenever
 * anyone asks.
 */
export async function recordPoolSnapshot(
  db: D1Like,
  input: EventInput<"pool_snapshot">,
): Promise<Event<"pool_snapshot">> {
  const { event, statements } = await sealOntoHead(db, input);
  await db.batch(statements);
  return event as Event<"pool_snapshot">;
}

/**
 * Record a draw: append the `assignment` event and open its row, atomically.
 *
 * The event is the record and the row is the index into it, so an assignments
 * row without its event would be an assignment nobody can verify offline, and an
 * event without its row would be an assignment the sweep cannot see when its
 * deadline passes. One `batch` makes both impossible.
 *
 * The row is read out of the event and nothing is computed here: the deadline
 * was set by `buildAssignment` from the policy window, and the row's seq is the
 * event's own position, which is what ties the two together.
 */
export async function recordAssignment(
  db: D1Like,
  input: EventInput<"assignment">,
): Promise<Event<"assignment">> {
  const { event, statements } = await sealOntoHead(db, input);
  const assignment = event as Event<"assignment">;
  const entryId = scopedEntryId(assignment);
  statements.push(
    assignmentStatement(db, entryId, {
      seq: assignment.seq,
      agent: assignment.payload.agent,
      operator: assignment.payload.operator,
      beacon_round: assignment.payload.beacon_round,
      deadline: assignment.payload.deadline,
      replacement: assignment.payload.replacement,
    }),
  );
  await db.batch(statements);
  return assignment;
}

/**
 * Record a miss: append the `assignment_missed` event and close the row it
 * closes, atomically. `assignmentSeq` names the assignment being closed, which
 * is the position of its own event in the log.
 */
export async function recordAssignmentMissed(
  db: D1Like,
  input: EventInput<"assignment_missed">,
  assignmentSeq: number,
): Promise<Event<"assignment_missed">> {
  const { event, statements } = await sealOntoHead(db, input);
  const missed = event as Event<"assignment_missed">;
  statements.push(
    db
      .prepare(
        `UPDATE assignments SET missed_seq = ? WHERE entry_id = ? AND seq = ?`,
      )
      .bind(missed.seq, scopedEntryId(missed), assignmentSeq),
  );
  await db.batch(statements);
  return missed;
}

/** What a writer stores for an entry: exactly what `putEntry` writes. */
export interface StoredEntryInput {
  readonly entry: Entry;
  readonly sidecar: Sidecar;
  readonly derivedThroughSeq: number;
}

/**
 * Record a validation: append the event, store the entry derived including it,
 * and close the assignment it answered, atomically.
 *
 * A validation is the one write that changes an entry's status, and status is
 * derived: the entry row has to be recomputed from a log that already holds this
 * event, and the event does not exist until it is sealed onto the head. So the
 * caller hands in a callback rather than an entry — it is given the sealed event
 * and returns what derivation made of it — and nothing here derives a field.
 *
 * `answeredAssignmentSeq` is the assignment this validation answers, or null
 * when the validator volunteered. Identity and operators: the operator is the
 * unit, so any agent under the assigned operator answers the assignment; which
 * assignment that is belongs to the caller's rules (src/assign.ts), not to
 * storage.
 *
 * `also` is for the entries this one's verification changes besides itself. The
 * case is supersession: the validation that verifies a superseding entry is the
 * moment the entry it supersedes acquires a `superseded_by`, and that target's
 * row has to be rewritten from the same log position, in the same batch, or a
 * reader between the two writes sees a superseding entry verified and its target
 * still standing. The caller rederives each of them and hands them in; nothing
 * here derives a field, and each row keeps its own submitted_seq because
 * submitted_seq is the position of that entry's own submission.
 *
 * `alsoEvents` is for the events this validation's verdict seals on ANOTHER
 * entry. The case is a dispute: Section 6, "An upheld challenge ... overturns
 * the entry", so the decision that verifies a correction entry is the same
 * moment `dispute_upheld` lands on the entry it corrects, and the decision that
 * rejects one is the moment `dispute_failed` does. Both have to be in this
 * batch: a reader between two writes would see a correction verified and its
 * target still standing, which is precisely the state the log must never show.
 * The callback is handed the sealed validation, so it can name its position, and
 * the events it returns are chained onto it in order.
 *
 * `ledger` is the stake rows the outcome produces (src/stake.ts), sealed in the
 * same batch for the same reason `recordReconfirmation` writes a bounty in its
 * own: a ledger row without its event would be a stake nobody can verify
 * offline. It is handed both the validation and the events `alsoEvents` sealed.
 *
 * `also` and `ledger` take the sealed extra events as a second argument, so a
 * caller that has none simply ignores it and is unchanged.
 */
export async function recordValidation(
  db: D1Like,
  input: {
    readonly event: EventInput<"validation">;
    readonly stored: (event: Event<"validation">) => StoredEntryInput;
    readonly answeredAssignmentSeq: number | null;
    readonly alsoEvents?: (event: Event<"validation">) => readonly EventInput[];
    readonly also?: (
      event: Event<"validation">,
      alsoEvents: readonly Event[],
    ) => readonly StoredEntryInput[];
    readonly ledger?: (
      event: Event<"validation">,
      alsoEvents: readonly Event[],
    ) => readonly StakeRecord[];
  },
): Promise<Event<"validation">> {
  const { events, statements } = await sealRunOntoHead(
    db,
    [input.event],
    (sealed) => input.alsoEvents?.(sealed[0] as Event<"validation">) ?? [],
  );
  const validation = events[0] as Event<"validation">;
  const extra = events.slice(1);
  const entryId = scopedEntryId(validation);
  const submittedSeq = await submittedSeqOf(db, entryId);

  const stored = input.stored(validation);
  statements.push(
    entryStatement(
      db,
      stored.entry,
      stored.sidecar,
      submittedSeq,
      stored.derivedThroughSeq,
    ),
  );
  if (input.also !== undefined) {
    for (const other of input.also(validation, extra)) {
      statements.push(
        entryStatement(
          db,
          other.entry,
          other.sidecar,
          await submittedSeqOf(db, entryField(other.entry, "id")),
          other.derivedThroughSeq,
        ),
      );
    }
  }
  if (input.answeredAssignmentSeq !== null) {
    statements.push(
      db
        .prepare(
          `UPDATE assignments SET answered_seq = ? WHERE entry_id = ? AND seq = ?`,
        )
        .bind(validation.seq, entryId, input.answeredAssignmentSeq),
    );
  }
  for (const stake of input.ledger?.(validation, extra) ?? []) {
    statements.push(stakeStatement(db, stake));
  }
  await db.batch(statements);
  return validation;
}

const LEDGER_COLUMNS = `id, kind, operator_id, seq, created_at, payload_json`;

/** The same row, plus the entry column 0009 added for the stakes. */
const STAKE_LEDGER_COLUMNS = `id, kind, operator_id, entry_id, seq, created_at, payload_json`;

/** The `kind` a bounty accrual is stored under: the record's own. */
const BOUNTY_ACCRUAL: BountyAccrual["kind"] = "bounty_accrual";

/**
 * Every kind of stake row, so `ledgerRowsForEntry` can say what it returns
 * rather than handing back whatever else the ledger may hold one day. The list
 * is src/stake.ts's `StakeKind`, spelled out because a type is not a value.
 */
const STAKE_KINDS: readonly StakeRecord["kind"][] = Object.freeze([
  "dispute_stake",
  "dispute_refund",
  "dispute_forfeit",
  "dispute_reward",
  "revalidation_stake",
  "revalidation_refund",
  "revalidation_forfeit",
] as const);

const STAKE_KINDS_IN = `kind IN (${STAKE_KINDS.map(() => "?").join(", ")})`;

/**
 * The insert that writes one stake row.
 *
 * The row's id is its kind and the position of the event that produced it. One
 * event produces at most one row of each kind — an upheld dispute produces a
 * refund and a reward, never two refunds — so the pair is unique, and a write
 * replayed after a partial failure lands on the same id rather than a second
 * row. `operator_id` is null for a bare-key challenger, which is exactly what
 * Section 6 means by "a bare-key challenger's reward accrues to the key": the
 * row is real, and the operator it would pay out through does not exist yet.
 *
 * The whole record goes in `payload_json` as it came from src/stake.ts, so the
 * columns beside it are never a second source of truth: they are what the
 * lookups seek on.
 */
function stakeStatement(db: D1Like, stake: StakeRecord): D1LikeStatement {
  return db
    .prepare(
      `INSERT INTO ledger (${STAKE_LEDGER_COLUMNS}) VALUES (?, ?, ?, ?, ?, ?, ?)
       ON CONFLICT (id) DO UPDATE SET
         kind = excluded.kind,
         operator_id = excluded.operator_id,
         entry_id = excluded.entry_id,
         seq = excluded.seq,
         created_at = excluded.created_at,
         payload_json = excluded.payload_json`,
    )
    .bind(
      `${stake.kind}:${stake.seq}`,
      stake.kind,
      stake.operator,
      stake.entry_id,
      stake.seq,
      stake.at,
      writeJson(stake),
    );
}

/**
 * Record a reconfirmation: append the event, store the entry derived including
 * it, and write the bounty it collected, atomically.
 *
 * The mirror of `recordValidation`, for the same reason: a reconfirmation
 * advances `last_confirmed`, reopens the window and rotates a read-share slot,
 * and every one of those is derived, so the entry row has to be recomputed from
 * a log that already holds this event — which does not exist until it is sealed
 * onto the head. The caller hands in callbacks rather than values, is given the
 * sealed event, and returns what derivation made of it. Nothing here derives a
 * field.
 *
 * Whitepaper Section 7, "Freshness and decay": the withheld half of a stale
 * entry's earnings "builds up on the entry as a reconfirmation bounty, paid to
 * whoever makes it fresh again". `bounty` returns that record (src/bounty.ts)
 * when the entry was stale and null when it was not, and it lands in the same
 * batch as the event that earned it: a ledger row without its reconfirmation
 * would be a bounty nobody can verify offline, and the event without the row
 * would be a bounty that was earned and never recorded.
 *
 * The row goes into `ledger`, which 0001 declared as a placeholder for the
 * read-share accounting M21 fills. It keeps that table's shape exactly — an id,
 * a kind, the operator the row is about, the log position it was produced at,
 * and the whole record as JSON — so M21 adds to it rather than reshaping it.
 */
export async function recordReconfirmation(
  db: D1Like,
  input: {
    readonly event: EventInput<"reconfirmation">;
    readonly stored: (event: Event<"reconfirmation">) => StoredEntryInput;
    readonly bounty: (event: Event<"reconfirmation">) => BountyAccrual | null;
  },
): Promise<Event<"reconfirmation">> {
  const { event, statements } = await sealOntoHead(db, input.event);
  const reconfirmation = event as Event<"reconfirmation">;
  const entryId = scopedEntryId(reconfirmation);
  const submittedSeq = await submittedSeqOf(db, entryId);

  const stored = input.stored(reconfirmation);
  statements.push(
    entryStatement(
      db,
      stored.entry,
      stored.sidecar,
      submittedSeq,
      stored.derivedThroughSeq,
    ),
  );

  const accrual = input.bounty(reconfirmation);
  if (accrual !== null) {
    statements.push(
      db
        .prepare(
          `INSERT INTO ledger (${LEDGER_COLUMNS}) VALUES (?, ?, ?, ?, ?, ?)`,
        )
        .bind(
          `${BOUNTY_ACCRUAL}:${accrual.seq}`,
          BOUNTY_ACCRUAL,
          accrual.operator,
          reconfirmation.seq,
          reconfirmation.at,
          writeJson(accrual),
        ),
    );
  }
  await db.batch(statements);
  return reconfirmation;
}

/**
 * A bounty row as the ledger table actually holds it: one of two shapes.
 *
 * M15's door writes the unpriced `BountyAccrual` the moment a reconfirmation
 * lands, and M21's sweep replaces it under the same id with src/ledger.ts's
 * priced `LedgerRow` (`priceLedgerRow`). So the same entry's bounties can come
 * back as either, depending on whether the sweep has run since, and a caller
 * has to ask which it is holding rather than assume. The accrual's three window
 * fields are what tells them apart: a priced row has none of them, which is
 * exactly the test the sweep's pricing step makes before it prices again.
 */
export type StoredBountyRow =
  | BountyAccrual
  | (LedgerRow & {
      readonly stale_from?: never;
      readonly stale_until?: never;
      readonly amount_micros?: never;
    });

/**
 * The bounties one entry accrued, oldest first, in whichever of the two shapes
 * above each one is in.
 *
 * Read through `json_extract` rather than a column of its own: `ledger` is the
 * placeholder 0001 declared and M21 is the milestone that shapes it, so adding
 * an entry_id column now would be guessing at that shape a milestone early. The
 * volume is one row per reconfirmation of one entry, and the caller's limit
 * bounds it.
 */
export async function bountiesForEntry(
  db: D1Like,
  entryId: string,
  limit: number,
): Promise<StoredBountyRow[]> {
  const rows = await db
    .prepare(
      `SELECT payload_json FROM ledger
       WHERE kind = ? AND json_extract(payload_json, '$.entry_id') = ?
       ORDER BY seq LIMIT ?`,
    )
    .bind(BOUNTY_ACCRUAL, entryId, limit)
    .all<Row>();
  return rows.results.map((row) =>
    readJson<StoredBountyRow>(row, "payload_json"),
  );
}

// ---------------------------------------------------------------------------
// Disputes, revalidations and failure reports
// ---------------------------------------------------------------------------

/** How a caller stores the correction entry a dispute is filed as. */
export interface DisputeCorrectionInput {
  /** The correction's own submission, exactly as `submitEntry` takes it. */
  readonly event: EventInput<"entry_submitted">;
  /** The derived correction entry, built from a log that already holds its events. */
  readonly stored: (
    submitted: Event<"entry_submitted">,
    filed: Event<"dispute_filed">,
  ) => StoredEntryInput;
  /** The captures the correction rests on: its cited page, and its receipt if it has one. */
  readonly captures: readonly CaptureRecord[];
}

/**
 * File a dispute: submit the correction entry, seal the challenge against its
 * target, write both entry rows and the challenger's stake, atomically.
 *
 * Whitepaper Section 6, "Dispute": "A challenge is itself an entry, in the
 * correction category, and it requires a citation ... Filing takes a stake, so
 * burner keys cannot dispute for free." So one act produces two events on two
 * entries and a ledger row, and every one of them has to land or none may. A
 * correction submitted without its `dispute_filed` would be an ordinary
 * correction nobody linked to anything; a `dispute_filed` without its correction
 * would name an entry that does not exist; and a stake row without either would
 * be a charge against a challenger who never filed.
 *
 * The two events are sealed in that order — the correction's submission first,
 * then the challenge — because the challenge names the correction, and an event
 * may not name an entry the log has not seen yet.
 *
 * `filed` is built from the sealed submission, so the caller can name the
 * correction's id without having invented a position. Nothing here derives a
 * field: both entry rows come back from the caller's own derivation over a log
 * that already holds both events, and `stake` is src/stake.ts's record over the
 * sealed `dispute_filed`.
 */
export async function recordDisputeFiling(
  db: D1Like,
  input: {
    readonly correction: DisputeCorrectionInput;
    readonly filed: (
      submitted: Event<"entry_submitted">,
    ) => EventInput<"dispute_filed">;
    /**
     * The events this filing seals on the target after the challenge itself, in
     * order, and empty by default.
     *
     * Section 6, "Revalidate": "A request that turns up a citation can be
     * upgraded into a dispute." An upgrade closes the request in the same breath
     * as it files the challenge — a `revalidation_resolved` with outcome
     * `upgraded` — and the two have to be in this batch, or a reader between the
     * writes sees a dispute filed against an entry whose check is still open and
     * whose stake is still up.
     */
    readonly also?: (
      submitted: Event<"entry_submitted">,
    ) => readonly EventInput[];
    /** The disputed entry, rederived: its `disputes[]` array gains this challenge. */
    readonly target: (
      submitted: Event<"entry_submitted">,
      filed: Event<"dispute_filed">,
      also: readonly Event[],
    ) => StoredEntryInput;
    readonly stake: (filed: Event<"dispute_filed">) => StakeRecord | null;
    /** The rows the events in `also` produce (src/stake.ts), if any. */
    readonly ledger?: (
      filed: Event<"dispute_filed">,
      also: readonly Event[],
    ) => readonly StakeRecord[];
    /**
     * The `revalidation_assigned` an upgrade closes, or null when the request
     * had no draw standing. A check whose request has been upgraded is not owed
     * an answer any more, so its row is closed here rather than left for the
     * sweep to seal a miss against a checker who was never late.
     */
    readonly answeredAssignmentSeq?: number | null;
  },
): Promise<{
  submitted: Event<"entry_submitted">;
  filed: Event<"dispute_filed">;
  also: Event[];
}> {
  const { events, statements } = await sealRunOntoHead(
    db,
    [input.correction.event],
    (sealed) => {
      const submission = sealed[0] as Event<"entry_submitted">;
      return [input.filed(submission), ...(input.also?.(submission) ?? [])];
    },
  );
  const submitted = events[0] as Event<"entry_submitted">;
  const filed = events[1] as Event<"dispute_filed">;
  const also = events.slice(2);
  const correctionId = scopedEntryId(submitted);
  const targetId = scopedEntryId(filed);

  const correction = input.correction.stored(submitted, filed);
  statements.push(
    entryStatement(
      db,
      correction.entry,
      correction.sidecar,
      submitted.seq,
      correction.derivedThroughSeq,
    ),
  );
  // 0009's `dispute_of`: the correction says which entry it was filed against.
  // A separate statement rather than a column on `entryStatement`, so every
  // later rederivation of this entry rewrites the derived columns and leaves
  // this one exactly where the filing put it.
  statements.push(
    db
      .prepare(`UPDATE entries SET dispute_of = ? WHERE id = ?`)
      .bind(targetId, correctionId),
  );
  for (const capture of input.correction.captures) {
    statements.push(captureStatement(db, capture));
  }

  const target = input.target(submitted, filed, also);
  statements.push(
    entryStatement(
      db,
      target.entry,
      target.sidecar,
      await submittedSeqOf(db, targetId),
      target.derivedThroughSeq,
    ),
  );

  const answered = input.answeredAssignmentSeq ?? null;
  if (answered !== null) {
    statements.push(
      db
        .prepare(
          `UPDATE assignments SET answered_seq = ? WHERE entry_id = ? AND seq = ?`,
        )
        .bind(events[events.length - 1]!.seq, targetId, answered),
    );
  }

  const stake = input.stake(filed);
  if (stake !== null) statements.push(stakeStatement(db, stake));
  for (const row of input.ledger?.(filed, also) ?? []) {
    statements.push(stakeStatement(db, row));
  }

  await db.batch(statements);
  return { submitted, filed, also };
}

/**
 * What every revalidation write takes: the event, the entry row rederived
 * including it, and the ledger rows it produces.
 *
 * `stored` and `ledger` are both optional because not every one of these events
 * changes either. A miss changes the sidecar's view of the request and nothing
 * in the ledger; a request opened at nomankind's expense stakes nothing
 * (src/stake.ts). Callbacks rather than values, for the reason
 * `recordValidation` gives: the event does not exist until it is sealed onto the
 * head, and the derived row has to be computed from a log that already holds it.
 */
export interface RevalidationWrite<T extends EventType> {
  readonly event: EventInput<T>;
  readonly stored?: (event: Event<T>) => StoredEntryInput;
  readonly ledger?: (event: Event<T>) => readonly StakeRecord[];
}

/** Seal one revalidation event, store what it changed, write what it charged. */
async function recordRevalidationEvent<T extends EventType>(
  db: D1Like,
  input: RevalidationWrite<T>,
  extra: (event: Event<T>) => readonly D1LikeStatement[] = () => [],
): Promise<Event<T>> {
  const { event, statements } = await sealOntoHead(db, input.event);
  const sealed = event as Event<T>;
  const entryId = scopedEntryId(sealed);

  const stored = input.stored?.(sealed);
  if (stored !== undefined) {
    statements.push(
      entryStatement(
        db,
        stored.entry,
        stored.sidecar,
        await submittedSeqOf(db, entryId),
        stored.derivedThroughSeq,
      ),
    );
  }
  statements.push(...extra(sealed));
  for (const stake of input.ledger?.(sealed) ?? []) {
    statements.push(stakeStatement(db, stake));
  }
  await db.batch(statements);
  return sealed;
}

/**
 * Record a revalidation request: the event, the entry row, and the standing the
 * requester staked.
 *
 * Section 6, "Revalidate": "Any operator can also request revalidation of an
 * entry inside its window by staking a small amount of standing." A request
 * auto-opened by failure reports stakes nothing (Section 8: "at nomankind's
 * expense"), and `ledger` returns nothing for it.
 */
export async function recordRevalidationRequest(
  db: D1Like,
  input: RevalidationWrite<"revalidation_requested">,
): Promise<Event<"revalidation_requested">> {
  return recordRevalidationEvent(db, input);
}

/**
 * Record a revalidation draw: the event, and the assignment row the sweep reads.
 *
 * The mirror of `recordAssignment`, with 0009's purpose column set to
 * 'revalidation' and the request's position carried beside it, so a revalidation
 * check can never be mistaken for an entry's validation assignment in either
 * direction.
 */
export async function recordRevalidationAssignment(
  db: D1Like,
  input: RevalidationWrite<"revalidation_assigned">,
): Promise<Event<"revalidation_assigned">> {
  return recordRevalidationEvent(db, input, (assigned) => [
    assignmentStatement(
      db,
      scopedEntryId(assigned),
      {
        seq: assigned.seq,
        agent: assigned.payload.agent,
        operator: assigned.payload.operator,
        beacon_round: assigned.payload.beacon_round,
        deadline: assigned.payload.deadline,
        // A revalidation draw is never a replacement: Section 6's replacement
        // rule is about the 2-1 split in validation, which a check has no
        // equivalent of.
        replacement: false,
      },
      REVALIDATION,
      assigned.payload.request_seq,
    ),
  ]);
}

/**
 * Record a missed check: the event, and the assignment row it closes.
 * `assignmentSeq` is the position of the `revalidation_assigned` event being
 * closed, exactly as `recordAssignmentMissed` takes it.
 */
export async function recordRevalidationMissed(
  db: D1Like,
  input: RevalidationWrite<"revalidation_missed">,
  assignmentSeq: number,
): Promise<Event<"revalidation_missed">> {
  return recordRevalidationEvent(db, input, (missed) => [
    db
      .prepare(
        `UPDATE assignments SET missed_seq = ? WHERE entry_id = ? AND seq = ?`,
      )
      .bind(missed.seq, scopedEntryId(missed), assignmentSeq),
  ]);
}

/**
 * Record how a check ended: the event, the entry row, the stake it settled, and
 * the assignment it answered.
 *
 * Section 6: "If the check finds the fact changed, the requester gets the stake
 * back plus a challenger-style reward. If the entry holds, the requester loses
 * the stake." Which of those it is belongs to src/stake.ts; this writes the rows
 * it returns, in the batch that seals the event they came from.
 *
 * `answeredAssignmentSeq` names the `revalidation_assigned` event this resolves,
 * or null when the request was resolved without a draw having landed — an
 * upgrade to a dispute, which the requester may make before any checker answers.
 */
export async function recordRevalidationResolution(
  db: D1Like,
  input: RevalidationWrite<"revalidation_resolved"> & {
    readonly answeredAssignmentSeq?: number | null;
  },
): Promise<Event<"revalidation_resolved">> {
  const answered = input.answeredAssignmentSeq ?? null;
  return recordRevalidationEvent(db, input, (resolved) =>
    answered === null
      ? []
      : [
          db
            .prepare(
              `UPDATE assignments SET answered_seq = ? WHERE entry_id = ? AND seq = ?`,
            )
            .bind(resolved.seq, scopedEntryId(resolved), answered),
        ],
  );
}

/**
 * Record a failure report: the event, the frozen artifact it rests on, the entry
 * row, and the revalidation it auto-opened if it was the one that reached the
 * threshold.
 *
 * Whitepaper Section 8: "A reader that acts on a verified entry and fails ...
 * files a signed failure report against the entry, with its transcript frozen
 * and hashed like any artifact. A single report is a signal. A published
 * threshold of reports from distinct operators auto-opens a revalidation at
 * nomankind's expense."
 *
 * `opens` is handed the sealed report and returns the `revalidation_requested`
 * to seal after it, or null. Whether the threshold was reached is
 * src/dispute.ts's question (`failureReportThresholdReached`), asked by the
 * caller over the reports it read; this only writes the answer, in the same
 * batch, so the report that opened a check and the check itself can never come
 * apart.
 *
 * The capture is the artifact's row, under a `report:<seq>` role so each report's
 * artifact is its own row and none of them overwrites the entry's own captures.
 * Its role therefore cannot be known before the event is sealed, so it too comes
 * from a callback.
 */
export async function recordFailureReport(
  db: D1Like,
  input: {
    readonly event: EventInput<"failure_report">;
    readonly capture: (report: Event<"failure_report">) => CaptureRecord;
    readonly opens?: (
      report: Event<"failure_report">,
    ) => EventInput<"revalidation_requested"> | null;
    readonly stored?: (
      report: Event<"failure_report">,
      opened: Event<"revalidation_requested"> | null,
    ) => StoredEntryInput;
  },
): Promise<{
  report: Event<"failure_report">;
  opened: Event<"revalidation_requested"> | null;
}> {
  const { events, statements } = await sealRunOntoHead(
    db,
    [input.event],
    (sealed) => {
      const opens = input.opens?.(sealed[0] as Event<"failure_report">) ?? null;
      return opens === null ? [] : [opens];
    },
  );
  const report = events[0] as Event<"failure_report">;
  const opened =
    events.length > 1 ? (events[1] as Event<"revalidation_requested">) : null;

  statements.push(captureStatement(db, input.capture(report)));

  const stored = input.stored?.(report, opened);
  if (stored !== undefined) {
    statements.push(
      entryStatement(
        db,
        stored.entry,
        stored.sidecar,
        await submittedSeqOf(db, scopedEntryId(report)),
        stored.derivedThroughSeq,
      ),
    );
  }
  await db.batch(statements);
  return { report, opened };
}

/**
 * The entry a correction was filed as a dispute against, or null.
 *
 * Null both when the id names no entry at all and when it names a correction
 * that was submitted on its own: neither disputes anything, and the caller's
 * question — "which entry does this challenge?" — has the same answer for both.
 */
export async function disputeOf(
  db: D1Like,
  correctionEntryId: string,
): Promise<string | null> {
  const row = await db
    .prepare(`SELECT dispute_of FROM entries WHERE id = ? ${ONE_ROW}`)
    .bind(correctionEntryId)
    .first<Row>();
  return row === null ? null : readNullableText(row, "dispute_of");
}

/**
 * The corrections filed as disputes against one entry, in filing order.
 *
 * Section 6: "The original stays in the log, marked overturned, linked to its
 * correction." This is that link followed the other way, for a reader looking at
 * the target and asking what was filed against it. Served by the partial
 * `entries_dispute_of` index; the limit is the caller's own.
 */
export async function correctionEntriesFor(
  db: D1Like,
  targetId: string,
  limit: number,
): Promise<StoredEntry[]> {
  const rows = await db
    .prepare(
      `SELECT ${ENTRY_COLUMNS} FROM entries
       WHERE dispute_of = ? ORDER BY submitted_seq LIMIT ?`,
    )
    .bind(targetId, limit)
    .all<Row>();
  return rows.results.map(toStoredEntry);
}

/**
 * One stake row, as src/stake.ts wrote it.
 *
 * A row the ledger step has priced carries a whole `LedgerRow` in
 * `payload_json` — the dispute reward, priced from the clawbacks of its own
 * event — and the record it was written as is under `ref`. So the record comes
 * back from there, carrying the price the row now holds, and a reader of this
 * list sees one shape whether the step has passed the row's position or not.
 */
function toStakeRecord(row: Row): StakeRecord {
  const payload = readJson<Record<string, unknown>>(row, "payload_json");
  const ref = payload["ref"];
  if (typeof ref !== "object" || ref === null) {
    return payload as unknown as StakeRecord;
  }
  return {
    ...(ref as unknown as StakeRecord),
    unit: payload["unit"] as StakeRecord["unit"],
    amount: payload["amount"] as StakeRecord["amount"],
  };
}

/**
 * The stake rows one entry's disputes and revalidations produced, oldest first.
 *
 * Read through 0009's `entry_id` column rather than `json_extract`, unlike
 * `bountiesForEntry`: a stake is looked up per entry on every entry page that
 * has ever been disputed, which is a seek and not a scan. Filtered to the stake
 * kinds so the return type is honest when M21 fills the rest of this table.
 *
 * That filter is also what skips the legacy `revalidation_reward`
 * (`LEGACY_KIND_SKIPPED`): the kind is no longer a `StakeKind`, so it is not in
 * `STAKE_KINDS` and an old log's row is left out of the entry page's stakes
 * panel exactly as `ledgerRowsForOperator` leaves it out of the operator's.
 */
export async function ledgerRowsForEntry(
  db: D1Like,
  entryId: string,
  limit: number,
): Promise<StakeRecord[]> {
  const rows = await db
    .prepare(
      `SELECT payload_json FROM ledger
       WHERE entry_id = ? AND ${STAKE_KINDS_IN} ORDER BY seq LIMIT ?`,
    )
    .bind(entryId, ...STAKE_KINDS, limit)
    .all<Row>();
  return rows.results.map(toStakeRecord);
}

/**
 * One stake row by its id, or null when there is none or it has been priced
 * already.
 *
 * The ledger step's read: it prices the `dispute_reward` row the dispute door
 * wrote at the outcome, and `amount IS NULL` is what says the row is still the
 * fact without the number. A row that has been priced comes back null, so a
 * replayed cursor reprices nothing — the same guard `priceLedgerRow`'s delete
 * applies, asked before the work rather than after it.
 */
export async function unpricedStakeRow(
  db: D1Like,
  id: string,
): Promise<StakeRecord | null> {
  const row = await db
    .prepare(`SELECT payload_json FROM ledger WHERE id = ? AND amount IS NULL`)
    .bind(id)
    .first<Row>();
  return row === null ? null : readJson<StakeRecord>(row, "payload_json");
}

/** What a filing puts up: the only two kinds that can still be in flight. */
const STAKE_FILED_KINDS: readonly StakeRecord["kind"][] = Object.freeze([
  "dispute_stake",
  "revalidation_stake",
] as const);

/**
 * What settles one, per mechanism. A reward is not a settlement — it is paid
 * beside the refund — so it is in neither list.
 */
const DISPUTE_SETTLING_KINDS: readonly StakeRecord["kind"][] = Object.freeze([
  "dispute_refund",
  "dispute_forfeit",
] as const);

const REVALIDATION_SETTLING_KINDS: readonly StakeRecord["kind"][] = Object.freeze([
  "revalidation_refund",
  "revalidation_forfeit",
] as const);

const IN = (kinds: readonly string[]): string =>
  `(${kinds.map(() => "?").join(", ")})`;

/**
 * One operator's stakes that are still in flight: filed, and neither refunded
 * nor forfeited.
 *
 * Section 9: standing "gates ... dispute stakes", and what an operator can stake
 * is what it holds less what its open stakes already hold. That subtraction is
 * this query's whole purpose, and src/dispute.ts's `checkStakeCover` makes it.
 *
 * The unsettledness is asked of the storage rather than paired in memory,
 * because an operator's stake rows accumulate for its lifetime while its OPEN
 * stakes never can: a page of the ledger read in log order is the oldest settled
 * history long before it is the recent filings, and pairing that page would
 * under-count what is in flight and let an operator hold more stakes than its
 * standing covers. So the limit here bounds open stakes only, and is a guard
 * rather than a page — an operator can never have more open stakes than its
 * standing covers.
 *
 * A settlement is matched to what it settles by what the two halves name: a
 * dispute stake by its target and the correction it was filed with, a
 * revalidation stake by its target and the position of the request. The
 * revalidation key deliberately ignores `correction_entry_id` — an upgrade's
 * refund names the correction the request became, and the stake it refunds names
 * none, so a key that read that field would never match the two. `IS` rather
 * than `=` because a dispute filed without a correction names none on either
 * half, and null never equals null.
 *
 * `json_extract` inside `NOT EXISTS` is not the scan it would be in a join: the
 * subquery is anchored on `settlement.entry_id = stake.entry_id`, which seeks
 * through 0009's `ledger_entry` index, so the JSON is read only for the handful
 * of rows one entry's disputes and checks ever wrote.
 */
export async function openStakeRowsForOperator(
  db: D1Like,
  operator: string,
  limit: number,
): Promise<StakeRecord[]> {
  const rows = await db
    .prepare(
      `SELECT stake.payload_json AS payload_json FROM ledger AS stake
        WHERE stake.operator_id = ?
          AND stake.kind IN ${IN(STAKE_FILED_KINDS)}
          AND NOT EXISTS (
                SELECT 1 FROM ledger AS settlement
                 WHERE settlement.entry_id = stake.entry_id
                   AND (
                     (stake.kind = 'dispute_stake'
                        AND settlement.kind IN ${IN(DISPUTE_SETTLING_KINDS)}
                        AND json_extract(settlement.payload_json, '$.correction_entry_id')
                         IS json_extract(stake.payload_json, '$.correction_entry_id'))
                     OR
                     (stake.kind = 'revalidation_stake'
                        AND settlement.kind IN ${IN(REVALIDATION_SETTLING_KINDS)}
                        AND json_extract(settlement.payload_json, '$.request_seq')
                         IS json_extract(stake.payload_json, '$.request_seq'))
                   )
              )
        ORDER BY stake.seq LIMIT ?`,
    )
    .bind(
      operator,
      ...STAKE_FILED_KINDS,
      ...DISPUTE_SETTLING_KINDS,
      ...REVALIDATION_SETTLING_KINDS,
      limit,
    )
    .all<Row>();
  return rows.results.map((row) => readJson<StakeRecord>(row, "payload_json"));
}

/**
 * How many overturned entries each operator signed, as submitter or as
 * approver, most first.
 *
 * Section 6: "An upheld challenge ... overturns the entry ... and claws back
 * what the approvers earned on it", so an operator's overturned count is what
 * the standing side of that sentence is measured on. An operator counts once per
 * entry however many of its agents signed it — Identity and operators: the
 * operator is the unit.
 *
 * The signers of an entry live inside `entry_json` (the core's `author_operator`
 * and every `approvers[]` item), and there is no column for them: adding one
 * would be a second source of truth for something derivation already computes.
 * So this is a grouped read over the overturned rows, parsed in the caller's
 * process rather than in SQL. That is acceptable at this volume and only at this
 * volume — an overturned entry is rare by construction, the caller's `limit`
 * bounds how many rows are read, and if overturned entries ever became common
 * enough for this to matter, the answer is a column written from derivation, not
 * a bigger scan.
 */
export async function overturnedCountsByOperator(
  db: D1Like,
  limit: number,
): Promise<Array<{ operator: string; count: number }>> {
  const rows = await db
    .prepare(
      `SELECT entry_json FROM entries
       WHERE status = 'overturned' ORDER BY submitted_seq LIMIT ?`,
    )
    .bind(limit)
    .all<Row>();

  const counts = new Map<string, number>();
  for (const row of rows.results) {
    const entry = readJson<Record<string, unknown>>(row, "entry_json");
    const signers = new Set<string>();
    const author = entry["author_operator"];
    if (typeof author === "string") signers.add(author);
    const approvers = entry["approvers"];
    if (Array.isArray(approvers)) {
      for (const approver of approvers) {
        const operator = (approver as Record<string, unknown>)["operator"];
        if (typeof operator === "string") signers.add(operator);
      }
    }
    for (const operator of signers) {
      counts.set(operator, (counts.get(operator) ?? 0) + 1);
    }
  }
  return [...counts.entries()]
    .map(([operator, count]) => ({ operator, count }))
    .sort((left, right) =>
      right.count === left.count
        ? left.operator.localeCompare(right.operator)
        : right.count - left.count,
    );
}

// ---------------------------------------------------------------------------
// The ledger (M21)
// ---------------------------------------------------------------------------

/**
 * The columns one ledger row is written into. `payload_json` carries the whole
 * row as src/ledger.ts built it, and every column beside it is what a lookup
 * seeks on — never a second source of truth. 0010 added amount, unit, role,
 * "date" and available_at for exactly that reason: a sum through json_extract is
 * a scan of the table.
 */
const LEDGER_ROW_COLUMNS =
  `id, kind, operator_id, entry_id, seq, created_at, payload_json, ` +
  `amount, unit, role, "date", available_at`;

/**
 * The kinds that carry money to or from an operator and wait out the holdback:
 * the accruals, the clawbacks that negate them, and the reward an upheld
 * challenge is paid. A clawback carries the release instant of the share it
 * cancels and a reward the latest of those, so all four are read by one
 * `available_at` test — and an unpriced reward, which has no release instant at
 * all until the ledger step prices it, fails that test and is never selected.
 * src/ledger.ts's `isBalanceKind` is the same list.
 */
const BALANCE_KINDS =
  `('read_share', 'bounty_accrual', 'clawback', 'dispute_reward')`;

/**
 * A kind no door writes any more: a revalidation check that found the fact
 * changed used to pay a reward of its own, and D-095 pays the requester in
 * standing instead — the currency the stake was in — leaving the money reward to
 * the dispute an upgraded check becomes. A log written before that decision can
 * still hold one of these rows, so every reader in this module skips it: the
 * mirror's fold never recomputes one, and a kind nothing prices and nothing pays
 * would read on a page as money still owed. Skipped here so no page has to know
 * the kind ever existed.
 */
const LEGACY_KIND_SKIPPED = `kind <> 'revalidation_reward'`;

/**
 * One row, as src/ledger.ts built it.
 *
 * A row written by this milestone carries the whole `LedgerRow` in
 * `payload_json`, so it comes back verbatim. A stake row (src/stake.ts) predates
 * `LedgerRow` and carries a `StakeRecord` instead, so it is presented through
 * the columns 0010 backfilled, with the record itself under `ref`. A reward row
 * whose amount was never priced reads as zero, and the record under `ref` is
 * where the null it actually carries can be read.
 */
function toLedgerRow(row: Row): LedgerRow {
  const payload = readJson<Record<string, unknown>>(row, "payload_json");
  if (typeof payload["ref"] === "object" && payload["ref"] !== null) {
    return payload as unknown as LedgerRow;
  }
  const unit = readNullableText(row, "unit");
  return {
    id: readText(row, "id"),
    kind: readText(row, "kind") as LedgerRow["kind"],
    entry_id: readNullableText(row, "entry_id"),
    operator: readNullableText(row, "operator_id"),
    role: readNullableText(row, "role") as LedgerRow["role"],
    date: readNullableText(row, "date"),
    reads: null,
    unit: (unit ?? "standing") as LedgerRow["unit"],
    amount: readNullableInteger(row, "amount") ?? 0,
    available_at: readNullableText(row, "available_at"),
    seq: readInteger(row, "seq"),
    at: readText(row, "created_at"),
    ref: payload,
  };
}

/**
 * The insert that writes one ledger row.
 *
 * INSERT OR IGNORE, and the id is the whole idempotence: every id src/ledger.ts
 * builds names the event that produced the row and what the row is about, so a
 * step replayed after a partial failure — or a cursor set back — writes the same
 * ids and changes nothing. It is OR IGNORE rather than an upsert on purpose: a
 * row that already exists was derived from the same sealed events, so rewriting
 * it could only ever overwrite a right answer with the same right answer, and if
 * it would not, the difference is a bug that must stay visible.
 */
function ledgerRowStatement(db: D1Like, row: LedgerRow): D1LikeStatement {
  return db
    .prepare(
      `INSERT OR IGNORE INTO ledger (${LEDGER_ROW_COLUMNS})
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    )
    .bind(
      row.id,
      row.kind,
      row.operator,
      row.entry_id,
      row.seq,
      row.at,
      writeJson(row),
      row.amount,
      row.unit,
      row.role,
      row.date,
      row.available_at,
    );
}

/** Write a run of ledger rows in one batch; idempotent by id. */
export async function putLedgerRows(
  db: D1Like,
  rows: readonly LedgerRow[],
): Promise<void> {
  if (rows.length === 0) return;
  await db.batch(rows.map((row) => ledgerRowStatement(db, row)));
}

/**
 * Replace an unpriced row with the priced one, atomically.
 *
 * Two rows are written by a door with no amount and priced by the sweep's
 * ledger step afterwards: M15's bounty accrual, and the `dispute_reward` an
 * upheld challenge is owed, whose price is the clawbacks of its own event. Both
 * are priced under exactly the same id the door wrote — so one of the two has to
 * go or the insert is ignored and the row stays unpriced forever. Two
 * statements would leave a window where the sweep has deleted the unpriced row
 * and not yet written the price: a crash there loses it, because the deleted
 * row is the only record that anything was ever owed. One batch makes that
 * window impossible.
 *
 * The `amount IS NULL` clause is what keeps a replayed cursor safe: a row that
 * has already been priced is never deleted, and the insert that follows is
 * ignored by id, so a rerun reprices nothing and removes nothing. A reward
 * priced at zero is priced: zero is not null, and the row is left alone.
 */
export async function priceLedgerRow(
  db: D1Like,
  unpricedId: string,
  row: LedgerRow,
): Promise<void> {
  await db.batch([
    db
      .prepare(`DELETE FROM ledger WHERE id = ? AND amount IS NULL`)
      .bind(unpricedId),
    ledgerRowStatement(db, row),
  ]);
}

/**
 * One operator's ledger, newest first, resuming strictly before `beforeSeq`.
 *
 * Newest first because that is the question an operator page asks — what
 * happened to my money lately — and because a payout cycle reads through
 * `releasedUnpaidRows` and not through this.
 *
 * The legacy `revalidation_reward` kind is skipped (`LEGACY_KIND_SKIPPED`), so
 * the operator page's ledger panel shows what the mirror can recompute and
 * nothing else.
 */
export async function ledgerRowsForOperator(
  db: D1Like,
  operator: string,
  limit: number,
  beforeSeq?: number,
): Promise<LedgerRow[]> {
  const rows =
    beforeSeq === undefined
      ? await db
          .prepare(
            `SELECT ${LEDGER_ROW_COLUMNS} FROM ledger
             WHERE operator_id = ? AND ${LEGACY_KIND_SKIPPED}
             ORDER BY seq DESC LIMIT ?`,
          )
          .bind(operator, limit)
          .all<Row>()
      : await db
          .prepare(
            `SELECT ${LEDGER_ROW_COLUMNS} FROM ledger
             WHERE operator_id = ? AND seq < ? AND ${LEGACY_KIND_SKIPPED}
             ORDER BY seq DESC LIMIT ?`,
          )
          .bind(operator, beforeSeq, limit)
          .all<Row>();
  return rows.results.map(toLedgerRow);
}

/**
 * Every row of one kind on one UTC day, oldest first: the read behind the daily
 * reconciliation. Served by 0010's (kind, "date") index.
 *
 * The optional `limit` is the caller's, as everywhere else in this module; a
 * day's rows are bounded by the entries read that day, so a reconciliation asks
 * for all of them and a page asks for a page.
 */
export async function ledgerRowsOn(
  db: D1Like,
  kind: LedgerRow["kind"],
  date: string,
  limit?: number,
): Promise<LedgerRow[]> {
  const rows =
    limit === undefined
      ? await db
          .prepare(
            `SELECT ${LEDGER_ROW_COLUMNS} FROM ledger
             WHERE kind = ? AND "date" = ? ORDER BY seq`,
          )
          .bind(kind, date)
          .all<Row>()
      : await db
          .prepare(
            `SELECT ${LEDGER_ROW_COLUMNS} FROM ledger
             WHERE kind = ? AND "date" = ? ORDER BY seq LIMIT ?`,
          )
          .bind(kind, date, limit)
          .all<Row>();
  return rows.results.map(toLedgerRow);
}

/**
 * One entry's read shares that are still inside the holdback at `at`, unpaid.
 *
 * Section 9: an upheld dispute "can claw them back before they leave", and the
 * rows that have already left are not this query's business. src/ledger.ts's
 * `clawbackRows` applies the same test again to what comes back.
 */
export async function heldReadShareRows(
  db: D1Like,
  entryId: string,
  at: string,
): Promise<LedgerRow[]> {
  const rows = await db
    .prepare(
      `SELECT ${LEDGER_ROW_COLUMNS} FROM ledger
       WHERE entry_id = ? AND kind = 'read_share' AND paid_by IS NULL
         AND available_at > ? ORDER BY seq`,
    )
    .bind(entryId, at)
    .all<Row>();
  return rows.results.map(toLedgerRow);
}

/**
 * One entry's withheld halves over a window of days, oldest first: what a
 * reconfirmation collects (Section 7's reconfirmation bounty). Both bounds are
 * inclusive, because the window runs from the day the entry went stale to the
 * day it was made fresh again and both of those days withheld.
 */
export async function bountyPoolRows(
  db: D1Like,
  entryId: string,
  fromDate: string,
  toDate: string,
): Promise<LedgerRow[]> {
  const rows = await db
    .prepare(
      `SELECT ${LEDGER_ROW_COLUMNS} FROM ledger
       WHERE entry_id = ? AND kind = 'bounty_pool'
         AND "date" >= ? AND "date" <= ? ORDER BY "date", seq`,
    )
    .bind(entryId, fromDate, toDate)
    .all<Row>();
  return rows.results.map(toLedgerRow);
}

/**
 * What one operator has coming at `now`: unpaid accruals past the holdback, and
 * the unpaid clawbacks that are past it too.
 *
 * A clawback carries the `available_at` of the read share it negates
 * (src/ledger.ts, `clawbackRows`), so it is read by the same test as everything
 * else: the two are released in the same instant, and a share can never be paid
 * out from under a clawback that is still held. src/ledger.ts's `payoutPlan`
 * applies the same rule again to what comes back.
 *
 * A priced `dispute_reward` comes back here too, at its own release. Selected by
 * `operator_id`, so a bare key's reward — a row with no operator — is never
 * selected by anyone and can never be paid: Section 6 has it accrue to the key
 * and hold, and "turning it into dollars means verifying as an operator". An
 * unpriced reward has no `available_at` yet and fails the release test.
 */
export async function releasedUnpaidRows(
  db: D1Like,
  operator: string,
  now: string,
): Promise<LedgerRow[]> {
  const rows = await db
    .prepare(
      `SELECT ${LEDGER_ROW_COLUMNS} FROM ledger
       WHERE operator_id = ? AND paid_by IS NULL
         AND kind IN ${BALANCE_KINDS} AND available_at <= ?
       ORDER BY seq`,
    )
    .bind(operator, now)
    .all<Row>();
  return rows.results.map(toLedgerRow);
}

/** The updates that stamp a payout onto the rows it covers. */
function ledgerPaidStatements(
  db: D1Like,
  rowIds: readonly string[],
  payoutId: string,
): D1LikeStatement[] {
  return rowIds.map((id) =>
    db
      .prepare(`UPDATE ledger SET paid_by = ? WHERE id = ? AND paid_by IS NULL`)
      .bind(payoutId, id),
  );
}

/**
 * Stamp a payout onto the rows it paid.
 *
 * `AND paid_by IS NULL` is the whole safety of it: a row already claimed by an
 * earlier payout is left where it is rather than being quietly reassigned, so
 * two cycles racing cannot both pay the same accrual.
 */
export async function markLedgerPaid(
  db: D1Like,
  rowIds: readonly string[],
  payoutId: string,
): Promise<void> {
  if (rowIds.length === 0) return;
  await db.batch(ledgerPaidStatements(db, rowIds, payoutId));
}

/**
 * Record a payout: write the payout row and stamp the rows it covers, in one
 * batch.
 *
 * The one write in this module that is not derivable from the log, so it is also
 * the one that must be atomic against itself: a payout row without its stamps
 * would pay the same accruals again next cycle, and stamps without their row
 * would lose the money's trail.
 */
export async function recordPayout(
  db: D1Like,
  row: LedgerRow,
  rowIds: readonly string[],
): Promise<void> {
  const statements = [ledgerRowStatement(db, row)];
  statements.push(...ledgerPaidStatements(db, rowIds, row.id));
  await db.batch(statements);
}

/** How far a ledger step has read, or null when it has never run. */
export async function ledgerCursor(
  db: D1Like,
  name: string,
): Promise<number | null> {
  const row = await db
    .prepare(`SELECT seq FROM ledger_state WHERE name = ? ${ONE_ROW}`)
    .bind(name)
    .first<Row>();
  return row === null ? null : readInteger(row, "seq");
}

/** Move a ledger step's cursor. */
export async function setLedgerCursor(
  db: D1Like,
  name: string,
  seq: number,
): Promise<void> {
  await db
    .prepare(
      `INSERT INTO ledger_state (name, seq) VALUES (?, ?)
       ON CONFLICT (name) DO UPDATE SET seq = excluded.seq`,
    )
    .bind(name, seq)
    .run();
}

/** The daily reconciliations, newest first. */
export async function reconciliationRows(
  db: D1Like,
  limit: number,
): Promise<LedgerRow[]> {
  const rows = await db
    .prepare(
      `SELECT ${LEDGER_ROW_COLUMNS} FROM ledger
       WHERE kind = 'reconciliation' ORDER BY seq DESC LIMIT ?`,
    )
    .bind(limit)
    .all<Row>();
  return rows.results.map(toLedgerRow);
}

/** The payouts, newest first, for one operator or for everyone. */
export async function payoutRows(
  db: D1Like,
  limit: number,
  operator?: string,
): Promise<LedgerRow[]> {
  const rows =
    operator === undefined
      ? await db
          .prepare(
            `SELECT ${LEDGER_ROW_COLUMNS} FROM ledger
             WHERE kind = 'payout' ORDER BY seq DESC LIMIT ?`,
          )
          .bind(limit)
          .all<Row>()
      : await db
          .prepare(
            `SELECT ${LEDGER_ROW_COLUMNS} FROM ledger
             WHERE kind = 'payout' AND operator_id = ? ORDER BY seq DESC LIMIT ?`,
          )
          .bind(operator, limit)
          .all<Row>();
  return rows.results.map(toLedgerRow);
}

/**
 * Every ledger row about one entry, oldest first, whatever its kind: the read
 * behind the entry page's money panel. `ledgerRowsForEntry` keeps its stake
 * filter, because the dispute panel asks a narrower question and its answer is
 * a `StakeRecord`.
 *
 * Whatever its kind but one: the legacy `revalidation_reward`
 * (`LEGACY_KIND_SKIPPED`) is skipped here as it is everywhere else, so the two
 * panels of one entry page cannot disagree about whether it exists.
 */
export async function entryLedgerRows(
  db: D1Like,
  entryId: string,
  limit: number,
): Promise<LedgerRow[]> {
  const rows = await db
    .prepare(
      `SELECT ${LEDGER_ROW_COLUMNS} FROM ledger
       WHERE entry_id = ? AND ${LEGACY_KIND_SKIPPED} ORDER BY seq LIMIT ?`,
    )
    .bind(entryId, limit)
    .all<Row>();
  return rows.results.map(toLedgerRow);
}

// ---------------------------------------------------------------------------
// Standing (M21)
// ---------------------------------------------------------------------------

/** One operator's cached standing, and the position it was computed at. */
export interface OperatorStanding {
  readonly standing: number;
  readonly seq: number;
}

/** The update that caches one operator's standing. */
function operatorStandingStatement(
  db: D1Like,
  operator: string,
  standing: number,
  seq: number,
): D1LikeStatement {
  return db
    .prepare(`UPDATE operators SET standing = ?, standing_seq = ? WHERE id = ?`)
    .bind(standing, seq, operator);
}

/**
 * Cache what the published formula returned for one operator, at the position it
 * was computed at.
 *
 * A cache and nothing more. Section 9: standing "is derived from the sealed
 * public events by a published formula, so anyone can recompute anyone's
 * standing from the log and get the same number" — so this column is never read
 * as an authority, and `standing_seq` is what makes it checkable: rerun
 * src/standing.ts over the log up to that position and the number must match.
 */
export async function setOperatorStanding(
  db: D1Like,
  operator: string,
  standing: number,
  seq: number,
): Promise<void> {
  await operatorStandingStatement(db, operator, standing, seq).run();
}

/**
 * The cached standings, by operator, highest first. Operators whose standing has
 * never been computed are not in the map at all: null is "not computed yet" and
 * never "zero", and a page that finds an operator missing recomputes.
 */
export async function standingByOperator(
  db: D1Like,
  limit: number,
): Promise<Map<string, OperatorStanding>> {
  const rows = await db
    .prepare(
      `SELECT id, standing, standing_seq FROM operators
       WHERE standing IS NOT NULL ORDER BY standing DESC, id LIMIT ?`,
    )
    .bind(limit)
    .all<Row>();
  const standings = new Map<string, OperatorStanding>();
  for (const row of rows.results) {
    standings.set(readText(row, "id"), {
      standing: readInteger(row, "standing"),
      seq: readInteger(row, "standing_seq"),
    });
  }
  return standings;
}

/**
 * One operator's own cached standing, or null when it has never been computed.
 *
 * `standingByOperator` is a leaderboard — the highest `limit` standings — so it
 * is the wrong read for a question about one named operator: the hundred-and
 * -first operator by standing is absent from it and would answer "not computed
 * yet" although its column is written. This asks the row itself, so the answer
 * does not depend on how the operator ranks.
 */
export async function operatorStanding(
  db: D1Like,
  operator: string,
): Promise<OperatorStanding | null> {
  const row = await db
    .prepare(
      `SELECT standing, standing_seq FROM operators
       WHERE id = ? AND standing IS NOT NULL`,
    )
    .bind(operator)
    .first<Row>();
  if (row === null) return null;
  return {
    standing: readInteger(row, "standing"),
    seq: readInteger(row, "standing_seq"),
  };
}

/**
 * The cached standings of exactly these operators, by operator.
 *
 * The directory's read: one grouped query over the ids on the page rather than a
 * read per row, and rather than a leaderboard joined against a page ordered by
 * id — those two orderings do not agree, so past the leaderboard's limit the
 * join silently drops standings that are stored. Ids with no cached standing are
 * absent from the map, which is "not computed yet" and never "zero".
 */
export async function standingForOperators(
  db: D1Like,
  ids: readonly string[],
): Promise<Map<string, OperatorStanding>> {
  const standings = new Map<string, OperatorStanding>();
  if (ids.length === 0) return standings;
  const rows = await db
    .prepare(
      `SELECT id, standing, standing_seq FROM operators
       WHERE standing IS NOT NULL AND id IN (${ids.map(() => "?").join(", ")})`,
    )
    .bind(...ids)
    .all<Row>();
  for (const row of rows.results) {
    standings.set(readText(row, "id"), {
      standing: readInteger(row, "standing"),
      seq: readInteger(row, "standing_seq"),
    });
  }
  return standings;
}

/**
 * Trust or untrust an operator because of its standing: append the event, cache
 * the standing that caused it, and rewrite the operator row, atomically.
 *
 * Section 9: standing "gates everything discretionary, from entry to and stay in
 * the trusted pool". The event is what grants or removes the trust and the row
 * is the index into it, so a row without its event would be a pool nobody can
 * verify offline and an event without its row would be a pool the Worker cannot
 * see. One `batch` makes both impossible, and the run is checked against the
 * head by exactly the rule a plain append uses.
 *
 * `named_by` is the reason rather than an agent id, because no key did this:
 * `/genesis` records the maintainer's agent when a human names an operator, and
 * here the formula did it. `standing` and `position` are what the sweep computed
 * and are cached beside the row for the same reason `setOperatorStanding` exists
 * — so a reader can recompute them and check.
 */
export async function recordTrustChange(
  db: D1Like,
  kind: "operator_trusted" | "operator_untrusted",
  operator: string,
  at: string,
  reason: "standing",
  standing: number,
  position: number,
): Promise<Event> {
  const record = await getOperator(db, operator);
  if (record === null) {
    throw new Error(`recordTrustChange: unknown operator ${operator}`);
  }

  const { event, statements } = await sealOntoHead(db, {
    at,
    type: kind,
    entry_id: null,
    payload: { operator },
  });

  const trusted = kind === "operator_trusted";
  statements.push(
    operatorStatement(db, {
      ...record,
      details: {
        ...record.details,
        trusted,
        trusted_seq: trusted ? event.seq : null,
        named_by: reason,
      },
    }),
  );
  statements.push(operatorStandingStatement(db, operator, standing, position));
  await db.batch(statements);
  return event;
}

// ---------------------------------------------------------------------------
// Seals
// ---------------------------------------------------------------------------

const SEAL_COLUMNS = `seq, first_seq, last_seq, size, root, sealed_at, prev_hash, hash, witnesses_json, registry_json`;

function toSeal(row: Row): Seal {
  const registry = readNullableText(row, "registry_json");
  return {
    seq: readInteger(row, "seq"),
    first_seq: readInteger(row, "first_seq"),
    last_seq: readInteger(row, "last_seq"),
    size: readInteger(row, "size"),
    root: readText(row, "root"),
    sealed_at: readText(row, "sealed_at"),
    prev_hash: readNullableText(row, "prev_hash"),
    hash: readText(row, "hash"),
    witnesses: readJson<WitnessSignature[]>(row, "witnesses_json"),
    // Null until the registry accepted the fingerprint, and null forever where
    // there is no registry to accept it (0006_sealing.sql).
    registry: registry === null ? null : (JSON.parse(registry) as RegistrySeal),
  };
}

/** The bound values of a seal row, in SEAL_COLUMNS order. */
function sealValues(seal: Seal): unknown[] {
  return [
    seal.seq,
    seal.first_seq,
    seal.last_seq,
    seal.size,
    seal.root,
    seal.sealed_at,
    seal.prev_hash,
    seal.hash,
    writeJson(seal.witnesses),
    seal.registry === null ? null : writeJson(seal.registry),
  ];
}

/** Store one seal, replacing whatever was there. */
export async function putSeal(db: D1Like, seal: Seal): Promise<void> {
  await db
    .prepare(
      `INSERT INTO seals (${SEAL_COLUMNS}) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
       ON CONFLICT (seq) DO UPDATE SET
         first_seq = excluded.first_seq,
         last_seq = excluded.last_seq,
         size = excluded.size,
         root = excluded.root,
         sealed_at = excluded.sealed_at,
         prev_hash = excluded.prev_hash,
         hash = excluded.hash,
         witnesses_json = excluded.witnesses_json,
         registry_json = excluded.registry_json`,
    )
    .bind(...sealValues(seal))
    .run();
}

/** The newest seal, or null when nothing has been sealed. */
export async function latestSeal(db: D1Like): Promise<Seal | null> {
  const row = await db
    .prepare(`SELECT ${SEAL_COLUMNS} FROM seals ORDER BY seq DESC ${ONE_ROW}`)
    .first<Row>();
  return row === null ? null : toSeal(row);
}

/** One seal by its sequence number, or null. */
export async function sealBySeq(db: D1Like, seq: number): Promise<Seal | null> {
  const row = await db
    .prepare(`SELECT ${SEAL_COLUMNS} FROM seals WHERE seq = ? ${ONE_ROW}`)
    .bind(seq)
    .first<Row>();
  return row === null ? null : toSeal(row);
}

/**
 * The seal covering one event, or null when the event is not sealed yet.
 * Seals are disjoint and contiguous, so the covering seal is the one whose
 * range contains the seq; the (last_seq) index gets there in one seek.
 */
export async function sealCovering(
  db: D1Like,
  eventSeq: number,
): Promise<Seal | null> {
  const row = await db
    .prepare(
      `SELECT ${SEAL_COLUMNS} FROM seals
       WHERE last_seq >= ? AND first_seq <= ?
       ORDER BY last_seq ${ONE_ROW}`,
    )
    .bind(eventSeq, eventSeq)
    .first<Row>();
  return row === null ? null : toSeal(row);
}

/**
 * Every seal overlapping the event range [firstSeq, lastSeq], in seal order.
 * This is what an inclusion proof over a slice of the log needs: not the seals
 * whose own seq falls in the range, but the seals that cover those events.
 */
export async function sealsBetween(
  db: D1Like,
  firstSeq: number,
  lastSeq: number,
): Promise<Seal[]> {
  const rows = await db
    .prepare(
      `SELECT ${SEAL_COLUMNS} FROM seals
       WHERE last_seq >= ? AND first_seq <= ?
       ORDER BY seq`,
    )
    .bind(firstSeq, lastSeq)
    .all<Row>();
  return rows.results.map(toSeal);
}

/**
 * The next page of seals after a known one, in seq order. The seal chain's
 * delta read: the caller keeps the last seq it saw and asks for what came
 * after. The limit is the caller's own; this module holds no page size.
 */
export async function sealsAfter(
  db: D1Like,
  afterSeq: number,
  limit: number,
): Promise<Seal[]> {
  const rows = await db
    .prepare(
      `SELECT ${SEAL_COLUMNS} FROM seals WHERE seq > ? ORDER BY seq LIMIT ?`,
    )
    .bind(afterSeq, limit)
    .all<Row>();
  return rows.results.map(toSeal);
}

/**
 * Every seal sealed on one UTC calendar day, in seq order: the anchor step's
 * read, and the only question about seals that starts from a date.
 *
 * `sealed_at` is the injected clock's ISO instant, always UTC and always
 * "<day>T...", so the day is the half-open text range from "<day>T" to "<day>U"
 * — 'U' is the character after 'T', so the range is exactly the strings with
 * that day's prefix. A range, not `substr(...) = ?`, because a range seeks the
 * (sealed_at) index and a function call over every row does not.
 */
export async function sealsSealedOn(db: D1Like, date: string): Promise<Seal[]> {
  const rows = await db
    .prepare(
      `SELECT ${SEAL_COLUMNS} FROM seals
       WHERE sealed_at >= ? AND sealed_at < ?
       ORDER BY seq`,
    )
    .bind(`${date}T`, `${date}U`)
    .all<Row>();
  return rows.results.map(toSeal);
}

/**
 * The seals still waiting on the outside world, oldest first: no
 * countersignature has been attached yet, or the registry has not accepted the
 * fingerprint. This is the sweep's work queue, and a seal leaves it by being
 * finished rather than by being marked.
 */
export async function unwitnessedSeals(
  db: D1Like,
  limit: number,
): Promise<Seal[]> {
  const rows = await db
    .prepare(
      `SELECT ${SEAL_COLUMNS} FROM seals
       WHERE witnesses_json = '[]' OR registry_json IS NULL
       ORDER BY seq LIMIT ?`,
    )
    .bind(limit)
    .all<Row>();
  return rows.results.map(toSeal);
}

/**
 * Record what the registry returned for a seal's fingerprint.
 *
 * No entry row moves: an entry's `seal` object carries the inclusion proof and
 * the countersignatures, and the registry receipt is neither. It is evidence
 * about the seal, kept with the seal.
 */
export async function setSealRegistry(
  db: D1Like,
  seq: number,
  registry: RegistrySeal | null,
): Promise<void> {
  await db
    .prepare(`UPDATE seals SET registry_json = ? WHERE seq = ?`)
    .bind(registry === null ? null : writeJson(registry), seq)
    .run();
}

/**
 * How the caller turns one covered entry into the row to store.
 *
 * Storage never derives a field, and it never reads the Worker's world module:
 * the caller is handed an entry id and the seal that now covers it, and gives
 * back what derivation made of them. The seal is passed rather than read back
 * because inside its own batch it is not readable yet.
 */
export type SealRederive = (
  entryId: string,
  seal: Seal,
  now: Date,
) => Promise<StoredEntryInput>;

/** The entries whose submission event falls inside a seal's range, in log order. */
async function entriesSubmittedIn(
  db: D1Like,
  firstSeq: number,
  lastSeq: number,
): Promise<Array<{ id: string; submittedSeq: number }>> {
  const rows = await db
    .prepare(
      `SELECT id, submitted_seq FROM entries
       WHERE submitted_seq >= ? AND submitted_seq <= ? ORDER BY submitted_seq`,
    )
    .bind(firstSeq, lastSeq)
    .all<Row>();
  return rows.results.map((row) => ({
    id: readText(row, "id"),
    submittedSeq: readInteger(row, "submitted_seq"),
  }));
}

/**
 * Write a seal and rewrite every entry it seals, atomically.
 *
 * Section 6, "Seal": the entry hash is sealed as a fingerprint at submission, so
 * the moment a batch closes, every entry submitted inside it acquires a `seal`
 * object — an inclusion proof of its own submission event. That is a derived
 * field like any other, so it is recomputed by the caller and stored here, and
 * it lands in the same batch as the seal: a seal without the entries would leave
 * entries denying they were sealed, and the entries without the seal would have
 * them claiming a seal nobody can find.
 *
 * A plain INSERT, with no ON CONFLICT: unlike `putSeal`, which exists so a test
 * or a rebuild can restate a seal, this is the live path, and a second run
 * arriving at the same range is a race to refuse rather than a row to
 * overwrite. One timer runs the sweep — the alarm — and the watchdog that keeps
 * it wound never sweeps itself, so the second run is an alarm overlapping the
 * one before it rather than a second kind of door.
 *
 * The range is bounded by the seal, so the entries read needs no page size: a
 * batch covers the events since the last seal and nothing more.
 */
export async function recordSeal(
  db: D1Like,
  seal: Seal,
  now: Date,
  rederive: SealRederive,
): Promise<string[]> {
  const covered = await entriesSubmittedIn(db, seal.first_seq, seal.last_seq);
  const statements = [
    db
      .prepare(`INSERT INTO seals (${SEAL_COLUMNS}) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
      .bind(...sealValues(seal)),
  ];
  for (const { id, submittedSeq } of covered) {
    const stored = await rederive(id, seal, now);
    statements.push(
      entryStatement(
        db,
        stored.entry,
        stored.sidecar,
        submittedSeq,
        stored.derivedThroughSeq,
      ),
    );
  }

  try {
    await db.batch(statements);
  } catch (cause) {
    // Ask the table rather than read the driver's message: a seal now standing
    // at this seq is what "conflict" means, and any other failure is not ours
    // to rename.
    if ((await sealBySeq(db, seal.seq)) !== null) {
      throw new SealConflictError(seal.seq, { cause });
    }
    throw cause;
  }
  return covered.map((entry) => entry.id);
}

/**
 * Attach countersignatures to a seal and rewrite every entry it covers, in one
 * batch.
 *
 * The entries have to move: `EntrySeal.witnesses` is the covering seal's
 * signature strings (src/seal.ts), and src/verify.ts compares an entry's
 * `seal.witnesses` against the seal's own. Written apart, a reader between the
 * two writes would see a countersigned seal and entries that deny it, and the
 * verifier would call the entries wrong.
 */
export async function setSealWitnesses(
  db: D1Like,
  seal: Seal,
  witnesses: readonly WitnessSignature[],
  now: Date,
  rederive: SealRederive,
): Promise<string[]> {
  const witnessed: Seal = { ...seal, witnesses: [...witnesses] };
  const statements = [
    db
      .prepare(`UPDATE seals SET witnesses_json = ? WHERE seq = ?`)
      .bind(writeJson(witnessed.witnesses), witnessed.seq),
  ];
  const covered = await entriesSubmittedIn(db, seal.first_seq, seal.last_seq);
  for (const { id, submittedSeq } of covered) {
    const stored = await rederive(id, witnessed, now);
    statements.push(
      entryStatement(
        db,
        stored.entry,
        stored.sidecar,
        submittedSeq,
        stored.derivedThroughSeq,
      ),
    );
  }
  await db.batch(statements);
  return covered.map((entry) => entry.id);
}

// ---------------------------------------------------------------------------
// Anchors
// ---------------------------------------------------------------------------

const ANCHOR_COLUMNS = `"date", first_seal_seq, last_seal_seq, roots_json, hash, external`;

/**
 * The stored receipt, with `upgraded` made total.
 *
 * Every row written before M23b carries no `upgraded` key at all, and the
 * routes, the mirror and the status page all read the field rather than ask
 * whether it is there. Filling it in on the way out costs one comparison and
 * saves the rest of the system from knowing the column has a history.
 */
function toExternal(json: string): AnchorExternal {
  const external = JSON.parse(json) as AnchorExternal;
  if (external === null) return null;
  return { ...external, upgraded: external.upgraded ?? null };
}

function toAnchor(row: Row): Anchor {
  // The column held nothing but null until M16; now it holds the external
  // timestamp receipt as JSON, and reading one back is no longer an error.
  const external = readNullableText(row, "external");
  return {
    date: readText(row, "date"),
    first_seal_seq: readNullableInteger(row, "first_seal_seq"),
    last_seal_seq: readNullableInteger(row, "last_seal_seq"),
    roots: readJson<string[]>(row, "roots_json"),
    hash: readText(row, "hash"),
    external: external === null ? null : toExternal(external),
  };
}

/** Store one day's anchor, replacing whatever was there. */
export async function putAnchor(db: D1Like, anchor: Anchor): Promise<void> {
  await db
    .prepare(
      `INSERT INTO anchors (${ANCHOR_COLUMNS}) VALUES (?, ?, ?, ?, ?, ?)
       ON CONFLICT ("date") DO UPDATE SET
         first_seal_seq = excluded.first_seal_seq,
         last_seal_seq = excluded.last_seal_seq,
         roots_json = excluded.roots_json,
         hash = excluded.hash,
         external = excluded.external`,
    )
    .bind(
      anchor.date,
      anchor.first_seal_seq,
      anchor.last_seal_seq,
      writeJson(anchor.roots),
      anchor.hash,
      anchor.external === null ? null : writeJson(anchor.external),
    )
    .run();
}

/** One day's anchor, by its UTC calendar day, or null. */
export async function getAnchor(
  db: D1Like,
  date: string,
): Promise<Anchor | null> {
  const row = await db
    .prepare(`SELECT ${ANCHOR_COLUMNS} FROM anchors WHERE "date" = ? ${ONE_ROW}`)
    .bind(date)
    .first<Row>();
  return row === null ? null : toAnchor(row);
}

/**
 * The most recent anchor, or null. Days sort as strings because the day is
 * always "YYYY-MM-DD" in UTC, so lexical order is chronological order.
 */
export async function latestAnchor(db: D1Like): Promise<Anchor | null> {
  const row = await db
    .prepare(
      `SELECT ${ANCHOR_COLUMNS} FROM anchors ORDER BY "date" DESC ${ONE_ROW}`,
    )
    .first<Row>();
  return row === null ? null : toAnchor(row);
}

/**
 * The next page of anchors after a known day, in day order. Days are
 * "YYYY-MM-DD" in UTC, so lexical order is chronological order and the primary
 * key is the keyset. The limit is the caller's own.
 */
export async function anchorsAfter(
  db: D1Like,
  afterDate: string,
  limit: number,
): Promise<Anchor[]> {
  const rows = await db
    .prepare(
      `SELECT ${ANCHOR_COLUMNS} FROM anchors WHERE "date" > ? ORDER BY "date" LIMIT ?`,
    )
    .bind(afterDate, limit)
    .all<Row>();
  return rows.results.map(toAnchor);
}

/**
 * The next page of anchors that hold a receipt still waiting on a block, in day
 * order — oldest first, which is the order they will upgrade in.
 *
 * The filter is in SQL rather than in the caller so that a log with years of
 * anchors behind it does not read them all to find the two that are pending.
 * `json_extract` over the receipt is the same shape the ledger reads its rows
 * by; the column is small and there is one row per day, so no index is owed.
 * The limit is the caller's own, like every other page here.
 */
export async function pendingAnchorsAfter(
  db: D1Like,
  afterDate: string,
  limit: number,
): Promise<Anchor[]> {
  const rows = await db
    .prepare(
      `SELECT ${ANCHOR_COLUMNS} FROM anchors
        WHERE "date" > ?
          AND external IS NOT NULL
          AND json_extract(external, '$.kind') = 'opentimestamps'
          AND json_extract(external, '$.upgraded') IS NULL
        ORDER BY "date" LIMIT ?`,
    )
    .bind(afterDate, limit)
    .all<Row>();
  return rows.results.map(toAnchor);
}

/**
 * The newest anchor whose receipt has reached a block, or null when none has.
 *
 * The three fields the status page says out loud rather than the whole anchor:
 * the roots and the completed .ots proof are the biggest thing in the table and
 * the page names none of them, so the query extracts the day, the block height
 * and the instant and leaves the rest in the column. Newest by day, and days
 * are "YYYY-MM-DD" in UTC, so the primary key's own descending order is
 * chronological order — one row read, whatever the log's age.
 *
 * `json_extract` over the receipt is the same filter `pendingAnchorsAfter`
 * reads by, inverted: that one wants the receipts still waiting, this one wants
 * the newest that is not.
 */
export interface UpgradedAnchorRow {
  readonly date: string;
  readonly block_height: number;
  readonly upgraded_at: string;
}

export async function newestUpgradedAnchor(
  db: D1Like,
): Promise<UpgradedAnchorRow | null> {
  const row = await db
    .prepare(
      `SELECT "date",
              json_extract(external, '$.upgraded.block_height') AS block_height,
              json_extract(external, '$.upgraded.upgraded_at') AS upgraded_at
         FROM anchors
        WHERE external IS NOT NULL
          AND json_extract(external, '$.kind') = 'opentimestamps'
          AND json_extract(external, '$.upgraded') IS NOT NULL
        ORDER BY "date" DESC ${ONE_ROW}`,
    )
    .first<Row>();
  if (row === null) return null;
  return {
    date: readText(row, "date"),
    block_height: readInteger(row, "block_height"),
    upgraded_at: readText(row, "upgraded_at"),
  };
}

/**
 * Record the external timestamp receipt for one day.
 *
 * Only the receipt moves. The anchor hash covers the date and the roots and
 * nothing else (D-037, item 5), so the day that was posted and the day that
 * comes back verifying are the same day.
 */
export async function setAnchorExternal(
  db: D1Like,
  date: string,
  external: AnchorExternal,
): Promise<void> {
  await db
    .prepare(`UPDATE anchors SET external = ? WHERE "date" = ?`)
    .bind(external === null ? null : writeJson(external), date)
    .run();
}

// ---------------------------------------------------------------------------
// Read receipts
// ---------------------------------------------------------------------------

/**
 * The `kind` a read receipt is stored under. The `receipts` table was declared
 * with a kind column in 0001 so more than one kind of receipt could share it;
 * this names the only one M17 writes.
 */
const READ_RECEIPT_KIND = "read";

/**
 * The `kind` a sync receipt is stored under.
 *
 * Whitepaper Section 8, "The delta stream": a sync response carries one signed
 * receipt covering every delivered entry, and each delivered verified entry
 * counts as a read. A different kind because the row is a different shape — one
 * receipt covering many entries, so `entry_id` is null and the entries live in
 * the payload — and the same counter because Section 9's running number is one
 * stream over everything served, never one per door.
 */
const SYNC_RECEIPT_KIND = "sync";

/** The event type a day's published count is written under. */
const READ_COUNT_TYPE: EventType = "read_count";

/** The two kinds that share the running counter, in the order they are bound. */
const COUNTED_RECEIPT_KINDS: readonly string[] = Object.freeze([
  READ_RECEIPT_KIND,
  SYNC_RECEIPT_KIND,
]);

/** `kind IN (?, ?)`, written from the list so the two can never drift apart. */
const COUNTED_KINDS_IN = `kind IN (${COUNTED_RECEIPT_KINDS.map(() => "?").join(", ")})`;

/**
 * One UTC day of receipt rows, as a half-open text range on `created_at`.
 *
 * `created_at` is the injected clock's ISO instant, always "<day>T...", so the
 * day is the range from "<day>T" to "<day>U" ('U' is the character after 'T') —
 * the same trick `sealsSealedOn` uses, and for the same reason: a range seeks
 * the (kind, created_at) index and a function call over every row does not.
 */
function dayRange(date: string): [string, string] {
  return [`${date}T`, `${date}U`];
}

/**
 * Every verified entry of every sync receipt on one UTC day, one row per entry.
 *
 * The counting happens in SQLite, through json_each over the stored payload,
 * because loading a day's receipts into an isolate to count them is exactly the
 * whole-log-in-memory failure this module exists to prevent: one sync receipt
 * can name a page of entries, and a busy day names a great many. The receipt is
 * still stored verbatim — nothing here recomputes a field, it only reads the
 * `status` the receipt was signed over.
 */
const SYNC_VERIFIED_ENTRIES = `
  SELECT json_extract(item.value, '$.entry_id') AS entry_id
  FROM receipts, json_each(receipts.payload_json, '$.entries') AS item
  WHERE receipts.kind = ?
    AND receipts.created_at >= ? AND receipts.created_at < ?
    AND json_extract(item.value, '$.status') = 'verified'`;

/**
 * The same verified entries, carrying the key the receipt was issued to.
 *
 * `COALESCE(key_id, '')` rather than the column, because the empty string is a
 * value a keyset page can compare and NULL is not: no key id is ever the empty
 * string (they are "key_" and sixteen hex), so the free tier's rows sort ahead
 * of every key's and the page boundary is total.
 */
const SYNC_VERIFIED_ENTRIES_BY_KEY = `
  SELECT json_extract(item.value, '$.entry_id') AS entry_id,
         COALESCE(receipts.key_id, '') AS key_id
  FROM receipts, json_each(receipts.payload_json, '$.entries') AS item
  WHERE receipts.kind = ?
    AND receipts.created_at >= ? AND receipts.created_at < ?
    AND json_extract(item.value, '$.status') = 'verified'`;

const RECEIPT_COLUMNS = `id, kind, entry_id, seq, created_at, payload_json, key_id, key_counter`;

/**
 * The row id for a receipt that carries the running counter: the counter
 * itself.
 *
 * Deterministic rather than random, so the primary key and the unique index
 * refuse the same duplicate. A random id would let two isolates racing for the
 * same counter differ in the id while colliding on the counter, which is a
 * second way to say the same thing and one more thing to keep in step. The
 * counter is shared by read and sync receipts, so the id is the same for both
 * and the primary key refuses a cross-kind duplicate on its own.
 */
export function readReceiptId(counter: number): string {
  return `rcpt_${counter}`;
}

/**
 * A counter that was already taken.
 *
 * The guard, and now only the guard. A door draws its number from
 * `allocateReadCounter`, which hands out a number no other isolate holds, so
 * this is what it means when a receipt row nonetheless stands at that number:
 * the counter row and the receipts table have fallen out of step, and the
 * unique index in migrations/0007_receipts.sql and 0008_sync.sql refused the
 * insert rather than let two receipts claim one position in the stream. The
 * door refuses too — the counter is inside the signed bytes and cannot be
 * edited afterwards, and a receipt whose number is a guess is worth nothing.
 */
export class ReceiptConflictError extends Error {
  override readonly name = "ReceiptConflictError";
  readonly counter: number;

  constructor(counter: number, options?: { cause?: unknown }) {
    super(`putReadReceipt: counter ${counter} is already issued`, options);
    this.counter = counter;
  }
}

/**
 * The one counter row read and sync receipts share
 * (migrations/0016_receipt_counter.sql).
 */
const RECEIPT_COUNTER_ROW = "reads";

/** Hand out the next number, in one statement. */
const ALLOCATE_COUNTER = `UPDATE receipt_counter SET counter = counter + 1 WHERE id = ? RETURNING counter`;

/**
 * Carry the counter up to a number a caller wrote a receipt at without drawing
 * it here, and never down. Paired with every receipt insert, so the high-water
 * mark is a fact about the table rather than a second place the same number is
 * kept.
 */
const CATCH_UP_COUNTER = `UPDATE receipt_counter SET counter = ? WHERE id = ? AND counter < ?`;

/**
 * The next running counter: one past the last number handed out, and 1 before
 * any has been.
 *
 * Whitepaper Section 8: the receipt names "a running counter". It runs across
 * every read, not per entry, so a reader can place their receipt in the whole
 * stream of reads nomankind served rather than only in one entry's.
 *
 * A read and nothing more — it is what the next reader will be handed, asked by
 * a caller that wants to know rather than to be served. The door draws its own
 * number with `allocateReadCounter`, because reading this and then inserting at
 * it is exactly the race migration 0016 exists to end.
 */
export async function nextReadCounter(db: D1Like): Promise<number> {
  const row = await db
    .prepare(`SELECT counter FROM receipt_counter WHERE id = ? ${ONE_ROW}`)
    .bind(RECEIPT_COUNTER_ROW)
    .first<Row>();
  const last = row === null ? null : readNullableInteger(row, "counter");
  return last === null ? 1 : last + 1;
}

/**
 * Draw the next running counter, and hand it to nobody else.
 *
 * One statement, which D1's single writer serializes: two isolates serving two
 * readers at the same instant are handed two numbers because the database hands
 * them out, exactly as one key's own counter is drawn (src/worker/access.ts,
 * `nextKeyCounter`). There is no read-then-insert here and so no retry loop
 * above it — the number in a door's hand is the door's own, and the signature
 * goes over it once.
 *
 * The number is drawn before the receipt is signed, so a request that dies in
 * between leaves a gap rather than a reused number. The gap is visible, and it
 * is `receipts` in the day's read_count payload that makes it so
 * (`countReceiptsOn`): the payload's `total` is reads and not rows — one sync
 * receipt can be six reads or none — so only the count of receipt rows can be
 * held against the counter range. `counter_last - counter_first + 1 -
 * receipts` is the number of numbers drawn and never handed over.
 */
export async function allocateReadCounter(db: D1Like): Promise<number> {
  const row = await db
    .prepare(ALLOCATE_COUNTER)
    .bind(RECEIPT_COUNTER_ROW)
    .first<Row>();
  const counter = row === null ? null : readNullableInteger(row, "counter");
  if (counter === null) {
    throw new TypeError("allocateReadCounter: no receipt_counter row");
  }
  return counter;
}

/**
 * The statement that carries the counter row up to a receipt being written, in
 * the same batch as the insert.
 *
 * A door draws its number first and this is then a no-op, which is the ordinary
 * case. It is here for the writer that does not draw — a test, an import, a
 * repair — so that "the counter row is at least the largest receipt stored"
 * holds however a receipt got in, and the next reader is never handed a number
 * the table already stands at.
 */
function counterCatchUp(db: D1Like, counter: number): D1LikeStatement {
  return db
    .prepare(CATCH_UP_COUNTER)
    .bind(counter, RECEIPT_COUNTER_ROW, counter);
}

/**
 * Whether some receipt already stands at this counter, of either kind.
 *
 * What "conflict" means, asked of the table rather than read out of a driver's
 * error message. Both kinds, because they share the counter: a read receipt
 * losing the race to a sync receipt is the same race, and the caller has to be
 * told the same thing.
 */
async function counterIsTaken(db: D1Like, counter: number): Promise<boolean> {
  const row = await db
    .prepare(
      `SELECT seq FROM receipts WHERE ${COUNTED_KINDS_IN} AND seq = ? ${ONE_ROW}`,
    )
    .bind(...COUNTED_RECEIPT_KINDS, counter)
    .first<Row>();
  return row !== null;
}

/**
 * Store one signed read receipt.
 *
 * `seq` is the counter inside the receipt, and the whole receipt goes into
 * `payload_json` verbatim: the signature covers exactly those five fields, so a
 * reader who lost their copy must get back the same bytes that were signed.
 * Nothing is recomputed on the way in or out.
 *
 * Throws `ReceiptConflictError` when the counter was already issued — a
 * concurrent reader took the number. The unique index is the guard; see
 * migrations/0007_receipts.sql.
 */
export async function putReadReceipt(
  db: D1Like,
  input: {
    readonly entryId: string;
    readonly createdAt: string;
    readonly receipt: ReadReceipt;
    /**
     * The key this read was served to, or null on the free tier (M24).
     *
     * Optional only for the callers that predate paid access — a receipt with
     * no key named is a free read, which is what every receipt written before
     * M24 was. The read door always says which.
     */
    readonly keyId?: string | null;
    /** The key's own counter, or null on the free tier. */
    readonly keyCounter?: number | null;
  },
): Promise<void> {
  const counter = input.receipt.counter;
  try {
    await db.batch([
      db
        .prepare(
          `INSERT INTO receipts (${RECEIPT_COLUMNS}) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
        )
        .bind(
          readReceiptId(counter),
          READ_RECEIPT_KIND,
          input.entryId,
          counter,
          input.createdAt,
          writeJson(input.receipt),
          input.keyId ?? null,
          input.keyCounter ?? null,
        ),
      counterCatchUp(db, counter),
    ]);
  } catch (cause) {
    // Ask the table rather than read the driver's message: a receipt now
    // standing at this counter is what "conflict" means, and any other failure
    // is not ours to rename.
    if (await counterIsTaken(db, counter)) {
      throw new ReceiptConflictError(counter, { cause });
    }
    throw cause;
  }
}

/**
 * Store one signed sync receipt.
 *
 * Whitepaper Section 8, "The delta stream": one receipt covers the whole
 * response, so the row names no entry — `entry_id` is null and the entries the
 * receipt covers are inside the signed payload, which goes in verbatim. `seq`
 * is the counter the receipt carries, drawn from the same running number read
 * receipts use.
 *
 * Throws `ReceiptConflictError` when the counter was already issued by either
 * kind. The unique index is the guard; see migrations/0008_sync.sql.
 */
export async function putSyncReceipt(
  db: D1Like,
  input: {
    readonly createdAt: string;
    readonly receipt: SyncReceipt;
    /** The key this page was served to, or null on the free tier (M24). */
    readonly keyId?: string | null;
    /** The key's own counter, or null on the free tier. */
    readonly keyCounter?: number | null;
  },
): Promise<void> {
  const counter = input.receipt.counter;
  try {
    await db.batch([
      db
        .prepare(
          `INSERT INTO receipts (${RECEIPT_COLUMNS}) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
        )
        .bind(
          readReceiptId(counter),
          SYNC_RECEIPT_KIND,
          null,
          counter,
          input.createdAt,
          writeJson(input.receipt),
          input.keyId ?? null,
          input.keyCounter ?? null,
        ),
      counterCatchUp(db, counter),
    ]);
  } catch (cause) {
    if (await counterIsTaken(db, counter)) {
      throw new ReceiptConflictError(counter, { cause });
    }
    throw cause;
  }
}

/** One sync receipt by its counter, or null. */
export async function syncReceiptByCounter(
  db: D1Like,
  counter: number,
): Promise<SyncReceipt | null> {
  const row = await db
    .prepare(
      `SELECT payload_json FROM receipts WHERE kind = ? AND seq = ? ${ONE_ROW}`,
    )
    .bind(SYNC_RECEIPT_KIND, counter)
    .first<Row>();
  return row === null ? null : readJson<SyncReceipt>(row, "payload_json");
}

/** One receipt by its counter, or null. */
export async function readReceiptByCounter(
  db: D1Like,
  counter: number,
): Promise<ReadReceipt | null> {
  const row = await db
    .prepare(
      `SELECT payload_json FROM receipts WHERE kind = ? AND seq = ? ${ONE_ROW}`,
    )
    .bind(READ_RECEIPT_KIND, counter)
    .first<Row>();
  return row === null ? null : readJson<ReadReceipt>(row, "payload_json");
}

/**
 * A page of one entry's read receipts, in counter order. Keyset, not offset:
 * the caller passes back the last counter it saw. The limit is the caller's
 * own; this module holds no page size.
 */
export async function readReceiptsForEntry(
  db: D1Like,
  entryId: string,
  afterCounter: number,
  limit: number,
): Promise<ReadReceipt[]> {
  const rows = await db
    .prepare(
      `SELECT payload_json FROM receipts
       WHERE kind = ? AND entry_id = ? AND seq > ?
       ORDER BY seq LIMIT ?`,
    )
    .bind(READ_RECEIPT_KIND, entryId, afterCounter, limit)
    .all<Row>();
  return rows.results.map((row) => readJson<ReadReceipt>(row, "payload_json"));
}

/**
 * One UTC day's reads, grouped by entry and in entry_id order.
 *
 * Whitepaper Section 9, Money: "Read counts are published to the sealed log
 * daily", so "any reader can compare the receipts they hold against the
 * published counts". This is the read behind that publication.
 *
 * Both kinds of receipt count. A read receipt is one read of the entry it
 * names; a sync receipt is one read of each verified entry it delivered
 * (Section 8, "Paying for the training path"), so the day is the union of the
 * read rows and the verified entries inside the sync payloads, grouped and
 * summed together. A trainer's read and a reader's read are the same read, and
 * the entry earns for both.
 *
 * `created_at` is the injected clock's ISO instant, always "<day>T...", so the
 * day is the half-open text range from "<day>T" to "<day>U" — the same trick
 * `sealsSealedOn` uses, and for the same reason: a range seeks the index and a
 * function call over every row does not.
 *
 * Keyset-paged by entry_id, because a day with more entries than one page can
 * still be published in full.
 */
export async function readCountsOn(
  db: D1Like,
  date: string,
  afterEntryId: string | undefined,
  limit: number,
): Promise<ReadCountRow[]> {
  const rows = await readCountsSplitOn(db, date, afterEntryId, limit);
  return rows.map((row) => ({
    entry_id: row.entry_id,
    count: row.read_reads + row.sync_reads,
  }));
}

/**
 * One entry's day, with the two kinds of read kept apart.
 *
 * `count` is the sum and is what the day publishes; the split exists because
 * the two kinds are not owed under the same condition. A read through
 * GET /read is a read of whatever the log served, and the log serves the newest
 * verified entry of a subject, so that read is always owed. A sync delivers
 * every verified entry in the delta, duplicates and all, and Section 9 pays for
 * "one verified entry delivered in a paid sync" — one, not one per copy of the
 * same fact (decision D-085).
 */
export interface ReadCountSplitRow {
  /** Reads through GET /read on that day. */
  readonly read_reads: number;
  /** Verified deliveries inside that day's sync receipts. */
  readonly sync_reads: number;
  readonly entry_id: string;
}

/**
 * The same day's reads as `readCountsOn`, with the read rows and the sync
 * deliveries returned as two columns rather than one sum.
 *
 * One query, not two: the UNION already visits both kinds once, so carrying a
 * second column through it costs nothing and keeps the two counts on the same
 * page boundary — two separately paged queries could disagree about where a
 * page ends, and the caller would have to reconcile them before it could
 * publish. Keyset-paged by entry_id with the caller's own limit, exactly as
 * `readCountsOn` is, because the publisher pages it the same way.
 */
export async function readCountsSplitOn(
  db: D1Like,
  date: string,
  afterEntryId: string | undefined,
  limit: number,
): Promise<ReadCountSplitRow[]> {
  const [dayFrom, dayTo] = dayRange(date);
  const bindings: unknown[] = [
    READ_RECEIPT_KIND,
    dayFrom,
    dayTo,
    SYNC_RECEIPT_KIND,
    dayFrom,
    dayTo,
  ];
  let after = "";
  if (afterEntryId !== undefined) {
    after = "WHERE entry_id > ? ";
    bindings.push(afterEntryId);
  }
  bindings.push(limit);

  const rows = await db
    .prepare(
      `SELECT entry_id,
              SUM(read_reads) AS read_reads,
              SUM(sync_reads) AS sync_reads FROM (
         SELECT entry_id, COUNT(*) AS read_reads, 0 AS sync_reads FROM receipts
           WHERE kind = ? AND created_at >= ? AND created_at < ?
           GROUP BY entry_id
         UNION ALL
         SELECT entry_id, 0 AS read_reads, 1 AS sync_reads
           FROM (${SYNC_VERIFIED_ENTRIES})
       ) ${after}
       GROUP BY entry_id ORDER BY entry_id LIMIT ?`,
    )
    .bind(...bindings)
    .all<Row>();
  return rows.results.map((row) => ({
    entry_id: readText(row, "entry_id"),
    read_reads: readInteger(row, "read_reads"),
    sync_reads: readInteger(row, "sync_reads"),
  }));
}

/** One entry's day under one key, with the two kinds of read kept apart. */
export interface ReadCountKeyRow extends ReadCountSplitRow {
  /** The key the reads were served to, or null for the free tier. */
  readonly key_id: string | null;
}

/** Where a page of `readCountsByKeyOn` resumes: the last pair it saw. */
export interface ReadCountKeyCursor {
  readonly entry_id: string;
  readonly key_id: string | null;
}

/**
 * The same day's reads as `readCountsSplitOn`, split by key as well as by
 * entry.
 *
 * Whitepaper Section 9, Money: "every paid read also returns a signed receipt
 * naming the entry, the time, and a running counter", and the day's published
 * count is what a holder checks those receipts against. A count published per
 * key is what makes that check possible for a payer rather than only for the
 * log as a whole, so the same UNION runs with the key in the grouping.
 *
 * Keyset-paged over the (entry_id, key_id) pair, written as an OR rather than a
 * row-value comparison so the plan is the same on every SQLite this runs on.
 * The caller passes back the last pair it saw, and the empty string stands for
 * the free tier throughout, exactly as the sub-select writes it.
 */
export async function readCountsByKeyOn(
  db: D1Like,
  date: string,
  after: ReadCountKeyCursor | undefined,
  limit: number,
): Promise<ReadCountKeyRow[]> {
  const [dayFrom, dayTo] = dayRange(date);
  const bindings: unknown[] = [
    READ_RECEIPT_KIND,
    dayFrom,
    dayTo,
    SYNC_RECEIPT_KIND,
    dayFrom,
    dayTo,
  ];
  let where = "";
  if (after !== undefined) {
    where = "WHERE (entry_id > ? OR (entry_id = ? AND key_id > ?)) ";
    bindings.push(after.entry_id, after.entry_id, after.key_id ?? "");
  }
  bindings.push(limit);

  const rows = await db
    .prepare(
      `SELECT entry_id, key_id,
              SUM(read_reads) AS read_reads,
              SUM(sync_reads) AS sync_reads FROM (
         SELECT entry_id, COALESCE(key_id, '') AS key_id,
                COUNT(*) AS read_reads, 0 AS sync_reads FROM receipts
           WHERE kind = ? AND created_at >= ? AND created_at < ?
           GROUP BY entry_id, COALESCE(key_id, '')
         UNION ALL
         SELECT entry_id, key_id, 0 AS read_reads, 1 AS sync_reads
           FROM (${SYNC_VERIFIED_ENTRIES_BY_KEY})
       ) ${where}
       GROUP BY entry_id, key_id ORDER BY entry_id, key_id LIMIT ?`,
    )
    .bind(...bindings)
    .all<Row>();
  return rows.results.map((row) => {
    const key = readText(row, "key_id");
    return {
      entry_id: readText(row, "entry_id"),
      key_id: key === "" ? null : key,
      read_reads: readInteger(row, "read_reads"),
      sync_reads: readInteger(row, "sync_reads"),
    };
  });
}

// ---------------------------------------------------------------------------
// What the provider has already been told (M24, decision D-078)
// ---------------------------------------------------------------------------

/** One key-day already reported to the payment provider, as the table holds it. */
export interface MeterReportRow {
  readonly key_id: string;
  readonly date: string;
  /** The `read_count` event the number was taken from. */
  readonly event_seq: number;
  readonly reads: number;
  /** The idempotency identifier the provider was sent. */
  readonly identifier: string;
  readonly reported_at: string;
}

/**
 * Whether this key-day has already been reported.
 *
 * The primary key is the pair, so this is one lookup and the row's existence is
 * the whole answer: a key-day reported once is never reported again, however
 * many times a sweep passes over the event that named it. Section 9's published
 * count is the number of record, and a meter event sent twice would bill a
 * reader twice for a day the log says they read once.
 */
export async function meterReported(
  db: D1Like,
  keyId: string,
  date: string,
): Promise<boolean> {
  const row = await db
    .prepare(
      `SELECT key_id FROM meter_reports WHERE key_id = ? AND date = ? ${ONE_ROW}`,
    )
    .bind(keyId, date)
    .first<Row>();
  return row !== null;
}

/** Record one key-day as reported. Written only after the provider said yes. */
export async function putMeterReport(
  db: D1Like,
  row: MeterReportRow,
): Promise<void> {
  await db
    .prepare(
      `INSERT INTO meter_reports (key_id, date, event_seq, reads, identifier, reported_at)
       VALUES (?, ?, ?, ?, ?, ?)
       ON CONFLICT (key_id, date) DO NOTHING`,
    )
    .bind(
      row.key_id,
      row.date,
      row.event_seq,
      row.reads,
      row.identifier,
      row.reported_at,
    )
    .run();
}

/** How many key-days have been reported, ever. What the status stage counts. */
export async function countMeterReports(db: D1Like): Promise<number> {
  const row = await db
    .prepare(`SELECT COUNT(*) AS total FROM meter_reports`)
    .first<Row>();
  return row === null ? 0 : readInteger(row, "total");
}

/**
 * How many published key-days past the metering cursor have no report yet.
 *
 * The status stage's one question, asked of the two tables rather than of a
 * fold in an isolate: the key-days a `read_count` event named, left-joined
 * against what has been reported. Bounded by the caller's own limit, because
 * the stage only needs to know whether the number is zero and a log that fell a
 * month behind must not turn its status page into a scan.
 *
 * `json_each` over `$.paid.keys` returns nothing for a payload with no paid
 * block, which is exactly right: an event that named no paid read owes no
 * meter event.
 */
export async function owedMeterReports(
  db: D1Like,
  afterSeq: number,
  throughSeq: number,
  limit: number,
): Promise<number> {
  const row = await db
    .prepare(
      `SELECT COUNT(*) AS owed FROM (
         SELECT day.key_id AS key_id, day.date AS date FROM (
           SELECT json_extract(events.payload, '$.date') AS date,
                  keys.key AS key_id
           FROM events, json_each(events.payload, '$.paid.keys') AS keys
           WHERE events.type = ? AND events.seq > ? AND events.seq <= ?
           LIMIT ?
         ) AS day
         LEFT JOIN meter_reports ON meter_reports.key_id = day.key_id
                                AND meter_reports.date = day.date
         WHERE meter_reports.key_id IS NULL
       )`,
    )
    .bind(READ_COUNT_TYPE, afterSeq, throughSeq, limit)
    .first<Row>();
  return row === null ? 0 : readInteger(row, "owed");
}

/**
 * The day's total and the counters that bound it: the smallest and largest
 * counter issued on that UTC day, both null when the day counted nothing.
 *
 * The total counts both kinds — read rows plus the verified entries the day's
 * sync receipts delivered — and the bounds are over both kinds' counters,
 * because the counter is one running number across everything served.
 *
 * The bounds are what make the published count checkable. A reader holding a
 * receipt whose counter falls inside the day's range knows their read should be
 * in that day's total, and a day that published fewer reads than its own
 * counter range spans has a hole in it.
 */
export async function readCounterRangeOn(
  db: D1Like,
  date: string,
): Promise<{
  total: number;
  counter_first: number | null;
  counter_last: number | null;
}> {
  const [dayFrom, dayTo] = dayRange(date);
  const row = await db
    .prepare(
      `SELECT
         (SELECT COUNT(*) FROM receipts
            WHERE kind = ? AND created_at >= ? AND created_at < ?)
         + (SELECT COUNT(*) FROM (${SYNC_VERIFIED_ENTRIES})) AS total,
         (SELECT MIN(seq) FROM receipts
            WHERE ${COUNTED_KINDS_IN} AND created_at >= ? AND created_at < ?)
           AS first_seq,
         (SELECT MAX(seq) FROM receipts
            WHERE ${COUNTED_KINDS_IN} AND created_at >= ? AND created_at < ?)
           AS last_seq`,
    )
    .bind(
      READ_RECEIPT_KIND,
      dayFrom,
      dayTo,
      SYNC_RECEIPT_KIND,
      dayFrom,
      dayTo,
      ...COUNTED_RECEIPT_KINDS,
      dayFrom,
      dayTo,
      ...COUNTED_RECEIPT_KINDS,
      dayFrom,
      dayTo,
    )
    .first<Row>();
  if (row === null) {
    return { total: 0, counter_first: null, counter_last: null };
  }
  return {
    total: readInteger(row, "total"),
    counter_first: readNullableInteger(row, "first_seq"),
    counter_last: readNullableInteger(row, "last_seq"),
  };
}

/**
 * How many receipts of either kind were issued on one UTC day.
 *
 * Rows, not reads. The day's `total` is what the entries earned — one per read
 * receipt and one per verified entry a sync delivered — and it is not a count
 * of receipts: a sync receipt covering six entries is one row and six reads,
 * and a sync that delivered nothing verified is one row and none. So the total
 * cannot be held against the counter range, and without this number a counter
 * drawn and never handed over would be invisible in the published payload.
 *
 * With it, the arithmetic is exact: `counter_last - counter_first + 1 -
 * receipts` is how many numbers the day drew and never issued a receipt for.
 * The publish step puts it in the payload beside the range (src/receipt.ts,
 * `buildReadCountPayload`).
 *
 * Both kinds, over the same half-open day range and the same index the range
 * and the counts use.
 */
export async function countReceiptsOn(
  db: D1Like,
  date: string,
): Promise<number> {
  const [dayFrom, dayTo] = dayRange(date);
  const row = await db
    .prepare(
      `SELECT COUNT(*) AS rows_issued FROM receipts
       WHERE ${COUNTED_KINDS_IN} AND created_at >= ? AND created_at < ?`,
    )
    .bind(...COUNTED_RECEIPT_KINDS, dayFrom, dayTo)
    .first<Row>();
  return row === null ? 0 : readInteger(row, "rows_issued");
}

/**
 * The UTC day of the oldest receipt of either kind, or null when none was ever
 * issued.
 *
 * Where the daily publication starts from: a sweep that has never published
 * has to know which day is the first one with anything to say.
 */
export async function earliestReadReceiptDay(
  db: D1Like,
): Promise<string | null> {
  const row = await db
    .prepare(
      `SELECT MIN(created_at) AS earliest FROM receipts WHERE ${COUNTED_KINDS_IN}`,
    )
    .bind(...COUNTED_RECEIPT_KINDS)
    .first<Row>();
  const earliest = row === null ? null : readNullableText(row, "earliest");
  return earliest === null ? null : utcDay(earliest);
}

/** What the reader's search asks the store for, and where it resumes. */
export interface ReadCandidatesQuery {
  readonly subject: string;
  readonly category: string;
  /** The registered domain (decision D-071); omit for every domain. */
  readonly domain?: string;
  /** The caller's own page size. There is no default. */
  readonly limit: number;
  /** Resume strictly before this submitted_seq; omit for the first page. */
  readonly beforeSubmittedSeq?: number;
}

/**
 * The verified entries a read may be answered from, newest submission first.
 *
 * Only `status = 'verified'` ever leaves this function: Section 8 promises the
 * reader an answer the log stands behind, and draft, rejected, superseded and
 * overturned are exactly the states it does not. Which of the verified ones is
 * actually served is `chooseReadable`'s answer (src/read.ts) — the tier and age
 * gates are rules, not SQL, and nothing here derives or filters on a field
 * derivation owns beyond the status it already wrote.
 *
 * Newest first, keyset-paged downward by submitted_seq, and served by the
 * `entries_subject_category_seq` index from 0001.
 */
export async function readCandidates(
  db: D1Like,
  query: ReadCandidatesQuery,
): Promise<StoredEntry[]> {
  const bindings: unknown[] = [query.subject, query.category];
  let domain = "";
  if (query.domain !== undefined) {
    domain = "AND domain = ? ";
    bindings.push(query.domain);
  }
  let before = "";
  if (query.beforeSubmittedSeq !== undefined) {
    before = "AND submitted_seq < ? ";
    bindings.push(query.beforeSubmittedSeq);
  }
  bindings.push(query.limit);

  const rows = await db
    .prepare(
      `SELECT ${ENTRY_COLUMNS} FROM entries
       WHERE subject = ? AND category = ? ${domain}${before}AND status = 'verified'
       ORDER BY submitted_seq DESC LIMIT ?`,
    )
    .bind(...bindings)
    .all<Row>();
  return rows.results.map(toStoredEntry);
}

/** What the duplicate door's backward read narrows by, and where it resumes. */
export interface EntriesNewestFirstQuery {
  readonly subject: string;
  readonly category: string;
  /** The registered domain (decision D-071); omit for every domain. */
  readonly domain?: string;
  /** The caller's own page size. There is no default. */
  readonly limit: number;
  /** Resume strictly before this submitted_seq; omit for the first page. */
  readonly beforeSubmittedSeq?: number;
}

/**
 * Every entry on one domain, subject and category, newest submission first.
 *
 * `readCandidates` above answers reads and so returns `status = 'verified'`
 * only, by design (Section 8). The duplicate door (decision D-085) asks a
 * different question and needs a different query: a draft holds its claim just
 * as much as a verified entry does, so there is no status filter here at all
 * and the live-status rule is src/duplicate.ts's, where it belongs.
 *
 * Newest first because the entry a submitter is told to look at is the newest
 * live one holding the key, and keyset-paged downward by submitted_seq — the
 * caller passes back the lowest position it saw — so a subject with more
 * entries than one page is read to the end rather than truncated at the first
 * hundred. Served by the `entries_subject_category_seq` index from 0001.
 */
export async function entriesNewestFirst(
  db: D1Like,
  query: EntriesNewestFirstQuery,
): Promise<StoredEntry[]> {
  const bindings: unknown[] = [query.subject, query.category];
  let domain = "";
  if (query.domain !== undefined) {
    domain = "AND domain = ? ";
    bindings.push(query.domain);
  }
  let before = "";
  if (query.beforeSubmittedSeq !== undefined) {
    before = "AND submitted_seq < ? ";
    bindings.push(query.beforeSubmittedSeq);
  }
  bindings.push(query.limit);

  const rows = await db
    .prepare(
      `SELECT ${ENTRY_COLUMNS} FROM entries
       WHERE subject = ? AND category = ? ${domain}${before}
       ORDER BY submitted_seq DESC LIMIT ?`,
    )
    .bind(...bindings)
    .all<Row>();
  return rows.results.map(toStoredEntry);
}

/**
 * The newest event of one type, or null when the log holds none.
 *
 * What a daily sweep asks to find where it left off: the last `read_count` it
 * published names the last day it published. One seek on the (type, seq) index
 * from 0001, never a scan of the log.
 */
export async function latestEventOfType(
  db: D1Like,
  type: EventType,
): Promise<Event | null> {
  const row = await db
    .prepare(
      `SELECT ${EVENT_COLUMNS} FROM events WHERE type = ? ORDER BY seq DESC ${ONE_ROW}`,
    )
    .bind(type)
    .first<Row>();
  return row === null ? null : toEvent(row);
}

// ---------------------------------------------------------------------------
// What the browsing UI asks (M19)
// ---------------------------------------------------------------------------

/**
 * How many entries there are, optionally narrowed by status or staleness.
 *
 * The home counters and the listing's "n of m" line, and the only reads in this
 * module that return a number instead of rows. Both are index-only: status is a
 * column with its own index (0001_init) and `stale` is the column 0005 added
 * beside the JSON, so neither has to parse an entry to count it. Nothing here
 * computes staleness — derivation did, and this counts what it stored.
 */
export async function countEntries(
  db: D1Like,
  query: {
    readonly status?: string;
    readonly stale?: boolean;
    /** The registered domain (decision D-071); omit for every domain. */
    readonly domain?: string;
  },
): Promise<number> {
  const conditions: string[] = [];
  const bindings: unknown[] = [];
  if (query.domain !== undefined) {
    conditions.push("domain = ?");
    bindings.push(query.domain);
  }
  if (query.status !== undefined) {
    conditions.push("status = ?");
    bindings.push(query.status);
  }
  if (query.stale !== undefined) {
    conditions.push("stale = ?");
    bindings.push(writeBoolean(query.stale));
  }
  const where =
    conditions.length === 0 ? "" : `WHERE ${conditions.join(" AND ")} `;
  const row = await db
    .prepare(`SELECT COUNT(*) AS n FROM entries ${where}`)
    .bind(...bindings)
    .first<Row>();
  return row === null ? 0 : readInteger(row, "n");
}

/** What the browsing listing may narrow by, and where it resumes. */
export interface ListEntriesPageQuery {
  readonly category?: string;
  /** The registered domain (decision D-071); omit for every domain. */
  readonly domain?: string;
  readonly status?: string;
  /** The sidecar's `effective_tier`, which is the tier a reader is shown. */
  readonly tier?: string;
  readonly stale?: boolean;
  /** The caller's own page size. There is no default. */
  readonly limit: number;
  /** Resume strictly before this submitted_seq; omit for the first page. */
  readonly beforeSubmittedSeq?: number;
}

/**
 * A page of entries, newest sealed position first.
 *
 * `listEntries` above pages forward for the API; a browser reads backward,
 * newest first, so this is its own query rather than a flag on that one. Keyset
 * again, not offset: the caller passes back the lowest position it saw.
 *
 * The tier filter reads `effective_tier` out of the sidecar rather than
 * `evidence_tier` off the entry, because they are not the same thing — an
 * observed entry whose test a majority rejected verifies as a document, and the
 * tier a reader is shown is the one it actually verified at (src/derive.ts).
 * There is no column for it, so it is a JSON extraction, which is why it is the
 * one filter here that does not ride an index.
 */
export async function listEntriesPage(
  db: D1Like,
  query: ListEntriesPageQuery,
): Promise<StoredEntry[]> {
  const conditions: string[] = [];
  const bindings: unknown[] = [];
  if (query.category !== undefined) {
    conditions.push("category = ?");
    bindings.push(query.category);
  }
  if (query.domain !== undefined) {
    conditions.push("domain = ?");
    bindings.push(query.domain);
  }
  if (query.status !== undefined) {
    conditions.push("status = ?");
    bindings.push(query.status);
  }
  if (query.tier !== undefined) {
    conditions.push("json_extract(sidecar_json, '$.effective_tier') = ?");
    bindings.push(query.tier);
  }
  if (query.stale !== undefined) {
    conditions.push("stale = ?");
    bindings.push(writeBoolean(query.stale));
  }
  if (query.beforeSubmittedSeq !== undefined) {
    conditions.push("submitted_seq < ?");
    bindings.push(query.beforeSubmittedSeq);
  }
  bindings.push(query.limit);

  const where =
    conditions.length === 0 ? "" : `WHERE ${conditions.join(" AND ")} `;
  const rows = await db
    .prepare(
      `SELECT ${ENTRY_COLUMNS} FROM entries ${where}ORDER BY submitted_seq DESC LIMIT ?`,
    )
    .bind(...bindings)
    .all<Row>();
  return rows.results.map(toStoredEntry);
}

/**
 * How many operators are in the trusted pool.
 *
 * Trust is granted by an `operator_trusted` event and recorded on the row by
 * whoever recomputed it (src/worker/registry.ts writes `trusted` into
 * `operator_json`), so this counts what the registry stored and derives nothing.
 * The condition is the JSON value's own truth rather than `= 1`, exactly as
 * 0005_freshness.sql reads a JSON boolean: a stored `true` extracts as truthy, a
 * stored `false` as false, and an operator whose row never carried the field at
 * all extracts as null and is not counted.
 */
export async function countTrustedOperators(
  db: D1Like,
  domain?: string,
): Promise<number> {
  if (domain === undefined) {
    const row = await db
      .prepare(
        `SELECT COUNT(*) AS n FROM operators
         WHERE json_extract(operator_json, '$.trusted')`,
      )
      .first<Row>();
    return row === null ? 0 : readInteger(row, "n");
  }
  // Trusted *and* attested in that domain (decision D-071): the trusted pool is
  // global, but who may judge an entry is not, so a count offered beside a
  // domain has to mean the operators that could actually judge in it.
  const row = await db
    .prepare(
      `SELECT COUNT(*) AS n FROM operators
        WHERE json_extract(operator_json, '$.trusted')
          AND id IN (SELECT operator FROM operator_domains WHERE domain = ?)`,
    )
    .bind(domain)
    .first<Row>();
  return row === null ? 0 : readInteger(row, "n");
}

/** How many seals the log has committed. */
export async function countSeals(db: D1Like): Promise<number> {
  const row = await db
    .prepare(`SELECT COUNT(*) AS n FROM seals`)
    .first<Row>();
  return row === null ? 0 : readInteger(row, "n");
}

/**
 * How many agents each operator has bound, ordered by operator.
 *
 * Section 5: "Every agent under an operator counts as one for validation", so
 * the directory shows the count an operator answers for. One grouped query over
 * the agents table rather than one query per operator: a directory of a hundred
 * operators is one read here and a hundred reads if the caller loops, and the
 * count is the only thing the row needs. An operator with no agent bound has no
 * row in the agents table and so no row here — the caller reads a missing
 * operator as zero, which is what it is.
 *
 * Served by the (operator_id, registered_seq) index from migration 0001. Limited
 * by the caller, because this module holds no page size (src/policy.ts holds
 * LIST_PAGE_LIMIT).
 */
export async function agentCountsByOperator(
  db: D1Like,
  limit: number,
): Promise<Array<{ operator: string; count: number }>> {
  const rows = await db
    .prepare(
      `SELECT operator_id AS operator, COUNT(*) AS n FROM agents
       GROUP BY operator_id ORDER BY operator_id LIMIT ?`,
    )
    .bind(limit)
    .all<Row>();
  return rows.results.map((row) => ({
    operator: readText(row, "operator"),
    count: readInteger(row, "n"),
  }));
}

/**
 * How many decisions each operator has signed, and when it last signed one.
 *
 * Section 5: the operator is the unit of accountability, so a validation is
 * counted against the operator the record names and not against the agent key
 * that signed it. Grouped straight out of the log — the `validation` events are
 * the record, and a count kept anywhere else would be a second source of truth
 * that could disagree with them. Ordered by operator so the page is stable
 * between reads, and limited by the caller, because this module holds no page
 * size.
 */
export async function validationCountsByOperator(
  db: D1Like,
  limit: number,
): Promise<Array<{ operator: string; count: number; lastSignedAt: string | null }>> {
  const rows = await db
    .prepare(
      `SELECT json_extract(payload, '$.record.operator') AS operator,
              COUNT(*) AS n,
              MAX(json_extract(payload, '$.record.signed_at')) AS last_signed_at
       FROM events WHERE type = 'validation'
       GROUP BY operator ORDER BY operator LIMIT ?`,
    )
    .bind(limit)
    .all<Row>();
  return rows.results.map((row) => ({
    operator: readText(row, "operator"),
    count: readInteger(row, "n"),
    lastSignedAt: readNullableText(row, "last_signed_at"),
  }));
}

/**
 * One operator's decisions, newest first: which entry, which way, and when.
 *
 * The operator page's own read. Served by the (type, seq) index from 0001 and
 * narrowed by the JSON path, so it walks the validations and nothing else.
 */
export async function validationsByOperator(
  db: D1Like,
  operator: string,
  limit: number,
): Promise<Array<{ entryId: string; decision: string; seq: number; signed_at: string }>> {
  const rows = await db
    .prepare(
      `SELECT seq, entry_id,
              json_extract(payload, '$.record.decision') AS decision,
              json_extract(payload, '$.record.signed_at') AS signed_at
       FROM events
       WHERE type = 'validation' AND json_extract(payload, '$.record.operator') = ?
       ORDER BY seq DESC LIMIT ?`,
    )
    .bind(operator, limit)
    .all<Row>();
  return rows.results.map((row) => ({
    entryId: readText(row, "entry_id"),
    decision: readText(row, "decision"),
    seq: readInteger(row, "seq"),
    signed_at: readText(row, "signed_at"),
  }));
}

// ---------------------------------------------------------------------------
// Drift attestation (M22)
// ---------------------------------------------------------------------------

/**
 * One attestation as the store holds it: the derived record, and the model's
 * answers.
 *
 * The answers are the one thing here that is not in the log. Whitepaper Section
 * 8, "Drift attestation": what is sealed is "the score and the probe hash", and
 * the answers themselves are hashed and stored (src/events.ts,
 * `attestation_answered`), so this is where a reader that wants to see what the
 * model actually said comes to look. Null until the model answers.
 */
export interface StoredAttestation {
  readonly attestation: DerivedAttestation;
  readonly answers: readonly ProbeAnswer[] | null;
}

const ATTESTATION_COLUMNS = `attestation_json, answers_json`;

function toStoredAttestation(row: Row): StoredAttestation {
  const answers = readNullableText(row, "answers_json");
  return {
    attestation: readJson<DerivedAttestation>(row, "attestation_json"),
    answers: answers === null ? null : (JSON.parse(answers) as ProbeAnswer[]),
  };
}

/**
 * The states an attestation can still be acted on in: still waiting for the
 * model, or waiting for its scorers.
 *
 * Not a policy number and not a knob — two of the four values `AttestationStatus`
 * declares, named here because two queries ask for exactly them: which
 * attestation is open for a model, and which have run out of time.
 */
const LIVE_ATTESTATION_STATUSES: readonly string[] = ["open", "answered"];

/**
 * The four event types an attestation's story is told in. Not a knob either:
 * the same four `EventPayloads` declares, named here because the one query that
 * reads them narrows on the type column before it touches the JSON.
 */
const ATTESTATION_EVENT_TYPES: readonly EventType[] = [
  "attestation_requested",
  "attestation_answered",
  "attestation_scored",
  "attestation_expired",
];

/**
 * The upsert that stores one attestation row. Taken as a statement rather than
 * run on the spot so the event that changed it and the row itself go into one
 * atomic batch, exactly as `entryStatement` does for an entry.
 *
 * Every column but `answers_json` is a copy of a field inside the derived
 * record; nothing is computed here. `answers` is passed separately because it is
 * not in the record and not in the log: on a write that does not touch them the
 * caller passes what it already had, so a rewrite of the row never loses them.
 */
function attestationStatement(
  db: D1Like,
  attestation: DerivedAttestation,
  answers: readonly ProbeAnswer[] | null,
): D1LikeStatement {
  const lastScore = attestation.scores.reduce<number | null>(
    (latest, score) =>
      latest === null || score.seq > latest ? score.seq : latest,
    null,
  );
  return db
    .prepare(
      `INSERT INTO attestations (
         id, model, model_operator, status, probe_hash, probe_count,
         requested_seq, requested_at, deadline,
         answers_json, answers_hash, scored_seq, score_agreed, "date",
         attestation_json
       ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
       ON CONFLICT (id) DO UPDATE SET
         model = excluded.model,
         model_operator = excluded.model_operator,
         status = excluded.status,
         probe_hash = excluded.probe_hash,
         probe_count = excluded.probe_count,
         requested_seq = excluded.requested_seq,
         requested_at = excluded.requested_at,
         deadline = excluded.deadline,
         answers_json = excluded.answers_json,
         answers_hash = excluded.answers_hash,
         scored_seq = excluded.scored_seq,
         score_agreed = excluded.score_agreed,
         "date" = excluded."date",
         attestation_json = excluded.attestation_json`,
    )
    .bind(
      attestation.id,
      attestation.model,
      attestation.model_operator,
      attestation.status,
      attestation.probe_hash,
      attestation.probe_count,
      attestation.requested_seq,
      attestation.requested_at,
      attestation.deadline,
      answers === null ? null : writeJson(answers),
      attestation.answers_hash,
      lastScore,
      attestation.score === null ? null : attestation.score.agreed,
      attestation.date,
      writeJson(attestation),
    );
}

/** Where the probe draw looks for candidates, and where it resumes. */
export interface ProbeCandidatesQuery {
  /** The caller's own page size. There is no default. */
  readonly limit: number;
  /** Resume strictly after this id; omit for the first page. */
  readonly afterId?: string;
  /**
   * The registered domain the probes are drawn from (decision D-071); omit for
   * every domain. An attestation is about a model in a domain, so the set it is
   * scored against is that domain's facts and not the whole log's.
   */
  readonly domain?: string;
}

/**
 * The entries a probe set may be drawn from: verified, observed, and fresh.
 *
 * Whitepaper Section 8, "Drift attestation": "A probe set is drawn from
 * verified, observed, fresh entries by public randomness." All three are stored
 * fields and reading them is not a rule, which is why they are here and the draw
 * itself is in src/probe.ts. `stale = 0` is "fresh" as derivation wrote it, and
 * the tier is the sidecar's `effective_tier` rather than the core's
 * `evidence_tier`: Section 4's gate says an observed entry whose test a majority
 * rejected "is validated as a document and its effective tier is stated", and an
 * entry the log itself treats as a document is not a measurement to probe on.
 *
 * Keyset by id and not by submitted_seq, because the caller reads EVERY page to
 * draw from the whole candidate set rather than a recent slice of it: id is the
 * primary key, so the walk is the cheapest total order the table has, and an
 * entry rewritten between two pages cannot shift a row across the boundary.
 */
export async function probeCandidates(
  db: D1Like,
  query: ProbeCandidatesQuery,
): Promise<StoredEntry[]> {
  const bindings: unknown[] = [];
  let domain = "";
  if (query.domain !== undefined) {
    domain = "AND domain = ? ";
    bindings.push(query.domain);
  }
  let after = "";
  if (query.afterId !== undefined) {
    after = "AND id > ? ";
    bindings.push(query.afterId);
  }
  bindings.push(query.limit);

  const rows = await db
    .prepare(
      `SELECT ${ENTRY_COLUMNS} FROM entries
       WHERE status = 'verified' AND stale = 0 ${domain}${after}
         AND json_extract(sidecar_json, '$.effective_tier') = 'observed'
       ORDER BY id LIMIT ?`,
    )
    .bind(...bindings)
    .all<Row>();
  return rows.results.map(toStoredEntry);
}

/**
 * What an attestation writer stores.
 *
 * `row` and `attestation` are callbacks rather than values for the reason
 * `recordValidation` gives: the event does not exist until it is sealed onto the
 * head, and the derived record has to be computed from a log that already holds
 * it — `requested_seq` is the request event's own position, and each score
 * carries the position of the event that made it. So the caller is handed the
 * sealed event and returns what derivation made of it, and nothing here derives
 * a field.
 */
export interface AttestationWrite<T extends EventType> {
  readonly event: EventInput<T>;
  readonly attestation: (event: Event<T>) => DerivedAttestation;
}

/**
 * Record an attestation request: the event, the attestation row, and one row per
 * drawn scorer, atomically.
 *
 * Section 8: the probes and the three scorers are both drawn by public
 * randomness from a snapshot sealed before the beacon round, and the event
 * carries everything either draw was computed from. The event is the record and
 * the rows are the index into it, so an attestations row without its event would
 * be an attestation nobody can recompute offline, and an event without its rows
 * would be an attestation the sweep cannot see when its deadline passes. One
 * `batch` makes both impossible.
 *
 * The id is the request's own: `attestationId` hashes the model, the snapshot
 * position, the round and the probe hash, so a second request by the same model
 * against the same round is the same id and the primary key is what refuses it —
 * which is how "one model attests at most once per beacon round" is enforced by
 * the shape of the data rather than by a check somebody could forget.
 */
export async function recordAttestationRequest(
  db: D1Like,
  input: {
    readonly event: EventInput<"attestation_requested">;
    readonly row: (event: Event<"attestation_requested">) => DerivedAttestation;
    readonly scorers: readonly AttestationScorer[];
  },
): Promise<Event<"attestation_requested">> {
  const { event, statements } = await sealOntoHead(db, input.event);
  const requested = event as Event<"attestation_requested">;
  const attestation = input.row(requested);

  statements.push(attestationStatement(db, attestation, null));
  for (const scorer of input.scorers) {
    statements.push(
      db
        .prepare(
          `INSERT INTO attestation_scorers (attestation, operator, agent, scored_seq)
           VALUES (?, ?, ?, NULL)`,
        )
        .bind(attestation.id, scorer.operator, scorer.agent),
    );
  }
  await db.batch(statements);
  return requested;
}

/**
 * Record the model's answers: the event, and the row rewritten around them.
 *
 * The log gets the hash and this row gets the answers themselves, which is the
 * whole reason `answers_json` exists (migrations/0011_attestations.sql). They are
 * written in the same batch as the event that hashed them, so a stored set of
 * answers can never be one the log never saw.
 */
export async function recordAttestationAnswers(
  db: D1Like,
  input: AttestationWrite<"attestation_answered"> & {
    readonly id: string;
    readonly answers: readonly ProbeAnswer[];
  },
): Promise<Event<"attestation_answered">> {
  const { event, statements } = await sealOntoHead(db, input.event);
  const answered = event as Event<"attestation_answered">;
  statements.push(
    attestationStatement(db, input.attestation(answered), input.answers),
  );
  await db.batch(statements);
  return answered;
}

/**
 * Record one scorer's verdict: the event, the row rewritten from the derived
 * record, and that scorer's own row closed.
 *
 * `operator` is the scorer, and its row is what "who has not scored yet" is read
 * from: the third score is the one that turns the status to `scored` and fills
 * the published score and date, and all of it has to land in the same batch as
 * the event, or a reader between two writes would see three scores and an
 * attestation still waiting.
 *
 * The answers are carried through unchanged: a rewrite of the row must not lose
 * what the model said.
 */
export async function recordAttestationScore(
  db: D1Like,
  input: AttestationWrite<"attestation_scored"> & {
    readonly id: string;
    readonly operator: string;
    readonly answers: readonly ProbeAnswer[] | null;
  },
): Promise<Event<"attestation_scored">> {
  const { event, statements } = await sealOntoHead(db, input.event);
  const scored = event as Event<"attestation_scored">;
  statements.push(
    attestationStatement(db, input.attestation(scored), input.answers ?? null),
    db
      .prepare(
        `UPDATE attestation_scorers SET scored_seq = ?
         WHERE attestation = ? AND operator = ?`,
      )
      .bind(scored.seq, input.id, input.operator),
  );
  await db.batch(statements);
  return scored;
}

/**
 * Record an expiry: the event, and the row rewritten around it.
 *
 * The sweep's write. An expiry claims nothing about drift — it says the window
 * ran out and names who never scored — so nothing but the status and the record
 * change, and the partial scores stay exactly where they are.
 */
export async function recordAttestationExpired(
  db: D1Like,
  input: AttestationWrite<"attestation_expired"> & {
    readonly id: string;
    readonly answers: readonly ProbeAnswer[] | null;
  },
): Promise<Event<"attestation_expired">> {
  const { event, statements } = await sealOntoHead(db, input.event);
  const expired = event as Event<"attestation_expired">;
  statements.push(
    attestationStatement(db, input.attestation(expired), input.answers ?? null),
  );
  await db.batch(statements);
  return expired;
}

/**
 * Store one attestation and its scorer rows, replacing whatever was there.
 *
 * The four writers above each write this row inside the batch that appends the
 * event that changed it, because a row without its event would be an attestation
 * nobody can recompute offline. A replay has the events already — `npm run
 * import-mirror` appends the whole sealed log first, and the record it stores is
 * `deriveAttestation`'s fold over exactly those events — so it needs the row on
 * its own, and it writes exactly the row those four write. The scorers come off
 * the derived record, each closed at the position of the score it signed, which
 * is what `recordAttestationScore` writes as it lands.
 *
 * The answers are the one thing that is not in the log (Section 8 seals "the
 * score and the probe hash"), so they are passed beside the record exactly as
 * they are to every other writer here.
 */
export async function putAttestation(
  db: D1Like,
  input: {
    readonly attestation: DerivedAttestation;
    readonly answers: readonly ProbeAnswer[] | null;
  },
): Promise<void> {
  const scoredAt = new Map<string, number>();
  for (const score of input.attestation.scores) {
    scoredAt.set(score.operator, score.seq);
  }
  const statements = [
    attestationStatement(db, input.attestation, input.answers),
    ...input.attestation.scorers.map((scorer) =>
      db
        .prepare(
          `INSERT INTO attestation_scorers (attestation, operator, agent, scored_seq)
           VALUES (?, ?, ?, ?)
           ON CONFLICT (attestation, operator) DO UPDATE SET
             agent = excluded.agent,
             scored_seq = excluded.scored_seq`,
        )
        .bind(
          input.attestation.id,
          scorer.operator,
          scorer.agent,
          scoredAt.get(scorer.operator) ?? null,
        ),
    ),
  ];
  await db.batch(statements);
}

/** One attestation by id, with the model's answers, or null. */
export async function getAttestation(
  db: D1Like,
  id: string,
): Promise<StoredAttestation | null> {
  const row = await db
    .prepare(
      `SELECT ${ATTESTATION_COLUMNS} FROM attestations WHERE id = ? ${ONE_ROW}`,
    )
    .bind(id)
    .first<Row>();
  return row === null ? null : toStoredAttestation(row);
}

/**
 * The attestation this model still has running, or null.
 *
 * The check behind the request route's refusal: a model with one open or
 * answered attestation does not get a second, so a model's operator cannot keep
 * redrawing until it likes the questions. Newest first, because an expired one
 * is not running and a scored one is finished. Served by the (model, status)
 * index.
 */
export async function openAttestationForModel(
  db: D1Like,
  model: string,
): Promise<StoredAttestation | null> {
  const row = await db
    .prepare(
      `SELECT ${ATTESTATION_COLUMNS} FROM attestations
       WHERE model = ? AND status IN (?, ?)
       ORDER BY requested_seq DESC ${ONE_ROW}`,
    )
    .bind(model, ...LIVE_ATTESTATION_STATUSES)
    .first<Row>();
  return row === null ? null : toStoredAttestation(row);
}

/** Where the attestation sweep looks, and how much of it takes at a time. */
export interface DueAttestationsQuery {
  readonly now: string;
  /** The caller's own page size. There is no default. */
  readonly limit: number;
}

/**
 * The attestations whose window has run out: still open or answered, and past
 * `now`.
 *
 * The third of the sweep's deadline-first reads, after `dueAssignments` and
 * `dueRevalidationAssignments`, and it holds the same rule they do: strictly
 * before, because the deadline instant itself is still inside the window
 * (src/attest.ts, `attestationDue`), and oldest deadline first so a sweep that
 * can only get through so many gets through the longest-overdue ones. Served by
 * the (status, deadline) index.
 */
export async function dueAttestations(
  db: D1Like,
  query: DueAttestationsQuery,
): Promise<StoredAttestation[]> {
  const rows = await db
    .prepare(
      `SELECT ${ATTESTATION_COLUMNS} FROM attestations
       WHERE status IN (?, ?) AND deadline < ?
       ORDER BY deadline LIMIT ?`,
    )
    .bind(...LIVE_ATTESTATION_STATUSES, query.now, query.limit)
    .all<Row>();
  return rows.results.map(toStoredAttestation);
}

/** What an attestation listing may narrow by, and where it resumes. */
export interface ListAttestationsQuery {
  readonly model?: string;
  readonly operator?: string;
  /** The caller's own page size. There is no default. */
  readonly limit: number;
  /** Resume strictly before this requested_seq; omit for the first page. */
  readonly beforeSeq?: number;
}

/**
 * A page of attestations, newest request first.
 *
 * Keyset downward by requested_seq, not offset: the caller passes back the last
 * position it saw, so the page is an index seek whose cost does not grow with
 * how far in it is. `operator` narrows to the model's operator — what a scorer
 * was drawn for is `attestationsForOperator`'s other half, which is a different
 * question and a different index.
 */
export async function listAttestations(
  db: D1Like,
  query: ListAttestationsQuery,
): Promise<StoredAttestation[]> {
  const conditions: string[] = [];
  const bindings: unknown[] = [];
  if (query.model !== undefined) {
    conditions.push("model = ?");
    bindings.push(query.model);
  }
  if (query.operator !== undefined) {
    conditions.push("model_operator = ?");
    bindings.push(query.operator);
  }
  if (query.beforeSeq !== undefined) {
    conditions.push("requested_seq < ?");
    bindings.push(query.beforeSeq);
  }
  bindings.push(query.limit);
  const where =
    conditions.length === 0 ? "" : `WHERE ${conditions.join(" AND ")} `;

  const rows = await db
    .prepare(
      `SELECT ${ATTESTATION_COLUMNS} FROM attestations ${where}ORDER BY requested_seq DESC LIMIT ?`,
    )
    .bind(...bindings)
    .all<Row>();
  return rows.results.map(toStoredAttestation);
}

/**
 * What one operator has to do with attestation, from both sides: the ones its
 * own model asked for, and the ones it was drawn to score.
 *
 * Two lists and not one, because they are two different relationships and the
 * paper is careful about the difference — Section 8's whole point is that the
 * scorers are "parties its lab does not control", so an operator's page must
 * never blur what it attested with what it judged. Newest request first on both
 * sides, and the caller's limit applies to each.
 */
export async function attestationsForOperator(
  db: D1Like,
  operator: string,
  limit: number,
): Promise<{ asModel: StoredAttestation[]; asScorer: StoredAttestation[] }> {
  const asModel = await db
    .prepare(
      `SELECT ${ATTESTATION_COLUMNS} FROM attestations
       WHERE model_operator = ? ORDER BY requested_seq DESC LIMIT ?`,
    )
    .bind(operator, limit)
    .all<Row>();

  const asScorer = await db
    .prepare(
      `SELECT a.attestation_json, a.answers_json FROM attestation_scorers AS s
       JOIN attestations AS a ON a.id = s.attestation
       WHERE s.operator = ? ORDER BY a.requested_seq DESC LIMIT ?`,
    )
    .bind(operator, limit)
    .all<Row>();

  return {
    asModel: asModel.results.map(toStoredAttestation),
    asScorer: asScorer.results.map(toStoredAttestation),
  };
}

/**
 * One attestation's whole story: the four events carrying its id, in seq order.
 *
 * The mirror of `eventsForEntry` for the training path. An attestation is not
 * entry-scoped, so its id lives in the payload rather than in the `entry_id`
 * column and the narrowing is a JSON path — bounded by the attestation and by
 * the four types, never a scan of the log, and served by the (type, seq) index
 * from 0001.
 */
export async function eventsForAttestation(
  db: D1Like,
  id: string,
): Promise<Event[]> {
  const rows = await db
    .prepare(
      `SELECT ${EVENT_COLUMNS} FROM events
       WHERE type IN (?, ?, ?, ?) AND json_extract(payload, '$.attestation') = ?
       ORDER BY seq`,
    )
    .bind(...ATTESTATION_EVENT_TYPES, id)
    .all<Row>();
  return rows.results.map(toEvent);
}

// ---------------------------------------------------------------------------
// The sweep's own account of itself (M23, decision D-076)
// ---------------------------------------------------------------------------

/**
 * One step of one sweep run, as the status page reads it.
 *
 * A status board and never a history: one row per step name, replaced at the
 * end of every run. `last_ok_at`, `last_skip_reason` and `last_skip_at` are null
 * when this run has nothing new to say about them, and the upsert keeps
 * whatever stood there — so a step that has been refusing since noon still
 * carries the morning it last worked.
 *
 * `detail` is the step's own part of the sweep report plus the facts the status
 * rules need that no event carries. Nothing derives anything from it here: it
 * goes in as JSON and comes back as JSON.
 */
export interface SweepStepRow {
  readonly step: string;
  readonly last_run_at: string;
  readonly last_ok_at: string | null;
  readonly last_skip_reason: string | null;
  readonly last_skip_at: string | null;
  readonly detail: Record<string, unknown>;
  /** `alarm`: the one door that runs the sweep, named on the row it wrote. */
  readonly trigger: string;
}

const SWEEP_STEP_COLUMNS = `step, last_run_at, last_ok_at, last_skip_reason, last_skip_at, detail_json, "trigger"`;

function toSweepStep(row: Row): SweepStepRow {
  return {
    step: readText(row, "step"),
    last_run_at: readText(row, "last_run_at"),
    last_ok_at: readNullableText(row, "last_ok_at"),
    last_skip_reason: readNullableText(row, "last_skip_reason"),
    last_skip_at: readNullableText(row, "last_skip_at"),
    detail: readJson<Record<string, unknown>>(row, "detail_json"),
    trigger: readText(row, "trigger"),
  };
}

/**
 * Write one run's step rows, in one batch.
 *
 * COALESCE on the three carried columns, and only on those three: a run that
 * reached a step always moves `last_run_at`, `detail_json` and `"trigger"`,
 * because those are about this run; `last_ok_at` and the skip pair are about the
 * last run that had something to say, so a null from this run means "no news"
 * rather than "never". A step that has never once succeeded therefore keeps a
 * null `last_ok_at`, which is exactly what the page reads as `idle`.
 *
 * One batch, so a reader between two steps of the same run never sees half a
 * board.
 */
export async function putSweepSteps(
  db: D1Like,
  rows: readonly SweepStepRow[],
): Promise<void> {
  if (rows.length === 0) return;
  const statements = rows.map((row) =>
    db
      .prepare(
        `INSERT INTO sweep_steps (${SWEEP_STEP_COLUMNS}) VALUES (?, ?, ?, ?, ?, ?, ?)
         ON CONFLICT (step) DO UPDATE SET
           last_run_at = excluded.last_run_at,
           last_ok_at = COALESCE(excluded.last_ok_at, sweep_steps.last_ok_at),
           last_skip_reason =
             COALESCE(excluded.last_skip_reason, sweep_steps.last_skip_reason),
           last_skip_at = COALESCE(excluded.last_skip_at, sweep_steps.last_skip_at),
           detail_json = excluded.detail_json,
           "trigger" = excluded."trigger"`,
      )
      .bind(
        row.step,
        row.last_run_at,
        row.last_ok_at,
        row.last_skip_reason,
        row.last_skip_at,
        writeJson(row.detail),
        row.trigger,
      ),
  );
  await db.batch(statements);
}

/**
 * Every step row, in step order.
 *
 * No limit, and it is not a list read that needs one: the table holds exactly
 * one row per step of the sweep, the steps are named in src/worker/sweep.ts, and
 * the count is a property of the code rather than of how much has happened.
 */
export async function sweepSteps(db: D1Like): Promise<SweepStepRow[]> {
  const rows = await db
    .prepare(`SELECT ${SWEEP_STEP_COLUMNS} FROM sweep_steps ORDER BY step`)
    .all<Row>();
  return rows.results.map(toSweepStep);
}

/**
 * How many events the newest seal does not cover, and the oldest one's instant.
 *
 * `afterSeq` is the seal's `last_seq`, or null when nothing is sealed at all —
 * in which case every event is unsealed. One aggregate over the primary key
 * range, so the cost is the seek and not the count.
 */
export async function unsealedEvents(
  db: D1Like,
  afterSeq: number | null,
): Promise<{ count: number; oldest_at: string | null }> {
  const row =
    afterSeq === null
      ? await db
          .prepare(`SELECT COUNT(*) AS n, MIN("at") AS oldest FROM events`)
          .first<Row>()
      : await db
          .prepare(
            `SELECT COUNT(*) AS n, MIN("at") AS oldest FROM events WHERE seq > ?`,
          )
          .bind(afterSeq)
          .first<Row>();
  if (row === null) return { count: 0, oldest_at: null };
  return {
    count: readInteger(row, "n"),
    oldest_at: readNullableText(row, "oldest"),
  };
}

/**
 * The trusted operators' ids, in id order, up to the caller's own limit.
 *
 * The same condition `countTrustedOperators` counts, returning the names: the
 * status page compares them against the operators the newest `pool_snapshot`
 * committed, and a count could not tell a swap from a match. The JSON value's
 * own truth rather than `= 1`, exactly as that count reads it.
 */
export async function trustedOperatorIds(
  db: D1Like,
  limit: number,
): Promise<string[]> {
  const rows = await db
    .prepare(
      `SELECT id FROM operators
       WHERE json_extract(operator_json, '$.trusted') ORDER BY id LIMIT ?`,
    )
    .bind(limit)
    .all<Row>();
  return rows.results.map((row) => readText(row, "id"));
}

/** How many operators are registered at all, trusted or not. */
export async function countOperators(db: D1Like): Promise<number> {
  const row = await db
    .prepare(`SELECT COUNT(*) AS n FROM operators`)
    .first<Row>();
  return row === null ? 0 : readInteger(row, "n");
}

/**
 * How many seals carry at least one countersignature.
 *
 * The complement of `unwitnessedSeals`'s first clause, counted rather than
 * listed: the status page shows witnessed over total and never the seals
 * themselves.
 */
export async function countWitnessedSeals(db: D1Like): Promise<number> {
  const row = await db
    .prepare(`SELECT COUNT(*) AS n FROM seals WHERE witnesses_json <> '[]'`)
    .first<Row>();
  return row === null ? 0 : readInteger(row, "n");
}

/**
 * How many seals were sealed on one UTC day.
 *
 * The same half-open text range `sealsSealedOn` seeks on, counted instead of
 * loaded: the anchoring stage asks only whether the day had anything to anchor,
 * and a day's seals are not a page anyone wants to read to answer that.
 */
export async function countSealsSealedOn(
  db: D1Like,
  date: string,
): Promise<number> {
  const row = await db
    .prepare(
      `SELECT COUNT(*) AS n FROM seals WHERE sealed_at >= ? AND sealed_at < ?`,
    )
    .bind(`${date}T`, `${date}U`)
    .first<Row>();
  return row === null ? 0 : readInteger(row, "n");
}

/**
 * The newest receipt of one kind: its counter and when it was created, or null
 * when none was ever issued.
 *
 * What the status page's "exercised, not probed" rows are: nobody probes the
 * read door on a schedule, so the evidence that it works is the last time
 * somebody used it. The counter is the receipts table's own `seq`, and it is
 * the index this seeks, so this is one seek rather than a scan.
 */
export async function latestReceipt(
  db: D1Like,
  kind: "read" | "sync",
): Promise<{ counter: number; created_at: string } | null> {
  const row = await db
    .prepare(
      `SELECT seq, created_at FROM receipts WHERE kind = ? ORDER BY seq DESC ${ONE_ROW}`,
    )
    .bind(kind)
    .first<Row>();
  if (row === null) return null;
  return {
    counter: readInteger(row, "seq"),
    created_at: readText(row, "created_at"),
  };
}

/**
 * How many attestations there have ever been.
 *
 * The status page's one question about the training path that a page of rows
 * cannot answer: "has anyone ever asked for a probe set here". A count, so the
 * answer does not depend on a limit.
 */
export async function countAttestations(db: D1Like): Promise<number> {
  const row = await db
    .prepare(`SELECT COUNT(*) AS n FROM attestations`)
    .first<Row>();
  return row === null ? 0 : readInteger(row, "n");
}

// ---------------------------------------------------------------------------
// The daily mirror
// ---------------------------------------------------------------------------

/**
 * One day's export, as the row keeps it (M23).
 *
 * The column names verbatim, except that the two git object names are `commit`
 * and `tree` here and `commit_sha` and `tree_sha` in SQLite: `commit` is a
 * SQLite keyword and a column of that name would have to be quoted everywhere,
 * while a reader of the JSON wants the git word.
 *
 * Nothing here is derived and nothing here is a source of truth about the log.
 * The mirror repository is the record of what was exported; this is the note
 * saying the day is done and where it landed.
 */
export interface MirrorRecord {
  /** The UTC day the export covers, "YYYY-MM-DD". */
  readonly date: string;
  readonly exported_at: string;
  /** The commit the export landed in, or the head it was already at. */
  readonly commit: string;
  readonly tree: string;
  /** The sealed position the export was built at. */
  readonly head: number;
  /** The newest seal's own seq at that position. */
  readonly seal_seq: number;
  readonly entries: number;
  /** 0 when the repository already held these bytes. */
  readonly files_changed: number;
  readonly url: string;
  readonly raw_url: string;
}

const MIRROR_COLUMNS = `"date", exported_at, commit_sha, tree_sha, head, seal_seq, entries, files_changed, url, raw_url`;

function toMirror(row: Row): MirrorRecord {
  return {
    date: readText(row, "date"),
    exported_at: readText(row, "exported_at"),
    commit: readText(row, "commit_sha"),
    tree: readText(row, "tree_sha"),
    head: readInteger(row, "head"),
    seal_seq: readInteger(row, "seal_seq"),
    entries: readInteger(row, "entries"),
    files_changed: readInteger(row, "files_changed"),
    url: readText(row, "url"),
    raw_url: readText(row, "raw_url"),
  };
}

/** Record one day's export, replacing whatever was there for that day. */
export async function putMirror(
  db: D1Like,
  record: MirrorRecord,
): Promise<void> {
  await db
    .prepare(
      `INSERT INTO mirrors (${MIRROR_COLUMNS}) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
       ON CONFLICT ("date") DO UPDATE SET
         exported_at = excluded.exported_at,
         commit_sha = excluded.commit_sha,
         tree_sha = excluded.tree_sha,
         head = excluded.head,
         seal_seq = excluded.seal_seq,
         entries = excluded.entries,
         files_changed = excluded.files_changed,
         url = excluded.url,
         raw_url = excluded.raw_url`,
    )
    .bind(
      record.date,
      record.exported_at,
      record.commit,
      record.tree,
      record.head,
      record.seal_seq,
      record.entries,
      record.files_changed,
      record.url,
      record.raw_url,
    )
    .run();
}

/**
 * The most recent export, or null when nothing has been exported here.
 *
 * Days sort as strings because the day is always "YYYY-MM-DD" in UTC, so lexical
 * order is chronological order and the primary key is the index.
 */
export async function latestMirror(db: D1Like): Promise<MirrorRecord | null> {
  const row = await db
    .prepare(
      `SELECT ${MIRROR_COLUMNS} FROM mirrors ORDER BY "date" DESC ${ONE_ROW}`,
    )
    .first<Row>();
  return row === null ? null : toMirror(row);
}

/** One day's export, by its UTC calendar day, or null when that day has none. */
export async function mirrorOn(
  db: D1Like,
  date: string,
): Promise<MirrorRecord | null> {
  const row = await db
    .prepare(`SELECT ${MIRROR_COLUMNS} FROM mirrors WHERE "date" = ? ${ONE_ROW}`)
    .bind(date)
    .first<Row>();
  return row === null ? null : toMirror(row);
}

/** Where a page of exportable entry ids starts and stops. */
export interface EntryIdsThroughQuery {
  /** The sealed head: no entry submitted after it is part of the export. */
  readonly throughSeq: number;
  /** The caller's own page size. There is no default. */
  readonly limit: number;
  /** Resume strictly after this submitted_seq; omit for the first page. */
  readonly afterSubmittedSeq?: number;
}

/**
 * The ids of the entries submitted at or below a sealed position, in submission
 * order.
 *
 * Ids and positions only, because the export re-derives every entry from its own
 * world at the sealed head and the stored copy — derived at whatever position
 * the last writer reached — is not what the mirror carries. Keyset over
 * submitted_seq, so the walk costs an index seek per page however far in it is.
 */
export async function entryIdsThrough(
  db: D1Like,
  query: EntryIdsThroughQuery,
): Promise<{ id: string; submittedSeq: number }[]> {
  const rows =
    query.afterSubmittedSeq === undefined
      ? await db
          .prepare(
            `SELECT id, submitted_seq FROM entries
             WHERE submitted_seq <= ? ORDER BY submitted_seq LIMIT ?`,
          )
          .bind(query.throughSeq, query.limit)
          .all<Row>()
      : await db
          .prepare(
            `SELECT id, submitted_seq FROM entries
             WHERE submitted_seq <= ? AND submitted_seq > ?
             ORDER BY submitted_seq LIMIT ?`,
          )
          .bind(query.throughSeq, query.afterSubmittedSeq, query.limit)
          .all<Row>();
  return rows.results.map((row) => ({
    id: readText(row, "id"),
    submittedSeq: readInteger(row, "submitted_seq"),
  }));
}
